#!/usr/bin/env python3
# coding: utf-8

"""
A tool for encrypting EC2 volumes
Forked from https://github.com/jbrt/ec2cryptomatic
"""

import argparse
import logging
import os
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore
from traceback import TracebackException, print_exc
from typing import List

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

# Define the global logger
LOGGER = logging.getLogger('encrypt-existing-volumes')
LOGGER.setLevel(logging.DEBUG)
STREAM_HANDLER = logging.StreamHandler()
STREAM_HANDLER.setLevel(logging.INFO)
LOGGER.addHandler(STREAM_HANDLER)

# Constants
MAX_RETRIES = 360 * 4
DELAY_RETRY = 15

# Rate limits
concurrent_snapshot_copies_limits = {
    'us-gov': 5,
    'us-iso': 5,
    'cn': 5
}
default_concurrent_snapshot_copies_limit = 20

def find_region_limit(region):
    for prefix, limit in concurrent_snapshot_copies_limits.items():
        if region.startswith(prefix):
            return limit

    return default_concurrent_snapshot_copies_limit


class Encryptor:
    """ Encrypt EBS volumes on EC2 instance(s) """

    def __init__(self, region: str, instances: List[str], key: str, discard_source: bool, discard_snapshot: bool, after_start: bool, force_stop: bool):
        """
        Initialization
        :param region: (str) the AWS region where the instance is
        :param instance: (str) one instance-id
        :param key: (str) the AWS KMS Key to be used to encrypt the volume
        """
        self._kms_key = key
        self._ec2_client = boto3.client('ec2', region_name=region)
        self._ec2_resource = boto3.resource('ec2', region_name=region)
        self._region = region

        self._discard_source = discard_source
        self._discard_snapshot = discard_snapshot
        self._after_start = after_start
        self._force_stop = force_stop

        self._instance_set = set()
        self._instance_progress = defaultdict(dict)
        self._volume_progress = defaultdict(dict)
        for id in instances:
            self._instance_set.add(self._ec2_resource.Instance(id=id))

        # Waiters
        self._wait_snapshot = self._ec2_client.get_waiter('snapshot_completed')
        self._wait_volume = self._ec2_client.get_waiter('volume_available')
        self._wait_instance = self._ec2_client.get_waiter('instance_stopped')

        # Waiters retries values
        for waiter in (self._wait_snapshot, self._wait_snapshot, self._wait_instance):
            waiter.config.max_attempts = MAX_RETRIES
            waiter.config.delay = DELAY_RETRY


    def _instance_is_exists(self, instance=None, instance_id=None) -> None:
        """
        Check if instance exists
        :return: None
        :except: ClientError
        """
        if instance:
            id = instance.id
        elif instance_id:
            id = instance_id
        else:
            LOGGER.error('Either instance object or instance_id must be given to `_instance_is_exists`')
            raise Exception

        try:
            self._ec2_client.describe_instances(InstanceIds=[id])
        except ClientError:
            raise


    def _instance_is_stopped(self, instance) -> None:
        """
        Check if instance is stopped
        :return: None
        :except: TypeError
        """
        if instance.state['Name'] != 'stopped':
            if not self._force_stop:
                raise TypeError('Instance is still running! Please stop it.')
            else:
                instance.stop()
                self._wait_instance.wait(InstanceIds=[instance.id])


    def _start_instance(self, instance) -> None:
        """
        Starts the instance
        :return: None
        :except: ClientError
        """
        prefix_string = self._make_prefix_string(instance=instance)
        try:
            LOGGER.info(f'{prefix_string} -- Starting instance {instance.id}')
            self._ec2_client.start_instances(InstanceIds=[instance.id])
            LOGGER.info(f'{prefix_string} -- Instance {instance.id} started')
        except ClientError:
            raise

    def _cleanup(self, device, snapshots) -> None:
        """
        Delete the temporary objects
        :param device: the original device to delete
        """
        prefix_string = self._make_prefix_string(volume=device) + ' [CLEANUP]'
        # LOGGER.info(f'{prefix_string} Cleanup of resources')

        if self._discard_source:
            self._wait_volume.wait(VolumeIds=[device.id])
            LOGGER.info(f'{prefix_string} [DELETING] Unencrypted Volume {device.id}')
            device.delete()

        else:
            LOGGER.info(f'{prefix_string} [PRESERVING] Unencrypted Volume {device.id}')


        snapshot, encrypted_snapshot = snapshots
        if self._discard_snapshot:
            LOGGER.info(f'{prefix_string} [DELETING] Unencrypted Snapshot {snapshot.id}')
            snapshot.delete()
            LOGGER.info(f'{prefix_string} [DELETING] Encrypted Snapshot {encrypted_snapshot.id}')
            encrypted_snapshot.delete()

        else:
            LOGGER.info(f'{prefix_string} [PRESERVING] Unencrypted Snapshot {snapshot.id}')
            LOGGER.info(f'{prefix_string} [PRESERVING] Encrypted Snapshot {encrypted_snapshot.id}')


    def _create_volume(self, snapshot, original_device):
        """
        Create an encrypted volume from an encrypted snapshot
        :param snapshot: an encrypted snapshot
        :param original_device: device where take additional information
        """
        prefix_string = self._make_prefix_string(volume=original_device)
        vol_args = {'SnapshotId': snapshot.id,
                    'VolumeType': original_device.volume_type,
                    'AvailabilityZone': original_device.availability_zone}

        if original_device.volume_type.startswith('io'):
            LOGGER.info(f'{prefix_string} Provisioned IOPS volume detected (with '
                        f'{original_device.iops} IOPS)')
            vol_args['Iops'] = original_device.iops


        elif original_device.volume_type == 'gp3':
            LOGGER.info(f'{prefix_string} GP3 volume detected (with '
                        f'{original_device.iops} IOPS'
                        f'and {original_device.throughput} Throughput)')
            vol_args['Iops'] = original_device.iops
            vol_args['Throughput'] = original_device.throughput


        LOGGER.info(f'{prefix_string} [CREATING] Encrypted Volume from {snapshot.id}')
        volume = self._ec2_resource.create_volume(**vol_args)
        self._wait_volume.wait(VolumeIds=[volume.id])

        if original_device.tags:
            # It's not possible to create tags starting by 'aws:'
            # So, we have to filter AWS managed tags (ex: CloudFormation tags)
            valid_tags = [tag for tag in original_device.tags if not tag['Key'].startswith('aws:')]
            if valid_tags:
                volume.create_tags(Tags=valid_tags)

        return volume


    def _swap_device(self, instance, old_volume, new_volume) -> None:
        """
        Swap the old device with the new encrypted one
        :param old_volume: volume to detach from the instance
        :param new_volume: volume to attach to the instance
        """
        prefix_string = self._make_prefix_string(volume=old_volume)
        LOGGER.info(f'{prefix_string} [SWAPPING] Old Volume {old_volume.id} and New Volume {new_volume.id}')
        device = old_volume.attachments[0]['Device']
        instance.detach_volume(Device=device, VolumeId=old_volume.id)
        self._wait_volume.wait(VolumeIds=[old_volume.id])
        instance.attach_volume(Device=device, VolumeId=new_volume.id)


    def _take_snapshot(self, device):
        """
        Take the first snapshot from the volume to encrypt
        :param device: EBS device to encrypt
        """
        prefix_string = self._make_prefix_string(volume=device)
        LOGGER.info(f'{prefix_string} [SNAPSHOT] Volume {device.id}')
        snapshot = device.create_snapshot(Description=f'[VOLUME-ENCRYPTION] Snapshot of {device.id}')
        snapshot.create_tags(Tags=[{'Key': 'Issuer',
                                    'Value': 'Volume-Encryption'},
                                   {'Key': 'Type',
                                    'Value': 'Unencrypted Snapshot'}])
        self._wait_snapshot.wait(SnapshotIds=[snapshot.id])

        return snapshot


    def _copy_snapshot(self, snapshot, volume):
        """
        Copy the first snapshot to another encrypted snapshot
        :param snapshot: EBS device to encrypt
        """
        prefix_string = self._make_prefix_string(volume=volume)
        LOGGER.info(f'{prefix_string} [COPYING] Encrypted Snapshot from {snapshot.id}')
        snapshot_dict = snapshot.copy(Encrypted=True,
                                      KmsKeyId=self._kms_key,
                                      SourceRegion=self._region,
                                      Description=f'Encrypted Snapshot of {snapshot.id}')
        snapshot_copy = self._ec2_resource.Snapshot(snapshot_dict['SnapshotId'])
        snapshot_copy.create_tags(Tags=[{'Key': 'Issuer',
                                         'Value': 'Volume-Encryption'},
                                        {'Key': 'Type',
                                         'Value': 'Encrypted Snapshot'}])
        self._wait_snapshot.wait(SnapshotIds=[snapshot_dict['SnapshotId']])

        return self._ec2_resource.Snapshot(snapshot_dict['SnapshotId'])


    def _make_prefix_string(self, instance=None, volume=None, instance_id=None):
        prefix_string = ""
        if volume:
            instance_id = self._volume_progress[volume.id]['instance_id']

        if instance:
            instance_id = instance.id
        if instance_id:
            prefix_string += f"[i{self._instance_progress[instance_id]['index']}] "

        if volume:
            prefix_string += f"[v{self._volume_progress[volume.id]['index']}] "


        return prefix_string.rstrip()


    def _instance_is_ready(self, instance):
        prefix_string = self._make_prefix_string(instance=instance)
        LOGGER.info(f'{prefix_string} [CHECKING] [EXISTS?] Instance {instance.id}')
        self._instance_is_exists(instance=instance)

        LOGGER.info(f'{prefix_string} [CHECKING] [STOPPED?] Instance {instance.id}')
        self._instance_is_stopped(instance=instance)

        return instance


    def start_encryption(self) -> None:
        """
        Launch encryption process
        :param discard_source: (bool) if yes, delete source volumes at the end
        :param discard_snapshot: (bool) if yes, delete snapshots at the end
        :return: None
        """

        volume_m = 0
        for n, instance in enumerate(self._instance_set, start=1):

            self._instance_progress[instance.id]['index'] = n
            self._instance_is_ready(instance)

            prefix_string = self._make_prefix_string(instance=instance)
            LOGGER.info(f'{prefix_string} Starting to encrypt instance {instance.id}')

            for device in instance.block_device_mappings:
                if 'Ebs' not in device:
                    msg = f'{prefix_string} {instance.id}: Skip {device["VolumeId"]} not an EBS device'
                    LOGGER.warning(msg)
                    continue

            for device in instance.volumes.all():
                if device.encrypted:
                    msg = f'{prefix_string} {instance.id}: Volume {device.id} already encrypted'
                    LOGGER.warning(msg)
                    continue

                volume_m += 1
                self._volume_progress[device.id] = {'index': volume_m, 'instance_id': instance.id}
                self.single_encryption(instance, device)

            if self._after_start:
                # starting the stopped instance
                self._start_instance(instance)

            LOGGER.info(f'{prefix_string} [FINISHED] Instance {instance.id}\n')


    def start_encryptions(self) -> None:
        num_volumes = 0
        instance_device_pairs = defaultdict(set)

        for instance in self._instance_set:
            for device in instance.block_device_mappings:
                if 'Ebs' not in device:
                    msg = f'{instance.id}: Skip {device["VolumeId"]} not an EBS device'
                    LOGGER.warning(msg)
                    continue

            for device in instance.volumes.all():
                if device.encrypted:
                    msg = f'[CHECKING] {instance.id}: Volume {device.id} is already encrypted'
                    LOGGER.warning(msg)

                else:
                    instance_device_pairs[instance].add(device)
                    num_volumes += 1

        volume_m = 0
        for n, (instance, volumes) in enumerate(instance_device_pairs.items(), start=1):
            self._instance_progress[instance.id]['index'] = n
            for volume in volumes:
                volume_m += 1
                self._volume_progress[volume.id]['index'] = volume_m
                self._volume_progress[volume.id]['instance_id'] = instance.id


        # def shutdown_and_encrypt(instance, semaphore=None):
        #     self._instance_is_ready(instance)

        snapshot_copies_limit = Semaphore(find_region_limit(self._region))

        with ThreadPoolExecutor() as executor:
            instance_futures = [executor.submit(self._instance_is_ready, instance)
                                for instance in instance_device_pairs.keys()]

            result_futures = []
            for future in as_completed(instance_futures):
                instance = future.result()
                result_futures.extend(executor.submit(self.single_encryption, instance, device, semaphore=snapshot_copies_limit)
                                      for device in instance_device_pairs[instance])

            # TODO: add workaround so following kicks off as soon as encryption starts, not after all instances stand down
            for finished, future in enumerate(as_completed(result_futures), start=1):
                LOGGER.info(f">>> {finished}/{num_volumes} Done ")
                try:
                    ret_instance, ret_volume = future.result()
                except Exception:
                    print_exc()
                    continue
                volumes_left = instance_device_pairs[ret_instance]

                volumes_left.discard(ret_volume)

                if not volumes_left:

                    prefix_string = self._make_prefix_string(instance=ret_instance)
                    if self._after_start:
                        # starting the stopped instance
                        self._start_instance(ret_instance)
                        LOGGER.info(f'{prefix_string} [STARTING] Instance {ret_instance.id}')

                    LOGGER.info(f'{prefix_string} [FINISHED] Instance {ret_instance.id}')

        LOGGER.info(f'>>> End of work on all instances, with a total of {num_volumes} volumes converted.')



    def single_encryption(self, instance, device, semaphore=None):
        prefix_string = self._make_prefix_string(instance=instance, volume=device)
        LOGGER.debug(f"{prefix_string} Starting to encrypt Volume {device.id}")

        # Keep in mind if DeleteOnTermination is need
        delete_flag = device.attachments[0]['DeleteOnTermination']
        flag_on = {'DeviceName': device.attachments[0]['Device'],
                   'Ebs': {'DeleteOnTermination': delete_flag}}

        # First we have to take a snapshot from the original device
        snapshot = self._take_snapshot(device=device)

        # block so only certain number of snapshot copies happen at the same time
        # this limititation is from aws rate limits (ConcurrentSnapshotCopies)
        if semaphore:
            semaphore.acquire()
        snapshot_copy = self._copy_snapshot(snapshot, device)
        if semaphore:
            semaphore.release()

        # Then, create a new encrypted volume from that encrypted snapshot
        volume = self._create_volume(snapshot=snapshot_copy,
                                     original_device=device)
        # Finally, swap the old-device for the new one
        self._swap_device(instance=instance, old_volume=device, new_volume=volume)
        # cleanup
        self._cleanup(device=device, snapshots=[snapshot, snapshot_copy])

        if not self._discard_source:
            LOGGER.info(f'{prefix_string} [TAGGING] Legacy Volume {device.id} with '
                        f'Encrypted Volume ID {volume.id}')
            device.create_tags(Tags=[{'Key': 'encryptedReplacement',
                                      'Value': volume.id},
                                     {'Key': 'sourceInstanceId',
                                      'Value': instance.id}])

        if delete_flag:
            LOGGER.info('{prefix_string} Put flag DeleteOnTermination on volume')
            instance.modify_attribute(BlockDeviceMappings=[flag_on])
            LOGGER.info('')

        LOGGER.info(f'{prefix_string} [FINISHED] Volume {device.id}')

        return instance, device


def main(args: argparse.Namespace) -> None:
    """
    Main program
    :param args: arguments from CLI
    :return: None
    """
    try:
        encrypt_ec2_class = Encryptor(region=args.region,
                                      instances=args.instances,
                                      key=args.key,
                                      discard_source=args.discard_source_volume,
                                      discard_snapshot=args.discard_snapshot,
                                      after_start=args.after_start,
                                      force_stop=args.force_stop)

        if args.disable_async:
            encrypt_ec2_class.start_encryption()
        else:
            encrypt_ec2_class.start_encryptions()

    except (EndpointConnectionError, ValueError) as error:
        LOGGER.error(f'Problem with your AWS region ? ({error})')
        print("".join(TracebackException.from_exception(error).format()))
        sys.exit(1)

    except (ClientError, TypeError) as error:
        LOGGER.error(f'Problem with the instance ({error})')
        print("".join(TracebackException.from_exception(error).format()))
        sys.exit(1)



def parse_arguments(only_known=False) -> argparse.Namespace:
    """
    Parse arguments from CLI
    :returns: argparse.Namespace
    """
    description = 'Encrypt EBS volumes from EC2 instances'
    parser = argparse.ArgumentParser(description=description)
    region = os.environ.get('AWS_REGION', os.environ.get('REGION'))

    if region:
        parser.add_argument('-r', '--region', help='AWS Region', default=region)
    else:
        parser.add_argument('-r', '--region', help='AWS Region', required=True)

    parser.add_argument('-i', '--instances', nargs='+',
                        help='Instance to encrypt', required=True)
    parser.add_argument('-k', '--key', help="KMS Key ID. For alias, add prefix 'alias/'", default='alias/aws/ebs')
    parser.add_argument('-da', '--disable-async', action='store_true',
                        help="Don't run Asynchronously, runs operations in serial rather than parallel (default: False)")
    parser.add_argument('-dv', '--discard-source-volume', action='store_true',
                        help='Discard source volume after encryption (default: False)')
    parser.add_argument('-ds', '--discard-snapshot', action='store_true',
                        help='Discard snapshots after encryption (default: False)')
    parser.add_argument('-as', '--after-start', action='store_true',
                        help='Start instances after encryption (default: False)')
    parser.add_argument('-s', '--force-stop', action='store_true',
                        help='Force stop instances before encryption (default: False)')

    if only_known:
        return parser.parse_known_args()[0]
    else:
        return parser.parse_args()


if __name__ == '__main__':
    main(parse_arguments())
