#!/usr/bin/env python3

import argparse
import errno
import os
import platform
import warnings

import update_payload
from update_payload import applier, error

if platform.machine == 'x86_64':
  os.environ['LD_LIBRARY_PATH'] = './lib64/'
if platform.machine == 'x86':
  os.environ['LD_LIBRARY_PATH'] = './lib/'
elif platform.machine == 'aarch64':
  os.environ['LD_LIBRARY_PATH'] = '/system/lib64:/system/lib'
elif platform.machine == 'arm':
  os.environ['LD_LIBRARY_PATH'] = '/system/lib'

def list_content(payload_file_name):
    with open(payload_file_name, 'rb') as payload_file:
        payload = update_payload.Payload(payload_file)
        payload.Init()

        for part in payload.manifest.partitions:
            print("{} ({} bytes)".format(part.partition_name,
                                         part.new_partition_info.size))


def determine_input_file_path(path):
    if os.path.isfile(path):
        return path

    path += ".img"
    if os.path.isfile(path):
        return path

    raise FileNotFoundError


def extract(payload_file_name, output_dir="output", old_dir="old", partition_names=None, ignore_block_size=None):
    try:
        os.makedirs(output_dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    
    with open(payload_file_name, 'rb') as payload_file:
        payload = update_payload.Payload(payload_file)
        payload.Init()

        is_warning_issued = False

        helper = applier.PayloadApplier(payload, ignore_block_size)
        for part in payload.manifest.partitions:
            if partition_names and part.partition_name not in partition_names:
                continue
            print("Extracting {}".format(part.partition_name))
            output_file = os.path.join(output_dir, "{}.img".format(part.partition_name))
            try:
                if payload.IsDelta():
                    old_file    = determine_input_file_path(os.path.join(old_dir,    part.partition_name))
                    helper._ApplyToPartition(
                        part.operations, part.partition_name,
                        'install_operations', output_file,
                        part.new_partition_info, old_file,
                        part.old_partition_info, part.hash_tree_data_extent if part.HasField("hash_tree_data_extent") else None,
                        part.hash_tree_extent if part.HasField("hash_tree_extent") else None, part.hash_tree_algorithm,
                        part.hash_tree_salt)
                else:
                    helper._ApplyToPartition(
                        part.operations, part.partition_name,
                        'install_operations', output_file,
                        part.new_partition_info)
            except error.PayloadError as e:
                is_warning_issued = True
                warnings.warn(e)

    return not is_warning_issued

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("payload", metavar="payload.bin",
                        help="Path to the payload.bin")
    parser.add_argument("--output_dir", default="output",
                        help="Output directory")
    parser.add_argument("--old_dir", default="old",
                        help="Old directory")
    parser.add_argument("--partitions", type=str, nargs='+',
                        help="Name of the partitions to extract")
    parser.add_argument("--list_partitions", action="store_true",
                        help="List the partitions included in the payload.bin")
    parser.add_argument("--ignore_block_size", action="store_true",
                        help="Ignore block size")

    args = parser.parse_args()
    if args.list_partitions:
        list_content(args.payload)
    else:
        if not extract(args.payload, args.output_dir, args.old_dir, args.partitions, args.ignore_block_size):
            exit(1)
