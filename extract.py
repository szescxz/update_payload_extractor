#!/usr/bin/env python3

import argparse
import errno
import io
import os
import platform
import warnings

from pathlib import Path
from zipfile import ZipFile

import update_payload
from update_payload import applier, error

import requests

if platform.machine == 'x86_64':
  os.environ['LD_LIBRARY_PATH'] = './lib64/'
if platform.machine == 'x86':
  os.environ['LD_LIBRARY_PATH'] = './lib/'
elif platform.machine == 'aarch64':
  os.environ['LD_LIBRARY_PATH'] = '/system/lib64:/system/lib'
elif platform.machine == 'arm':
  os.environ['LD_LIBRARY_PATH'] = '/system/lib'


class HttpFile(io.RawIOBase):
    def __init__(self, url, additional_headers={}):
        self.url = url
        self.additional_headers = additional_headers
        self.session = requests.Session()

        resp = self.request("HEAD")
        resp.raise_for_status()
        if resp.headers.get("Accept-Ranges", None) != "bytes":
            raise ValueError("Server rejecting HEAD request")

        self.size = int(resp.headers.get("Content-Length", "0"))
        self.pos = 0
        self.is_closed = False
    
    def request(self, method, headers={}):
        headers.update(self.additional_headers)
        return self.session.request(method, self.url, headers=headers, stream=True)

    def close(self):
        self.session.close()
        self.is_closed = True

    def closed(self):
        return self.is_closed

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
    
    def seekable(self):
        return True

    def readable(self):
        return True

    def writable(self):
        return False
    
    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            return self._seek_to(offset)
        elif whence == os.SEEK_CUR:
            return self._seek_to(self.pos + offset)
        elif whence == os.SEEK_END:
            return self._seek_to(self.size + offset)
        else:
            raise io.UnsupportedOperation

    def _seek_to(self, pos):
        if pos < 0 or pos > self.size:
            raise ValueError("Invalid seek operation")
        self.pos = pos
        return pos

    def readall(self):
        buffer = bytearray(self.size - self.pos)
        self.readinto(buffer)
        return buffer

    def readinto(self, buffer):
        buffer_size = len(buffer)
        end_pos = self.pos + buffer_size - 1
        if self.pos >= self.size:
            raise ValueError("EOF")

        resp = self.request("GET", headers={
            "Range": f"bytes={self.pos}-{end_pos}"
        })
        resp.raise_for_status()
        assert resp.status_code == 206

        read_offset = 0
        for chunk in resp.iter_content(None):
            chunk_size = len(chunk)
            buffer[read_offset:read_offset+chunk_size] = chunk
            read_offset += chunk_size

        self.pos += buffer_size

        return buffer_size

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


def extract(payload_file, output_dir="output", old_dir="old", partition_names=None, ignore_block_size=None):
    try:
        os.makedirs(output_dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    payload = update_payload.Payload(payload_file)
    payload.Init()

    is_warning_issued = False

    helper = applier.PayloadApplier(payload, ignore_block_size)
    for part in payload.manifest.partitions:
        if partition_names and part.partition_name not in partition_names:
            continue
        print("Extracting {}".format(part.partition_name), end="")
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

def open_ota_file_and_extract(ota_file: ZipFile, *args, **kwargs):
    with ota_file.open("payload.bin", "r") as payload_file:
        return extract(payload_file, *args, **kwargs)

def open_package_and_extract(package_path, *args, **kwargs):
    if package_path.startswith("http://") or package_path.startswith("https://"):
        # assume it's an OTA package
        with HttpFile(package_path) as http_file:
            with ZipFile(http_file, "r") as ota_file:
                return open_ota_file_and_extract(ota_file, *args, **kwargs)
    else:
        file_extension = Path(package_path).suffix
        
        if file_extension == ".zip":
            with ZipFile(package_path, "r") as ota_file:
                return open_ota_file_and_extract(ota_file, *args, **kwargs)

        elif file_extension == ".bin":
            with open(package_path, "rb") as payload_file:
                return extract(payload_file, *args, **kwargs)
        else:
            raise NotImplementedError("Unsupported file extension")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("payload", metavar="payload.bin/update.zip",
                        help="Path to the payload.bin or OTA zip, or HTTP(S) URL of OTA zip")
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
        if not open_package_and_extract(args.payload, args.output_dir, args.old_dir, args.partitions, args.ignore_block_size):
            exit(1)
