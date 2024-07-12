## System requirements

- Python3, pip
- google protobuf for python, six
```
pip3 install -r requirements.txt
```

### Full OTA
```
./extract.py [--output dir <output-dir-name>] payload.bin
```
- This will start to extract the images within the payload.bin file to a folder named "output" by default (a different folder name can be specified).

### Incremental OTA

- Copy original images (from full OTA or dumped from devices) to old_dir folder
```
./extract.py [--ignore_block_size] [--output dir <output-dir-name>] [--old_dir <old-dir-name>] payload.bin
```
