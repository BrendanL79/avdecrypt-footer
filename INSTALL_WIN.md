# AVDecrypt on Windows 10

## Requirements
- Configure the <a href="Windows-Subsystem für Linux" target="_blank" rel="noopener noreferrer nofollow">_Windows Subsystem for Linux (WSL)_</a> and install the <a href="https://www.microsoft.com/de-de/p/ubuntu/9nblggh4msv6" target="_blank" rel="noopener noreferrer nofollow">_Ubuntu_</a> app on your Windows 10 host system

## Ubuntu Terminal

### Requirements
- Install Python 3:
    ```
    sudo apt update
    sudo apt upgrade -y
    sudo apt install python3 python3-pip -y
    ```
- Install requirements:
    ```
    sudo apt install libssl-dev libfuse-dev openssl swig qemu-utils sleuthkit -y
    ```
- Install Python requirements by pointing to [`requirements.txt`](requirements.txt) on your host system:
    ```
    pip3 install -r /mnt/c/[PATH_TO]/requirements.txt
    ```

### Running AVDecrypt within WSL (Ubuntu)

```
python3 /mnt/c/[PATH_TO]/avdecrypt.py \
    -a /mnt/c/Users/[USERNAME]/.android/avd/[AVD_NAME].avd/ \
    -s [SNAPSHOT_NAME] \
    -o /mnt/c/[OUTPUT_PATH]/
```