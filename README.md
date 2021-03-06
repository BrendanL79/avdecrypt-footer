# Decrypting Full-Disk Encryption (FDE) of Android Virtual Devices

This repository contains a Python 3 version of the code from 
<a href="https://github.com/sogeti-esec-lab/android-fde" target="_blank" rel="noopener nofollow noreferrer">android-fde</a> 
that is used to decrypt full-disk encrypted `userdata` partition of Android devices.  

AVDecrypt aims to ease the workflow of 
exporting decrypted images of particular snapshots 
of Android Virtual Devices (AVD) for differential forensic analysis. 

**Important:** Works with Android 9.0 (“*Pie*”, API Level 28). 
Devices using file-based encryption (FBE), 
i.e., Android 10.0 and higher, are not supported. 


## Requirements

* <a href="https://www.python.org/downloads/" target="_blank" rel="noopener noreferrer nofollow">Python</a> (3.6 and higher)
* <a href="https://developer.android.com/studio" target="_blank" rel="noopener noreferrer nofollow">Android Studio</a> (incl. Android SDK, Android Emulator, Android Debug Bridge)


## Installation

* Clone the repository:
    ```
    git clone https://faui1-gitlab.cs.fau.de/gaston.pugliese/avdecrypt.git
    ```
    * _Alternative:_ Download the repository as [ZIP file](https://faui1-gitlab.cs.fau.de/gaston.pugliese/avdecrypt/-/archive/master/avdecrypt-master.zip).
* Ensure that the Android SDK directory `emulator/` is in `PATH`, because of `qemu-img`.
* Run the appropriate installation script for your operating system:
    * macOS: `install-macos.sh` (tested on 10.14.6, 10.15.7)
    * Ubuntu: `install-ubuntu.sh` (tested on 19.10)
    * Windows: see [`INSTALL_WIN.md`](INSTALL_WIN.md)
* Afterwards, install the Python requirements:
    ```
    pip install -r requirements.txt
    ```

## Getting started

### Verifying Full-Disk Encryption

After starting the Android Virtual Device (AVD), 
make sure that it does not use file-based encryption (FBE), 
but full-disk encryption (FDE).

To verify enabled FDE, run the following command on your host:

```
adb shell getprop ro.crypto.type \
&& adb shell getprop ro.crypto.state
```

| Command | Expected output |
| -- | -- |
| `adb shell getprop ro.crypto.type` | `block` |
| `adb shell getprop ro.crypto.state` | `encrypted` |

### Decrypting

After verifying that FDE is enabled, simply run:
```
python3 avdecrypt.py 
    -a <PATH_OF_AVD_DIRECTORY> 
    -s <SNAPSHOT_NAME>
    -p <PASSWORD> (Default password: default_password; optional)
    -o <PATH_OF_OUTPUT_DIRECTORY>
    -v (verbose; optional)
```

## Credits

The original source was written in Python 2 
by Cédric Halbronn and released under a 
<a href="https://github.com/sogeti-esec-lab/android-fde/blob/master/LICENSE" target="_blank" rel="noopener noreferrer nofollow">BSD 3-Clause License</a>. 
His work was based on prior work of Thomas Cannon (see <a href="https://github.com/sogeti-esec-lab/android-fde/blob/master/README.md" target="_blank" rel="noopener noreferrer nofollow">`android-fde/README.md`</a>). 
This repository only makes use of a small portion of the tools and code 
provided by the <a href="https://github.com/sogeti-esec-lab/android-fde" target="_blank" rel="noopener noreferrer nofollow">android-fde</a> repository.  

AVDecrypt was inspired by an existing wrapper script 
for `android-fde` written by [Davide Bove](https://www.cs1.tf.fau.de/person/davide-bove/) in Python 2. 
Kudos to [Tobias Groß](https://www.cs1.tf.fau.de/person/tobias-gros/) for discussing Android's full-disk encryption.
