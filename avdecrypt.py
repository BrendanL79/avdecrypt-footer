#
# Android FDE Decryption
#
# Authors:  Thomas Cannon <tcannon@viaforensics.com>
#           Andrey Belenko <abelenko@viaforensics.com>
#           Cedric Halbronn <cedric.halbronn@sogeti.com>
# Requires: Python, M2Crypto (sudo apt-get install python-m2crypto)
#
# --
#
# This is a Python 3 version of the original code
# to decrypt Android's full-disk encryption (FDE)
# written by the authors mentioned above.
# Extended to support decryption of specific snapshots
# of a given Android Virtual Device (AVD).
#

import os

import scrypt
import struct
import tempfile
import typing
import hashlib
import pathlib
import argparse
import subprocess

from M2Crypto import EVP


DEFAULT_FILE_DATA_PARTITION = 'userdata-qemu.img.qcow2'
DEFAULT_FILE_ENCRYPTION_KEY_PARTITION = 'encryptionkey.img.qcow2'

HEADER_FORMAT = '=LHHLLLLLLL64s'
IV_LEN_BYTES = 16
SECTOR_SIZE = 512
HASH_COUNT = 2000
BLOCK_SIZE = 16
DECRYPT = 0
ENCRYPT = 1


def parse_arguments() -> argparse.Namespace:
    # define command-line arguments
    parser = argparse.ArgumentParser(description='Decrypting Android\'s full-disk encryption (FDE)')

    parser.add_argument('-a', '--avd', help='Path to Android Virtual Device directory', required=True)
    parser.add_argument('-s', '--snapshot', help='Snapshot name')
    parser.add_argument('-d', '--data_partition', help="Data partition file. Default is " + DEFAULT_FILE_DATA_PARTITION,
                        default=DEFAULT_FILE_DATA_PARTITION)
    parser.add_argument('-k', '--key_partition', help="Key partition file. Default is " + DEFAULT_FILE_ENCRYPTION_KEY_PARTITION,
                        default=DEFAULT_FILE_ENCRYPTION_KEY_PARTITION)
    parser.add_argument('-f', '--key_footer', help="Key is in crypto footer of data partition", action='store_true')
    parser.add_argument('-p', '--password', help='Android screen lock password. Default is "default_password"',
                        default='default_password')
    parser.add_argument('-o', '--outdir', help='Path to save the decrypted partition to', required=True)
    parser.add_argument('-c', '--chunk_size', help='Chunk size in bytes for hash calculation', default=4096, type=int)
    parser.add_argument('-v', '--verbose', help='Print verbose messages', default=False, action='store_true')

    # parse command-line arguments
    args: argparse.Namespace = parser.parse_args()
    args.avd = pathlib.Path(args.avd)
    args.outdir = pathlib.Path(args.outdir)

    if not args.outdir.exists():
        os.makedirs(args.outdir.as_posix())

    args.outname = f'{args.snapshot}' if args.snapshot else "userdata-decrypted"
    args.header_file = "" if args.key_footer else args.avd.joinpath(args.key_partition).as_posix()
    args.encrypted_partition = args.avd.joinpath(args.data_partition).as_posix()

    if(args.header_file):
        assert os.path.isfile(args.header_file), f"Header file '{args.header_file}' not found."
    else:
        args.header_file = "(data partition footer)"
    assert os.path.isfile(args.encrypted_partition), f"Encrypted partition '{args.encrypted_partition}' not found."

    # print command-line arguments
    if args.verbose:
        print('\n' + '=' * 72 + '\nDecrypting Android\'s Full-Disk Encryption (FDE)\n'
                                'for Android Virtual Devices (AVD)\n' + '=' * 72 + '\n')
        print(f'    AVD directory: {args.avd}')
        print(f'   Data partition: {args.encrypted_partition}')
        print(f'    Key partition: {args.header_file}')
        if(args.snapshot):
            print(f'         Snapshot: {args.snapshot}')
        print(f'         Password: {args.password}')
        print(f' Output directory: {args.outdir}')
        print(f'Chunk size (hash): {args.chunk_size:,} (bytes)')
        print()
        print('-' * 72 + '\n')

    return args


def parse_encryption_key_from_partition(header_file: pathlib.Path, verbose: bool) -> tuple:
    
    if(header_file):
        # check header file is bigger than 0x100
        file_size = os.path.getsize(header_file.as_posix())
        assert (file_size >= 0x100)

        # read header file
        with open(header_file.as_posix(), 'rb') as f:
            header = f.read()
    elif(args.key_footer):
        header = extract_footer()
    else:
        print("ERROR finding encryption data")
        exit(-1)

    # unpack header
    ftr_magic, major_version, minor_version, ftr_size, flags, key_size, spare1, fs_size1, fs_size2, failed_decrypt, \
    crypto_type = struct.unpack(HEADER_FORMAT, header[0:100])

    if minor_version != 0:  # TODO: This is a dirty fix for 1.2 header. Need to do something more generic
        ftr_size = 0x68

    encrypted_key = header[ftr_size:ftr_size + key_size]
    salt = header[ftr_size + key_size + 32:ftr_size + key_size + 32 + 16]

    # display parsed header
    if verbose:
        print('Magic          :', '0x%0.8X' % ftr_magic)
        print('Major Version  :', major_version)
        print('Minor Version  :', minor_version)
        print('Footer Size    :', ftr_size, 'bytes')
        print('Flags          :', '0x%0.8X' % flags)
        print('Key Size       :', key_size * 8, 'bits')
        print('Failed Decrypts:', failed_decrypt)
        print('Crypto Type    :', crypto_type.decode('utf-8').rstrip('\0'))
        print('Encrypted Key  :', f'0x{encrypted_key.hex().upper()}')
        print('Salt           :', f'0x{salt.hex().upper()}')

    return encrypted_key, salt, header


def get_decrypted_key(encrypted_key: bytes, salt: bytes, password: str, header: bytes,
                      verbose: bool) -> typing.Union[bytes, None]:
    key_size = len(encrypted_key)
    assert (key_size == 16 or key_size == 32)  # Other cases should be double-checked
    if key_size == 16:
        algorithm = 'aes_128_cbc'
    elif key_size == 32:
        algorithm = 'aes_256_cbc'
    else:
        print('Error: unsupported key_size')
        return None

    # Calculate the key decryption key and IV from the password
    # We encountered problems with EVP.pbkdf2 on some Windows platforms with M2Crypto-0.21.1
    # In such case, use pbkdf2.py from https://github.com/mitsuhiko/python-pbkdf2
    # For scrypt case, use py-script from https://bitbucket.org/mhallin/py-scrypt/src

    dk_len = key_size + IV_LEN_BYTES

    if header[0xbc] == 2:  # if the header specify a dkType == 2, the partition uses scrypt
        if verbose:
            print('[+] This partition uses scrypt')
        factors = (fact for fact in header[0xbd:0xc0])
        n = next(factors)
        r = next(factors)
        p = next(factors)
        if verbose:
            print(f'[+] scrypt parameters are: N={hex(n)}, r={hex(r)}, p={hex(p)}')
        deriv_result = scrypt.hash(password, salt, 1 << n, 1 << r, 1 << p)[:dk_len]
    else:
        if verbose:
            print('[+] This partition uses pbkdf2')
        deriv_result = EVP.pbkdf2(password.encode('utf-8'), salt, iter=HASH_COUNT, keylen=dk_len)

    key = deriv_result[:key_size]
    iv = deriv_result[key_size:]

    # decrypt the encryption key
    cipher = EVP.Cipher(alg=algorithm, key=key, iv=iv, padding=0, op=DECRYPT)
    decrypted_key = cipher.update(encrypted_key)
    decrypted_key = decrypted_key + cipher.final()

    # print decrypted key
    if verbose:
        print(f'Password       : {password}')
        print(f'Derived Key    : 0x{key.hex().upper()}')
        print(f'Derived IV     : 0x{iv.hex().upper()}')
        print(f'Decrypted Key  : 0x{decrypted_key.hex().upper()}')

    return decrypted_key


def decrypt_data(decrypted_key: bytes, essiv: bytes, data: bytes) -> typing.Union[bytes, None]:
    key_size = len(decrypted_key)
    assert (key_size == 16 or key_size == 32)  # other cases should be double checked
    if key_size == 16:
        algorithm = 'aes_128_cbc'
    elif key_size == 32:
        algorithm = 'aes_256_cbc'
    else:
        print('Error: unsupported key size')
        return None

    # decrypt the actual data
    cipher = EVP.Cipher(alg=algorithm, key=decrypted_key, iv=essiv, op=0)  # 0 is DEC
    cipher.set_padding(padding=0)
    dec_data = cipher.update(data)
    dec_data = dec_data + cipher.final()

    print("DECRYPTED DATA:")
    print(dec_data.hex()[0:16])
    exit(0)

    return dec_data


def decrypt(encrypted_partition: pathlib.Path, sector_start: int, decrypted_key: bytes, outfile: pathlib.Path):
    # ensure that encrypted partition size is a multiple of sector size
    file_size = os.path.getsize(encrypted_partition.as_posix())
    assert (file_size % SECTOR_SIZE == 0)
    nb_sectors = file_size // SECTOR_SIZE

    fd = open(encrypted_partition.as_posix(), 'rb')

    if(outfile.exists()):
        outmode = 'wb'
    else:
        outmode = 'w+b'

    print("Opening ",outfile.as_posix()," in mode: ",outmode)

    outfd = open(outfile.as_posix(), outmode)

    key_size = len(decrypted_key)
    assert (key_size == 16 or key_size == 32)  # other cases should be double checked
    if key_size == 16:
        pass  # algorithm = 'aes_128_cbc'
    elif key_size == 32:
        pass  # algorithm = 'aes_256_cbc'
    else:
        print('Error: unsupported keySize')
        return

    # decrypt one sector at a time
    for i in range(0, nb_sectors):
        # read encrypted sector
        sector_offset = sector_start + i
        encrypted_data = fd.read(SECTOR_SIZE)

        # calculate ESSIV; SALT=Hash(KEY); IV=E(SALT,sector_number)
        salt = hashlib.sha256(decrypted_key).digest()
        sector_number = struct.pack('<I', sector_offset) + b'\x00' * (BLOCK_SIZE - 4)

        # Since our ESSIV hash is SHA-256 we should use AES-256
        # We use ECB mode here (instead of CBC with IV of all zeroes) due to crypto lib weirdness
        # EVP engine PKCS7-pads data by default so we explicitly disable that
        cipher = EVP.Cipher(alg='aes_256_ecb', key=salt, iv=b'', padding=0, op=ENCRYPT)
        essiv = cipher.update(sector_number)
        essiv += cipher.final()

        # decrypt sector of userdata image
        decrypted_data = decrypt_data(decrypted_key, essiv, encrypted_data)

        outfd.write(decrypted_data)

    fd.close()
    outfd.close()


def get_encrypted_raw_image(img_dir: pathlib.Path, img_filename: str,
                            out_dir: pathlib.Path, out_filename: str,
                            snapshot: typing.Union[str, None], verbose: bool) -> pathlib.Path:
    imgpath = img_dir.joinpath(img_filename)
    outpath = out_dir.joinpath(f'{out_filename}.raw.enc')

    if(not (".qcow2" in img_filename[-5:])):
        # assume already raw, return input
        return imgpath

    # convert disk image to raw
    cmd = ['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw']
    if snapshot:
        cmd.extend(['-l', snapshot])
    cmd.extend([imgpath.as_posix(), outpath.as_posix()])

    if verbose:
        print(f"   RUN: {' '.join(cmd)}")

    p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    stdout, stderr = stdout.decode('utf-8'), stderr.decode('utf-8')
    if verbose:
        print(f'STDOUT: {stdout}')
        print(f'STDERR: {stderr}\n')

    return outpath


def get_file_hash(path: pathlib.Path, chunk_size: int, hash_alg) -> str:
    with open(path.as_posix(), 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            hash_alg.update(chunk)
    return hash_alg.hexdigest()


def get_file_md5(path: pathlib.Path, chunk_size: int) -> str:
    return get_file_hash(path=path, chunk_size=chunk_size, hash_alg=hashlib.md5())


def get_file_sha256(path: pathlib.Path, chunk_size: int) -> str:
    return get_file_hash(path=path, chunk_size=chunk_size, hash_alg=hashlib.sha256())


def get_file_system_details(path: pathlib.Path) -> str:
    cmd = ['fsstat', path.as_posix()]
    p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    stdout, stderr = stdout.decode('utf-8'), stderr.decode('utf-8')
    return stdout if stdout else '<empty>'


def get_file_info(path: pathlib.Path, chunk_size: int):
    size = os.path.getsize(path.as_posix())
    print(f'  PATH: {path}')
    print(f'  SIZE: {size / 1e6:,.2f} MB ({size:,} B)')
    #print(f'   MD5: {get_file_md5(path=path, chunk_size=chunk_size)}')
    #print(f'SHA256: {get_file_sha256(path=path, chunk_size=chunk_size)}')
    #print(f'FSSTAT: {get_file_system_details(path=path)}\n')


def get_encrypted_key_and_data_partitions(args: argparse.Namespace) -> tuple:
    if args.verbose:
        i_substr = "(crypto-footer of data partition)" if args.key_footer else FILE_ENCRYPTION_KEY_PARTITION
        snapshot_substr = f' (at snapshot state `{args.snapshot}`)' if args.snapshot else ""
        print(f'STEP 1: Get encrypted RAW images of (i) `{i_substr}`\n'
              f'        and (ii) `{args.encrypted_partition}` {snapshot_substr}\n'
              f'        from AVD directory: `{args.avd}`\n')

    path_data = get_encrypted_raw_image(img_dir=args.avd, img_filename=args.encrypted_partition,
                                        out_dir=args.outdir, out_filename=args.outname,
                                        snapshot=args.snapshot, verbose=args.verbose)
    if args.verbose:
        get_file_info(path=path_data, chunk_size=args.chunk_size)

    if args.key_footer:
        path_key = None
        return path_key, path_data

    path_key = get_encrypted_raw_image(img_dir=args.avd, img_filename=args.header_file,
                                       out_dir=args.outdir, out_filename=f'{args.outname}.key',
                                       snapshot=None, verbose=args.verbose)

    if args.verbose:
        get_file_info(path=path_key, chunk_size=args.chunk_size)

    return path_key, path_data


def extract_encrypted_key(path_key: pathlib.Path, verbose: bool) -> tuple:

    header_file_str = path_key.relative_to(args.outdir) if path_key else "(data partition footer)"
    if verbose:
        print(f'\nSTEP 2: Extract encrypted key from header file `{header_file_str}`\n')
    encrypted_key, salt, header = parse_encryption_key_from_partition(header_file=path_key, verbose=verbose)
    return encrypted_key, salt, header


def decrypt_encryption_key(encrypted_key: bytes, salt: bytes, password: str, header: bytes, verbose: bool) -> bytes:
    if verbose:
        print('\n\nSTEP 3: Get decrypted key\n')
    decrypted_key = get_decrypted_key(encrypted_key=encrypted_key, salt=salt, password=password, header=header,
                                      verbose=verbose)
    return decrypted_key


def decrypt_data_partition(path_in: pathlib.Path, decrypted_key: bytes, args: argparse.Namespace, sector_start=0):
    path_out = args.outdir.joinpath(f'{args.outname}.raw')
    if args.verbose:
        print(f'\n\nSTEP 4: Decrypt encrypted image `{path_data}` '
              f'to `{path_out}`\n'
              f'        using decrypted key `Ox{decrypted_key.hex().upper()}`\n')

    decrypt(encrypted_partition=path_in, sector_start=sector_start, decrypted_key=decrypted_key, outfile=path_out)
    get_file_info(path=path_out, chunk_size=args.chunk_size)

def extract_footer() -> bytes:
    print("Extracting footer...\n")
    CRYPTO_FOOTER_SIZE=16384
    with open(args.encrypted_partition, 'rb') as f:
        f.seek(-1 * CRYPTO_FOOTER_SIZE, os.SEEK_END)
        ftr = f.read(CRYPTO_FOOTER_SIZE)
        print(ftr.hex()[:16])
        return ftr

if __name__ == '__main__':
    # parse command-line arguments
    args = parse_arguments()

    # get partitions of encrypted key and data partitions as raw files
    path_key, path_data = get_encrypted_key_and_data_partitions(args=args)
    
    # extract encrypted key from encrypted key partition (raw file)
    encrypted_key, salt, header = extract_encrypted_key(path_key=path_key, verbose=args.verbose)

    # decrypt encryption key
    decrypted_key = decrypt_encryption_key(encrypted_key=encrypted_key, salt=salt, password=args.password,
                                           header=header, verbose=args.verbose)

    # decrypt data partition
    decrypt_data_partition(path_in=path_data, decrypted_key=decrypted_key, args=args, sector_start=0)

    # EOF
    if args.verbose:
        print('Done.\n')
