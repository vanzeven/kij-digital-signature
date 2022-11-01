import argparse
import os
import re
import rsa

from HashFile import HashFile
from KeyPairGenerator import KeyPairGenerator


def is_valid_path(path):
    """Validates the path inputted and checks whether it is a file path or a folder path"""
    if not path:
        raise ValueError(f"Invalid Path")
    if os.path.isfile(path):
        return path
    elif os.path.isdir(path):
        return path
    else:
        raise ValueError(f"Invalid Path {path}")
def parse_args():
    """Get user command line parameters"""
    parser = argparse.ArgumentParser(description="Available Options")
    parser.add_argument('-l', '--load', dest='load', action="store_true",
                        help="Load the required configurations and create the certificate")
    parser.add_argument('-i', '--input_path', dest='input_path', type=is_valid_path,
                        help="Enter the path of the file or the folder to process")
    parser.add_argument('-v', '--verify', dest='verify', type=is_valid_path,
                        help="Enter the path of the file or the folder to verify")

    path = parser.parse_known_args()[0].input_path
    if path and os.path.isfile(path):
        parser.add_argument('-o', '--output_file', dest='output_file',
                            type=str, help="Enter a valid output file")
    args = vars(parser.parse_args())
    # To Display The Command Line Arguments
    print("## Command Arguments #################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in args.items()))
    print("######################################################################")
    return args


def write(filename, content):
    f = open(filename, "w+")
    f.write(content)
    f.close()

def writeb(filename, content):
    f = open(filename, "wb")
    f.write(content)
    f.close()

def load():
    key_pair_generator = KeyPairGenerator()
    (private_key, public_key) = key_pair_generator.generateKeyPair()

    write(".\private_key.pem", private_key.decode())
    write(".\public_key.pem", public_key.decode())

def hashfile(path):
    hash_generator = HashFile()
    return hash_generator.startHashFile(path)

def sign_sha1(msg, key):
    return rsa.sign(msg.encode(), key, 'SHA-1')

def verify_sha1(msg, signature, key):
    try:
        tes = rsa.verify(msg.encode(), signature, key) == 'SHA-1'
        return tes
    except:
        return False

def signer(path):
     key = open('private_key.pem', 'rb')
     privKey = rsa.PrivateKey.load_pkcs1(key.read())
     # msg = open(path, "rb")
     # msg2 = msg.read().decode()
     msg2 = path
     signature = sign_sha1(msg2, privKey)
     sign = signature
     writeb('signature.txt', sign)

     key.close()
     # msg.close()


def verify(path):
    key = open('public_key.pem', 'rb')
    pubKey = rsa.PublicKey.load_pkcs1(key.read())
    signature = open('signature.txt', 'rb')
    # msg = open(path, "r+")
    # msg2 = msg.read()
    msg2 = path
    sign = signature.read()
    cek = verify_sha1(msg2, sign, pubKey)
    if cek:
        print('Signature verified!')
    else:
        print('Could not verify the message signature.')

    key.close()
    # msg.close()
    signature.close()


if __name__ == '__main__':
    # Parsing command line arguments entered by user
    args = parse_args()
    if args['load']:
        load()
    elif args['input_path']:
        # If File Path
        if os.path.isfile(args['input_path']):
            hasher = HashFile()
            hash = hasher.startHashFile(args['input_path'])
            signer(hash)
        # If Folder Path
        elif os.path.isdir(args['input_path']):
            # Process a folder
            print("not a file")
    elif args['verify']:
        if os.path.isfile(args['verify']):
            hasher = HashFile()
            hash = hasher.startHashFile(args['verify'])
            verify(hash)
        # If Folder Path
        elif os.path.isdir(args['verify']):
            # Process a folder
            print("not a file")
