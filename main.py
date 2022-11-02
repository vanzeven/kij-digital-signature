import argparse
import os
import re
import rsa
import shutil
import base64

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
    parser.add_argument('-e', '--embed_path', dest='embed_path', type=is_valid_path,
                        help="Enter the path of the pdf file to be sign embed")
    parser.add_argument('-x', '--verify_embed', dest='verify_embed', type=is_valid_path,
                        help="Enter the path of the embedded pdf file to be verify")
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

def signer_embed(path, hash):
    key = open('private_key.pem', 'rb')
    privKey = rsa.PrivateKey.load_pkcs1(key.read())
    
    msg2 = hash
    signature = sign_sha1(msg2, privKey)
    sign = signature

    signature_path = 'signature.txt'

    writeb(signature_path, sign)

    write_pdf_embed(path, signature_path)

    key.close()

def write_pdf_embed(pdf_path, signature_path):
    (basename, ext) = os.path.splitext(pdf_path)
    filename = basename + '_signed' + ext

    shutil.copyfile(pdf_path, filename)

    pdf_file = open(filename, 'ab')
    signature_file = open(signature_path, 'rb')

    pdf_file.write(base64.b64encode(signature_file.read()))
    # pdf_file.write(b'x')

    pdf_file.close()
    signature_file.close()

def verify_embed(path):
    key = open('public_key.pem', 'rb')
    pubKey = rsa.PublicKey.load_pkcs1(key.read())

    key.close()

    combined_file = open(path, 'rb')

    combined_bytes = combined_file.read()

    combined_file.close()

    splited_chunks = combined_bytes.split(b'EOF')

    signature_chunk = splited_chunks[-1]

    splited_chunks.pop()
    pdf_chunk = b''

    for i in range(len(splited_chunks)):
        pdf_chunk += splited_chunks[i]
        pdf_chunk += b'EOF'

    new_pdf_file = open('new_unsigned_pdf.pdf', 'wb')

    original_pdf = pdf_chunk
    embeded_signature = base64.b64decode(signature_chunk)

    new_pdf_file.write(original_pdf)
    new_pdf_file.close()

    hasher = HashFile()
    original_signed = hasher.startHashFile('new_unsigned_pdf.pdf')

    os.remove('new_unsigned_pdf.pdf')

    cek = verify_sha1(original_signed, embeded_signature, pubKey)

    if cek:
        print('Signature verified!')
    else:
        print('Could not verify the message signature.')



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
    elif args['embed_path']:
        # If File Path
        if os.path.isfile(args['embed_path']):
            hasher = HashFile()
            hash = hasher.startHashFile(args['embed_path'])
            signer_embed(args['embed_path'], hash)
        # If Folder Path
        elif os.path.isdir(args['embed_path']):
            # Process a folder
            print("not a file")
    elif args['verify_embed']:
        if os.path.isfile(args['verify_embed']):
            verify_embed(args['verify_embed'])
        # If Folder Path
        elif os.path.isdir(args['verify_embed']):
            # Process a folder
            print("not a file")
