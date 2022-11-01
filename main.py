import argparse
import os

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


def write_key(filename, content):
    f = open(filename, "w+")
    f.write(content)
    f.close()

def load():
    key_pair_generator = KeyPairGenerator()
    (private_key, public_key) = key_pair_generator.generateKeyPair()

    write_key(".\private_key.pem", private_key.decode())
    write_key(".\public_key.pem", public_key.decode())

def hashfile(path):
    hash_generator = HashFile()
    return hash_generator.startHashFile(path)

if __name__ == '__main__':
    # Parsing command line arguments entered by user
    args = parse_args()
    if args['load'] == True:
        load()
    else:
        # If File Path
        if os.path.isfile(args['input_path']):
            hash = hashfile(args['input_path'])
            print(hash)
            # sign_file(
            #     input_file=args['input_path'], output_file=args['output_file']
            # )
        # If Folder Path
        elif os.path.isdir(args['input_path']):
            # Process a folder
            print("not a file")
