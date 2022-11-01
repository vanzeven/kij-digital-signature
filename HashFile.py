import hashlib
import sys
import os

class HashFile:
    def startHashFile(self, filepath):
        with open(filepath, mode='rb') as f:
                data = f.read()
                hash_obj = hashlib.sha256()
                hash_obj.update(data)
                generated_checksum = hash_obj.hexdigest()

        return (generated_checksum)
        ##print(f"Generated Checksum: {generated_checksum}")
