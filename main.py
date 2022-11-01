import os
from KeyPairGenerator import KeyPairGenerator
from HashFile import HashFile

key_pair_generator = KeyPairGenerator()
(private_key, public_key) = key_pair_generator.generateKeyPair()

print(private_key)
print(public_key)

filepath = r'AWS Academy Learner Lab - Student Guide.pdf'
hasher = HashFile()
checksum = hasher.startHashFile(filepath)

print(checksum)