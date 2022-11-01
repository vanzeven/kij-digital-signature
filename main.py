from KeyPairGenerator import KeyPairGenerator

key_pair_generator = KeyPairGenerator()
(private_key, public_key) = key_pair_generator.generateKeyPair()

print(private_key)
print(public_key)