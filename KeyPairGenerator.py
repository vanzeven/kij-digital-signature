import rsa

class KeyPairGenerator:
    def generateKeyPair(self):
        (public_key, private_key) = rsa.newkeys(1024)

        public_key_pem = public_key.save_pkcs1('PEM')
        private_key_pem = private_key.save_pkcs1('PEM')

        return (private_key_pem, public_key_pem)