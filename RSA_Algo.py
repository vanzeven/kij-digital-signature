from msilib.schema import Class
import rsa

class RSA_Algo:
    def encrypt(msg, key):
        return rsa.encrypt(msg.encode('ascii'), key)

    def decrypt(ciphertext, key):
        try:
            return rsa.decrypt(ciphertext, key).decode('ascii')
        except:
            return False