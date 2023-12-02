import os
import base64
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json

class Encryptor():
    def __init__(self, message: str, password: str):
        # encode the string as a byte string, since cryptographic functions usually work on bytes
        self.plaintext = message.encode('utf-8')
        self.password = password.encode('utf-8')
        # Content to be returned
        self.ciphertext = {}

    def _get_key(self, salt, password, bit_length):
        # Password derive a 256-bit key using PBKDF2
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=bit_length,
        salt=salt,
        iterations=200000,
        )
        # Length of 256 bits = 32 bytes, same as used hash output length (recommended)
        return kdf.derive(password)
    
    def encrypt_message(self):
        # Salts should be randomly generated
        salt = os.urandom(16)
        self.ciphertext["salt"] = base64.urlsafe_b64encode(salt).decode('utf-8')
        key = self._get_key(salt, self.password, 16)
        # Nonce should be randomly generated, size same as block (128 bits = 16 bytes)
        nonce = os.urandom(16)
        self.ciphertext["nonce"] = base64.urlsafe_b64encode(nonce).decode('utf-8')
        # Using AES-128 in CTR mode to encrypt
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        ct = encryptor.update(self.plaintext) + encryptor.finalize()
        # Store value of ciphertext
        self.ciphertext["ciphertext"] = base64.urlsafe_b64encode(ct).decode('utf-8')
        h = self.authenticate()
        h.update(ct)
        # Tag of our ciphertext (Using encrypt-then-MAC approach)
        signature = h.finalize()
        # Store value of tag
        self.ciphertext["signature"] = base64.urlsafe_b64encode(signature).decode('utf-8')
        return json.dumps(self.ciphertext)

    def authenticate(self):
        # Salt to use in PBKDF2 to obtain key to use in HMAC
        salt_hmac = os.urandom(16)
        self.ciphertext["salt_hmac"] = base64.urlsafe_b64encode(salt_hmac).decode('utf-8')
        # Get key for HMAC using PBKDF2
        key_hmac = self._get_key(salt_hmac, self.password, 32)
        h = hmac.HMAC(key_hmac, hashes.SHA3_256())
        return h
        
class Decryptor():
    def __init__(self, ciphertext, password):
        self.ciphertext = ciphertext
        self.password = password.encode('utf-8')
        
    def decrypt(self):
        # Get the salt used to get key for encrypting
        salt = base64.urlsafe_b64decode(self.ciphertext["salt"].encode('utf-8'))
        # Get key used for encrypting using PBKDF2
        key = self._get_key(salt, self.password, 16)
        # Get the nonce used for encrypting
        nonce = base64.urlsafe_b64decode(self.ciphertext["nonce"].encode('utf-8'))
        # Using same algorithm as for encrypt, AES-128 on CTR mode
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        # Decrypt ciphertext
        plaintext = decryptor.update(base64.urlsafe_b64decode(self.ciphertext["ciphertext"].encode('utf-8'))) + decryptor.finalize()
        # decode the byte string back to a string
        return plaintext.decode('utf-8')


    def _get_key(self, salt, password, bit_length):
        # Password derive a 256-bit key using PBKDF2
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=bit_length,
        salt=salt,
        iterations=200000,
        )
        return kdf.derive(password)

    def verify(self):
        # Get the salt used to get key for HMAC
        salt_hmac = base64.urlsafe_b64decode(self.ciphertext["salt_hmac"].encode('utf-8'))
        # Get same key used for HMAC using PBKDF2 with same values as before
        key_hmac = self._get_key(salt_hmac, self.password, 32)
        h = hmac.HMAC(key_hmac, hashes.SHA3_256())
        h.update(base64.urlsafe_b64decode(self.ciphertext["ciphetext"].encode('utf-8')))
        h_copy = h.copy() # get a copy of 'h' to be reused
        # Verify tag. Important doing this step before decrypting.
        h.verify(base64.urlsafe_b64decode(self.ciphertext["signature"].encode('utf-8')))
