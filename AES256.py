"""
    simple AES-256 encryption in GCM mode with PBKDF2 key derivation.
"""

import os
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


class AES256:
    """
    A class providing AES-256 encryption and decryption using GCM and PBKDF2.

    This class is designed to perform encryption and decryption operations with
    robust security features, including utilizing AES-256 in GCM mode for
    authenticated encryption and employing PBKDF2 for deriving encryption keys
    securely. It is suitable for scenarios where data confidentiality and
    integrity are critical.

    Attributes:
        passphrase (str): Passphrase used to derive encryption and decryption keys.
        salt_size (int): Size of the randomly generated salt in bytes, suggested to be at least 16 bytes.
        nonce_size (int): Size of the randomly generated nonce in bytes, 12 is recommended for GCM.
        tag_size (int): Size of the authentication tag in bytes, 16 is the default tag length.
        kdf_iterations (int): Number of iterations for key derivation via PBKDF2.
    """

    def __init__(self, passphrase: str, salt_size: int = 16, nonce_size: int = 12, tag_size: int = 16, kdf_iterations: int = 100_000):
        """
        :param passphrase: secret passphrase (e.g. from KEYS.py or env var)
        :param kdf_iterations: PBKDF2 rounds (tune to your threat model/hardware)
        """
        self.passphrase = passphrase.encode('utf-8')
        self.salt_size = salt_size
        self.nonce_size = nonce_size
        self.tag_size = tag_size
        self.kdf_iterations = kdf_iterations

    def _derive_key(self, salt: bytes) -> bytes:
        return PBKDF2(self.passphrase, salt, dkLen=32, count=self.kdf_iterations)

    def encrypt(self, plaintext: bytes) -> bytes | None:
        if plaintext is None:
            return None
        # 1. Generate fresh salt & derive key
        salt = os.urandom(self.salt_size)
        key = self._derive_key(salt)

        # 2. Create GCM cipher & encrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(self.nonce_size))
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # 3. Output: salt || nonce || tag || ciphertext
        blob = salt + cipher.nonce + tag + ciphertext
        return base64.b64encode(blob)

    def decrypt(self, b64_input: bytes) -> bytes | None:
        if b64_input is None:
            return None
        # 1. Decode & split out components
        data = base64.b64decode(b64_input)
        salt = data[:self.salt_size]
        nonce = data[self.salt_size:self.salt_size + self.nonce_size]
        tag = data[self.salt_size + self.nonce_size:
                   self.salt_size + self.nonce_size + self.tag_size]
        ciphertext = data[self.salt_size + self.nonce_size + self.tag_size:]

        # 2. Re‑derive key & decrypt/verify
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

    def encrypts(self, plaintext: str) -> bytes | None:
        if plaintext is None:
            return None
        # 1. Generate fresh salt & derive key
        salt = os.urandom(self.salt_size)
        key = self._derive_key(salt)

        # 2. Create GCM cipher & encrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(self.nonce_size))
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

        # 3. Output: salt || nonce || tag || ciphertext
        blob = salt + cipher.nonce + tag + ciphertext
        return base64.b64encode(blob)

    def decrypts(self, b64_input: bytes) -> str | None:
        if b64_input is None:
            return None
        # 1. Decode & split out components
        data = base64.b64decode(b64_input)
        salt = data[:self.salt_size]
        nonce = data[self.salt_size:self.salt_size + self.nonce_size]
        tag = data[self.salt_size + self.nonce_size:
                   self.salt_size + self.nonce_size + self.tag_size]
        ciphertext = data[self.salt_size + self.nonce_size + self.tag_size:]

        # 2. Re‑derive key & decrypt/verify
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

    def get_metadata(self) -> str:
        """
        Return a comma-separated string of metadata parameters:
        kdf_iterations,salt_size,nonce_size,tag_size
        """
        fields = [
            "AES256,GCM,PBKDF2",
            str(self.kdf_iterations),
            str(self.salt_size),
            str(self.nonce_size),
            str(self.tag_size)
        ]
        return ','.join(fields)
