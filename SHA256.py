"""
Simple SHA-256 hashing and verification from hashlib.
Fast and not memory-intensive, so not so secure for password storage.
https://docs.python.org/3/library/hashlib.html#hashlib.sha256

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

import hashlib
from typing import Union

class SHA256:
    """
    A utility class for computing and verifying peppered SHA-256 hashes with instance methods,
    expecting the caller to supply the salt.
    """

    def __init__(self, pepper: Union[str, bytes]):
        """
        Initialize the hasher with a secret pepper.

        :param pepper: Secret value (str or bytes) added to each hash (for defense-in-depth).
        """
        if isinstance(pepper, str):
            pepper = pepper.encode('utf-8')
        self.pepper = pepper

    def hash(self, data: Union[str, bytes], salt: Union[str, bytes]) -> str:
        """
        Compute a peppered SHA-256 hash of the given data using the supplied salt.

        :param data: The input data, as a str or bytes.
        :param salt: The salt to use, as bytes or hex-encoded str.
        :return: Hexadecimal SHA-256 digest string.
        """
        data_bytes = data
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')

        # Normalize salt to bytes
        salt_bytes = salt
        if isinstance(salt, str):
            salt_bytes = bytes.fromhex(salt)

        # Combine salt, data, and pepper
        to_hash = salt_bytes + data_bytes + self.pepper
        return hashlib.sha256(to_hash).hexdigest()

    def verify(self, data_hashed: str, data: Union[str, bytes], salt: Union[str, bytes]) -> bool:
        """
        Verify that a peppered SHA-256 hash matches the given data and salt.

        :param data: The input data to check, as a str or bytes.
        :param salt: The salt is used during hashing, as bytes or hex-encoded str.
        :param data_hashed: The expected hexadecimal digest.
        :return: True if match, False otherwise.
        """
        return self.hash(data, salt) == data_hashed

    def get_metadata(self) -> str:
        fields = [
            "SHA256"
        ]
        return ','.join(fields)
