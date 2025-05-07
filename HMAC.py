"""
simple HMAC hashing and verification.
Keyed-hash message authentication code.
Fast, deterministic, keyed.
Good for hash comparison.
https://docs.python.org/3/library/hmac.html

Author: Ömer Ünlüsoy
Date:   20-April-2025
"""

import hmac
import hashlib


class HMAC:
    """
    Class representing HMAC hashing and verification.

    This class provides functionality for computing HMAC-SHA256 hashes and verifying
    if a given HMAC hash corresponds to specific data using a secret key.

    Attributes:
        key (bytes): Encoded version of the provided secret key used to compute
            HMAC hashes.
    """

    def __init__(self, secret_key: str):
        if not secret_key:
            raise ValueError("Secret key must not be empty.")
        self.key = secret_key.encode()

    def hash(self, data: str) -> str:
        # Returns the HMAC-SHA256 of the input data.
        return hmac.new(self.key, data.encode(), hashlib.sha256).hexdigest()

    def verify(self, hashed: str, data: str) -> bool:
        # Compares input data to a given HMAC hash.
        computed_hash = self.hash(data)
        return hmac.compare_digest(computed_hash, hashed)

    def get_metadata(self) -> str:
        fields = [
            "HMAC,SHA256"
        ]
        return ','.join(fields)
