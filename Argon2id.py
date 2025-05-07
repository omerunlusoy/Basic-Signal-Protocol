"""
simple Argon2id hashing and verification.
Slow and memory-intensive, but secure.
Good for password hashing and verification.
https://github.com/hynek/argon2_cffi

Author: Ömer Ünlüsoy
Date:   20-April-2025
"""

import argon2
from typing import Union


class Argon2id:
    """
    Implements Argon2id hashing with additional input manipulation for enhanced cryptographic processes.

    This class provides a mechanism to generate and verify cryptographic hashes using the Argon2id algorithm. It
    incorporates a pre-defined pepper and allows for input data and variable salt combination, enhancing the hash
    generation process. It also supports metadata management for Argon2 configuration, enabling the retrieval and
    update of metadata relevant to the hashing process.

    Attributes:
        metadata (Argon2Metadata): Utility object to handle Argon2-specific configuration metadata.
        argon_hasher: Internal Argon2 hasher instance configured based on metadata.
        pepper (Union[str, bytes]): Pre-defined cryptographic pepper combined with other inputs for hashing.
    """

    def __init__(self, pepper: Union[str, bytes], metadata_str: str = None):
        self.metadata = Argon2Metadata()
        if metadata_str is not None:
            self.metadata.update_metadata_from_str(metadata_str)
        self.argon_hasher = self.metadata.to_hasher()
        if isinstance(pepper, str):
            pepper = pepper.encode('utf-8')
        self.pepper = pepper

    def hash(self, data: Union[str, bytes], variable_salt: Union[str, bytes]) -> str:
        """
        Hashes the given data using a combination of variable salt (per user) and a pre-defined pepper using Argon2 hashing algorithm.
        Salt parameter is not passed directly to the hasher, but is combined with the data and pepper before hashing.
        Thus, Argon2id still has internal random salt which should not be interfered with.

        Args:
            data: The input data to be hashed. The data can be provided as either a string or bytes. If provided
                as string, it will be internally converted to bytes using UTF-8 encoding.
            variable_salt: The salt value to be used in the hash generation. Can be provided as either a
                hexadecimal string or bytes.

        Returns:
            str: The resulting hash as a string.
        """

        # str data to bytes data
        # it is always a better practice to use bytes instead of str internally
        data_bytes = data
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')

        # Normalize salt to bytes
        variable_salt_bytes = variable_salt
        if isinstance(variable_salt, str):
            variable_salt_bytes = variable_salt.encode('utf-8')

        # Combine salt, data, and pepper
        to_hash = variable_salt_bytes + data_bytes + self.pepper

        return self.argon_hasher.hash(to_hash)

    def verify(self, data_hashed: str, data: Union[str, bytes], variable_salt: Union[str, bytes]) -> bool:
        """
        Verifies the integrity of provided data by checking its hash against the given hashed value.
        The function combines a user-provided variable salt, the data, and a fixed pepper value
        from the object before verification. This ensures that the hash check is protected against
        potential threats such as dictionary attacks by combining variable and static salts.

        Args:
            data_hashed (str): The hashed value that needs to be verified.
            data (Union[str, bytes]): The original data which is expected to generate the hash.
            variable_salt (Union[str, bytes]): A variable salt value used during hashing.

        Returns:
            bool: Returns `True` if the provided hash matches the generated hash based on
                the provided data, variable salt, and internal pepper. Returns `False` otherwise.
        """
        # str data to bytes data
        data_bytes = data
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')

        # Normalize salt to bytes
        variable_salt_bytes = variable_salt
        if isinstance(variable_salt, str):
            variable_salt_bytes = variable_salt.encode('utf-8')

        to_verify = variable_salt_bytes + data_bytes + self.pepper
        try:
            return self.argon_hasher.verify(data_hashed, to_verify)
        except:
            return False

    def needs_rehash(self, data_hashed: str) -> bool:
        """
        Determine whether the given hash should be rehashed to comply with updated parameters.

        Args:
            data_hashed (str): Existing hash string to check.

        Returns:
            bool: `True` if the hash needs rehashing; `False` otherwise.
        """
        try:
            return self.argon_hasher.check_needs_rehash(data_hashed)
        except argon2.exceptions.InvalidHash:
            # If the hash is invalid, we consider it needing rehash
            return True

    def get_metadata(self) -> str:
        """
        Retrieves the metadata as a string representation.

        This method accesses the `metadata` attribute and converts it to its string
        representation using the `to_str()` method.

        Returns:
            str: The string representation of the metadata.
        """
        return self.metadata.to_str()


class Argon2Metadata:
    """
    Simple metadata container for Argon2id hasher parameters,
    with string serialization and deserialization.

    Allows creation of PasswordHasher directly from the metadata string.
    """

    def __init__(self, time_cost=1, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16, encoding='utf-8', type_=argon2.low_level.Type.ID):
        # Normalize type
        if isinstance(type_, str):
            type_ = getattr(argon2.low_level.Type, type_)
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self.salt_len = salt_len
        self.encoding = encoding
        self.type_ = type_

    def to_str(self) -> str:
        """
        Serialize metadata to a compact string for storage.
        Format: time_cost,memory_cost,parallelism,hash_len,salt_len,encoding,type_name
        """
        fields = [
            "Argon2",
            str(self.time_cost),
            str(self.memory_cost),
            str(self.parallelism),
            str(self.hash_len),
            str(self.salt_len),
            self.encoding,
            self.type_.name,
        ]
        return ','.join(fields)

    def update_metadata_from_str(self, metadata_str: str) -> None:
        """
        Deserialize metadata from its string form into an Argon2Metadata instance.
        """
        parts = metadata_str.split(',')
        if len(parts) != 8:
            raise ValueError(f"Metadata string malformed: expected 7 fields, got {len(parts)}")
        _, tc, mc, par, hl, sl, enc, tname = parts
        self.time_cost = int(tc)
        self.memory_cost = int(mc)
        self.parallelism = int(par)
        self.hash_len = int(hl)
        self.salt_len = int(sl)
        self.encoding = enc
        self.type_ = tname
        self.type_ = getattr(argon2.low_level.Type, tname)  # convert back to enum

    def to_hasher(self) -> argon2.PasswordHasher:
        """
        Create a PasswordHasher based on this metadata.
        """
        return argon2.PasswordHasher(time_cost=self.time_cost, memory_cost=self.memory_cost, parallelism=self.parallelism, hash_len=self.hash_len, salt_len=self.salt_len, encoding=self.encoding, type=self.type_)
