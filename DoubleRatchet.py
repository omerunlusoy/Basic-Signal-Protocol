"""
Educational implementation of the Signal Double Ratchet
===============================================================================

This file shows the cryptographic mechanics of Signal’s Double Ratchet
(X25519 + symmetric-key ratchet). It is intentionally minimal,
omitting padding, replay windows, and constant-time safeguards,
so **do not use this exact code in production**.

Running this file prints a short Alice ↔ Bob conversation proving that encryption
and decryption succeed—even with out-of-order delivery.

Dependencies:
    pip install cryptography

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import json
import base64


# ----------------------------------------------------------------------------------------------- #
# Double Ratchet Header                                                                           #
# ----------------------------------------------------------------------------------------------- #

class DoubleRatchetHeader:
    """Metadata header accompanying each ciphertext (40 bytes)."""

    def __init__(self, public_ratchet_key: bytes, previous_num: int, sending_num: int):
        self.public_ratchet_key = public_ratchet_key
        self.previous_sending_message_number = previous_num
        self.sending_message_number = sending_num

    def serialize(self) -> bytes:
        """Serialize the header to bytes: key || prev_num || send_num."""
        prev_bytes = self.previous_sending_message_number.to_bytes(4, 'big')
        send_bytes = self.sending_message_number.to_bytes(4, 'big')
        return self.public_ratchet_key + prev_bytes + send_bytes

    @staticmethod
    def deserialize(data: bytes) -> 'DoubleRatchetHeader':
        """Deserialize 40 bytes into a RatchetHeader."""
        if len(data) < 40:
            raise ValueError("Header too short (need 40 bytes).")
        pub = data[:32]
        prev = int.from_bytes(data[32:36], 'big')
        send = int.from_bytes(data[36:40], 'big')
        return DoubleRatchetHeader(pub, prev, send)


# ----------------------------------------------------------------------------------------------- #
# Double Ratchet Session                                                                          #
# ----------------------------------------------------------------------------------------------- #

class DoubleRatchetSession:

    def __init__(self, initial_dh_private_key: X25519PrivateKey, root_key: bytes, sending_chain_key: Optional[bytes] = None, receiving_chain_key: Optional[bytes] = None,
                 initial_remote=None):
        self.root_key = root_key
        self.sending_chain_key = sending_chain_key
        self.receiving_chain_key = receiving_chain_key

        # Counters
        self.sending_message_number = 0
        self.receiving_message_number = 0
        self.previous_sending_message_number = 0

        # DH keys
        self.dh_private_key = initial_dh_private_key
        self.dh_public_key = self.dh_private_key.public_key()
        self.remote_public_key: Optional[X25519PublicKey] = initial_remote

        # Skipped keys cache
        self.skipped_message_keys: Dict[Tuple[bytes, int], bytes] = {}
        self.MAX_SKIPPED_KEYS = 2 ** 16

    def encrypt_message(self, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes, bytes]:
        """Encrypt a plaintext: returns (header_bytes, ciphertext, aad)."""
        if self.sending_chain_key is None:
            self.__perform_dh_ratchet()

        self.sending_chain_key, msg_key = DoubleRatchetSession.__derive_chain_and_message_keys(self.sending_chain_key)
        self.sending_message_number += 1

        header = DoubleRatchetHeader(
            DoubleRatchetSession.__get_raw_public_key_bytes(self.dh_private_key.public_key()),
            self.previous_sending_message_number,
            self.sending_message_number
        )
        header_bytes = header.serialize()
        ciphertext = self.__encrypt_with_aead(msg_key, header_bytes, associated_data, plaintext)
        return header_bytes, ciphertext, associated_data

    def decrypt_message(self, encrypted_tuple: tuple[bytes, bytes, bytes]) -> bytes:
        """Decrypt ciphertext using header and optional AAD."""

        header_bytes, ciphertext, associated_data = encrypted_tuple
        header = DoubleRatchetHeader.deserialize(header_bytes)

        key_tuple = (header.public_ratchet_key, header.sending_message_number)
        cached = self.skipped_message_keys.pop(key_tuple, None)
        if cached is not None:
            return self.__decrypt_with_aead(cached, header_bytes, associated_data, ciphertext)

        current_remote = (
            DoubleRatchetSession.__get_raw_public_key_bytes(self.remote_public_key)
            if self.remote_public_key else None
        )
        if header.public_ratchet_key != current_remote:
            self.__cache_skipped_message_keys(header.previous_sending_message_number)
            self.__perform_dh_ratchet(remote_public_bytes=header.public_ratchet_key)

        self.__cache_skipped_message_keys(header.sending_message_number - 1)

        if self.receiving_chain_key is None:
            raise ValueError("Receiving chain key missing – protocol desync.")

        self.receiving_chain_key, msg_key = DoubleRatchetSession.__derive_chain_and_message_keys(self.receiving_chain_key)
        self.receiving_message_number += 1
        return self.__decrypt_with_aead(msg_key, header_bytes, associated_data, ciphertext)

    def __perform_dh_ratchet(self, remote_public_bytes: Optional[bytes] = None) -> None:
        """Perform DH ratchet step: incoming when remote_public_bytes given, outgoing otherwise."""
        if remote_public_bytes is None:
            if self.remote_public_key is None:
                raise ValueError("Cannot perform DH ratchet without a remote public key.")
            self.dh_private_key = X25519PrivateKey.generate()
            shared = self.dh_private_key.exchange(self.remote_public_key)
            self.root_key, self.sending_chain_key = DoubleRatchetSession.derive_root_and_chain_keys(self.root_key, shared)
            self.previous_sending_message_number = self.sending_message_number
            self.sending_message_number = 0
            return

        # incoming step
        self.remote_public_key = X25519PublicKey.from_public_bytes(remote_public_bytes)
        shared_recv = self.dh_private_key.exchange(self.remote_public_key)
        self.root_key, self.receiving_chain_key = DoubleRatchetSession.derive_root_and_chain_keys(self.root_key, shared_recv)

        self.dh_private_key = X25519PrivateKey.generate()
        shared_send = self.dh_private_key.exchange(self.remote_public_key)
        self.root_key, self.sending_chain_key = DoubleRatchetSession.derive_root_and_chain_keys(self.root_key, shared_send)

        self.previous_sending_message_number = self.sending_message_number
        self.sending_message_number = 0
        self.receiving_message_number = 0

    def __cache_skipped_message_keys(self, until: int) -> None:
        """Cache skipped message keys up to index `until`."""
        while self.receiving_message_number < until and self.receiving_chain_key is not None:
            self.receiving_chain_key, msg_key = DoubleRatchetSession.__derive_chain_and_message_keys(self.receiving_chain_key)
            self.receiving_message_number += 1
            key = (DoubleRatchetSession.__get_raw_public_key_bytes(self.remote_public_key), self.receiving_message_number)
            if len(self.skipped_message_keys) >= self.MAX_SKIPPED_KEYS:
                self.skipped_message_keys.pop(next(iter(self.skipped_message_keys)))
            self.skipped_message_keys[key] = msg_key

    def serialize(self) -> bytes:
        """
        Serialize the entire session state to a JSON‐encoded bytes object.
        Byte‐values are Base64‐encoded strings.
        """
        # helper to b64‐encode bytes
        b64 = lambda b: base64.b64encode(b).decode('ascii')

        # serialize skipped_message_keys: key is "<pub_b64>:msg_num"
        skipped = {
            f"{b64(pub)}:{num}": b64(msg_key)
            for (pub, num), msg_key in self.skipped_message_keys.items()
        }

        obj = {
            'root_key': b64(self.root_key),
            'sending_chain_key': b64(self.sending_chain_key) if self.sending_chain_key else None,
            'receiving_chain_key': b64(self.receiving_chain_key) if self.receiving_chain_key else None,
            'sending_message_number': self.sending_message_number,
            'receiving_message_number': self.receiving_message_number,
            'previous_sending_message_number': self.previous_sending_message_number,
            'dh_private_key': b64(
                self.dh_private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
            ),
            'remote_public_key': b64(
                self.remote_public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            ) if self.remote_public_key else None,
            'skipped_message_keys': skipped
        }
        return json.dumps(obj).encode('utf-8')

    @staticmethod
    def deserialize(data: bytes) -> 'DoubleRatchetSession':
        """
        Reconstruct a DoubleRatchetSession from its JSON serialization.
        """
        # helper to decode Base64
        b64dec = lambda s: base64.b64decode(s.encode('ascii'))

        obj = json.loads(data.decode('utf-8'))

        # rebuild keys
        dh_private_key_ = X25519PrivateKey.from_private_bytes(b64dec(obj['dh_private_key']))
        remote_public_key_ = (X25519PublicKey.from_public_bytes(b64dec(obj['remote_public_key']))
                  if obj['remote_public_key'] else None)

        # create a fresh session with the exact chain keys and root
        session = DoubleRatchetSession(
            initial_dh_private_key=dh_private_key_,
            root_key=b64dec(obj['root_key']),
            sending_chain_key=(b64dec(obj['sending_chain_key'])
                               if obj['sending_chain_key'] else None),
            receiving_chain_key=(b64dec(obj['receiving_chain_key'])
                                 if obj['receiving_chain_key'] else None),
            initial_remote=remote_public_key_
        )

        # restore counters
        session.sending_message_number = obj['sending_message_number']
        session.receiving_message_number = obj['receiving_message_number']
        session.previous_sending_message_number = obj['previous_sending_message_number']

        # restore skipped‐message cache
        for keystr, msg_key_b64 in obj['skipped_message_keys'].items():
            pub_b64, num_str = keystr.split(':')
            pub_bytes = b64dec(pub_b64)
            num = int(num_str)
            session.skipped_message_keys[(pub_bytes, num)] = b64dec(msg_key_b64)

        return session

    @staticmethod
    # in signal_double_ratchet.py, you already have:
    def derive_root_and_chain_keys(root_key: bytes, dh_shared_secret: bytes) -> Tuple[bytes, bytes]:
        """Derive a new root key and chain key from DH output.

        Args:
            root_key: Current root key.
            dh_shared_secret: Shared secret from X25519 exchange.

        Returns:
            (new_root_key, new_chain_key).
        """
        material = DoubleRatchetSession.__derive_hkdf(dh_shared_secret, salt=root_key, info=b"DR:Root", length=64)
        return material[:32], material[32:]

    @staticmethod
    def __encrypt_with_aead(msg_key: bytes, header: bytes, aad: bytes, plaintext: bytes) -> bytes:
        key = msg_key[:32]
        nonce = msg_key[32:44]
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, header + aad)

    @staticmethod
    def __decrypt_with_aead(msg_key: bytes, header: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        key = msg_key[:32]
        nonce = msg_key[32:44]
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, header + aad)

    @staticmethod
    def __derive_hkdf(input_keying_material: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
        """Derive key material using HKDF-SHA256.

        Args:
            input_keying_material: Input keying material (IKM).
            salt: Salt for HKDF.
            info: Application-specific context.
            length: Number of bytes to derive.

        Returns:
            Derived key of specified length.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info
        )
        return hkdf.derive(input_keying_material)

    @staticmethod
    def __derive_chain_and_message_keys(chain_key: bytes) -> Tuple[bytes, bytes]:
        """Derive the next chain key and message key material.

        Args:
            chain_key: Current chain key.

        Returns:
            (next_chain_key, message_key_material)
            where message_key_material is a 32-byte key || 12-byte nonce.
        """
        material = DoubleRatchetSession.__derive_hkdf(chain_key, salt=b"", info=b"DR:Chain", length=76)
        return material[:32], material[32:]

    @staticmethod
    def __get_raw_public_key_bytes(pub: X25519PublicKey) -> bytes:
        """Get a raw 32-byte representation of an X25519 public key."""
        return pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
