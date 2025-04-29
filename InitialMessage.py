"""
InitialMessage serialization module.

Defines a TypedDict for the X3DH initial handshake message payload and
provides helper functions to serialize it into a plain dict of raw bytes
for transport/storage, and reconstruct it back into Python objects.

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

from typing import TypedDict
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey


class InitialMessage(TypedDict):
    """
    Represents the initiator's first X3DH handshake message.

    Fields:
        initiator_identity_public_key: The initiator's long-term X25519 public key.
        initiator_ephemeral_public_key: The initiator's ephemeral X25519 public key for this handshake.
        one_time_prekey_public_index: Index of the one-time pre-key used by the initiator.
    """
    initiator_identity_public_key: X25519PublicKey
    initiator_ephemeral_public_key: X25519PublicKey
    one_time_prekey_public_index: int


def serialize_initial_message(message: InitialMessage) -> dict[str, bytes]:
    """
    Convert an InitialMessage into a dict of raw bytes for pickling or network transport.

    Each public key is serialized to its 32-byte raw form, and the pre-key index is copied as-is.

    Args:
        message: The InitialMessage TypedDict to serialize.

    Returns:
        A dict mapping field names to raw bytes or integer index.
    """
    return {
        # Serialize long-term identity public key to 32 raw bytes
        "initiator_identity_public_key": message["initiator_identity_public_key"].public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        ),
        # Serialize ephemeral handshake public key to 32 raw bytes
        "initiator_ephemeral_public_key": message["initiator_ephemeral_public_key"].public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        ),
        # Include the index of the one-time pre-key used
        "one_time_prekey_public_index": message["one_time_prekey_public_index"]
    }


def deserialize_initial_message(data: dict[str, bytes]) -> InitialMessage:
    """
    Reconstruct an InitialMessage from a dict of raw bytes.

    Validates the input dict, deserializes each public key from its raw form,
    and returns a TypedDict instance.

    Args:
        data: A dict produced by `serialize_initial_message`.

    Raises:
        TypeError: If `data` is not a dict.
        ValueError: If required keys are missing from `data`.

    Returns:
        An InitialMessage TypedDict with reconstructed key objects.
    """
    if not isinstance(data, dict):
        raise TypeError("Deserialized object is not a dict")

    # Ensure all expected fields are present before reconstruction
    expected_keys = {
        "initiator_identity_public_key",
        "initiator_ephemeral_public_key",
        "one_time_prekey_public_index"
    }
    if not expected_keys.issubset(data):
        raise ValueError("Deserialized dict does not match InitialMessage structure")

    # Rebuild public key objects from raw bytes
    identity_key = X25519PublicKey.from_public_bytes(
        data["initiator_identity_public_key"]
    )
    ephemeral_key = X25519PublicKey.from_public_bytes(
        data["initiator_ephemeral_public_key"]
    )

    return InitialMessage(
        initiator_identity_public_key=identity_key,
        initiator_ephemeral_public_key=ephemeral_key,
        one_time_prekey_public_index=data["one_time_prekey_public_index"]
    )
