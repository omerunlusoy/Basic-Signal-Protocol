"""
PreKeyBundle serialization module.

Defines a TypedDict for an X3DH PreKeyBundle and provides functions to
serialize it into a plain dict of raw bytes for transport/storage, and
reconstruct it back into Python objects.

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

from typing import TypedDict
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class PreKeyBundle(TypedDict):
    """
    TypedDict representing an X3DH PreKeyBundle published by a user.

    Attributes:
        identity_public_key: X25519 public key identifying the user.
        signing_public_key: Ed25519 public key for signature verification.
        signed_prekey_public: X25519 public key signed by the user's identity key.
        signed_prekey_signature: Signature over the signed_prekey_public.
        one_time_prekey_public_list: List of X25519 one-time pre-keys.
        one_time_prekey_public_index: Index of the next one-time pre-key to use.
    """
    identity_public_key: X25519PublicKey
    signing_public_key: Ed25519PublicKey
    signed_prekey_public: X25519PublicKey
    signed_prekey_signature: bytes
    one_time_prekey_public_list: list[X25519PublicKey]
    one_time_prekey_public_index: int


def serialize_prekey_bundle(bundle: PreKeyBundle) -> dict[str, bytes]:
    """
    Convert a PreKeyBundle into a dictionary of raw bytes for pickling.

    Iterates through each public key in the bundle, serializes it to its
    raw 32-byte form, and includes the one-time pre-key list and its index.

    Args:
        bundle: The PreKeyBundle to serialize.

    Returns:
        A dict mapping field names to bytes or lists of bytes.
    """
    # Serialize the one-time pre-key list to raw bytes
    one_time_serialized: list[bytes] = []
    for key in bundle["one_time_prekey_public_list"]:
        raw = key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        one_time_serialized.append(raw)

    return {
        # Raw encoding of X25519 keys yields 32-byte values
        "identity_public_key": bundle["identity_public_key"].public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        ),
        "signing_public_key": bundle["signing_public_key"].public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        ),
        "signed_prekey_public": bundle["signed_prekey_public"].public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        ),
        "signed_prekey_signature": bundle["signed_prekey_signature"],
        "one_time_prekey_public_list": one_time_serialized,
        "one_time_prekey_public_index": bundle["one_time_prekey_public_index"],
    }


def deserialize_prekey_bundle(data: dict[str, bytes]) -> PreKeyBundle:
    """
    Reconstruct a PreKeyBundle from a dict of raw bytes.

    Validates the input dict, deserializes each public key from its
    raw byte form, and rebuilds the one-time pre-key list.

    Args:
        data: A dict typically produced by `serialize_prekey_bundle`.

    Raises:
        TypeError: If `data` is not a dict.
        ValueError: If required keys are missing.

    Returns:
        A PreKeyBundle TypedDict with reconstructed key objects.
    """
    if not isinstance(data, dict):
        raise TypeError("Deserialized object is not a dict")

    # Ensure required fields are present
    expected = {"identity_public_key", "signing_public_key", "signed_prekey_public", "signed_prekey_signature", "one_time_prekey_public_list", "one_time_prekey_public_index"}
    if not expected.issubset(data):
        raise ValueError("Deserialized dict does not match PreKeyBundle structure")

    # Deserialize each one-time pre-key from raw bytes
    one_time_deserialized: list[X25519PublicKey] = []
    for raw in data["one_time_prekey_public_list"]:
        key_obj = X25519PublicKey.from_public_bytes(raw)
        one_time_deserialized.append(key_obj)

    return PreKeyBundle(
        identity_public_key=X25519PublicKey.from_public_bytes(
            data["identity_public_key"]
        ),
        signing_public_key=Ed25519PublicKey.from_public_bytes(
            data["signing_public_key"]
        ),
        signed_prekey_public=X25519PublicKey.from_public_bytes(
            data["signed_prekey_public"]
        ),
        signed_prekey_signature=data["signed_prekey_signature"],
        one_time_prekey_public_list=one_time_deserialized,
        one_time_prekey_public_index=data["one_time_prekey_public_index"]
    )
