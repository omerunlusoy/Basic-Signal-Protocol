from typing import TypedDict
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

class PreKeyBundle(TypedDict):
    identity_public_key: X25519PublicKey
    signing_public_key: Ed25519PublicKey
    signed_prekey_public: X25519PublicKey
    signed_prekey_signature: bytes
    one_time_prekey_public_list: list[X25519PublicKey]
    one_time_prekey_public_index: int

def serialize_prekey_bundle(bundle: PreKeyBundle) -> dict[str, bytes]:
    """
    Turn a PreKeyBundle into a plain dict of bytes so it can be pickled.
    """

    one_time_prekey_public_list_serialized = []
    for key in bundle["one_time_prekey_public_list"]:
        one_time_prekey_public_list_serialized.append(key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw))

    return {
        # X25519PublicKey.public_bytes([...Raw…]) → 32 bytes
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
        "one_time_prekey_public_list": one_time_prekey_public_list_serialized,
        "one_time_prekey_public_index": bundle["one_time_prekey_public_index"],
    }

def deserialize_prekey_bundle(data: dict[str, bytes]) -> PreKeyBundle:
    """
    Reconstruct the PreKeyBundle from the dict of raw bytes.
    """
    if not isinstance(data, dict):
        raise TypeError("Deserialized object is not a dict")

    # Optionally check required keys
    expected_keys = {"signed_prekey_signature", "one_time_prekey_public_list", "one_time_prekey_public_index"}
    if not expected_keys.issubset(data):
        raise ValueError("Deserialized dict does not match PreKeyBundle structure")

    one_time_prekey_public_list_deserialized = []
    for key in data["one_time_prekey_public_list"]:
        one_time_prekey_public_list_deserialized.append(X25519PublicKey.from_public_bytes(key))

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
        one_time_prekey_public_list=one_time_prekey_public_list_deserialized,
        one_time_prekey_public_index=data["one_time_prekey_public_index"]
    )
