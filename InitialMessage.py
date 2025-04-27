from typing import TypedDict
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey


class InitialMessage(TypedDict):
    """
    A typed dictionary representing the initial handshake message from the initiator.

    Fields:
        initiator_identity_public_key: The initiator's long-term X25519 public key.
        initiator_ephemeral_public_key: The initiator's ephemeral X25519 public key.
    """
    initiator_identity_public_key: X25519PublicKey
    initiator_ephemeral_public_key: X25519PublicKey
    one_time_prekey_public_index: int

def serialize_initial_message(message: InitialMessage) -> dict[str, bytes]:
    """
    Turn an InitialMessage into a plain dict of bytes so it can be pickled.
    """
    return {
        # X25519PublicKey.public_bytes([...Raw…]) → 32 bytes
        "initiator_identity_public_key": message["initiator_identity_public_key"].public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        ),
        "initiator_ephemeral_public_key": message["initiator_ephemeral_public_key"].public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        ),
        "one_time_prekey_public_index": message["one_time_prekey_public_index"]
    }

def deserialize_initial_message(data: dict[str, bytes]) -> InitialMessage:
    """
    Reconstruct the InitialMessage from the dict of raw bytes.
    """
    return InitialMessage(
        initiator_identity_public_key=X25519PublicKey.from_public_bytes(
            data["initiator_identity_public_key"]
        ),
        initiator_ephemeral_public_key=X25519PublicKey.from_public_bytes(
            data["initiator_ephemeral_public_key"]
        ),
        one_time_prekey_public_index = data["one_time_prekey_public_index"]
    )