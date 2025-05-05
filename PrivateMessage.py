"""
PrivateMessage serialization and display utilities.

Defines a TypedDict for end-to-end encrypted messages exchanged via the Signal-like protocol,
provides helpers to serialize/deserialize both initial handshake messages and regular messages,
and prints stored messages in timestamp order.

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

from typing import TypedDict, Tuple, Any

from InitialMessage import InitialMessage, serialize_initial_message, deserialize_initial_message


class PrivateMessage(TypedDict):
    """
    TypedDict representing an encrypted message envelope.

    Attributes:
        sender:        Hashed ID of the message sender.
        receiver:      Hashed ID of the message recipient.
        message:       Payload, which may be:
                         - InitialMessage for X3DH handshake,
                         - bytes for Double Ratchet ciphertext,
                         - or a raw string for testing/debugging.
        is_initial_message: True if this is part of the X3DH handshake.
        timestamp:     ISO-formatted timestamp when the message was created.
        profile_serialized_encrypted:
                       Optional encrypted sender profile attached to the message.
    """
    sender: str
    receiver: str
    message: str | bytes | InitialMessage
    is_initial_message: bool
    timestamp: str
    profile_serialized_encrypted: Tuple[bytes, bytes, bytes] | bytes | None

def serialize_private_message(message: PrivateMessage) -> dict[str, Any]:
    """
    Prepare a PrivateMessage for transport/storage by converting it into a plain dict.

    If `is_initial_message` is True, the `message` field is an InitialMessage object
    that must itself be serialized via `serialize_initial_message`. Otherwise, the
    message payload is left unchanged (bytes or str).

    Args:
        message: A PrivateMessage TypedDict to serialize.

    Returns:
        A dict with the same keys, where the 'message' field is serialized if needed.
    """
    if message["is_initial_message"]:
        # Serialize the InitialMessage payload for X3DH handshake
        serialized = serialize_initial_message(message["message"])
    else:
        # Leave Double Ratchet ciphertext or plain text unchanged
        serialized = message["message"]

    return {
        "sender": message["sender"],
        "receiver": message["receiver"],
        "message": serialized,
        "is_initial_message": message["is_initial_message"],
        "timestamp": message["timestamp"],
        "profile_serialized_encrypted": message["profile_serialized_encrypted"]
    }

def deserialize_private_message(data: dict[str, Any]) -> PrivateMessage:
    """
    Reconstruct a PrivateMessage TypedDict from a plain dict.

    Validates that `data` is a dict with the required keys. If `is_initial_message`
    is True, the 'message' field is passed through `deserialize_initial_message`.

    Args:
        data: A dict, typically produced by `serialize_private_message`.

    Raises:
        TypeError: If `data` is not a dict.
        ValueError: If 'required keys' are missing.

    Returns:
        A fully typed PrivateMessage object.
    """
    if not isinstance(data, dict):
        raise TypeError("Deserialized object is not a dict")

    expected_keys = {"sender", "receiver", "message", "is_initial_message", "timestamp"}
    if not expected_keys.issubset(data):
        raise ValueError("Deserialized dict does not match PrivateMessage structure")

    if data["is_initial_message"]:
        # Deserialize the InitialMessage payload for X3DH handshake
        msg = deserialize_initial_message(data["message"])
    else:
        # Use raw bytes or str for Double Ratchet messages
        msg = data["message"]

    return PrivateMessage(
        sender=data["sender"],
        receiver=data["receiver"],
        message=msg,
        is_initial_message=data["is_initial_message"],
        timestamp=data["timestamp"],
        profile_serialized_encrypted=data.get("profile_serialized_encrypted")
    )
