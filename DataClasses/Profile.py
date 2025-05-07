"""
Profile class and helper functions for serializing and deserializing profiles
from/to bytes using pickle.

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

from typing import TypedDict
import pickle


class Profile(TypedDict):
    """
    TypedDict representing a user's profile information.

    Attributes:
        name: Optional display name of the user.
        phone_number: The user's phone number (always present).
        about: Optional 'about me' text for the user.
        profile_picture: Optional raw bytes of the user's profile picture.
    """
    name: str | None
    phone_number: str
    about: str | None
    profile_picture: bytes | None

def serialize_profile(profile: Profile) -> bytes:
    """
    Convert a Profile object into a bytes payload for storage or transmission.

    Internally uses pickle to dump a dictionary containing the profile fields.

    Args:
        profile: The Profile TypedDict to serialize.

    Returns:
        A bytes object containing the pickled profile data.
    """
    # Build a plain dict to ensure only the expected fields are serialized
    payload = {
        "name": profile["name"],
        "phone_number": profile["phone_number"],
        "about": profile["about"],
        "profile_picture": profile["profile_picture"]
    }
    return pickle.dumps(payload)

def deserialize_profile(data: bytes) -> Profile:
    """
    Reconstruct a Profile object from bytes' payload.

    Unpickles the data and validates that it is a dict matching the Profile schema.

    Args:
        data: Bytes object previously produced by serialize_profile.

    Raises:
        TypeError: If the unpickled object is not a dict.
        ValueError: If 'required profile keys' are missing.

    Returns:
        A Profile TypedDict populated with the deserialized values.
    """
    obj = pickle.loads(data)
    if not isinstance(obj, dict):
        raise TypeError("Deserialized object is not a dict")

    # Ensure all expected keys are present
    expected_keys = {"name", "phone_number", "about", "profile_picture"}
    if not expected_keys.issubset(obj):
        raise ValueError("Deserialized dict does not match Profile structure")

    # Return as a Profile TypedDict
    return Profile(
        name=obj["name"],
        phone_number=obj["phone_number"],
        about=obj["about"],
        profile_picture=obj["profile_picture"]
    )
