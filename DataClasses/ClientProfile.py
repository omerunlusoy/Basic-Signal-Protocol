"""
ClientProfile class and helper functions for serializing and deserializing profiles
from/to JSON using JSON.

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

import pickle
from typing import TypedDict
from DataClasses.Profile import Profile, serialize_profile, deserialize_profile
from X3DH import X3DH

class ClientProfile(TypedDict):
    profile: Profile
    phone_hashed: str
    receivers_can_see_my_name: bool
    verbose: bool
    x3dh: X3DH

def serialize_client_profile(cp: ClientProfile) -> bytes:
    """
    Convert a ClientProfile TypedDict into a JSON-encoded bytes object.
    Any bytes values (e.g., from nested serializers) are Base64-encoded.
    """
    payload = {
        "profile": serialize_profile(cp["profile"]),
        "phone_hashed": cp["phone_hashed"],
        "receivers_can_see_my_name": cp["receivers_can_see_my_name"],
        "verbose": cp["verbose"],
        "x3dh": cp["x3dh"].serialize_x3dh(),
    }
    return pickle.dumps(payload)

def deserialize_client_profile(data: bytes) -> ClientProfile:
    """
    Reconstruct a ClientProfile TypedDict from a JSON-encoded bytes object.
    Decodes Base64 strings back to bytes for any fields that represent bytes.
    """
    obj = pickle.loads(data)
    if not isinstance(obj, dict):
        raise TypeError("Deserialized object is not a dict")

    # Ensure all expected keys are present
    expected_keys = {"profile", "phone_hashed", "receivers_can_see_my_name", "verbose", "x3dh"}
    if not expected_keys.issubset(obj):
        raise ValueError("Deserialized dict does not match ClientProfile structure")

    # reverse of serialize_profile: assume it handles nested structures
    return ClientProfile(
        profile=deserialize_profile(obj["profile"]),
        phone_hashed=obj["phone_hashed"],
        receivers_can_see_my_name=obj["receivers_can_see_my_name"],
        verbose=obj["verbose"],
        x3dh=X3DH.deserialize_x3dh(obj["x3dh"])
    )
