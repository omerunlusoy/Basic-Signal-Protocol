from typing import TypedDict
import pickle


class Profile(TypedDict):
    name: str | None
    phone_number: str
    about: str | None
    profile_picture: bytes | None


def serialize_profile(profile: Profile) -> bytes:
    return pickle.dumps({"name": profile["name"], "phone_number": profile["phone_number"], "about": profile["about"], "profile_picture": profile["profile_picture"]})


def deserialize_profile(data: bytes) -> Profile:
    data_ = pickle.loads(data)
    if not isinstance(data_, dict):
        raise TypeError("Deserialized object is not a dict")

    # Optionally check required keys
    expected_keys = {"name", "phone_number", "about", "profile_picture"}
    if not expected_keys.issubset(data_):
        raise ValueError("Deserialized dict does not match Profile structure")

    return Profile(name=data_["name"], phone_number=data_["phone_number"], about=data_["about"], profile_picture=data_["profile_picture"])
