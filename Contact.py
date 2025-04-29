"""
Contact class for the basic Signal protocol client.

Defines a `Contact` TypedDict to represent peer metadata and cryptographic state,
plus a helper function `list_contact` to display contact details succinctly.

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

from typing import TypedDict

from DoubleRatchet import DoubleRatchetSession
from Profile import Profile


class Contact(TypedDict):
    """
    Represents a peer in the user's contact list, including identity and crypto state.

    Fields:
        name: Optional label the user assigned to this contact.
        phone_number: The contact's phone number as a string.
        phone_hashed: Hashed phone number used as the unique ID on the server.
        profile: Deserialized Profile object received from this contact (may be None).
        prekey_bundle_serialized: The raw bytes of the contact's latest PreKeyBundle.
        x3dh_secret: Shared secret established via X3DH (None until handshake completes).
        session: Active DoubleRatchetSession for this contact (None before ratchet starts).
    """
    name: str | None
    phone_number: str
    phone_hashed: str
    profile: Profile | None
    prekey_bundle_serialized: bytes | None
    x3dh_secret: bytes | None
    session: DoubleRatchetSession | None


def list_contact(contact: Contact) -> None:
    """
    Print a summary of a single contact's information.

    The display varies depending on which profile fields are available:
      - If no profile data: show only the assigned name and phone number.
      - If profile.name present, include that label.
      - If profile.about present, include that description.

    Args:
        contact: A Contact TypedDict containing metadata and optional profile info.
    """
    profile = contact.get('profile')

    # Base output: user-assigned name and phone number
    base = f"\t{contact['name']}: phone number: {contact['phone_number']}"

    # If no profile or no name/about in profile, just print the base info
    if profile is None or (profile.get('name') is None and profile.get('about') is None):
        print(base)
        return

    # If only profile.name is set
    if profile.get('about') is None:
        print(f"{base}, profile name: {profile['name']}")
        return

    # If only profile.about is set
    if profile.get('name') is None:
        print(f"{base}, profile description: {profile['about']}")
        return

    # If both profile.name and profile.about are set
    print(f"{base}, profile name: {profile['name']}, profile description: {profile['about']}")
