"""

"""

from Double_Ratchet import DoubleRatchetSession
from Profile import Profile

from typing import TypedDict

class Contact(TypedDict):
    # name: (name, profile, port, prekey_bundle_serialized, x3dh_secret, DoubleRatchetSession)
    # name is how someone is added as a contact
    # profile.name is what someone sends to you
    name: str | None
    phone_number: str
    phone_hashed: str
    profile: Profile | None
    prekey_bundle_serialized: bytes | None
    x3dh_secret: bytes | None
    session: DoubleRatchetSession | None

def list_contact(contact: Contact) -> None:
    if contact['profile'] is None or (contact['profile']['name'] is None and contact['profile']['about'] is None):
        print(f"\t{contact['name']}, phone number: {contact['phone_number']}")
    elif contact['profile']['about'] is None:
        print(f"\t{contact['name']}: phone number: {contact['phone_number']}, profile name: {contact['profile']['name']}")
    elif contact['profile']['name'] is None:
        print(f"\t{contact['name']}: phone number: {contact['phone_number']}, profile description: {contact['profile']['about']}")
    else:
        print(f"\t{contact['name']}: phone number: {contact['phone_number']}, profile name: {contact['profile']['name']}, profile description: {contact['profile']['about']}")
