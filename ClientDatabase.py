"""
TODO:
    - check cryptography.fernet (https://dev.to/dev1721/do-you-wanna-keep-your-embedded-database-encrypted-5egk)
    - check SQLite 3's adaptors and converters (https://stackoverflow.com/questions/2047814/is-it-possible-to-store-python-class-objects-in-sqlite)
    - adaptor/converter solution might not be suitable for encrypted SQLite!

Author: Ömer Ünlüsoy
Date:   5-May-2025
"""

from Contact import Contact, list_contact
from PrivateMessage import PrivateMessage
from Profile import Profile
from DoubleRatchet import DoubleRatchetSession


class ClientDatabase:
    def __init__(self, phone_number: str, password: str):
        self.contacts: dict[str, Contact] | None = None
        self.messages: dict[str, list[PrivateMessage]] | None = None
        self.__fetch_from_database(phone_number=phone_number, password=password)

    # Contacts functions
    def phone_number_in_contacts(self, phone_number: str) -> bool:
        return phone_number in self.contacts

    def add_contact(self, name: str, phone_number: str, phone_hashed: str) -> bool:
        if self.phone_number_in_contacts(phone_number=phone_number):
            return False
        self.contacts[phone_number] = Contact(name=name, phone_number=phone_number, profile=None, phone_hashed=phone_hashed, prekey_bundle_serialized=None, x3dh_secret=None, session=None)
        return True

    def get_contact(self, phone_number: str) -> Contact | None:
        if self.phone_number_in_contacts(phone_number=phone_number):
            return self.contacts[phone_number]
        else:
            return None

    def update_name(self, phone_number: str, contact_name: str) -> bool:
        """Updates the name of a given contact."""
        if self.phone_number_in_contacts(phone_number=phone_number):
            self.contacts[phone_number]["name"] = contact_name
            return True
        else:
            return False

    def update_profile(self, sender_profile: Profile) -> None:
        """Updates the profile of a given contact."""
        self.contacts[sender_profile["phone_number"]]["profile"] = sender_profile

    def update_prekey_bundle_serialized(self, phone_number: str, prekey_bundle_serialized: bytes) -> None:
        """Updates the prekey bundle of a given contact."""
        self.contacts[phone_number]["prekey_bundle_serialized"] = prekey_bundle_serialized

    def update_x3dh_secret(self, phone_number: str, x3dh_secret: bytes) -> None:
        """Updates the x3dh secret of a given contact."""
        self.contacts[phone_number]["x3dh_secret"] = x3dh_secret

    def update_double_ratchet_session(self, phone_number: str, session: DoubleRatchetSession) -> None:
        """Updates the x3dh session of a given contact."""
        self.contacts[phone_number]["session"] = session

    def get_contact_name_and_number_from_hash(self, phone_hashed: str) -> tuple[str | None, str | None]:
        """
        Retrieve the name and phone number associated with a given hashed phone number.

        This method searches through the stored contacts. If a match is found,
        it returns the corresponding name (which can still be None) and phone
        number. If no match is found, it returns None for both values.

        Parameters:
            phone_hashed (str): The hashed phone number to search for.

        Returns:
            tuple[str | None, str | None]: A tuple where the first element is the
            name associated with the hashed phone number (or None if no match is
            found or the name is not saved along with the phone number), and the
            second element is the actual phone number (or None if no match is found).
        """
        # iterate over the contacts
        for phone_number, contact in self.contacts.items():
            # if the hashed phone numbers match, return the name and the phone number, the name can still be None
            if contact["phone_hashed"] == phone_hashed:
                return contact["name"], phone_number
        # if not found, return None
        return None, None

    def get_phone_number_from_name(self, name: str) -> str | None:
        """Retrieves the phone number associated with a given name."""
        for phone_number, contact in self.contacts.items():
            if contact["name"] == name:
                return phone_number
        return None

    def get_phone_number_from_profile_name(self, name: str) -> str | None:
        """Retrieves the phone number associated with a given profile name."""
        for phone_number, contact in self.contacts.items():
            if contact["profile"]["name"] is not None:
                if contact["profile"]["name"] == name:
                    return phone_number
        return None

    def list_contacts(self, profile_name) -> None:
        """Lists all contacts associated with the user's profile."""
        # check if there is any contact saved
        if self.contacts == {}:
            print(f"\n{profile_name} does not have any contacts.")
        else:
            print(f"\n{profile_name} has the following contacts:")
            # iterate within the contacts and list them one by one
            for _, contact in self.contacts.items():
                list_contact(contact)

    # Messages functions
    def create_empty_message_list_for(self, phone_number: str) -> None:
        self.messages[phone_number] = []

    def add_message_to(self, sender_phone_number: str, private_message: PrivateMessage) -> None:
        self.messages[sender_phone_number].append(private_message)

    def get_all_messages_for(self, sender_phone_number: str, sort: bool = True) -> list[PrivateMessage]:
        if sort:
            self.messages[sender_phone_number].sort(key=lambda x: x["timestamp"])
        return self.messages[sender_phone_number]

    def list_all_messages(self, name: str) -> None:
        """
        Print all stored messages for a user, grouped by sender and ordered by timestamp.

        Iterates through the `messages` dict (keyed by sender ID), sorts each sender’s
        message list chronologically, and prints them with timestamps. If no messages
        exist for any sender, prints a placeholder line.

        Args:
            name:     Display name of the message owner (for header text).
            messages: Mapping from sender ID to list of raw message dicts.
        """
        # If every sender’s list is empty, notify the user and return
        if not any(self.messages[s] for s in self.messages):
            print(f"No messages for {name}.")
            return

        print(f"\nMessages for {name}:")
        for sender, msg_list in self.messages.items():
            if not msg_list:
                continue  # Skip empty lists

            # Sort this sender's messages by ISO timestamp
            msg_list.sort(key=lambda x: x["timestamp"])
            print(f"\tFrom {msg_list[0]['sender']}:")
            for msg in msg_list:
                print(f"\t\t({msg['timestamp']}): {msg['message']}")

    def __fetch_from_database(self, phone_number: str, password: str):
        self.contacts = {}
        self.messages = {}
