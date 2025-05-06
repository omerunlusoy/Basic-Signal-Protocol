"""
ClientDatabaseSQLite.py

Provides an SQLite-backed storage layer for encrypted contacts and private messages,
with an in-memory cache for fast lookup and mutation.  Each contact stores associated
Signal-like state (profiles, pre-key bundles, Double Ratchet sessions), and each message
is pickled for secure persistence.
"""
import pickle
from datetime import datetime
from pathlib import Path
import sqlite3
from Contact import Contact, list_contact
from PrivateMessage import PrivateMessage
from Profile import Profile, serialize_profile, deserialize_profile
from DoubleRatchet import DoubleRatchetSession


class ClientDatabase:
    """
    A persistent client-side database for storing contacts and private messages.

    Attributes:
        database_path (str): Filesystem path to the SQLite database file.
        database_connection (sqlite3.Connection): Active connection handle.
        contacts (dict[str, Contact]): In-memory cache of all Contact objects.
        messages (dict[str, list[PrivateMessage]]): In-memory cache of message lists per contact.
    """

    def __init__(self, phone_number: str, password: str):
        """
        Initialize or open the SQLite database and load all data into memory.

        Args:
            phone_number: Unique identifier for this user (used as DB filename).
            password:    Password for optional file encryption (TODO: implement).
        """
        self.database_dir = "client_databases/"
        Path(self.database_dir).mkdir(parents=True, exist_ok=True)
        self.database_path = self.database_dir + f"{phone_number}.db"
        self.database_connection = sqlite3.connect(self.database_path)
        self.database_connection.row_factory = sqlite3.Row

        self._initialize_database_schema()
        self.contacts: dict[str, Contact] = {}
        self.messages: dict[str, list[PrivateMessage]] = {}
        self._load_from_database()

    def _initialize_database_schema(self) -> None:
        """
        Create 'contacts' and 'messages' tables if they do not yet exist.
        """
        cursor = self.database_connection.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            phone_number TEXT PRIMARY KEY,
            name           TEXT,
            phone_hashed   TEXT,
            profile_blob   BLOB,
            prekey_bundle_serialized  BLOB,
            x3dh_secret    BLOB,
            session_blob   BLOB
        )""")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id                          INTEGER PRIMARY KEY AUTOINCREMENT,
            sender                      TEXT,
            sender_phone_number         TEXT,
            receiver                    TEXT,
            message                     BLOB,
            timestamp                   TEXT,
            profile_serialized_encrypted BLOB,
            FOREIGN KEY(sender) REFERENCES contacts(phone_number)
        )""")
        self.database_connection.commit()

    def _load_from_database(self) -> None:
        """
        Load all persisted contacts and messages into the in-memory caches.
        """
        cursor = self.database_connection.cursor()

        # Load contacts
        for row in cursor.execute("SELECT * FROM contacts"):
            profile_blob = row["profile_blob"]
            profile_obj = deserialize_profile(profile_blob) if profile_blob else None

            session_blob = row["session_blob"]
            session_obj = DoubleRatchetSession.deserialize_session(session_blob) if session_blob else None

            contact = Contact(
                name=row["name"],
                phone_number=row["phone_number"],
                profile=profile_obj,
                phone_hashed=row["phone_hashed"],
                prekey_bundle_serialized=row["prekey_bundle_serialized"],
                x3dh_secret=row["x3dh_secret"],
                session=session_obj
            )
            self.contacts[row["phone_number"]] = contact

        # Load messages
        for row in cursor.execute(
            "SELECT sender, sender_phone_number, receiver, message, timestamp, profile_serialized_encrypted FROM messages ORDER BY timestamp"
        ):
            private_message = PrivateMessage(sender=row["sender"], receiver=row["receiver"], message=row["message"], is_initial_message=False, timestamp=row["timestamp"], profile_serialized_encrypted=pickle.loads(row["profile_serialized_encrypted"]))
            self.messages.setdefault(row["sender_phone_number"], []).append(private_message)

        # Ensure every contact has a message list
        for key in self.contacts:
            self.messages.setdefault(key, [])

    def delete_database(self) -> None:
        """
        Drop the 'messages' and 'contacts' tables if they exist,
        effectively resetting the database schema.
        """
        cursor = self.database_connection.cursor()
        # Turn off FK checks so we can drop contacts even if messages refer to it
        cursor.execute("PRAGMA foreign_keys = OFF;")
        # Drop in dependency order: messages first, then contacts
        cursor.execute("DROP TABLE IF EXISTS messages;")
        cursor.execute("DROP TABLE IF EXISTS contacts;")
        # Re-enable FK checks
        cursor.execute("PRAGMA foreign_keys = ON;")
        self.database_connection.commit()

    # contacts' operations
    def phone_number_in_contacts(self, phone_number: str) -> bool:
        """Return True if phone_number exists in contacts."""
        return phone_number in self.contacts

    def add_contact(self, name: str, phone_number: str, phone_hashed: str) -> bool:
        """Add or replace a contact in both memory and SQLite."""
        if self.phone_number_in_contacts(phone_number):
            return False
        self.database_connection.execute("""
            INSERT OR REPLACE INTO contacts
              (phone_number, name, phone_hashed)
            VALUES (?, ?, ?)
        """, (phone_number, name, phone_hashed))
        self.database_connection.commit()

        contact = Contact(
            name=name,
            phone_number=phone_number,
            profile=None,
            phone_hashed=phone_hashed,
            prekey_bundle_serialized=None,
            x3dh_secret=None,
            session=None
        )
        self.contacts[phone_number] = contact
        return True

    def get_contact(self, phone_number: str) -> Contact | None:
        """Retrieve a contact by phone number or return None."""
        return self.contacts.get(phone_number)

    def update_name(self, phone_number: str, contact_name: str) -> bool:
        """Update the display name of an existing contact."""
        if phone_number not in self.contacts:
            return False
        self.database_connection.execute("""
            UPDATE contacts
            SET name = ?
            WHERE phone_number = ?
        """, (contact_name, phone_number))
        self.database_connection.commit()
        self.contacts[phone_number]["name"] = contact_name
        return True

    def update_profile(self, sender_profile: Profile) -> None:
        """Store a new Profile blob for a contact."""
        sender_phone_number = sender_profile["phone_number"]
        blob = serialize_profile(sender_profile)
        self.database_connection.execute("""
            UPDATE contacts
            SET profile_blob = ?
            WHERE phone_number = ?
        """, (blob, sender_phone_number))
        self.database_connection.commit()
        self.contacts[sender_phone_number]["profile"] = sender_profile

    def update_prekey_bundle_serialized(self, phone_number: str, prekey_bundle_serialized: bytes) -> None:
        """Store an X3DH pre-key bundle for a contact."""
        self.database_connection.execute("""
            UPDATE contacts
            SET prekey_bundle_serialized = ?
            WHERE phone_number = ?
        """, (prekey_bundle_serialized, phone_number))
        self.database_connection.commit()
        self.contacts[phone_number]["prekey_bundle_serialized"] = prekey_bundle_serialized

    def update_x3dh_secret(self, phone_number: str, x3dh_secret: bytes) -> None:
        """Store the shared X3DH secret for a contact."""
        self.database_connection.execute("""
            UPDATE contacts
            SET x3dh_secret = ?
            WHERE phone_number = ?
        """, (x3dh_secret, phone_number))
        self.database_connection.commit()
        self.contacts[phone_number]["x3dh_secret"] = x3dh_secret

    def update_double_ratchet_session(self, phone_number: str, session: DoubleRatchetSession) -> None:
        """Persist updated DoubleRatchetSession for a contact."""
        blob = session.serialize_session()
        self.database_connection.execute("""
            UPDATE contacts
            SET session_blob = ?
            WHERE phone_number = ?
        """, (blob, phone_number))
        self.database_connection.commit()
        self.contacts[phone_number]["session"] = session

    # Lookup helpers

    def get_contact_name_and_number_from_hash(self, phone_hashed: str) -> tuple[str | None, str | None]:
        """Return (name, phone) for a given hashed phone, else (None, None)."""
        for ph, contact in self.contacts.items():
            if contact["phone_hashed"] == phone_hashed:
                return contact["name"], ph
        return None, None

    def get_phone_number_from_name(self, name: str) -> str | None:
        """Return the phone number for a given contact name."""
        for ph, contact in self.contacts.items():
            if contact["name"] == name:
                return ph
        return None

    def get_phone_number_from_profile_name(self, profile_name: str) -> str | None:
        """Return the phone number for a given profile name."""
        for ph, contact in self.contacts.items():
            prof = contact["profile"]
            if prof and prof["name"] == profile_name:
                return ph
        return None

    def list_contacts(self, profile_name: str) -> None:
        """Print all contacts for the user."""
        if not self.contacts:
            print(f"\n{profile_name} has no contacts.")
            return
        print(f"\n{profile_name}'s contacts:")
        for contact in self.contacts.values():
            list_contact(contact)

    # messages methods
    def create_empty_message_list_for(self, phone_number: str) -> None:
        """Delete all messages for a contact and clear the in-memory list."""
        self.database_connection.execute("""
            DELETE FROM messages
            WHERE sender = ?
        """, (phone_number,))
        self.database_connection.commit()
        self.messages[phone_number] = []

    def add_message_to(self, sender_phone: str, private_message: PrivateMessage) -> None:
        """Store a PrivateMessage in both memory and SQLite."""
        self.database_connection.execute("""
            INSERT INTO messages
              (sender, sender_phone_number, receiver, message, timestamp, profile_serialized_encrypted)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (private_message["sender"], sender_phone, private_message["receiver"], private_message["message"],
              private_message["timestamp"], pickle.dumps(private_message["profile_serialized_encrypted"])))
        self.database_connection.commit()
        self.messages.setdefault(sender_phone, []).append(private_message)

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
        """
        # If every sender’s list is empty, notify the user and return
        if not any(self.messages[s] for s in self.messages):
            print(f"No messages for {name}.")
            return

        print(f"\nMessages for {name}:")
        for sender_phone_number, msg_list in self.messages.items():
            if not msg_list:
                continue  # Skip empty lists

            # Sort this sender's messages by ISO timestamp
            msg_list.sort(key=lambda x: datetime.fromisoformat(x["timestamp"]))
            print(f"\tFrom {msg_list[-1]["sender"]}:")
            for msg in msg_list:
                print(f"\t\t({msg['timestamp']}): {msg['message']}")
