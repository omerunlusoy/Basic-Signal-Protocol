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
from typing import Optional, Tuple

from AES256 import AES256
from DataClasses.Contact import Contact, list_contact
from DataClasses.PrivateMessage import PrivateMessage
from DataClasses.Profile import Profile, serialize_profile, deserialize_profile
from DoubleRatchet import DoubleRatchetSession
from HMAC import HMAC
from SHA256 import SHA256


class ClientDatabase:
    """
    A persistent client-side database for storing contacts and private messages.

    Attributes:
        database_path (str): Filesystem path to the SQLite database file.
        database_connection (sqlite3.Connection): Active connection handle.
        contacts (dict[str, Contact]): In-memory cache of all Contact objects.
        messages (dict[str, list[PrivateMessage]]): In-memory cache of message lists per contact.
    """

    def __init__(self, phone_number_hashed: str, aes_cipher: AES256, hmac_hasher: HMAC):
        """
        Initializes an instance of the class for handling encrypted message and contact storage
        on a local SQLite database. During initialization, it ensures the database directory is
        created, connects to the SQLite database, and sets up AES cipher and HMAC hasher for
        encryption and hashing respectively. Two in-memory dictionaries for storing contacts and
        messages are also initialized.

        Args:
            phone_number_hashed: The hashed phone number used to uniquely identify the
                user's database.
            aes_cipher: The AES cipher used for encrypting and decrypting sensitive data.
            hmac_hasher: The HMAC hasher instance used for hashing sensitive data.
        """
        # create directory
        self.database_dir = "databases/"
        Path(self.database_dir).mkdir(parents=True, exist_ok=True)

        # database path
        self.database_path = self.database_dir + f"{phone_number_hashed}.db"
        self.database_connection = sqlite3.connect(self.database_path)
        self.database_connection.row_factory = sqlite3.Row

        # aes_cipher and hmac_hasher
        self.aes_cipher = aes_cipher
        self.hmac_hasher = hmac_hasher

        # in memory
        self.contacts: dict[str, Contact] = {}
        self.messages: dict[str, list[PrivateMessage]] = {}

    def save_client_profile(self, client_profile_encrypted: bytes, password_hashed: str) -> bool:
        """
            Returns False if the 'client_profile' table already exists.
            Otherwise, creates it, inserts the given row, commits, and returns True.
        """

        # 1) check for table existence
        res = self.database_connection.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            AND name = 'client_profile'
            """)
        if res.fetchone():
            # table already exists → do nothing
            return False

        # 2) create the table
        self.database_connection.execute("""
            CREATE TABLE client_profile (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_encrypted BLOB NOT NULL,
                password_hashed   TEXT NOT NULL
            )""")

        # 3) insert the provided data
        self.database_connection.execute("""
            INSERT INTO client_profile 
                (profile_encrypted, password_hashed) 
            VALUES (?, ?)
            """, (client_profile_encrypted, password_hashed))

        self.database_connection.commit()
        return True

    def get_client_profile(self) -> Optional[Tuple[bytes, str]]:
        """
        Fetch the stored client_profile if it exists.
        Returns a tuple (profile_encrypted, password_hashed),
        or None if no table or no row is found.
        """

        # Make sure the table exists
        res = self.database_connection.execute("""
            SELECT name
              FROM sqlite_master
             WHERE type='table'
               AND name='client_profile'
        """)
        if not res.fetchone():
            return None

        # Fetch the first (and only) row
        res = self.database_connection.execute("""
            SELECT profile_encrypted, password_hashed
              FROM client_profile
             LIMIT 1
        """)
        row = res.fetchone()
        return (row[0], row[1]) if row else None

    def initialize_database_schema(self) -> None:
        """
        Create 'contacts' and 'messages' tables if they do not yet exist.
        """
        cursor = self.database_connection.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            phone_number TEXT PRIMARY KEY,
            name           TEXT,
            phone_hashed   TEXT,
            phone_hmac     TEXT,
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

    def load_from_database(self) -> None:
        """
        Load all persisted contacts and messages into the in-memory caches.
        """
        cursor = self.database_connection.cursor()

        # Load contacts
        for row in cursor.execute("SELECT * FROM contacts"):
            profile_blob = self.aes_cipher.decrypt(row["profile_blob"])
            profile_obj = deserialize_profile(profile_blob) if profile_blob else None

            session_blob = self.aes_cipher.decrypt(row["session_blob"])
            session_obj = DoubleRatchetSession.deserialize_session(session_blob) if session_blob else None

            contact = Contact(
                name=self.aes_cipher.decrypts(row["name"]),
                phone_number=self.aes_cipher.decrypts(row["phone_number"]),
                profile=profile_obj,
                phone_hashed=self.aes_cipher.decrypts(row["phone_hashed"]),
                prekey_bundle_serialized=self.aes_cipher.decrypt(row["prekey_bundle_serialized"]),
                x3dh_secret=self.aes_cipher.decrypt(row["x3dh_secret"]),
                session=session_obj
            )
            self.contacts[self.aes_cipher.decrypts(row["phone_number"])] = contact

        # Load messages
        for row in cursor.execute(
            "SELECT sender, sender_phone_number, receiver, message, timestamp, profile_serialized_encrypted FROM messages ORDER BY timestamp"
        ):
            private_message = PrivateMessage(sender=self.aes_cipher.decrypts(row["sender"]), receiver=self.aes_cipher.decrypts(row["receiver"]), message=self.aes_cipher.decrypts(row["message"]), is_initial_message=False, timestamp=self.aes_cipher.decrypts(row["timestamp"]), profile_serialized_encrypted=pickle.loads(self.aes_cipher.decrypt(row["profile_serialized_encrypted"])))
            self.messages.setdefault(self.aes_cipher.decrypts(row["sender_phone_number"]), []).append(private_message)

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
              (phone_number, name, phone_hashed, phone_hmac)
            VALUES (?, ?, ?, ?)
        """, (self.aes_cipher.encrypts(phone_number), self.aes_cipher.encrypts(name), self.aes_cipher.encrypts(phone_hashed), self.hmac_hasher.hash(phone_number)))
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
            WHERE phone_hmac = ?
        """, (self.aes_cipher.encrypts(contact_name), self.hmac_hasher.hash(phone_number)))
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
            WHERE phone_hmac = ?
        """, (self.aes_cipher.encrypt(blob), self.hmac_hasher.hash(sender_phone_number)))
        self.database_connection.commit()
        self.contacts[sender_phone_number]["profile"] = sender_profile

    def update_prekey_bundle_serialized(self, phone_number: str, prekey_bundle_serialized: bytes) -> None:
        """Store an X3DH pre-key bundle for a contact."""
        self.database_connection.execute("""
            UPDATE contacts
            SET prekey_bundle_serialized = ?
            WHERE phone_hmac = ?
        """, (self.aes_cipher.encrypt(prekey_bundle_serialized), self.hmac_hasher.hash(phone_number)))
        self.database_connection.commit()
        self.contacts[phone_number]["prekey_bundle_serialized"] = prekey_bundle_serialized

    def update_x3dh_secret(self, phone_number: str, x3dh_secret: bytes) -> None:
        """Store the shared X3DH secret for a contact."""
        self.database_connection.execute("""
            UPDATE contacts
            SET x3dh_secret = ?
            WHERE phone_hmac = ?
        """, (self.aes_cipher.encrypt(x3dh_secret), self.hmac_hasher.hash(phone_number)))
        self.database_connection.commit()
        self.contacts[phone_number]["x3dh_secret"] = x3dh_secret

    def update_double_ratchet_session(self, phone_number: str, session: DoubleRatchetSession) -> None:
        """Persist updated DoubleRatchetSession for a contact."""
        blob = session.serialize_session()
        self.database_connection.execute("""
            UPDATE contacts
            SET session_blob = ?
            WHERE phone_hmac = ?
        """, (self.aes_cipher.encrypt(blob), self.hmac_hasher.hash(phone_number)))
        self.database_connection.commit()
        self.contacts[phone_number]["session"] = session

    # Lookup helpers

    def get_contact_name_and_number_from_hash(self, phone_hashed: str, sha: SHA256) -> tuple[str | None, str | None]:
        """Return (name, phone) for a given hashed phone, else (None, None)."""
        for ph, contact in self.contacts.items():
            if sha.verify(phone_hashed, contact["phone_number"], ""):
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
        self.messages[phone_number] = []

    def add_message_to(self, sender_phone: str, private_message: PrivateMessage) -> None:
        """Store a PrivateMessage in both memory and SQLite."""
        self.database_connection.execute("""
            INSERT INTO messages
              (sender, sender_phone_number, receiver, message, timestamp, profile_serialized_encrypted)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (self.aes_cipher.encrypts(private_message["sender"]), self.aes_cipher.encrypts(sender_phone), self.aes_cipher.encrypts(private_message["receiver"]),
              self.aes_cipher.encrypts(private_message["message"]),
              self.aes_cipher.encrypts(private_message["timestamp"]), self.aes_cipher.encrypt(pickle.dumps(private_message["profile_serialized_encrypted"]))))
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
