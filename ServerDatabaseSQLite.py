"""
Server Database class for the Signal protocol server.
SQLite implementation.

Author: Ömer Ünlüsoy
Date:   7-May-2025
"""

import sqlite3
from pathlib import Path
from typing import Optional, List

from AES256 import AES256

class ServerDatabase:
    """
    SQLite-backed storage for server-side Signal protocol state:
      - `users` table: maps hashed phone → encrypted pre-key bundle
      - `messages` table: queued serialized messages per recipient
    In-memory caches mirror the tables for fast operations.
    """

    def __init__(self, db_name: str, admin_password_hashed: str, aes_cipher: AES256, verbose: bool = False):

        # create the directory (if not exist)
        database_dir = "databases/"
        Path(database_dir).mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(database_dir + db_name + ".db")
        self.conn.row_factory = sqlite3.Row

        self.aes_cipher = aes_cipher
        self.password_hashed = admin_password_hashed
        self.verbose = verbose

        # in-memory caches
        self.users: dict[str, bytes] = {}
        self.messages: dict[str, List[bytes]] = {}

    def initialize_server_database_schema(self) -> None:
        cursor = self.conn.cursor()
        # users: hashed phone as the primary key, store the encrypted bundle
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                phone_hashed    TEXT PRIMARY KEY,
                prekey_bundle   BLOB NOT NULL
            )""")
        # messages: auto-id, recipient hashed phone foreign key → users
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                receiver_hashed     TEXT NOT NULL,
                message_blob        BLOB NOT NULL,
                FOREIGN KEY(receiver_hashed) REFERENCES users(phone_hashed)
            )""")
        # admin: auto-id, recipient hashed phone foreign key → users
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin (
               id              INTEGER PRIMARY KEY AUTOINCREMENT,
               password_hashed BLOB NOT NULL,
               verbose         INTEGER NOT NULL
            )""")
        self.conn.commit()
        self.conn.execute(
            "INSERT INTO admin (password_hashed, verbose) VALUES (?, ?)",
            (self.aes_cipher.encrypts(self.password_hashed), int(self.verbose)),
        )
        self.conn.commit()
        if self.verbose:
            print("Database schema initialized.")

    def restore_database(self) -> None:
        # load users
        cursor = self.conn.cursor()
        for row in cursor.execute("SELECT phone_hashed, prekey_bundle FROM users"):
            # decrypt bundle bytes
            bundle = self.aes_cipher.decrypt(row["prekey_bundle"])
            self.users[row["phone_hashed"]] = bundle
            # ensure message box exists
            self.messages.setdefault(row["phone_hashed"], [])

        # load messages per recipient
        for row in cursor.execute(
            "SELECT receiver_hashed, message_blob FROM messages ORDER BY id"
        ):
            msg = self.aes_cipher.decrypt(row["message_blob"])
            self.messages.setdefault(row["receiver_hashed"], []).append(msg)

        if self.verbose:
            print("Database loaded from disk.")

    def phone_hashed_in_users(self, phone_hashed: str) -> bool:
        return phone_hashed in self.users

    def save_user_prekey_bundle_serialized(self, phone_hashed: str, prekey_bundle_serialized: bytes) -> None:
        enc = self.aes_cipher.encrypt(prekey_bundle_serialized)
        self.conn.execute(
            "INSERT OR REPLACE INTO users (phone_hashed, prekey_bundle) VALUES (?, ?)",
            (phone_hashed, enc),
        )
        self.conn.commit()
        # cache and message box
        self.users[phone_hashed] = prekey_bundle_serialized
        self.messages.setdefault(phone_hashed, [])
        if self.verbose:
            print(f"Saved bundle for {phone_hashed}")

    def fetch_user_prekey_bundle_serialized(self, phone_hashed: str) -> Optional[bytes]:
        bundle = self.users.get(phone_hashed)
        return bundle

    def save_message_serialized(self, receiver: str, message_serialized: bytes) -> None:
        enc = self.aes_cipher.encrypt(message_serialized)
        self.conn.execute(
            "INSERT INTO messages (receiver_hashed, message_blob) VALUES (?, ?)",
            (receiver, enc),
        )
        self.conn.commit()
        self.messages.setdefault(receiver, []).append(message_serialized)
        if self.verbose:
            print(f"Saved message for {receiver}")

    def initialize_message_box(self, receiver_phone_hashed: str) -> None:
        # ensure both DB row and in-memory list
        if receiver_phone_hashed not in self.messages:
            self.messages[receiver_phone_hashed] = []

    def fetch_receiver_messages_serialized(self, receiver_phone_hashed: str) -> List[bytes]:
        msgs = list(self.messages.get(receiver_phone_hashed, []))
        # delete from DB
        self.conn.execute(
            "DELETE FROM messages WHERE receiver_hashed = ?", (receiver_phone_hashed,)
        )
        self.conn.commit()
        # clear in-memory
        self.messages[receiver_phone_hashed] = []
        if self.verbose:
            print(f"Fetched and cleared {len(msgs)} messages for {receiver_phone_hashed}")
        return msgs

    def fetch_admin_password_hashed_and_verbose(self) -> tuple[str, bool]:
        res = self.conn.execute("""
                SELECT password_hashed, verbose
                FROM admin
                LIMIT 1
        """)
        row = res.fetchone()
        return self.aes_cipher.decrypts(row[0]), bool(row[1])

    # -- Debug helpers --
    def debug_list_users(self):
        """Print all registered users and their pre-key bundles (verbose mode only)."""
        print("\n--- Registered Users on Server ---")
        for uid, bundle in self.users.items():
            print(uid, bundle)
        print("------------------------\n")

    def debug_list_messages(self):
        """Print all queued messages (verbose mode only)."""
        print("\n--- Message Queue on Server ---")
        for id_, msg in self.messages.items():
            print(f"{{ id: {id_}, messages: {msg} }}")
        print("---------------------\n")
