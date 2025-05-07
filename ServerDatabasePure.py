"""
Server Database class for the Signal protocol server.
in memory implementation.

Author: Ömer Ünlüsoy
Date:   7-May-2025
"""
from AES256 import AES256


class ServerDatabase:

    def __init__(self, db_name: str, admin_password_hashed: str, aes_cipher: AES256, verbose: bool):

        # database name
        self.db_name = db_name

        # users and messages dicts
        self.users: dict[str, bytes] | None = None
        self.messages: dict[str: list[bytes]] | None = None

        # hashers and cipher
        self.aes_cipher = aes_cipher

        # save password hashed
        self.password_hashed = admin_password_hashed
        self.verbose = verbose

    def initialize_server_database_schema(self):
        self.users = {}
        self.messages = {}

    def restore_database(self) -> None:
        return

    def phone_hashed_in_users(self, phone_hashed) -> bool:
        return phone_hashed in self.users

    def save_user_prekey_bundle_serialized(self, phone_hashed: str, prekey_bundle_serialized: bytes) -> None:
        self.users[phone_hashed] = prekey_bundle_serialized
        self.initialize_message_box(phone_hashed)

    def fetch_user_prekey_bundle_serialized(self, phone_hashed) -> bytes | None:
        return self.users.get(phone_hashed)

    def save_message_serialized(self, receiver: str, message_serialized: bytes):
        self.messages[receiver].append(message_serialized)

    def initialize_message_box(self, receiver_phone_hashed):
        if receiver_phone_hashed not in self.messages:
            self.messages[receiver_phone_hashed] = []

    def fetch_receiver_messages_serialized(self, receiver_phone_hashed: str) -> list[bytes]:
        message_list = self.messages[receiver_phone_hashed]
        self.messages[receiver_phone_hashed] = []
        return message_list

    def fetch_admin_password_hashed(self) -> str:
        return self.password_hashed

    def fetch_verbose(self) -> bool:
        return self.verbose
