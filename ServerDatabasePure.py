"""

"""
from AES256 import AES256
from Argon2id import Argon2id
from HMAC import HMAC


class ServerDatabase:

    def __init__(self, password_hashed: str, argon_hasher: Argon2id, aes_cipher: AES256, hmac_hasher: HMAC, verbose: bool):

        # users and messages dicts
        self.users: dict[str, bytes] | None = None
        self.messages: dict[str: list[bytes]] | None = None

        # hashers and cipher
        self.argon_hasher = argon_hasher
        self.aes_cipher = aes_cipher
        self.hmac_hasher = hmac_hasher

        # save password hashed
        self.password_hashed = password_hashed
        self.verbose = verbose

    def initialize_server_database_schema(self, db_name: str):
        self.users = {}
        self.messages = {}

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

    def restore_database(self, db_name: str) -> None:
        return
