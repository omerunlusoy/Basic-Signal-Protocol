"""
Server-side implementation of the basic Signal protocol.

This module defines a `Server` class that listens for client connections on TCP port 12345
and handles registration, pre-key bundle distribution, and storage/retrieval of encrypted
messages (both initial handshake messages and regular messages) for a simple Signal-like
messaging system.

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

import socket
import pickle

from AES256 import AES256
from SHA256 import SHA256
from Argon2id import Argon2id

from DataClasses.PrekeyBundle import serialize_prekey_bundle, deserialize_prekey_bundle
from DataClasses.PrivateMessage import deserialize_private_message
from ServerDatabaseSQLite import ServerDatabase


class Server:
    """
    A Signal protocol server that manages user registrations, pre-key bundles,
    and relays encrypted messages between clients.

    Attributes:
        host (str):
            Hostname or IP address on which the server listens to.
        port (int):
            TCP port number on which the server listens to.
        database (ServerDatabase):
            The database instance to use for user management.
        verbose (bool):
            If True, prints debug information about registered users and message queues.
    """

    # class variables
    host = 'localhost'
    port = 12345

    def __init__(self) -> None:
        """
        Represents a basic initializer for an object with a database and a verbosity flag.

        This class's instance variables are defined for managing a database connection
        and controlling the verbosity level. The database attribute is initialized as
        None, and the verbose attribute is a boolean flag set to False by default.

        Variables:
            database: Represents the database connection. Initialized as None.
            verbose: A boolean flag indicating whether verbose mode is enabled.
                Defaults to False.
        """
        self.database = None
        self.verbose: bool = False

    def register_server(self, admin_username: str, admin_password: str, verbose: bool = False):
        # hashers and cipher
        argon_hasher = Argon2id(admin_password)
        aes_cipher = AES256(admin_password)

        # hash admin password
        password_hashed = argon_hasher.hash(admin_password, variable_salt=admin_username)

        self.database = ServerDatabase(db_name=self.__hash(admin_username), admin_password_hashed=password_hashed, aes_cipher=aes_cipher, verbose=verbose)
        self.database.initialize_server_database_schema()
        self.verbose = verbose

    def login_server(self, admin_username: str, admin_password: str):
        # hashers and cipher
        argon_hasher = Argon2id(admin_password)
        aes_cipher = AES256(admin_password)

        # hash admin password
        password_hashed = argon_hasher.hash(admin_password, variable_salt=admin_username)

        # initialize the database and get the admin password hashed
        self.database = ServerDatabase(db_name=self.__hash(admin_username), admin_password_hashed=password_hashed, aes_cipher=aes_cipher, verbose=False)
        password_hashed, self.verbose = self.database.fetch_admin_password_hashed_and_verbose()

        verify_login_ = argon_hasher.verify(data_hashed=password_hashed, data=admin_password, variable_salt=admin_username)
        if not verify_login_:
            print("Incorrect password!")
            return
        else:
            self.database.restore_database()

    def __create_account(self, phone_hashed: str, prekey_bundle_serialized: bytes) -> bool:
        """
        Register a new user by storing their pre-key bundle.

        Args:
            phone_hashed: Hashed phone number to use as unique user ID.
            prekey_bundle_serialized: The user’s serialized PreKeyBundle object.

        Returns:
            True if the account was created; False if it already exists.
        """
        # check if the user already exists
        if self.database.phone_hashed_in_users(phone_hashed):
            return False
        self.database.save_user_prekey_bundle_serialized(phone_hashed, prekey_bundle_serialized)
        return True

    def __fetch_prekey_bundle_serialized(self, phone_hashed: str) -> bytes | None:
        """
        Retrieve and rotate a user’s pre-key bundle for a handshake.

        Increments the one-time pre-key index before returning.

        Args:
            phone_hashed: Recipient’s hashed phone number.

        Returns:
            The serialized PreKeyBundle if the user exists; otherwise None.
        """
        bundle_serialized = self.database.fetch_user_prekey_bundle_serialized(phone_hashed)
        if bundle_serialized is None:
            return None

        # Rotate one-time pre-key index
        bundle = deserialize_prekey_bundle(bundle_serialized)
        bundle["one_time_prekey_public_index"] += 1
        bundle_serialized = serialize_prekey_bundle(bundle)

        # also need to update the database
        self.database.save_user_prekey_bundle_serialized(phone_hashed, bundle_serialized)
        return bundle_serialized

    def __save_message_on_server(self, message_serialized: bytes) -> None:

        # deserialize a message to verify both sender and receiver are registered users
        message = deserialize_private_message(message_serialized)

        sender, receiver = message["sender"], message["receiver"]
        # if not self.database.phone_hashed_in_users(sender) or not self.database.phone_hashed_in_users(receiver):
        #     return "Error: invalid private message!".encode("utf-8")
        self.database.save_message_serialized(receiver, message_serialized)

    def __fetch_my_messages(self, receiver_phone_hashed: str) -> list[bytes]:
        """
        Collect and remove all messages addressed to a given user.

        Args:
            receiver_phone_hashed: Hashed phone number of the requesting client.

        Returns:
            List of serialized PrivateMessage objects for delivery.
        """
        messages_serialized = self.database.fetch_receiver_messages_serialized(receiver_phone_hashed)

        if self.verbose:
            self._debug_list_messages()
        return messages_serialized

    def __analyze_request(self, request: tuple) -> bytes | list[bytes] | str:
        """
        Dispatch a client request tuple to the appropriate handler.

        Supported requests:
          - ("register", phone_hashed, serialized_prekey_bundle)
          - ("fetch_prekey_bundle", sender_phone_hashed, receiver_phone_hashed)
          - ("initial_message", serialized_PrivateMessage)
          - ("private_message", serialized_PrivateMessage)
          - ("check_for_messages", receiver_phone_hashed)

        Args:
            request: Tuple received from the client after unpickling.

        Returns:
            Either a serialized response (bytes) or status string.
        """
        command = request[0]

        if command == "register":
            # Unpack and deserialize pre-key bundle
            phone_hashed, bundle_serialized = request[1], request[2]
            success = self.__create_account(phone_hashed, bundle_serialized)
            if self.verbose:
                self._debug_list_users()
            return "Account created successfully!".encode("utf-8") if success else "Error: account already exists!".encode("utf-8")

        elif command == "fetch_prekey_bundle":
            # Client asks for another user’s bundle
            # request[1] is the sender of the request
            receiver = request[2]
            prekey_bundle_serialized = self.__fetch_prekey_bundle_serialized(receiver)
            if prekey_bundle_serialized is None:
                return "Error: no account found!".encode("utf-8")
            return prekey_bundle_serialized

        elif command in ("initial_message", "private_message"):
            # Store incoming PrivateMessage on server queue
            message_serialized = request[1]
            self.__save_message_on_server(message_serialized)
            if self.verbose:
                self._debug_list_messages()
            return ("Double Ratchet initial message stored on server.".encode("utf-8")
                    if command == "initial_message"
                    else "Message stored on server.".encode("utf-8"))

        elif command == "check_for_messages":
            # Client requests its queued messages
            receiver = request[1]
            # if receiver not in self.users:
            #     return "Error: invalid private message!".encode("utf-8")
            return self.__fetch_my_messages(receiver)

        else:
            return "Error: invalid message!".encode("utf-8")

    def loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((Server.host, Server.port))
        sock.listen()

        # server is listening
        if self.verbose:
            print(f"Server listening on {Server.host}:{Server.port}...")

        # main server loop
        try:
            while True:
                conn, addr = sock.accept()
                if self.verbose:
                    print(f"Connection from {addr}")
                # handle each client in its own small try/except
                try:
                    with conn:
                        while True:
                            raw_len = Server.__recv_all(conn, 4)
                            # if the client cleanly closed, raw_len will be zero‐lengths
                            if not raw_len:
                                break
                            length = int.from_bytes(raw_len, 'big')
                            data = Server.__recv_all(conn, length)
                            request = pickle.loads(data)
                            response = self.__analyze_request(request)
                            out = pickle.dumps(response)
                            conn.sendall(len(out).to_bytes(4, 'big') + out)
                except ConnectionError:
                    if self.verbose:
                        print(f"Client {addr} disconnected.")
                except Exception as e:
                    # log unexpected per-client errors but keep the server up
                    print(f"Error handling client {addr}: {e}")
        except KeyboardInterrupt:
            print("\nServer shutting down.")
        finally:
            sock.close()
            if self.verbose:
                print("Server closed.")
                self._debug_list_users()
                self._debug_list_messages()

    @staticmethod
    def __recv_all(socket_, length_: int) -> bytes:
        data = b''
        while len(data) < length_:
            packet = socket_.recv(length_ - len(data))
            if not packet:
                raise ConnectionError("Socket connection broken")
            data += packet
        return data

    # -- Debug helpers --
    def _debug_list_users(self):
        self.database.debug_list_users()

    def _debug_list_messages(self):
        self.database.debug_list_messages()

    @staticmethod
    def __hash(phone_number: str) -> str:
        """Hashes a phone number using hashlib's SHA256."""
        return SHA256(pepper="").hash(phone_number, salt="")
