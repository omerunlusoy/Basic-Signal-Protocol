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

from PrekeyBundle import PreKeyBundle, serialize_prekey_bundle, deserialize_prekey_bundle
from PrivateMessage import PrivateMessage, serialize_private_message, deserialize_private_message


class Server:
    """
    A Signal protocol server that manages user registrations, pre-key bundles,
    and relays encrypted messages between clients.

    Attributes:
        users (dict[str, PreKeyBundle]):
            Maps each user’s hashed phone number to their current pre-key bundle.
        messages (list[PrivateMessage]):
            Queue of pending PrivateMessage objects stored for delivery.
        host (str):
            Hostname or IP address on which the server listens.
        port (int):
            TCP port number on which the server listens.
        verbose (bool):
            If True, prints debug information about registered users and message queues.
    """

    def __init__(self, host: str = 'localhost', port: int = 12345, verbose: bool = False):
        """
        Initialize server state and start the listening loop.

        Args:
            host: Address to bind the server socket to.
            port: Port to listen for incoming client connections.
            verbose: Enable debug output if True.
        """
        self.users: dict[str, PreKeyBundle] = {}
        self.messages: list[PrivateMessage] = []
        self.host = host
        self.port = port
        self.verbose = verbose
        self._server_loop()

    def __create_account(self, phone_hashed: str, prekey_bundle: PreKeyBundle) -> bool:
        """
        Register a new user by storing their pre-key bundle.

        Args:
            phone_hashed: Hashed phone number to use as unique user ID.
            prekey_bundle: The user’s PreKeyBundle object.

        Returns:
            True if the account was created; False if it already exists.
        """
        if phone_hashed in self.users:
            return False
        self.users[phone_hashed] = prekey_bundle
        return True

    def __fetch_prekey_bundle(self, phone_hashed: str) -> PreKeyBundle | None:
        """
        Retrieve and rotate a user’s pre-key bundle for a handshake.

        Increments the one-time pre-key index before returning.

        Args:
            phone_hashed: Recipient’s hashed phone number.

        Returns:
            The PreKeyBundle if the user exists; otherwise None.
        """
        bundle = self.users.get(phone_hashed)
        if bundle is None:
            return None
        # Rotate one-time pre-key index
        bundle["one_time_prekey_public_index"] += 1
        return bundle

    def __analyze_request(self, request: tuple) -> bytes | str:
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
            phone_hashed, bundle_data = request[1], request[2]
            prekey_bundle = deserialize_prekey_bundle(bundle_data)
            success = self.__create_account(phone_hashed, prekey_bundle)
            if self.verbose:
                self._debug_list_users()
            return "Account created successfully!" if success else "Error: account already exists!"

        elif command == "fetch_prekey_bundle":
            # Client asks for another user’s bundle
            # request[1] is the sender of the request
            receiver = request[2]
            prekey_bundle = self.__fetch_prekey_bundle(receiver)
            if prekey_bundle is None:
                return "Error: no account found!"
            return serialize_prekey_bundle(prekey_bundle)

        elif command in ("initial_message", "private_message"):
            # Store incoming PrivateMessage on server queue
            msg = deserialize_private_message(request[1])
            sender, receiver = msg["sender"], msg["receiver"]
            if sender not in self.users or receiver not in self.users:
                return "Error: invalid private message!"
            self.messages.append(msg)
            if self.verbose:
                self._debug_list_messages()
            return ("Double Ratchet initial message stored on server."
                    if command == "initial_message"
                    else "Message stored on server.")

        elif command == "check_for_messages":
            # Client requests its queued messages
            receiver = request[1]
            return self.__fetch_my_messages(receiver)

        else:
            return "Error: invalid message!"

    def __fetch_my_messages(self, receiver_phone_hashed: str) -> list[bytes]:
        """
        Collect and remove all messages addressed to a given user.

        Args:
            receiver_phone_hashed: Hashed phone number of the requesting client.

        Returns:
            List of serialized PrivateMessage objects for delivery.
        """
        selected: list[bytes] = []
        # Iterate in reverse to remove delivered messages safely
        for idx in reversed(range(len(self.messages))):
            msg = self.messages[idx]
            if msg["receiver"] == receiver_phone_hashed:
                selected.append(serialize_private_message(msg))
                del self.messages[idx]
        selected.reverse()  # Restore original chronological order
        if self.verbose:
            self._debug_list_messages()
        return selected

    def _server_loop(self):
        """
        Main loop: accept client connections, process requests, and send responses.

        Runs until interrupted (e.g., via KeyboardInterrupt).
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow quick reuse of the socket address
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen()
        if self.verbose:
            print(f"Server listening on {self.host}:{self.port}...")

        try:
            while True:
                conn, addr = sock.accept()
                if self.verbose:
                    print(f"Connection from {addr}")
                with conn:
                    while True:
                        data = conn.recv(4096)
                        if not data:
                            break  # Client closed connection
                        request = pickle.loads(data)
                        response = self.__analyze_request(request)
                        conn.sendall(pickle.dumps(response))
        except KeyboardInterrupt:
            print("\nServer shutting down.")
        finally:
            sock.close()

    # -- Debug helpers --

    def _debug_list_users(self):
        """Print all registered users and their pre-key bundles (verbose mode only)."""
        print("\n--- Registered Users ---")
        for uid, bundle in self.users.items():
            print(uid, bundle)
        print("------------------------\n")

    def _debug_list_messages(self):
        """Print all queued messages (verbose mode only)."""
        print("\n--- Message Queue ---")
        for msg in self.messages:
            print(msg["sender"], "→", msg["receiver"], "| initial:", msg["is_initial_message"])
        print("---------------------\n")
