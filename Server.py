"""
Server side of the basic signal protocol.
There should be one server running on the same machine.
"""

from PrekeyBundle import PreKeyBundle, serialize_prekey_bundle, deserialize_prekey_bundle
from PrivateMessage import PrivateMessage, serialize_private_message, deserialize_private_message

import socket
import pickle


class Server:

    def __init__(self, verbose: bool = False):
        self.users: dict[str, PreKeyBundle] = {}
        self.messages: list[PrivateMessage] = []
        self.verbose = verbose
        self.__server_loop()

    def create_account(self, phone_hashed: str, prekey_bundle: PreKeyBundle):
        # check if phone_hashed is in the database
        if phone_hashed in self.users:
            return False
        else:
            self.users[phone_hashed] = prekey_bundle
            return True

    def fetch_prekey_bundle(self, phone_hashed: str) -> PreKeyBundle | None:
        if phone_hashed in self.users:
            self.users[phone_hashed]["one_time_prekey_public_index"] += 1
            return self.users[phone_hashed]
        else:
            return None

    def list_users(self):
        print("\n------------------------ Users ------------------------")
        for user in self.users:
            print(user, self.users[user], "\n")
        print("-------------------------------------------------------\n")

    def list_messages(self):
        print("\n---------------------- Messages -----------------------")
        for message in self.messages:
            print(message["sender"], message["receiver"], message["is_initial_message"], "\n")
        print("-------------------------------------------------------\n")

    def analyze_request(self, message_bundle):
        if message_bundle[0] == "register":
            phone_hashed = message_bundle[1]
            prekey_bundle = deserialize_prekey_bundle(message_bundle[2])
            if self.create_account(phone_hashed, prekey_bundle):
                if self.verbose:
                    self.list_users()
                return "Account created successfully!"
            return "Error: account already exists!"

        elif message_bundle[0] == "fetch_prekey_bundle":
            receiver_phone_hashed = message_bundle[2]
            fetched_bundle = self.fetch_prekey_bundle(receiver_phone_hashed)
            if fetched_bundle is not None:
                client_public_data = serialize_prekey_bundle(fetched_bundle)
                return client_public_data
            else:
                return "Error: no account found!"

        elif message_bundle[0] == "initial_message":
            message_ = deserialize_private_message(message_bundle[1])
            if message_["sender"] in self.users and message_["receiver"] in self.users:
                self.messages.append(message_)
                if self.verbose:
                    self.list_messages()
                return "Double Ratchet initial message stored on server."
            else:
                return "Error: invalid private message!"

        elif message_bundle[0] == "private_message":
            message_ = deserialize_private_message(message_bundle[1])
            if message_["sender"] in self.users and message_["receiver"] in self.users:
                self.messages.append(message_)
                if self.verbose:
                    self.list_messages()
                return "Message stored on server."
            else:
                return "Error: invalid private message!"

        elif message_bundle[0] == "check_for_messages":
            return self.fetch_my_messages(message_bundle[1])
        else:
            return "Error: invalid message!"

    def fetch_my_messages(self, receiver_phone_hashed) -> list[PrivateMessage]:
        selected = []
        for i in reversed(range(len(self.messages))):  # Reverse to avoid index shifting
            if self.messages[i]["receiver"] == receiver_phone_hashed:
                selected.append(serialize_private_message(self.messages[i]))
                del self.messages[i]
        selected.reverse()  # Optional: restore original order
        if self.verbose:
            self.list_messages()
        return selected

    def __server_loop(self):
        # Create a socket object (IPv4 + TCP) and allow quick reuse of the address
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('localhost', 12345))
        server_socket.listen()
        if self.verbose:
            print("Server is listening on port 12345...")

        try:
            while True:
                conn, addr = server_socket.accept()
                # print(f"Connected by {addr}")
                with conn:
                    # Inner loop: handle multiple messages per connection
                    while True:
                        data = conn.recv(4096)
                        if not data:
                            # client closed connection
                            # print(f"Connection closed by {addr}")
                            break

                        # deserialize and process
                        message_bundle = pickle.loads(data)
                        response_str = self.analyze_request(message_bundle)

                        # send response back
                        conn.sendall(pickle.dumps(response_str))

        except KeyboardInterrupt:
            print("\nShutting down server.")
        finally:
            server_socket.close()
