"""
Client side of the basic signal protocol.
Each client has to have their Client() object.
Limitations:
    You can only send messages to contacts that you have in your contact list.
    You can only receive messages from contacts that you have in your contact list.
    assume
"""

from SHA256 import SHA256
from X3DH import X3DH
from Double_Ratchet import DoubleRatchetSession

from PrekeyBundle import serialize_prekey_bundle, deserialize_prekey_bundle
from PrivateMessage import PrivateMessage, serialize_private_message, deserialize_private_message, list_messages
from Profile import Profile, serialize_profile, deserialize_profile
from Contact import Contact, list_contact

import socket
import pickle
from datetime import datetime       # to get timestamp
from tzlocal import get_localzone   # timezone information for timestamp


class Client:
    """
    Manages client functionality, including messaging, contact management, and
    communication with the server.

    The Client class models a messaging client that can register with a server,
    send and receive secure messages using the X3DH and Double Ratchet protocols,
    and manage a list of contacts. The client supports functionality such as
    initiating handshakes for secure communication, checking for new messages,
    and handling session-based encrypted communication.

    Attributes:
        profile (Profile): The client's profile containing display name, phone
            number, about information, and profile picture.
        receivers_can_see_my_name (bool): Determines if receivers can see the
            client's display name.
        contacts (dict[str, Contact]): The list of contacts associated with the
            client, keyed by contact name.
        messages (dict[str, list[PrivateMessage]]): Stored messages for each
            contact, keyed by contact name.
        verbose (bool): Toggle for verbose output during operations.
        phone_hashed (str): Hashed version of the client's phone number.
        x3dh (X3DH): Instance of X3DH protocol for managing the cryptographic
            handshake process.
        server_port (int): The port used by the server for communication.
    """

    def __init__(self, phone_number: str, name: str = "", about: str = None, profile_picture: bytes = None, receivers_can_see_my_name: bool = False,
                 contacts: dict[str, Contact] = None, messages: dict[str, list[PrivateMessage]] = None, verbose: bool = False):

        self.profile = Profile(name=name, phone_number=phone_number, about=about, profile_picture=profile_picture)
        self.receivers_can_see_my_name = receivers_can_see_my_name

        self.contacts = contacts
        if contacts is None:
            self.contacts = {}
        self.messages = messages
        if messages is None:
            self.messages = {}
        self.verbose = verbose

        self.phone_hashed = Client.__hash_phone_number(phone_number)
        self.x3dh = X3DH(N=10)

        # decide on the ports
        self.server_port = 12345  # server's port

        if verbose:
            print(f"\t Account {self.profile["name"]} ({self.profile["phone_number"]}) is created.")

        # register the client on server
        self.__register_on_server()

    def send_private_message(self, name: str = None, phone_number: str = None, message: str = None) -> None:

        if message is None:
            raise ValueError("Message must be provided.")

        phone_number_ = phone_number
        # if the name is provided, fetch the phone_number from the contacts dictionary
        if name is not None:
            phone_number_ = self.__get_phone_number_from_name(name)
            if phone_number_ is None:
                phone_number_ = self.__get_phone_number_from_profile_name(name)
                if phone_number_ is None:
                    raise ValueError("Contact not found!")
        elif phone_number is not None:
            if phone_number not in self.contacts:
                self.add_contact(phone_number=phone_number)
        else:
            raise ValueError("Either name or phone_number must be provided.")

        # check if a session exists, if not initiate handshake
        if self.contacts[phone_number_]["session"] is None:
            self.__initiate_handshake(phone_number_)

        # encrypt the message and profile, and send it to the server
        session = self.contacts[phone_number_]["session"]
        message_encrypted = session.encrypt_message(str.encode(message))
        profile_serialized_encrypted_ = session.encrypt_message(self.__get_profile_for_sender(phone_number_))
        serialized_private_message = serialize_private_message(
            PrivateMessage(sender=self.phone_hashed, receiver=self.contacts[phone_number_]["phone_hashed"], message=message_encrypted, is_initial_message=False,
                           timestamp=datetime.now(get_localzone()).isoformat(), profile_serialized_encrypted=profile_serialized_encrypted_))
        message_encrypted_tuple = ("private_message", serialized_private_message)
        message_encrypted_tuple_serialized = pickle.dumps(message_encrypted_tuple)
        server_respond = self.__send_to_server(message_encrypted_tuple_serialized)

        # receive the server's response
        if self.verbose:
            print("\t", server_respond)

    def check_for_messages(self):
        check_for_messages_tuple = ("check_for_messages", self.phone_hashed)
        check_for_messages_tuple_serialized = pickle.dumps(check_for_messages_tuple)
        server_respond = self.__send_to_server(check_for_messages_tuple_serialized)

        # first check for x3dh initial_messages to create required sessions
        for message in server_respond:
            private_message = deserialize_private_message(message)

            # check if the message is a handshake (they don't have to be stored)
            if private_message["is_initial_message"]:

                # x3dh respond handshake
                initial_message_ = private_message["message"]
                x3dh_secret = self.x3dh.respond_handshake(initial_message_)

                # establish "receiver" DoubleRatchetSession
                initial_root_key, initial_chain_key = DoubleRatchetSession.derive_root_and_chain_keys(root_key=b"\x00" * 32, dh_shared_secret=x3dh_secret)
                receiver_session = DoubleRatchetSession(initial_dh_private_key=self.x3dh.signed_prekey_private_key, root_key=initial_root_key, sending_chain_key=None,
                                                        receiving_chain_key=initial_chain_key, initial_remote=initial_message_["initiator_ephemeral_public_key"])

                sender_profile = deserialize_profile(receiver_session.decrypt_message(private_message["profile_serialized_encrypted"][0], private_message[
                    "profile_serialized_encrypted"][1], private_message["profile_serialized_encrypted"][2]))
                sender_phone_number = sender_profile["phone_number"]

                # add to contacts if not already there
                if sender_phone_number not in self.contacts:
                    self.add_contact(phone_number=sender_phone_number)

                # update the profile of the sender
                self.__update_profile(sender_profile)

                # update the x3dh secret and session
                self.__update_x3dh_secret(sender_phone_number, x3dh_secret)
                self.__update_x3dh_session(sender_phone_number, receiver_session)

        # check for non-initial messages and store them
        # at this point; the client has the sender's phone number, session, and profile (name as well if the sender is a contact)
        for message in server_respond:
            private_message = deserialize_private_message(message)
            if not private_message["is_initial_message"]:
                # sender_name might be None
                _, sender_phone_number = self.__get_name_and_number_from_hash(private_message["sender"])

                session = self.contacts[sender_phone_number]["session"]
                if session is not None:
                    # decrypt the message and profile, store it in the messages dictionary
                    message_decrypted = session.decrypt_message(private_message["message"][0], private_message["message"][1], private_message["message"][2]).decode("utf-8")

                    sender_profile = deserialize_profile(session.decrypt_message(private_message["profile_serialized_encrypted"][0], private_message["profile_serialized_encrypted"][1], private_message["profile_serialized_encrypted"][2]))
                    self.__update_profile(sender_profile)

                    # update the message
                    sender_phone_number = sender_profile["phone_number"]
                    if self.contacts[sender_phone_number]["name"] is None:
                        if sender_profile["name"] is None:
                            private_message["sender"] = sender_phone_number
                        else:
                            private_message["sender"] = sender_profile["name"]
                    else:
                        private_message["sender"] = self.contacts[sender_phone_number]["name"]

                    private_message["receiver"] = self.profile["name"]
                    private_message["message"] = message_decrypted
                    self.messages[sender_phone_number].append(private_message)
                    # print(f"\t Message from {sender_name} ({sender_phone_number}) to {self.profile["name"]} ({self.profile["phone_number"]}): {message_decrypted}")
                else:
                    raise ValueError("Session not found!")
        list_messages(self.profile["name"], self.messages)

    def add_contact(self, phone_number: str, name: str = None) -> None:
        """Adds a contact to the client's contact list."""
        phone_hashed_ = Client.__hash_phone_number(phone_number)
        self.contacts[phone_number] = Contact(name=name, phone_number=phone_number, profile=None, phone_hashed=phone_hashed_, prekey_bundle_serialized=None, x3dh_secret=None, session=None)
        self.messages[phone_number] = []
        if self.verbose:
            print(f"\t Contact {name} ({phone_number}) added to contacts.")

    def list_contacts(self) -> None:
        if self.contacts == {}:
            print(f"\n{self.profile["name"]} does not have any contacts.")
            return
        print(f"\n{self.profile['name']} has the following contacts:")
        for _, contact in self.contacts.items():
            list_contact(contact)

    def receivers_can_see_my_name(self, receivers_can_see_my_name: bool = False) -> None:
        """Toggles whether receivers can see the client's display name."""
        self.receivers_can_see_my_name = receivers_can_see_my_name

    def __initiate_handshake(self, phone_number: str):
        """Initiates the X3DH handshake with a given contact."""
        if phone_number in self.contacts:

            # load prekey bundle
            self.__ask_server_for_prekey_bundle(phone_number)
            receiver_prekey_bundle_ = deserialize_prekey_bundle(self.contacts[phone_number]["prekey_bundle_serialized"])
            self.x3dh.load_peer_prekey_bundle(receiver_prekey_bundle_)

            # x3dh initiate handshake (derive x3dh secret)
            x3dh_first_message, x3dh_secret, ephemeral_private_key = self.x3dh.initiate_handshake(receiver_prekey_bundle_, receiver_prekey_bundle_["one_time_prekey_public_index"])
            self.__update_x3dh_secret(phone_number, x3dh_secret)

            # establish "sender" DoubleRatchetSession
            initial_root_key, initial_chain_key = DoubleRatchetSession.derive_root_and_chain_keys(root_key=b"\x00" * 32, dh_shared_secret=x3dh_secret)
            sender_session = DoubleRatchetSession(initial_dh_private_key=ephemeral_private_key, root_key=initial_root_key, sending_chain_key=initial_chain_key, receiving_chain_key=None, initial_remote=receiver_prekey_bundle_["identity_public_key"])
            self.__update_x3dh_session(phone_number, sender_session)

            # send x3dh_first_message to server
            profile_serialized_encrypted_ = sender_session.encrypt_message(self.__get_profile_for_sender(phone_number))

            x3dh_first_message_tuple = ("initial_message", serialize_private_message(
                PrivateMessage(sender=self.phone_hashed, receiver=self.contacts[phone_number]["phone_hashed"], message=x3dh_first_message, is_initial_message=True,
                               timestamp=datetime.now(get_localzone()).isoformat(), profile_serialized_encrypted=profile_serialized_encrypted_)))
            x3dh_first_message_tuple_serialized = pickle.dumps(x3dh_first_message_tuple)
            server_respond = self.__send_to_server(x3dh_first_message_tuple_serialized, buffer_size=2048 * 2)
            if self.verbose:
                print("\t", server_respond)

            # Zeroize ephemeral_private_key
            # ephemeral_private_key = None
        else:
            raise ValueError("Contact not found!")

    def __register_on_server(self) -> None:
        """Registers the client on the server."""
        register_tuple = ("register", self.phone_hashed, serialize_prekey_bundle(self.x3dh.get_prekey_bundle()))
        register_tuple_serialized = pickle.dumps(register_tuple)
        server_respond = self.__send_to_server(register_tuple_serialized)
        if self.verbose:
            print("\t", server_respond)

    def __send_to_server(self, data: bytes, buffer_size: int = 1024 * 4):
        """Sends data to the server."""
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', self.server_port))
        client_socket.sendall(data)
        response = client_socket.recv(buffer_size)
        server_respond = pickle.loads(response)
        client_socket.close()
        if isinstance(server_respond, str) and "error" in server_respond:
            raise ValueError(server_respond)
        return server_respond

    def __ask_server_for_prekey_bundle(self, phone_number: str) -> None:
        """Asks the server for a prekey bundle for a given contact."""
        if phone_number not in self.contacts:
            raise ValueError("Contact not found!")
        phone_hashed_ = self.contacts[phone_number]["phone_hashed"]
        fetch_tuple = ("fetch_prekey_bundle", self.phone_hashed, phone_hashed_)
        fetch_tuple_serialized = pickle.dumps(fetch_tuple)
        server_respond = self.__send_to_server(fetch_tuple_serialized, buffer_size=2048)
        prekey_bundle_serialized_ = server_respond
        self.__update_prekey_bundle_serialized(phone_number, prekey_bundle_serialized_)

    def __update_profile(self, sender_profile: Profile) -> None:
        self.contacts[sender_profile["phone_number"]]["profile"] = sender_profile

    def __update_prekey_bundle_serialized(self, phone_number: str, prekey_bundle_serialized: bytes) -> None:
        self.contacts[phone_number]["prekey_bundle_serialized"] = prekey_bundle_serialized

    def __update_x3dh_secret(self, phone_number: str, x3dh_secret: bytes) -> None:
        self.contacts[phone_number]["x3dh_secret"] = x3dh_secret

    def __update_x3dh_session(self, phone_number: str, session: DoubleRatchetSession) -> None:
        self.contacts[phone_number]["session"] = session

    def __get_name_and_number_from_hash(self, phone_hashed: str) -> tuple[str | None, str | None]:
        for phone_number, contact in self.contacts.items():
            if contact["phone_hashed"] == phone_hashed:
                return contact["name"], phone_number
        return None, None

    def __get_profile_for_sender(self, phone_number: str) -> bytes:
        if self.receivers_can_see_my_name or (phone_number in self.contacts and self.contacts[phone_number]["name"] is not None):
            return serialize_profile(Profile(name=self.profile["name"], phone_number=self.profile["phone_number"], about=self.profile["about"], profile_picture=self.profile["profile_picture"]))
        else:
            return serialize_profile(Profile(name=None, phone_number=self.profile["phone_number"], about=None, profile_picture=None))

    def __get_phone_number_from_name(self, name: str) -> str | None:
        for phone_number, contact in self.contacts.items():
            if contact["name"] == name:
                return phone_number
        return None

    def __get_phone_number_from_profile_name(self, name: str) -> str | None:
        for phone_number, contact in self.contacts.items():
            if contact["profile"]["name"] is not None:
                if contact["profile"]["name"] == name:
                    return phone_number
        return None

    @staticmethod
    def __hash_phone_number(phone_number: str):
        return SHA256(pepper="").hash(phone_number, salt="")
