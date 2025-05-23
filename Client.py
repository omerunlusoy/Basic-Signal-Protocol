"""
Client-side implementation of the Signal messaging protocol.

This module defines the `Client` class, which handles user registration with a central server,
contact management, and secure message exchange using the X3DH handshake and Double Ratchet
algorithms. It supports:

  • Registration: publishes the user’s pre-key bundle for peers to retrieve
  • Contact management: add, list, and look up contacts by name or phone number
  • Key agreement: initiates and responds to X3DH handshakes to establish shared secrets
  • Message encryption: ratchets messages end-to-end with the Double Ratchet session
  • Serialization: (de)serializes profiles, pre-key bundles, and messages for network transport
  • Networking: communicates with the server over TCP sockets using pickle

Example:
    client = Client(phone_number="+1234567890", name="Bob")
    client.add_contact(phone_number="+1987654321", name="Alice")
    client.send_private_message(name="Alice", message="Hello, Alice!")
    client.check_for_messages()

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

import os
import socket
import pickle
from datetime import datetime  # to get timestamp
from tzlocal import get_localzone  # timezone information for timestamp
from typing import List

from AES256 import AES256
from Argon2id import Argon2id
from HMAC import HMAC
from SHA256 import SHA256
from X3DH import X3DH
from DoubleRatchet import DoubleRatchetSession

from DataClasses import Contact
from DataClasses.PrekeyBundle import serialize_prekey_bundle, deserialize_prekey_bundle
from DataClasses.PrivateMessage import PrivateMessage, serialize_private_message, deserialize_private_message
from DataClasses.Profile import Profile, serialize_profile, deserialize_profile
from DataClasses.ClientProfile import ClientProfile, serialize_client_profile, deserialize_client_profile
from ClientDatabaseSQLite import ClientDatabase


class Client:
    """
    Manages client functionality, including messaging, contact management, and
    communication with the server.

    The Client class models a messaging client that can register with a server,
    send and receive secure messages using the X3DH and Double Ratchet protocols,
    and manage a list of contacts. The client supports functionality such as
    initiating handshakes for secure communication, checking for new messages,
    and handling session-based encrypted communication.
    """

    # Class variables
    x3dh_one_time_prekey_list_size = 10
    server_port = 12345
    database_dir = "databases/"

    def __init__(self):
        self.client_profile = None
        self.database = None

    def register(self, phone_number: str, password: str, name: str = "", about: str = None, profile_picture: bytes = None, receivers_can_see_my_name: bool = False, verbose: bool = False) -> bool:

        # hash phone number for future use
        phone_hashed = Client.__hash_phone_number(phone_number)

        # hashers and cipher
        argon_hasher = Argon2id(password)
        aes_cipher = AES256(password)
        hmac_hasher = HMAC(password)

        # check if the database already exists
        if os.path.exists(Client.database_dir + f"{phone_hashed}.db"):
            if self.client_profile["verbose"]:
                print(f"\t Account {self.client_profile['profile']['name']} ({self.client_profile['profile']['phone_number']}) already exists.")
            return False

        # create a profile for the client profile
        profile = Profile(name=name, phone_number=phone_number, about=about, profile_picture=profile_picture)

        # create a x3dh instance
        x3dh = X3DH(N=Client.x3dh_one_time_prekey_list_size)
        # create the client profile
        self.client_profile = ClientProfile(profile=profile, phone_hashed=phone_hashed, receivers_can_see_my_name=receivers_can_see_my_name, verbose=verbose, x3dh=x3dh)

        client_profile_encrypted = aes_cipher.encrypt(serialize_client_profile(self.client_profile))

        # create a client database instance
        password_hashed = argon_hasher.hash(password, variable_salt=password)
        self.database = ClientDatabase(database_dir=Client.database_dir, phone_number_hashed=phone_hashed, aes_cipher=aes_cipher, hmac_hasher=hmac_hasher)
        self.database.initialize_database_schema()

        # save the client profile
        self.database.save_client_profile(client_profile_encrypted, password_hashed)

        if self.client_profile["verbose"]:
            print(f"\t Account {self.client_profile["profile"]["name"]} ({self.client_profile["profile"]["phone_number"]}) is created.")

        # register the client on server
        return self.__register_on_server()

    def login(self, phone_number: str, password: str) -> bool:
        # hash phone number for future use
        phone_hashed = Client.__hash_phone_number(phone_number)

        # hasher and cipher
        argon_hasher = Argon2id(password)
        aes_cipher = AES256(password)
        hmac_hasher = HMAC(password)

        self.database = ClientDatabase(database_dir=Client.database_dir, phone_number_hashed=phone_hashed, aes_cipher=aes_cipher, hmac_hasher=hmac_hasher)
        success = self.database.load_from_database()
        client_profile, password_hashed = self.database.get_client_profile()
        if not success or client_profile is None:
            return False
        verify_login_ = argon_hasher.verify(data_hashed=password_hashed, data=password, variable_salt=password)
        if not verify_login_:
            print("Incorrect password!")
            return False
        else:
            aes_cipher = AES256(password)
            self.client_profile = deserialize_client_profile(aes_cipher.decrypt(client_profile))
            return True

    def send_private_message(self, name: str = None, phone_number: str = None, message: str = None) -> bool:
        """
        Sends a private encrypted message to a contact specified by name or phone number.

        This method ensures that a contact exists, a session is established, and the
        message is securely transmitted via the server after encryption. It handles
        various conditions such as resolving contact details, initiating handshakes
        for new sessions, and preparing serialized messages to ensure safe and
        efficient communication. This function requires either a contact name or
        phone number to identify the recipient.

        Args:
            name (str, optional): The name of the contact to send the message to.
                Name can be a contact name or profile name. Defaults to None.
            phone_number (str, optional): The phone number of the recipient. If the
                contact is not found, it will be added without a name. Defaults to None.
            message (str): The content of the message to be sent. Must be
                provided. Defaults to None.

        Raises:
            ValueError: If both `name` and `phone_number` are not provided.
            ValueError: If the `message` is not provided.
            ValueError: If the contact, specified by name, cannot be found.

        Returns:
            None
        """
        # a message has to be provided
        if message is None:
            raise ValueError("Message must be provided.")

        # the phone number that will be used to send the message
        phone_number_ = phone_number
        # if the name is provided, fetch the phone_number from the contacts dictionary (name can be contact name or profile name)
        if name is not None:
            phone_number_ = self.database.get_phone_number_from_name(name)
            if phone_number_ is None:
                phone_number_ = self.database.get_phone_number_from_profile_name(name)
                if phone_number_ is None:
                    raise ValueError("Contact not found!")
        # if the phone number is provided, check if it is a contact (if not, add it without a name)
        elif phone_number is not None:
            if not self.database.phone_number_in_contacts(phone_number):
                self.add_contact(phone_number=phone_number)
        else:
            raise ValueError("Either name or phone_number must be provided.")

        contact = self.database.get_contact(phone_number_)

        # check if a session exists, if not initiate handshake
        if contact["session"] is None:
            self.__initiate_handshake(phone_number_)

        # encrypt the message and profile
        session = contact["session"]
        message_encrypted_ = session.encrypt_message(str.encode(message))

        profile_serialized_encrypted_ = session.encrypt_message(self.__get_serialized_profile_for_sender(phone_number_))
        serialized_private_message = serialize_private_message(
            PrivateMessage(sender=self.client_profile["phone_hashed"], receiver=contact["phone_hashed"], message=message_encrypted_, is_initial_message=False, timestamp=datetime.now(get_localzone()).isoformat(), profile_serialized_encrypted=profile_serialized_encrypted_))
        # create a private message tuple and serialize with pickle
        message_encrypted_tuple = ("private_message", serialized_private_message)
        message_encrypted_tuple_serialized = pickle.dumps(message_encrypted_tuple)
        # send it to the server
        server_respond, success = Client.__send_to_server(message_encrypted_tuple_serialized)

        # update the session
        self.database.update_double_ratchet_session(phone_number=phone_number_, session=session)

        # receive the server's response
        if self.client_profile["verbose"]:
            print("\t", server_respond)
        return success

    def check_for_messages(self, list_messages: bool = False) -> list[PrivateMessage]:
        """
        Processes incoming messages from the server, including setting up encrypted sessions via X3DH
        if initial messages are found, and decrypting non-initial messages. It updates contact and profile
        information, establishes required sessions, and stores messages in a structured format while
        managing cryptographic operations for secure communication.

        Raises:
            ValueError: If no session is found for a sender when processing non-initial messages.
        """
        check_for_messages_tuple = ("check_for_messages", self.client_profile["phone_hashed"])
        check_for_messages_tuple_serialized = pickle.dumps(check_for_messages_tuple)
        server_respond, success = Client.__send_to_server(check_for_messages_tuple_serialized)

        # check if the return is valid
        if not success:
            raise ValueError("Server did not respond! Check your internet connection and try again.")

        # first check for x3dh initial_messages to create required sessions
        for message in server_respond:
            # deserialize the private message
            private_message = deserialize_private_message(message)

            # check if the message is a handshake (they don't have to be stored)
            if private_message["is_initial_message"]:

                # x3dh respond handshake
                initial_message_ = private_message["message"]
                x3dh_secret = self.client_profile["x3dh"].respond_handshake(initial_message_)

                # establish "receiver" DoubleRatchetSession
                initial_root_key, initial_chain_key = DoubleRatchetSession.derive_root_and_chain_keys(root_key=b"\x00" * 32, dh_shared_secret=x3dh_secret)
                receiver_session = DoubleRatchetSession(initial_dh_private_key=self.client_profile["x3dh"].signed_prekey_private_key, root_key=initial_root_key, sending_chain_key=None, receiving_chain_key=initial_chain_key, initial_remote=initial_message_["initiator_ephemeral_public_key"])

                sender_profile = deserialize_profile(receiver_session.decrypt_message(private_message["profile_serialized_encrypted"]))
                sender_phone_number = sender_profile["phone_number"]

                # add to contacts if not already there
                if not self.database.phone_number_in_contacts(sender_phone_number):
                    self.add_contact(phone_number=sender_phone_number)

                # update the profile of the sender
                self.database.update_profile(sender_profile=sender_profile)

                # update the x3dh secret and session
                self.database.update_x3dh_secret(phone_number=sender_phone_number, x3dh_secret=x3dh_secret)
                self.database.update_double_ratchet_session(phone_number=sender_phone_number, session=receiver_session)

        # add messages to the list
        private_messages = []

        # check for non-initial messages and store them
        # at this point; the client has the sender's phone number, session, and profile (name as well if the sender is a contact)
        for message in server_respond:
            # deserialize the private message
            private_message = deserialize_private_message(message)

            # make sure the message is not a handshake
            if not private_message["is_initial_message"]:

                # the sender's phone number will always be present in any private message in the attached profile
                _, sender_phone_number = self.database.get_contact_name_and_number_from_hash(private_message["sender"], sha=SHA256(pepper=""))

                # fetch the session from the sender's phone number (we assume that handshake already happened and the session is created.)
                session = self.database.get_contact(sender_phone_number)["session"]
                if session is not None:

                    # decrypt the message and profile, store it in the messages dictionary
                    message_decrypted = session.decrypt_message(private_message["message"]).decode("utf-8")

                    sender_profile = deserialize_profile(session.decrypt_message(private_message["profile_serialized_encrypted"]))

                    # update the saved profile to the latest attached one
                    self.database.update_profile(sender_profile)

                    # update the message sender and receiver info and save the decrypted version
                    sender_phone_number = sender_profile["phone_number"]
                    contact = self.database.get_contact(sender_phone_number)
                    if contact["name"] is None:
                        if sender_profile["name"] is None:
                            private_message["sender"] = sender_phone_number
                        else:
                            private_message["sender"] = sender_profile["name"]
                    else:
                        private_message["sender"] = contact["name"]

                    private_message["receiver"] = self.client_profile["profile"]["name"]
                    private_message["message"] = message_decrypted

                    # add the message to the messages list
                    self.database.add_message_to(sender_phone_number, private_message)
                    private_messages.append(private_message)
                else:
                    raise ValueError("Session not found!")
        # list all the messages
        if list_messages:
            self.database.list_all_messages(self.client_profile["profile"]["name"])
        return private_messages

    def add_contact(self, phone_number: str, name: str = None) -> None:
        """
        Adds a new contact to the contacts' list with the provided phone number and optional name.
        Hashes the phone number and initializes an empty list of messages for the contact.

        Args:
            phone_number (str): The phone number of the contact to be added.
            name (str, optional): The name of the contact. Defaults to None.

        Returns:
            None
        """
        # hash the phone number
        phone_hashed_ = Client.__hash_phone_number(phone_number)

        # create a new Contact instance and store it in contacts dict with the phone number as the key
        added_ = self.database.add_contact(name=name, phone_number=phone_number, phone_hashed=phone_hashed_)
        if not added_:
            print("Contact already exists!")
            return

        # initialize an empty messages_from_phone_number list within the messages dict with the phone number as the key
        self.database.create_empty_message_list_for(phone_number)
        if self.client_profile["verbose"]:
            print(f"\t Contact {name} ({phone_number}) added to contacts.")

    def update_contact_name(self, phone_number: str, contact_name: str) -> bool:
        updated_ = self.database.update_name(phone_number=phone_number, contact_name=contact_name)
        if not updated_ and self.client_profile["verbose"]:
            print("Contact not found!")
        return updated_

    def delete_contact(self, phone_number: str) -> bool:
        return self.database.delete_contact(phone_number=phone_number)

    def list_contacts(self, list_contacts: bool = True) -> List[Contact]:
        return self.database.list_contacts(self.client_profile["profile"]["name"], list_contacts)

    def update_receivers_can_see_my_name(self, receivers_can_see_my_name: bool, password: str) -> bool:
        """Toggles whether receivers can see the client's display name."""
        self.client_profile["receivers_can_see_my_name"] = receivers_can_see_my_name
        return self.update_client_profile(password)

    def update_verbose(self, verbose: bool, password: str) -> bool:
        """Toggles whether receivers can see the client's display name."""
        self.client_profile["verbose"] = verbose
        return self.update_client_profile(password)

    def update_profile_name(self, profile_name: str, password: str) -> bool:
        """Updates the client's profile name."""
        self.client_profile["profile"]["name"] = profile_name
        return self.update_client_profile(password)

    def update_about(self, about: str, password: str) -> bool:
        """Updates the client's profile picture."""
        self.client_profile["profile"]["about"] = about
        return self.update_client_profile(password)

    def update_profile_picture(self, profile_picture: str, password: str) -> bool:
        """Updates the client's profile picture."""
        self.client_profile["profile"]["profile_picture"] = profile_picture
        return self.update_client_profile(password)

    def update_client_profile(self, password: str) -> bool:
        """Updates the client's profile with the new information provided by the user."""

        # hashers and cipher
        argon_hasher = Argon2id(password)
        aes_cipher = AES256(password)

        # delete the table and recreate it
        success1 = self.database.delete_client_profile_table()
        client_profile_encrypted = aes_cipher.encrypt(serialize_client_profile(self.client_profile))
        password_hashed = argon_hasher.hash(password, variable_salt=password)
        success2 = self.database.save_client_profile(client_profile_encrypted, password_hashed)
        if not (success1 and success2):
            if self.client_profile["verbose"]:
                print("Failed to update!")
            return False
        return True

    def delete_account(self) -> None:
        """Deletes the client's account from the server."""
        self.__delete_on_server()
        self.database.delete_database()
        del self.client_profile
        del self.database

    def __initiate_handshake(self, phone_number: str):
        """Initiates the X3DH handshake with a given contact."""
        if self.database.phone_number_in_contacts(phone_number):

            # load prekey bundle
            self.__ask_server_for_prekey_bundle(phone_number)
            receiver_prekey_bundle_ = deserialize_prekey_bundle(self.database.get_contact(phone_number)["prekey_bundle_serialized"])
            X3DH.verify_signed_prekey_signature(receiver_prekey_bundle_)

            # x3dh initiate handshake (derive x3dh secret)
            x3dh_first_message, x3dh_secret, ephemeral_private_key = self.client_profile["x3dh"].initiate_handshake(receiver_prekey_bundle_, receiver_prekey_bundle_["one_time_prekey_public_index"])
            self.database.update_x3dh_secret(phone_number=phone_number, x3dh_secret=x3dh_secret)

            # establish "sender" DoubleRatchetSession
            initial_root_key, initial_chain_key = DoubleRatchetSession.derive_root_and_chain_keys(root_key=b"\x00" * 32, dh_shared_secret=x3dh_secret)
            sender_session = DoubleRatchetSession(initial_dh_private_key=ephemeral_private_key, root_key=initial_root_key, sending_chain_key=initial_chain_key, receiving_chain_key=None, initial_remote=receiver_prekey_bundle_["identity_public_key"])
            self.database.update_double_ratchet_session(phone_number=phone_number, session=sender_session)

            # send x3dh_first_message to server
            profile_serialized_encrypted_ = sender_session.encrypt_message(self.__get_serialized_profile_for_sender(phone_number))

            # create a handshake message to be stored on the server
            x3dh_first_message_tuple = ("initial_message", serialize_private_message(PrivateMessage(sender=self.client_profile["phone_hashed"], receiver=self.database.get_contact(phone_number)["phone_hashed"], message=x3dh_first_message, is_initial_message=True, timestamp=datetime.now(get_localzone()).isoformat(), profile_serialized_encrypted=profile_serialized_encrypted_)))

            # serialize the message and send it to the server
            x3dh_first_message_tuple_serialized = pickle.dumps(x3dh_first_message_tuple)
            server_respond, _ = Client.__send_to_server(x3dh_first_message_tuple_serialized)
            if self.client_profile["verbose"]:
                print("\t", server_respond)

            # Zeroize ephemeral_private_key
            del ephemeral_private_key
        else:
            raise ValueError("Contact not found!")

    def __register_on_server(self) -> bool:
        """Registers the client on the server."""
        register_tuple = ("register", self.client_profile["phone_hashed"], serialize_prekey_bundle(self.client_profile["x3dh"].get_prekey_bundle()))
        register_tuple_serialized = pickle.dumps(register_tuple)
        server_respond, success = Client.__send_to_server(register_tuple_serialized)
        if self.client_profile["verbose"]:
            print("\t", server_respond)
        return success

    def __delete_on_server(self) -> bool:
        """Deletes the client on the server."""
        delete_tuple = ("delete", self.client_profile["phone_hashed"])
        delete_tuple_serialized = pickle.dumps(delete_tuple)
        server_respond, success = Client.__send_to_server(delete_tuple_serialized)
        if self.client_profile["verbose"]:
            print("\t", server_respond)
        return success

    def __ask_server_for_prekey_bundle(self, phone_number: str) -> None:
        """Asks the server for a prekey bundle for a given contact."""

        # fetch the hashed phone number from contacts for the server
        phone_hashed_ = self.database.get_contact(phone_number)["phone_hashed"]

        # create a server request tuple and serialize
        fetch_tuple = ("fetch_prekey_bundle", self.client_profile["phone_hashed"], phone_hashed_)
        fetch_tuple_serialized = pickle.dumps(fetch_tuple)

        # save server response as the prekey bundle
        prekey_bundle_serialized_, success = Client.__send_to_server(fetch_tuple_serialized)
        if not success:
            raise ValueError("Handshake failed! No prekey bundle is returned from the server.")
        self.database.update_prekey_bundle_serialized(phone_number=phone_number, prekey_bundle_serialized=prekey_bundle_serialized_)

    def __get_serialized_profile_for_sender(self, phone_number: str) -> bytes:
        """
        Retrieves and serializes the profile information of the user for presentation to a specific sender.

        The method determines whether the sender (identified by their phone number) is allowed to view the user's profile
        details, which include name, about information, and profile picture. This determination is based on user settings
        and whether the sender exists in the user's contacts list. The serialized profile is returned as a bytes object.

        Args:
            phone_number: str
                The phone number of the sender requesting the user's profile details.

        Returns:
            bytes
                The serialized representation of the user's profile appropriate for the sender.
        """
        # if the sender can view the user's profile (phone is saved or the user allows everyone to see their profile)
        if self.client_profile["receivers_can_see_my_name"] or (self.database.phone_number_in_contacts(phone_number) and self.database.get_contact(phone_number)["name"] is not None):
            return serialize_profile(Profile(name=self.client_profile["profile"]["name"], phone_number=self.client_profile["profile"]["phone_number"], about=self.client_profile["profile"]["about"], profile_picture=self.client_profile["profile"]["profile_picture"]))
        else:
            return serialize_profile(Profile(name=None, phone_number=self.client_profile["profile"]["phone_number"], about=None, profile_picture=None))

    @staticmethod
    def __send_to_server(serialized_data: bytes):
        """Sends data to the server."""

        # inner method to receive all data from the socket
        def __recv_all(socket_, length_to_receive: int):
            data_ = b''
            while len(data_) < length_to_receive:
                packet = socket_.recv(length_to_receive - len(data_))
                if not packet:
                    raise ConnectionError("Connection closed before receiving full data")
                data_ += packet
            return data_

        # create a socket and connect to the server's port
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', Client.server_port))

        # send the passed data and receive a response from the server
        client_socket.sendall(len(serialized_data).to_bytes(4, 'big') + serialized_data)

        # Read a 4-byte length prefix
        raw_message_length = __recv_all(client_socket, 4)
        message_length = int.from_bytes(raw_message_length, 'big')

        # receive success
        raw_success = __recv_all(client_socket, 4)
        success = bool.from_bytes(raw_success, 'big')

        # receive the response and deserialize it
        response = __recv_all(client_socket, message_length)
        server_respond = pickle.loads(response)

        # check if the message includes an error
        if isinstance(server_respond, str) and "Error" in server_respond:
            raise ValueError(server_respond)

        # close the socket
        client_socket.close()
        return server_respond, success

    @staticmethod
    def __hash_phone_number(phone_number: str) -> str:
        """Hashes a phone number using hashlib's SHA256."""
        return SHA256(pepper="").hash(phone_number, salt="")
