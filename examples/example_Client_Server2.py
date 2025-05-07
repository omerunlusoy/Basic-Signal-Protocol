"""
Integration test for the basic Signal protocol Server and Client implementations.

This script launches a server process and four client processes (Alice, Bob, Charlie, Dave)
to simulate registration, key exchanges, and encrypted message exchanges. Each client
sends and receives messages in turn, demonstrating initial handshakes, ratchet updates,
and fallback behavior when the recipient is unknown.

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

import multiprocessing
import time

from Server import Server
from Client import Client

# Toggle verbose output for debug logging in clients
verbose_ = False

# delete all accounts at the end
delete_accounts_ = False


def run_server():
    """
    Start the Signal protocol server.

    Creates and runs a Server instance that listens on localhost: 12345
    and handles incoming client connections until the process is terminated.
    """
    Server(verbose=False)
    # The server loop runs indefinitely until externally terminated.


def run_bob():
    """
    Simulate Bob’s behavior: register, add contacts, receive and reply to messages.

    - Waits for server to start.
    - Registers as phone "0002" with name "Bob".
    - Adds Alice as a contact.
    - Waits for Alice’s initial handshake messages.
    - Fetches and decrypts incoming messages.
    - Sends multiple replies to Alice.
    - Sends messages to Charlie and Dave (including unknown contacts).
    - Lists final contact state.
    """
    time.sleep(2)  # allow server to come up

    bob = Client()
    bob.login(phone_number="0002", password="1234")

    time.sleep(3)  # wait for Alice’s initial handshake
    bob.check_for_messages()

    # Send a series of encrypted replies to Alice
    bob.send_private_message(name="Alice", message="It is been a while...")

    # update Charlie's name
    bob.update_contact_name(phone_number="0003", contact_name="Charlie")
    bob.update_contact_name(phone_number="0004", contact_name="Dave")

    time.sleep(5)  # give Alice time to fetch replies
    bob.check_for_messages()

    # Send messages to other contacts (including first-time and unknown)
    bob.send_private_message(name="Charlie", message="Whats up Charlie!")      # using Charlie's profile name
    bob.send_private_message(phone_number="0003", message="Are you ok?")   # using Charlie's phone number
    bob.send_private_message(phone_number="0004", message="I added you Dave.")

    # Display Bob’s contact list at the end of the run
    bob.list_contacts()

    # delete the account
    if delete_accounts_:
        bob.delete_account()

def run_alice():
    """
    Simulate Alice’s behavior: register, add Bob, send initial messages, then fetch replies.

    - Waits for server to start.
    - Registers as phone "0001" with name "Alice".
    - Adds Bob as a contact.
    - Sends three initial messages to Bob to initiate X3DH handshake plus ratchet chain.
    - Waits for Bob’s responses.
    - Fetches and decrypts incoming messages from Bob.
    - Lists final contact state.
    """
    time.sleep(2)  # ensure the server is ready

    alice = Client()
    alice.login(phone_number="0001", password="1234")

    time.sleep(1)  # ensure Bob is registered

    # Send initial handshake and messages to Bob
    alice.send_private_message(name="Bob", message="Sup Bob :)")

    time.sleep(5)  # allow Bob to process and reply
    alice.check_for_messages()
    alice.list_contacts()

    # delete the account
    if delete_accounts_:
        alice.delete_account()


def run_charlie():
    """
    Simulate Charlie’s behavior: register, add Bob, send one message, then fetch replies.

    - Registers as phone "0003" with the name "Charlie".
    - Adds Bob as a contact.
    - Sends an initial message to Bob.
    - Waits for any responses.
    - Fetches and decrypts incoming messages.
    """
    time.sleep(6)  # ensure the server has been up long enough

    charlie = Client()
    charlie.login(phone_number="0003", password="1234")

    # Send a single message to Bob
    charlie.send_private_message(name="Bob", message="Hello Bob!")
    time.sleep(6)  # await replies
    charlie.check_for_messages()

    # delete the account
    if delete_accounts_:
        charlie.delete_account()


def run_dave():
    """
    Simulate Dave’s behavior: register, send a message to Bob without adding as contact, then fetch replies.

    - Registers as phone "0004" with the name "Dave".
    - Does not add Bob explicitly as a contact.
    - Sends a message to Bob; Bob should add Dave on first contact.
    - Waits for any responses.
    - Fetches and decrypts incoming messages.
    """
    time.sleep(8)  # wait for server and other processes

    dave = Client()
    dave.login(phone_number="0004", password="1234")

    # Send a message directly using Bob's phone number
    dave.send_private_message(
        phone_number="0002",
        message="Hello Bob."
    )
    time.sleep(6)
    dave.check_for_messages()

    # delete the account
    if delete_accounts_:
        dave.delete_account()


if __name__ == "__main__":
    # Launch server and client processes in parallel
    p_server = multiprocessing.Process(target=run_server, name="Server")
    p_alice = multiprocessing.Process(target=run_alice, name="Alice")
    p_bob = multiprocessing.Process(target=run_bob, name="Bob")
    p_charlie = multiprocessing.Process(target=run_charlie, name="Charlie")
    p_dave = multiprocessing.Process(target=run_dave, name="Dave")

    # Start all processes
    p_server.start()
    p_alice.start()
    p_bob.start()
    p_charlie.start()
    p_dave.start()

    # Wait for clients to finish their interactions
    p_alice.join()
    p_bob.join()
    p_charlie.join()
    p_dave.join()

    # Terminate the server process
    print("\nProcess 0: Server")
    print("\tTerminating server")
    p_server.terminate()
    p_server.join()
