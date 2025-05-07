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

wait_ = 0.03


def run_server():
    """
    Start the Signal protocol server.

    Creates and runs a Server instance that listens on localhost: 12345
    and handles incoming client connections until the process is terminated.
    """
    server = Server()
    server.register_server(admin_username="omer", admin_password="123", verbose=False)
    server.loop()
    # The server loop runs indefinitely until externally terminated.


def run_clients():
    time.sleep(wait_)
    # Bob
    bob = Client()
    bob.register(phone_number="0002", password="1234", name="Bob", verbose=verbose_)
    bob.add_contact(phone_number="0001", name="Alice")

    time.sleep(wait_)
    # Alice
    alice = Client()
    alice.register(
        phone_number="0001",
        password="1234",
        name="Alice",
        about="Love from Alice :)",
        receivers_can_see_my_name=True,
        verbose=verbose_
    )
    alice.add_contact(phone_number="0002", name="Bob")

    time.sleep(wait_)
    alice.send_private_message(name="Bob", message="Hello Bob!")
    alice.send_private_message(name="Bob", message="How are you?")
    alice.send_private_message(name="Bob", message="I am just testing Signal.")

    time.sleep(wait_)

    # Charlie
    charlie = Client()
    charlie.register(
        phone_number="0003",
        password="1234",
        name="Charlie",
        receivers_can_see_my_name=True,
        verbose=verbose_
    )
    charlie.add_contact(phone_number="0002", name="Bob")

    time.sleep(wait_)
    # Send a single message to Bob
    charlie.send_private_message(name="Bob", message="Hello Bob!")

    time.sleep(wait_)
    # Dave
    dave = Client()
    dave.register(
        phone_number="0004",
        password="1234",
        name="Dave",
        receivers_can_see_my_name=False,
        verbose=verbose_
    )

    time.sleep(wait_)
    # Send a message directly using Bob's phone number
    dave.send_private_message(
        phone_number="0002",
        message="Hello Bob, it is Dave, save my number please."
    )
    time.sleep(wait_)
    # Bob check messages
    bob.check_for_messages()

    time.sleep(wait_)
    # Send a series of encrypted replies to Alice
    bob.send_private_message(name="Alice", message="Hello Alice!")
    bob.send_private_message(name="Alice", message="I am fine, thank you.")
    bob.send_private_message(name="Alice", message="Glad to see it works.")

    time.sleep(wait_)
    # Send messages to other contacts (including first-time and unknown)
    bob.send_private_message(name="Charlie", message="Hello Charlie!")  # using Charlie's profile name
    bob.send_private_message(phone_number="0003", message="How are you?")  # using Charlie's phone number
    bob.send_private_message(phone_number="0004", message="Who is this?")

    time.sleep(wait_)
    # update Charlie's name
    bob.update_contact_name(phone_number="0003", contact_name="Charlie")

    # Display Bob’s contact list at the end of the run
    bob.list_contacts()

    time.sleep(wait_)
    # Alice check messages
    alice.check_for_messages()
    alice.list_contacts()

    time.sleep(wait_)
    # Charlie check messages
    charlie.check_for_messages()

    time.sleep(wait_)
    # Dave check messages
    dave.check_for_messages()

    # delete accounts
    if delete_accounts_:
        alice.delete_account()
        bob.delete_account()
        charlie.delete_account()
        dave.delete_account()


if __name__ == "__main__":
    # Launch server and client processes in parallel
    p_server = multiprocessing.Process(target=run_server, name="Server")
    p_clients = multiprocessing.Process(target=run_clients, name="Clients")

    # Start all processes
    p_server.start()
    p_clients.start()

    # Wait for clients to finish their interactions
    p_clients.join()

    # Terminate the server process
    print("\nProcess 0: Server")
    print("\tTerminating server")
    p_server.terminate()
    p_server.join()
