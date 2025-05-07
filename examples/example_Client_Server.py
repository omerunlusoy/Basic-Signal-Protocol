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

# delete server at the end
delete_server_ = False

# list messages after checking
list_messages_ = True


def run_server():
    """
    Start the Signal protocol server.

    Creates and runs a Server instance that listens on localhost: 12345
    and handles incoming client connections until the process is terminated.
    """
    # The server loop runs indefinitely until externally terminated.
    server = Server()
    server.register_server(admin_username="omer", admin_password="123", verbose=False)
    server.loop()


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
    bob.register(phone_number="0002", password="1234", name="Bob", verbose=verbose_)
    bob.add_contact(phone_number="0001", name="Alice")

    time.sleep(3)  # wait for Alice’s initial handshake
    bob.check_for_messages(list_messages_)

    # Send a series of encrypted replies to Alice
    bob.send_private_message(name="Alice", message="Hello Alice!")
    bob.send_private_message(name="Alice", message="I am fine, thank you.")
    bob.send_private_message(name="Alice", message="Glad to see it works.")

    time.sleep(5)  # give Alice time to fetch replies
    bob.check_for_messages(list_messages_)

    # Send messages to other contacts (including first-time and unknown)
    bob.send_private_message(name="Charlie", message="Hello Charlie!")      # using Charlie's profile name
    bob.send_private_message(phone_number="0003", message="How are you?")   # using Charlie's phone number
    bob.send_private_message(phone_number="0004", message="Who is this?")

    # update Charlie's name
    bob.update_contact_name(phone_number="0003", contact_name="Charlie")

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
    alice.register(
        phone_number="0001",
        password="1234",
        name="Alice",
        about="Love from Alice :)",
        receivers_can_see_my_name=True,
        verbose=verbose_
    )
    alice.add_contact(phone_number="0002", name="Bob")

    time.sleep(1)  # ensure Bob is registered

    # Send initial handshake and messages to Bob
    alice.send_private_message(name="Bob", message="Hello Bob!")
    alice.send_private_message(name="Bob", message="How are you?")
    alice.send_private_message(name="Bob", message="I am just testing Signal.")

    time.sleep(5)  # allow Bob to process and reply
    alice.check_for_messages(list_messages_)
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
    charlie.register(
        phone_number="0003",
        password="1234",
        name="Charlie",
        receivers_can_see_my_name=True,
        verbose=verbose_
    )
    charlie.add_contact(phone_number="0002", name="Bob")

    # Send a single message to Bob
    charlie.send_private_message(name="Bob", message="Hello Bob!")
    time.sleep(6)  # await replies
    charlie.check_for_messages(list_messages_)

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
    dave.register(
        phone_number="0004",
        password="1234",
        name="Dave",
        receivers_can_see_my_name=False,
        verbose=verbose_
    )

    # Send a message directly using Bob's phone number
    dave.send_private_message(
        phone_number="0002",
        message="Hello Bob, it is Dave, save my number please."
    )
    time.sleep(6)
    # dave.check_for_messages(list_messages_)

    # delete the account
    if delete_accounts_:
        dave.delete_account()


def main():
    # list to keep track of all processes
    processes = []

    try:
        # 1) Start the server
        p_server = multiprocessing.Process(target=run_server, name="Server")
        p_server.start()
        processes.append(p_server)

        # 2) Kick off all four clients
        for fn, name in [(run_alice, "Alice"),
                         (run_bob, "Bob"),
                         (run_charlie, "Charlie"),
                         (run_dave, "Dave")]:
            p = multiprocessing.Process(target=fn, name=name)
            p.start()
            processes.append(p)

        # 3) Wait for clients to finish, but don’t block forever
        for p in processes[1:]:   # skip server
            # you can choose an appropriate timeout (seconds)
            p.join(timeout=60)
            if p.is_alive():
                print(f"{p.name} didn’t exit in time, terminating…")
                p.terminate()
                p.join()

        # 4) All clients done—now shutdown the server
        print("\nAll clients finished; shutting down server…")
        p_server.terminate()
        p_server.join(timeout=5)
        if p_server.is_alive():
            print("Server still alive, killing it")
            p_server.kill()
            p_server.join()

        if delete_server_:
            Server().delete_server(admin_username="omer")

    except KeyboardInterrupt:
        # if you hit Ctrl-C, this will let you fall through to finally
        print("Interrupted by user; cleaning up…")
    finally:
        # this is *guaranteed* to run once main() exits the try block
        for p in processes:
            if p.is_alive():
                print(f"Terminating {p.name}")
                p.terminate()
                p.join()


if __name__ == "__main__":
    main()
