"""
Test for Server and Client
"""

import multiprocessing
import time

from Server import Server  # your Server implementation
from Client import Client  # your Client implementation

verbose_ = False

def run_server():
    Server(verbose=False)
    # print("[Server] starting…")


def run_bob():
    time.sleep(2)
    if verbose_:
        print("Process 2: Bob")
    bob = Client(phone_number="0002", name="Bob", verbose=verbose_)
    if verbose_:
        print("Process 2: Bob")
    bob.add_contact(phone_number="0001", name="Alice")

    time.sleep(3)  # wait for Alice’s initial message
    if verbose_:
        print("\nProcess 2: Bob")
    bob.check_for_messages()
    if verbose_:
        print("Process 2: Bob")
    bob.send_private_message(name="Alice", message="Hello Alice!")
    bob.send_private_message(name="Alice", message="I am fine, thank you.")
    bob.send_private_message(name="Alice", message="Glad to see it works.")
    time.sleep(5)  # give Alice time to fetch it
    if verbose_:
        print("\nProcess 2: Bob")
    bob.check_for_messages()
    bob.send_private_message(name="Charlie", message="Hello Charlie!")
    bob.send_private_message(phone_number="0003", message="How are you?")
    bob.send_private_message(phone_number="0004", message="Who is this?")
    bob.list_contacts()


def run_alice():
    time.sleep(2)  # ensure te server is up
    if verbose_:
        print("\nProcess 1: Alice")
    alice = Client(phone_number="0001", name="Alice", about="Love from Alice :)", receivers_can_see_my_name=True, verbose=verbose_)
    if verbose_:
        print("Process 1: Alice")
    alice.add_contact(phone_number="0002", name="Bob")
    if verbose_:
        print("Process 1: Alice")
    alice.send_private_message(name="Bob", message="Hello Bob!")
    alice.send_private_message(name="Bob", message="How are you?")
    alice.send_private_message(name="Bob", message="I am just testing Signal.")

    time.sleep(5)  # let Bob process and reply
    if verbose_:
        print("\nProcess 1: Alice")
    alice.check_for_messages()
    alice.list_contacts()


def run_charlie():
    time.sleep(6)  # ensure te server is up
    if verbose_:
        print("\nProcess 3: Charlie")
    charlie = Client(phone_number="0003", name="Charlie", receivers_can_see_my_name=True, verbose=verbose_)
    if verbose_:
        print("Process 3: Charlie")
    charlie.add_contact(phone_number="0002", name="Bob")
    if verbose_:
        print("Process 3: Charlie")
    charlie.send_private_message(name="Bob", message="Hello Bob!")
    time.sleep(6)
    charlie.check_for_messages()


def run_dave():
    time.sleep(8)  # ensure te server is up
    if verbose_:
        print("\nProcess 4: Dave")
    dave = Client(phone_number="0004", name="Dave", receivers_can_see_my_name=False, verbose=verbose_)
    if verbose_:
        print("Process 4: Dave")
    # dave.add_contact(phone_number="0002", name="Bob")
    if verbose_:
        print("Process 4: Dave")
    dave.send_private_message(phone_number="0002", message="Hello Bob, it is Dave, save my number please.")
    time.sleep(6)
    dave.check_for_messages()


if __name__ == "__main__":
    # Spawn the three processes
    p_server = multiprocessing.Process(target=run_server, name="Server")
    p_bob = multiprocessing.Process(target=run_bob, name="Bob")
    p_alice = multiprocessing.Process(target=run_alice, name="Alice")
    p_charlie = multiprocessing.Process(target=run_charlie, name="Charlie")
    p_dave = multiprocessing.Process(target=run_dave, name="Dave")

    p_server.start()
    p_bob.start()
    p_alice.start()
    p_charlie.start()
    p_dave.start()

    # Wait for the clients to finish
    p_alice.join()
    p_bob.join()
    p_charlie.join()
    p_dave.join()

    # Tear down the server
    print("\nProcess 0: Server")
    print("\t Terminating server")
    p_server.terminate()
    p_server.join()
