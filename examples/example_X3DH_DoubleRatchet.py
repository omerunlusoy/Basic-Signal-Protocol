"""
Demo for performing an X3DH handshake and verifying Double Ratchet message exchange.

This script:
  1. Performs an X3DH key agreement between two parties (initiator and responder),
     verifying that both derive the same shared secret.
  2. Uses that shared secret to initialize a Double Ratchet session for Alice ↔ Bob,
     then runs a four-message back-and-forth to confirm encryption/decryption works.

Requirements:
    - X3DH implementation in `X3DH.py`
    - Double Ratchet implementation in `DoubleRatchet.py`

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

from X3DH import X3DH
from DoubleRatchet import DoubleRatchetSession


def main() -> None:

    """Demonstrate an X3DH handshake between two parties."""
    initiator = X3DH()
    responder = X3DH()

    # Responder publishes their bundle; initiator loads and verifies it
    responder_bundle = responder.get_prekey_bundle()
    initiator.verify_signed_prekey_signature(responder_bundle)

    # Initiator starts handshake
    message, secret_initiator, ephemeral_private_key = initiator.initiate_handshake(responder_bundle)

    # Responder processes handshake and derives same secret
    secret_responder = responder.respond_handshake(message)

    # make sure that the shared secret's match
    assert secret_initiator == secret_responder, "Shared secrets do not match!"
    print("X3DH handshake successful. Shared secret:", secret_initiator.hex())

    """Run a four-message Alice ↔ Bob exchange to verify ratchet behavior."""
    print("Starting Double Ratchet test...\n")

    # derive the session keys from the X3DH shared secret
    initial_root_key, initial_chain_key = DoubleRatchetSession.derive_root_and_chain_keys(root_key=b"\x00" * 32, dh_shared_secret=secret_initiator)

    # create Alice as the initiator
    alice = DoubleRatchetSession(initial_dh_private_key=ephemeral_private_key, root_key=initial_root_key, sending_chain_key=initial_chain_key, receiving_chain_key=None, initial_remote=responder_bundle["identity_public_key"])

    # test serialization
    alice = alice.serialize_session()
    alice = DoubleRatchetSession.deserialize_session(alice)

    # create Bob as the responder
    bob = DoubleRatchetSession(initial_dh_private_key=responder.signed_prekey_private_key, root_key=initial_root_key, sending_chain_key=None, receiving_chain_key=initial_chain_key, initial_remote=message["initiator_ephemeral_public_key"])

    # Initial DH exchange
    # alice.remote_public_key = bob.dh_private_key.public_key()
    # bob.remote_public_key = alice.dh_private_key.public_key()

    convo = [
        ("Alice", b"Hey Bob, this is a new session."),
        ("Bob", b"Hi Alice! Good to hear from you."),
        ("Alice", b"How's the thesis going?"),
        ("Bob", b"Slow but steady. Yours?"),
    ]

    for speaker, msg in convo:
        if speaker == "Alice":
            msg_encrypted = alice.encrypt_message(msg)
            rec = bob.decrypt_message(msg_encrypted)
            print(f"{speaker}->Bob   :", msg.decode())
            print("Bob  decrypted :", rec.decode(), "\n")
        else:
            msg_encrypted = bob.encrypt_message(msg)
            rec = alice.decrypt_message(msg_encrypted)
            print(f"{speaker}->Alice :", msg.decode())
            print("Alice decrypted :", rec.decode(), "\n")

    print("All messages round-tripped successfully.")


if __name__ == "__main__":
    main()
