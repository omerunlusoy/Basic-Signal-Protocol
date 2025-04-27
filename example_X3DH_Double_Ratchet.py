"""
Test for X3DH and Double Ratchet
"""

from X3DH import X3DH
from Double_Ratchet import DoubleRatchetSession


def main() -> None:

    """Demonstrate an X3DH handshake between two parties."""
    initiator = X3DH()
    responder = X3DH()

    # Responder publishes their bundle; initiator loads and verifies it
    responder_bundle = responder.get_prekey_bundle()
    initiator.load_peer_prekey_bundle(responder_bundle)

    # Initiator starts handshake
    message, secret_initiator, ephemeral_private_key = initiator.initiate_handshake(responder_bundle)
    # Responder processes handshake and derives same secret
    secret_responder = responder.respond_handshake(message)

    assert secret_initiator == secret_responder, "Shared secrets do not match!"
    print("X3DH handshake successful. Shared secret:", secret_initiator.hex())

    """Run a four-message Alice ↔ Bob exchange to verify ratchet behavior."""
    print("[Demo] Starting Double Ratchet test...\n")

    initial_root_key, initial_chain_key = DoubleRatchetSession.derive_root_and_chain_keys(root_key=b"\x00" * 32, dh_shared_secret=secret_initiator)

    alice = DoubleRatchetSession(initial_dh_private_key=ephemeral_private_key, root_key=initial_root_key, sending_chain_key=initial_chain_key, receiving_chain_key=None, initial_remote=responder_bundle["identity_public_key"])

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
            h, c, ad = alice.encrypt_message(msg)
            rec = bob.decrypt_message(h, c, ad)
            print(f"{speaker}->Bob   :", msg.decode())
            print("Bob  decrypted :", rec.decode(), "\n")
        else:
            h, c, ad = bob.encrypt_message(msg)
            rec = alice.decrypt_message(h, c, ad)
            print(f"{speaker}->Alice :", msg.decode())
            print("Alice decrypted :", rec.decode(), "\n")

    print("[✓] Demo complete – all messages round-tripped successfully.")


if __name__ == "__main__":
    main()
