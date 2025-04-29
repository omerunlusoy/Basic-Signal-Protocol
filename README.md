# Basic Signal Protocol

This project implements X3DH Key agreement protocol and Double Ratchet algorithm within the Signal Protocol in Python using cryptography and hashlib packages [[1]](#1). This code is written for educational purposes only and should not be used in production.

## X3DH Key Agreement Protocol
  - establishes a shared secret key between two parties who mutually authenticate each other based on public keys.
  - perfect forward secrecy
  - post compromised security (self-healing)
  - cryptographic deniability

## Double Ratchet Algorithm
  - derives new keys for every Double Ratchet (session) message so that earlier keys cannot be calculated from later ones.

## Folder Structure
- __`X3DH`__ : Contains the X3DH class implementation.
- __`DoubleRatchet`__ : Contains the DoubleRatchetSession class.
- __`SHA256`__ : Provides a wrapper around Python’s hashlib.sha256 with optional salt & pepper for anonymizing phone numbers.
- __`Client`__ : Implements the user-side Client class:
    - Registers on the server with a pre-key bundle
    - Manages contacts, local state, and profile settings
    - Carries X3DH handshakes and Double Ratchet sessions
    - Sends / receives encrypted messages via the server
- __`Server`__ : Implements the Server class:
    - Listens on TCP port 12345 for client connections
    - Handles account registration and pre-key bundle requests
    - Queues and relays both initial handshake messages and normal encrypted messages
- __`Contact`__ : Defines the Contact TypedDict and list_contact() helper.
- __`Profile`__ : Defines the Profile TypedDict and (de)serialization functions.
- __`PrivateMessage`__ : Defines the PrivateMessage TypedDict, plus serialization and deserialization helpers.
- __`PrekeyBundle`__ : Defines the PreKeyBundle TypedDict and (de)serialization functions:
    - Encodes X25519 identity keys, signed pre-keys, and one-time pre-keys into raw bytes
- __`InitialMessage`__ : Defines the InitialMessage TypedDict and (de)serialization functions:
	- Represents the initiator’s first handshake message in X3DH
	- Includes identity & ephemeral public keys plus a one-time pre-key index
- __`example_X3DH_DoubleRatchet`__ : A standalone script test script:
	- Demonstrates a complete X3DH handshake between two parties
	- Runs a four-message back-and-forth using the Double Ratchet session
	- Prints decrypted outputs to verify correctness
- __`example_Client_Server`__ : A standalone test script that:
	- Spawns a Server process and multiple Client processes (Alice, Bob, Charlie, Dave)
	- Simulates registration, key exchanges, and encrypted messaging in parallel
	- Shows how new contacts are added dynamically and messages are fetched


### References
<a id="1">[1]</a> “Documentation.” Signal Messenger, https://signal.org/docs/. Accessed 30 Apr. 2025.
