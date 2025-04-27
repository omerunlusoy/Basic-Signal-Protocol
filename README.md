# Basic Signal Protocol

This project implements X3DH Key Exchange and Double Ratchet algorithm for Signal Protocol in Python using cryptography and hashlib packages.


## Signal Protocol
- X3DH  (Extended Triple Diffie-Hellman) key agreement protocol
  - establishes a shared secret key between two parties who mutually authenticate each other based on public keys.
  - perfect forward secrecy
  - post compromised security (self-healing)
    - If the eavesdropper looks away for a second, they lose the keys.
  - cryptographic deniability

- Double Ratchet
  - derives new keys for every Double Ratchet (session) message so that earlier keys cannot be calculated from later ones.
