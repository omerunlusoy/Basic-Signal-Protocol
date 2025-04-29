"""
Educational implementation of the Signal X3DH
===============================================================================

X3DH key agreement implementation in Python using the Signal Protocol's
Extended Triple Diffie-Hellman handshake.

This script demonstrates:
1. Generation of identity and pre-keys
2. Performing four Diffie-Hellman computations
3. Deriving a shared secret via HKDF with salt
4. A simple handshake between an Initiator (Alice) and Responder (Bob)

Dependencies:
    pip install cryptography

Key Significance:
    Alice   ↔   Bob
 1.  IK_A   ↔   SPK_B   (authenticity via SPK signature)
 2.  EK_A   ↔   IK_B    (ties Alice’s fresh randomness to Bob’s identity)
 3.  EK_A   ↔   SPK_B   (strengthens binding between Alice’s ephemeral and Bob’s semi-static)
 4.  EK_A   ↔   OPK_B   (per-session one-time secrecy boost)

Note:
    Your display name and avatar live in your Signal Profile
        (stored encrypted on Signal’s servers as profile blob)
    Your first message establishes X3DH and then sends your
        symmetric profile key

Author: Ömer Ünlüsoy
Date:   30-April-2025
"""

from typing import Tuple, List, Optional
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.exceptions import InvalidSignature

from PrekeyBundle import PreKeyBundle
from InitialMessage import InitialMessage


def generate_identity_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """
    Generate a long-term X25519 identity key pair.
    Identity Key Pair (X25519) Role & significance:
        This is your long‑term Diffie–Hellman key pair. Its public half is published in your “address book” and used by anyone initiating a session.
        Provides a stable anchor for authenticity: others can trust your identity.
    Lifetime:
        Rotate very infrequently—months to years. Protect its private half rigorously (HSM or encrypted storage).
    """
    identity_private_key = X25519PrivateKey.generate()
    identity_public_key = identity_private_key.public_key()
    return identity_private_key, identity_public_key


def generate_signed_prekey(signing_key_private: Ed25519PrivateKey) -> Tuple[X25519PrivateKey, X25519PublicKey, bytes]:
    """
    Generate a semi-static X25519 pre-key and sign its public key with an Ed25519 signing key.
    Signed Pre-Key Pair (X25519) Role & significance:
        A semi‑static DH key published with an Ed25519 signature. Allows asynchronous session starts without you online.
    Lifetime:
        Rotate periodically—days to weeks. Limits the impact of compromise and balances bundle update frequency.

    Args:
        signing_key_private: The Ed25519 private key used to sign the pre-key.

    Returns:
        A tuple of (prekey_private_key, prekey_public_key, signature).
    """
    signed_prekey_private = X25519PrivateKey.generate()
    signed_prekey_public = signed_prekey_private.public_key()
    raw_public = signed_prekey_public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    signed_prekey_signature = signing_key_private.sign(raw_public)
    return signed_prekey_private, signed_prekey_public, signed_prekey_signature


def generate_one_time_prekey_list(N: int) -> Tuple[list[X25519PublicKey], list[X25519PrivateKey]]:
    """
    Generates two lists of one-time X25519 prekeys.
    The first list contains public keys, the second list contains the associated private keys.

    One-Time Pre-Key Pair (X25519) Role & significance:
        A single‑use DH key providing extra forward‑secrecy boost per session.
    Lifetime:
        Until used, then removed. Client replenishes automatically.

    This method creates N one-time prekey pairs using the X25519 key exchange algorithm.
    Each pair consists of a public key and a corresponding private key. The generated
    public and private keys are stored in separate lists that are returned as a tuple.

    Args:
        N: The number of one-time prekey pairs to generate.

    Returns:
        A tuple containing two lists:
        - A list of X25519PublicKey objects, each representing a generated public key.
        - A list of X25519PrivateKey objects, each representing the corresponding
          private key.
    """
    one_time_prekey_public_list = []
    one_time_prekey_private_list = []
    for _ in range(N):
        one_time_private_key = X25519PrivateKey.generate()
        one_time_prekey_private_list.append(one_time_private_key)
        one_time_prekey_public_list.append(one_time_private_key.public_key())
    return one_time_prekey_public_list, one_time_prekey_private_list


def derive_shared_secret(dh_shared_materials: List[bytes], salt: bytes, info: bytes = b'X3DH') -> bytes:
    """
    Derive a final symmetric shared secret via HKDF-SHA256.

    Args:
        dh_shared_materials: A list of raw Diffie-Hellman shared secrets.
        salt: A byte string used as salt for HKDF.
        info: Optional context information for HKDF.

    Returns:
        A 32-byte shared secret.
    """
    concatenated_materials = b''.join(dh_shared_materials)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    )
    return hkdf.derive(concatenated_materials)


class X3DH:
    """
    An implementation of the Extended Triple Diffie-Hellman (X3DH) key agreement protocol.
    Each instance can act as both initiator and responder.
    """
    def __init__(self, N: int = 10) -> None:
        """
        Initialize a new X3DH party with:
            - A long-term identity key pair.
            - A signing key pair for pre-key authentication.
            - A semi-static signed pre-key.
            - A one-time pre-key.
        """
        # Long-term identity key pair
        self.identity_private_key, self.identity_public_key = generate_identity_keypair()
        # Ed25519 signing key pair for authenticating the signed pre-key
        self.signing_private_key = Ed25519PrivateKey.generate()
        self.signing_public_key = self.signing_private_key.public_key()
        # Generate and sign the semi-static pre-key
        (
            self.signed_prekey_private_key,
            self.signed_prekey_public_key,
            self.signed_prekey_signature
        ) = generate_signed_prekey(self.signing_private_key)
        # Generate a one-time pre-key
        self.one_time_prekey_public_list, self.one_time_prekey_private_list = generate_one_time_prekey_list(N)
        # Storage for the peer's pre-key bundle when acting as initiator
        self.peer_prekey_bundle: Optional[PreKeyBundle] = None
        self.N = N

    def get_prekey_bundle(self) -> PreKeyBundle:
        """
        Publish this party's public pre-key bundle.

        Returns:
            A PreKeyBundle containing all public keys and signatures.
        """
        return {
            'identity_public_key': self.identity_public_key,
            'signing_public_key': self.signing_public_key,
            'signed_prekey_public': self.signed_prekey_public_key,
            'signed_prekey_signature': self.signed_prekey_signature,
            'one_time_prekey_public_list': self.one_time_prekey_public_list,
            'one_time_prekey_public_index': 0
        }

    def load_peer_prekey_bundle(self, bundle: PreKeyBundle) -> None:
        """
        Load and verify a peer's pre-key bundle before initiating a handshake.

        Args:
            bundle: The PreKeyBundle published by the peer.

        Raises:
            ValueError: If the signed pre-key signature is invalid.
        """
        raw_prekey_bytes = bundle['signed_prekey_public'].public_bytes(Encoding.Raw, PublicFormat.Raw)
        try:
            bundle['signing_public_key'].verify(bundle['signed_prekey_signature'], raw_prekey_bytes)
        except InvalidSignature as error:
            raise ValueError("Invalid signed pre-key signature") from error

    def initiate_handshake(self, peer_prekey_bundle: PreKeyBundle, one_time_prekey_public_index: int = 0) -> Tuple[InitialMessage, bytes, Optional[X25519PrivateKey]]:
        """
        Act as initiator: produce an InitialMessage and derive the shared secret.

        Returns:
            A tuple of (InitialMessage, shared_secret).

        Raises:
            ValueError: If no peer bundle is loaded.
        """
        if peer_prekey_bundle is None:
            raise ValueError("Peer pre-key bundle not loaded")

        # Generate ephemeral key pair for this handshake
        ephemeral_private_key = X25519PrivateKey.generate()
        ephemeral_public_key = ephemeral_private_key.public_key()

        # Construct salt from all public keys
        salt_material = (
            self.identity_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            + ephemeral_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            + peer_prekey_bundle['identity_public_key'].public_bytes(Encoding.Raw, PublicFormat.Raw)
            + peer_prekey_bundle['signed_prekey_public'].public_bytes(Encoding.Raw, PublicFormat.Raw)
            + peer_prekey_bundle['one_time_prekey_public_list'][one_time_prekey_public_index].public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

        # Perform four DH exchanges
        dh_identity_signed = self.identity_private_key.exchange(
            peer_prekey_bundle['signed_prekey_public']
        )
        dh_ephemeral_identity = ephemeral_private_key.exchange(
            peer_prekey_bundle['identity_public_key']
        )
        dh_ephemeral_signed = ephemeral_private_key.exchange(
            peer_prekey_bundle['signed_prekey_public']
        )
        dh_ephemeral_one_time = ephemeral_private_key.exchange(
            peer_prekey_bundle['one_time_prekey_public_list'][one_time_prekey_public_index]
        )

        # Zeroize ephemeral private key
        # ephemeral_private_key = None # type: ignore

        # Derive the final shared secret
        shared_secret = derive_shared_secret(
            [dh_identity_signed, dh_ephemeral_identity, dh_ephemeral_signed, dh_ephemeral_one_time],
            salt_material
        )

        initial_message: InitialMessage = {
            'initiator_identity_public_key': self.identity_public_key,
            'initiator_ephemeral_public_key': ephemeral_public_key,
            'one_time_prekey_public_index': one_time_prekey_public_index
        }
        return initial_message, shared_secret, ephemeral_private_key

    def respond_handshake(self, initial_message: InitialMessage) -> bytes:
        """
        Act as responder: process an InitialMessage and derive the shared secret.

        Args:
            initial_message: The InitialMessage received from the initiator.

        Returns:
            The shared secret.
        """

        one_time_prekey_public_index_ = initial_message['one_time_prekey_public_index']
        # Reconstruct salt from all public keys
        salt_material = (
            initial_message['initiator_identity_public_key'].public_bytes(Encoding.Raw, PublicFormat.Raw)
            + initial_message['initiator_ephemeral_public_key'].public_bytes(Encoding.Raw, PublicFormat.Raw)
            + self.identity_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            + self.signed_prekey_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            + self.one_time_prekey_public_list[one_time_prekey_public_index_].public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

        # Perform four DH exchanges
        dh_signed_identity = self.signed_prekey_private_key.exchange(
            initial_message['initiator_identity_public_key']
        )
        dh_identity_ephemeral = self.identity_private_key.exchange(
            initial_message['initiator_ephemeral_public_key']
        )
        dh_signed_ephemeral = self.signed_prekey_private_key.exchange(
            initial_message['initiator_ephemeral_public_key']
        )
        dh_one_time_ephemeral = self.one_time_prekey_private_list[one_time_prekey_public_index_].exchange(
            initial_message['initiator_ephemeral_public_key']
        )

        # Zeroize a one-time pre-key private key
        self.one_time_prekey_private_list[one_time_prekey_public_index_] = None  # type: ignore

        # Derive the final shared secret
        return derive_shared_secret(
            [dh_signed_identity, dh_identity_ephemeral, dh_signed_ephemeral, dh_one_time_ephemeral],
            salt_material
        )
