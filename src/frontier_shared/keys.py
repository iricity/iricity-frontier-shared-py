"""Ed25519 identity primitives.

Identities are ``did:key`` identifiers (W3C did:key method):
``did:key:z<base58btc(0xed 0x01 || 32-byte public key)>``.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .base58 import multibase_decode_base58btc, multibase_encode_base58btc

__all__ = [
    "ED25519_MULTICODEC_PREFIX",
    "KeyPair",
    "resolve_signer",
    "did_from_public_key_bytes",
    "public_key_bytes_from_did",
    "public_key_multibase_from_did",
    "is_did_key",
    "fingerprint_did",
    "sign_bytes",
    "verify_bytes",
    "encode_signature",
    "decode_signature",
]

ED25519_MULTICODEC_PREFIX = b"\xed\x01"
DID_KEY_PREFIX = "did:key:"


def did_from_public_key_bytes(raw: bytes) -> str:
    raw = _to_bytes(raw, "did_from_public_key_bytes")
    if len(raw) != 32:
        raise ValueError("ed25519 public key must be 32 bytes")
    return DID_KEY_PREFIX + multibase_encode_base58btc(ED25519_MULTICODEC_PREFIX + raw)


def is_did_key(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(DID_KEY_PREFIX + "z6Mk")


def public_key_bytes_from_did(did: str) -> bytes:
    if not isinstance(did, str) or not did.startswith(DID_KEY_PREFIX):
        raise ValueError("expected a did:key identifier")
    decoded = multibase_decode_base58btc(did[len(DID_KEY_PREFIX):])
    if len(decoded) != 34 or decoded[:2] != ED25519_MULTICODEC_PREFIX:
        raise ValueError("did:key is not an ed25519 public key")
    return decoded[2:]


def public_key_multibase_from_did(did: str) -> str:
    return did[len(DID_KEY_PREFIX):]


def fingerprint_did(did: str) -> str:
    return "fp_" + hashlib.sha256(public_key_bytes_from_did(did)).hexdigest()[:20]


def _to_bytes(value: Any, label: str) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str) and len(value) % 2 == 0:
        try:
            return bytes.fromhex(value)
        except ValueError:
            pass
    raise TypeError(f"{label}: expected bytes or hex")


@dataclass(frozen=True)
class KeyPair:
    """An ed25519 key pair with its did:key."""

    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes | str) -> "KeyPair":
        raw = _to_bytes(seed, "KeyPair.from_seed")
        if len(raw) != 32:
            raise ValueError("ed25519 seed must be 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    @classmethod
    def from_private_key_pem(cls, pem: str | bytes) -> "KeyPair":
        text = pem.decode("utf-8") if isinstance(pem, bytes) else pem
        text = text.replace("\\n", "\n").strip()
        key = serialization.load_pem_private_key(text.encode("utf-8"), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("private key is not ed25519")
        return cls(key)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @property
    def seed(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )

    @property
    def did(self) -> str:
        return did_from_public_key_bytes(self.public_key_bytes)

    @property
    def key_id(self) -> str:
        return self.did

    @property
    def public_key_multibase(self) -> str:
        return public_key_multibase_from_did(self.did)

    def sign(self, message: bytes | str) -> bytes:
        data = message.encode("utf-8") if isinstance(message, str) else bytes(message)
        return self.private_key.sign(data)


def resolve_signer(signer: Any) -> KeyPair:
    """Accept a KeyPair, a hex seed, a PEM string, or a mapping with
    ``private_key_seed_hex`` / ``private_key_pem`` / ``private_key``."""
    if signer is None:
        raise TypeError("signer is required")
    if isinstance(signer, KeyPair):
        return signer
    if isinstance(signer, Ed25519PrivateKey):
        return KeyPair(signer)
    if isinstance(signer, str):
        if "PRIVATE KEY" in signer:
            return KeyPair.from_private_key_pem(signer)
        return KeyPair.from_seed(signer)
    if isinstance(signer, (bytes, bytearray)):
        return KeyPair.from_seed(bytes(signer))
    if isinstance(signer, Mapping):
        pair: KeyPair | None = None
        private_key = signer.get("private_key")
        if isinstance(private_key, KeyPair):
            pair = private_key
        elif isinstance(private_key, Ed25519PrivateKey):
            pair = KeyPair(private_key)
        elif isinstance(private_key, str) and "PRIVATE KEY" in private_key:
            pair = KeyPair.from_private_key_pem(private_key)
        elif private_key is not None:
            pair = KeyPair.from_seed(private_key)
        elif signer.get("private_key_pem"):
            pair = KeyPair.from_private_key_pem(signer["private_key_pem"])
        elif signer.get("private_key_seed_hex"):
            pair = KeyPair.from_seed(signer["private_key_seed_hex"])
        if pair is None:
            raise TypeError("signer has no private key material")
        expected = signer.get("did")
        if expected and expected != pair.did:
            raise ValueError("signer did does not match the private key")
        return pair
    raise TypeError("unsupported signer")


def encode_signature(signature: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(signature)).decode("ascii").rstrip("=")


def decode_signature(text: str) -> bytes:
    if not isinstance(text, str):
        raise TypeError("signature must be a string")
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def sign_bytes(message: bytes | str, signer: Any) -> bytes:
    return resolve_signer(signer).sign(message)


def verify_bytes(message: bytes | str, signature: bytes | str, verifier: Any) -> bool:
    try:
        if isinstance(verifier, KeyPair):
            public_key = verifier.public_key
        elif isinstance(verifier, Ed25519PublicKey):
            public_key = verifier
        elif is_did_key(verifier):
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes_from_did(verifier))
        elif isinstance(verifier, Mapping) and verifier.get("did"):
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes_from_did(verifier["did"]))
        else:
            public_key = Ed25519PublicKey.from_public_bytes(_to_bytes(verifier, "verify_bytes"))
        data = message.encode("utf-8") if isinstance(message, str) else bytes(message)
        sig = decode_signature(signature) if isinstance(signature, str) else bytes(signature)
        public_key.verify(sig, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
