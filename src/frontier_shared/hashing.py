"""SHA-256 hash references over canonical JSON."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .canonical import canonical_json

__all__ = ["HASH_PREFIX", "sha256_hex", "sha256_hex_bytes", "hash_payload", "hash_text", "hash_bytes", "hash_record", "is_hash_ref"]

HASH_PREFIX = "sha256:"
_HASH_REF = re.compile(r"^sha256:[0-9a-f]{64}$")


def sha256_hex(text: str) -> str:
    """Hex SHA-256 of a UTF-8 string."""
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_payload(payload: Any) -> str:
    """Hash reference of any JSON value, always over its canonical JSON form.

    A string payload is hashed as the JSON string (quoted), never as raw text, so an
    object and the text of that object can never share a reference.
    """
    return HASH_PREFIX + sha256_hex(canonical_json(payload))


def hash_text(text: str) -> str:
    """Hash reference of raw UTF-8 text (not JSON-encoded)."""
    if not isinstance(text, str):
        raise TypeError("hash_text expects a string")
    return HASH_PREFIX + sha256_hex(text)


def hash_bytes(data: bytes) -> str:
    return HASH_PREFIX + sha256_hex_bytes(data)


def hash_record(record: Any) -> str:
    """Identical to hash_payload, kept for readability."""
    return hash_payload(record)


def is_hash_ref(value: Any) -> bool:
    return isinstance(value, str) and bool(_HASH_REF.match(value))
