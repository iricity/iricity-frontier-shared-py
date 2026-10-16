"""Base58btc (Bitcoin alphabet), as used by multibase prefix 'z'."""

from __future__ import annotations

__all__ = ["base58_encode", "base58_decode", "multibase_encode_base58btc", "multibase_decode_base58btc"]

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {char: index for index, char in enumerate(ALPHABET)}


def base58_encode(data: bytes) -> str:
    data = bytes(data)
    if not data:
        return ""
    value = int.from_bytes(data, "big")
    encoded = ""
    while value > 0:
        value, remainder = divmod(value, 58)
        encoded = ALPHABET[remainder] + encoded
    leading = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading + encoded


def base58_decode(text: str) -> bytes:
    if not isinstance(text, str):
        raise TypeError("base58_decode expects a string")
    if text == "":
        return b""
    value = 0
    for char in text:
        digit = _INDEX.get(char)
        if digit is None:
            raise ValueError(f"base58_decode: invalid character {char!r}")
        value = value * 58 + digit
    body = b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")
    leading = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading + body


def multibase_encode_base58btc(data: bytes) -> str:
    return "z" + base58_encode(data)


def multibase_decode_base58btc(text: str) -> bytes:
    if not isinstance(text, str) or not text.startswith("z"):
        raise ValueError('expected a multibase base58btc string starting with "z"')
    return base58_decode(text[1:])
