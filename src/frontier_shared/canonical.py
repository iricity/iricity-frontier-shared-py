"""Canonical JSON per RFC 8785 (JSON Canonicalization Scheme).

Rules implemented:
- object members sorted by the UTF-16 code units of their names
- numbers serialized with the ECMAScript Number-to-string algorithm
- strings escaped exactly as ECMAScript JSON.stringify escapes them
- no insignificant whitespace

Non-finite floats are rejected: a canonical form must be unambiguous.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

__all__ = ["canonical_json", "format_number"]


def format_number(value: float | int) -> str:
    """ECMAScript Number::toString for a finite number (ECMA-262 section 6.1.6.1.20)."""
    if isinstance(value, bool):
        raise TypeError("booleans are not numbers")
    if isinstance(value, int):
        return str(value)
    if not isinstance(value, float):
        raise TypeError(f"not a number: {type(value).__name__}")
    if math.isnan(value) or math.isinf(value):
        raise ValueError("canonical_json: non-finite number")
    if value == 0.0:
        return "0"

    sign = "-" if value < 0 else ""
    # repr() gives the shortest digit string that round-trips, the same digits
    # ECMAScript chooses. Decimal exposes them as (digits, exponent).
    tup = Decimal(repr(abs(value))).as_tuple()
    digits = list(tup.digits)
    exponent = int(tup.exponent)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    k = len(digits)
    n = k + exponent  # value = 0.d1d2...dk x 10^n
    s = "".join(str(d) for d in digits)

    if k <= n <= 21:
        body = s + "0" * (n - k)
    elif 0 < n <= 21:
        body = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + s
    else:
        e = n - 1
        exp = ("+" if e >= 0 else "-") + str(abs(e))
        body = (s if k == 1 else s[0] + "." + s[1:]) + "e" + exp
    return sign + body


_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _escape_string(text: str) -> str:
    out = ['"']
    for ch in text:
        esc = _SHORT_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
            continue
        code = ord(ch)
        if code < 0x20 or 0xD800 <= code <= 0xDFFF:
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _key_order(name: Any) -> bytes:
    # Lexicographic order of UTF-16BE bytes equals UTF-16 code unit order.
    if not isinstance(name, str):
        raise TypeError("canonical_json: object keys must be strings")
    return name.encode("utf-16-be", "surrogatepass")


def _serialize(value: Any, path: str) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, (int, float)):
        try:
            return format_number(value)
        except ValueError as error:
            raise ValueError(f"{error} at {path}") from None
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(item, f"{path}[{index}]") for index, item in enumerate(value)) + "]"
    if isinstance(value, dict):
        members = []
        for key in sorted(value.keys(), key=_key_order):
            if not isinstance(key, str):
                raise TypeError(f"canonical_json: object keys must be strings at {path}")
            members.append(_escape_string(key) + ":" + _serialize(value[key], f"{path}.{key}"))
        return "{" + ",".join(members) + "}"
    raise TypeError(f"canonical_json: unsupported value {type(value).__name__} at {path}")


def canonical_json(value: Any) -> str:
    """Return the RFC 8785 canonical JSON text of a JSON-compatible Python value."""
    return _serialize(value, "$")
