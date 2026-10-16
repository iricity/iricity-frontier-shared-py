"""Canonical JSON per RFC 8785 (JSON Canonicalization Scheme).

Rules implemented:
- object members sorted by the UTF-16 code units of their names
- numbers serialized with the ECMAScript Number-to-string algorithm; every number
  is a double, so integers beyond 2**53 are rounded exactly as JavaScript rounds them
- strings escaped exactly as ECMAScript JSON.stringify escapes them
- no insignificant whitespace

Rejected, because a canonical form must be unambiguous and a verifier must not be
crashable: non-finite floats, non-string keys, non-JSON values, nesting deeper than
MAX_DEPTH.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

__all__ = ["canonical_json", "format_number", "MAX_DEPTH"]

MAX_DEPTH = 256
_MAX_SAFE_INTEGER = 2**53


def format_number(value: float | int) -> str:
    """ECMAScript Number::toString for a finite number (ECMA-262 section 6.1.6.1.20)."""
    if isinstance(value, bool):
        raise TypeError("booleans are not numbers")
    if isinstance(value, int):
        if abs(value) < _MAX_SAFE_INTEGER:
            return str(value)
        # JSON has only doubles: a larger integer literal is the nearest double.
        value = float(value)
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


def _serialize(value: Any, path: str, depth: int) -> str:
    if depth > MAX_DEPTH:
        raise TypeError(f"canonical_json: nesting deeper than {MAX_DEPTH} at {path}")
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
        return "[" + ",".join(_serialize(item, f"{path}[{index}]", depth + 1) for index, item in enumerate(value)) + "]"
    if isinstance(value, dict):
        members = []
        for key in sorted(value.keys(), key=_key_order):
            members.append(_escape_string(key) + ":" + _serialize(value[key], f"{path}.{key}", depth + 1))
        return "{" + ",".join(members) + "}"
    raise TypeError(f"canonical_json: unsupported value {type(value).__name__} at {path}")


def canonical_json(value: Any) -> str:
    """Return the RFC 8785 canonical JSON text of a JSON-compatible Python value."""
    return _serialize(value, "$", 0)
