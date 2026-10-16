"""Signed envelope, wire format ``state-envelope/1``.

The signature covers the canonical JSON of the header (version, payload type,
payload hash, signer, creation time, previous link) prefixed with a domain tag.
The payload travels by hash, so an envelope verifies with or without its body.
Verification never raises on malformed input; every problem is an entry in ``errors``.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Mapping

from .canonical import canonical_json
from .hashing import hash_payload, is_hash_ref, sha256_hex
from .keys import encode_signature, is_did_key, is_valid_signature_text, resolve_signer, verify_bytes

__all__ = [
    "ENVELOPE_VERSION",
    "ENVELOPE_DOMAIN_TAG",
    "HEADER_FIELDS",
    "TIMESTAMP_PATTERN",
    "is_timestamp",
    "now_iso",
    "envelope_header",
    "envelope_signing_input",
    "envelope_hash",
    "envelope_id_from_hash",
    "create_envelope",
    "verify_envelope",
]

ENVELOPE_VERSION = "state-envelope/1"
ENVELOPE_DOMAIN_TAG = "state-envelope/1:"
HEADER_FIELDS = ["envelope_version", "payload_type", "payload_hash", "signer", "created_at", "previous_envelope_hash"]

# ISO-8601 UTC with a Z suffix and an optional fraction of up to three digits.
TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$")

_UNSET = object()


def now_iso() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def is_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not TIMESTAMP_PATTERN.match(value):
        return False
    try:
        datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return False
    return True


def envelope_header(envelope: Mapping[str, Any]) -> dict:
    """The six header fields, each present (None when absent) so the signing input is total."""
    return {field: envelope.get(field) for field in HEADER_FIELDS}


def envelope_signing_input(envelope: Mapping[str, Any]) -> str:
    return ENVELOPE_DOMAIN_TAG + canonical_json(envelope_header(envelope))


def envelope_hash(envelope: Mapping[str, Any]) -> str:
    return "sha256:" + sha256_hex(envelope_signing_input(envelope))


def envelope_id_from_hash(digest: str) -> str:
    return "env_" + digest[7:31]


def create_envelope(
    payload: Any,
    payload_type: str,
    signer: Any,
    created_at: str | None = None,
    previous_envelope_hash: str | None = None,
    detached: bool = False,
) -> dict:
    if not payload_type or not isinstance(payload_type, str):
        raise TypeError("payload_type is required")
    stamp = now_iso() if created_at is None else created_at
    if not is_timestamp(stamp):
        raise ValueError("created_at must be ISO-8601 UTC with a Z suffix")
    if previous_envelope_hash is not None and not is_hash_ref(previous_envelope_hash):
        raise ValueError("previous_envelope_hash must be a sha256: reference or None")

    pair = resolve_signer(signer)
    header = {
        "envelope_version": ENVELOPE_VERSION,
        "payload_type": payload_type,
        "payload_hash": hash_payload(payload),
        "signer": pair.did,
        "created_at": stamp,
        "previous_envelope_hash": previous_envelope_hash,
    }
    signing_input = ENVELOPE_DOMAIN_TAG + canonical_json(header)
    digest = "sha256:" + sha256_hex(signing_input)

    envelope = dict(header)
    envelope["envelope_hash"] = digest
    envelope["envelope_id"] = envelope_id_from_hash(digest)
    if not detached:
        envelope["payload"] = payload
    envelope["signature"] = {
        "algorithm": "ed25519",
        "key_id": pair.did,
        "value": encode_signature(pair.sign(signing_input)),
    }
    return envelope


def _result(envelope: Mapping[str, Any] | None, checks: list[str], errors: list[str]) -> dict:
    get = envelope.get if isinstance(envelope, Mapping) else (lambda key, default=None: default)
    return {
        "verified": not errors,
        "signer": get("signer"),
        "payload_type": get("payload_type"),
        "payload_hash": get("payload_hash"),
        "envelope_hash": get("envelope_hash"),
        "checks": checks,
        "errors": errors,
    }


def verify_envelope(
    envelope: Any,
    payload: Any = _UNSET,
    expected_signer: str | None = None,
    allowed_payload_types: Any = None,
) -> dict:
    checks: list[str] = []
    errors: list[str] = []

    if not isinstance(envelope, Mapping):
        return _result(None, checks, ["envelope must be an object"])

    for field in HEADER_FIELDS:
        if field == "previous_envelope_hash":
            if field not in envelope:
                errors.append("missing header field: previous_envelope_hash")
        elif envelope.get(field) is None:
            errors.append(f"missing header field: {field}")
    if not errors:
        checks.append("header_complete")

    if envelope.get("envelope_version") != ENVELOPE_VERSION:
        errors.append(f"unsupported envelope_version: {envelope.get('envelope_version')}")
    else:
        checks.append("version_supported")

    payload_type = envelope.get("payload_type")
    if not isinstance(payload_type, str) or not payload_type:
        errors.append("payload_type must be a non-empty string")
    if not is_hash_ref(envelope.get("payload_hash")):
        errors.append("payload_hash must be a sha256: reference")
    previous = envelope.get("previous_envelope_hash")
    if previous is not None and not is_hash_ref(previous):
        errors.append("previous_envelope_hash must be a sha256: reference or null")
    if not is_timestamp(envelope.get("created_at")):
        errors.append("created_at must be ISO-8601 UTC with a Z suffix")
    else:
        checks.append("timestamp_format")

    signer = envelope.get("signer")
    if not is_did_key(signer):
        errors.append("signer must be an ed25519 did:key")
    else:
        checks.append("signer_is_did_key")

    if expected_signer and signer != expected_signer:
        errors.append("signer does not match expected_signer")

    if allowed_payload_types is not None:
        if not isinstance(allowed_payload_types, (list, tuple, set, frozenset)):
            errors.append("allowed_payload_types must be a list")
        elif payload_type not in allowed_payload_types:
            errors.append(f"payload_type not allowed: {payload_type}")

    body = payload if payload is not _UNSET else envelope.get("payload", _UNSET)
    if body is not _UNSET:
        try:
            body_hash = hash_payload(body)
        except (TypeError, ValueError) as error:
            body_hash = None
            errors.append(f"payload is not canonicalizable: {error}")
        if body_hash is not None:
            if body_hash == envelope.get("payload_hash"):
                checks.append("payload_hash_match")
            else:
                errors.append("payload hash mismatch")
    else:
        checks.append("payload_detached_hash_only")

    if not errors:
        expected_hash = envelope_hash(envelope)
        if not is_hash_ref(envelope.get("envelope_hash")):
            errors.append("envelope_hash must be a sha256: reference")
        elif envelope.get("envelope_hash") != expected_hash:
            errors.append("envelope hash mismatch")
        else:
            checks.append("envelope_hash_match")
        if "envelope_id" in envelope:
            if envelope.get("envelope_id") == envelope_id_from_hash(expected_hash):
                checks.append("envelope_id_match")
            else:
                errors.append("envelope_id does not match envelope_hash")

    if not errors:
        signature = envelope.get("signature")
        if not isinstance(signature, Mapping):
            errors.append("signature must be an object")
        elif signature.get("algorithm") != "ed25519":
            errors.append(f"unsupported signature algorithm: {signature.get('algorithm')}")
        elif "key_id" in signature and signature.get("key_id") != signer:
            errors.append("signature key_id does not match signer")
        elif not is_valid_signature_text(signature.get("value")):
            errors.append("signature value must be 64 bytes as unpadded base64url")
        elif verify_bytes(envelope_signing_input(envelope), signature["value"], signer):
            checks.append("signature_valid")
        else:
            errors.append("signature invalid")

    return _result(envelope, checks, errors)
