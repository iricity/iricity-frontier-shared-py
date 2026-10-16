"""Signed envelope, wire format ``state-envelope/1``.

The signature covers the canonical JSON of the header (version, payload type,
payload hash, signer, creation time, previous link) prefixed with a domain tag.
The payload travels by hash, so an envelope verifies with or without its body.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from .canonical import canonical_json
from .hashing import hash_payload, is_hash_ref, sha256_hex
from .keys import encode_signature, is_did_key, resolve_signer, verify_bytes

__all__ = [
    "ENVELOPE_VERSION",
    "ENVELOPE_DOMAIN_TAG",
    "envelope_header",
    "envelope_signing_input",
    "envelope_hash",
    "create_envelope",
    "verify_envelope",
]

ENVELOPE_VERSION = "state-envelope/1"
ENVELOPE_DOMAIN_TAG = "state-envelope/1:"

_UNSET = object()


def now_iso() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def envelope_header(envelope: Mapping[str, Any]) -> dict:
    return {
        "envelope_version": envelope.get("envelope_version"),
        "payload_type": envelope.get("payload_type"),
        "payload_hash": envelope.get("payload_hash"),
        "signer": envelope.get("signer"),
        "created_at": envelope.get("created_at"),
        "previous_envelope_hash": envelope.get("previous_envelope_hash"),
    }


def envelope_signing_input(envelope: Mapping[str, Any]) -> str:
    return ENVELOPE_DOMAIN_TAG + canonical_json(envelope_header(envelope))


def envelope_hash(envelope: Mapping[str, Any]) -> str:
    return "sha256:" + sha256_hex(envelope_signing_input(envelope))


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
    if previous_envelope_hash is not None and not is_hash_ref(previous_envelope_hash):
        raise ValueError("previous_envelope_hash must be a sha256: reference or None")

    pair = resolve_signer(signer)
    header = {
        "envelope_version": ENVELOPE_VERSION,
        "payload_type": payload_type,
        "payload_hash": hash_payload(payload),
        "signer": pair.did,
        "created_at": created_at or now_iso(),
        "previous_envelope_hash": previous_envelope_hash,
    }
    signing_input = ENVELOPE_DOMAIN_TAG + canonical_json(header)
    digest = "sha256:" + sha256_hex(signing_input)

    envelope = dict(header)
    envelope["envelope_hash"] = digest
    envelope["envelope_id"] = "env_" + digest[7:31]
    if not detached:
        envelope["payload"] = payload
    envelope["signature"] = {
        "algorithm": "ed25519",
        "key_id": pair.did,
        "value": encode_signature(pair.sign(signing_input)),
    }
    return envelope


def verify_envelope(
    envelope: Any,
    payload: Any = _UNSET,
    expected_signer: str | None = None,
    allowed_payload_types: list[str] | None = None,
) -> dict:
    checks: list[str] = []
    errors: list[str] = []

    if not isinstance(envelope, Mapping):
        return {"verified": False, "checks": checks, "errors": ["envelope must be an object"]}

    if envelope.get("envelope_version") != ENVELOPE_VERSION:
        errors.append(f"unsupported envelope_version: {envelope.get('envelope_version')}")
    else:
        checks.append("version_supported")

    signer = envelope.get("signer")
    if not is_did_key(signer):
        errors.append("signer must be an ed25519 did:key")
    else:
        checks.append("signer_is_did_key")

    if expected_signer and signer != expected_signer:
        errors.append("signer does not match expected_signer")

    if allowed_payload_types is not None and envelope.get("payload_type") not in allowed_payload_types:
        errors.append(f"payload_type not allowed: {envelope.get('payload_type')}")

    body = payload if payload is not _UNSET else envelope.get("payload", _UNSET)
    if body is not _UNSET:
        if hash_payload(body) == envelope.get("payload_hash"):
            checks.append("payload_hash_match")
        else:
            errors.append("payload hash mismatch")
    else:
        checks.append("payload_detached_hash_only")

    if not errors:
        expected_hash = envelope_hash(envelope)
        if envelope.get("envelope_hash") and envelope.get("envelope_hash") != expected_hash:
            errors.append("envelope hash mismatch")
        else:
            checks.append("envelope_hash_match")

    if not errors:
        signature = envelope.get("signature") or {}
        if signature.get("algorithm") != "ed25519":
            errors.append(f"unsupported signature algorithm: {signature.get('algorithm')}")
        elif signature.get("key_id") and signature.get("key_id") != signer:
            errors.append("signature key_id does not match signer")
        elif verify_bytes(envelope_signing_input(envelope), signature.get("value", ""), signer):
            checks.append("signature_valid")
        else:
            errors.append("signature invalid")

    return {
        "verified": not errors,
        "signer": signer,
        "payload_type": envelope.get("payload_type"),
        "payload_hash": envelope.get("payload_hash"),
        "envelope_hash": envelope.get("envelope_hash"),
        "checks": checks,
        "errors": errors,
    }
