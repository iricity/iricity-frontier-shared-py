"""Signed receipt chain, wire format ``state-receipt/1``.

A receipt proves that an issuer accepted a record (by canonical hash) at a time,
linked to the previous receipt. ``signature_algorithm`` is one of ``ed25519``
(issuer is a did:key), ``sha256_chain_legacy`` (integrity only) or ``none``.
An issuer that is a did:key must sign: unsigned receipts may not borrow an identity.
Verification never raises on malformed input.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .canonical import canonical_json
from .envelope import is_timestamp, now_iso
from .hashing import hash_payload, hash_record, is_hash_ref, sha256_hex
from .keys import encode_signature, is_did_key, is_valid_signature_text, resolve_signer, verify_bytes

__all__ = [
    "RECEIPT_VERSION",
    "RECEIPT_DOMAIN_TAG",
    "RECEIPT_SIGNATURE_ALGORITHMS",
    "CORE_FIELDS",
    "receipt_core",
    "receipt_signing_input",
    "compute_receipt_hash",
    "derive_receipt_id",
    "create_receipt_record",
    "verify_receipt_record",
    "verify_receipt_chain",
]

RECEIPT_VERSION = "state-receipt/1"
RECEIPT_DOMAIN_TAG = "state-receipt/1:"
RECEIPT_SIGNATURE_ALGORITHMS = ["ed25519", "sha256_chain_legacy", "none"]
CORE_FIELDS = ["receipt_id", "record_hash", "previous_hash", "timestamp", "issuer"]

_UNSET = object()


def receipt_core(receipt: Mapping[str, Any]) -> dict:
    """The five fields every receipt commits to, each present (None when absent)."""
    return {field: receipt.get(field) for field in CORE_FIELDS}


def receipt_signing_input(receipt: Mapping[str, Any]) -> str:
    return RECEIPT_DOMAIN_TAG + canonical_json(receipt_core(receipt))


def compute_receipt_hash(receipt: Mapping[str, Any]) -> str:
    return hash_payload(receipt_core(receipt))


def derive_receipt_id(receipt: Mapping[str, Any]) -> str:
    material = canonical_json(
        {
            "record_hash": receipt.get("record_hash"),
            "previous_hash": receipt.get("previous_hash"),
            "timestamp": receipt.get("timestamp"),
            "issuer": receipt.get("issuer"),
        }
    )
    return "rcp_" + sha256_hex(material)[:24]


def create_receipt_record(
    record: Any = _UNSET,
    record_hash: str | None = None,
    previous_hash: str | None = None,
    issuer: Any = None,
    timestamp: str | None = None,
) -> dict:
    digest = record_hash if record_hash is not None else (hash_record(record) if record is not _UNSET else None)
    if not is_hash_ref(digest):
        raise ValueError("record or record_hash (sha256:) is required")
    if previous_hash is not None and not is_hash_ref(previous_hash):
        raise ValueError("previous_hash must be a sha256: reference or None")
    stamp = now_iso() if timestamp is None else timestamp
    if not is_timestamp(stamp):
        raise ValueError("timestamp must be ISO-8601 UTC with a Z suffix")
    if isinstance(issuer, str) and is_did_key(issuer):
        raise ValueError("a did:key issuer must be given as a signer with its private key")

    pair = resolve_signer(issuer) if issuer is not None and not isinstance(issuer, str) else None
    issuer_id = pair.did if pair else (issuer or "unsigned")
    core = {"record_hash": digest, "previous_hash": previous_hash, "timestamp": stamp, "issuer": issuer_id}
    core = {"receipt_id": derive_receipt_id(core), **core}

    receipt: dict = {"record_type": "receipt", "receipt_version": RECEIPT_VERSION}
    receipt.update(core)
    receipt["receipt_hash"] = hash_payload(core)

    if pair:
        receipt["signature"] = encode_signature(pair.sign(RECEIPT_DOMAIN_TAG + canonical_json(core)))
        receipt["signature_algorithm"] = "ed25519"
        receipt["key_id"] = pair.did
        receipt["verification_status"] = "issued"
    else:
        receipt["signature"] = None
        receipt["signature_algorithm"] = "none"
        receipt["key_id"] = None
        receipt["verification_status"] = "unsigned"
    return receipt


def _result(receipt: Mapping[str, Any] | None, algorithm: str | None, checks: list[str], errors: list[str]) -> dict:
    get = receipt.get if isinstance(receipt, Mapping) else (lambda key, default=None: default)
    return {
        "verified": not errors,
        "receipt_id": get("receipt_id"),
        "issuer": get("issuer"),
        "signature_algorithm": algorithm,
        "identity_bound": (not errors) and algorithm == "ed25519",
        "checks": checks,
        "errors": errors,
    }


def verify_receipt_record(
    receipt: Any,
    record: Any = _UNSET,
    previous_receipt: Any = _UNSET,
    expected_issuer: str | None = None,
) -> dict:
    checks: list[str] = []
    errors: list[str] = []
    if not isinstance(receipt, Mapping):
        return _result(None, None, checks, ["receipt must be an object"])

    algorithm = receipt.get("signature_algorithm")
    if algorithm is None:
        algorithm = "sha256_chain_legacy" if receipt.get("signature") else "none"
    legacy = algorithm == "sha256_chain_legacy"

    if "record_type" in receipt and receipt.get("record_type") != "receipt":
        errors.append('record_type must be "receipt"')
    if not legacy and receipt.get("receipt_version") != RECEIPT_VERSION:
        errors.append(f"unsupported receipt_version: {receipt.get('receipt_version')}")
    elif not legacy:
        checks.append("version_supported")

    for field in CORE_FIELDS:
        if field == "previous_hash":
            if field not in receipt:
                errors.append("missing core field: previous_hash")
        elif receipt.get(field) is None:
            errors.append(f"missing core field: {field}")
    if not errors:
        checks.append("core_complete")

    if not is_hash_ref(receipt.get("record_hash")):
        errors.append("record_hash must be a sha256: reference")
    previous_hash = receipt.get("previous_hash")
    if previous_hash is not None and not is_hash_ref(previous_hash):
        errors.append("previous_hash must be a sha256: reference or null")
    if not is_timestamp(receipt.get("timestamp")):
        errors.append("timestamp must be ISO-8601 UTC with a Z suffix")
    else:
        checks.append("timestamp_format")
    issuer = receipt.get("issuer")
    if not isinstance(issuer, str) or not issuer:
        errors.append("issuer must be a non-empty string")

    if not errors:
        if not legacy:
            if receipt.get("receipt_id") == derive_receipt_id(receipt):
                checks.append("receipt_id_match")
            else:
                errors.append("receipt_id does not match its derivation")
        expected_hash = compute_receipt_hash(receipt)
        receipt_hash = receipt.get("receipt_hash")
        if not is_hash_ref(receipt_hash):
            if legacy and "receipt_hash" not in receipt:
                checks.append("legacy_receipt_without_hash")
            else:
                errors.append("receipt_hash must be a sha256: reference")
        elif receipt_hash == expected_hash:
            checks.append("receipt_hash_match")
        else:
            errors.append("receipt hash mismatch")

    if record is not _UNSET:
        try:
            record_digest = hash_record(record)
        except (TypeError, ValueError) as error:
            record_digest = None
            errors.append(f"record is not canonicalizable: {error}")
        if record_digest is not None:
            if record_digest == receipt.get("record_hash"):
                checks.append("record_hash_match")
            else:
                errors.append("record hash mismatch")

    if previous_receipt is not _UNSET:
        if not isinstance(previous_receipt, Mapping):
            errors.append("previous_receipt must be an object")
        else:
            prev_hash = previous_receipt.get("receipt_hash")
            if not is_hash_ref(prev_hash):
                prev_hash = compute_receipt_hash(previous_receipt)
            if prev_hash == previous_hash:
                checks.append("previous_link_match")
            else:
                errors.append("previous_hash does not match previous receipt")

    if expected_issuer is not None and issuer != expected_issuer:
        errors.append("issuer does not match expected_issuer")

    if algorithm == "ed25519":
        if not is_did_key(issuer):
            errors.append("ed25519 receipts require a did:key issuer")
        elif receipt.get("key_id") is not None and receipt.get("key_id") != issuer:
            errors.append("key_id does not match issuer")
        elif "verification_status" in receipt and receipt.get("verification_status") != "issued":
            errors.append(f'verification_status must be "issued" for signed receipts, got {receipt.get("verification_status")}')
        elif not is_valid_signature_text(receipt.get("signature")):
            errors.append("signature must be 64 bytes as unpadded base64url")
        elif not errors and verify_bytes(receipt_signing_input(receipt), receipt["signature"], issuer):
            checks.append("signature_valid")
        elif not errors:
            errors.append("signature invalid")
    elif legacy:
        if is_did_key(issuer):
            errors.append("a did:key issuer requires an ed25519 signature")
        else:
            digest = sha256_hex("|".join([str(receipt.get("record_hash")), previous_hash or "", str(issuer), str(receipt.get("timestamp"))]))
            if digest == receipt.get("signature"):
                checks.append("legacy_chain_digest_match")
            else:
                errors.append("legacy chain digest mismatch")
    elif algorithm == "none":
        if is_did_key(issuer):
            errors.append("a did:key issuer requires an ed25519 signature")
        elif "verification_status" in receipt and receipt.get("verification_status") != "unsigned":
            errors.append(f'verification_status must be "unsigned" for unsigned receipts, got {receipt.get("verification_status")}')
        elif receipt.get("signature") is not None:
            errors.append("unsigned receipts must not carry a signature")
        else:
            checks.append("unsigned_receipt")
    else:
        errors.append(f"unsupported signature_algorithm: {algorithm}")

    return _result(receipt, algorithm, checks, errors)


def verify_receipt_chain(
    receipts: Sequence[Mapping[str, Any]],
    expected_issuer: str | None = None,
    require_genesis: bool = False,
) -> dict:
    results: list[dict] = []
    errors: list[str] = []
    if isinstance(receipts, (str, bytes, Mapping)) or not isinstance(receipts, Sequence) or len(receipts) == 0:
        return {"verified": False, "length": 0, "head": None, "results": results, "errors": ["chain is empty"]}

    for index, receipt in enumerate(receipts):
        result = verify_receipt_record(
            receipt,
            previous_receipt=receipts[index - 1] if index > 0 else _UNSET,
            expected_issuer=expected_issuer,
        )
        if index == 0 and require_genesis and isinstance(receipt, Mapping) and receipt.get("previous_hash") is not None:
            result["errors"].append("first receipt must have previous_hash null")
            result["verified"] = False
        results.append(result)
        if not result["verified"]:
            rid = receipt.get("receipt_id", "unknown") if isinstance(receipt, Mapping) else "unknown"
            errors.append(f"receipt {index} ({rid}): {'; '.join(result['errors'])}")

    last = receipts[-1]
    return {
        "verified": not errors,
        "length": len(receipts),
        "head": last.get("receipt_hash") if isinstance(last, Mapping) else None,
        "results": results,
        "errors": errors,
    }
