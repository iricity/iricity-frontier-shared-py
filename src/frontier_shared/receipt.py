"""Signed receipt chain, wire format ``state-receipt/1``.

A receipt proves that an issuer accepted a record (by canonical hash) at a time,
linked to the previous receipt. ``signature_algorithm`` is one of ``ed25519``
(issuer is a did:key), ``sha256_chain_legacy`` (integrity only) or ``none``.
"""

from __future__ import annotations

from typing import Any, Mapping

from .canonical import canonical_json
from .envelope import now_iso
from .hashing import hash_payload, hash_record, is_hash_ref, sha256_hex
from .keys import encode_signature, is_did_key, resolve_signer, verify_bytes

__all__ = [
    "RECEIPT_VERSION",
    "RECEIPT_DOMAIN_TAG",
    "RECEIPT_SIGNATURE_ALGORITHMS",
    "receipt_core",
    "receipt_signing_input",
    "compute_receipt_hash",
    "create_receipt_record",
    "verify_receipt_record",
    "verify_receipt_chain",
]

RECEIPT_VERSION = "state-receipt/1"
RECEIPT_DOMAIN_TAG = "state-receipt/1:"
RECEIPT_SIGNATURE_ALGORITHMS = ["ed25519", "sha256_chain_legacy", "none"]

_UNSET = object()


def receipt_core(receipt: Mapping[str, Any]) -> dict:
    return {
        "receipt_id": receipt.get("receipt_id"),
        "record_hash": receipt.get("record_hash"),
        "previous_hash": receipt.get("previous_hash"),
        "timestamp": receipt.get("timestamp"),
        "issuer": receipt.get("issuer"),
    }


def receipt_signing_input(receipt: Mapping[str, Any]) -> str:
    return RECEIPT_DOMAIN_TAG + canonical_json(receipt_core(receipt))


def compute_receipt_hash(receipt: Mapping[str, Any]) -> str:
    return hash_payload(receipt_core(receipt))


def _derive_receipt_id(record_hash: str, previous_hash: str | None, timestamp: str, issuer: str) -> str:
    material = canonical_json(
        {"record_hash": record_hash, "previous_hash": previous_hash, "timestamp": timestamp, "issuer": issuer}
    )
    return "rcp_" + sha256_hex(material)[:24]


def create_receipt_record(
    record: Any = _UNSET,
    record_hash: str | None = None,
    previous_hash: str | None = None,
    issuer: Any = None,
    timestamp: str | None = None,
    receipt_id: str | None = None,
) -> dict:
    digest = record_hash if record_hash is not None else (hash_record(record) if record is not _UNSET else None)
    if not is_hash_ref(digest):
        raise ValueError("record or record_hash (sha256:) is required")
    if previous_hash is not None and not is_hash_ref(previous_hash):
        raise ValueError("previous_hash must be a sha256: reference or None")

    pair = resolve_signer(issuer) if issuer is not None and not isinstance(issuer, str) else None
    issuer_id = pair.did if pair else (issuer or "unsigned")
    stamp = timestamp or now_iso()
    core = {
        "receipt_id": receipt_id or _derive_receipt_id(digest, previous_hash, stamp, issuer_id),
        "record_hash": digest,
        "previous_hash": previous_hash,
        "timestamp": stamp,
        "issuer": issuer_id,
    }

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


def verify_receipt_record(
    receipt: Any,
    record: Any = _UNSET,
    previous_receipt: Mapping[str, Any] | None = None,
    expected_issuer: str | None = None,
) -> dict:
    checks: list[str] = []
    errors: list[str] = []
    if not isinstance(receipt, Mapping):
        return {"verified": False, "checks": checks, "errors": ["receipt must be an object"]}

    if receipt.get("record_type") and receipt.get("record_type") != "receipt":
        errors.append('record_type must be "receipt"')
    if not is_hash_ref(receipt.get("record_hash")):
        errors.append("record_hash must be a sha256: reference")
    previous_hash = receipt.get("previous_hash")
    if previous_hash is not None and not is_hash_ref(previous_hash):
        errors.append("previous_hash must be a sha256: reference or null")

    expected_hash = compute_receipt_hash(receipt)
    if receipt.get("receipt_hash"):
        if receipt.get("receipt_hash") == expected_hash:
            checks.append("receipt_hash_match")
        else:
            errors.append("receipt hash mismatch")

    if record is not _UNSET:
        if hash_record(record) == receipt.get("record_hash"):
            checks.append("record_hash_match")
        else:
            errors.append("record hash mismatch")

    if previous_receipt is not None:
        prev_hash = previous_receipt.get("receipt_hash") or compute_receipt_hash(previous_receipt)
        if prev_hash == previous_hash:
            checks.append("previous_link_match")
        else:
            errors.append("previous_hash does not match previous receipt")

    issuer = receipt.get("issuer")
    if expected_issuer and issuer != expected_issuer:
        errors.append("issuer does not match expected_issuer")

    algorithm = receipt.get("signature_algorithm")
    if algorithm is None:
        algorithm = "sha256_chain_legacy" if receipt.get("signature") else "none"

    if algorithm == "ed25519":
        if not is_did_key(issuer):
            errors.append("ed25519 receipts require a did:key issuer")
        elif receipt.get("key_id") and receipt.get("key_id") != issuer:
            errors.append("key_id does not match issuer")
        elif not errors and verify_bytes(receipt_signing_input(receipt), receipt.get("signature") or "", issuer):
            checks.append("signature_valid")
        elif not errors:
            errors.append("signature invalid")
    elif algorithm == "sha256_chain_legacy":
        legacy = sha256_hex("|".join([
            str(receipt.get("record_hash")),
            previous_hash or "",
            str(issuer),
            str(receipt.get("timestamp")),
        ]))
        if legacy == receipt.get("signature"):
            checks.append("legacy_chain_digest_match")
        else:
            errors.append("legacy chain digest mismatch")
    elif algorithm == "none":
        checks.append("unsigned_receipt")
    else:
        errors.append(f"unsupported signature_algorithm: {algorithm}")

    return {
        "verified": not errors,
        "receipt_id": receipt.get("receipt_id"),
        "issuer": issuer,
        "signature_algorithm": algorithm,
        "identity_bound": algorithm == "ed25519",
        "checks": checks,
        "errors": errors,
    }


def verify_receipt_chain(
    receipts: list[Mapping[str, Any]],
    expected_issuer: str | None = None,
    require_genesis: bool = False,
) -> dict:
    results: list[dict] = []
    errors: list[str] = []
    if not isinstance(receipts, list) or not receipts:
        return {"verified": False, "length": 0, "results": results, "errors": ["chain is empty"]}

    for index, receipt in enumerate(receipts):
        result = verify_receipt_record(
            receipt,
            previous_receipt=receipts[index - 1] if index > 0 else None,
            expected_issuer=expected_issuer,
        )
        if index == 0 and require_genesis and receipt.get("previous_hash") is not None:
            result["errors"].append("first receipt must have previous_hash null")
            result["verified"] = False
        results.append(result)
        if not result["verified"]:
            errors.append(f"receipt {index} ({receipt.get('receipt_id', 'unknown')}): {'; '.join(result['errors'])}")

    return {
        "verified": not errors,
        "length": len(receipts),
        "head": receipts[-1].get("receipt_hash"),
        "results": results,
        "errors": errors,
    }
