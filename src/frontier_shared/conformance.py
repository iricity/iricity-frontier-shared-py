"""Conformance runner: prove this implementation reproduces the published vectors byte for byte.

Usage::

    frontier-shared-conformance                 # bundled vectors
    frontier-shared-conformance path/to/vectors.json
    python -m frontier_shared.conformance

An implementation conforms only when every suite passes and none is skipped.
Exit status 0 when conformant, 1 otherwise.
"""

from __future__ import annotations

import json
import sys
from importlib import resources
from pathlib import Path
from typing import Any

from .base58 import base58_decode, base58_encode
from .canonical import canonical_json
from .envelope import create_envelope, verify_envelope
from .hashing import hash_payload
from .keys import KeyPair, did_from_public_key_bytes, public_key_bytes_from_did
from .receipt import create_receipt_record, verify_receipt_record

__all__ = ["VECTORS_VERSION", "SUITES", "load_vectors", "bundled_vectors_path", "bundled_lock_path", "run_conformance", "format_report", "main"]

VECTORS_VERSION = "2"
SUITES = ["canonical_json", "hash_payload", "base58btc", "did_key", "ed25519", "envelope", "receipt", "rejections"]


def bundled_vectors_path() -> Path:
    return Path(str(resources.files("frontier_shared") / "vectors" / f"v{VECTORS_VERSION}" / "vectors.json"))


def bundled_lock_path() -> Path:
    return Path(str(resources.files("frontier_shared") / "vectors" / f"v{VECTORS_VERSION}" / "vectors.lock.json"))


def load_vectors(path: str | Path | None = None) -> dict:
    target = Path(path) if path else bundled_vectors_path()
    with open(target, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _signer(v: dict) -> dict:
    return {"private_key_seed_hex": v["signer_seed_hex"]}


def run_conformance(vectors: dict | None = None) -> dict:
    if vectors is None:
        vectors = load_vectors()
    results: list[dict] = []

    def record(suite: str, case_id: str, status: str, detail: str | None = None) -> None:
        entry = {"suite": suite, "id": case_id, "status": status}
        if detail:
            entry["detail"] = detail
        results.append(entry)

    def check(suite: str, case_id: str, fn) -> None:
        try:
            outcome = fn()
            if outcome is True:
                record(suite, case_id, "passed")
            else:
                record(suite, case_id, "failed", outcome if isinstance(outcome, str) else "mismatch")
        except Exception as error:  # noqa: BLE001 - every failure is a finding
            record(suite, case_id, "failed", f"{type(error).__name__}: {error}")

    def suite(name: str) -> list:
        cases = vectors.get(name)
        if not isinstance(cases, list) or not cases:
            record(name, "*", "failed", f'vectors file has no "{name}" suite')
            return []
        return cases

    for v in suite("canonical_json"):
        def canonical_case(v=v):
            actual = canonical_json(v["input"])
            if actual != v["expected_canonical"]:
                return f"expected {v['expected_canonical']} got {actual}"
            digest = hash_payload(v["input"])
            return True if digest == v["expected_hash"] else f"hash mismatch: {digest}"
        check("canonical_json", v["id"], canonical_case)

    for v in suite("hash_payload"):
        def hash_case(v=v):
            actual = hash_payload(v["input"])
            return True if actual == v["expected_hash"] else f"expected {v['expected_hash']} got {actual}"
        check("hash_payload", v["id"], hash_case)

    for v in suite("base58btc"):
        def base58_case(v=v):
            encoded = base58_encode(bytes.fromhex(v["input_hex"]))
            if encoded != v["expected"]:
                return f"encode: expected {v['expected']} got {encoded}"
            decoded = base58_decode(v["expected"]).hex()
            return True if decoded == v["input_hex"] else f"decode: expected {v['input_hex']} got {decoded}"
        check("base58btc", v.get("id") or v["input_hex"] or "empty", base58_case)

    for v in suite("did_key"):
        def did_case(v=v):
            did = did_from_public_key_bytes(bytes.fromhex(v["public_key_hex"]))
            if did != v["expected_did"]:
                return f"encode: expected {v['expected_did']} got {did}"
            raw = public_key_bytes_from_did(v["expected_did"]).hex()
            return True if raw == v["public_key_hex"] else f"decode: expected {v['public_key_hex']} got {raw}"
        check("did_key", v["expected_did"], did_case)

    for v in suite("ed25519"):
        def ed25519_case(v=v):
            pair = KeyPair.from_seed(v["seed_hex"])
            if pair.public_key_bytes.hex() != v["public_key_hex"]:
                return "public key mismatch"
            actual = pair.sign(bytes.fromhex(v["message_hex"])).hex()
            return True if actual == v["expected_signature_hex"] else f"signature mismatch: {actual}"
        check("ed25519", v["id"], ed25519_case)

    for v in suite("envelope"):
        def envelope_case(v=v):
            detached = bool(v.get("detached"))
            env = create_envelope(
                payload=v["payload"],
                payload_type=v["payload_type"],
                signer=_signer(v),
                created_at=v["created_at"],
                previous_envelope_hash=v["previous_envelope_hash"],
                detached=detached,
            )
            e = v["expected"]
            for field in ("signer", "payload_hash", "envelope_hash", "envelope_id"):
                if env[field] != e[field]:
                    return f"{field}: expected {e[field]} got {env[field]}"
            if env["signature"]["value"] != e["signature_value"]:
                return f"signature: {env['signature']['value']}"
            if detached and "payload" in env:
                return "detached envelope must not carry a payload"
            verification = verify_envelope(env, payload=v["payload"]) if detached else verify_envelope(env)
            if not verification["verified"]:
                return "self-verification failed: " + "; ".join(verification["errors"])
            if detached and not verify_envelope(env)["verified"]:
                return "detached envelope must verify without its payload"
            return True
        check("envelope", v["id"], envelope_case)

    for v in suite("receipt"):
        def receipt_case(v=v):
            if v.get("legacy"):
                verification = verify_receipt_record(v["receipt"], record=v["record"])
                if verification["verified"] != v["expected"]["verified"]:
                    return f"legacy: expected verified={v['expected']['verified']} got {verification['verified']}: " + "; ".join(verification["errors"])
                return True
            issuer: Any = _signer(v) if v.get("signer_seed_hex") else v["issuer"]
            receipt = create_receipt_record(record=v["record"], previous_hash=v["previous_hash"], issuer=issuer, timestamp=v["timestamp"])
            e = v["expected"]
            for field in ("receipt_id", "record_hash", "previous_hash", "receipt_hash", "issuer", "signature", "signature_algorithm", "verification_status"):
                if receipt.get(field) != e.get(field):
                    return f"{field}: expected {e.get(field)} got {receipt.get(field)}"
            verification = verify_receipt_record(receipt, record=v["record"])
            return True if verification["verified"] else "self-verification failed: " + "; ".join(verification["errors"])
        check("receipt", v["id"], receipt_case)

    for v in suite("rejections"):
        def rejection_case(v=v):
            options = v.get("options") or {}
            if v["kind"] == "envelope":
                kwargs = {}
                if "payload" in options:
                    kwargs["payload"] = options["payload"]
                if "expected_signer" in options:
                    kwargs["expected_signer"] = options["expected_signer"]
                if "allowed_payload_types" in options:
                    kwargs["allowed_payload_types"] = options["allowed_payload_types"]
                verification = verify_envelope(v["object"], **kwargs)
                return True if verification["verified"] is False else "tampered envelope was accepted"
            if v["kind"] == "receipt":
                kwargs = {}
                if "record" in options:
                    kwargs["record"] = options["record"]
                if "previous_receipt" in options:
                    kwargs["previous_receipt"] = options["previous_receipt"]
                if "expected_issuer" in options:
                    kwargs["expected_issuer"] = options["expected_issuer"]
                verification = verify_receipt_record(v["object"], **kwargs)
                return True if verification["verified"] is False else "tampered receipt was accepted"
            return f"unknown rejection kind {v['kind']}"
        check("rejections", v["id"], rejection_case)

    passed = sum(1 for r in results if r["status"] == "passed")
    failed = sum(1 for r in results if r["status"] == "failed")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    return {
        "vectors_version": vectors.get("vectors_version"),
        "conformant": failed == 0 and skipped == 0 and passed > 0,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "results": results,
    }


def format_report(report: dict) -> str:
    lines = [
        f"conformance vectors {report['vectors_version']}: {report['passed']} passed, "
        f"{report['failed']} failed, {report['skipped']} skipped"
    ]
    for r in report["results"]:
        if r["status"] != "passed":
            detail = f": {r['detail']}" if r.get("detail") else ""
            lines.append(f"  [{r['status']}] {r['suite']}/{r['id']}{detail}")
    lines.append("RESULT: conformant" if report["conformant"] else "RESULT: not conformant")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    vectors = load_vectors(args[0]) if args else load_vectors()
    report = run_conformance(vectors)
    print(format_report(report))
    return 0 if report["conformant"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
