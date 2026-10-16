"""Conformance runner: prove this implementation reproduces the published vectors byte for byte.

Usage::

    frontier-shared-conformance                 # bundled vectors (version 1)
    frontier-shared-conformance path/to/vectors.json
    python -m frontier_shared.conformance

Exit status 0 when conformant, 1 otherwise.
"""

from __future__ import annotations

import json
import sys
from importlib import resources
from pathlib import Path
from typing import Any

from .base58 import base58_encode
from .canonical import canonical_json
from .envelope import create_envelope, verify_envelope
from .hashing import hash_payload
from .keys import KeyPair, did_from_public_key_bytes
from .receipt import create_receipt_record, verify_receipt_record

__all__ = ["load_vectors", "bundled_vectors_path", "run_conformance", "format_report", "main"]


def bundled_vectors_path() -> Path:
    return Path(str(resources.files("frontier_shared") / "vectors" / "v1" / "vectors.json"))


def load_vectors(path: str | Path | None = None) -> dict:
    target = Path(path) if path else bundled_vectors_path()
    with open(target, "r", encoding="utf-8") as handle:
        return json.load(handle)


def run_conformance(vectors: dict | None = None) -> dict:
    vectors = vectors or load_vectors()
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

    for v in vectors["canonical_json"]:
        def canonical_case(v=v):
            actual = canonical_json(v["input"])
            if actual != v["expected_canonical"]:
                return f"expected {v['expected_canonical']} got {actual}"
            if hash_payload(v["input"]) != v["expected_hash"]:
                return "hash mismatch"
            return True
        check("canonical_json", v["id"], canonical_case)

    for v in vectors["base58btc"]:
        def base58_case(v=v):
            actual = base58_encode(bytes.fromhex(v["input_hex"]))
            return True if actual == v["expected"] else f"expected {v['expected']} got {actual}"
        check("base58btc", v["input_hex"] or "empty", base58_case)

    for v in vectors["did_key"]:
        def did_case(v=v):
            actual = did_from_public_key_bytes(bytes.fromhex(v["public_key_hex"]))
            return True if actual == v["expected_did"] else f"expected {v['expected_did']} got {actual}"
        check("did_key", v["expected_did"], did_case)

    for v in vectors["ed25519"]:
        def ed25519_case(v=v):
            pair = KeyPair.from_seed(v["seed_hex"])
            if pair.public_key_bytes.hex() != v["public_key_hex"]:
                return "public key mismatch"
            actual = pair.sign(bytes.fromhex(v["message_hex"])).hex()
            return True if actual == v["expected_signature_hex"] else f"signature mismatch: {actual}"
        check("ed25519", v["id"], ed25519_case)

    for v in vectors["envelope"]:
        def envelope_case(v=v):
            env = create_envelope(
                payload=v["payload"],
                payload_type=v["payload_type"],
                signer={"private_key_seed_hex": v["signer_seed_hex"]},
                created_at=v["created_at"],
                previous_envelope_hash=v["previous_envelope_hash"],
            )
            e = v["expected"]
            for field, expected in (
                ("signer", e["signer"]),
                ("payload_hash", e["payload_hash"]),
                ("envelope_hash", e["envelope_hash"]),
                ("envelope_id", e["envelope_id"]),
            ):
                if env[field] != expected:
                    return f"{field}: expected {expected} got {env[field]}"
            if env["signature"]["value"] != e["signature_value"]:
                return f"signature: {env['signature']['value']}"
            if not verify_envelope(env)["verified"]:
                return "self-verification failed"
            return True
        check("envelope", v["id"], envelope_case)

    for v in vectors["receipt"]:
        def receipt_case(v=v):
            issuer: Any = {"private_key_seed_hex": v["signer_seed_hex"]} if v.get("signer_seed_hex") else v["issuer"]
            receipt = create_receipt_record(
                record=v["record"], previous_hash=v["previous_hash"], issuer=issuer, timestamp=v["timestamp"]
            )
            e = v["expected"]
            for field in ("receipt_id", "record_hash", "previous_hash", "receipt_hash", "issuer", "signature", "signature_algorithm"):
                if receipt.get(field) != e.get(field):
                    return f"{field}: expected {e.get(field)} got {receipt.get(field)}"
            if not verify_receipt_record(receipt, record=v["record"])["verified"]:
                return "self-verification failed"
            return True
        check("receipt", v["id"], receipt_case)

    passed = sum(1 for r in results if r["status"] == "passed")
    failed = sum(1 for r in results if r["status"] == "failed")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    return {
        "vectors_version": vectors.get("vectors_version"),
        "conformant": failed == 0 and passed > 0,
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
