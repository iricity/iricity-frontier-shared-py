import math

import pytest

from frontier_shared import (
    KeyPair,
    canonical_json,
    create_envelope,
    create_receipt_record,
    did_from_public_key_bytes,
    fingerprint_did,
    hash_payload,
    hash_record,
    is_did_key,
    public_key_bytes_from_did,
    resolve_signer,
    sign_bytes,
    verify_bytes,
    verify_envelope,
    verify_receipt_chain,
    verify_receipt_record,
)
from frontier_shared.canonical import format_number

RECORD = {"record_type": "entity", "entity_id": "NODE-1", "entity_type": "node", "created_at": "2026-01-01T00:00:00Z"}


def test_number_formatting_matches_ecmascript():
    cases = {
        1.0: "1",
        0.0: "0",
        -0.0: "0",
        1e21: "1e+21",
        1e20: "100000000000000000000",
        123456789012345680000.0: "123456789012345680000",
        1e-7: "1e-7",
        1e-6: "0.000001",
        0.002: "0.002",
        4.5: "4.5",
        333333333.3333333: "333333333.3333333",
        1e30: "1e+30",
        1e-27: "1e-27",
        5e-324: "5e-324",
        -1.5e-9: "-1.5e-9",
        12345678.9: "12345678.9",
        100.0: "100",
    }
    for value, expected in cases.items():
        assert format_number(value) == expected, value
    assert format_number(7) == "7"
    assert format_number(-42) == "-42"
    with pytest.raises(ValueError):
        format_number(math.nan)
    with pytest.raises(ValueError):
        format_number(math.inf)


def test_canonical_json_rules():
    assert canonical_json({"b": 1, "a": [True, None, "x"]}) == '{"a":[true,null,"x"],"b":1}'
    assert canonical_json({"é": 1, "e": 2, "A": 3, "😀": 4, "Ａ": 5}) == '{"A":3,"e":2,"é":1,"😀":4,"Ａ":5}'
    assert canonical_json({"s": "\u0000\u0001\u001f\"\\/\b\f\n\r\t"}) == '{"s":"\\u0000\\u0001\\u001f\\"\\\\/\\b\\f\\n\\r\\t"}'
    with pytest.raises(TypeError):
        canonical_json({"x": object()})
    with pytest.raises(TypeError):
        canonical_json({1: "non-string key"})


def test_keys_round_trip():
    pair = KeyPair.generate()
    assert is_did_key(pair.did)
    assert KeyPair.from_seed(pair.seed).did == pair.did
    assert KeyPair.from_seed(pair.seed.hex()).did == pair.did
    assert public_key_bytes_from_did(pair.did) == pair.public_key_bytes
    assert did_from_public_key_bytes(pair.public_key_bytes) == pair.did
    assert fingerprint_did(pair.did).startswith("fp_")
    assert resolve_signer({"private_key_seed_hex": pair.seed.hex()}).did == pair.did
    with pytest.raises(ValueError):
        resolve_signer({"did": KeyPair.generate().did, "private_key_seed_hex": pair.seed.hex()})


def test_sign_and_verify():
    pair = KeyPair.generate()
    signature = sign_bytes("hello", pair)
    assert verify_bytes("hello", signature, pair.did)
    assert not verify_bytes("hellp", signature, pair.did)
    assert not verify_bytes("hello", signature, KeyPair.generate().did)


def test_envelopes():
    pair = KeyPair.generate()
    payload = {"NORAD_CAT_ID": 25544, "EPOCH": "2026-01-01T00:00:00"}
    envelope = create_envelope(payload, "ccsds.omm.json/1", pair)
    assert envelope["signer"] == pair.did
    assert envelope["payload_hash"] == hash_payload(payload)
    result = verify_envelope(envelope)
    assert result["verified"], result["errors"]
    assert "signature_valid" in result["checks"]

    detached = create_envelope(payload, "ccsds.omm.json/1", pair, detached=True)
    assert "payload" not in detached
    assert verify_envelope(detached)["verified"]
    assert verify_envelope(detached, payload=payload)["verified"]
    assert not verify_envelope(detached, payload={**payload, "EPOCH": "x"})["verified"]

    tampered = {**envelope, "payload": {**payload, "NORAD_CAT_ID": 1}}
    assert not verify_envelope(tampered)["verified"]
    resigned = {**envelope, "signer": KeyPair.generate().did}
    assert not verify_envelope(resigned)["verified"]
    assert not verify_envelope(envelope, expected_signer=KeyPair.generate().did)["verified"]
    assert not verify_envelope(envelope, allowed_payload_types=["opaque.json/1"])["verified"]

    chained = create_envelope({"n": 2}, "opaque.json/1", pair, previous_envelope_hash=envelope["envelope_hash"])
    assert chained["previous_envelope_hash"] == envelope["envelope_hash"]
    assert verify_envelope(chained)["verified"]
    with pytest.raises(ValueError):
        create_envelope({}, "opaque.json/1", pair, previous_envelope_hash="nope")


def test_receipts_and_chains():
    issuer = KeyPair.generate()
    first = create_receipt_record(record=RECORD, issuer=issuer, timestamp="2026-01-01T00:00:01Z")
    assert first["signature_algorithm"] == "ed25519"
    assert first["issuer"] == issuer.did
    assert first["record_hash"] == hash_record(RECORD)
    assert first["previous_hash"] is None
    ok = verify_receipt_record(first, record=RECORD)
    assert ok["verified"], ok["errors"]
    assert "signature_valid" in ok["checks"] and "record_hash_match" in ok["checks"]

    second = create_receipt_record(
        record={**RECORD, "status": "active"}, previous_hash=first["receipt_hash"], issuer=issuer, timestamp="2026-01-01T00:00:02Z"
    )
    chain = verify_receipt_chain([first, second], expected_issuer=issuer.did, require_genesis=True)
    assert chain["verified"], chain["errors"]
    assert chain["head"] == second["receipt_hash"]
    assert not verify_receipt_chain([second, first])["verified"]

    tampered = {**first, "record_hash": hash_record({**RECORD, "entity_id": "NODE-2"})}
    assert not verify_receipt_record(tampered)["verified"]
    impostor = {**first, "issuer": KeyPair.generate().did, "key_id": None}
    assert not verify_receipt_record(impostor)["verified"]

    unsigned = create_receipt_record(record=RECORD, issuer="iricity-state-stack", timestamp="2026-01-01T00:00:01Z")
    assert unsigned["signature_algorithm"] == "none"
    assert unsigned["verification_status"] == "unsigned"
    result = verify_receipt_record(unsigned, record=RECORD)
    assert result["verified"] and result["identity_bound"] is False
