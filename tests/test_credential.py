import json

from frontier_shared import (
    KeyPair,
    canonical_json,
    credential_hash_data,
    issue_authorization_credential,
    verify_authorization_credential,
    verify_credential,
)
from frontier_shared.conformance import bundled_vectors_path

REGULATOR = KeyPair.from_seed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
LICENCE = {
    "subject_id": "station_vu2abc",
    "capability": "transmit",
    "scope": "amateur_general_grade",
    "jurisdiction": "IN",
    "bands": [
        {"lower_hz": 144000000, "upper_hz": 146000000, "service": "amateur"},
        {"lower_hz": 434000000, "upper_hz": 438000000, "service": "amateur"},
    ],
    "max_eirp_dbw": 20,
    "location": {"latitude": 28.6139, "longitude": 77.209, "radius_km": 1},
    "license_reference": "ASOC/EXAMPLE/0001",
    "valid_from": "2026-01-01T00:00:00.000Z",
    "valid_until": "2031-01-01T00:00:00.000Z",
}


def test_issued_credential_matches_the_javascript_reference_byte_for_byte():
    vectors = json.load(open(bundled_vectors_path(), encoding="utf-8"))
    case = next(v for v in vectors["credential"] if v["id"] == "credential-transmit-licence")
    credential = issue_authorization_credential(case["authorization"], {"private_key_seed_hex": case["signer_seed_hex"]}, created=case["created"])
    assert credential["id"] == case["expected"]["id"]
    assert credential["proof"]["proofValue"] == case["expected"]["proof_value"]
    assert credential_hash_data(credential, credential["proof"]).hex() == case["expected"]["hash_data_hex"]
    assert canonical_json(credential["credentialSubject"]) == canonical_json(case["expected"]["credential_subject"])


def test_credential_structure_and_verification():
    credential = issue_authorization_credential(LICENCE, REGULATOR, created="2026-01-01T00:00:00.000Z")
    assert credential["@context"] == ["https://www.w3.org/ns/credentials/v2", {"@vocab": "urn:frontier-state-protocol:vocab:authorization#"}]
    assert credential["type"] == ["VerifiableCredential", "SpectrumAuthorizationCredential"]
    assert credential["issuer"] == REGULATOR.did
    assert credential["proof"]["cryptosuite"] == "eddsa-jcs-2022"
    assert credential["proof"]["verificationMethod"] == f"{REGULATOR.did}#{REGULATOR.did[8:]}"
    ok = verify_credential(credential, at="2027-06-01T00:00:00Z", expected_issuer=REGULATOR.did)
    assert ok["verified"], ok["errors"]
    assert ok["checks"] == [
        "context_v2", "type_verifiable_credential", "issuer_did_key", "issuer_match", "subject_present",
        "verification_method_bound", "proof_value_decoded", "signature_valid", "within_validity",
    ]
    assert issue_authorization_credential(LICENCE, REGULATOR, created="2026-01-01T00:00:00.000Z") == credential


def test_tampering_substitution_and_validity_are_refused_without_raising():
    credential = issue_authorization_credential(LICENCE, REGULATOR, created="2026-01-01T00:00:00.000Z")
    other = KeyPair.generate().did
    cases = [
        ({**credential, "credentialSubject": {**credential["credentialSubject"], "max_eirp_dbw": 30}}, "does not verify"),
        ({**credential, "issuer": other}, "verificationMethod"),
        ({**credential, "proof": {**credential["proof"], "cryptosuite": "eddsa-rdfc-2022"}}, "cryptosuite"),
        ({**credential, "proof": {**credential["proof"], "proofValue": "z" + credential["proof"]["proofValue"][2:]}}, "signature"),
        ({**credential, "@context": ["https://www.w3.org/2018/credentials/v1"]}, "@context"),
        ({k: v for k, v in credential.items() if k != "proof"}, "proof is required"),
        ("text", "must be an object"),
        (None, "must be an object"),
    ]
    for obj, needle in cases:
        result = verify_credential(obj, at="2027-06-01T00:00:00Z")
        assert result["verified"] is False
        assert any(needle in e for e in result["errors"]), (needle, result["errors"])
    assert "not valid before" in verify_credential(credential, at="2025-12-31T00:00:00Z")["errors"][0]
    assert "expired" in verify_credential(credential, at="2031-01-02T00:00:00Z")["errors"][0]
    assert "not the expected" in verify_credential(credential, at="2027-01-01T00:00:00Z", expected_issuer=other)["errors"][0]


def test_authorization_binding_follows_the_vectors():
    vectors = json.load(open(bundled_vectors_path(), encoding="utf-8"))
    bound = next(v for v in vectors["credential"] if v["id"] == "authorization-regulator-issued-binds")
    record = bound["authorization_record"]
    ok = verify_authorization_credential(record, at=bound["at"])
    assert ok["verified"], ok["errors"]
    assert "controller_is_issuer" in ok["checks"]
    assert ok["revoked"] is False
    assert verify_authorization_credential({**record, "bands": record["bands"][:1]}, at=bound["at"])["verified"] is False
    assert verify_authorization_credential({**record, "revoked": True}, at=bound["at"])["revoked"] is True
    assert verify_authorization_credential({**record, "proof": None})["verified"] is False
    assert verify_authorization_credential(None)["verified"] is False
