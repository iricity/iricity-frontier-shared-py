"""Regulator-issued authorizations: a W3C Verifiable Credential (Data Model 2.0)
carried in an authorization record's ``proof``, secured with a Data Integrity proof
using the ``eddsa-jcs-2022`` cryptosuite.

That cryptosuite canonicalises with JCS (RFC 8785), the protocol's own canonical
form, so issuing and verifying need SHA-256 and Ed25519 only::

    hash_data   = sha256(canonical(proof_config)) || sha256(canonical(document without proof))
    proof_value = multibase base58btc of ed25519(hash_data)

The issuer is a did:key; the verification method is that DID with its own key
fragment. Verification never raises: it returns a result with errors and checks.
Byte-for-byte compatible with the JavaScript reference; see the ``credential``
suite of the conformance vectors.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping

from .base58 import multibase_decode_base58btc, multibase_encode_base58btc
from .canonical import canonical_json
from .envelope import TIMESTAMP_PATTERN, now_iso
from .hashing import hash_payload
from .keys import is_did_key, resolve_signer, sign_bytes, verify_bytes

__all__ = [
    "CREDENTIAL_CONTEXT_V2",
    "AUTHORIZATION_VOCAB",
    "AUTHORIZATION_CREDENTIAL_TYPE",
    "DATA_INTEGRITY_PROOF",
    "CRYPTOSUITE",
    "PROOF_PURPOSE",
    "CREDENTIAL_SUBJECT_FIELDS",
    "credential_hash_data",
    "credential_subject_from_authorization",
    "issue_authorization_credential",
    "verify_credential",
    "verify_authorization_credential",
]

CREDENTIAL_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
AUTHORIZATION_VOCAB = "urn:frontier-state-protocol:vocab:authorization#"
AUTHORIZATION_CREDENTIAL_TYPE = "SpectrumAuthorizationCredential"
DATA_INTEGRITY_PROOF = "DataIntegrityProof"
CRYPTOSUITE = "eddsa-jcs-2022"
PROOF_PURPOSE = "assertionMethod"
CREDENTIAL_SUBJECT_FIELDS = ["capability", "scope", "jurisdiction", "bands", "max_eirp_dbw", "location", "license_reference"]


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _is_empty(value: Any) -> bool:
    return value is None or (isinstance(value, (list, tuple)) and len(value) == 0)


def _timestamp_ok(value: Any) -> bool:
    return isinstance(value, str) and TIMESTAMP_PATTERN.match(value) is not None


def _parse_instant(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _verification_method_for(did: str) -> str:
    return f"{did}#{did[len('did:key:'):]}"


def credential_hash_data(document: Mapping[str, Any], proof_config: Mapping[str, Any]) -> bytes:
    """The Data Integrity hash input for eddsa-jcs-2022: proof-config hash followed by document hash."""
    unsecured = {key: value for key, value in document.items() if key != "proof"}
    config = {key: value for key, value in proof_config.items() if key != "proofValue"}
    if "@context" in unsecured:
        config["@context"] = unsecured["@context"]
    return _sha256(canonical_json(config).encode("utf-8")) + _sha256(canonical_json(unsecured).encode("utf-8"))


def credential_subject_from_authorization(authorization: Mapping[str, Any]) -> dict:
    """Build the credential subject from an authorization's attested fields."""
    subject: dict = {"id": authorization["subject_id"]}
    for field in CREDENTIAL_SUBJECT_FIELDS:
        if not _is_empty(authorization.get(field)):
            subject[field] = authorization[field]
    return subject


def issue_authorization_credential(
    authorization: Mapping[str, Any],
    issuer: Any,
    *,
    id: str | None = None,  # noqa: A002 - mirrors the credential field
    valid_from: str | None = None,
    valid_until: str | None = None,
    created: str | None = None,
) -> dict:
    """Issue a credential over an authorization's attested fields, signed by the issuer."""
    if not _is_mapping(authorization) or not authorization.get("subject_id"):
        raise TypeError("authorization with subject_id is required")
    signer = resolve_signer(issuer)
    from_ = valid_from or authorization.get("valid_from") or now_iso()
    until = valid_until if valid_until is not None else authorization.get("valid_until")
    created_at = created or now_iso()
    for label, value in (("valid_from", from_), ("created", created_at), ("valid_until", until)):
        if value is not None and not _timestamp_ok(value):
            raise TypeError(f"{label} must be an ISO-8601 UTC timestamp with a Z suffix")

    unsecured: dict = {
        "@context": [CREDENTIAL_CONTEXT_V2, {"@vocab": AUTHORIZATION_VOCAB}],
        "type": ["VerifiableCredential", AUTHORIZATION_CREDENTIAL_TYPE],
        "issuer": signer.did,
        "validFrom": from_,
    }
    if until:
        unsecured["validUntil"] = until
    unsecured["credentialSubject"] = credential_subject_from_authorization(authorization)
    unsecured["id"] = id if id is not None else f"urn:frontier-state-protocol:credential:{hash_payload(unsecured)[7:39]}"

    proof_config = {
        "type": DATA_INTEGRITY_PROOF,
        "cryptosuite": CRYPTOSUITE,
        "created": created_at,
        "verificationMethod": _verification_method_for(signer.did),
        "proofPurpose": PROOF_PURPOSE,
    }
    signature = sign_bytes(credential_hash_data(unsecured, proof_config), signer)
    credential = dict(unsecured)
    credential["proof"] = {**proof_config, "proofValue": multibase_encode_base58btc(signature)}
    return credential


def verify_credential(credential: Any, *, expected_issuer: str | None = None, at: Any = None) -> dict:
    """Verify a credential's structure, proof and validity window at ``at`` (default now)."""
    errors: list[str] = []
    checks: list[str] = []

    def result() -> dict:
        return {
            "verified": not errors,
            "errors": errors,
            "checks": checks,
            "issuer": credential.get("issuer") if _is_mapping(credential) else None,
            "subject": credential.get("credentialSubject") if _is_mapping(credential) else None,
        }

    if not _is_mapping(credential):
        errors.append("credential must be an object")
        return result()
    context = credential.get("@context")
    context_list = context if isinstance(context, list) else [context]
    if not context_list or context_list[0] != CREDENTIAL_CONTEXT_V2:
        errors.append(f"@context must start with {CREDENTIAL_CONTEXT_V2}")
    else:
        checks.append("context_v2")
    types = credential.get("type")
    type_list = types if isinstance(types, list) else [types]
    if "VerifiableCredential" not in type_list:
        errors.append("type must include VerifiableCredential")
    else:
        checks.append("type_verifiable_credential")
    issuer = credential.get("issuer")
    if not is_did_key(issuer):
        errors.append("issuer must be an ed25519 did:key")
    else:
        checks.append("issuer_did_key")
    if expected_issuer is not None and issuer != expected_issuer:
        errors.append(f"issuer {issuer} is not the expected {expected_issuer}")
    elif expected_issuer is not None:
        checks.append("issuer_match")
    subject = credential.get("credentialSubject")
    if not _is_mapping(subject) or not isinstance(subject.get("id"), str):
        errors.append("credentialSubject with an id is required")
    else:
        checks.append("subject_present")
    if not _timestamp_ok(credential.get("validFrom")):
        errors.append("validFrom must be an ISO-8601 UTC timestamp")
    if "validUntil" in credential and not _timestamp_ok(credential.get("validUntil")):
        errors.append("validUntil must be an ISO-8601 UTC timestamp")

    proof = credential.get("proof")
    if not _is_mapping(proof):
        errors.append("proof is required")
        return result()
    if proof.get("type") != DATA_INTEGRITY_PROOF:
        errors.append(f"proof.type must be {DATA_INTEGRITY_PROOF}")
    if proof.get("cryptosuite") != CRYPTOSUITE:
        errors.append(f"proof.cryptosuite must be {CRYPTOSUITE}")
    if proof.get("proofPurpose") != PROOF_PURPOSE:
        errors.append(f"proof.proofPurpose must be {PROOF_PURPOSE}")
    if not _timestamp_ok(proof.get("created")):
        errors.append("proof.created must be an ISO-8601 UTC timestamp")
    if is_did_key(issuer):
        if proof.get("verificationMethod") != _verification_method_for(issuer):
            errors.append("proof.verificationMethod must be the issuer did:key with its own key fragment")
        else:
            checks.append("verification_method_bound")
    if errors:
        return result()

    proof_value = proof.get("proofValue")
    try:
        if not isinstance(proof_value, str) or not proof_value.startswith("z"):
            raise ValueError("not multibase base58btc")
        signature = multibase_decode_base58btc(proof_value)
        if len(signature) != 64:
            raise ValueError("not 64 bytes")
    except Exception as error:  # noqa: BLE001 - reported, never raised
        errors.append(f"proof.proofValue is not an ed25519 signature: {error}")
        return result()
    checks.append("proof_value_decoded")

    try:
        hash_data = credential_hash_data(credential, proof)
    except Exception as error:  # noqa: BLE001
        errors.append(f"credential cannot be canonicalised: {error}")
        return result()
    if not verify_bytes(hash_data, signature, issuer):
        errors.append("proof signature does not verify against the issuer")
    else:
        checks.append("signature_valid")

    instant = _parse_instant(at) if at is not None else datetime.now(timezone.utc)
    if instant is None:
        errors.append("at must be a valid instant")
    else:
        valid_from = _parse_instant(credential.get("validFrom"))
        valid_until = _parse_instant(credential.get("validUntil")) if credential.get("validUntil") else None
        if valid_from is not None and valid_from > instant:
            errors.append(f"credential is not valid before {credential.get('validFrom')}")
        elif valid_until is not None and valid_until < instant:
            errors.append(f"credential expired at {credential.get('validUntil')}")
        else:
            checks.append("within_validity")
    return result()


def _same_value(a: Any, b: Any) -> bool:
    left = None if _is_empty(a) else a
    right = None if _is_empty(b) else b
    if left is None and right is None:
        return True
    if left is None or right is None:
        return False
    try:
        return canonical_json(left) == canonical_json(right)
    except Exception:  # noqa: BLE001
        return False


def verify_authorization_credential(authorization: Any, *, at: Any = None) -> dict:
    """Verify that an authorization record's ``proof`` is a credential that verifies at ``at``,
    was issued by the record's controller, and attests exactly the record's fields.
    Revocation is reported, not treated as a verification failure."""
    errors: list[str] = []
    checks: list[str] = []
    if not _is_mapping(authorization) or authorization.get("record_type") != "authorization":
        return {"verified": False, "errors": ["an authorization record is required"], "checks": checks, "issuer": None}
    proof = authorization.get("proof")
    if not _is_mapping(proof):
        return {"verified": False, "errors": ["authorization.proof must carry a verifiable credential"], "checks": checks, "issuer": None}

    controller = authorization.get("controller_id")
    credential = verify_credential(proof, expected_issuer=controller if is_did_key(controller) else None, at=at)
    errors.extend(credential["errors"])
    checks.extend(credential["checks"])
    if not is_did_key(controller):
        errors.append("controller_id must be the issuing authority did:key")
    elif credential["issuer"] == controller:
        checks.append("controller_is_issuer")

    subject = proof.get("credentialSubject") if _is_mapping(proof.get("credentialSubject")) else {}
    if subject.get("id") != authorization.get("subject_id"):
        errors.append(f"credential subject {subject.get('id')} is not the authorization subject {authorization.get('subject_id')}")
    else:
        checks.append("subject_match")
    mismatches = 0
    for field in CREDENTIAL_SUBJECT_FIELDS:
        if not _same_value(subject.get(field), authorization.get(field)):
            errors.append(f"credential {field} does not match the authorization")
            mismatches += 1
    if mismatches == 0:
        checks.append("fields_match")
    if not _same_value(proof.get("validFrom"), authorization.get("valid_from")):
        errors.append("credential validFrom does not match valid_from")
    if not _same_value(proof.get("validUntil"), authorization.get("valid_until")):
        errors.append("credential validUntil does not match valid_until")

    return {"verified": not errors, "errors": errors, "checks": checks, "issuer": credential["issuer"], "revoked": authorization.get("revoked") is True}
