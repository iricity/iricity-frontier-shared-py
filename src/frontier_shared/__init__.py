"""Frontier State Protocol primitives, Python implementation.

Byte-for-byte compatible with the JavaScript reference (`@iricity/frontier-shared`),
proven by the shared conformance vectors in ``frontier_shared/vectors``.
"""

from .base58 import base58_decode, base58_encode, multibase_decode_base58btc, multibase_encode_base58btc
from .canonical import canonical_json
from .envelope import (
    ENVELOPE_DOMAIN_TAG,
    ENVELOPE_VERSION,
    create_envelope,
    envelope_hash,
    envelope_header,
    envelope_signing_input,
    verify_envelope,
)
from .hashing import HASH_PREFIX, hash_bytes, hash_payload, hash_record, is_hash_ref, sha256_hex, sha256_hex_bytes
from .keys import (
    ED25519_MULTICODEC_PREFIX,
    KeyPair,
    decode_signature,
    did_from_public_key_bytes,
    encode_signature,
    fingerprint_did,
    is_did_key,
    public_key_bytes_from_did,
    public_key_multibase_from_did,
    resolve_signer,
    sign_bytes,
    verify_bytes,
)
from .receipt import (
    RECEIPT_DOMAIN_TAG,
    RECEIPT_SIGNATURE_ALGORITHMS,
    RECEIPT_VERSION,
    compute_receipt_hash,
    create_receipt_record,
    receipt_core,
    receipt_signing_input,
    verify_receipt_chain,
    verify_receipt_record,
)

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "canonical_json",
    "HASH_PREFIX",
    "sha256_hex",
    "sha256_hex_bytes",
    "hash_payload",
    "hash_bytes",
    "hash_record",
    "is_hash_ref",
    "base58_encode",
    "base58_decode",
    "multibase_encode_base58btc",
    "multibase_decode_base58btc",
    "ED25519_MULTICODEC_PREFIX",
    "KeyPair",
    "resolve_signer",
    "did_from_public_key_bytes",
    "public_key_bytes_from_did",
    "public_key_multibase_from_did",
    "is_did_key",
    "fingerprint_did",
    "sign_bytes",
    "verify_bytes",
    "encode_signature",
    "decode_signature",
    "ENVELOPE_VERSION",
    "ENVELOPE_DOMAIN_TAG",
    "create_envelope",
    "verify_envelope",
    "envelope_header",
    "envelope_hash",
    "envelope_signing_input",
    "RECEIPT_VERSION",
    "RECEIPT_DOMAIN_TAG",
    "RECEIPT_SIGNATURE_ALGORITHMS",
    "create_receipt_record",
    "verify_receipt_record",
    "verify_receipt_chain",
    "receipt_core",
    "receipt_signing_input",
    "compute_receipt_hash",
]
