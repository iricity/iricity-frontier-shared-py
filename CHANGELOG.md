# Changelog

## 0.5.0 - 2026-10-27

- Regulator-issued authorization credentials: `issue_authorization_credential`, `verify_credential`, `verify_authorization_credential`, `credential_hash_data` (W3C Verifiable Credentials Data Model 2.0, Data Integrity `eddsa-jcs-2022`), byte-for-byte compatible with the JavaScript reference.
- Conformance vectors version 3 (73 cases, nine suites): the new `credential` suite and twelve credential and authorization rejections, all passing. Version jumps to 0.5.0 to match the JavaScript reference that publishes the same vectors.

## 0.3.0 - 2026-10-17

- Integers at or above 2**53 are formatted as doubles, exactly as the JavaScript reference and RFC 8785 treat JSON numbers.
- hash_payload always hashes canonical JSON; hash_text covers raw text.
- Verifiers never raise on malformed input and apply the same checks as the reference: complete header and core, version tags, derived ids, required hashes, UTC timestamps, exact signature encoding, no unsigned receipt with a did:key issuer.
- Nesting deeper than 256 levels and bytes values are rejected by canonical_json.
- KeyPair gains seed_hex, public_key_hex, private_key_pem and public_key_pem; a 64-hex seed string is accepted as a signer.
- Conformance vectors version 2 vendored with their lock; the runner reports a missing suite as a failure and conforms only with zero skipped suites.
- Build backend requires setuptools 77 (PEP 639 license fields).

## 0.2.0 - 2026-10-17

- First release. Canonical JSON (RFC 8785 with ECMAScript number formatting), SHA-256 hash references, base58btc, ed25519 identity as did:key, `state-envelope/1`, `state-receipt/1`.
- Passes conformance vectors version 1 with no suite skipped; version aligned with `@iricity/frontier-shared` 0.2.0.
