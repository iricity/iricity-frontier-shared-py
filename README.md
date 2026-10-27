# frontier-shared (Python)

Python implementation of the Frontier State Protocol primitives, byte-for-byte compatible with the JavaScript reference `@iricity/frontier-shared`. Its purpose is to prove that the specification is portable: it passes the published conformance vectors with no suite skipped.

| Module | Provides | Standard |
| --- | --- | --- |
| `frontier_shared.canonical` | `canonical_json`, `format_number` | RFC 8785, ECMAScript number formatting |
| `frontier_shared.hashing` | `hash_payload`, `hash_record`, `hash_text`, `hash_bytes`, `sha256_hex` | SHA-256 over canonical JSON, `sha256:` prefixed hex |
| `frontier_shared.base58` | `base58_encode`, `base58_decode` | base58btc, multibase `z` |
| `frontier_shared.keys` | `KeyPair`, `did_from_public_key_bytes`, `sign_bytes`, `verify_bytes` | W3C did:key, RFC 8032 Ed25519 |
| `frontier_shared.envelope` | `create_envelope`, `verify_envelope` | `state-envelope/1` |
| `frontier_shared.receipt` | `create_receipt_record`, `verify_receipt_record`, `verify_receipt_chain` | `state-receipt/1` |
| `frontier_shared.conformance` | `run_conformance`, console script `frontier-shared-conformance` | vectors version 2, eight suites |

Only runtime dependency: `cryptography`.

## Install and verify

```
pip install iricity-frontier-shared
frontier-shared-conformance
```

```
conformance vectors 2: 60 passed, 0 failed, 0 skipped
RESULT: conformant
```

Pass a path to run against a different vectors file, for example the one in the JavaScript repository:

```
frontier-shared-conformance ../iricity-frontier-shared/conformance/vectors.json
```

## Use

```python
from frontier_shared import KeyPair, create_envelope, verify_envelope, create_receipt_record, verify_receipt_chain

node = KeyPair.generate()
envelope = create_envelope(omm, "ccsds.omm.json/1", node)
verify_envelope(envelope)            # {'verified': True, 'signer': 'did:key:z6Mk…', ...}

first = create_receipt_record(record=record, issuer=node)
second = create_receipt_record(record=next_record, previous_hash=first["receipt_hash"], issuer=node)
verify_receipt_chain([first, second], require_genesis=True)
```

Objects produced here verify in the JavaScript implementation and vice versa; the vectors pin the signing inputs, hashes and encodings on both sides, and 26 rejection vectors pin what both verifiers must refuse. Verifiers never raise on malformed input; every problem is an entry in `errors`.

## Where the traps were

Four places decide whether a second implementation matches the bytes, and all four are covered by vectors:

1. **Numbers.** RFC 8785 uses the ECMAScript Number-to-string algorithm (`1e+21`, `1e-7`, `123456789012345680000`, `-0` as `0`), and every JSON number is a double, so an integer literal at or above 2**53 rounds the way JavaScript rounds it. `format_number` implements both from the shortest round-trip digits.
2. **Strings.** Only `"`, `\`, control characters below U+0020 and lone surrogates are escaped; `/` and non-ASCII are not.
3. **Key order.** Object members sort by UTF-16 code units, not code points. The vector with a supplementary-plane key exists for this.
4. **Signing inputs.** Domain tag plus canonical JSON of the header (envelopes) or the core fields (receipts), nothing else.

## Not yet in this implementation

The JavaScript reference 0.4.0 adds regulator-issued authorization credentials (W3C Verifiable Credentials with an `eddsa-jcs-2022` Data Integrity proof). This package covers the protocol core (canonical JSON, hashes, did:key, envelopes, receipts) and passes conformance vectors version 2 in full; credentials arrive here together with vector version 3, so that both implementations are measured against the same cases.

## Development

```
pip install -e .[test]
pytest
python -m frontier_shared.conformance
```

Vectors are vendored under `src/frontier_shared/vectors/v2/` with the lock file from the JavaScript repository; a test fails if the copy drifts from the lock. A new vectors version is a new directory.

## License

Apache-2.0.
