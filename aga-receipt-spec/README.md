# AGA Receipt Specification

Normative specification for the Attested Governance Architecture (AGA)
receipt format, continuity chain linking, and offline verification algorithm.

Copyright (c) 2026 Attested Intelligence Holdings LLC

## What This Defines

- **Receipt format**: The canonical JSON structure for interaction receipts,
  tool-call governance receipts, and attestation events.
- **Chain linking**: How receipts form a tamper-evident continuity chain
  using SHA-256 leaf hashes with length-prefixed field encoding.
- **Merkle tree**: Binary SHA-256 Merkle tree construction for evidence
  bundles, including inclusion proof generation and verification.
- **Verification algorithm**: The four-step offline verification process
  for evidence bundles (artifact signature, receipt signatures, Merkle
  proofs, optional checkpoint anchoring).

## Directory Structure

```
spec.md              Full normative specification
vectors/             Cross-language test vectors
  aga_test_vectors.json
verify/              Standalone verifiers (no external dependencies)
  verify.py          Python verifier (chain + Merkle, stdlib only)
  verify.go          Go verifier (chain + Merkle, stdlib only)
examples/            Structural example JSON files
  receipt.json       Single receipt example
  chain.json         Four-receipt chain example
  bundle.json        Evidence bundle example
LICENSE              Apache-2.0
```

## Using the Verifiers

### Python

```bash
python verify/verify.py examples/bundle.json
```

Verifies chain hash linking and Merkle inclusion proofs. Signature
verification requires an Ed25519 library (not included in stdlib).

### Go

```bash
go run verify/verify.go examples/bundle.json
```

Verifies chain hash linking and Merkle inclusion proofs using only the
Go standard library.

## Test Vectors

The `vectors/aga_test_vectors.json` file contains comprehensive test
vectors covering:

- Leaf hash computation (length-prefixed SHA-256)
- Collision prevention (field boundary ambiguity)
- Seal computation
- Merkle tree roots and inclusion proofs
- RFC 8785 JSON canonicalization
- Timestamp normalization
- Ed25519 signing
- Receipt canonicalization and chain hashing

Both Go and Python implementations must produce identical outputs for
all test vectors. See the assertions array in the test vectors file
for the complete list of invariants.

## Related Repositories

- **aga-k8s**: Reference Go implementation (private)
- **attestedintelligence-web**: TypeScript SDK and web verifier (private)

## License

Apache-2.0. See [LICENSE](LICENSE).
