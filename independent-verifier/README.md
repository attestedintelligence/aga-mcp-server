# AGA Independent Verifier

Standalone verification of AGA Evidence Bundles using only standard
cryptographic libraries. **This verifier imports zero modules from the
AGA codebase.**

## Why This Exists

AGA claims that Evidence Bundles provide tamper-evident, offline-verifiable
proof of governance enforcement. This verifier proves that claim by
implementing the complete 4-step verification using only Ed25519 and SHA-256
from @noble - no AGA code, no trust assumptions, no hidden dependencies.

## Usage

```bash
npx tsx verify.ts <bundle.json>
```

## What It Verifies

1. **Artifact Signature** - Ed25519 over RFC 8785 canonical JSON
2. **Receipt Signatures** - Ed25519 for each enforcement receipt
3. **Merkle Inclusion Proofs** - Structural metadata leaf hashes vs checkpoint root
4. **Checkpoint Anchor** - (Optional, requires network access)

Steps 1-3 work fully offline. Step 4 is optional.

## Reference

Implements the AGA 4-step offline verification process.
