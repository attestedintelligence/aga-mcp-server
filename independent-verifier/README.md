# AGA Offline Verifier (`@attested-intelligence/aga-verify`)

Standalone, producer-independent verification of canonical **AGA SEP Evidence Bundles**:
it runs without contacting the producer. The verifier is company-authored, so audit it
yourself: one source file, **zero AGA imports and zero third-party dependencies**, only
Node's built-in `crypto` (Ed25519 + SHA-256). The trust chain ends at the Node runtime,
this package's one auditable source file, and the gateway public key you pin.

## Why this exists

AGA claims its Evidence Bundles are tamper-evident and offline-verifiable. This tool
makes that claim checkable by **anyone**: the complete verification is implemented from
scratch in one auditable file with zero AGA imports and zero npm dependencies, and it
runs against a bundle you provide, offline.

## Quickstart

```bash
# grab a real signed bundle from the public site, then verify it offline:
curl -sO https://attestedintelligence.com/sample-bundle.json
npx @attested-intelligence/aga-verify sample-bundle.json

# integrity + PROVENANCE (proves it came from a gateway key you trust out of band;
# the demo gateway key is published at attestedintelligence.com/verify):
npx @attested-intelligence/aga-verify sample-bundle.json --pubkey <64-hex-gateway-key>

# or verify the example shipped inside this package (labeled as the packaged sample):
npx @attested-intelligence/aga-verify --sample \
  --pubkey ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c
```

Exit codes: `0` on `VERIFIED`; `1` on `FAILED` (including an unreadable file, and
v2/post-quantum bundles, which this CLI does not implement and reports as FAILED);
`2` on usage error. `--version` prints the CLI version; `--help` prints the checks
and exit codes. Usable directly in CI.

## What it verifies

Implements the canonical construction in
[`aga-receipt-spec/CANONICAL_CONSTRUCTION_v2.md`](https://attestedintelligence.com/spec) §6:

1. **Structural floor**: algorithm, well-formed (non-small-order) key, receipt/proof counts.
2. **Receipt signatures**: Ed25519 over the canonical receipt bytes, for every receipt.
3. **Chain + ordering**: each receipt links to the previous leaf; monotonic ids/timestamps.
4. **Merkle + bijection**: every leaf is **recomputed from receipt content**, walked to one root, and the proof set is the complete contiguous `0..N-1`.
5. **Signed checkpoint (mandatory)**: a gateway-signed checkpoint binds the root, the receipt count, and the chain head, so adding/dropping/reordering receipts fails.
6. **Provenance (only with `--pubkey`)**: the bundle key equals the key you pinned.

All steps are fully offline. No network calls, ever.

## What a PASS proves, and what it does not

A PASS proves every **present** receipt is authentic, correctly chained, Merkle-included
under a signed checkpoint, and (with `--pubkey`) issued by the pinned gateway: nothing
present was added, reordered, or truncated.

A PASS does **not** prove **non-omission**: it cannot establish that the signer recorded
*every* action it took. Completeness is bounded by the tamper-evidence of the interception
point, which is outside the bundle. Without `--pubkey`, a PASS proves integrity and
self-consistency under the bundle's own key, **not** provenance.

## What you have to trust

`npm ls` shows **zero runtime dependencies**. The verifier is one source file
(`verify.ts`, bundled to `dist/aga-verify.mjs`) using only `node:crypto`. No AGA library
imports, no third-party packages, no network for verification. What remains is exactly
what you can check yourself: this file (read it), the Node runtime, and the key you pin.

## From source

```bash
npm install        # devDeps only (esbuild, vitest, tsx), zero runtime deps
npm test           # vitest: genuine VERIFIES + every tamper/truncation/wrong-key FAILS
npm run build      # bundles verify.ts -> dist/aga-verify.mjs (esbuild)
node dist/aga-verify.mjs example-bundle.json --pubkey <key>
```

---
Attested Intelligence Holdings LLC · MIT. Implements the canonical AGA SEP Evidence Bundle verification (`aga-receipt-spec` v2).
