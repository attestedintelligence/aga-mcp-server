# AGA Independent Verifier (`@attested-intelligence/aga-verify`)

Standalone verification of canonical **AGA SEP Evidence Bundles**. **Zero AGA imports
and zero third-party dependencies** — it uses only Node's built-in `crypto` (Ed25519 +
SHA-256). The trust chain dead-ends at the Node runtime and the gateway public key you
pin; nothing else.

## Why this exists

AGA claims its Evidence Bundles are tamper-evident and offline-verifiable. This tool
proves that claim is checkable by **anyone**, with no trust in AGA's own code or in any
npm dependency: it re-implements the complete verification from scratch and runs against
a bundle you provide.

## Quickstart

```bash
# integrity only (proves the bundle is internally authentic + complete-as-presented):
npx @attested-intelligence/aga-verify <bundle.json>

# integrity + PROVENANCE (proves it came from a specific gateway you trust out of band):
npx @attested-intelligence/aga-verify <bundle.json> --pubkey <64-hex-gateway-key>

# smoke-test against the bundled canonical example (a real signed bundle):
npx @attested-intelligence/aga-verify example-bundle.json \
  --pubkey ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c
```

Exit code is `0` on `VERIFIED`, `1` on `FAILED` — usable directly in CI.

## What it verifies

Implements the canonical construction in
[`aga-receipt-spec/CANONICAL_CONSTRUCTION_v2.md`](https://attestedintelligence.com/technology) §6:

1. **Structural floor** — algorithm, well-formed (non-small-order) key, receipt/proof counts.
2. **Receipt signatures** — Ed25519 over the canonical receipt bytes, for every receipt.
3. **Chain + ordering** — each receipt links to the previous leaf; monotonic ids/timestamps.
4. **Merkle + bijection** — every leaf is **recomputed from receipt content**, walked to one root, and the proof set is the complete contiguous `0..N-1`.
5. **Signed checkpoint (mandatory)** — a gateway-signed checkpoint binds the root, the receipt count, and the chain head, so adding/dropping/reordering receipts fails.
6. **Provenance (only with `--pubkey`)** — the bundle key equals the key you pinned.

All steps are fully offline. No network calls, ever.

## What a PASS proves — and what it does not

A PASS proves every **present** receipt is authentic, correctly chained, Merkle-included
under a signed checkpoint, and (with `--pubkey`) issued by the pinned gateway — nothing
present was added, reordered, or truncated.

A PASS does **not** prove **non-omission**: it cannot establish that the signer recorded
*every* action it took. Completeness is bounded by the tamper-evidence of the interception
point, which is outside the bundle. Without `--pubkey`, a PASS proves integrity and
self-consistency under the bundle's own key, **not** provenance.

## Independence guarantee

`npm ls` shows **zero runtime dependencies**. The verifier is one source file
(`verify.ts`, bundled to `dist/aga-verify.mjs`) using only `node:crypto`. No AGA code, no
third-party packages, no network for verification.

## From source

```bash
npm install        # devDeps only (esbuild, vitest, tsx) — zero runtime deps
npm test           # vitest: genuine VERIFIES + every tamper/truncation/wrong-key FAILS
npm run build      # bundles verify.ts -> dist/aga-verify.mjs (esbuild)
node dist/aga-verify.mjs example-bundle.json --pubkey <key>
```

---
Attested Intelligence Holdings LLC · MIT. Implements the canonical AGA SEP Evidence Bundle verification (`aga-receipt-spec` v2).
