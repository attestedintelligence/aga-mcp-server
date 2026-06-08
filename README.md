# AGA - Attested Governance Artifacts

Cryptographic runtime governance for AI agents and autonomous systems.

[![npm](https://img.shields.io/npm/v/@attested-intelligence/aga-mcp-server)](https://www.npmjs.com/package/@attested-intelligence/aga-mcp-server)
[![PyPI](https://img.shields.io/pypi/v/aga-governance)](https://pypi.org/project/aga-governance/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![release](https://img.shields.io/badge/release-3.0.0-brightgreen)](https://www.npmjs.com/package/@attested-intelligence/aga-mcp-server)
[![npm provenance](https://img.shields.io/badge/npm-SLSA%20provenance-brightgreen)](https://www.npmjs.com/package/@attested-intelligence/aga-mcp-server)

> **Status: 3.0.0 (latest, published to npm with SLSA build provenance).** The server tools and the `aga-proxy` emit the **canonical SEP evidence bundle**, verifiable offline by the published `@attested-intelligence/aga-verify` and the reference verifier `aga-receipt-spec/verify/verify-sep.mjs`. Pre-3.0 releases (a legacy continuity-chain bundle that does *not* verify under the SEP verifier) are deprecated; use `^3.0.0`. Claim scope and residual attack surface are documented honestly in `THREAT_BOUNDARY.md`.

```bash
# This package IS the AGA MCP server (TypeScript, runs over stdio). Use it from any MCP client:
npx -y @attested-intelligence/aga-mcp-server
```

A Python companion SDK (`aga-governance`) is documented in the Python SDK section below.

## Verify this yourself (no trust required)

You do not have to take any of this on faith. The repo ships the reference verifier, the canonical vectors, and sample bundles, so you can check one offline right now with no network and no dependency on us:

```bash
git clone https://github.com/attestedintelligence/aga-mcp-server
cd aga-mcp-server
# A canonical SEP bundle verifies; a one-byte-tampered copy is rejected.
node aga-receipt-spec/verify/verify-sep.mjs fixtures/valid_minimal.json   # OVERALL: VERIFIED (integrity only; no key pinned)
node aga-receipt-spec/verify/verify-sep.mjs fixtures/tampered.json        # OVERALL: FAILED
```

The published `@attested-intelligence/aga-verify@2.0.0` CLI renders the identical verdict, and `npm run conformance:cross-stack` proves six independent verifiers (the reference, the in-server engine, `aga-verify`, Go, and two Python implementations) agree on all 55 canonical cases. For a full trust-free reproduction (build the package yourself, reproduce the published tarball byte-for-byte, re-run every gate), see **[REPRODUCIBILITY.md](REPRODUCIBILITY.md)** and the step-by-step **[SKEPTICAL_AUDITOR.md](SKEPTICAL_AUDITOR.md)**. The 3.0.0 npm release carries SLSA build provenance, checkable with `npm audit signatures`.

## What This Does

Every tool call an AI agent makes passes through the AGA gateway. Each call is evaluated against policy, and the decision (PERMITTED or DENIED) is recorded as a signed, hash-linked governance receipt. Receipts are collected into evidence bundles that any third party can verify offline using standard cryptography.

**Record. Prove. Verify.**

**Scope:** a verified bundle proves the *integrity of the receipts present* — each is authentic, correctly ordered, Merkle-included, and (when a key is pinned) provenance-bound. It does **not** prove non-omission (that every action the agent took was logged); completeness is bounded by the tamper-evidence of the interception point, which is outside the bundle. See **[KNOWN_LIMITATIONS.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/KNOWN_LIMITATIONS.md)** for the full honest boundary, and `THREAT_BOUNDARY.md` for the per-field detail.

## Use with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "aga": {
      "command": "npx",
      "args": ["-y", "@attested-intelligence/aga-mcp-server"]
    }
  }
}
```

Claude can then seal artifacts, measure integrity, generate evidence bundles, and verify compliance through natural language.

### Persist the signing key (do this first)

By default the gateway signs with an **ephemeral** key that rotates on every restart. That is fine for a first look, but evidence-bundle provenance cannot be pinned across restarts (and the server warns about it on stderr). Set one stable 64-hex Ed25519 seed so provenance stays pinnable:

```bash
# generate a seed once (32 random bytes, hex)
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Provide it via `AGA_GATEWAY_KEY`, or `AGA_GATEWAY_KEY_FILE` (a path to the seed). In Claude Desktop, add an `env` block:

```json
{
  "mcpServers": {
    "aga": {
      "command": "npx",
      "args": ["-y", "@attested-intelligence/aga-mcp-server"],
      "env": { "AGA_GATEWAY_KEY": "<your-64-hex-seed>" }
    }
  }
}
```

Keep the seed secret and out of version control; see `DEPLOYMENT.md` for key handling.

## MCP Tools (15)

| Category | Tools |
|----------|-------|
| **Identity** | `get_server_info`, `get_portal_state` |
| **Lifecycle** | `init_chain`, `attest_subject`, `revoke_artifact` |
| **Enforcement** | `measure_integrity`, `measure_behavior`, `verify_chain` |
| **Evidence** | `generate_evidence_bundle`, `verify_bundle_offline` |
| **Privacy** | `request_claim`, `list_claims` |
| **Delegation** | `delegate_to_subagent` |
| **Audit** | `get_receipts`, `get_chain_events` |

> **`measure_behavior` is detective-only by default** — it observes tool-usage patterns and records a *signed, provable* drift finding, but does not block. Enforcement (drift → quarantine) is opt-in via `enforce=true` and off by default. Hard governance decisions (PERMITTED/DENIED) are made by the portal/PEP, not the behavioral monitor.

## Quick Start — verify a bundle offline

A bundle this package emits (via the `generate_evidence_bundle` tool, or `aga-proxy export`) is a **canonical SEP bundle**. Verify it offline, with no network and no dependency on us:

```bash
# Reference verifier (zero deps, Node 18+). Pin the gateway key (from get_server_info) to prove provenance.
node aga-receipt-spec/verify/verify-sep.mjs evidence-bundle.json --pubkey <gateway-public-key>
```

The published `@attested-intelligence/aga-verify` CLI mirrors this reference (**2.0.0**, published on npm; the older forgeable 1.0.0 is deprecated). Without `--pubkey` you get an **integrity-only** result (`issuerVerified=false`); pin the key to also prove *who* issued it — see `THREAT_BOUNDARY.md` §3.7. A hosted browser verifier is linked under [Links](#links).

The reference §6 algorithm is implemented in **three languages** — JavaScript (`aga-receipt-spec/verify/verify-sep.mjs`), Go (`verify.go`, stdlib `crypto/ed25519`), and Python (`verify.py`, pure-stdlib RFC-8032 Ed25519) — and a cross-stack harness (`npm run conformance:cross-stack`) proves all three, plus the in-server engine and `aga-verify`, render **identical verdicts** on the canonical vectors (valid, adversarial, and every small-order forgery).

## How It Works

```
AI Agent                  AGA Gateway                    Verifier
   |                          |                              |
   |-- tools/call ----------->|                              |
   |                    [Evaluate Policy]                    |
   |                    [Sign Receipt]                       |
   |                    [Chain to Previous]                  |
   |<-- PERMITTED/DENIED -----|                              |
   |                          |                              |
   |                    [Export Bundle]                       |
   |                          |--------- evidence.json ----->|
   |                          |                  [Verify Signatures]
   |                          |                  [Verify Chain + Order]
   |                          |                  [Verify Merkle Tree]
   |                          |                  [Verify Signed Checkpoint]
   |                          |                  [PASS / FAIL]
```

## MCP Governance Proxy

Run AGA as a transparent proxy between any MCP client and any MCP server. Every tool call gets evaluated against policy and produces a signed receipt.

```bash
# Start the proxy (the `aga-proxy` bin) in front of an upstream MCP server.
# stdio upstream = the hardened default (the upstream is a child process, not network-reachable).
npx -p @attested-intelligence/aga-mcp-server aga-proxy start \
  --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp/test" --profile standard

# Export the canonical SEP evidence bundle, then verify it offline
npx -p @attested-intelligence/aga-mcp-server aga-proxy export --output evidence.json
npx -p @attested-intelligence/aga-mcp-server aga-proxy verify evidence.json
```

The proxy intercepts `tools/call` requests, evaluates them against a sealed policy, and generates a signed SEP receipt for **every** decision. Permitted calls are forwarded to the downstream server; denied calls return an MCP error and never reach it. Every decision is hash-linked and checkpoint-bound into a tamper-evident bundle. (Methods other than `tools/call` aren't policy-evaluated, but non-benign ones are recorded as signed *passthrough* receipts for auditability, and an optional denylist can reject them; see `THREAT_BOUNDARY.md` §3.2.)

Three built-in policy profiles:
- **permissive** - log everything, block nothing (default)
- **standard** - rate limits + blocks destructive operations
- **restrictive** - explicit tool allowlist, all unknown tools denied

## Verification _(canonical SEP — 3.0; normative §6 algorithm in `aga-receipt-spec/verify/verify-sep.mjs`)_

1. **Structural floor** - Bundle declares Ed25519-SHA256-JCS, public key well-formed (all small-order encodings + non-canonical `y ≥ p` rejected), `receipts.length > 0`, proof count = receipt count
2. **Receipt Signatures** - Ed25519 over JCS-profile canonical JSON, sorted-key (signature field excluded)
3. **Chain + ordering** - Each receipt's `previous_receipt_hash` = leaf of the preceding receipt; non-decreasing timestamps
4. **Merkle Proofs** - Recompute every leaf from receipt content, walk siblings/directions to one root, leaf indices form the complete `0..N-1` bijection
5. **Signed checkpoint** - Verify the gateway-signed checkpoint binding `merkle_root`, `leaf_count`, and chain head (this makes the no-prefix construction truncation-safe)
6. **Provenance** _(when a key is pinned)_ - `public_key == expected key`; otherwise integrity-only is reported

## Cryptographic Primitives

| Primitive | Purpose |
|-----------|---------|
| Ed25519 | Receipt signatures |
| SHA-256 | Hash chaining, Merkle trees, leaf computation |
| JCS-profile (sorted-key canonical JSON) | Deterministic signing (canon is byte-compatible with the reference verifier) |
| Merkle Trees | Binding all receipts to a single verifiable root |

## Live Gateway

A demo gateway is deployed on Cloudflare Workers (a **separate deployment** that may track its own version; treat it as a convenience mirror, and always verify what it returns offline against a pinned key — not as the canonical artifact):

```bash
# Check status
curl https://aga-mcp-gateway.attestedintelligence.workers.dev/health

# Export evidence bundle
curl https://aga-mcp-gateway.attestedintelligence.workers.dev/bundle -o evidence-bundle.json
```

## Python SDK

```bash
pip install aga-governance
```

```python
from aga import AgentSession

with AgentSession(gateway_id="my-gateway") as session:
    session.record_tool_call(
        tool_name="search_web",
        decision="PERMITTED",
        reason="tool in allowlist",
        request_id="req-1",
    )
    bundle = session.export_bundle()
    result = session.verify()
    assert result["overall_valid"]
```

## Test Suite

Automated tests across TypeScript and Python, plus a conformance corpus:

- **TypeScript MCP server:** 297 tests (vitest), including provable-denial and behavioral-monitor regressions
- **SEP conformance corpus:** `npm run test:conformance` (valid → VERIFIED, negatives → FAILED)
- **Python companion SDK:** the separately-published `aga-governance` PyPI package (pytest)

```bash
npm test                              # TypeScript tests (vitest)
npm run test:conformance              # SEP conformance corpus
pip install aga-governance && python -m pytest --pyargs aga   # Python companion tests
```

## Benchmarks

Receipt-format determinism is reproducible here: `npm test` runs the cross-language vectors, and `npm run conformance:cross-stack` shows all six independent verifiers agree on the canonical 55-case corpus.

## Project Structure

```
src/
  sep/                 # Canonical SEP evidence engine — single source of truth (canon, merkle, receipt, checkpoint, bundle, verify)
  core/                # Governance primitives (portal, artifact, attestation, disclosure, delegation, behavioral) + internal continuity-chain profile
  crypto/              # Internal continuity-chain crypto: Ed25519 (node:crypto), SHA-256/blake2b, salt
  proxy/               # MCP governance proxy (transparent interception + policy enforcement; emits SEP bundles)
  middleware/          # Governance PEP wrapper (records a signed PERMITTED/DENIED receipt per governed call)
independent-verifier/  # @attested-intelligence/aga-verify — standalone SEP verifier, zero AGA imports
scenarios/             # Demo scenarios (SCADA, autonomous vehicle, AI agent) — emit SEP bundles
tests/                 # TypeScript test suite (297 tests)
```

## Links

- [Website](https://attestedintelligence.com)
- [Technology](https://attestedintelligence.com/technology)
- [Live Verifier](https://attestedintelligence.com/verify)
- [Trust and Scope](https://attestedintelligence.com/trust)
- [Diligence Materials](https://attestedintelligence.com/diligence)
- [MCP Server (npm)](https://www.npmjs.com/package/@attested-intelligence/aga-mcp-server)
- [Python SDK (PyPI)](https://pypi.org/project/aga-governance/)

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Contributing

See [CONTRIBUTING.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/CONTRIBUTING.md) for development setup and guidelines.

## License

[MIT](LICENSE)

---

Attested Intelligence Holdings LLC
