# AGA - Attested Governance Artifacts

Cryptographic runtime governance for AI agents and autonomous systems.

[![npm](https://img.shields.io/npm/v/@attested-intelligence/aga-mcp-server)](https://www.npmjs.com/package/@attested-intelligence/aga-mcp-server)
[![PyPI](https://img.shields.io/pypi/v/aga-governance)](https://pypi.org/project/aga-governance/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm provenance](https://img.shields.io/badge/npm-SLSA%20provenance-brightgreen)](https://www.npmjs.com/package/@attested-intelligence/aga-mcp-server)

> **Status: published to npm; this release carries SLSA build provenance (check it: `npm audit signatures`).** The server tools and the `aga-proxy` emit the **canonical SEP evidence bundle**, verifiable offline by the published `@attested-intelligence/aga-verify` and the reference verifier `aga-receipt-spec/verify/verify-sep.mjs`. **Since 3.2.0 the verifier is algorithm-agile and ships a post-quantum profile:** v1 `Ed25519-SHA256-JCS` (the default the gateway emits) and v2 `ML-DSA-65+Ed25519-SHA256-JCS` (a NIST FIPS-204 ML-DSA-65 + RFC-8032 Ed25519 **composite**, both must verify), selected per-bundle by the `algorithm` field with a `VERIFIED / FAILED / UNSUPPORTED_PROFILE` trichotomy. Pre-3.0 releases (a legacy continuity-chain bundle that does *not* verify under the SEP verifier) are deprecated; use `^3.0.0`. Claim scope and residual attack surface are documented honestly in `THREAT_BOUNDARY.md`.

```bash
# This package IS the AGA MCP server (TypeScript, runs over stdio). Use it from any MCP client:
npx -y @attested-intelligence/aga-mcp-server
```

A Python companion SDK (`aga-governance`) is documented in the Python SDK section below.

## Verify this yourself (don't take our word)

You do not have to take any of this on faith. The repo ships the reference verifier, the canonical vectors, and sample bundles, so you can check one offline right now, with no network and no callback to us:

```bash
git clone https://github.com/attestedintelligence/aga-mcp-server
cd aga-mcp-server
# A canonical SEP bundle verifies; a one-byte-tampered copy is rejected.
node aga-receipt-spec/verify/verify-sep.mjs fixtures/valid_minimal.json   # OVERALL: VERIFIED (integrity only; no key pinned)
node aga-receipt-spec/verify/verify-sep.mjs fixtures/tampered.json        # OVERALL: FAILED
```

The published `@attested-intelligence/aga-verify` CLI renders the identical verdict, and `npm run conformance:cross-stack` (first: `npm run build && npm --prefix independent-verifier run build`) proves six v1 verifier configurations, spanning **three independent toolchains (JavaScript, Go, and Python, including a pure-stdlib, no-third-party-crypto path)**, agree on all **57** cross-stack cases; `npm run conformance:cross-stack-v2` proves **two genuinely independent-language oracles (@noble/JS and CIRCL/Go)** agree on the v2 composite corpus. For a full trust-free reproduction (build the package yourself, reproduce the published tarball byte-for-byte, re-run every gate), see the **[REVIEWER_GUIDE.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/REVIEWER_GUIDE.md)** (a command-by-command self-service path), **[REPRODUCIBILITY.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/REPRODUCIBILITY.md)**, and the step-by-step **[SKEPTICAL_AUDITOR.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/SKEPTICAL_AUDITOR.md)**. This release carries SLSA build provenance, checkable with `npm audit signatures`.

## What This Does

Every tool call an AI agent makes passes through the AGA gateway. Each call is evaluated against policy, and the decision (PERMITTED or DENIED) is recorded as a signed, hash-linked governance receipt. Receipts are collected into evidence bundles that any third party can verify offline using standard cryptography.

**Record. Prove. Verify.**

**Scope:** a verified bundle proves the *integrity of the receipts present*: each is authentic, correctly ordered, Merkle-included, and (when a key is pinned) provenance-bound. It does **not** prove non-omission (that every action the agent took was logged); completeness is bounded by the tamper-evidence of the interception point, which is outside the bundle. See **[KNOWN_LIMITATIONS.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/KNOWN_LIMITATIONS.md)** for the full honest boundary, and `THREAT_BOUNDARY.md` for the per-field detail.

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
| **Measurement & decision** | `measure_integrity`, `measure_behavior`, `verify_chain` |
| **Evidence** | `generate_evidence_bundle`, `verify_bundle_offline` |
| **Privacy** | `request_claim`, `list_claims` |
| **Delegation** | `delegate_to_subagent` |
| **Audit** | `get_receipts`, `get_chain_events` |

> **`measure_behavior` is detective-only by default**: it observes tool-usage patterns and records a *signed, provable* drift finding, but does not block. Enforcement (drift → quarantine) is opt-in via `enforce=true` and off by default. Hard governance decisions (PERMITTED/DENIED) are made by the portal/PEP, not the behavioral monitor.

## Quick Start: verify a bundle offline

A bundle this package emits (via the `generate_evidence_bundle` MCP tool) is a **canonical SEP bundle**. Verify it offline, with no network and no callback to us:

```bash
# Published verifier CLI — ships on npm, nothing to clone. Pin the gateway key (from get_server_info) to prove provenance.
npx -y @attested-intelligence/aga-verify evidence-bundle.json --pubkey <gateway-public-key>

# Or, from a clone of this repo, the zero-dep reference verifier (Node 18+) renders the identical verdict:
node aga-receipt-spec/verify/verify-sep.mjs evidence-bundle.json --pubkey <gateway-public-key>
```

The published `@attested-intelligence/aga-verify` CLI is the shipped path (the older forgeable 1.0.0 is deprecated); the reference `verify-sep.mjs` renders the identical verdict from a repo clone. Without `--pubkey` you get an **integrity-only** result (`issuerVerified=false`); pin the key to also prove *who* issued it. See `THREAT_BOUNDARY.md` §3.7. A hosted browser verifier is linked under [Links](#links).

The reference §6 algorithm is implemented in **three languages**: JavaScript (`aga-receipt-spec/verify/verify-sep.mjs`), Go (`verify.go`, stdlib `crypto/ed25519`), and Python (`verify.py`, pure-stdlib RFC-8032 Ed25519). A cross-stack harness (`npm run conformance:cross-stack`; first: `npm run build && npm --prefix independent-verifier run build`) proves all three, plus the in-server engine and `aga-verify`, render **identical verdicts** on the canonical vectors (valid, adversarial, and every small-order forgery). The **v2 composite** profile (`ML-DSA-65+Ed25519-SHA256-JCS`) is held to the same bar by a second harness (`npm run conformance:cross-stack-v2`): a `@noble`/JavaScript engine and a CIRCL/Go oracle, two genuinely independent toolchains, render identical verdicts on the pinned v2 corpus, and the **reference** v1 verifier (`verify-sep.mjs`/`verify.py`/`verify.go`) returns `UNSUPPORTED_PROFILE` (exit 3) on a v2 bundle, signalling "profile not implemented" rather than a misleading "invalid". *(The published `aga-verify` CLI does not implement this profile trichotomy: on a v2 bundle it returns FAILED (exit 1). Use exit 3 as the unsupported-profile signal only with the reference verifiers.)*

### Check-name mapping across implementations

The JS reference verifier and the Python SDK (`aga-governance`) decompose the same seven-check verification differently. Overall verdicts and exit codes agree on every conformance-corpus case (re-proven 2026-07-01: 10/10 cells across pristine/tampered bundles with unpinned, correct, and wrong keys); the sub-check that reports a given tamper can differ:

| JS reference check | Python result field | What it covers |
|---|---|---|
| `structural` | `algorithm_valid` + parts of `bundle_consistent` | algorithm id, key well-formedness, receipt/proof counts |
| `receipt_signatures` | `receipt_signatures_valid` | Ed25519 over canonical receipt bytes |
| `chain_and_ordering` | `chain_integrity_valid` | prev-leaf linkage, monotonic ids and timestamps |
| `merkle_and_bijection` | `merkle_proofs_valid` | leaf recompute, single-root walk, index bijection |
| `signed_checkpoint` | `checkpoint_valid` | gateway-signed root + count + chain-head binding |
| `envelope_consistency` | `envelope_consistent` | envelope metadata vs signed content |
| `gateway_key_match` (with `--pubkey`) | `gateway_key_match` / `provenance` | pinned issuer key |

Known decomposition difference: the JS reference recomputes every Merkle leaf from full receipt content, so a receipt-signature tamper also fails `merkle_and_bijection`; the Python verifier surfaces the same tamper in `receipt_signatures_valid`, `chain_integrity_valid`, and `bundle_consistent` while its `merkle_proofs_valid` can remain true. Neither is looser: the bundle fails in both stacks, exit 1. One input-handling difference is deliberate: a malformed `--pubkey` pin is a usage error (exit 2) in the Python SDK, while the JS reference treats a malformed pin as unpinned; the Python behavior is strictly tighter.

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
```

### Exporting the evidence bundle from a running proxy

The proxy records receipts in its own process and keeps the SEP ledger **in memory**. To make that live ledger reachable from a separate shell, `aga-proxy start` opens a **loopback-only control channel** — an HTTP listener bound to `127.0.0.1` (never a routable interface), on its own port (default `18801`, override with `--control-port`), distinct from the agent-facing proxy port (`18800`). It exposes only read routes (`/export`, `/status`, `/receipts`); nothing on it mutates policy or state, and it is unreachable off-host by construction (the loopback bind is the guarantee). The proxy writes the chosen control port to `~/.aga-proxy/control.json` alongside `proxy.pid`.

A **separate** `aga-proxy export` invocation reads that file and fetches the same signed bundle the running proxy would emit:

```bash
# Terminal A — start the proxy in front of an upstream MCP server
npx -p @attested-intelligence/aga-mcp-server aga-proxy start \
  --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp/test" --profile standard

# Terminal B — export the live ledger from a different shell, then verify it offline
npx -p @attested-intelligence/aga-mcp-server aga-proxy export -o evidence.json
npx -y @attested-intelligence/aga-verify evidence.json --pubkey <gateway-public-key>
```

If no proxy is running, `aga-proxy export` prints `no running proxy found; start it first, or export from within the session` and exits non-zero — it never emits an empty or placeholder bundle. Within the MCP **server** session you can also call the `generate_evidence_bundle` tool and save the returned JSON.

**In-memory ledger:** the exported bundle is the durable cryptographic record, but the live in-process chain does **not** survive a proxy restart. This flow makes the *live* ledger reachable from another process; it does **not** add cross-restart persistence, which needs the persistent (SQLite) backend and remains roadmap (see [`KNOWN_LIMITATIONS.md`](https://github.com/attestedintelligence/aga-mcp-server/blob/main/KNOWN_LIMITATIONS.md)).

The proxy intercepts `tools/call` requests, evaluates them against a sealed policy, and generates a signed SEP receipt for **every** decision. Permitted calls are forwarded to the downstream server; denied calls return an MCP error and never reach it. Every decision is hash-linked and checkpoint-bound into a tamper-evident bundle. (Methods other than `tools/call` aren't policy-evaluated, but non-benign ones are recorded as signed *passthrough* receipts for auditability, and an optional denylist can reject them; see `THREAT_BOUNDARY.md` §3.2.)

Three built-in policy profiles:
- **permissive** - log everything, block nothing (default)
- **standard** - rate limits + blocks destructive operations
- **restrictive** - explicit tool allowlist, all unknown tools denied

## Verification _(canonical SEP 3.0; normative §6 algorithm in `aga-receipt-spec/verify/verify-sep.mjs`)_

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

A demo gateway is deployed on Cloudflare Workers (a **separate deployment** that may track its own version; treat it as a convenience mirror, and always verify what it returns offline against a pinned key, not as the canonical artifact):

```bash
# Check status
curl https://aga-mcp-gateway.attested-intelligence.workers.dev/health

# Export evidence bundle
curl https://aga-mcp-gateway.attested-intelligence.workers.dev/bundle -o evidence-bundle.json
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

- **TypeScript MCP server:** 384 automated tests (vitest), including provable-denial and behavioral-monitor regressions
- **SEP conformance corpus:** `npm run test:conformance` (valid → VERIFIED, negatives → FAILED)
- **Python companion SDK:** the separately-published `aga-governance` PyPI package (install + smoke-checked here; its full pytest suite runs from the source tree)

```bash
npm test                              # TypeScript tests (vitest)
npm run test:conformance              # SEP conformance corpus
pip install aga-governance && python -c "import aga; print(aga.__version__)"   # Python SDK smoke check
```

## Benchmarks

Receipt-format determinism is reproducible here: `npm test` runs the cross-language vectors, and `npm run conformance:cross-stack` (first: `npm run build && npm --prefix independent-verifier run build`) shows the six v1 verifier configurations (across three independent toolchains: JS, Go, Python) agree on the canonical 57-case corpus, while `npm run conformance:cross-stack-v2` shows the two independent-language v2 oracles agree on the composite corpus.

## Project Structure

```
src/
  sep/                 # Canonical SEP evidence engine: single source of truth (canon, merkle, receipt, checkpoint, bundle, verify)
  core/                # Governance primitives (portal, artifact, attestation, disclosure, delegation, behavioral) + internal continuity-chain profile
  crypto/              # Internal continuity-chain crypto: Ed25519 (node:crypto), SHA-256/blake2b, salt
  proxy/               # MCP governance proxy (transparent interception + policy enforcement; emits SEP bundles)
  middleware/          # Governance PEP wrapper (records a signed PERMITTED/DENIED receipt per governed call)
independent-verifier/  # @attested-intelligence/aga-verify: standalone SEP verifier, zero AGA imports
scenarios/             # Demo scenarios (SCADA, autonomous vehicle, AI agent) that emit SEP bundles
tests/                 # TypeScript test suite (384 automated tests)
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
