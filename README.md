# AGA - Attested Governance Artifacts

Verifiable decision records for AI agents: each recorded tool-call decision is a signed, hash-chained receipt, exported in evidence bundles a reviewer can verify offline against the published format. Verification establishes the integrity of the receipts present, not that every action was recorded.

[![npm](https://img.shields.io/npm/v/@attested-intelligence/aga-mcp-server)](https://www.npmjs.com/package/@attested-intelligence/aga-mcp-server)
[![PyPI](https://img.shields.io/pypi/v/aga-governance)](https://pypi.org/project/aga-governance/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/attestedintelligence/aga-mcp-server/blob/main/LICENSE)

> **Status: published reference implementation, before independent pilot validation.** Version 3.6.4 updates documentation and release verification. Runtime code and known issues are unchanged from 3.6.3 and 3.6.2. The gateway emits classical Ed25519-SHA256-JCS bundles. The published `@attested-intelligence/aga-verify@2.2.2` CLI checks that classical profile; on a v2/hybrid bundle it reports FAILED because it does not implement that profile. The package also exposes an ML-DSA-65 + Ed25519 composite as a library profile, and `aga-proxy verify` can check it. Reference verifiers have their own unsupported-profile behavior. These are different components, not one interchangeable verifier. Build provenance concerns the published build; it is not runtime correctness or an external security audit.

> **Runtime status.** Since 3.5.0, a measurement requested after the active artifact's TTL expires moves it to TERMINATE; `delegate_to_subagent` also refuses after expiry. Nothing checks the TTL on a schedule, and the exported bundle does not record that transition. Do not downgrade to deprecated 3.3.3 as the evaluation path. Since 3.6.0, `aga-proxy` honors `AGA_GATEWAY_KEY` / `AGA_GATEWAY_KEY_FILE`; the stdio upstream can inherit those variables. Read the known issues and `THREAT_BOUNDARY.md` before any runtime evaluation.

A Python companion SDK (`aga-governance`) is documented in the Python SDK section below.

## Verify this yourself (don't take our word)

Obtain the repository or the [website's static sample kit](https://attestedintelligence.com/verify#offline) while online. Once the verifier, sample and expected public key are local, the verification command itself needs no network or callback to us. Repository cloning and package installation require network access unless their inputs are already cached:

```bash
git clone https://github.com/attestedintelligence/aga-mcp-server
cd aga-mcp-server
# A canonical SEP bundle verifies; a one-byte-tampered copy is rejected.
node aga-receipt-spec/verify/verify-sep.mjs fixtures/valid_minimal.json   # OVERALL: VERIFIED (integrity only; no key pinned)
node aga-receipt-spec/verify/verify-sep.mjs fixtures/tampered.json        # OVERALL: FAILED
```

The published `@attested-intelligence/aga-verify` CLI agrees on the tested classical corpus as the harness supplies it. `npm run conformance:cross-stack` (first: `npm run build && npm --prefix independent-verifier run build`) proves that **six v1 verifier configurations**, spanning **three independent toolchains (JavaScript, Go, and Python, including a pure-stdlib, no-third-party-crypto path)**, agree on the **54 object-level cases**. The **five file-parsing verifiers** also agree on the **7 raw-byte/file-parse cases** (**61 total**). The in-server engine is library-only, receiving parsed objects rather than raw file bytes, so it does not run the file-parse cases; six configurations do not agree on all 61 and this no longer claims they do. `npm run conformance:cross-stack-v2` proves **two genuinely independent-language oracles (@noble/JS and CIRCL/Go)** agree on the v2 composite corpus. For a source-and-build reproduction (build the package yourself, reproduce the published tarball byte-for-byte, re-run every gate), see the **[REVIEWER_GUIDE.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/REVIEWER_GUIDE.md)** (a command-by-command self-service path), **[REPRODUCIBILITY.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/REPRODUCIBILITY.md)**, and the step-by-step **[SKEPTICAL_AUDITOR.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/SKEPTICAL_AUDITOR.md)**. Check build provenance for the exact version: registry signatures and SLSA build attestations are different. The documentation-only 3.6.3 release has registry signatures but no SLSA build attestation. See [REPRODUCIBILITY.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/REPRODUCIBILITY.md) for the version-specific record.

## What This Does

This is built for teams shipping agentic-AI products into financial services and insurance, at the moment a customer's vendor-risk, model-risk, or internal-audit review asks what your agent did and how anyone would know.

Covered tool calls routed through `aga-proxy` are evaluated against its configured policy. Each recorded decision (PERMITTED or DENIED) takes the form of a signed, hash-linked governance receipt; known issue 7 below describes calls refused without a receipt. `aga-proxy` also signs the SHA-256 of its policy's canonical JSON into every receipt; see [KNOWN_LIMITATIONS.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/KNOWN_LIMITATIONS.md) for what that field binds. Receipts are collected into evidence bundles that anyone holding the published format and the public key can verify offline, with no callback to us.

**Record. Prove. Verify.**

**Scope:** a verified bundle proves the *integrity of the receipts present*: each is authentic, correctly ordered, Merkle-included, and (when a key is pinned) provenance-bound. It does **not** prove non-omission (that every action the agent took was logged); completeness is bounded by the tamper-evidence of the interception point, which is outside the bundle. See **[KNOWN_LIMITATIONS.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/KNOWN_LIMITATIONS.md)** for the full honest boundary, and `THREAT_BOUNDARY.md` for the per-field detail.

## Optional runtime evaluation

Runtime examples identify the observed 3.6.2 package. They are not a production recommendation. Review all known issues and use approved isolation with synthetic inputs before starting a gateway. For a first check, use the static sample and verifier above. Do not start these examples on a workstation containing production credentials or customer data.

```bash
# Runtime example only, after the isolation and known-issue review.
npx -y @attested-intelligence/aga-mcp-server@3.6.2
```

### Use with Claude Desktop in the approved evaluation environment

Add to that environment's Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "aga": {
      "command": "npx",
      "args": ["-y", "@attested-intelligence/aga-mcp-server@3.6.2"]
    }
  }
}
```

Claude can then seal artifacts, measure integrity, generate evidence bundles, and verify them offline through natural language.

### Persist a synthetic evaluation key before testing restarts

By default the gateway signs with an **ephemeral** key that rotates on every restart. That is fine for a first look, but evidence-bundle provenance cannot be pinned across restarts (and the server warns about it on stderr). Set one stable 64-hex Ed25519 seed so provenance stays pinnable:

> **Since 3.6.0 this applies to both binaries.** `aga-proxy` reads the same two variables through the same resolver and prints the active public key at startup so you can pin it out of band; `--ephemeral` makes a throwaway key a stated choice. **In 3.5.0 and earlier `aga-proxy` ignored both variables silently**; a key you set had no effect and no warning was printed, so evidence from such a proxy is integrity-verifiable but not provenance-pinnable across restarts. See `DEPLOYMENT.md` §2.

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
      "args": ["-y", "@attested-intelligence/aga-mcp-server@3.6.2"],
      "env": { "AGA_GATEWAY_KEY": "<your-64-hex-seed>" }
    }
  }
}
```

Keep the seed secret and out of version control; see `DEPLOYMENT.md` for key handling. A seed in an agent client's environment is not a separate trust domain, and the stdio upstream can inherit the key-related variables (known issue 3). Same-key restarts do not preserve the in-memory ledger: export and verify before stopping.

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

The MCP tool exports a canonical SEP bundle. Acquire the pinned verifier while online, then run the local verifier with a nonempty expected key obtained through a separate trusted channel. The npx command below may contact npm to obtain the package; it is not an air-gapped acquisition command. The [downloadable sample kit](https://attestedintelligence.com/verify#offline) provides a dependency-free local alternative after download, using Node.js:

```bash
# Published verifier CLI. Obtain and authenticate the expected key outside the bundle before running.
npx -y @attested-intelligence/aga-verify@2.2.2 evidence-bundle.json --pubkey <gateway-public-key>

# Or, from a clone of this repo, the zero-dependency reference verifier (Node 18+) checks its supported profile; parser/pin behavior can differ:
node aga-receipt-spec/verify/verify-sep.mjs evidence-bundle.json --pubkey <gateway-public-key>
```

The published `@attested-intelligence/aga-verify` CLI is the shipped path (the older forgeable 1.0.0 is deprecated); the reference `verify-sep.mjs` provides another implementation from a repo clone; verdict agreement is scoped to tested cases, not all input bytes. Without `--pubkey` you get an **integrity-only** result (`issuerVerified=false`); supply a nonempty expected key from a separate trusted channel to authenticate that signing key; the mapping to an organization depends on that channel. A trailing `--pubkey` without a value falls back to integrity-only success in 2.2.2. See `THREAT_BOUNDARY.md` §3.7. A hosted browser verifier is linked under [Links](#links).

The reference §6 algorithm is implemented in **three languages**: JavaScript (`aga-receipt-spec/verify/verify-sep.mjs`), Go (`verify.go`, stdlib `crypto/ed25519`), and Python (`verify.py`, pure-stdlib RFC-8032 Ed25519). A cross-stack harness (`npm run conformance:cross-stack`; first: `npm run build && npm --prefix independent-verifier run build`) proves all three, plus the in-server engine and `aga-verify`, agree on the published canonical cases as the harness feeds them (object cases are re-serialized; raw-byte cases are separate). Outside that corpus, the implementations differ, including some parser and pin semantics. The **v2 composite** profile (`ML-DSA-65+Ed25519-SHA256-JCS`) is held to the same bar by a second harness (`npm run conformance:cross-stack-v2`): a `@noble`/JavaScript engine and a CIRCL/Go oracle, two genuinely independent toolchains, render identical verdicts on the pinned v2 corpus, and the **reference** v1 verifier (`verify-sep.mjs`/`verify.py`/`verify.go`) returns `UNSUPPORTED_PROFILE` (exit 3) on a v2 bundle, signalling "profile not implemented" rather than a misleading "invalid". *(The published `aga-verify` CLI does not implement this profile trichotomy: on a v2 bundle it returns FAILED (exit 1). Use exit 3 as the unsupported-profile signal only with the reference verifiers.)*

### Check-name mapping across implementations

The JS reference verifier and the Python SDK (`aga-governance`) decompose the same seven-check verification differently. Overall verdicts and exit codes agree on all 61 conformance-corpus cases as the cross-stack harness feeds them (object-level cases re-serialized, so float spellings arrive as integers; measured on aga-governance 0.3.2 on 2026-09-25) and on the 10 cells re-proven 2026-07-01 (pristine and tampered bundles with unpinned, correct and wrong keys). On the literal file bytes of the corpus's float-spelled `leaf_index` case (`0.0`), aga-governance 0.3.2 reports FAILED where the JS reference, `aga-verify`, Go and Python reference verifiers report VERIFIED; see <https://attestedintelligence.com/spec>. The sub-check that reports a given tamper can differ:

| JS reference check | Python result field | What it covers |
|---|---|---|
| `structural` | `algorithm_valid` + parts of `bundle_consistent` | algorithm id, key well-formedness, receipt/proof counts |
| `receipt_signatures` | `receipt_signatures_valid` | Ed25519 over canonical receipt bytes |
| `chain_and_ordering` | `chain_integrity_valid` | prev-leaf linkage, canonical non-decreasing timestamps (ids are not ordering fields and are not checked) |
| `merkle_and_bijection` | `merkle_proofs_valid` | leaf recompute, single-root walk, index bijection |
| `signed_checkpoint` | `checkpoint_valid` | gateway-signed root + count + chain-head binding |
| `envelope_consistency` | `envelope_consistent` | envelope `gateway_id`, `generated_at`, `merkle_root` vs signed content (`bundle_id`, `schema_version`, the envelope `policy_reference` and `offline_capable` are unsigned and unchecked) |
| `gateway_key_match` (with `--pubkey`) | `gateway_key_match` / `provenance` | pinned issuer key |

Known decomposition difference: the JS reference recomputes every Merkle leaf from full receipt content, so a receipt-signature tamper also fails `merkle_and_bijection`; the Python verifier surfaces the same tamper in `receipt_signatures_valid`, `chain_integrity_valid`, and `bundle_consistent` while its `merkle_proofs_valid` can remain true. Neither is looser: the bundle fails in both stacks, exit 1. A `--pubkey KEY` that is not 64 lowercase hex characters is a usage error (exit 2) in the JS reference, `aga-verify` and the Python SDK, and a 64-hex pin that is not a valid curve point is honored, fails to match, and fails the bundle (exit 1). Written as `--pubkey=KEY`, the pin is ignored by the JS reference, `aga-verify`, `verify.go` and `v2/verify-v2.go`, and by `verify.py` when it follows the bundle path (integrity only, exit 0), and read by the Python SDK. Other verifiers differ as well. The in-server engine (the package's `./verify` export, which `verify_bundle_offline` calls) treats a pin that is not a well-formed key for the bundle's profile (for a v1 bundle, a small-order point or a non-canonical encoding) as no pin, and returns VERIFIED with `pinned: false`. `v2/verify-v2.go` does the same and prints `integrity only; no key pinned` (exit 0). A 64-hex value that is not a curve point counts as well-formed, so both take it as a pin and the bundle fails. The Go and Python reference verifiers in `aga-receipt-spec/verify/` treat a pin that is not 64 lowercase hex the same way and print `integrity only; no key pinned` (exit 0). Read `pinned` before taking a VERIFIED as provenance; in CI, pass the key after a space and check that the output says provenance verified. A `--pubkey` given with no value is also treated as no pin (exit 0, integrity only) by `aga-verify`, `verify-sep.mjs`, `verify.py`, `verify.go` and `v2/verify-v2.go`, and is a usage error in the Python SDK. Other differences concern the bundle rather than the pin, and <https://attestedintelligence.com/security> lists the ones measured, including which algorithm labels each verifier leaves unchecked; outside the conformance corpus the verifiers differ in both directions. Two examples, where the failing side fails closed: a proof `leaf_index` spelled as an integral float (`1.0`) reports FAILED in aga-governance 0.3.2 and VERIFIED in the others, and object keys outside the Basic Multilingual Plane (possible only in a non-string field value, which no shipped producer emits) sort differently in `verify.py`, `verify.go`, `v2/verify-v2.go` and aga-governance than in the JavaScript verifiers, so such a bundle reports VERIFIED in JavaScript and FAILED in Go and Python. These wait for the next reviewed release.

## How It Works

```
AI Agent                  AGA Proxy                      Verifier
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

Run AGA as a proxy in front of an MCP server that it starts as a stdio child process (the default stdio transport), or one it reaches with a plain JSON-RPC POST (`--upstream-url`; no Streamable HTTP session or SSE handling). The proxy's agent port speaks newline-delimited JSON-RPC 2.0 over raw TCP, not stdio or Streamable HTTP. A stdio MCP client needs a relay you provide (a few lines that pipe stdin to the port and the port to stdout); none ships. A scripted client can speak that framing directly. Every `tools/call` request with a non-empty string tool name and arguments the proxy can canonicalize is evaluated against the policy and produces a signed receipt, except the calls that known issue 7 below describes as refused without one. Other methods that are not benign are forwarded with a signed passthrough receipt and are not policy-evaluated, and benign protocol methods (`initialize`, `initialized`, `ping`, `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`, `logging/setLevel`, `completion/complete` and `notifications/*`) produce no receipt (THREAT_BOUNDARY.md section 3 item 2). Read the known issues below before you expose the port.

```bash
# Start the proxy (the `aga-proxy` bin) in front of an upstream MCP server.
# stdio upstream = the default stdio transport (the upstream is a child process, not network-reachable).
npx -p @attested-intelligence/aga-mcp-server@3.6.2 aga-proxy start \
  --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp/test" --profile permissive
```

`permissive` records each `tools/call` it evaluates (known issue 7 describes the exceptions) and denies nothing on policy
grounds. `standard` and `restrictive` allow only generic example tool names, so they deny every tool this example server
exposes; to permit some of your server's tools and deny the rest, pass a `--policy` file that names them.

### Exporting the evidence bundle from a running proxy

The proxy records receipts in its own process and keeps the SEP ledger **in memory**. To make that live ledger reachable from a separate shell, `aga-proxy start` opens a **loopback-only control channel**: an HTTP listener bound to `127.0.0.1` (never a routable interface), on its own port (default `18801`, override with `--control-port`), distinct from the agent-facing proxy port (`18800`). It exposes only read routes (`/export`, `/status`, `/receipts`); nothing on it mutates policy or state. It does not check a request's Host or Origin header, so a web page in a browser on the same host can read its responses through DNS rebinding unless the browser blocks it (known issue 12). The proxy writes the chosen control port to `~/.aga-proxy/control.json` alongside `proxy.pid`.

A **separate** `aga-proxy export` invocation reads that file and fetches the same signed bundle the running proxy would emit:

```bash
# Terminal A: start the proxy in front of an upstream MCP server
npx -p @attested-intelligence/aga-mcp-server@3.6.2 aga-proxy start \
  --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp/test" --profile permissive

# (First, drive at least one tools/call through the proxy from your MCP client; an empty
#  ledger has no receipts to checkpoint, and the export reports there is nothing to export.)
# Terminal B: export the live ledger from a different shell, then verify it offline
npx -p @attested-intelligence/aga-mcp-server@3.6.2 aga-proxy export -o evidence.json
npx -y @attested-intelligence/aga-verify@2.2.2 evidence.json --pubkey <gateway-public-key>
```

Export and verify before you stop the proxy: `aga-proxy stop` ends the process without exporting, and the in-memory chain
goes with it (known issue 9 covers export time and bounding the chain).

If no proxy is running, `aga-proxy export` prints `no running proxy found; start it first, or export from within the session` and exits non-zero; it never emits an empty or placeholder bundle. Within the MCP **server** session you can also call the `generate_evidence_bundle` tool and save the returned JSON.

**In-memory ledger:** the exported bundle is the durable cryptographic record, but the live in-process chain does **not** survive a proxy restart. This flow makes the *live* ledger reachable from another process; it does **not** add cross-restart persistence, which needs the persistent (SQLite) backend and remains roadmap (see [`KNOWN_LIMITATIONS.md`](https://github.com/attestedintelligence/aga-mcp-server/blob/main/KNOWN_LIMITATIONS.md)).

The proxy intercepts `tools/call` requests, evaluates them against the loaded policy (a JSON file or a built-in profile; the SHA-256 of its canonical JSON is signed into every receipt), and generates a signed SEP receipt for **every** decision (except the calls that known issue 7 below describes as refused without one). Permitted calls are forwarded to the downstream server; denied calls return an MCP error and never reach it. Each recorded decision is hash-linked and checkpoint-bound into a tamper-evident bundle. (Methods other than `tools/call` aren't policy-evaluated, but non-benign ones are recorded as signed *passthrough* receipts for auditability, and a library caller can pass a method denylist (`denyMethods`) to reject them; the `aga-proxy` CLI has no flag for it; see `THREAT_BOUNDARY.md` §3.2.)

Three built-in policy profiles:
- **permissive** - `audit_only`: denies nothing on policy grounds and records each `tools/call` it evaluates (default); the fail-closed refusals below and known issue 7 still apply
- **standard** - an allowlist of ten generic example tool names (`filesystem_read`, `shell_execute`, `web_search` and others) with rate limits, and substring denials on two of them; every other tool is denied, so a real server's tools need a `--policy` file
- **restrictive** - an allowlist of three generic example tool names with lower rate limits and a path prefix on one; every other tool is denied

Because the default (`permissive`) is audit-only, starting with an `audit_only` policy prints a loud stderr banner stating that every call is permitted and recorded and no call is denied in that mode. No call is denied on policy grounds, but the proxy still refuses, fail-closed, a `tools/call` with no tool name or with arguments it cannot canonicalize (nested past 100 levels, for example), and signs a DENIED receipt for each; a name of `0`, `false`, `null` or an empty string counts as no name. Policy denial needs `--profile standard` or `restrictive`, or a `--policy` file in `allowlist` or `denylist` mode. In `denylist` mode a policy denies each tool it lists as an object whose `allowed` value is missing or falsy (`false`, `0`, `null` or an empty string); any other `allowed` value allows the tool, including the string `"false"`, and so does a listed entry that is itself `false`, `0`, `null` or an empty string rather than an object. In 3.6.0 through 3.6.2 it also denies an unlisted tool named like a built-in object property, such as `constructor`. It applies the rate limits of the listed tools it allows; path and pattern rules apply in `allowlist` mode only and check only top-level string arguments (known issue 10). A `--policy` file in `audit_only` mode permits every call; one with any other mode, or none, denies every `tools/call`, and in 3.6.0 through 3.6.2 one in `allowlist` or `denylist` mode whose `constraints` member is missing or null refuses, with no receipt and no response, every `tools/call` that has a tool name and arguments the proxy can canonicalize (known issue 7). An unrecognized `--profile` value is a hard error (exit 2 listing the valid names), never a silent fallback to `permissive`.

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

# Download a static demonstration bundle (not a live export)
curl https://attestedintelligence.com/sample-bundle.json -o evidence-bundle.json
# Static sample only. Use the separately published sample pin, not a key read from this file.
```

## Python SDK

> **Status, checked against PyPI on 2026-09-28.** The current release is `aga-governance` 0.3.2. Version 0.3.1 fixed the depth-bomb crash; 0.3.0 was yanked for that crash. Both 0.2.6 files are now yanked as well, but that does not repair installed copies. Use the reviewed current version when evaluating untrusted bundles and retain its documented parser and verdict limitations. The JavaScript reference verifier and `aga-verify` do not have that Python depth-bomb crash.

```bash
pip install "aga-governance==0.3.2"
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

- **TypeScript MCP server:** historical 3.6.0 release CI reported 428 automated tests (vitest), including provable-denial and behavioral-monitor regressions. That evidence was reviewed September 21, 2026; these tests were not rerun during the September 28 website review.
- **SEP conformance corpus:** `npm run test:conformance` (valid → VERIFIED, negatives → FAILED)
- **Python companion SDK:** the separately-published `aga-governance` PyPI package (install + smoke-checked here; its full pytest suite runs from the source tree). The smoke check imports the package and prints its version. It does not exercise the verifier.

```bash
npm test                              # TypeScript tests (vitest)
npm run test:conformance              # SEP conformance corpus
pip install "aga-governance==0.3.2" && python -c "import aga; print(aga.__version__)"   # Python SDK smoke check
```

## Benchmarks

Receipt-format determinism is reproducible here: `npm test` runs the cross-language vectors, and `npm run conformance:cross-stack` (first: `npm run build && npm --prefix independent-verifier run build`) shows the six v1 verifier configurations (across three independent toolchains: JS, Go, Python) agree on the 54 object-level cases of the canonical 61-case corpus. The remaining 7 are raw-byte/file-parse cases run by the five file-parsing verifiers, since the in-server engine never receives raw bytes. `npm run conformance:cross-stack-v2` shows the two independent-language v2 oracles agree on the composite corpus.

## Project Structure

```
src/
  sep/                 # Canonical SEP evidence engine: single source of truth (canon, merkle, receipt, checkpoint, bundle, verify)
  core/                # Governance primitives (portal, artifact, attestation, disclosure, delegation, behavioral) + internal continuity-chain profile
  crypto/              # Internal continuity-chain crypto: Ed25519 (node:crypto), SHA-256/blake2b, salt
  proxy/               # MCP governance proxy (transparent interception + policy evaluation; emits SEP bundles)
  middleware/          # Governance PEP wrapper (records a signed PERMITTED/DENIED receipt per governed call)
independent-verifier/  # @attested-intelligence/aga-verify: standalone SEP verifier, zero AGA imports
scenarios/             # Demo scenarios (SCADA, autonomous vehicle, AI agent) that emit SEP bundles
tests/                 # Historical 3.6.0 CI: 428 tests; reviewed 2026-09-21
```

## Links

- [Website](https://attestedintelligence.com)
- [Technology](https://attestedintelligence.com/technology)
- [Live Verifier](https://attestedintelligence.com/verify)
- [Trust and Scope](https://attestedintelligence.com/trust)
- [Diligence Materials](https://attestedintelligence.com/diligence)
- [MCP Server (npm)](https://www.npmjs.com/package/@attested-intelligence/aga-mcp-server)
- [Python SDK (PyPI)](https://pypi.org/project/aga-governance/)
- [Changelog](https://github.com/attestedintelligence/aga-mcp-server/blob/main/CHANGELOG.md)
- [Threat boundary](https://github.com/attestedintelligence/aga-mcp-server/blob/main/THREAT_BOUNDARY.md)
- [Deployment guide](https://github.com/attestedintelligence/aga-mcp-server/blob/main/DEPLOYMENT.md)

## Known issues in 3.6.0 to 3.6.2 and the published verifiers

3.6.1 and 3.6.2 change only the documentation and the version number; the runtime is 3.6.0's. Items 1 to 4 were reproduced on 2026-09-23 on `@attested-intelligence/aga-mcp-server` 3.6.0 installed from npm, and
concern the `aga-proxy` gateway. Item 5, added 2026-09-25, concerns the verifiers and was reproduced on 2026-09-25
on the current releases. Item 6, also added 2026-09-25, concerns aga-proxy with an HTTP upstream and was
reproduced on 2026-09-25 on 3.6.2. Item 7, also added 2026-09-25, concerns `tools/call` messages that aga-proxy refuses
without a receipt and was reproduced on 2026-09-25 on 3.6.2 (its oversized-message case was added and reproduced on
2026-09-26). Items 8 to 12, added 2026-09-26, concern non-ASCII text,
the cost of exporting evidence, what policy constraints check, oversized tool results and the control channel; each
was reproduced on 2026-09-26 on 3.6.2, as were the memory and Windows port cases added to item 1 that day. The same
list is kept at <https://attestedintelligence.com/security>.

1. **The agent port listens on every network interface, with no authentication.** Anyone who can
   reach the host on that port can send governed calls through the proxy. The proxy also sets no limit on the number
   of connections, so although each connection's unfinished message is capped (item 7), the memory they hold together
   is not: on 3.6.2, ten connections that each sent 7.5 MiB without ending a message raised the proxy's working set
   from 68 MiB to 392 MiB while they stayed open, and a governed call on another connection was still answered. On
   Windows, a process running under the same user account as the proxy can bind 127.0.0.1 on the same port while the
   proxy listens, and a local client that connects to 127.0.0.1 then reaches that process instead of the proxy, with no
   policy check and no receipt (measured on 3.6.2 with both processes under one account). Block inbound traffic to the
   port in the host firewall, or admit only the agent with network policy; on Windows, run nothing untrusted under the
   proxy's account, and check while the proxy runs that its process is the only listener on the port. The control
   port is bound to loopback; see item 12.
2. **Two clients that reuse a JSON-RPC id through one proxy can receive each other's tool results.**
   Workaround, measured on 3.6.0: give each client its own id range, or run one proxy per client.
   With disjoint ids, every result reached the client that asked for it.
3. **When the gateway key is supplied through `AGA_GATEWAY_KEY` (with or without `--ephemeral`) or
   `AGA_GATEWAY_KEY_FILE`, the stdio upstream inherits that variable** (the seed, or the file's
   path), so the upstream sits inside the key's trust domain. Workaround, measured on 3.6.0: run
   without either variable. The upstream then sees neither, but the proxy signs with a per-process
   key that cannot be pinned across restarts.
4. **The `--upstream-url` mode forwards raw JSON-RPC over HTTP POST with only a content-type header.** It does not
   implement the MCP Streamable HTTP transport (the Accept header, the request metadata headers and event-stream
   handling), so a spec-conformant HTTP MCP server rejects its requests. Workaround: bridge to the server over stdio.
5. **A bundle file can repeat a field name anywhere: in a receipt, in the checkpoint or in the envelope.** For example,
   a forged `"decision": "PERMITTED"` can be placed ahead of the signed `"decision": "DENIED"`, or a forged checkpoint
   `leaf_count` ahead of the signed one. The published verifiers (aga-verify 2.2.2, aga-governance 0.3.2, the verifier in
   this package, and the reference verifiers in `aga-receipt-spec/verify/`) and the site's /verify page read the last
   occurrence, and when it holds the genuine value they report VERIFIED, with provenance when the key is pinned. They do
   not reject the file, so a tool or a person reading the first occurrence can see a value that was never signed.
   Measured on the public sample bundle, pinned to the sample key: with the repeated name inserted in a receipt, in the
   checkpoint or in the envelope, aga-verify 2.2.2, aga-governance 0.3.2, the verifier in this package and /verify report
   VERIFIED, and a real change of the checkpoint value fails. Workaround: treat the verifier's parsed output as the
   record's content, and reject or flag files with repeated field names before displaying them. A strict rejection of
   repeated field names is planned for the reviewed release.
6. **A message can repeat the `"method"` member when aga-proxy has an HTTP upstream (`--upstream-url`).** With
   `tools/call` first and another method last, aga-proxy reads the last copy, so it never checks the tool call against
   the policy, and it forwards every method other than `tools/call` to the HTTP upstream as the exact bytes it
   received. An upstream whose JSON parser keeps the first copy of a repeated name then runs the tool call, even one
   the policy denies. The bundle holds no receipt for that call: nothing at all when the last method is one the proxy
   passes through without a receipt (such as `ping`, `initialize`, a list method or a notification), and otherwise only
   a passthrough receipt that names the last method. An upstream that keeps the last copy handles the message as the
   method the proxy read. The stdio upstream, the default, is not affected: the proxy re-serializes each message
   before writing it, so the upstream receives one method. Measured on 3.6.2 from npm on 2026-09-25, with the
   restrictive profile and with the default permissive profile. Workaround: keep the stdio default, or have the HTTP
   upstream reject any message that repeats a member name. A strict rejection of repeated member names in the proxy
   is planned for the reviewed release.
7. **aga-proxy does not record every `tools/call` it refuses.** It signs a `tools/call`'s receipt before it forwards the
   call, so with a stdio upstream a call it cannot record never reaches the tool (for an HTTP upstream, see item 6), but
   such a call leaves no receipt. These cases were measured on 3.6.2 from npm on 2026-09-25, each with no receipt and no
   response to the client: a `tools/call` whose tool name is a non-zero number, an array or an object (a name of `0`, `false`,
   `null` or an empty string counts as no name and gets a DENIED receipt and an error); one whose tool name or string id
   holds an unpaired surrogate (the JSON escape `\ud800`, for example); under a `--policy` file in `allowlist` or
   `denylist` mode whose `constraints` member is missing or null, every `tools/call` with a tool name and arguments the
   proxy can canonicalize; and, under an allowlist file, a call it would otherwise permit that carries a string path when that
   tool's `path_prefix` is neither a string nor false, 0 or null. The proxy starts with such a policy file, and it reports
   each refusal listed above only on its own stderr. A message sent as a JSON-RPC batch array or without
   `"jsonrpc": "2.0"` is refused differently: the client gets an error, and there is no receipt. A message of 8,388,608
   characters or more (UTF-16 code units, about 8.4 million), not counting the newline that ends it but counting a carriage
   return before that newline, also gets an error and no receipt, and the proxy then closes
   the connection, dropping any reply still due on it. The limit counts input not yet split into messages, so a message
   just under the limit can be refused the same way when the read that completes it also carries enough input after it to pass the limit; whether that happens depends on where the reads fall. On 3.6.2, when a 100-character
   message, a message 58 characters under the limit and a 100,000-character message were sent in one write, the first
   was answered, the second got the error and the connection closed; sent without the 100,000-character message, or
   without the 100-character one, every message was forwarded. These are
   the cases measured, not a proof that no other input does the same. Workaround: give every policy file a `constraints`
   object whose `path_prefix` values are strings, and have the client time out a call that gets no reply. A DENIED
   receipt and an error for a malformed tool name, and a check of the policy file at startup, are planned for the
   reviewed release.
8. **aga-proxy can alter non-ASCII text whose bytes are split between two reads.** It decodes each chunk it reads from
   the agent's connection, and from a stdio upstream's output, on its own, so a character split between two chunks
   becomes one or more replacement characters (U+FFFD). A tool call's arguments can then reach the upstream altered, and
   the receipt's arguments hash is the hash of the altered arguments; a large non-ASCII result from a stdio upstream can
   reach the agent altered. An HTTP upstream's result is decoded whole. Whether a split happens depends on how the bytes
   arrive, so any message with non-ASCII text can be affected, and large ones more often. Measured on 3.6.2 from npm on
   2026-09-26: a forced split inside "é" reached the upstream as two replacement characters, and a result of 200,000 "€"
   reached the client with 15 replacement characters in it. Workaround: send JSON whose non-ASCII characters are written
   as `\uXXXX` escapes, so every byte the proxy reads from the agent is ASCII, and have a stdio upstream do the same; a
   forced split of the escaped message then arrived intact. A fix is planned for the reviewed release.
9. **Exporting the evidence bundle takes time that grows with the square of the number of receipts, and aga-proxy
   handles nothing else while it runs**: every governed call waits until the export ends. A call forwarded to a stdio
   upstream that has not answered when an export starts gets a timeout error if the export ends more than 30 seconds
   after the call was forwarded, although the upstream ran it and its receipt says PERMITTED, so an agent that retries
   can run the tool twice. Measured on 3.6.2 from npm on
   2026-09-26 through the control channel's `GET /export`: 2.8 seconds at 1,000 receipts and 17.4 seconds at 2,500, with
   a `tools/call` sent during the export waiting as long; at 4,000 receipts an export took 43.8 seconds, and a call
   forwarded just before it, which the upstream answered in 2 seconds, got the timeout error. At 1,000 to 4,000
   receipts a compact bundle took about 1.7 to 1.9 KB per receipt, rising with the count. An audit the same day measured 88 to 113 seconds at 5,000 receipts.
   Verification time grows close to linearly. Workaround: each export covers every receipt since the proxy started and
   does not shorten the chain, so bound the chain by restarting the proxy on a schedule: pause the agents, export and
   verify, then restart. A restart begins a new chain that is not linked to the last one and resets the rate-limit counts;
   with a per-process key (`--ephemeral`, or neither `AGA_GATEWAY_KEY` nor `AGA_GATEWAY_KEY_FILE` set) it also begins a
   new signing key, printed at startup, that cannot be pinned across restarts (item 3). Export outside busy periods, and
   export and verify before any stop, because the live chain is kept in memory and a stop loses receipts not yet
   exported. A fix
   that leaves the bundle's bytes unchanged is planned for the reviewed release.
10. **Policy constraints check less than their names suggest.** A `path_prefix` is checked only when the value under the
    checked key (`path`, or the keys a rule lists in `path_keys`) is a string, so the same path sent inside an array or an
    object is not checked. `denied_patterns` match case-sensitively and only in top-level string arguments, so an
    uppercased command, or one inside an array or a nested object, is not matched. A constraint key the proxy does not
    recognise, such as a misspelling, is ignored without a warning, and a value of the wrong JSON type is not rejected:
    `allowed: "false"`, a string, allows the tool; in denylist mode a tool listed as `false`, `null` or `0` instead of an
    object is allowed; and a non-empty `path_keys` string instead of an array makes the check read each character as a key
    name, so the intended key goes unchecked. Rate limits count per tool name across the whole
    proxy, shared by every client, and in allowlist mode the limit is checked before the path and pattern rules, so a
    call those rules deny still uses up a slot. Measured on 3.6.2 from npm on 2026-09-26 with allowlist and denylist policy files: a
    `path_prefix` of `/home` denied `"/etc/passwd"` and forwarded `["/etc/passwd"]`; a denied pattern of `rm -rf` denied
    `rm -rf /` and forwarded `RM -RF /` and the same command inside an array; a rule spelled `denied_pattern` denied
    nothing; `allowed: "false"` forwarded the call in both modes; a denylist entry of `false` forwarded the call;
    `path_keys: "path"` forwarded `/etc/passwd` past a `/home` prefix; and, under a limit of 2 a minute, two calls denied by a
    `/home` prefix left a third call, to a path under `/home`, denied for the rate limit, while after one such denial that
    call was forwarded. Workaround: treat path and pattern rules as a convenience rather than a boundary, restrict paths in the
    upstream server itself, and check a policy file's keys against the constraint names in `dist/proxy/types.d.ts`.
    Checks that fail closed on these inputs, and a check of the policy file at startup, are planned for the reviewed
    release.
11. **A stdio upstream's response whose JSON line is 8,388,608 characters or more (UTF-16 code units, counting JSON
    escaping and a carriage return before the newline, but not the newline itself) is dropped.** The call already
    has a PERMITTED receipt, and the agent gets a timeout error after 30 seconds, so an agent that retries can run the tool
    twice; the proxy reports the drop only on its own stderr. The limit counts upstream output not yet split into lines, so
    a response just under it can be dropped when the read that completes it also carries enough output after it to pass
    the limit; every response after it that begins in that read, possibly to other clients' calls, is dropped with it.
    Whether that happens depends on where the reads fall. Measured on 3.6.2 from npm on 2026-09-26: a
    9,000,000-character result was dropped and the agent got the timeout after 30.0 seconds, while a 1,000,000-character
    result came back in 31 milliseconds. Through a running proxy, a response line of 8,388,607 characters was returned and
    one of 8,388,608 was dropped; and when the upstream answered three calls in one write (100 characters and 58 under the
    limit for one client, then 100 for the other), the first was answered and the other two, one of them the other client's,
    timed out, while the same answers without the leading 100-character answer were both returned. These are the cases measured. An HTTP upstream's
    result is read whole and is not dropped this way; on Linux, one at the same bound closes the agent's connection
    instead (item 13). Workaround: keep tool results well under the bound, for example by
    reading large files in parts, and where results are large run one proxy per client. An error returned at once is
    planned for the reviewed release.
12. **The control channel does not check a request's Host or Origin header.** It listens on 127.0.0.1 (port 18801 by
    default) so that a separate `aga-proxy export` can fetch the live bundle (routes `/export`, `/status` and
    `/receipts`). Measured on 3.6.2 from npm on 2026-09-26: `GET /receipts` and
    `GET /export` sent with the Host and Origin of another site returned 200, and both carried a denied call's argument
    path in its denial reason. A web page open in a browser on the same host can therefore read the live receipts and
    the evidence bundle through DNS rebinding, unless the browser blocks a public site's requests to the loopback
    address; any local user on the host can read them as well. A page can also start an export with a plain
    `GET /export` without rebinding, unless the browser blocks it, and each export holds up governed calls while it
    runs (item 9). The CLI has no option meant to turn the channel off; a `--control-port` of 70000, or any number
    above 65535, leaves it unstarted while governance runs, but then no command can export the running
    proxy's receipts. Workaround: do not browse the web on the host while the proxy runs, or run the proxy on a host
    where no one does, and on a host shared with other users treat the live receipts as readable by all of them.
    A Host and Origin check is planned for the reviewed release.
13. **On Linux, an HTTP upstream's (`--upstream-url`) response whose JSON line, as the proxy serializes it, is 8,388,608
    characters or more (UTF-16 code units, counting JSON escaping but not the newline) closes the agent's connection.**
    The proxy writes the whole line to the agent's socket in one call. A Linux kernel with its default socket buffers
    takes only part of a write that size; the rest goes out as the client reads, but the whole line counts as waiting
    until it has all gone, so the proxy's guard against a client that does not read its responses sees more than
    8,388,608 characters waiting, the newline included, and destroys the socket. The call already has a PERMITTED
    receipt and the upstream has run the tool; the agent's connection closes part-way through the reply with no error
    message, so an agent that reconnects and retries can run the tool twice; every other call in flight on that
    connection is lost with it; and the proxy reports nothing. Measured on 3.6.2 from npm on 2026-09-26 on a Linux 6.18
    host with Node 24 and the default socket buffers (`net.ipv4.tcp_wmem` 4096 16384 4194304): result lines of
    4,000,000, 8,000,000, 8,388,606 and 8,388,607 characters were returned, and lines of 8,388,608, 8,388,609,
    9,000,000, 10,000,000, 12,000,000, 16,000,000, 20,000,000 and 32,000,000 characters closed the connection after 3.1
    to 5.0 MB of the reply had arrived; a client that read nothing for 4 seconds got a 4,000,000-character result and
    lost a 9,000,000-character one after 2.7 MB. On Windows 11 the same proxy returned a 20,000,000-character result, and a
    9,000,000-character one to a client that read nothing for 4 seconds, because that kernel took each write whole. A
    stdio upstream's response of this size is dropped instead (item 11). Workaround: keep tool results well under the bound,
    for example by reading large files in parts. An error returned at once is planned for the reviewed release.

No fixed version is named until one is published.

## Security

See [SECURITY.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/SECURITY.md) for vulnerability reporting.

## Contributing

See [CONTRIBUTING.md](https://github.com/attestedintelligence/aga-mcp-server/blob/main/CONTRIBUTING.md) for development setup and guidelines.

## License

[MIT](https://github.com/attestedintelligence/aga-mcp-server/blob/main/LICENSE). The `aga-receipt-spec/` directory carries its own
Apache-2.0 license (see `aga-receipt-spec/LICENSE`).

---

Attested Intelligence Holdings LLC
