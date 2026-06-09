# AGA MCP Server — Threat Boundary & Bypass Surface (honest audit)

**Scope:** `@attested-intelligence/aga-mcp-server` 3.0.1 (npm `latest`). Written for Sprint 3 CP3.
**Stance:** defensibility through honesty. This documents what the package **does** guarantee, what it **does not**, and the **residual attack surface** that remains by design or is deferred. Per the project discipline: better a precisely-stated boundary than an overclaim.

---

## 1. The core claim (what is proven + tested)

> Every **governed** decision (PERMITTED *and* DENIED) produces a signed, hash-chained, Merkle-included, **checkpoint-bound** SEP receipt that any third party can verify offline (`aga-verify` / `verify-sep.mjs`), with provenance when the gateway key is pinned.

A denial **cannot be silently erased by the agent**:

| Attack | Defense | Test |
|---|---|---|
| Tamper a receipt | Ed25519 signature + leaf-recompute fail | `acceptance.test.ts 9.3`, `fixtures/cross-stack` |
| Drop the DENIED receipt (truncation) | signed checkpoint binds `leaf_count` + head | `fixtures/cross-stack` (SC4) |
| Reorder to bury it | `previous_receipt_hash` chain + non-decreasing timestamp | `fixtures/cross-stack` (SC5) |
| Re-attest to wipe history | SEP ledger is **not** reset on `attest_subject` | `tests/integration/provable-denial.test.ts` |
| Forge under a different key | receipts checked vs **pinned** key; **all** small-order encodings (10 canonical + non-canonical `y≥p`) rejected | `fixtures/cross-stack` (SC6), `tests/sep/reaudit-fixes.test.ts` |
| Crash the recorder to erase a decision (deeply-nested arg "depth bomb") | `canonicalize` is **depth-bounded**; the governance wrapper + proxy **fail closed** — an uncanonicalizable call is DENIED *and recorded*, never silently dropped or forwarded | `tests/proxy/dos-failclosed.test.ts`, `tests/sep/reaudit-fixes.test.ts` |

Claim scope is **integrity-of-present-receipts, NOT non-omission**: a PASS proves every *present* receipt is authentic and complete-as-a-set under the checkpoint; it does **not** prove the gateway logged every action it took. Completeness is bounded by the tamper-evidence of the interception point, which is outside the bundle.

---

## 2. Governed vs ungoverned tool surface

**Governed (PEP-gated + SEP-recorded; PERMITTED/DENIED on every call):**
`measure_integrity`, `revoke_artifact`, `request_claim`, `delegate_to_subagent` — the agent-action tools.

**Ungoverned (by design):**
| Tool | Why ungoverned (safe) |
|---|---|
| `get_server_info`, `get_portal_state`, `get_receipts`, `get_chain_events`, `list_claims`, `verify_chain` | read-only; no side effects on the governed subject |
| `init_chain`, `attest_subject` | **bootstrap** — they *establish* the governance relationship (chicken-and-egg: cannot be gated by a policy that doesn't exist yet). `attest_subject` sets policy, it does not perform an agent action, and re-attestation **cannot erase** the prior SEP ledger (§1). |
| `generate_evidence_bundle`, `verify_bundle_offline` | **evidence operations** — must work *especially after* TERMINATION/quarantine (you need to export and verify the record once governance is revoked). Not agent actions; not SEP-recorded. (The legacy `create_checkpoint` continuity tool was removed in P4.) |
| `measure_behavior` | **detective-only** monitor (§CP2); records a provable drift finding, does not block unless `enforce=true`. |

**Maintenance invariant (must hold for the core claim):** any *new* tool that performs an agent **action** with side effects MUST be added to the governed set (i.e., NOT in `UNGOVERNED_TOOLS`), so it produces a PERMITTED/DENIED receipt. Read/bootstrap/evidence tools stay ungoverned. A CI check that flags new non-ungoverned-listed tools is recommended (future).

---

## 3. Residual attack surface (honest, deferred, or deployment-dependent)

1. **Proxy — mandatory mediation is a deployment property.** `GovernanceProxy` governs the path *through it*; if the agent can reach the upstream MCP server **directly** (network), it bypasses governance entirely. `upstreamUrl` (HTTP) is directly reachable. → **Deployment requirement:** the agent must be network-isolated so the proxy is its *only* route to tools. Documented, not code-enforceable here. *(Empirically demonstrated in CP3 A7 — a direct POST to the upstream fired a side effect with no receipt; the red-team scripts are maintained in the private validation tree, not shipped in this package.)* **See `DEPLOYMENT.md` §1: stdio-upstream is the hardened default — the upstream is a non-network-reachable child process, closing this bypass by construction; HTTP-upstream mode now warns on stderr.**
2. **Proxy — only `method === "tools/call"` is policy-evaluated; partially mitigated in 3.0.** Other JSON-RPC methods are still forwarded (not policy-evaluated), but they are now recorded as **signed passthrough receipts** in the evidence bundle for auditability — so a side-effecting non-`tools/call` method is no longer *invisible* (the CP3 A7 `admin/deleteAllData` would now appear as a `(passthrough)` receipt with `method` set and `reason: forwarded, not policy-evaluated`). Benign protocol methods (`initialize`, `ping`, `tools/list`, `*/list`, `notifications/*`, …) are excluded by default; an optional `denyMethods` denylist rejects known side-effecting methods (a **DENIED** passthrough receipt, not forwarded). **What this closes:** invisibility — every forwarded non-benign method is now in the tamper-evident, checkpoint-bound bundle. **What it does NOT close:** the method is not policy-evaluated and still *executes* unless explicitly denylisted (this is *visibility, not governance*), and a direct-to-upstream call (§3.1) still bypasses the proxy entirely. Full per-method policy evaluation remains future work.
3. **Proxy — denial is observable.** A DENIED call returns a distinctive `-32600` error, which an adversary can use as a policy-probing oracle. Low severity; structured denial metadata could be tightened later.
4. **Key persistence — mitigated in 3.0.** The gateway signing key can be **persisted** via `AGA_GATEWAY_KEY` (64-hex seed) or `AGA_GATEWAY_KEY_FILE` (`DEPLOYMENT.md` §2), so `gateway_public_key` is stable and **pinnable across restarts**. The default remains an ephemeral key (warned on stderr). HSM/KMS backing remains future work. A verifier MUST still pin the key it expects.
5. **Storage durability (Sprint 5).** Default storage is in-memory → the live chain is lost on **process restart**. The cryptographic record survives via the **exported signed bundle**; durable cross-restart retention needs the SQLite/persistent backend (Sprint 5). The raw quarantine forensic buffer is in-memory by design (only the `arguments_hash` commitment is signed — privacy-preserving and sufficient to *prove* a capture).
6. **Out of scope entirely (not what AGA does).** AGA does not prevent: model jailbreaks, model-weight theft, credential compromise, or infrastructure compromise. It provides *accountability and provenance* for governed decisions, not prevention of those classes. If an attacker holds the gateway signing key, they can author receipts — protect the key (Sprint 4).
7. **Verifier-UX / unpinned consumers (NEW — CP3 A5).** A consumer that verifies a bundle **without pinning** the gateway key gets an integrity-only `VERIFIED` with `issuerVerified=false` — *even on a forged, attacker-signed, denial-free bundle*. This is correct (integrity-of-present-receipts ≠ provenance, and the result object/CLI say so explicitly), but a UI that shows a bare "VERIFIED" without prominently propagating `issuerVerified=false` could mislead a non-expert. → Downstream consumers (esp. the website demo) MUST pin the gateway key and never present an unpinned PASS as proof of *who* issued the bundle. **Mitigated in 3.0:** the verify result now carries a prominent `summary` — `VERIFIED (provenance verified …)` vs `VERIFIED (integrity only — NOT provenance …)` — surfaced by `verify_bundle_offline` and the reference/`aga-verify` CLIs; key-pinning ergonomics are in `DEPLOYMENT.md` §2. Consumers must still pin.
8. **Cross-stack verifier conformance (CLOSED — 2026-06-07).** Earlier in the 3.0 hardening only `src/sep/verify.ts` carried the full strict floor; the reference `verify-sep.mjs`, the published `aga-verify`, Go, and Python lagged. **That asymmetry is now closed.** All six verifiers — engine (`src/sep`), reference (`verify-sep.mjs`), `aga-verify`, Go (`verify.go`), and Python (audited library + pure-stdlib) — apply the identical strict floor and return **byte-identical verdicts**. The shared floor: strict field allowlist; `envelope_consistency` (binds the unsigned `gateway_id`/`merkle_root`/`generated_at` to the signed/recomputed values); checkpoint-algorithm binding; lexicographic-string canonicalization with RFC-8785 integral-number normalization; complete small-order/non-canonical-key rejection; **one library-free canonical-timestamp rule** (exact `.sssZ` UTC form via an ASCII regex + integer-arithmetic calendar + lexicographic ordering — no native date parser); merkle-direction-token strictness (`left`/`right` only, length-matched); unpaired-UTF-16-surrogate rejection; depth-bounded never-throw; and whole-document parse (trailing content rejected). Verified by `npm run conformance:cross-stack` — six verifiers agree on every case in the committed corpus (57 cases incl. raw-byte/file-parse, incl. an uppercase-Merkle-sibling cross-stack case), confirmed across multiple rounds of independent blind differential re-audit. See `fixtures/cross-stack/README.md`. **Residual (by design, not a divergence):** the bundle envelope still carries four *unsigned* metadata fields with no signed counterpart — `bundle_id`, `schema_version`, `policy_reference`, `offline_capable`. They are informational and are **not** security-identity fields (the identity fields `gateway_id`/`merkle_root`/`generated_at` ARE bound); a relying party must still trust only signed/verified values and pin the gateway key (§3.7). Of the four, **`policy_reference` is the only identity-grade one** — but the governing policy IS captured and cryptographically verified inside **every signed receipt's own `policy_reference` field** (one of the 15 signed fields), so the unsigned *envelope* `policy_reference` is only a convenience mirror, not the source of truth. Binding the envelope copy is a recommended near-term (3.1) format revision; a coordinated verifier-output flag that marks these four envelope fields as unsigned/not-verified is a recommended enhancement, deliberately deferred here to avoid adding an untested cross-language output surface immediately after the cross-stack-consistency campaign (the verdict surface already attests only the steps it runs, and never claims these fields). One further residual is **unreachable by construction:** SEP signed fields are strings plus the single integer `leaf_count` (the emit guard `assertSignedReceiptFieldsAreStrings` forbids any other number in a signed field), so a verifier's canonicalization of a *non-integer / exponential* number placed in a signed field — which no conformant gateway can emit — is intentionally left unspecified and MAY differ across language stdlibs; it cannot affect any bundle a conformant gateway produces. Reachable string content is fully cross-stack-consistent (an exhaustive 0..0x10FFFF code-point sweep confirms the only ever-divergent characters, `U+2028`/`U+2029`, are normalized identically by every verifier).

---

## 4. CP3 adversarial verification results (2026-06-06)

A focused adversarial workflow ran **7 independent red-team attacks** on the core claim. Each was attempted *concretely* against the real in-process MCP server / proxy and the **pinned** reference verifier (`verify-sep.mjs`) and published-sound `aga-verify@2.0.0`. A1–A5 were fully adjudicated + agreed in the original workflow. **A6 and A7 — whose original adjudication hit a session usage cap — were re-adjudicated first-hand on 2026-06-07 from the source:** **A6 HELD** — `src/middleware/governance.ts` shows `UNGOVERNED_TOOLS` contains only read/bootstrap/evidence/monitor tools (no mutating agent-action), a tool is GOVERNED iff absent from that set, and every GOVERNED call that is blocked emits a signed DENIED receipt via the `deny()` path (including the fail-closed branch for uncanonicalizable arguments); **A7 RESIDUAL** — the only upstream-reach bypasses are exactly the documented §3.1 (direct upstream HTTP, a deployment/network-isolation property) and §3.2 (non-`tools/call` methods, now recorded as signed passthrough receipts); no new bypass was found. (Red-team scripts are maintained in the private validation tree, not shipped in this package.)

| # | Attack | Result | Why |
|---|---|---|---|
| A1 | Tamper a DENIED receipt (19 mutations) | **HELD** | every mutation FAILED; signature + leaf-recompute + signed checkpoint each reject |
| A2 | Truncate (drop the DENIED receipt) | **HELD** | signed checkpoint binds `leaf_count`/head → truncated set fails `signed_checkpoint` |
| A3 | Reorder to bury the denial | **HELD** | `previous_receipt_hash` chain + checkpoint fail |
| A4 | Re-attest to erase | **HELD** | SEP ledger is not reset on `attest_subject`; the denial is still present in the export |
| A5 | Key-forge (attacker re-signs a denial-free bundle) | **HELD** | pinned to the real key → FAIL `gateway_key_match` on **both** verifiers; unpinned → integrity-only PASS with `issuerVerified=false` (by design; see §3.7) |
| A6 | PEP bypass (ungoverned mutating action) | **HELD** | all 15 tools censused; no ungoverned mutating agent-action; even blocked governed calls emit a DENIED receipt; `measure_behavior` enforcement is coupled to a signed receipt |
| A7 | Proxy bypass | **RESIDUAL** | every governed `tools/call` gets a receipt (PERMITTED+DENIED; DENIED never reaches upstream); the two bypasses are the already-documented §3.1 (direct upstream reach) and §3.2 (non-`tools/call` methods) |

**Verdict: 0 guarantee-broken — 6 HELD, 1 RESIDUAL (out-of-claim, already documented).** The core claim — *denials cannot be silently erased by the agent through tampering, truncation, reordering, or re-attestation, and forgery is caught when the gateway key is pinned* — **holds under the tested adversarial pressure**, on both the reference verifier and the published-sound `aga-verify@2.0.0`.

---

## 5. Net boundary statement (for public copy)

> Every governed decision produces a signed, chained, checkpoint-bound receipt; denials cannot be silently erased by the agent through tampering, truncation, reordering, or re-attestation, and are independently verifiable offline with provenance. The behavioral monitor is detective-only by default. Mandatory mediation (network isolation), cross-session key persistence, and cross-restart durability are deployment/roadmap properties, documented above. AGA proves *what was governed*; it does not claim to prevent jailbreaks, key theft, or non-`tools/call` side channels.
