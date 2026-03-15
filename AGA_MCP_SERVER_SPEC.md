# AGA MCP Server - Complete Implementation Specification

**Package:** `@attested-intelligence/aga-mcp-server@0.1.0`
**Repository:** https://github.com/attestedintelligence/aga-mcp-server

---

## 1. WHAT THIS IS

A reference implementation of the **Attested Governance Artifact (AGA)** protocol, built as an MCP (Model Context Protocol) server. The server acts as a cryptographic **Portal** — a zero-trust Policy Enforcement Point that sits between an AI agent and the systems it interacts with. Every operation is attested, measured against a sealed cryptographic reference, and logged to a tamper-evident continuity chain with signed receipts.

This codebase is:
- The working code behind two NIST public comments and a USPTO patent application
- A live MCP server any AI agent (Claude, GPT, etc.) can connect to via Claude Desktop or any MCP client
- Benchmarked at 3.7ms per measurement cycle (NIST target: <10ms)
- Fully tested with 63 tests across 11 test files

---

## 2. CODEBASE METRICS

| Metric | Value |
|---|---|
| TypeScript source files | 35 |
| Test files | 11 |
| Total tests | 63 (all passing) |
| MCP tools | 16 |
| Git commits | 5 |
| Git tags | 4 (v0.1.0, v0.2.0, v0.3.0, v0.4.0) |
| Benchmark | 3.74ms per measure+receipt cycle |
| Build | Zero TypeScript errors |
| Dependencies | @noble/ed25519, @noble/hashes, @modelcontextprotocol/sdk, uuid, zod |
| Node requirement | >= 20.0.0 |
| Module system | ESM only |

---

## 3. ARCHITECTURE

```
┌─────────────────────────────────────────────────────────┐
│                   MCP CLIENT (Claude Desktop)            │
└──────────────────────────┬──────────────────────────────┘
                           │ JSON-RPC over stdio
┌──────────────────────────▼──────────────────────────────┐
│                     src/index.ts                         │
│                  StdioServerTransport                    │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│                    src/server.ts                         │
│              McpServer + 16 Tool Handlers                │
│                                                          │
│  ┌─────────────────────────────────────────────────┐     │
│  │         src/middleware/governance.ts             │     │
│  │   Governance Wrapper (zero-trust PEP)           │     │
│  │   - Blocks governed tools when TERMINATED       │     │
│  │   - Captures forensic inputs during QUARANTINE  │     │
│  │   - Records behavioral invocations              │     │
│  └─────────────────────────────────────────────────┘     │
└───┬──────────┬───────────┬──────────┬───────────────────┘
    │          │           │          │
    ▼          ▼           ▼          ▼
src/core/   src/crypto/  src/storage/  src/utils/
```

### Directory Structure

```
aga-mcp-server/
├── src/
│   ├── crypto/              Cryptographic primitives
│   │   ├── types.ts           Type aliases (PublicKey, SecretKey, HashHex, etc.)
│   │   ├── hash.ts            SHA-256, BLAKE2b, sha256Cat, sha256HexCat
│   │   ├── sign.ts            Ed25519 sign/verify via @noble/ed25519
│   │   ├── salt.ts            128-bit salts, salted commitments
│   │   ├── merkle.ts          Merkle tree build, inclusion proofs
│   │   └── index.ts           Barrel export
│   │
│   ├── core/                Protocol logic
│   │   ├── types.ts           All interfaces (patent ref numerals annotated)
│   │   ├── subject.ts         Subject identity (bytes hash + metadata hash)
│   │   ├── attestation.ts     Sealed hash generation
│   │   ├── artifact.ts        Policy artifact generation + signature
│   │   ├── receipt.ts         Signed measurement receipts (every measurement)
│   │   ├── chain.ts           Continuity chain (leaf hash excludes payload)
│   │   ├── portal.ts          Portal state machine (6 states, fail-closed)
│   │   ├── quarantine.ts      Phantom execution (capture inputs, sever outputs)
│   │   ├── checkpoint.ts      Merkle checkpoints over chain events
│   │   ├── bundle.ts          Offline-verifiable evidence bundles
│   │   ├── disclosure.ts      Privacy-preserving claims + auto-substitution
│   │   ├── behavioral.ts      Behavioral drift detection (tool patterns)
│   │   ├── delegation.ts      Constrained sub-agent delegation
│   │   └── index.ts           Barrel export
│   │
│   ├── middleware/          Governance enforcement layer
│   │   ├── governance.ts      Zero-trust PEP wrapper for MCP tools
│   │   └── index.ts           Barrel export
│   │
│   ├── storage/             Persistence layer
│   │   ├── interface.ts       AGAStorage interface
│   │   ├── memory.ts          In-memory implementation (active)
│   │   ├── sqlite.ts          SQLite implementation (optional)
│   │   └── index.ts           Barrel export
│   │
│   ├── utils/               Shared utilities
│   │   ├── constants.ts       Protocol version constants
│   │   ├── canonical.ts       Deterministic JSON serialization
│   │   ├── timestamp.ts       Time utilities (TTL, expiry)
│   │   └── uuid.ts            UUID v4 wrapper
│   │
│   ├── server.ts            MCP server factory (16 tools)
│   └── index.ts             Entry point (stdio transport)
│
├── tests/
│   ├── crypto/              22 tests (hash, sign, salt, merkle)
│   ├── core/                39 tests (artifact, chain, portal, governance,
│   │                                  behavioral, delegation)
│   └── integration/         2 tests (full NCCoE lab scenario)
│
├── scripts/
│   ├── demo.ts              Full lifecycle console demo
│   ├── benchmark.ts         Performance benchmark (NIST <10ms)
│   └── generate-keypair.ts  Ed25519 keypair generation
│
├── config/
│   ├── claude-desktop-config.json        Template
│   └── claude-desktop-config-local.json  Resolved absolute path
│
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── LICENSE                  MIT — Attested Intelligence Holdings LLC
├── README.md
├── PATENT_MAPPING.md        Claim-to-code mapping + NIST alignment
└── .npmignore
```

---

## 4. THE 16 MCP TOOLS

### Ungoverned (always available)

| # | Tool | Patent Ref | Description |
|---|---|---|---|
| 1 | `get_server_info` | — | Server version, public keys, portal state |
| 2 | `get_portal_state` | — | Current enforcement state, artifact info, TTL, quarantine status |
| 3 | `init_chain` | Claim 3a | Initialize continuity chain with genesis event |
| 4 | `attest_subject` | Claims 1a-1d | Hash content, attest, seal, generate signed artifact, load into portal. Accepts optional `behavioral_baseline` |
| 5 | `verify_chain` | Claim 3c | Verify chain integrity (leaf hashes, linkage, payload hashes) |
| 6 | `list_claims` | Claim 2 | List available claims with sensitivity levels |
| 7 | `measure_behavior` | NIST-2025-0035 | Measure behavioral patterns — unauthorized tools, rate violations, forbidden sequences |
| 8 | `get_receipts` | — | Get all signed receipts, filter by artifact |
| 9 | `get_chain_events` | — | Get continuity chain events, filter by sequence range |

### Governed (blocked when TERMINATED/QUARANTINED/UNATTESTED)

| # | Tool | Patent Ref | Description |
|---|---|---|---|
| 10 | `measure_integrity` | Claims 1e-1g | Measure content against sealed hash, enforce on drift, generate receipt |
| 11 | `revoke_artifact` | NCCoE 3b | Mid-session artifact revocation, pushes REVOCATION chain event |
| 12 | `create_checkpoint` | Claims 3d-3f | Build Merkle tree over chain events, produce checkpoint |
| 13 | `generate_evidence_bundle` | Claim 9 | Package artifact + receipts + Merkle proofs for offline verification |
| 14 | `verify_bundle_offline` | Section J | 4-step offline verification (artifact sig, receipt sigs, Merkle proofs, anchor) |
| 15 | `request_claim` | Claim 2 | Privacy-preserving disclosure with sensitivity-based auto-substitution |
| 16 | `delegate_to_subagent` | NCCoE | Derive constrained artifact for sub-agent (scope only diminishes) |

### Governance Behavior

When a governed tool is called:

| Portal State | Behavior |
|---|---|
| `INITIALIZATION` | Blocked — "Call attest_subject first" |
| `ARTIFACT_VERIFICATION` | Blocked — attestation in progress |
| `ACTIVE_MONITORING` | Allowed — invocation recorded for behavioral analysis |
| `DRIFT_DETECTED` | Allowed — enforcement may follow |
| `PHANTOM_QUARANTINE` | Blocked — tool call captured as forensic input, outputs severed |
| `TERMINATED` | Blocked — "Agent governance has been revoked" |

---

## 5. CRYPTOGRAPHIC DESIGN

### 5.1 Key Algorithms

| Operation | Algorithm | Library |
|---|---|---|
| Hashing | SHA-256 | @noble/hashes |
| Signing | Ed25519 | @noble/ed25519 |
| Salts | 128-bit (16 bytes) CSPRNG | @noble/hashes/utils |
| Merkle trees | SHA-256 binary tree | Custom (src/crypto/merkle.ts) |
| Canonical serialization | Sorted-key JSON.stringify | Custom (src/utils/canonical.ts) |

### 5.2 Sealed Hash (Patent Core)

```
sealed_hash = SHA-256(bytes_hash || metadata_hash || policy_reference || seal_salt)
```

- No delimiters between fields — raw hex concatenation via `sha256HexCat()`
- `bytes_hash` = SHA-256 of subject content bytes
- `metadata_hash` = SHA-256 of canonicalized metadata JSON
- `seal_salt` = 128-bit random salt (32 hex chars), stored in artifact

### 5.3 Leaf Hash (Claim 3c — Privacy Innovation)

```
leaf_hash = SHA-256(
  sequence_number || "||" ||
  event_type || "||" ||
  event_id || "||" ||
  timestamp || "||" ||
  prev_leaf_hash || "||" ||
  payload_hash
)
```

**The actual payload is EXCLUDED from the leaf hash.** This is the key patent innovation (Claim 3c) — chain integrity can be verified without revealing the contents of any event. Only a hash of the payload is included, preserving privacy while maintaining tamper evidence.

### 5.4 Salted Commitments

Evidence items are committed via:
```
commitment = SHA-256(content_bytes || salt_bytes)
```

The salt allows selective disclosure: reveal the salt to prove the commitment, keep it secret to maintain privacy.

### 5.5 Artifact Signature

```
signature = Ed25519.sign(canonicalize(unsigned_artifact), issuer_secret_key)
```

Where `canonicalize()` = sorted-key JSON.stringify with no whitespace. The signature covers every field of the artifact except the signature itself.

### 5.6 Receipt Signature

```
signature = Ed25519.sign(canonicalize(unsigned_receipt), portal_secret_key)
```

V3 behavior: a signed receipt is generated for **every** measurement — match or mismatch. This fulfills the NIST filing promise: "each measurement generates a signed receipt."

### 5.7 Merkle Tree

- Binary tree over event leaf hashes
- Odd leaf count: last leaf is duplicated
- Internal nodes: `SHA-256(left || right)` (hex concatenation)
- Inclusion proofs: array of `{ hash, direction }` pairs
- Verification: reconstruct root from leaf + proof, compare to checkpoint root

---

## 6. PORTAL STATE MACHINE

```
                    loadArtifact()
INITIALIZATION ──────────────────► ARTIFACT_VERIFICATION
                                          │
                              sig OK?  ───┤
                              time OK?    │
                              revoked? ───┤
                                          │
                                   ┌──────▼──────┐
                                   │    ACTIVE    │◄──── ALERT_ONLY
                                   │  MONITORING  │      (resumes)
                                   └──────┬──────┘
                                          │
                                    drift detected
                                          │
                                   ┌──────▼──────┐
                                   │    DRIFT     │
                                   │  DETECTED    │
                                   └──┬───┬───┬──┘
                                      │   │   │
                            QUARANTINE│   │   │TERMINATE/SAFE_STATE
                                      │   │   │
                              ┌───────▼┐  │  ┌▼──────────┐
                              │PHANTOM │  │  │TERMINATED  │
                              │QUARANT.│  │  │(fail-closed│
                              └───┬────┘  │  │no recovery)│
                                  │       │  └────────────┘
                                  │       │
                                  ▼       │
                             TERMINATED◄──┘
```

### Fail-Closed Semantics

On **every** call to `Portal.measure()`:
1. Check TTL — if expired → `TERMINATED` immediately
2. Check revocation — if revoked → `TERMINATED` immediately
3. Compare hashes — if mismatch → `DRIFT_DETECTED`

There is no recovery from `TERMINATED`. The agent must be re-attested.

---

## 7. BEHAVIORAL DRIFT DETECTION

Binary hashing detects file modification but NOT prompt injection — the binary is unchanged while behavior is compromised. The `BehavioralMonitor` tracks tool invocation patterns:

### Violation Types

| Type | Detection |
|---|---|
| `UNAUTHORIZED_TOOL` | Agent calls a tool not in the permitted list |
| `RATE_EXCEEDED` | Tool invoked more times than allowed in the measurement window |
| `FORBIDDEN_SEQUENCE` | Prohibited tool chain detected (e.g., `read_secret` → `send_email`) |

### Integration

- Every governed tool invocation is recorded by the governance middleware
- `measure_behavior` tool returns violations + behavioral hash (pattern fingerprint)
- Behavioral drift events are appended to the continuity chain
- Behavioral baseline can be sealed into the artifact via `attest_subject`

---

## 8. CONSTRAINED SUB-AGENT DELEGATION

NCCoE filing: "Scope can only diminish through delegation, never expand."

```
Primary Agent (TTL=3600s, triggers=[QUARANTINE, TERMINATE, SAFE_STATE])
    │
    ├── delegate_to_subagent(TTL=1800, triggers=[QUARANTINE])
    │   └── Child Artifact: TTL=1800, triggers=[QUARANTINE]
    │       - TTL clamped to parent remaining
    │       - Triggers ⊆ parent triggers
    │       - Measurement types ⊆ parent types
    │       - Disclosure policy inherited (cannot expand)
    │
    └── delegate_to_subagent(TTL=9999, triggers=[KEY_REVOKE])
        └── REJECTED: Cannot expand scope
```

### Enforcement Rules

1. Child TTL = `min(requested_ttl, parent_remaining_ttl)`
2. Child enforcement triggers must be a subset of parent's
3. Child measurement types must be a subset of parent's
4. Child disclosure policy = parent's (inherited, cannot expand)
5. `DELEGATION` event appended to parent's continuity chain
6. `validateDelegation()` provides independent scope verification

---

## 9. CONTINUITY CHAIN

An append-only chain of `ContinuityEvent` objects:

### Event Types

| Type | When Created |
|---|---|
| `GENESIS` | Chain initialization (`init_chain` or auto-init) |
| `POLICY_ISSUANCE` | Artifact created (`attest_subject`) |
| `INTERACTION_RECEIPT` | Measurement taken (`measure_integrity`) or behavioral drift |
| `REVOCATION` | Artifact revoked (`revoke_artifact`) |
| `ATTESTATION` | Delegation event (`delegate_to_subagent`) |
| `ANCHOR_BATCH` | Checkpoint created (`create_checkpoint`) |
| `DISCLOSURE` | Claim disclosed (`request_claim`) |
| `SUBSTITUTION` | Auto-substitution triggered (`request_claim`) |
| `KEY_ROTATION` | Key rotation (reserved) |

### Chain Integrity Verification

`verifyChainIntegrity()` checks:
1. Genesis event at sequence 0
2. Each event's `leaf_hash` matches recomputed leaf hash
3. Each event's `prev_leaf_hash` matches previous event's `leaf_hash`
4. Each event's `payload_hash` matches recomputed payload hash

---

## 10. OFFLINE EVIDENCE BUNDLES

4-step offline verification (`verifyBundleOffline`):

| Step | What It Checks | Current Status |
|---|---|---|
| Step 1 | Artifact signature (Ed25519) | Implemented — PASS |
| Step 2 | Receipt signatures (Ed25519) | Implemented — PASS |
| Step 3 | Merkle inclusion proofs | Implemented — PASS |
| Step 4 | Anchor validation (blockchain) | Returns `SKIPPED_OFFLINE` — no chain integration yet |

---

## 11. PRIVACY-PRESERVING DISCLOSURE

Claims have sensitivity levels:
- **S1_LOW** — can be revealed fully
- **S2_MODERATE** — can be revealed minimally or proved
- **S3_HIGH** — proof only, auto-substitutes to lower-sensitivity claim

Example: requesting `identity.name` (S3_HIGH) with mode `REVEAL_FULL` triggers auto-substitution to `identity.pseudonym` (S2_MODERATE) or `identity.org` (S1_LOW).

Substitution receipts are appended to the continuity chain for audit.

---

## 12. STORAGE

### Interface (`AGAStorage`)

```typescript
interface AGAStorage {
  initialize(): Promise<void>;
  storeArtifact(a: PolicyArtifact): Promise<void>;
  getLatestArtifact(): Promise<PolicyArtifact | null>;
  storeEvent(e: ContinuityEvent): Promise<void>;
  getLatestEvent(): Promise<ContinuityEvent | null>;
  getAllEvents(): Promise<ContinuityEvent[]>;
  getEvents(start: number, end: number): Promise<ContinuityEvent[]>;
  storeReceipt(r: SignedReceipt): Promise<void>;
  getReceiptsByArtifact(hash: string): Promise<SignedReceipt[]>;
  getAllReceipts(): Promise<SignedReceipt[]>;
  storeCheckpoint(c: CheckpointReference): Promise<void>;
  getLatestCheckpoint(): Promise<CheckpointReference | null>;
}
```

### Implementations

| Implementation | Status | Notes |
|---|---|---|
| `MemoryStorage` | Active | In-memory Maps/arrays, sufficient for all use cases |
| `SQLiteStorage` | Optional | Requires `better-sqlite3` + VS Build Tools. WAL mode, 4 tables. Gracefully unavailable on current machine. |

---

## 13. TEST COVERAGE

| Test File | Tests | What It Covers |
|---|---|---|
| `crypto/hash.test.ts` | 5 | SHA-256 determinism, hex format, ordering, hexcat |
| `crypto/sign.test.ts` | 7 | Ed25519 keypair, sign/verify bytes+string, tamper/wrong-key rejection, base64+hex roundtrips |
| `crypto/salt.test.ts` | 4 | Salt format (32 hex), uniqueness, commitment verification |
| `crypto/merkle.test.ts` | 6 | Root format, single leaf, proof verification, tamper detection, odd count, empty rejection |
| `core/artifact.test.ts` | 4 | Signature verification, tamper rejection, seal_salt storage |
| `core/chain.test.ts` | 7 | Genesis sequence, increment, intact chain, tampered leaf/payload, **leaf excludes payload (Claim 3c)**, REVOCATION event |
| `core/portal.test.ts` | 10 | Load, bad key rejection, match, drift, QUARANTINE, TERMINATE, ALERT_ONLY, TTL expiry, revoke, revocation-on-measure |
| `core/governance.test.ts` | 5 | TERMINATED blocks, ungoverned always allowed, QUARANTINE captures forensic, pre-attestation blocks, ACTIVE allows |
| `core/behavioral.test.ts` | 5 | Compliant behavior, unauthorized tool, rate exceeded, forbidden sequence, behavioral hash uniqueness |
| `core/delegation.test.ts` | 8 | Reduced scope, TTL clamping, scope expansion rejection (triggers + types), child signature valid, validateDelegation pass/fail, scope reduction tracking |
| `integration/nccoe-lab-demo.test.ts` | 2 | Full NCCoE lab scenario: attestation → clean measurements → drift → quarantine → revocation → chain verification → checkpoint → evidence bundle → offline verification |
| **Total** | **63** | |

---

## 14. PATENT CLAIM MAPPING

| Claim | Implementation | Source File | Function/Class |
|---|---|---|---|
| 1(a) receive subject | `attest_subject` | core/subject.ts | `computeSubjectIdFromString()` |
| 1(b) generate identifier | `attest_subject` | core/subject.ts | `computeSubjectId()` |
| 1(c) perform attestation | `attest_subject` | core/attestation.ts | `performAttestation()` |
| 1(d) generate artifact | `attest_subject` | core/artifact.ts | `generateArtifact()` |
| 1(e) portal + measurement | `measure_integrity` | core/portal.ts | `Portal.measure()` |
| 1(f) compare to sealed | `measure_integrity` | core/portal.ts | `Portal.measure()` |
| 1(g) enforce + receipt | `measure_integrity` | core/receipt.ts | `generateReceipt()` |
| 2 disclosure | `request_claim` | core/disclosure.ts | `processDisclosure()` |
| 3(a) genesis | `init_chain` | core/chain.ts | `createGenesisEvent()` |
| 3(b) append events | auto (every tool) | core/chain.ts | `appendEvent()` |
| 3(c) leaf hash (no payload) | `verify_chain` | core/chain.ts | `computeLeafHash()` |
| 3(d-f) checkpoint | `create_checkpoint` | core/checkpoint.ts | `createCheckpoint()` |
| 5 quarantine | `measure_integrity` | core/quarantine.ts | `initQuarantine()` |
| 6 TTL expiration | `measure_integrity` | core/portal.ts | `Portal.measure()` |
| 9 evidence bundle | `generate_evidence_bundle` | core/bundle.ts | `generateBundle()` |
| 10 pinned key | portal load | core/portal.ts | `Portal.loadArtifact()` |
| 11 phantom execution | `measure_integrity` | core/quarantine.ts | `captureInput()` |
| 12 graceful degradation | `measure_integrity` | core/portal.ts | TTL + fail-closed |

### NIST Filing Alignment

| NIST Promise | Implementation | Status |
|---|---|---|
| "each measurement generates a signed receipt" | `measure_integrity` generates receipt for match AND mismatch | DONE |
| "fail-closed semantics" | Portal checks TTL + revocation on every measurement | DONE |
| "mid-session revocation" (NCCoE 3b) | `revoke_artifact` tool + REVOCATION chain event | DONE |
| "phantom execution" | `QUARANTINE` enforcement → forensic capture buffer | DONE |
| "offline verification" | `generate_evidence_bundle` + `verify_bundle_offline` | DONE |
| "graduated enforcement" | TERMINATE / QUARANTINE / SAFE_STATE / ALERT_ONLY | DONE |
| "portal intercepts MCP tool invocations" | Governance middleware wraps all governed tools | DONE |
| "semantic drift without binary modification" | BehavioralMonitor tracks tool patterns | DONE |
| "constrained sub-mandates" | `delegate_to_subagent` + scope-only-diminishes | DONE |
| "sub-10ms per tool invocation" | 3.74ms per measure+receipt cycle | DONE |

---

## 15. VERSION HISTORY

| Tag | Commit | What Changed |
|---|---|---|
| `v0.1.0` | `62394ed` | Initial reference implementation — 45 files, 45 tests, all patent claims |
| (v0.1.1) | `1093631` | Hardening — .npmignore, LICENSE, keypair gen, benchmark, Claude Desktop config |
| `v0.2.0` | `897b2f7` | Governance middleware — portal as zero-trust PEP. 50 tests |
| `v0.3.0` | `bc48a28` | Behavioral drift detection — tool pattern monitoring. 55 tests |
| `v0.4.0` | `8f77321` | Constrained sub-agent delegation — scope only diminishes. 63 tests |

---

## 16. WHAT HAS BEEN ESTABLISHED

### Infrastructure
- [x] Git repository initialized with clean commit history
- [x] GitHub public repo at `attestedintelligence/aga-mcp-server`
- [x] 4 version tags pushed (v0.1.0 through v0.4.0)
- [x] Claude Desktop config generated with absolute path
- [x] MIT License (Attested Intelligence Holdings LLC)
- [x] .npmignore for clean npm packaging

### Protocol Implementation
- [x] Complete Ed25519 + SHA-256 cryptographic layer
- [x] Sealed hash generation with salted commitments
- [x] Policy artifact generation with issuer signature
- [x] Portal state machine with fail-closed semantics
- [x] Continuity chain with privacy-preserving leaf hashes (Claim 3c)
- [x] Merkle checkpoint anchoring
- [x] Offline-verifiable evidence bundles (4-step)
- [x] Privacy-preserving disclosure with auto-substitution
- [x] Phantom execution / quarantine with forensic capture
- [x] Mid-session revocation (NCCoE Phase 3b)
- [x] Receipt generation for every measurement (match or mismatch)

### v0.2.0+ Features
- [x] Governance middleware — portal as true zero-trust PEP
- [x] Behavioral drift detection — unauthorized tools, rate limits, forbidden sequences
- [x] Constrained sub-agent delegation — scope only diminishes through delegation

### Verification
- [x] 63 tests all passing
- [x] NCCoE lab demo scenario verified end-to-end
- [x] Benchmark: 3.74ms per cycle (NIST target <10ms)
- [x] TypeScript strict mode, zero build errors

---

## 17. WHAT'S NEXT

### Immediate (Requires User Action)

| Item | Action | Why |
|---|---|---|
| **npm publish** | Run `npm login` then `npm publish --access public` in terminal | Creates immutable npm registry timestamp for patent prosecution. Requires interactive 2FA. |
| **Claude Desktop smoke test** | Copy `config/claude-desktop-config-local.json` to `%APPDATA%\Claude\claude_desktop_config.json`, restart Claude Desktop, run test sequence | Proves the MCP server works as a live tool for AI agents |

### Near-Term Development

| Priority | Feature | NIST/Patent Ref | Description |
|---|---|---|---|
| HIGH | Arweave Anchoring | Patent Section I | Replace `SKIPPED_OFFLINE` stub with real blockchain anchoring. POST Merkle root to Arweave, store transaction IDs, enable Step 4 of offline verification. |
| HIGH | SPIFFE/SPIRE Integration | NCCoE filing | SPIRE handles workload-to-node identity (SVID), AGA handles workload-to-intent governance. Integration point: SVID provides transport identity, AGA binds governance. |
| MEDIUM | Multi-Agent Chain Linking | NCCoE filing | Child agent's genesis event links to parent's chain. Cross-chain verification for delegation audit trails. |
| MEDIUM | Persistent Storage | — | Install VS Build Tools, enable SQLiteStorage for durable state across server restarts. |
| LOW | WebSocket Transport | — | Add HTTP/SSE/WebSocket transport in addition to stdio for remote MCP clients. |
| LOW | CI/CD Pipeline | — | GitHub Actions for automated test + build + publish on tag push. |

### Architecture Evolution

```
Current (v0.4.0):
  Single MCP server ← single agent

Next (v0.5.0+):
  Primary MCP server ← primary agent
    ├── Derived portal ← sub-agent A (constrained)
    ├── Derived portal ← sub-agent B (constrained)
    └── Arweave anchor ← immutable timestamp proof

Future (v1.0.0):
  Federation of portals with cross-chain verification
  SPIFFE/SPIRE transport identity binding
  Real-time behavioral anomaly scoring
  Hardware attestation integration (TPM/SGX)
```

---

## 18. HOW TO RUN

### Build + Test + Demo
```bash
cd C:\aga-mcp-server
npm run build          # TypeScript compilation
npm test               # 63 tests
npm run demo           # Full NCCoE lab scenario output
npm run benchmark      # Performance benchmark
```

### Connect to Claude Desktop
1. Build: `npm run build`
2. Copy config:
   - From: `config/claude-desktop-config-local.json`
   - To: `%APPDATA%\Claude\claude_desktop_config.json`
3. Restart Claude Desktop
4. Test: "Use the AGA server. Call get_server_info."

### Generate Keypair
```bash
npx tsx scripts/generate-keypair.ts
```

---

## 19. KEY DESIGN DECISIONS

| Decision | Rationale |
|---|---|
| SHA-256 over BLAKE2b for primary hashing | Broader hardware support, NIST standard, sufficient for this use case |
| Leaf hash excludes payload | Patent innovation (Claim 3c) — enables chain verification without revealing event contents |
| Receipt for every measurement | NIST filing promise — creates complete audit trail regardless of outcome |
| Fail-closed on TTL/revocation | Security principle — expired or revoked artifacts must never be honored |
| ESM only, no require() | Forward-compatible, matches @noble library requirements |
| Server.ts monolith for tools | Simpler for reference implementation; refactor path documented in src/tools/README.md |
| MemoryStorage as default | Sufficient for MCP server lifecycle (state is session-scoped); SQLite available when build tools are installed |
| Governance middleware as wrapper | Non-invasive — existing tool handlers unchanged, enforcement added as a layer |
| Behavioral monitor in middleware | Natural interception point — every governed tool call passes through anyway |

---
