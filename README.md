# @attested-intelligence/aga-mcp-server v2.1.0

[![MCP Badge](https://lobehub.com/badge/mcp/attested-intelligence-aga-mcp-server)](https://lobehub.com/mcp/attested-intelligence-aga-mcp-server)

MCP server and governance proxy implementing the Attested Governance Artifact (AGA) protocol - cryptographic compliance enforcement for autonomous AI systems.

## What It Does

This server acts as a **Portal** (zero-trust Policy Enforcement Point) for AI agents. Every tool call is attested, measured against a sealed cryptographic reference, and logged to a tamper-evident continuity chain with signed receipts.

**20 tools, 3 resources, 3 prompts, governance proxy, 199 tests**

## Governance Proxy (New in v2.1.0)

Sits between any MCP client (OpenClaw, Claude Desktop, etc.) and any downstream MCP server. Intercepts every `tools/call`, evaluates it against a sealed policy, and produces Ed25519-signed receipts in the canonical Ed25519-SHA256-JCS format (compatible with the Python SDK, gateway, and browser verifier).

```
MCP Client --> AGA Proxy (:18800) --> Downstream MCP Server
                  |
                  +-- Policy evaluation
                  +-- Signed receipt per tool call
                  +-- Merkle tree + evidence bundle
```

### Proxy Quick Start

```bash
# Start with a downstream MCP server
npx tsx src/proxy/index.ts start --upstream "node server.js" --profile standard

# Policy profiles: permissive, standard, restrictive
npx tsx src/proxy/index.ts start --upstream-url http://localhost:3000 --profile restrictive

# Export evidence bundle (verifiable at attestedintelligence.com/verify)
npx tsx src/proxy/index.ts export --output bundle.json

# Verify a bundle
npx tsx src/proxy/index.ts verify bundle.json
```

### Proxy Features

- **Policy modes**: allowlist, denylist, audit_only
- **Rate limiting**: per-tool calls/minute with sliding window
- **Path constraints**: restrict file tools to allowed prefixes
- **Denied patterns**: block dangerous argument patterns
- **Receipt format**: Ed25519-SHA256-JCS (canonical across all AGA SDKs)
- **Evidence bundles**: verifiable at `attestedintelligence.com/verify`
- **Two-process boundary**: proxy holds all signing keys, client holds none

## 20 MCP Tools

| # | Tool | Description |
| --- | --- | --- |
| 1 | `aga_server_info` | Server identity, keys, portal state, framework alignment |
| 2 | `aga_init_chain` | Initialize continuity chain with genesis event |
| 3 | `aga_create_artifact` | Attest subject, generate sealed Policy Artifact |
| 4 | `aga_measure_subject` | Measure subject, compare to sealed ref, generate receipt |
| 5 | `aga_verify_artifact` | Verify artifact signature against issuer key |
| 6 | `aga_start_monitoring` | Start/restart behavioral monitoring with baseline |
| 7 | `aga_get_portal_state` | Current portal enforcement state and TTL |
| 8 | `aga_trigger_measurement` | Trigger measurement with specific type |
| 9 | `aga_generate_receipt` | Generate signed measurement receipt manually |
| 10 | `aga_export_bundle` | Package artifact + receipts + Merkle proofs |
| 11 | `aga_verify_bundle` | 4-step offline bundle verification |
| 12 | `aga_disclose_claim` | Privacy-preserving disclosure with auto-substitution |
| 13 | `aga_get_chain` | Get chain events with optional integrity verification |
| 14 | `aga_quarantine_status` | Quarantine state and forensic capture status |
| 15 | `aga_revoke_artifact` | Mid-session artifact revocation |
| 16 | `aga_set_verification_tier` | Set verification tier (BRONZE/SILVER/GOLD) |
| 17 | `aga_demonstrate_lifecycle` | Full lifecycle: attest, measure, checkpoint, verify |
| 18 | `aga_measure_behavior` | Behavioral drift detection (tool patterns) |
| 19 | `aga_delegate_to_subagent` | Constrained sub-agent delegation (scope only diminishes) |
| 20 | `aga_rotate_keys` | Key rotation with chain event |

## 3 Resources

| Resource | URI | Description |
| --- | --- | --- |
| Protocol Spec | `aga://specification/protocol-v2` | Full protocol specification with SPIFFE alignment |
| Sample Bundle | `aga://resources/sample-bundle` | Sample evidence bundle documentation |
| Crypto Primitives | `aga://resources/crypto-primitives` | Cryptographic primitives documentation |

## 3 Prompts

| Prompt | Description |
|--------|-------------|
| `nccoe-demo` | 4-phase NCCoE lab demo with behavioral drift |
| `governance-report` | Session governance summary report |
| `drift-analysis` | Drift event analysis and remediation |

## CoSAI MCP Security Threat Coverage

The AGA MCP Server addresses all 12 threat categories identified in the
[CoSAI MCP Security whitepaper](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md)
(Coalition for Secure AI / OASIS, January 2026).

| CoSAI Category | Threat Domain | AGA Governance Mechanism |
|---|---|---|
| T1: Improper Authentication | Identity & Access | Ed25519 artifact signatures, pinned issuer keys, TTL re-attestation, key rotation chain events |
| T2: Missing Access Control | Identity & Access | Portal as mandatory enforcement boundary, sealed constraints, delegation with scope diminishment |
| T3: Input Validation Failures | Input Handling | Runtime measurement against sealed reference, behavioral drift detection |
| T4: Data/Control Boundary Failures | Input Handling | Behavioral baseline (permitted tools, forbidden sequences, rate limits), phantom execution forensics |
| T5: Inadequate Data Protection | Data & Code | Salted commitments, privacy-preserving disclosure with substitution, inference risk prevention |
| T6: Missing Integrity Controls | Data & Code | Content-addressable hash binding, 10 measurement embodiments, continuous runtime verification |
| T7: Session/Transport Security | Network & Transport | TTL-based artifact expiration, fail-closed on expiry, mid-session revocation, Ed25519 signed receipts |
| T8: Network Isolation Failures | Network & Transport | Two-process architecture, agent holds no credentials, NETWORK_ISOLATE enforcement action |
| T9: Trust Boundary Failures | Trust & Design | Enforcement pre-committed by human authorities in sealed artifact, not delegated to LLM |
| T10: Resource Management | Trust & Design | Per-tool rate limits in behavioral baseline, configurable measurement cadence (10ms to 3600s) |
| T11: Supply Chain Failures | Operational | Content-addressable hashing at attestation, runtime hash comparison blocks modified components |
| T12: Insufficient Observability | Operational | Signed receipts, tamper-evident continuity chain, Merkle anchoring, offline evidence bundles |

Full mapping details available via the `aga://specification` resource.

## Quick Start

```bash
npm install && npm run build && npm test
```

## Connect to an MCP Client

Add to your MCP client config:

```json
{
  "mcpServers": {
    "aga": { "command": "node", "args": ["/path/to/aga-mcp-server/dist/index.js"] }
  }
}
```

## Architecture

```
MCP Client
    | JSON-RPC over stdio
    v
src/server.ts - 20 tools + 3 resources + 3 prompts
    |
    +-- src/tools/          20 individual tool handlers
    +-- src/core/           Protocol logic (artifact, chain, portal, etc.)
    +-- src/crypto/         Ed25519 + SHA-256 + Merkle + canonical JSON
    +-- src/middleware/     Zero-trust governance PEP
    +-- src/storage/        In-memory + optional SQLite
    +-- src/resources/      Protocol docs + crypto primitives
    +-- src/prompts/        Demo + report + analysis prompts
    +-- src/proxy/          Governance proxy (NEW in v2.1.0)
    +-- src/adapters/       OpenClaw config adapter
```

## Test Coverage

| Suite | Tests | What |
|-------|-------|------|
| Crypto | 33 | SHA-256, Ed25519, Merkle, salt, canonical, keys |
| Core | 56 | Artifact, chain, portal, governance, behavioral, delegation, privacy, revocation, fail-closed |
| Tools | 25 | All 20 tool handlers |
| Integration | 38 | Bundle tamper, lifecycle, performance, NCCoE demo, crucible compatibility |
| Proxy | 40 | Policy evaluator, round-trip, cross-verification, OpenClaw adapter |
| **Total** | **199** | |

## License

MIT - Attested Intelligence Holdings LLC
