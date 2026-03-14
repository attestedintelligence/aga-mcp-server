# @attested-intelligence/aga-mcp-server v2.0.0

MCP server implementing the Attested Governance Artifact (AGA) protocol - cryptographic compliance enforcement for autonomous AI systems.

**Patent Pending:** USPTO Application No. 19/433,835
**Referenced in:** NIST-2025-0035, NCCoE AI Agent Identity and Authorization

## What It Does

This server acts as a **Portal** (zero-trust Policy Enforcement Point) for AI agents. Every tool call is attested, measured against a sealed cryptographic reference, and logged to a tamper-evident continuity chain with signed receipts.

**20 tools, 4 resources, 3 prompts, 159 tests**

## 20 MCP Tools

| # | Tool | NIST/Patent Ref | Description |
|---|------|-----------------|-------------|
| 1 | `aga_server_info` | - | Server identity, keys, portal state, framework alignment |
| 2 | `aga_init_chain` | Claim 3a | Initialize continuity chain with genesis event |
| 3 | `aga_create_artifact` | Claims 1a-1d | Attest subject, generate sealed Policy Artifact |
| 4 | `aga_measure_subject` | Claims 1e-1g | Measure subject, compare to sealed ref, generate receipt |
| 5 | `aga_verify_artifact` | Claim 10 | Verify artifact signature against issuer key |
| 6 | `aga_start_monitoring` | NIST-2025-0035 | Start/restart behavioral monitoring with baseline |
| 7 | `aga_get_portal_state` | - | Current portal enforcement state and TTL |
| 8 | `aga_trigger_measurement` | Claims 1e-1g | Trigger measurement with specific type |
| 9 | `aga_generate_receipt` | V3 Promise | Generate signed measurement receipt manually |
| 10 | `aga_export_bundle` | Claim 9 | Package artifact + receipts + Merkle proofs |
| 11 | `aga_verify_bundle` | Section J | 4-step offline bundle verification |
| 12 | `aga_disclose_claim` | Claim 2 | Privacy-preserving disclosure with auto-substitution |
| 13 | `aga_get_chain` | Claim 3c | Get chain events with optional integrity verification |
| 14 | `aga_quarantine_status` | Claim 5 | Quarantine state and forensic capture status |
| 15 | `aga_revoke_artifact` | NCCoE 3b | Mid-session artifact revocation |
| 16 | `aga_set_verification_tier` | - | Set verification tier (BRONZE/SILVER/GOLD) |
| 17 | `aga_demonstrate_lifecycle` | All | Full lifecycle: attest, measure, checkpoint, verify |
| 18 | `aga_measure_behavior` | NIST-2025-0035 | Behavioral drift detection (tool patterns) |
| 19 | `aga_delegate_to_subagent` | NCCoE | Constrained sub-agent delegation (scope only diminishes) |
| 20 | `aga_rotate_keys` | Claim 3 | Key rotation with chain event |

## 4 Resources

| Resource | URI | Description |
|----------|-----|-------------|
| Protocol Spec | `aga://specification/protocol-v2` | Full protocol specification with SPIFFE alignment |
| Sample Bundle | `aga://resources/sample-bundle` | Sample evidence bundle documentation |
| Crypto Primitives | `aga://resources/crypto-primitives` | Cryptographic primitives documentation |
| Patent Claims | `aga://resources/patent-claims` | 20 patent claims mapped to tools |

## 3 Prompts

| Prompt | Description |
|--------|-------------|
| `nccoe-demo` | 4-phase NCCoE lab demo with behavioral drift |
| `governance-report` | Session governance summary report |
| `drift-analysis` | Drift event analysis and remediation |

## Quick Start

```bash
npm install && npm run build && npm test
```

## Connect to Claude Desktop

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aga": { "command": "node", "args": ["C:/Users/neuro/AIH/aga-mcp-server/dist/index.js"] }
  }
}
```

## Architecture

```
MCP Client (Claude Desktop)
    │ JSON-RPC over stdio
    ▼
src/server.ts - 20 tools + 4 resources + 3 prompts
    │
    ├── src/tools/          20 individual tool handlers
    ├── src/core/           Protocol logic (artifact, chain, portal, etc.)
    ├── src/crypto/         Ed25519 + SHA-256 + Merkle + canonical JSON
    ├── src/middleware/     Zero-trust governance PEP
    ├── src/storage/        In-memory + optional SQLite
    ├── src/resources/      Protocol docs + patent claims
    └── src/prompts/        Demo + report + analysis prompts
```

## Test Coverage

| Suite | Tests | What |
|-------|-------|------|
| Crypto | 33 | SHA-256, Ed25519, Merkle, salt, canonical, keys |
| Core | 56 | Artifact, chain, portal, governance, behavioral, delegation, privacy, revocation, fail-closed |
| Tools | 25 | All 20 tool handlers |
| Integration | 38 | Bundle tamper, lifecycle, performance, NCCoE demo, crucible compatibility |
| **Total** | **159** | |

## License

MIT - Attested Intelligence Holdings LLC
