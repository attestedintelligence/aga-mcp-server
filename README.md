# @attested-intelligence/aga-mcp-server

MCP server implementing the Attested Governance Artifact (AGA) protocol.

**Patent Pending:** USPTO Application No. 19/433,835
**Referenced in:** NIST-2025-0035, NCCoE AI Agent Identity and Authorization

## What It Does

This server acts as a **Portal** (enforcement boundary) for AI agents. Every tool call is attested, measured, and logged to a tamper-evident continuity chain.

| MCP Tool | Patent Claim | Description |
|---|---|---|
| `attest_subject` | 1a-1d | Attest and seal a policy artifact |
| `measure_integrity` | 1e-1g | Measure, compare, enforce, receipt |
| `revoke_artifact` | NCCoE 3b | Mid-session artifact revocation |
| `request_claim` | 2 | Privacy-preserving disclosure |
| `init_chain` | 3a | Initialize continuity chain |
| `verify_chain` | 3c | Verify chain integrity |
| `create_checkpoint` | 3d-3f | Merkle tree + anchor |
| `generate_evidence_bundle` | 9 | Offline-verifiable package |
| `get_portal_state` | — | Current enforcement status |
| `get_receipts` | — | Signed measurement receipts |
| `get_chain_events` | — | Continuity chain events |

## Quick Start

npm install && npm run build && npm run demo

## Connect to Claude Desktop

Add to ~/Library/Application Support/Claude/claude_desktop_config.json:
{
  "mcpServers": {
    "aga": { "command": "node", "args": ["/path/to/dist/index.js"] }
  }
}

## License
MIT — NeuroCrypt / Attested Intelligence Holdings LLC
