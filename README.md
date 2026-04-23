# AGA - Attested Governance Artifacts

Cryptographic runtime governance for AI agents and autonomous systems.

[![npm](https://img.shields.io/npm/v/@attested-intelligence/aga-mcp-server)](https://www.npmjs.com/package/@attested-intelligence/aga-mcp-server)
[![PyPI](https://img.shields.io/pypi/v/aga-governance)](https://pypi.org/project/aga-governance/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-355%2B-brightgreen)](https://github.com/attestedintelligence/aga-mcp-server)

```bash
# Try it now
pip install aga-governance
python -m aga demo
python -m aga verify demo-bundle.json
```

## What This Does

Every tool call an AI agent makes passes through the AGA gateway. Each call is evaluated against policy, and the decision (PERMITTED or DENIED) is recorded as a signed, hash-linked governance receipt. Receipts are collected into evidence bundles that any third party can verify offline using standard cryptography.

**Record. Prove. Verify.**

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

## MCP Tools (20)

| Category | Tools |
|----------|-------|
| **Identity** | `get_server_info`, `get_portal_state` |
| **Lifecycle** | `init_chain`, `attest_subject`, `revoke_artifact` |
| **Enforcement** | `measure_integrity`, `measure_behavior`, `verify_chain` |
| **Evidence** | `create_checkpoint`, `generate_evidence_bundle`, `verify_bundle_offline` |
| **Privacy** | `request_claim`, `list_claims` |
| **Delegation** | `delegate_to_subagent` |
| **Audit** | `get_receipts`, `get_chain_events` |

## Quick Start

### Verify an evidence bundle (3 commands)

```bash
pip install aga-governance
curl -s https://aga-mcp-gateway.attestedintelligence.workers.dev/bundle -o evidence-bundle.json
python -m aga verify evidence-bundle.json
```

### Or verify in your browser

Go to [attestedintelligence.com/verify](https://attestedintelligence.com/verify) and click "Run Verification." Zero installs required.

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
   |                          |                  [Verify Chain]
   |                          |                  [Verify Merkle Tree]
   |                          |                  [PASS / FAIL]
```

## MCP Governance Proxy

Run AGA as a transparent proxy between any MCP client and any MCP server. Every tool call gets evaluated against policy and produces a signed receipt.

```bash
# Start the proxy with an upstream MCP server
npx tsx src/proxy/index.ts start --upstream "npx -y @modelcontextprotocol/server-filesystem /tmp/test" --profile standard

# Export the evidence bundle
npx tsx src/proxy/index.ts export --output evidence.json

# Verify
npx tsx src/proxy/index.ts verify evidence.json
```

The proxy intercepts `tools/call` requests, evaluates them against a sealed policy artifact, and generates signed receipts. Permitted calls are forwarded to the downstream server. Denied calls return an MCP error. Every decision is hash-linked into a tamper-evident chain.

Three built-in policy profiles:
- **permissive** - log everything, block nothing (default)
- **standard** - rate limits + blocks destructive operations
- **restrictive** - explicit tool allowlist, all unknown tools denied

## Verification (5 steps)

1. **Algorithm Check** - Bundle declares Ed25519-SHA256-JCS, fail closed on anything else
2. **Receipt Signatures** - Ed25519 over RFC 8785 canonical JSON (signature field excluded)
3. **Chain Integrity** - Each receipt's `previous_receipt_hash` = SHA-256 of the preceding receipt
4. **Merkle Proofs** - Walk siblings/directions to root, compare against bundle root
5. **Bundle Consistency** - Proof count = receipt count, leaf hashes match receipt hashes

## Cryptographic Primitives

| Primitive | Purpose |
|-----------|---------|
| Ed25519 | Receipt signatures |
| SHA-256 | Hash chaining, Merkle trees, leaf computation |
| RFC 8785 (JCS) | Canonical JSON for deterministic signing |
| Merkle Trees | Binding all receipts to a single verifiable root |

## Live Gateway

The demo gateway is deployed on Cloudflare Workers:

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

355+ automated tests across TypeScript and Python:

- **TypeScript MCP Server:** 218 tests (vitest)
- **Python SDK:** 137 tests (pytest)
- **Cross-language test vectors:** 37 vectors across 9 categories

```bash
npm test                              # TypeScript tests
```

For the Python SDK, install `aga-governance` from PyPI: https://pypi.org/project/aga-governance/

## Project Structure

```
src/                   # Core protocol: artifacts, receipts, chain, Merkle, crypto, portal state machine
  core/                # Governance primitives (artifact, receipt, chain, portal, bundle)
  crypto/              # Ed25519, SHA-256, BLAKE2b, Merkle, JCS canonicalization
  proxy/               # MCP governance proxy (transparent interception + policy enforcement)
  tools/               # MCP tool handlers (20 tools)
  middleware/          # Zero-trust governance enforcement wrapper
independent-verifier/  # Standalone verifier with zero AGA imports
scenarios/             # Deployment scenarios (SCADA, drone, AI agent)
tests/                 # TypeScript test suite (218 tests)
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

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

[MIT](LICENSE)

---

Attested Intelligence Holdings LLC
