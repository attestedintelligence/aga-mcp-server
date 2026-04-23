# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AGA, please report it responsibly.

**Email:** [admin@attestedintelligence.com](mailto:admin@attestedintelligence.com)

**Subject line:** `[SECURITY] AGA Vulnerability Report`

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if you have one)

### Response Timeline

- **Acknowledgment:** Within 48 hours of receipt
- **Initial assessment:** Within 5 business days
- **Resolution target:** Dependent on severity, typically within 30 days for critical issues

### Scope

This policy covers:

- The AGA reference implementation (`src/`, `independent-verifier/`)
- The MCP server (`@attested-intelligence/aga-mcp-server`)
- Cryptographic operations (signing, verification, hash computation, chain integrity)
- Evidence Bundle generation and verification

### Out of Scope

- The attestedintelligence.com website (report separately to the same email)
- Third-party dependencies (report to the upstream maintainer, but let us know)
- Social engineering or phishing attacks

### Cryptographic Considerations

AGA relies on Ed25519 signatures, SHA-256 hashing, BLAKE2b-256 fingerprinting, and Merkle tree anchoring. If you identify a weakness in how these primitives are applied (not the primitives themselves), that is a valid report.

Key areas of concern:

- Sealed hash computation correctness
- Receipt chain integrity (hash linking)
- Merkle checkpoint verification
- Key separation enforcement between Portal and agent
- Evidence Bundle completeness and tamper detection

### Disclosure

We follow coordinated disclosure. Please do not publicly disclose vulnerabilities until we have released a fix or 90 days have elapsed, whichever comes first.

We do not currently operate a bug bounty program.

---

Attested Intelligence Holdings LLC
