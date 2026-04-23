# Contributing to AGA

Thank you for your interest in contributing to Attested Governance Artifacts.

## Development Setup

```bash
git clone https://github.com/attestedintelligence/aga-mcp-server.git
cd aga-mcp-server
npm install
npm test
```

### Prerequisites

- Node.js 20+
- npm 9+

### Running Tests

```bash
npm test                    # Run all tests
npm run test:coverage       # Coverage report
npm run test:watch          # Watch mode
```

### Project Structure

```
src/               # Core AGA implementation
independent-verifier/  # Standalone verification tool
scenarios/         # Deployment scenario implementations
tests/             # Test suite (94 tests)
scripts/           # Utility scripts
```

## Guidelines

### Code Style

- TypeScript strict mode
- No `any` types without explicit justification
- All public functions must include JSDoc comments
- Cryptographic operations must be deterministic and offline-capable

### Commit Messages

Use clear, descriptive commit messages:

```
Add Merkle checkpoint anchoring for continuity chain
Fix sealed hash computation for empty claim arrays
Update Evidence Bundle schema to v1.1
```

### Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Write tests for new functionality
4. Ensure all existing tests pass (`npm test`)
5. Submit a pull request with a clear description

### Testing Requirements

- All new features must include tests
- Cryptographic operations require both positive and negative test cases
- Evidence Bundle tests must verify offline verification capability
- Maintain or improve the existing test count

### Areas of Contribution

- Test coverage improvements
- Documentation clarification
- Scenario implementations for new deployment environments
- Performance optimizations (especially for O(1) receipt generation)
- Independent verifier enhancements

## Code of Conduct

Be professional. Be constructive. Focus on the technical merits. We are building critical infrastructure governance technology and take quality seriously.

## Questions

For questions about contributing, open a GitHub issue or email [admin@attestedintelligence.com](mailto:admin@attestedintelligence.com).

---

Attested Intelligence Holdings LLC
