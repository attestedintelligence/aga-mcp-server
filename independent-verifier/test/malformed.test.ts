import { describe, it, expect } from 'vitest';
import { verifyEvidenceBundle } from '../verify';

// The verifier must fail cleanly (return a result, never throw) on input that is
// not a canonical SEP evidence bundle — including the LEGACY artifact-shape and
// the receipt-spec example bundles. Regression guard for the crash the audit found.
describe('verifier robustness on malformed / wrong-format input', () => {
  const cases: Array<[string, string]> = [
    ['empty object', '{}'],
    ['null', 'null'],
    ['array', '[]'],
    ['non-JSON', 'not json {'],
    ['legacy artifact-shape bundle', JSON.stringify({
      artifact: { signature: 'x', issuer_identifier: 'y' }, receipts: [], public_key: 'z',
      merkle_proofs: [], checkpoint_reference: { merkle_root: 'r' },
    })],
    ['wrong algorithm', JSON.stringify({
      algorithm: 'BLAKE2b-XX', public_key: 'ea', receipts: [], merkle_proofs: [],
      checkpoint: { signature: 's', merkle_root: '', leaf_count: 0, head_leaf_hash: '' },
    })],
    ['missing checkpoint', JSON.stringify({
      algorithm: 'Ed25519-SHA256-JCS', public_key: 'ea', receipts: [], merkle_proofs: [],
    })],
  ];

  for (const [name, input] of cases) {
    it(`${name}: fails cleanly without throwing`, () => {
      const r = verifyEvidenceBundle(input);
      expect(r.verdict).toBe('FAILED');
      expect(Array.isArray(r.errors)).toBe(true);
      expect(r.errors.length).toBeGreaterThan(0);
    });
  }

  it('non-JSON reports a parse error', () => {
    expect(verifyEvidenceBundle('not json {').errors[0]).toMatch(/parse/i);
  });

  it('legacy artifact shape reports unrecognized format (not a crash)', () => {
    const r = verifyEvidenceBundle(JSON.stringify({ artifact: { signature: 'x', issuer_identifier: 'y' }, receipts: [] }));
    expect(r.errors[0]).toMatch(/unrecognized evidence-bundle format/);
  });
});
