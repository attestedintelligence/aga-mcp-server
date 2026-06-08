/**
 * Validates THIS stack against the committed cross-stack vectors
 * (fixtures/cross-stack/vectors.json). The same vectors are the portable contract the
 * sibling stacks (reference verify-sep.mjs, Python, Go) must satisfy identically.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { verifySepBundle } from '../../src/sep/index.js';
import { canonicalize } from '../../src/sep/canonical.js';

const vectors = JSON.parse(
  readFileSync(new URL('../../fixtures/cross-stack/vectors.json', import.meta.url), 'utf8'),
);

describe('cross-stack vectors — canonicalization byte-identity', () => {
  for (const v of vectors.canonical) {
    it(v.desc, () => {
      expect(canonicalize(v.input)).toBe(v.canonical);
    });
  }
});

describe('cross-stack vectors — bundle verdicts', () => {
  it('valid bundle VERIFIES with provenance (pinned)', () => {
    const { bundle, pinned_public_key } = vectors.valid_bundle;
    const r = verifySepBundle(bundle, pinned_public_key);
    expect(r.verdict).toBe('VERIFIED');
    expect(r.issuerVerified).toBe(true);
  });

  for (const v of (vectors.valid_variants ?? [])) {
    it(`valid variant VERIFIES: ${v.desc}`, () => {
      const r = verifySepBundle(v.bundle, v.pinned_public_key);
      expect(r.verdict).toBe('VERIFIED');
      expect(r.issuerVerified).toBe(true);
    });
  }

  for (const a of vectors.adversarial) {
    it(`adversarial FAILS: ${a.desc}`, () => {
      const r = verifySepBundle(a.bundle, vectors.valid_bundle.pinned_public_key);
      expect(r.verdict).toBe('FAILED');
      expect(r.steps.find((s) => s.name === a.failing_step)?.ok).toBe(false);
    });
  }
});
