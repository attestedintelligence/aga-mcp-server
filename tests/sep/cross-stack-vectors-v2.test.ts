/**
 * Validates THIS stack (the agile engine) against the committed v2 (ML-DSA-65+Ed25519 composite)
 * cross-stack vectors (fixtures/cross-stack/vectors-v2.json) and PINS the corpus by digest. The same
 * vectors are the portable contract the second independent-language oracle (CIRCL/Go) must satisfy
 * identically — proven by fixtures/cross-stack/run-v2-stacks.mjs. The construction is profile-
 * invariant, so every hardening fixture here must render the same verdict as its v1 twin.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { verifySepBundle } from '../../src/sep/index.js';
import { ALG_ED25519, ALG_HYBRID } from '../../src/sep/profiles.js';

const corpusUrl = new URL('../../fixtures/cross-stack/vectors-v2.json', import.meta.url);
const corpusText = readFileSync(corpusUrl, 'utf8');
const vectors = JSON.parse(corpusText);
const pinText = readFileSync(new URL('../../fixtures/cross-stack/vectors-v2.sha256', import.meta.url), 'utf8');

describe('cross-stack v2 vectors — corpus pin', () => {
  it('sha256(vectors-v2.json) matches vectors-v2.sha256 (tamper-evident corpus)', () => {
    const digest = createHash('sha256').update(Buffer.from(corpusText, 'utf8')).digest('hex');
    expect(pinText.trim().split(/\s+/)[0]).toBe(digest);
  });
  it('declares the v2 composite profile', () => {
    expect(vectors.algorithm).toBe(ALG_HYBRID);
    expect(vectors.profile_version).toBe(2);
  });
});

describe('cross-stack v2 vectors — bundle verdicts', () => {
  it('valid v2 bundle VERIFIES with provenance (pinned)', () => {
    const { bundle, pinned_public_key } = vectors.valid_bundle;
    const r = verifySepBundle(bundle, pinned_public_key);
    expect(r.verdict).toBe('VERIFIED');
    expect(r.issuerVerified).toBe(true);
  });

  for (const v of (vectors.valid_variants ?? [])) {
    it(`valid v2 variant VERIFIES: ${v.desc}`, () => {
      const r = verifySepBundle(v.bundle, v.pinned_public_key);
      expect(r.verdict).toBe('VERIFIED');
      expect(r.issuerVerified).toBe(true);
    });
  }

  for (const a of vectors.adversarial) {
    it(`v2 adversarial FAILS: ${a.desc}`, () => {
      const r = verifySepBundle(a.bundle, vectors.valid_bundle.pinned_public_key);
      expect(r.verdict).toBe('FAILED');
      expect(r.steps.find((s) => s.name === a.failing_step)?.ok).toBe(false);
    });
  }
});

describe('cross-stack v2 vectors — trichotomy', () => {
  it('the valid v2 bundle on a v1-only verifier returns UNSUPPORTED_PROFILE (not FAILED)', () => {
    const { bundle } = vectors.valid_bundle;
    const r = verifySepBundle(bundle, undefined, { supportedProfiles: [ALG_ED25519] });
    expect(r.verdict).toBe('UNSUPPORTED_PROFILE');
  });
});
