import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { verifyEvidenceBundle } from '../verify';
const fixture = readFileSync(new URL('../example-bundle.json', import.meta.url), 'utf8');
const key = JSON.parse(fixture).public_key as string;
describe('explicit expected issuer keys', () => {
  it.each(['', 'bad', key.toUpperCase()])('malformed expected key %s fails without silent downgrade', (pin) => {
    const r = verifyEvidenceBundle(fixture, pin);
    expect(r.verdict).toBe('FAILED'); expect(r.pinned).toBe(true); expect(r.issuerVerified).toBe(false);
  });
  it('the correct expected key passes and the absent key stays integrity-only', () => {
    expect(verifyEvidenceBundle(fixture, key).issuerVerified).toBe(true);
    expect(verifyEvidenceBundle(fixture).pinned).toBe(false);
  });
});
