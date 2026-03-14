/**
 * Privacy tests - 3 tests.
 * Disclosure, substitution, inference risk.
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '../../src/crypto/sign.js';
import { processDisclosure } from '../../src/core/disclosure.js';
import type { DisclosurePolicy } from '../../src/core/types.js';

describe('privacy - disclosure + substitution', () => {
  const kp = generateKeyPair();
  const policy: DisclosurePolicy = {
    claims_taxonomy: [
      { claim_id: 'identity.name', sensitivity: 'S3_HIGH', substitutes: ['identity.pseudonym', 'identity.org'], inference_risks: [], permitted_modes: ['PROOF_ONLY'] },
      { claim_id: 'identity.pseudonym', sensitivity: 'S2_MODERATE', substitutes: ['identity.org'], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN'] },
      { claim_id: 'identity.org', sensitivity: 'S1_LOW', substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL'] },
    ],
    substitution_rules: [],
  };
  const values = { 'identity.name': 'Alice', 'identity.pseudonym': 'AJ-7742', 'identity.org': 'AI Holdings' };

  it('permits PROOF_ONLY for S3_HIGH claim', () => {
    const r = processDisclosure(
      { requested_claim_id: 'identity.name', requester_id: 'test', mode: 'PROOF_ONLY', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );
    expect(r.permitted).toBe(true);
    expect(r.was_substituted).toBe(false);
    expect(r.disclosed_value).toBe(true); // PROOF_ONLY returns boolean
  });

  it('auto-substitutes S3_HIGH to S2_MODERATE on REVEAL_MIN', () => {
    const r = processDisclosure(
      { requested_claim_id: 'identity.name', requester_id: 'test', mode: 'REVEAL_MIN', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );
    expect(r.permitted).toBe(true);
    expect(r.was_substituted).toBe(true);
    expect(r.disclosed_claim_id).toBe('identity.pseudonym');
    expect(r.substitution_receipt).toBeTruthy();
  });

  it('permits REVEAL_FULL for S1_LOW claim', () => {
    const r = processDisclosure(
      { requested_claim_id: 'identity.org', requester_id: 'test', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );
    expect(r.permitted).toBe(true);
    expect(r.was_substituted).toBe(false);
    expect(r.disclosed_value).toBe('AI Holdings');
  });
});
