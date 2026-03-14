/**
 * Revocation tests - 3 tests.
 * Mid-session revocation, portal termination, re-attestation.
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPair, pkToHex } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';
import { performAttestation } from '../../src/core/attestation.js';
import { generateArtifact } from '../../src/core/artifact.js';
import { Portal } from '../../src/core/portal.js';

describe('revocation - mid-session artifact revocation', () => {
  const kp = generateKeyPair();
  function mkArtifact() {
    const subId = computeSubjectIdFromString('code', { filename: 'a.py' });
    const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('p'), evidence_items: [] });
    return generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('p'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: { measurement_cadence_ms: 1000, ttl_seconds: 3600, enforcement_triggers: ['TERMINATE'], re_attestation_required: true, measurement_types: ['FILE_SYSTEM_STATE'] },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: [], issuer_keypair: kp,
    });
  }

  it('revoke terminates portal immediately', () => {
    const portal = new Portal();
    const a = mkArtifact();
    portal.loadArtifact(a, pkToHex(kp.publicKey));
    expect(portal.state).toBe('ACTIVE_MONITORING');
    portal.revoke(a.sealed_hash);
    expect(portal.state).toBe('TERMINATED');
    expect(portal.isRevoked(a.sealed_hash)).toBe(true);
  });

  it('revoked artifact fails next measurement', () => {
    const portal = new Portal();
    const a = mkArtifact();
    portal.loadArtifact(a, pkToHex(kp.publicKey));
    portal.revoke(a.sealed_hash);
    expect(() => portal.measure(new TextEncoder().encode('code'), { filename: 'a.py' })).toThrow();
  });

  it('portal can be reset and re-attested after revocation', () => {
    const portal = new Portal();
    const a = mkArtifact();
    portal.loadArtifact(a, pkToHex(kp.publicKey));
    portal.revoke(a.sealed_hash);
    expect(portal.state).toBe('TERMINATED');
    portal.reset();
    expect(portal.state).toBe('INITIALIZATION');
    const a2 = mkArtifact();
    portal.loadArtifact(a2, pkToHex(kp.publicKey));
    expect(portal.state).toBe('ACTIVE_MONITORING');
  });
});
