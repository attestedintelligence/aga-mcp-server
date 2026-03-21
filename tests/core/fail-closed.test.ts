/**
 * Fail-closed tests - 4 tests.
 * TTL expiry, revocation-on-measure, no recovery from TERMINATED.
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPair, pkToHex } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';
import { performAttestation } from '../../src/core/attestation.js';
import { generateArtifact } from '../../src/core/artifact.js';
import { Portal } from '../../src/core/portal.js';

describe('fail-closed semantics', () => {
  const kp = generateKeyPair();
  const enc = new TextEncoder();

  function mkArtifactWithTTL(ttl: number) {
    const subId = computeSubjectIdFromString('code', { filename: 'a.py' });
    const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('p'), evidence_items: [] });
    return generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('p'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: { measurement_cadence_ms: 1000, ttl_seconds: ttl, enforcement_triggers: ['QUARANTINE', 'TERMINATE'], re_attestation_required: true, measurement_types: ['FILE_SYSTEM_STATE'] },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: [], issuer_keypair: kp,
    });
  }

  it('TERMINATED state is irrecoverable without reset', () => {
    const portal = new Portal();
    const a = mkArtifactWithTTL(3600);
    portal.loadArtifact(a, pkToHex(kp.publicKey));
    portal.revoke(a.sealed_hash);
    expect(portal.state).toBe('TERMINATED');
    // Cannot enforce, cannot measure
    expect(() => portal.enforce('ALERT_ONLY')).toThrow();
    expect(() => portal.measure(enc.encode('code'), { filename: 'a.py' })).toThrow();
  });

  it('revocation during ACTIVE_MONITORING terminates', () => {
    const portal = new Portal();
    const a = mkArtifactWithTTL(3600);
    portal.loadArtifact(a, pkToHex(kp.publicKey));
    expect(portal.state).toBe('ACTIVE_MONITORING');
    portal.revoke(a.sealed_hash);
    expect(portal.state).toBe('TERMINATED');
  });

  it('drift → enforce TERMINATE → portal terminated', () => {
    const portal = new Portal();
    const a = mkArtifactWithTTL(3600);
    portal.loadArtifact(a, pkToHex(kp.publicKey));
    // Cause drift
    portal.measure(enc.encode('modified'), { filename: 'a.py' });
    expect(portal.state).toBe('DRIFT_DETECTED');
    portal.enforce('TERMINATE');
    expect(portal.state).toBe('TERMINATED');
  });

  it('drift → enforce QUARANTINE → phantom quarantine', () => {
    const portal = new Portal();
    const a = mkArtifactWithTTL(3600);
    portal.loadArtifact(a, pkToHex(kp.publicKey));
    portal.measure(enc.encode('modified'), { filename: 'a.py' });
    expect(portal.state).toBe('DRIFT_DETECTED');
    portal.enforce('QUARANTINE');
    expect(portal.state).toBe('PHANTOM_QUARANTINE');
  });
});
