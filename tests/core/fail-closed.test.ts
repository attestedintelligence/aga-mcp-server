/**
 * Fail-Closed Tests - CAISI §4a
 * Block execution if ANY of 4 conditions is true
 */
import { describe, it, expect } from 'vitest';
import { Portal } from '../../src/core/portal.js';
import { generateArtifact } from '../../src/core/artifact.js';
import { performAttestation } from '../../src/core/attestation.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';
import { generateKeyPair, pkToHex, signStr, sigToB64 } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { canonicalize } from '../../src/utils/canonical.js';

describe('fail-closed semantics (CAISI §4a)', () => {
  const kp = generateKeyPair();
  const content = 'print("hello")';
  const meta = { filename: 'app.py', version: '1.0' };
  const subId = computeSubjectIdFromString(content, meta);
  const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('pol'), evidence_items: [] });
  const enc = new TextEncoder();

  function makeArtifact(ttl = 3600) {
    return generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('pol'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: { measurement_cadence_ms: 1000, ttl_seconds: ttl, enforcement_triggers: ['QUARANTINE'], re_attestation_required: false, measurement_types: ['EXECUTABLE_IMAGE'] },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] }, evidence_commitments: [], issuer_keypair: kp,
    });
  }

  it('fail-closed: invalid signature blocks execution - CAISI §4a condition 2', () => {
    const portal = new Portal();
    const wrongKP = generateKeyPair();
    const result = portal.loadArtifact(makeArtifact(), pkToHex(wrongKP.publicKey));
    expect(result.ok).toBe(false);
    expect(result.error).toContain('Signature');
    expect(portal.state).toBe('TERMINATED');
  });

  it('fail-closed: expired TTL blocks execution - CAISI §4a condition 3', () => {
    const portal = new Portal();
    const result = portal.loadArtifact(makeArtifact(0), pkToHex(kp.publicKey));
    // TTL=0 means immediately expired; loadArtifact checks effective period
    // The artifact is created with effective_timestamp=now and TTL=0
    // Since isWithinPeriod checks expiration_timestamp (null here), but TTL
    // is checked during measure, not load. Load checks effective period.
    // So we load and then measure to trigger TTL check.
    if (result.ok) {
      const m = portal.measure(enc.encode(content), meta);
      expect(m.ttl_ok).toBe(false);
      expect(portal.state).toBe('SAFE_STATE');
    } else {
      // If load rejected due to period check, that's also fail-closed
      expect(portal.state).toBe('TERMINATED');
    }
  });

  it('fail-closed: initial hash mismatch blocks execution - CAISI §4a condition 4', () => {
    const portal = new Portal();
    portal.loadArtifact(makeArtifact(), pkToHex(kp.publicKey));
    expect(portal.state).toBe('ACTIVE_MONITORING');

    // First measurement with wrong content
    const m = portal.measure(enc.encode('WRONG CONTENT'), meta);
    expect(m.match).toBe(false);
    expect(portal.state).toBe('DRIFT_DETECTED');
  });

  it('fail-closed: revoked artifact blocks execution - combined', () => {
    const portal = new Portal();
    const artifact = makeArtifact();
    portal.loadArtifact(artifact, pkToHex(kp.publicKey));
    portal.revoke(artifact.sealed_hash);
    expect(portal.state).toBe('TERMINATED');
  });
});
