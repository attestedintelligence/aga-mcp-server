import { describe, it, expect } from 'vitest';
import { Portal } from '../../src/core/portal.js';
import { generateArtifact } from '../../src/core/artifact.js';
import { performAttestation } from '../../src/core/attestation.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';
import { generateKeyPair, pkToHex } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';

describe('portal', () => {
  const kp = generateKeyPair();
  const content = 'print("hello")'; const meta = { filename: 'app.py', version: '1.0' };
  const subId = computeSubjectIdFromString(content, meta);
  const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('pol'), evidence_items: [] });
  function mk(ttl = 3600) {
    return generateArtifact({ subject_identifier: subId, policy_reference: sha256Str('pol'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: { measurement_cadence_ms: 1000, ttl_seconds: ttl, enforcement_triggers: ['QUARANTINE'], re_attestation_required: false, measurement_types: ['FILE_SYSTEM_STATE'] },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] }, evidence_commitments: [], issuer_keypair: kp });
  }
  const enc = new TextEncoder();

  it('loads → ACTIVE_MONITORING', () => { const p = new Portal(); expect(p.loadArtifact(mk(), pkToHex(kp.publicKey)).ok).toBe(true); expect(p.state).toBe('ACTIVE_MONITORING'); });
  it('rejects bad key', () => { const p = new Portal(); expect(p.loadArtifact(mk(), pkToHex(generateKeyPair().publicKey)).ok).toBe(false); expect(p.state).toBe('TERMINATED'); });
  it('match unchanged', () => { const p = new Portal(); p.loadArtifact(mk(), pkToHex(kp.publicKey)); const r = p.measure(enc.encode(content), meta); expect(r.match).toBe(true); expect(r.ttl_ok).toBe(true); });
  it('drift on tamper', () => { const p = new Portal(); p.loadArtifact(mk(), pkToHex(kp.publicKey)); expect(p.measure(enc.encode('BAD'), meta).match).toBe(false); expect(p.state).toBe('DRIFT_DETECTED'); });
  it('QUARANTINE', () => { const p = new Portal(); p.loadArtifact(mk(), pkToHex(kp.publicKey)); p.measure(enc.encode('x'), meta); p.enforce('QUARANTINE'); expect(p.state).toBe('PHANTOM_QUARANTINE'); });
  it('TERMINATE', () => { const p = new Portal(); p.loadArtifact(mk(), pkToHex(kp.publicKey)); p.measure(enc.encode('x'), meta); p.enforce('TERMINATE'); expect(p.state).toBe('TERMINATED'); });
  it('ALERT_ONLY resumes', () => { const p = new Portal(); p.loadArtifact(mk(), pkToHex(kp.publicKey)); p.measure(enc.encode('x'), meta); p.enforce('ALERT_ONLY'); expect(p.state).toBe('ACTIVE_MONITORING'); });
  it('TTL expiry → SAFE_STATE (graceful degradation)', () => { const p = new Portal(); p.loadArtifact(mk(0), pkToHex(kp.publicKey)); const r = p.measure(enc.encode(content), meta); expect(r.ttl_ok).toBe(false); expect(r.degraded).toBe(true); expect(p.state).toBe('SAFE_STATE'); expect(p.degradationLog).toHaveLength(1); expect(p.degradationLog[0].reason).toBe('TTL_EXPIRED'); });
  it('SAFE_STATE allows continued measurement (continued logging)', () => { const p = new Portal(); p.loadArtifact(mk(0), pkToHex(kp.publicKey)); p.measure(enc.encode(content), meta); expect(p.state).toBe('SAFE_STATE'); const r2 = p.measure(enc.encode(content), meta); expect(r2.degraded).toBe(true); expect(p.degradationLog).toHaveLength(2); });
  it('revoke → TERMINATED', () => { const p = new Portal(); const a = mk(); p.loadArtifact(a, pkToHex(kp.publicKey)); p.revoke(a.sealed_hash); expect(p.state).toBe('TERMINATED'); });
  it('revocation checked on measure', () => { const p = new Portal(); const a = mk(); p.loadArtifact(a, pkToHex(kp.publicKey)); p.revocations.add(a.sealed_hash); p.state = 'ACTIVE_MONITORING'; expect(p.measure(enc.encode(content), meta).revoked).toBe(true); expect(p.state).toBe('TERMINATED'); });
});
