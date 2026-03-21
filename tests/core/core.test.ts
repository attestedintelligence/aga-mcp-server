/**
 * Core protocol tests - 14 tests.
 * Artifact, receipt, chain, bundle, portal, measurement, identity.
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPair, pkToHex } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';
import { performAttestation } from '../../src/core/attestation.js';
import { generateArtifact, hashArtifact, verifyArtifactSignature } from '../../src/core/artifact.js';
import { generateReceipt } from '../../src/core/receipt.js';
import { createGenesisEvent, appendEvent, verifyChainIntegrity } from '../../src/core/chain.js';
import { Portal } from '../../src/core/portal.js';
import { generateBundle, verifyBundleOffline } from '../../src/core/bundle.js';
import { createCheckpoint, eventInclusionProof } from '../../src/core/checkpoint.js';
import { measureSubject, compareState } from '../../src/core/measurement.js';
import { keyFingerprint, rotateKeys } from '../../src/core/identity.js';

describe('core protocol - 14 tests', () => {
  const issuerKP = generateKeyPair();
  const portalKP = generateKeyPair();
  const chainKP = generateKeyPair();

  function mkArtifact() {
    const subId = computeSubjectIdFromString('test-code', { filename: 'test.py' });
    const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('policy'), evidence_items: [] });
    return generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('policy'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: {
        measurement_cadence_ms: 1000, ttl_seconds: 3600,
        enforcement_triggers: ['QUARANTINE', 'TERMINATE'],
        re_attestation_required: true, measurement_types: ['EXECUTABLE_IMAGE'],
      },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: att.evidence_commitments, issuer_keypair: issuerKP,
    });
  }

  // 1. Artifact generation and signature
  it('generates artifact with valid signature', () => {
    const a = mkArtifact();
    expect(verifyArtifactSignature(a, pkToHex(issuerKP.publicKey))).toBe(true);
  });

  // 2. Re-attestation produces new sealed hash
  it('re-attestation produces different sealed hash', () => {
    const a1 = mkArtifact();
    const a2 = mkArtifact();
    expect(a1.sealed_hash).not.toBe(a2.sealed_hash); // different salts
  });

  // 3. Receipt generation for match
  it('generates receipt for clean measurement', () => {
    const a = mkArtifact();
    const r = generateReceipt({
      subjectId: a.subject_identifier, artifactRef: hashArtifact(a),
      currentHash: 'abc', sealedHash: 'abc', driftDetected: false,
      driftDescription: null, action: null, measurementType: 'EXECUTABLE_IMAGE',
      seq: 1, prevLeaf: null, portalKP,
    });
    expect(r.drift_detected).toBe(false);
    expect(r.portal_signature).toBeTruthy();
  });

  // 4. Receipt generation for mismatch
  it('generates receipt for drift measurement', () => {
    const a = mkArtifact();
    const r = generateReceipt({
      subjectId: a.subject_identifier, artifactRef: hashArtifact(a),
      currentHash: 'abc', sealedHash: 'xyz', driftDetected: true,
      driftDescription: 'Hash mismatch', action: 'QUARANTINE', measurementType: 'EXECUTABLE_IMAGE',
      seq: 2, prevLeaf: null, portalKP,
    });
    expect(r.drift_detected).toBe(true);
    expect(r.enforcement_action).toBe('QUARANTINE');
  });

  // 5. Chain genesis + append
  it('creates chain with genesis and appended events', () => {
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const e1 = appendEvent('POLICY_ISSUANCE', { test: true }, genesis, chainKP);
    expect(e1.sequence_number).toBe(1);
    expect(e1.previous_leaf_hash).toBe(genesis.leaf_hash);
  });

  // 6. Chain integrity verification
  it('verifies intact chain', () => {
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const e1 = appendEvent('POLICY_ISSUANCE', { test: true }, genesis, chainKP);
    const e2 = appendEvent('INTERACTION_RECEIPT', { receipt: 'r1' }, e1, chainKP);
    expect(verifyChainIntegrity([genesis, e1, e2]).valid).toBe(true);
  });

  // 7. Chain detects tamper
  it('detects tampered chain event', () => {
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const e1 = appendEvent('POLICY_ISSUANCE', { test: true }, genesis, chainKP);
    const tampered = { ...e1, payload: { test: false } };
    expect(verifyChainIntegrity([genesis, tampered]).valid).toBe(false);
  });

  // 8. Bundle generation + offline verification
  it('generates bundle that passes 3-step offline verification', () => {
    const a = mkArtifact();
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const e1 = appendEvent('POLICY_ISSUANCE', { ah: hashArtifact(a) }, genesis, chainKP);
    const chain = [genesis, e1];
    const { checkpoint } = createCheckpoint(chain);
    const proof = eventInclusionProof(chain, e1.sequence_number);
    const bundle = generateBundle(a, [], [proof], checkpoint, portalKP);
    const v = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
    expect(v.step1_artifact_sig).toBe(true);
    expect(v.step3_merkle_proofs).toBe(true);
    expect(v.overall).toBe(true);
  });

  // 9. Portal state transitions
  it('portal transitions through states correctly', () => {
    const portal = new Portal();
    expect(portal.state).toBe('INITIALIZATION');
    const a = mkArtifact();
    portal.loadArtifact(a, pkToHex(issuerKP.publicKey));
    expect(portal.state).toBe('ACTIVE_MONITORING');
  });

  // 10. Portal drift detection
  it('portal detects drift on modified subject', () => {
    const portal = new Portal();
    const a = mkArtifact();
    portal.loadArtifact(a, pkToHex(issuerKP.publicKey));
    const result = portal.measure(new TextEncoder().encode('modified-code'), { filename: 'test.py' });
    expect(result.match).toBe(false);
    expect(portal.state).toBe('DRIFT_DETECTED');
  });

  // 11. measureSubject + compareState
  it('measureSubject matches for identical content', () => {
    const content = 'test-code';
    const meta = { filename: 'test.py' };
    const subId = computeSubjectIdFromString(content, meta);
    const measured = measureSubject({ subjectBytes: new TextEncoder().encode(content), metadata: meta });
    const comparison = compareState(measured, subId);
    expect(comparison.match).toBe(true);
  });

  // 12. measureSubject detects mismatch
  it('measureSubject detects mismatch for different content', () => {
    const subId = computeSubjectIdFromString('original', { filename: 't.py' });
    const measured = measureSubject({ subjectBytes: new TextEncoder().encode('modified'), metadata: { filename: 't.py' } });
    const comparison = compareState(measured, subId);
    expect(comparison.match).toBe(false);
    expect(comparison.bytesMatch).toBe(false);
  });

  // 13. keyFingerprint consistency
  it('keyFingerprint is deterministic for same key', () => {
    const kp = generateKeyPair();
    expect(keyFingerprint(kp.publicKey)).toBe(keyFingerprint(kp.publicKey));
  });

  // 14. rotateKeys produces new keypair
  it('rotateKeys produces different keypair', () => {
    const kp = generateKeyPair();
    const result = rotateKeys(kp);
    expect(result.newPublicKeyHex).not.toBe(result.oldPublicKeyHex);
    expect(result.rotatedAt).toBeTruthy();
  });
});
