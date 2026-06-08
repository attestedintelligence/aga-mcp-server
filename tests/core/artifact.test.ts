import { describe, it, expect } from 'vitest';
import { generateArtifact, verifyArtifactSignature, hashArtifact } from '../../src/core/artifact.js';
import { performAttestation } from '../../src/core/attestation.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';
import { generateKeyPair, pkToHex } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';

describe('policy artifact', () => {
  const kp = generateKeyPair();
  const subId = computeSubjectIdFromString('bin', { filename: 't.bin' });
  const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('p'), evidence_items: [] });
  const mkI = () => ({
    subject_identifier: subId, policy_reference: sha256Str('p'), policy_version: 1,
    sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
    enforcement_parameters: { measurement_cadence_ms: 1000, ttl_seconds: 3600, enforcement_triggers: ['TERMINATE' as const], re_attestation_required: false, measurement_types: ['FILE_SYSTEM_STATE' as const] },
    disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
    evidence_commitments: att.evidence_commitments, issuer_keypair: kp,
  });
  it('has signature', () => { expect(generateArtifact(mkI()).signature).toBeTruthy(); });
  it('verifies', () => { expect(verifyArtifactSignature(generateArtifact(mkI()), pkToHex(kp.publicKey))).toBe(true); });
  it('rejects tampered', () => { const a = generateArtifact(mkI()); expect(verifyArtifactSignature({ ...a, policy_version: 99 }, pkToHex(kp.publicKey))).toBe(false); });
  it('stores seal_salt', () => { expect(generateArtifact(mkI()).seal_salt).toBe(att.seal_salt); });
});
