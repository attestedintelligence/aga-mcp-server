/**
 * Bundle tamper tests - 5 tests.
 * Tamper resistance of evidence bundles.
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPair, pkToHex } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';
import { performAttestation } from '../../src/core/attestation.js';
import { generateArtifact, hashArtifact } from '../../src/core/artifact.js';
import { generateReceipt } from '../../src/core/receipt.js';
import { createGenesisEvent, appendEvent } from '../../src/core/chain.js';
import { createCheckpoint, eventInclusionProof } from '../../src/core/checkpoint.js';
import { generateBundle, verifyBundleOffline } from '../../src/core/bundle.js';

describe('bundle tamper resistance - 5 tests', () => {
  const issuerKP = generateKeyPair();
  const portalKP = generateKeyPair();
  const chainKP = generateKeyPair();

  function mkBundle() {
    const subId = computeSubjectIdFromString('code', { filename: 'a.py' });
    const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('p'), evidence_items: [] });
    const artifact = generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('p'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: { measurement_cadence_ms: 1000, ttl_seconds: 3600, enforcement_triggers: ['TERMINATE'], re_attestation_required: true, measurement_types: ['FILE_SYSTEM_STATE'] },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: [], issuer_keypair: issuerKP,
    });
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const e1 = appendEvent('POLICY_ISSUANCE', { ah: hashArtifact(artifact) }, genesis, chainKP);
    const receipt = generateReceipt({
      subjectId: subId, artifactRef: hashArtifact(artifact),
      currentHash: 'h', sealedHash: 'h', driftDetected: false,
      driftDescription: null, action: null, measurementType: 'FILE_SYSTEM_STATE',
      seq: 1, prevLeaf: null, portalKP,
    });
    const chain = [genesis, e1];
    const { checkpoint } = createCheckpoint(chain);
    const proof = eventInclusionProof(chain, e1.sequence_number);
    const bundle = generateBundle(artifact, [receipt], [proof], checkpoint, portalKP);
    return { bundle, artifact };
  }

  it('valid bundle passes all steps', () => {
    const { bundle } = mkBundle();
    const v = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
    expect(v.overall).toBe(true);
  });

  it('wrong issuer key fails step 1', () => {
    const { bundle } = mkBundle();
    const wrongKP = generateKeyPair();
    const v = verifyBundleOffline(bundle, pkToHex(wrongKP.publicKey));
    expect(v.step1_artifact_sig).toBe(false);
    expect(v.overall).toBe(false);
  });

  it('tampered artifact fails step 1', () => {
    const { bundle } = mkBundle();
    const tampered = { ...bundle, artifact: { ...bundle.artifact, policy_version: 99 } };
    const v = verifyBundleOffline(tampered, pkToHex(issuerKP.publicKey));
    expect(v.step1_artifact_sig).toBe(false);
  });

  it('tampered receipt fails step 2', () => {
    const { bundle } = mkBundle();
    const tampered = {
      ...bundle,
      receipts: bundle.receipts.map(r => ({ ...r, drift_detected: true })),
    };
    const v = verifyBundleOffline(tampered, pkToHex(issuerKP.publicKey));
    expect(v.step2_receipt_sigs).toBe(false);
  });

  it('tampered Merkle proof fails step 3', () => {
    const { bundle } = mkBundle();
    const tampered = {
      ...bundle,
      merkle_proofs: bundle.merkle_proofs.map(p => ({ ...p, leafHash: 'aaaa'.repeat(16) })),
    };
    const v = verifyBundleOffline(tampered, pkToHex(issuerKP.publicKey));
    expect(v.step3_merkle_proofs).toBe(false);
  });
});
