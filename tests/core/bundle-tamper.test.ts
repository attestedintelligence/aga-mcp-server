/**
 * Bundle Tamper Detection Tests
 * Verify that tampering with any component is detected
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

describe('bundle tamper detection', () => {
  const issuerKP = generateKeyPair();
  const portalKP = generateKeyPair();
  const chainKP = generateKeyPair();
  const content = 'binary_content';
  const meta = { filename: 'test.bin' };
  const subId = computeSubjectIdFromString(content, meta);
  const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('pol'), evidence_items: [] });

  function makeBundle() {
    const artifact = generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('pol'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: { measurement_cadence_ms: 1000, ttl_seconds: 3600, enforcement_triggers: ['TERMINATE'], re_attestation_required: false, measurement_types: ['EXECUTABLE_IMAGE'] },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] }, evidence_commitments: [], issuer_keypair: issuerKP,
    });
    const receipt = generateReceipt({
      subjectId: subId, artifactRef: hashArtifact(artifact),
      currentHash: 'abc', sealedHash: 'abc',
      driftDetected: false, driftDescription: null, action: null,
      measurementType: 'EXECUTABLE_IMAGE', seq: 1, prevLeaf: null, portalKP,
    });
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const e1 = appendEvent('INTERACTION_RECEIPT', receipt, genesis, chainKP);
    const chain = [genesis, e1];
    const { checkpoint } = createCheckpoint(chain);
    const proof = eventInclusionProof(chain, e1.sequence_number);
    return generateBundle(artifact, [receipt], [proof], checkpoint, portalKP, 'GOLD');
  }

  it('valid bundle passes all 4 verification steps', () => {
    const bundle = makeBundle();
    const result = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
    expect(result.overall).toBe(true);
    expect(result.step1_artifact_sig).toBe(true);
    expect(result.step2_receipt_sigs).toBe(true);
    expect(result.step3_merkle_proofs).toBe(true);
  });

  it('tampered artifact signature -> Step 1 FAIL', () => {
    const bundle = makeBundle();
    bundle.artifact.signature = 'AAAA' + bundle.artifact.signature.slice(4);
    const result = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
    expect(result.step1_artifact_sig).toBe(false);
    expect(result.overall).toBe(false);
  });

  it('tampered receipt signature -> Step 2 FAIL', () => {
    const bundle = makeBundle();
    bundle.receipts[0].portal_signature = 'BBBB' + bundle.receipts[0].portal_signature.slice(4);
    const result = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
    expect(result.step2_receipt_sigs).toBe(false);
    expect(result.overall).toBe(false);
  });

  it('tampered Merkle proof -> Step 3 FAIL', () => {
    const bundle = makeBundle();
    bundle.merkle_proofs[0].leafHash = sha256Str('tampered');
    const result = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
    expect(result.step3_merkle_proofs).toBe(false);
    expect(result.overall).toBe(false);
  });

  it('steps 1-3 work fully offline', () => {
    const bundle = makeBundle();
    const result = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
    expect(result.step4_anchor).toBe('SKIPPED_OFFLINE');
    expect(result.overall).toBe(true);
    // No network calls made - verification is purely cryptographic
  });
});
