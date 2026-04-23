import { describe, it, expect } from 'vitest';
import { generateKeyPair, pkToHex } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';
import { performAttestation } from '../../src/core/attestation.js';
import { generateArtifact } from '../../src/core/artifact.js';
import { generateReceipt } from '../../src/core/receipt.js';
import { createGenesisEvent, appendEvent } from '../../src/core/chain.js';
import { createCheckpoint, eventInclusionProof } from '../../src/core/checkpoint.js';
import { generateBundle, verifyBundleOffline } from '../../src/core/bundle.js';

describe('bundle verification tiers (CAISI §3b)', () => {
  const issuerKP = generateKeyPair();
  const portalKP = generateKeyPair();
  const chainKP = generateKeyPair();

  const content = 'print("hello")';
  const meta = { filename: 'app.py', version: '1.0' };
  const subId = computeSubjectIdFromString(content, meta);
  const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('pol'), evidence_items: [] });
  const artifact = generateArtifact({
    subject_identifier: subId, policy_reference: sha256Str('pol'), policy_version: 1,
    sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
    enforcement_parameters: { measurement_cadence_ms: 1000, ttl_seconds: 3600, enforcement_triggers: ['TERMINATE'], re_attestation_required: false, measurement_types: ['FILE_SYSTEM_STATE'] },
    disclosure_policy: { claims_taxonomy: [], substitution_rules: [] }, evidence_commitments: [], issuer_keypair: issuerKP,
  });

  const receipt = generateReceipt({
    subjectId: subId, artifactRef: sha256Str('ref'),
    currentHash: 'abc', sealedHash: 'abc',
    driftDetected: false, driftDescription: null, action: null,
    measurementType: 'FILE_SYSTEM_STATE', seq: 1, prevLeaf: null, portalKP,
  });

  const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
  const e1 = appendEvent('INTERACTION_RECEIPT', receipt, genesis, chainKP);
  const chain = [genesis, e1];
  const { checkpoint } = createCheckpoint(chain);
  const proof = eventInclusionProof(chain, e1.sequence_number);

  it('GOLD tier includes proofs and checkpoint', () => {
    const bundle = generateBundle(artifact, [receipt], [proof], checkpoint, portalKP, 'GOLD');
    expect(bundle.verification_tier).toBe('GOLD');
    expect(bundle.merkle_proofs).toHaveLength(1);
    expect(bundle.checkpoint_reference.transaction_id).toBeTruthy();
  });

  it('SILVER tier includes proofs but reduced checkpoint', () => {
    const bundle = generateBundle(artifact, [receipt], [proof], checkpoint, portalKP, 'SILVER');
    expect(bundle.verification_tier).toBe('SILVER');
    expect(bundle.merkle_proofs).toHaveLength(1);
  });

  it('BRONZE tier omits proofs', () => {
    const bundle = generateBundle(artifact, [receipt], [proof], checkpoint, portalKP, 'BRONZE');
    expect(bundle.verification_tier).toBe('BRONZE');
    expect(bundle.merkle_proofs).toHaveLength(0);
  });

  it('defaults to GOLD when tier omitted', () => {
    const bundle = generateBundle(artifact, [receipt], [proof], checkpoint, portalKP);
    expect(bundle.verification_tier).toBe('GOLD');
    expect(bundle.merkle_proofs).toHaveLength(1);
  });

  it('GOLD bundle verifies offline', () => {
    const bundle = generateBundle(artifact, [receipt], [proof], checkpoint, portalKP, 'GOLD');
    const result = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
    expect(result.overall).toBe(true);
  });
});
