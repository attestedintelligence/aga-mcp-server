/**
 * Sample Evidence Bundle: generates a real, cryptographically signed bundle.
 * Can be verified with aga_verify_bundle.
 */
import { generateKeyPair, pkToHex } from '../crypto/sign.js';
import { sha256Str } from '../crypto/hash.js';
import { computeSubjectIdFromString } from '../core/subject.js';
import { performAttestation } from '../core/attestation.js';
import { generateArtifact, hashArtifact } from '../core/artifact.js';
import { generateReceipt } from '../core/receipt.js';
import { createGenesisEvent, appendEvent } from '../core/chain.js';
import { createCheckpoint, eventInclusionProof } from '../core/checkpoint.js';
import { generateBundle, verifyBundleOffline } from '../core/bundle.js';

let cachedBundle: { bundle: string; issuerPkHex: string } | null = null;

export function generateSampleBundle(): { bundle: string; issuerPkHex: string } {
  if (cachedBundle) return cachedBundle;

  const issuerKP = generateKeyPair();
  const portalKP = generateKeyPair();
  const chainKP = generateKeyPair();

  const content = 'def sample_agent(): return task.execute()';
  const meta = { filename: 'sample_agent.py', version: '1.0.0' };
  const subId = computeSubjectIdFromString(content, meta);
  const policyRef = sha256Str('sample-policy');
  const att = performAttestation({ subject_identifier: subId, policy_reference: policyRef, evidence_items: [] });

  const artifact = generateArtifact({
    subject_identifier: subId, policy_reference: policyRef, policy_version: 1,
    sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
    enforcement_parameters: {
      measurement_cadence_ms: 1000, ttl_seconds: 3600,
      enforcement_triggers: ['QUARANTINE', 'TERMINATE'],
      re_attestation_required: true, measurement_types: ['EXECUTABLE_IMAGE'],
    },
    disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
    evidence_commitments: att.evidence_commitments, issuer_keypair: issuerKP,
  });

  const artRef = hashArtifact(artifact);
  const receipt = generateReceipt({
    subjectId: subId, artifactRef: artRef,
    currentHash: subId.bytes_hash, sealedHash: subId.bytes_hash,
    driftDetected: false, driftDescription: null, action: null,
    measurementType: 'EXECUTABLE_IMAGE', seq: 1, prevLeaf: null, portalKP,
  });

  const genesis = createGenesisEvent(chainKP, sha256Str('AGA-Spec'));
  const e1 = appendEvent('POLICY_ISSUANCE', { artifact_hash: artRef }, genesis, chainKP);
  const e2 = appendEvent('INTERACTION_RECEIPT', { receipt_id: receipt.receipt_id }, e1, chainKP);
  const chain = [genesis, e1, e2];
  const { checkpoint } = createCheckpoint(chain);
  const proof = eventInclusionProof(chain, e1.sequence_number);
  const bundle = generateBundle(artifact, [receipt], [proof], checkpoint, portalKP);

  cachedBundle = {
    bundle: JSON.stringify(bundle, null, 2),
    issuerPkHex: pkToHex(issuerKP.publicKey),
  };
  return cachedBundle;
}

export const SAMPLE_BUNDLE_URI = 'aga://sample-bundle';
