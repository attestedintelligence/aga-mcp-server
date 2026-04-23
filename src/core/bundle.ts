import { signStr, sigToB64, b64ToSig, hexToPk, verifyStr, pkToHex } from '../crypto/sign.js';
import { verifyProof } from '../crypto/merkle.js';
import { canonicalize } from '../utils/canonical.js';
import type { KeyPair, MerkleInclusionProof } from '../crypto/types.js';
import type { EvidenceBundle, PolicyArtifact, SignedReceipt, CheckpointReference, VerificationTier } from './types.js';

/**
 * Generate an evidence bundle. Original signature preserved for backward compatibility.
 * Tiered bundle generation (CAISI §3b):
 *   BRONZE - artifact + receipts only (proofs omitted)
 *   SILVER - artifact + receipts + Merkle proofs
 *   GOLD   - artifact + receipts + Merkle proofs + anchor checkpoint reference
 */
export function generateBundle(artifact: PolicyArtifact, receipts: SignedReceipt[], proofs: MerkleInclusionProof[], checkpoint: CheckpointReference, kp: KeyPair, tier?: VerificationTier): EvidenceBundle {
  const effectiveTier = tier ?? 'GOLD';
  const bundleProofs = effectiveTier === 'BRONZE' ? [] : proofs;
  const bundleCheckpoint: CheckpointReference = effectiveTier === 'GOLD' ? checkpoint : {
    ...checkpoint,
    transaction_id: effectiveTier === 'BRONZE' ? '' : checkpoint.transaction_id,
    anchor_network: effectiveTier === 'BRONZE' ? '' : checkpoint.anchor_network,
  };
  const unsigned = { artifact, receipts, merkle_proofs: bundleProofs, checkpoint_reference: bundleCheckpoint, public_key: pkToHex(kp.publicKey), verification_tier: effectiveTier };
  return { ...unsigned, bundle_signature: sigToB64(signStr(canonicalize(unsigned), kp.secretKey)) };
}

export interface VerificationResult {
  step1_artifact_sig: boolean; step2_receipt_sigs: boolean;
  step3_merkle_proofs: boolean; step4_anchor: 'SKIPPED_OFFLINE' | boolean;
  overall: boolean; errors: string[];
}

export function verifyBundleOffline(bundle: EvidenceBundle, pinnedPkHex: string): VerificationResult {
  const errors: string[] = [];
  const { signature: aSig, ...aU } = bundle.artifact;
  const s1 = verifyStr(b64ToSig(aSig), canonicalize(aU), hexToPk(pinnedPkHex));
  if (!s1) errors.push('Artifact signature failed');
  let s2 = true;
  for (const r of bundle.receipts) {
    const { portal_signature, ...rU } = r;
    if (!verifyStr(b64ToSig(portal_signature), canonicalize(rU), hexToPk(bundle.public_key))) { s2 = false; errors.push(`Receipt ${r.receipt_id} sig failed`); }
  }
  let s3 = true;
  for (const p of bundle.merkle_proofs) { if (!verifyProof(p)) { s3 = false; errors.push(`Merkle proof failed leaf ${p.leafIndex}`); } }
  return { step1_artifact_sig: s1, step2_receipt_sigs: s2, step3_merkle_proofs: s3, step4_anchor: 'SKIPPED_OFFLINE', overall: s1 && s2 && s3, errors };
}
