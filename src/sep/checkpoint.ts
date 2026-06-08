/**
 * Mandatory signed checkpoint — CANONICAL_CONSTRUCTION_v2.md §5.
 * Binds receipt count + chain head + merkle root to a gateway signature; this is what makes
 * the no-prefix leaf construction truncation-safe. `leaf_count` is intentionally numeric
 * (the reference verifier compares it numerically; small integers are RFC-8785-stable).
 */
import { canonicalize } from './canonical.js';
import type { SepSigner } from './crypto.js';
import { SEP_ALGORITHM, leafHash, type SepReceipt } from './receipt.js';
import { merkleRoot } from './merkle.js';

export interface SignedCheckpoint {
  algorithm: string;
  gateway_id: string;
  generated_at: string;
  head_leaf_hash: string;
  leaf_count: number;
  merkle_root: string;
  signature: string;
}

/** The EXACT canonical field set of a signed SEP checkpoint (strict-schema floor in the verifier). */
export const SEP_CHECKPOINT_FIELDS = [
  'algorithm', 'gateway_id', 'generated_at', 'head_leaf_hash', 'leaf_count', 'merkle_root', 'signature',
] as const;

export function buildCheckpoint(
  receipts: SepReceipt[],
  gatewayId: string,
  generatedAt: string,
  signer: SepSigner,
): SignedCheckpoint {
  if (receipts.length === 0) throw new Error('Cannot checkpoint an empty receipt set');
  const leaves = receipts.map(leafHash);
  const body = {
    algorithm: SEP_ALGORITHM,
    gateway_id: gatewayId,
    generated_at: generatedAt,
    head_leaf_hash: leaves[leaves.length - 1],
    leaf_count: receipts.length,
    merkle_root: merkleRoot(leaves),
  };
  return { ...body, signature: signer.sign(canonicalize(body)) };
}
