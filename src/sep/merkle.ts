/**
 * SEP Merkle tree — CANONICAL_CONSTRUCTION_v2.md §5.
 * Node = sha256(rawbytes(L) ‖ rawbytes(R)) — RAW 32-byte concatenation (NOT hex-string concat).
 * Odd node is PROMOTED (carried up unchanged), NOT duplicated.
 */
import { createHash } from 'node:crypto';

export function nodeHash(leftHex: string, rightHex: string): string {
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from(leftHex, 'hex'), Buffer.from(rightHex, 'hex')]))
    .digest('hex');
}

export interface MerkleProof {
  leaf_hash: string;
  leaf_index: number;
  siblings: string[];
  directions: Array<'left' | 'right'>;
  merkle_root: string;
}

export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return '';
  let level = [...leaves];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]); // promote odd
    }
    level = next;
  }
  return level[0];
}

export function merkleProof(leaves: string[], leafIndex: number): MerkleProof {
  const siblings: string[] = [];
  const directions: Array<'left' | 'right'> = [];
  let level = [...leaves];
  let idx = leafIndex;
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    }
    if (idx % 2 === 0) {
      if (idx + 1 < level.length) { siblings.push(level[idx + 1]); directions.push('right'); }
      // else: promoted node, no sibling at this level
    } else {
      siblings.push(level[idx - 1]); directions.push('left');
    }
    idx = Math.floor(idx / 2);
    level = next;
  }
  return { leaf_hash: leaves[leafIndex], leaf_index: leafIndex, siblings, directions, merkle_root: level[0] };
}

/** Build every proof from shared levels, hashing each internal node only once.
 * Proof material still occupies O(n log n) space in the returned export.
 * The existing single-proof API and odd-node promotion rule are unchanged.
 */
export function merkleProofs(leaves: readonly string[]): MerkleProof[] {
  if (leaves.length === 0) return [];
  const levels: string[][] = [[...leaves]];
  while (levels[levels.length - 1].length > 1) {
    const level = levels[levels.length - 1];
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    }
    levels.push(next);
  }
  const root = levels[levels.length - 1][0];
  return leaves.map((leaf, leafIndex) => {
    const siblings: string[] = [];
    const directions: Array<'left' | 'right'> = [];
    let index = leafIndex;
    for (let depth = 0; depth < levels.length - 1; depth++) {
      const level = levels[depth];
      if (index % 2 === 1) {
        siblings.push(level[index - 1]);
        directions.push('left');
      } else if (index + 1 < level.length) {
        siblings.push(level[index + 1]);
        directions.push('right');
      }
      index = Math.floor(index / 2);
    }
    return { leaf_hash: leaf, leaf_index: leafIndex, siblings, directions, merkle_root: root };
  });
}
