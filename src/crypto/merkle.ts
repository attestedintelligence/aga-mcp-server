import { sha256Str } from './hash.js';
import type { HashHex, MerkleInclusionProof } from './types.js';

function pair(l: HashHex, r: HashHex): HashHex { return sha256Str(l + r); }

export function buildMerkleTree(leaves: HashHex[]): { root: HashHex; layers: HashHex[][] } {
  if (!leaves.length) throw new Error('Empty leaf set');
  if (leaves.length === 1) return { root: leaves[0], layers: [leaves] };
  const layers: HashHex[][] = [[...leaves]];
  let cur = leaves;
  while (cur.length > 1) {
    const next: HashHex[] = [];
    for (let i = 0; i < cur.length; i += 2) {
      next.push(pair(cur[i], i + 1 < cur.length ? cur[i + 1] : cur[i]));
    }
    layers.push(next);
    cur = next;
  }
  return { root: cur[0], layers };
}

export function inclusionProof(leaves: HashHex[], idx: number): MerkleInclusionProof {
  if (idx < 0 || idx >= leaves.length) throw new RangeError(`Index ${idx} out of [0,${leaves.length})`);
  const { root, layers } = buildMerkleTree(leaves);
  const siblings: MerkleInclusionProof['siblings'] = [];
  let ci = idx;
  for (let L = 0; L < layers.length - 1; L++) {
    const layer = layers[L];
    const isRight = ci % 2 === 1;
    const si = isRight ? ci - 1 : (ci + 1 < layer.length ? ci + 1 : ci);
    siblings.push({ hash: layer[si], position: isRight ? 'left' : 'right' });
    ci = Math.floor(ci / 2);
  }
  return { leafHash: leaves[idx], leafIndex: idx, siblings, root };
}

export function verifyProof(proof: MerkleInclusionProof): boolean {
  let h = proof.leafHash;
  for (const s of proof.siblings) {
    h = s.position === 'left' ? pair(s.hash, h) : pair(h, s.hash);
  }
  return h === proof.root;
}
