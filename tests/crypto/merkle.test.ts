import { describe, it, expect } from 'vitest';
import { buildMerkleTree, inclusionProof, verifyProof } from '../../src/crypto/merkle.js';
import { sha256Str } from '../../src/crypto/hash.js';

describe('Merkle tree', () => {
  const leaves = ['a','b','c','d'].map(sha256Str);
  it('root is hex', () => { expect(buildMerkleTree(leaves).root).toMatch(/^[0-9a-f]{64}$/); });
  it('single leaf = root', () => { expect(buildMerkleTree([leaves[0]]).root).toBe(leaves[0]); });
  it('proof verifies all leaves', () => {
    for (let i = 0; i < leaves.length; i++) expect(verifyProof(inclusionProof(leaves, i))).toBe(true);
  });
  it('tampered proof fails', () => {
    const p = inclusionProof(leaves, 0);
    p.leafHash = sha256Str('x');
    expect(verifyProof(p)).toBe(false);
  });
  it('odd leaf count', () => {
    const odd = ['a','b','c'].map(sha256Str);
    for (let i = 0; i < odd.length; i++) expect(verifyProof(inclusionProof(odd, i))).toBe(true);
  });
  it('throws on empty', () => { expect(() => buildMerkleTree([])).toThrow(); });
});
