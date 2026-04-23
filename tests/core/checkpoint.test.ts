/**
 * Checkpoint Tests
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { buildMerkleTree, inclusionProof, verifyProof } from '../../src/crypto/merkle.js';
import { createGenesisEvent, appendEvent } from '../../src/core/chain.js';
import { createCheckpoint, eventInclusionProof } from '../../src/core/checkpoint.js';

describe('checkpoint', () => {
  const chainKP = generateKeyPair();

  it('Merkle tree over leaf hashes produces deterministic root', () => {
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const e1 = appendEvent('POLICY_ISSUANCE', { hash: 'abc' }, genesis, chainKP);
    const chain = [genesis, e1];

    const { checkpoint: cp1 } = createCheckpoint(chain);
    const { checkpoint: cp2 } = createCheckpoint(chain);

    // Same chain -> same merkle root (deterministic)
    // Note: timestamps in checkpoint differ, but merkle_root is deterministic
    expect(cp1.merkle_root).toBe(cp2.merkle_root);
    expect(cp1.merkle_root).toMatch(/^[0-9a-f]{64}$/);
  });

  it('Merkle inclusion proof for specific event verifies', () => {
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const e1 = appendEvent('POLICY_ISSUANCE', { hash: 'abc' }, genesis, chainKP);
    const e2 = appendEvent('INTERACTION_RECEIPT', { data: 'receipt1' }, e1, chainKP);
    const e3 = appendEvent('INTERACTION_RECEIPT', { data: 'receipt2' }, e2, chainKP);
    const chain = [genesis, e1, e2, e3];

    const proof = eventInclusionProof(chain, e2.sequence_number);
    expect(proof.leafHash).toBe(e2.leaf_hash);
    expect(verifyProof(proof)).toBe(true);
  });

  it('tampered Merkle proof fails verification', () => {
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const e1 = appendEvent('POLICY_ISSUANCE', { hash: 'abc' }, genesis, chainKP);
    const chain = [genesis, e1];

    const proof = eventInclusionProof(chain, e1.sequence_number);
    // Tamper with leaf hash
    const tampered = { ...proof, leafHash: sha256Str('tampered') };
    expect(verifyProof(tampered)).toBe(false);
  });

  it('anchor interface returns checkpoint reference', () => {
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const e1 = appendEvent('POLICY_ISSUANCE', { hash: 'abc' }, genesis, chainKP);
    const chain = [genesis, e1];

    const { checkpoint, payload } = createCheckpoint(chain, 'ethereum');
    expect(checkpoint.anchor_network).toBe('ethereum');
    expect(checkpoint.transaction_id).toContain('ethereum:');
    expect(checkpoint.batch_start_sequence).toBe(0);
    expect(checkpoint.batch_end_sequence).toBe(1);
    expect(payload.leaf_count).toBe(2);
  });
});
