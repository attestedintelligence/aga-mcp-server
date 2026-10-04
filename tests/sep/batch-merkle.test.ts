import { describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { merkleProof, merkleProofs, merkleRoot } from '../../src/sep/merkle.js';
import { SepGateway } from '../../src/sep/bundle.js';
import { leafHash } from '../../src/sep/receipt.js';
import { buildCheckpoint } from '../../src/sep/checkpoint.js';
import { signerFromSeed, type SepSigner } from '../../src/sep/crypto.js';
import { hybridSignerFromSeeds } from '../../src/sep/hybrid.js';
import { verifySepBundle } from '../../src/sep/verify.js';

const hashes = vi.hoisted(() => ({ count: 0 }));
vi.mock('node:crypto', async importOriginal => {
  const original = await importOriginal<typeof import('node:crypto')>();
  return {
    ...original,
    createHash: (...args: Parameters<typeof original.createHash>) => {
      hashes.count++;
      return original.createHash(...args);
    },
  };
});

function leaves(count: number): string[] {
  return Array.from({ length: count }, (_, i) => createHash('sha256').update(`synthetic-leaf-${i}`).digest('hex'));
}

describe('batch Merkle proof compatibility and work bound', () => {
  it('returns no proofs for an empty leaf set', () => {
    expect(merkleProofs([])).toEqual([]);
  });

  it.each([1, 2, 3, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 65, 129])(
    'matches every retained single-proof result for %i leaves', count => {
      const input = leaves(count);
      const original = [...input];
      const expected = input.map((_, index) => merkleProof(input, index));
      Object.freeze(input);
      expect(merkleProofs(input)).toEqual(expected);
      expect(input).toEqual(original);
    },
  );

  it.each([1, 2, 3, 17, 129, 4096])('hashes exactly n-1 internal nodes for %i leaves', count => {
    const input = leaves(count);
    hashes.count = 0;
    const proofs = merkleProofs(input);
    expect(hashes.count).toBe(count - 1);
    expect(proofs).toHaveLength(count);
  });

  it('does not share mutable sibling or direction arrays between proofs or exports', () => {
    const input = leaves(5);
    const first = merkleProofs(input);
    const second = merkleProofs(input);
    const expectedNeighbor = structuredClone(first[1]);
    first[0].siblings[0] = 'changed';
    first[0].directions[0] = 'left';
    expect(first[1]).toEqual(expectedNeighbor);
    expect(second).toEqual(input.map((_, index) => merkleProof(input, index)));
  });
});

function checkExport(signer: SepSigner) {
  const timestamp = '2026-10-03T00:00:00.000Z';
  let id = 0;
  const gateway = new SepGateway({ gatewayId: 'synthetic-batch', signer, clock: () => timestamp, idGen: () => `synthetic-${id++}` });
  for (let i = 0; i < 17; i++) gateway.record({ tool_name: 'read_document', decision: i % 2 ? 'DENIED' : 'PERMITTED', reason: 'synthetic compatibility case', request_id: i });
  const receipts = [...gateway.getReceipts()];
  const input = receipts.map(leafHash);
  const expected = {
    schema_version: '2.0', bundle_id: 'synthetic-17', algorithm: signer.algorithm,
    generated_at: timestamp, gateway_id: 'synthetic-batch', public_key: signer.publicKeyHex,
    policy_reference: '', receipts, merkle_root: merkleRoot(input),
    merkle_proofs: input.map((_, index) => merkleProof(input, index)),
    checkpoint: buildCheckpoint(receipts, 'synthetic-batch', timestamp, signer), offline_capable: true,
  };
  const actual = gateway.exportBundle();
  expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
  const result = verifySepBundle(actual, signer.publicKeyHex);
  expect(result.verdict).toBe('VERIFIED');
  expect(result.issuerVerified).toBe(true);
}

describe('serialized gateway export compatibility', () => {
  it('preserves classical signed receipt, proof and checkpoint bytes', () => checkExport(signerFromSeed(new Uint8Array(32).fill(37))));
  it('preserves hybrid signed receipt, proof and checkpoint bytes', () => checkExport(hybridSignerFromSeeds(new Uint8Array(32).fill(41), new Uint8Array(32).fill(43))));
  it('still refuses an empty export', () => {
    const gateway = new SepGateway({ gatewayId: 'synthetic-empty', signer: signerFromSeed(new Uint8Array(32).fill(47)) });
    expect(() => gateway.exportBundle()).toThrow('No receipts to export');
  });
});
