/**
 * Phase 12 — the small-order forge must be rejected by EVERY verifier, not just src/sep.
 * The final re-audit showed the reference verifier and the published aga-verify accepted a
 * from-nothing forged bundle keyed to the Ed25519 identity point. This pins all three JS
 * verifiers (engine, reference, aga-verify) to reject small-order keys identically.
 */
import { describe, it, expect } from 'vitest';
import { SepGateway, signerFromSeed, verifySepBundle } from '../../src/sep/index.js';
import { verifyEvidenceBundle } from '../../independent-verifier/verify.js';
import { verifySepBundle as refVerify } from '../../aga-receipt-spec/verify/verify-sep.mjs';

const SMALL_ORDER = [
  '01' + '00'.repeat(31),        // identity (order 1)
  '01' + '00'.repeat(30) + '80', // identity, sign bit set (was the missing encoding)
  'ec' + 'ff'.repeat(30) + '7f', // order-2
  'ec' + 'ff'.repeat(31),        // order-2, sign bit set (was the missing encoding)
  '00'.repeat(32),               // all-zero / order-4
];

function realBundle() {
  const gw = new SepGateway({ gatewayId: 'g', signer: signerFromSeed(new Uint8Array(32).fill(9)) });
  gw.record({ tool_name: 'measure_integrity', decision: 'DENIED', reason: 'blocked', arguments: {} });
  gw.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'ok', arguments: { a: 1 } });
  return { bundle: gw.exportBundle(), pub: gw.publicKeyHex };
}

describe('cross-stack small-order rejection (engine == reference == aga-verify)', () => {
  it('a real bundle VERIFIES on all three stacks', () => {
    const { bundle, pub } = realBundle();
    expect(verifySepBundle(bundle, pub).verdict).toBe('VERIFIED');
    expect(verifyEvidenceBundle(JSON.stringify(bundle), pub).verdict).toBe('VERIFIED');
    expect(refVerify(bundle, pub).verdict).toBe('VERIFIED');
  });

  for (const key of SMALL_ORDER) {
    it(`a bundle keyed to small-order ${key.slice(0, 8)}… is FAILED on all three stacks`, () => {
      const { bundle } = realBundle();
      const b = JSON.parse(JSON.stringify(bundle));
      b.public_key = key;
      expect(verifySepBundle(b, undefined).verdict).toBe('FAILED');
      expect(verifyEvidenceBundle(JSON.stringify(b)).verdict).toBe('FAILED');
      expect(refVerify(b, undefined).verdict).toBe('FAILED');
    });
  }
});
