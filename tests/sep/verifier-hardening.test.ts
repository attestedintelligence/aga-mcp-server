/**
 * Phase 4 — verifier completeness hardening.
 * Envelope/cross-field consistency (M-1/M-2/L-3), proof-root binding (L-7),
 * strict timestamps (L-2), small-order key rejection (L-1), getReceipts copy (M-3).
 */
import { describe, it, expect } from 'vitest';
import { SepGateway, signerFromSeed, verifySepBundle } from '../../src/sep/index.js';
import { wellFormedKey } from '../../src/sep/crypto.js';
import type { SepReceipt } from '../../src/sep/index.js';

function gateway() {
  const seed = new Uint8Array(32).fill(11);
  const gw = new SepGateway({ gatewayId: 'hard-gw', signer: signerFromSeed(seed) });
  gw.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'a', arguments: { x: 1 } });
  gw.record({ tool_name: 'revoke_artifact', decision: 'DENIED', reason: 'b', arguments: { y: 2 } });
  return gw;
}
const wire = (b: unknown) => JSON.parse(JSON.stringify(b));

describe('envelope + cross-field consistency', () => {
  it('rejects a tampered envelope merkle_root (M-1)', () => {
    const gw = gateway();
    const b = wire(gw.exportBundle());
    b.merkle_root = 'f'.repeat(64);
    const res = verifySepBundle(b, gw.publicKeyHex);
    expect(res.verdict).toBe('FAILED');
    expect(res.steps.find((s) => s.name === 'envelope_consistency')?.ok).toBe(false);
  });

  it('rejects a tampered envelope gateway_id (M-1/M-2)', () => {
    const gw = gateway();
    const b = wire(gw.exportBundle());
    b.gateway_id = 'someone-else';
    const res = verifySepBundle(b, gw.publicKeyHex);
    expect(res.verdict).toBe('FAILED');
    expect(res.steps.find((s) => s.name === 'envelope_consistency')?.ok).toBe(false);
  });

  it('rejects a tampered proof merkle_root (L-7)', () => {
    const gw = gateway();
    const b = wire(gw.exportBundle());
    b.merkle_proofs[0].merkle_root = 'a'.repeat(64);
    const res = verifySepBundle(b, gw.publicKeyHex);
    expect(res.verdict).toBe('FAILED');
    expect(res.steps.find((s) => s.name === 'merkle_and_bijection')?.ok).toBe(false);
  });

  it('rejects an unparseable timestamp (L-2)', () => {
    const gw = gateway();
    const b = wire(gw.exportBundle());
    b.receipts[0].timestamp = 'not-a-date';
    const res = verifySepBundle(b, gw.publicKeyHex);
    expect(res.verdict).toBe('FAILED');
    expect(res.steps.find((s) => s.name === 'chain_and_ordering')?.ok).toBe(false);
  });

  it('still verifies a clean bundle (regression)', () => {
    const gw = gateway();
    const res = verifySepBundle(gw.exportBundle(), gw.publicKeyHex);
    expect(res.verdict).toBe('VERIFIED');
    expect(res.issuerVerified).toBe(true);
  });
});

describe('small-order key rejection (L-1)', () => {
  it('rejects all-zero, identity, and y=-1 encodings', () => {
    expect(wellFormedKey('00'.repeat(32))).toBe(false);
    expect(wellFormedKey('01' + '00'.repeat(31))).toBe(false);
    expect(wellFormedKey('ec' + 'ff'.repeat(30) + '7f')).toBe(false);
    expect(wellFormedKey('00'.repeat(31) + '80')).toBe(false);
  });

  it('accepts a real gateway key', () => {
    const gw = gateway();
    expect(wellFormedKey(gw.publicKeyHex)).toBe(true);
  });
});

describe('getReceipts returns a copy (M-3)', () => {
  it('mutating the returned array does not affect the ledger', () => {
    const gw = gateway();
    const got = gw.getReceipts() as SepReceipt[];
    const n = got.length;
    got.push({} as SepReceipt);
    expect(gw.getReceipts().length).toBe(n);
    expect(gw.count).toBe(n);
  });
});
