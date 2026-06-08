// Canonical SEP verification tests (CANONICAL_CONSTRUCTION_v2.md §6/§7).
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifySepBundle } from '../verify';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
// Public key of the canonical conformance corpus (aga-receipt-spec/vectors).
const PUBKEY = 'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c';
const load = () => JSON.parse(readFileSync(join(ROOT, 'example-bundle.json'), 'utf8'));
const clone = (o: any) => JSON.parse(JSON.stringify(o));

describe('canonical SEP verification', () => {
  it('genuine bundle VERIFIES with provenance when key pinned', () => {
    const r = verifySepBundle(load(), PUBKEY);
    expect(r.verdict).toBe('VERIFIED');
    expect(r.issuerVerified).toBe(true);
    expect(r.pinned).toBe(true);
    expect(r.steps.find((s) => s.name === 'signed_checkpoint')!.ok).toBe(true);
  });

  it('no pin: VERIFIED integrity but issuerVerified=false (two-tier)', () => {
    const r = verifySepBundle(load());
    expect(r.verdict).toBe('VERIFIED');
    expect(r.issuerVerified).toBe(false);
    expect(r.pinned).toBe(false);
  });

  it('wrong pinned key: FAILED', () => {
    const r = verifySepBundle(load(), '0'.repeat(63) + '1');
    expect(r.verdict).toBe('FAILED');
    expect(r.issuerVerified).toBe(false);
  });

  it('tampered recorded decision: FAILED', () => {
    const b = clone(load());
    b.receipts[2].decision = b.receipts[2].decision === 'DENIED' ? 'PERMITTED' : 'DENIED';
    expect(verifySepBundle(b, PUBKEY).verdict).toBe('FAILED');
  });

  it('trailing-drop (truncation) caught by the signed checkpoint: FAILED', () => {
    const b = clone(load());
    b.receipts = b.receipts.slice(0, 2);
    b.merkle_proofs = b.merkle_proofs.slice(0, 2);
    const r = verifySepBundle(b, PUBKEY);
    expect(r.verdict).toBe('FAILED');
    expect(r.steps.find((s) => s.name === 'signed_checkpoint')!.ok).toBe(false);
  });

  it('re-pointed Merkle proof index (broken bijection): FAILED', () => {
    const b = clone(load());
    b.merkle_proofs[0].leaf_index = 1;
    expect(verifySepBundle(b, PUBKEY).verdict).toBe('FAILED');
  });

  it('all-zero public key is rejected', () => {
    const b = clone(load());
    b.public_key = '0'.repeat(64);
    expect(verifySepBundle(b).verdict).toBe('FAILED');
  });
});
