/**
 * Agile verifier + v2 producer — T2.2 / T2.4.
 * Produces a v1 (Ed25519) and a v2 (ML-DSA-65+Ed25519 composite) SEP bundle through the SAME
 * SepGateway, verifies each through the SAME agile verifier, and exercises the verdict trichotomy:
 *  - v1 and v2 both round-trip to VERIFIED (+ provenance when the key is pinned);
 *  - a v2 bundle handed to a v1-only verifier returns UNSUPPORTED_PROFILE (exit 3), NOT FAILED;
 *  - a v1 bundle still VERIFIES on a v1-only verifier (backward compat);
 *  - an unknown/unregistered algorithm is FAILED (not UNSUPPORTED_PROFILE);
 *  - tampering with a v2 signature is FAILED (composite AND-verify).
 */
import { describe, it, expect } from 'vitest';
import { SepGateway } from '../../src/sep/bundle.js';
import { signerFromSeed, type SepSigner } from '../../src/sep/crypto.js';
import { hybridSignerFromSeeds } from '../../src/sep/hybrid.js';
import { ALG_ED25519, ALG_HYBRID } from '../../src/sep/profiles.js';
import { verifySepBundle } from '../../src/sep/verify.js';

const seedV1 = new Uint8Array(32).fill(7);
const seedMldsa = new Uint8Array(32).fill(11);
const seedEd = new Uint8Array(32).fill(13);

function buildBundle(signer: SepSigner) {
  let s = 0;
  const clock = () => new Date(Date.UTC(2026, 2, 19, 12, 0, s++)).toISOString(); // valid .sssZ, non-decreasing
  let i = 0;
  const idGen = () => `id-${i++}`;
  const gw = new SepGateway({ gatewayId: 'gw-test', signer, clock, idGen });
  gw.record({ tool_name: 'read_file', decision: 'PERMITTED', reason: 'allowed', request_id: 'r1' });
  gw.record({ tool_name: 'write_file', decision: 'DENIED', reason: 'blocked', request_id: 'r2' });
  return gw.exportBundle();
}

describe('agile verifier — v1/v2 dispatch + trichotomy', () => {
  it('v1: produces + verifies an Ed25519 bundle; provenance when pinned', () => {
    const b = buildBundle(signerFromSeed(seedV1));
    expect(b.algorithm).toBe(ALG_ED25519);
    expect(verifySepBundle(b).verdict).toBe('VERIFIED');
    const pinned = verifySepBundle(b, b.public_key);
    expect(pinned.verdict).toBe('VERIFIED');
    expect(pinned.issuerVerified).toBe(true);
  });

  it('v2: produces + verifies an ML-DSA-65+Ed25519 composite bundle; provenance when pinned', () => {
    const b = buildBundle(hybridSignerFromSeeds(seedMldsa, seedEd));
    expect(b.algorithm).toBe(ALG_HYBRID);
    expect(verifySepBundle(b).verdict).toBe('VERIFIED');
    const pinned = verifySepBundle(b, b.public_key);
    expect(pinned.verdict).toBe('VERIFIED');
    expect(pinned.issuerVerified).toBe(true);
  });

  it('trichotomy: a v2 bundle on a v1-only verifier -> UNSUPPORTED_PROFILE (not FAILED)', () => {
    const b = buildBundle(hybridSignerFromSeeds(seedMldsa, seedEd));
    const r = verifySepBundle(b, undefined, { supportedProfiles: [ALG_ED25519] });
    expect(r.verdict).toBe('UNSUPPORTED_PROFILE');
  });

  it('backward compat: a v1 bundle on a v1-only verifier still VERIFIES', () => {
    const b = buildBundle(signerFromSeed(seedV1));
    expect(verifySepBundle(b, undefined, { supportedProfiles: [ALG_ED25519] }).verdict).toBe('VERIFIED');
  });

  it('unknown/unregistered algorithm -> FAILED (not UNSUPPORTED_PROFILE)', () => {
    const b = buildBundle(signerFromSeed(seedV1)) as any;
    b.algorithm = 'Bogus-Algo-1';
    expect(verifySepBundle(b).verdict).toBe('FAILED');
  });

  it('tamper: flipping a v2 receipt signature -> FAILED (composite AND-verify)', () => {
    const b = buildBundle(hybridSignerFromSeeds(seedMldsa, seedEd)) as any;
    const sig: string = b.receipts[0].signature;
    b.receipts[0].signature = sig.slice(0, -1) + (sig.slice(-1) === '0' ? '1' : '0');
    expect(verifySepBundle(b).verdict).toBe('FAILED');
  });
});
