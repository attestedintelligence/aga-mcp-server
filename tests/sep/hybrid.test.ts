/**
 * v2 composite (ML-DSA-65 + Ed25519) conformance — T2.3.
 * Verifies the ported src/sep/hybrid.ts against the PINNED cross-verify fixtures (the Go<->JS
 * byte-identity set, SHARED_CRYPTO_FOUNDATION §8). Per the fixture note, `message` is the RAW SIGNED
 * BYTES in hex (not a UTF-8 string), so we decode it and use the *Bytes variants. The port must:
 *  (a) verify each pinned composite; (b) reproduce the pinned public-key + signature bytes EXACTLY
 *  from the seeds (byte-identity to AGA Go / VerifyBundle JS); (c) reject tampering; (d) enforce
 *  AND-acceptance (corrupting EITHER component — ML-DSA or Ed25519 — must fail; no partial accept).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { verifyHybridBytes, signHybridBytes, hybridKeypairFromSeeds } from '../../src/sep/hybrid.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(
  readFileSync(resolve(HERE, '../../fixtures/cross-stack/cross-verify-fixtures.json'), 'utf8'),
) as { algorithm: string; cases: Array<{ name: string; mldsa_seed: string; ed_seed: string; message: string; composite_public_key: string; composite_signature: string }> };

describe('v2 composite — pinned cross-verify fixtures (byte-identity Go<->JS)', () => {
  it('fixture set is the hybrid profile with cases', () => {
    expect(fx.algorithm).toBe('ML-DSA-65+Ed25519-SHA256-JCS');
    expect(fx.cases.length).toBeGreaterThanOrEqual(5);
  });

  for (const c of fx.cases) {
    const msg = hexToBytes(c.message); // fixture note: message is the raw signed bytes in hex
    const pub = hexToBytes(c.composite_public_key);
    const sig = hexToBytes(c.composite_signature);

    it(`verifies the pinned composite: ${c.name}`, () => {
      expect(verifyHybridBytes(pub, msg, sig)).toBe(true);
    });

    it(`reproduces the pinned bytes from seeds (byte-identity): ${c.name}`, () => {
      const kp = hybridKeypairFromSeeds(hexToBytes(c.mldsa_seed), hexToBytes(c.ed_seed));
      expect(kp.publicKeyHex).toBe(c.composite_public_key);
      expect(bytesToHex(signHybridBytes(msg, kp.secretKey))).toBe(c.composite_signature);
    });

    it(`rejects a tampered (Ed25519-half) signature: ${c.name}`, () => {
      const t = sig.slice();
      t[t.length - 1] ^= 0x01; // last byte is the tail of the Ed25519 component
      expect(verifyHybridBytes(pub, msg, t)).toBe(false);
    });
  }

  it('AND-acceptance: corrupting the ML-DSA half (valid Ed25519 half) does NOT verify (no partial)', () => {
    const c = fx.cases[0];
    const pub = hexToBytes(c.composite_public_key);
    const msg = hexToBytes(c.message);
    const sig = hexToBytes(c.composite_signature);
    const t = sig.slice();
    t[100] ^= 0x01; // index 100 falls inside the 3309-byte ML-DSA component (offset 4..3313)
    expect(verifyHybridBytes(pub, msg, t)).toBe(false);
  });
});
