/**
 * Phase 10 — fixes for the final adversarial re-audit findings.
 * FIX-1 canon integer-key order (match reference); FIX-2 depth-bound + safe hash + robust verify;
 * FIX-3 complete small-order key rejection.
 */
import { describe, it, expect } from 'vitest';
import {
  canonicalize, MAX_CANON_DEPTH, safeArgumentsHash,
  SepGateway, signerFromSeed, verifySepBundle, generateSigner,
} from '../../src/sep/index.js';
import { wellFormedKey } from '../../src/sep/crypto.js';

// Verbatim copy of the normative reference verifier's canon (aga-receipt-spec/verify/verify-sep.mjs)
const refCanon = (o: unknown): string =>
  o === null || typeof o !== 'object' ? JSON.stringify(o)
    : Array.isArray(o) ? '[' + o.map(refCanon).join(',') + ']'
      : '{' + Object.keys(o as object).sort().map((k) => JSON.stringify(k) + ':' + refCanon((o as any)[k])).join(',') + '}';

describe('FIX-1: canonicalization matches the reference on integer-like keys', () => {
  const cases: unknown[] = [
    JSON.parse('{"22":"a","3":"b","100":"c"}'),
    JSON.parse('{"ports":{"22":"ssh","8":"x","100":"y","9":"z"}}'),
    { z: 1, a: 'x', m: [3, 2, 1] },
    JSON.parse('{"a":1,"__proto__":{"e":true}}'),
    { nested: { '2': { '10': 1, '1': 2 } }, unicode: 'café ✓' },
  ];
  for (const [i, c] of cases.entries()) {
    it(`case ${i} is byte-identical to the reference canon`, () => {
      expect(canonicalize(c)).toBe(refCanon(c));
    });
  }

  it('integer keys sort lexicographically, not numerically', () => {
    expect(canonicalize(JSON.parse('{"22":"a","3":"b","100":"c"}'))).toBe('{"100":"c","22":"a","3":"b"}');
  });

  it('still keeps a __proto__ key (injective)', () => {
    expect(canonicalize(JSON.parse('{"a":1,"__proto__":{"e":true}}'))).toBe('{"__proto__":{"e":true},"a":1}');
  });
});

describe('FIX-2: depth bound + never-throwing arguments hash', () => {
  const deepObject = (depth: number) => {
    const root: Record<string, unknown> = {};
    let cur = root;
    for (let i = 0; i < depth; i++) { const next: Record<string, unknown> = {}; cur.x = next; cur = next; }
    return root;
  };

  it('canonicalize throws a controlled error beyond MAX_CANON_DEPTH', () => {
    expect(() => canonicalize(deepObject(MAX_CANON_DEPTH + 50))).toThrow(/nesting exceeds/);
  });

  it('shallow input canonicalizes fine', () => {
    expect(() => canonicalize(deepObject(10))).not.toThrow();
  });

  it('safeArgumentsHash never throws: ok=false + sentinel on a depth bomb', () => {
    const r = safeArgumentsHash(deepObject(5000));
    expect(r.ok).toBe(false);
    expect(r.hash).toMatch(/^[0-9a-f]{64}$/);
    const good = safeArgumentsHash({ a: 1, b: [1, 2, 3] });
    expect(good.ok).toBe(true);
  });

  it('verifySepBundle returns FAILED (does not throw) on a deep-value receipt', () => {
    const gw = new SepGateway({ gatewayId: 'g', signer: signerFromSeed(new Uint8Array(32).fill(5)) });
    gw.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'ok', arguments: { a: 1 } });
    const b = JSON.parse(JSON.stringify(gw.exportBundle()));
    b.receipts[0].reason = deepObject(MAX_CANON_DEPTH + 50); // hostile deep value in a signed field
    let res: ReturnType<typeof verifySepBundle> | undefined;
    expect(() => { res = verifySepBundle(b, gw.publicKeyHex); }).not.toThrow();
    expect(res!.verdict).toBe('FAILED');
  });
});

describe('FIX-3: complete small-order / non-canonical key rejection', () => {
  const smallOrder = [
    '00'.repeat(32),
    '00'.repeat(31) + '80',
    '01' + '00'.repeat(31),
    '01' + '00'.repeat(30) + '80', // identity, sign bit set (was MISSING)
    'ec' + 'ff'.repeat(30) + '7f',
    'ec' + 'ff'.repeat(31),        // order-2, sign bit set (was MISSING)
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  ];

  it('rejects every small-order encoding (incl. the two sign-bit variants)', () => {
    for (const k of smallOrder) expect(wellFormedKey(k)).toBe(false);
  });

  it('rejects non-canonical encodings (y >= p)', () => {
    expect(wellFormedKey('ed' + 'ff'.repeat(30) + '7f')).toBe(false); // y = p
    expect(wellFormedKey('ee' + 'ff'.repeat(30) + '7f')).toBe(false); // y = p+1
  });

  it('accepts real gateway keys', () => {
    for (let i = 0; i < 20; i++) {
      const { signer } = generateSigner();
      expect(wellFormedKey(signer.publicKeyHex)).toBe(true);
    }
  });

  it('a forged bundle under the identity key fails when pinned to a real key', () => {
    const real = generateSigner();
    const realBundle = (() => {
      const gw = new SepGateway({ gatewayId: 'g', signer: real.signer });
      gw.record({ tool_name: 'measure_integrity', decision: 'DENIED', reason: 'blocked', arguments: {} });
      return gw.exportBundle();
    })();
    // structural floor rejects the small-order key outright; and pinning to the real key never matches.
    const forged = JSON.parse(JSON.stringify(realBundle));
    forged.public_key = '01' + '00'.repeat(30) + '80';
    expect(verifySepBundle(forged, real.signer.publicKeyHex).verdict).toBe('FAILED');
  });
});
