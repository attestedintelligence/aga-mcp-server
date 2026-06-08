/**
 * Phase 2 — canonicalization soundness + strict-schema floor.
 *
 * Proves: (1) canonicalize is INJECTIVE (no "__proto__" collision); (2) the verifier
 * rejects "__proto__" injection and any extra/unknown key on the signed receipt or
 * checkpoint; (3) a clean bundle still verifies (regression). These are the in-repo
 * half of the cross-stack soundness contract (see fixtures/cross-stack/).
 */
import { describe, it, expect } from 'vitest';
import { SepGateway, signerFromSeed, verifySepBundle } from '../../src/sep/index.js';
import { canonicalize } from '../../src/sep/canonical.js';

function buildBundle() {
  const seed = new Uint8Array(32).fill(7);
  const gw = new SepGateway({ gatewayId: 'test-gw', signer: signerFromSeed(seed) });
  gw.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'ok', arguments: { x: 1 } });
  gw.record({ tool_name: 'revoke_artifact', decision: 'DENIED', reason: 'blocked', arguments: { y: 2 } });
  gw.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'ok2', arguments: { z: 3 } });
  return { bundle: gw.exportBundle(), pub: gw.publicKeyHex };
}

/** Deep clone a bundle through JSON (as a verifier would receive it off the wire). */
const wire = (b: unknown) => JSON.parse(JSON.stringify(b));

describe('canonicalize injectivity', () => {
  it('does not drop a "__proto__" key (no collision with the same object minus it)', () => {
    const withProto = JSON.parse('{"a":1,"__proto__":{"evil":true}}');
    expect(Object.keys(withProto)).toContain('__proto__'); // JSON.parse => own key
    expect(canonicalize(withProto)).not.toBe(canonicalize({ a: 1 }));
    expect(canonicalize(withProto)).toBe('{"__proto__":{"evil":true},"a":1}');
  });

  it('is byte-stable and key-sorted for ordinary input', () => {
    expect(canonicalize({ z: 1, a: 'x', m: [3, 2, 1] })).toBe('{"a":"x","m":[3,2,1],"z":1}');
  });

  it('does not pollute Object.prototype', () => {
    canonicalize(JSON.parse('{"__proto__":{"polluted":"yes"}}'));
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe('strict-schema floor in the verifier', () => {
  it('verifies a clean bundle (regression)', () => {
    const { bundle, pub } = buildBundle();
    const res = verifySepBundle(bundle, pub);
    expect(res.verdict).toBe('VERIFIED');
    expect(res.issuerVerified).toBe(true);
  });

  it('rejects a "__proto__"-injected receipt at the structural floor', () => {
    const { bundle, pub } = buildBundle();
    const b = wire(bundle);
    // attacker adds an own "__proto__" key to a receipt (as JSON.parse of wire bytes would)
    Object.defineProperty(b.receipts[0], '__proto__', { value: { evil: true }, enumerable: true, writable: true, configurable: true });
    expect(Object.keys(b.receipts[0])).toContain('__proto__');
    const res = verifySepBundle(b, pub);
    expect(res.verdict).toBe('FAILED');
    expect(res.steps.find((s) => s.name === 'structural')?.ok).toBe(false);
  });

  it('rejects an extra/unknown field on a receipt', () => {
    const { bundle, pub } = buildBundle();
    const b = wire(bundle);
    b.receipts[1].surprise = 'extra';
    const res = verifySepBundle(b, pub);
    expect(res.verdict).toBe('FAILED');
    expect(res.steps.find((s) => s.name === 'structural')?.ok).toBe(false);
  });

  it('rejects a receipt missing a canonical field', () => {
    const { bundle, pub } = buildBundle();
    const b = wire(bundle);
    delete b.receipts[0].reason;
    const res = verifySepBundle(b, pub);
    expect(res.verdict).toBe('FAILED');
    expect(res.steps.find((s) => s.name === 'structural')?.ok).toBe(false);
  });

  it('rejects an extra/unknown field on the checkpoint', () => {
    const { bundle, pub } = buildBundle();
    const b = wire(bundle);
    b.checkpoint.surprise = 'extra';
    const res = verifySepBundle(b, pub);
    expect(res.verdict).toBe('FAILED');
    expect(res.steps.find((s) => s.name === 'signed_checkpoint')?.ok).toBe(false);
  });

  it('rejects a checkpoint with a tampered algorithm value', () => {
    const { bundle, pub } = buildBundle();
    const b = wire(bundle);
    b.checkpoint.algorithm = 'Ed25519-SHA256-RFC8785';
    const res = verifySepBundle(b, pub);
    expect(res.verdict).toBe('FAILED');
    expect(res.steps.find((s) => s.name === 'signed_checkpoint')?.ok).toBe(false);
  });
});
