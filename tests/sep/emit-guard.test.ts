/**
 * Emit-guard regression test (F-governance item 3).
 *
 * The "a non-integer / non-string value in a SIGNED field is unreachable" residual documented in
 * THREAT_BOUNDARY §3.8 rests ENTIRELY on `assertSignedReceiptFieldsAreStrings`: it forces every signed
 * receipt field to be string | boolean | null (the only signed number anywhere is the integer
 * checkpoint.leaf_count, handled identically by all six verifiers). If that guard is ever weakened or
 * removed, the documented residual silently becomes REACHABLE (a gateway could emit a number in a signed
 * field, where the six language stdlibs canonicalize differently). This test fails RED if that happens.
 */
import { describe, it, expect } from 'vitest';
import { assertSignedReceiptFieldsAreStrings } from '../../src/sep/canonical.js';
import { buildReceipt } from '../../src/sep/receipt.js';
import { signerFromSeed } from '../../src/sep/crypto.js';

describe('emit guard — assertSignedReceiptFieldsAreStrings (locks the unreachable-number residual)', () => {
  it('accepts string | boolean | null scalar fields', () => {
    expect(() => assertSignedReceiptFieldsAreStrings({ a: 'x', b: true, c: null })).not.toThrow();
  });

  it('THROWS on a raw number in a signed field (integer, float, and exponential)', () => {
    expect(() => assertSignedReceiptFieldsAreStrings({ a: 2 })).toThrow();
    expect(() => assertSignedReceiptFieldsAreStrings({ a: 2.5 })).toThrow();
    expect(() => assertSignedReceiptFieldsAreStrings({ a: 1e21 })).toThrow();
  });

  it('THROWS on a bigint field', () => {
    expect(() => assertSignedReceiptFieldsAreStrings({ a: 1n as unknown as string })).toThrow();
  });

  it('THROWS on an object / array field (signed fields must be flat scalars)', () => {
    expect(() => assertSignedReceiptFieldsAreStrings({ a: { nested: 1 } })).toThrow();
    expect(() => assertSignedReceiptFieldsAreStrings({ a: [1, 2] })).toThrow();
  });

  it('buildReceipt fails closed on the EMIT path when a signed field is a non-string', () => {
    const signer = signerFromSeed(new Uint8Array(32).fill(9));
    const base = {
      receipt_id: 'r1',
      timestamp: '2026-01-01T00:00:00.000Z',
      tool_name: 't',
      decision: 'PERMITTED' as const,
      reason: 'ok',
      policy_reference: 'p',
      previous_receipt_hash: '',
      gateway_id: 'g',
    };
    // A conformant receipt builds fine...
    expect(() => buildReceipt({ ...base }, signer)).not.toThrow();
    // ...but a raw number smuggled into a signed field is rejected at emit, never producing a bundle
    // whose canonicalization could diverge across language stacks.
    expect(() => buildReceipt({ ...base, reason: 5 as unknown as string }, signer)).toThrow();
  });
});
