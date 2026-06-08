/**
 * RFC 8785 (JCS) conformance — proves the `Ed25519-SHA256-JCS` algorithm id is HONEST.
 *
 * The SEP construction signs/hashes `canonicalize(obj)`, and the algorithm id claims RFC 8785 JCS, so a
 * skeptic's first move is to check the canon against the RFC 8785 reference. This test does that two ways:
 *   (1) LIVE differential — assert the shipped `canonicalize()` is byte-identical to the reference
 *       RFC 8785 implementation (the `canonicalize` npm package, a dev-dependency only) on the real
 *       receipt + checkpoint and on the classic RFC 8785 edge cases (control-char / empty / astral
 *       property-name sort, number serialization incl. 1e+21 / 5e-324 / max-double / -0, escaping).
 *   (2) COMMITTED vectors — assert it reproduces `vectors/jcs-rfc8785-vectors.json`, whose
 *       `expected_rfc8785` strings were produced by that same reference (regenerate: `npx canonicalize`).
 * If this passes, "JCS" is a verified claim rather than an approximation. AGA signs only string fields
 * plus the integer `leaf_count`, so the (already-matching) float edge cases are unreachable in a real
 * bundle — they are tested anyway to leave no doubt.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import refCanonicalize from 'canonicalize';
import { canonicalize } from '../../src/sep/canonical.js';

const { vectors } = JSON.parse(
  readFileSync(new URL('../../aga-receipt-spec/vectors/jcs-rfc8785-vectors.json', import.meta.url), 'utf8'),
) as { vectors: { name: string; input: unknown; expected_rfc8785: string }[] };

// Extra live-only edge cases (no committed expectation needed — the reference IS the oracle).
const liveExtra: Record<string, unknown> = {
  number_edges: { a: 1e21, b: 5e-324, c: 1.7976931348623157e308, d: -0, e: 0, f: 9007199254740991 },
  astral_value_and_key: { '😀': 'x', a: 'café ✓' },
  nested_arrays_keep_order: { z: [3, 1, 2, { b: 2, a: 1 }], a: [true, false, null] },
};

describe('RFC 8785 (JCS) conformance', () => {
  it('ships the real receipt + checkpoint + RFC 8785 edge-case vectors', () => {
    const names = vectors.map((v) => v.name);
    expect(names).toContain('aga_real_receipt_no_sig');
    expect(names).toContain('aga_real_checkpoint_no_sig');
    expect(vectors.length).toBeGreaterThanOrEqual(7);
  });

  for (const v of vectors) {
    it(`matches committed RFC 8785 vector: ${v.name}`, () => {
      expect(canonicalize(v.input)).toBe(v.expected_rfc8785);
    });
    it(`matches the LIVE RFC 8785 reference: ${v.name}`, () => {
      expect(canonicalize(v.input)).toBe(refCanonicalize(v.input));
    });
  }

  for (const [name, input] of Object.entries(liveExtra)) {
    it(`matches the LIVE RFC 8785 reference (edge): ${name}`, () => {
      expect(canonicalize(input)).toBe(refCanonicalize(input));
    });
  }
});
