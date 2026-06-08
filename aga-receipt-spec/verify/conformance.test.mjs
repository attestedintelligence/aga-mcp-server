// Conformance harness for the canonical SEP Evidence Bundle (CANONICAL_CONSTRUCTION_v2.md §7).
// A conformant verifier VERIFIES every genuine corpus bundle and FAILs on each negative mutation.
// Run: node --test verify/conformance.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifySepBundle } from './verify-sep.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const corpus = JSON.parse(readFileSync(join(ROOT, 'vectors', 'aga_evidence_bundle_vectors.json'), 'utf8'));
const PK = corpus.public_key;
const clone = (o) => JSON.parse(JSON.stringify(o));

for (const [name, v] of Object.entries(corpus.bundles)) {
  test(`${name}: genuine bundle VERIFIES with provenance`, () => {
    const r = verifySepBundle(v.bundle, PK);
    assert.equal(r.verdict, 'VERIFIED');
    assert.equal(r.issuerVerified, true);
    assert.equal(v.bundle.merkle_root, v.expected_merkle_root);
    assert.equal(v.independently_corroborated, true);
  });

  test(`${name}: tampering a recorded decision => FAILED`, () => {
    const b = clone(v.bundle);
    b.receipts[b.receipts.length - 1].decision = b.receipts[b.receipts.length - 1].decision === 'DENIED' ? 'PERMITTED' : 'DENIED';
    assert.equal(verifySepBundle(b, PK).verdict, 'FAILED');
  });

  test(`${name}: wrong pinned key => FAILED + not issuer-verified`, () => {
    const r = verifySepBundle(v.bundle, '0'.repeat(63) + '1');
    assert.equal(r.verdict, 'FAILED');
    assert.equal(r.issuerVerified, false);
  });

  if (v.bundle.receipts.length > 1) {
    test(`${name}: dropping the trailing receipt (truncation) => FAILED (checkpoint)`, () => {
      const b = clone(v.bundle);
      b.receipts = b.receipts.slice(0, -1);
      b.merkle_proofs = b.merkle_proofs.slice(0, -1);
      const r = verifySepBundle(b, PK);
      assert.equal(r.verdict, 'FAILED');
      assert.equal(r.steps.find((s) => s.name === 'signed_checkpoint').ok, false);
    });

    test(`${name}: re-pointing a Merkle proof leaf_index => FAILED`, () => {
      const b = clone(v.bundle);
      b.merkle_proofs[0].leaf_index = 1; // duplicate index 1, break the 0..N-1 bijection
      assert.equal(verifySepBundle(b, PK).verdict, 'FAILED');
    });
  }
}

test('no-pin genuine bundle: VERIFIED integrity but issuerVerified=false (two-tier)', () => {
  const v = corpus.bundles['len-3-odd-with-deny'];
  const r = verifySepBundle(v.bundle);
  assert.equal(r.verdict, 'VERIFIED');
  assert.equal(r.issuerVerified, false);
  assert.equal(r.pinned, false);
});
