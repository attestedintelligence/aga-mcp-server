/**
 * R3 SAFE-INTEGER FLOOR — regression coverage for the 3.4.0 / 2.2.0 headline change.
 *
 * The GATE-01 review (2026-07-31) proved the floor shipped with ZERO test coverage: it removed the
 * floor from both JS verifiers and every existing gate stayed green, because in every previously
 * exercised bundle a > 2^53 value ALSO breaks the signature or a numeric check — so the FAILED
 * verdict was never actually attributable to the floor.
 *
 * This test isolates the floor. It builds a fully valid, consistently RE-SIGNED bundle whose one
 * signed receipt carries a numeric `request_id` (the spec's type is string|int|null, so a
 * non-coercing third-party signer can put a raw number there), then:
 *   - a SAFE numeric value (42, and exactly 2^53-1) → VERIFIED. This control proves the whole
 *     reconstruction is valid and that a numeric request_id is otherwise accepted — so any FAILED
 *     below is the floor and nothing else.
 *   - a NON-safe value (2^53, 1.5, and a value JS holds exactly but isSafeInteger rejects) →
 *     FAILED, at the floor, in BOTH the engine (src/sep) and the published aga-verify.
 * Delete the floor line and the non-safe cases flip to VERIFIED — this file goes red.
 */
import { describe, it, expect } from 'vitest';
import { signerFromSeed } from '../../src/sep/crypto.js';
import { canonicalize } from '../../src/sep/canonical.js';
import { leafHash, type SepReceipt } from '../../src/sep/receipt.js';
import { merkleRoot, merkleProof } from '../../src/sep/merkle.js';
import { verifySepBundle } from '../../src/sep/verify.js';
import { verifyEvidenceBundle } from '../../independent-verifier/verify.js';

const seed = new Uint8Array(32).fill(7);
const signer = signerFromSeed(seed);
const GW = 'gw-floor-test';
const POLICY = 'de7b447c291b43a0bb683a3c2abd4fea638ae0884c77924b5c18e63fca7a1ae2';

// Build a receipt whose fields are exactly the canonical 15, re-signing over the 14-field body.
// `request_id` is injected as-is (may be a number) — this is the non-coercing third-party path the
// floor exists to catch, so we deliberately bypass buildReceipt's string coercion.
function makeReceipt(requestId: unknown, previous: string, ts: string, id: string): SepReceipt {
  const unsigned: Record<string, unknown> = {
    receipt_id: id,
    receipt_version: '1.0',
    algorithm: signer.algorithm,
    timestamp: ts,
    request_id: requestId,
    method: 'tools/call',
    tool_name: 'read_file',
    decision: 'PERMITTED',
    reason: 'allowed',
    policy_reference: POLICY,
    arguments_hash: '',
    previous_receipt_hash: previous,
    gateway_id: GW,
    public_key: signer.publicKeyHex,
  };
  // Sign over the canonical body. canonicalize serializes a numeric request_id as its JSON literal,
  // exactly what a preserving (Go/Python) signer would sign — so this bundle is genuinely valid.
  const signature = signer.sign(canonicalize(unsigned));
  return { ...(unsigned as object), signature } as SepReceipt;
}

function buildBundle(requestId: unknown) {
  const ts = '2026-03-19T12:00:00.000Z';
  const r0 = makeReceipt(requestId, '', ts, 'id-0');
  const leaf0 = leafHash(r0);
  const r1 = makeReceipt('r1', leaf0, ts, 'id-1');
  const receipts = [r0, r1];
  const leaves = receipts.map(leafHash);
  const root = merkleRoot(leaves);
  const cpBody = {
    algorithm: signer.algorithm,
    gateway_id: GW,
    generated_at: ts,
    head_leaf_hash: leaves[leaves.length - 1],
    leaf_count: receipts.length,
    merkle_root: root,
  };
  const checkpoint = { ...cpBody, signature: signer.sign(canonicalize(cpBody)) };
  return {
    schema_version: '2.0',
    bundle_id: 'id-b',
    algorithm: signer.algorithm,
    generated_at: ts,
    gateway_id: GW,
    public_key: signer.publicKeyHex,
    policy_reference: POLICY,
    receipts,
    merkle_root: root,
    merkle_proofs: leaves.map((_, i) => merkleProof(leaves, i)),
    checkpoint,
    offline_capable: true,
  };
}

const bothVerdicts = (b: unknown) => ({
  engine: verifySepBundle(b).verdict,
  agaVerify: verifyEvidenceBundle(JSON.stringify(b)).verdict,
});

describe('R3 safe-integer floor — isolated (engine == published aga-verify)', () => {
  // Controls: a numeric request_id that IS a JS-safe integer verifies on both stacks, proving the
  // reconstruction is valid and that the floor — not a type check — is what rejects the cases below.
  it.each([
    ['string request_id', 'r0'],
    ['safe integer 42', 42],
    ['safe integer 2^53-1 (the boundary, inclusive)', Number.MAX_SAFE_INTEGER],
    ['safe integer -(2^53-1)', -Number.MAX_SAFE_INTEGER],
  ])('VERIFIES with %s', (_label, rid) => {
    const v = bothVerdicts(buildBundle(rid));
    expect(v.engine).toBe('VERIFIED');
    expect(v.agaVerify).toBe('VERIFIED');
  });

  // The floor: each value is one the reconstruction signs consistently, so ONLY the floor makes it
  // FAIL. Remove the floor and these flip to VERIFIED.
  it.each([
    ['2^53 (first unsafe integer)', Number.MAX_SAFE_INTEGER + 1],
    ['-(2^53)', -(Number.MAX_SAFE_INTEGER + 1)],
    ['non-integral 1.5', 1.5],
    ['large integer 10^16', 1e16],
  ])('FAILS the floor with %s', (_label, rid) => {
    const v = bothVerdicts(buildBundle(rid));
    expect(v.engine).toBe('FAILED');
    expect(v.agaVerify).toBe('FAILED');
  });
});
