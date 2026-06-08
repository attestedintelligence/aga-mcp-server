/**
 * Cross-stack v2 (ML-DSA-65+Ed25519 composite) vector generator (deterministic).
 *
 *   npx tsx fixtures/cross-stack/generate-v2.mjs
 *
 * Emits vectors-v2.json + vectors-v2.sha256: a valid composite-signed SEP bundle (+ variants), the
 * H1-H11 hardening set re-expressed under the v2 profile, the v2-specific composite-codec / key
 * edges, and the cross-profile / trichotomy cases. The construction (canon / leaf / Merkle / signed
 * checkpoint / 6-step verify) is profile-INVARIANT — only the signature primitive and the public-key
 * well-formedness change — so every hardening fixture here MUST render the SAME verdict the v1 corpus
 * proves on 56 cases across 6 stacks. This corpus is the portable contract the agile engine (noble/JS)
 * and the agile Go oracle (CIRCL) must satisfy identically — see run-v2-stacks.mjs.
 *
 * Self-checks against the agile engine before writing, then SHA-256-pins the serialized corpus.
 */
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  SepGateway, verifySepBundle, leafHash, merkleRoot, merkleProof,
  SEP_RECEIPT_VERSION, ALG_HYBRID, ALG_ED25519, hybridSignerFromSeeds,
} from '../../src/sep/index.ts';
import { canonicalize } from '../../src/sep/canonical.ts';

// Deterministic composite signer (two fixed 32-byte seeds). Distinct from the cross-verify-fixtures
// seeds so this corpus is an independent witness; the primitive byte-identity is proven separately.
const MLDSA_SEED = new Uint8Array(32).fill(11);
const ED_SEED = new Uint8Array(32).fill(13);
const signer = hybridSignerFromSeeds(MLDSA_SEED, ED_SEED);
const pub = signer.publicKeyHex; // composite public key, 3984 lower-hex
const GW = 'cross-stack-gw-v2';

const mkGw = (clock, idPrefix) => {
  let n = 0;
  return new SepGateway({ gatewayId: GW, signer, clock, idGen: () => `${idPrefix}-${String(n++).padStart(4, '0')}` });
};

// Main 3-receipt bundle (odd leaf count -> exercises odd-node Merkle promotion) under v2.
let t = 0;
const gw = mkGw(() => `2026-01-01T00:00:${String(t++).padStart(2, '0')}.000Z`, 'rcpt');
gw.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'ok', arguments: { x: 1 }, request_id: 'r1' });
gw.record({ tool_name: 'revoke_artifact', decision: 'DENIED', reason: 'blocked', arguments: { y: 2 }, request_id: 'r2' });
gw.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'ok2', arguments: { z: 3 }, request_id: 'r3' });
const bundle = gw.exportBundle();

// ── valid variants ──────────────────────────────────────────────────────────
const single = mkGw(() => '2026-02-01T00:00:00.000Z', 'rs');
single.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'single', arguments: {}, request_id: 's1' });
const singleLeaf = single.exportBundle();

const uni = mkGw(() => '2026-03-01T00:00:00.000Z', 'ru');
uni.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'café ✓ é — 日本語 — é', arguments: { k: 'v' }, request_id: 'u1' });
const unicodeReason = uni.exportBundle();

const valid_variants = [
  { desc: 'v2 single-leaf bundle (1 receipt)', expect: 'VERIFIED', pinned_public_key: pub, bundle: singleLeaf },
  { desc: 'v2 unicode non-ASCII signed reason field (canon is profile-invariant)', expect: 'VERIFIED', pinned_public_key: pub, bundle: unicodeReason },
];

// ── helpers: re-sign a self-consistent v2 bundle so exactly ONE invariant is violated ─────────────
const wire = (b) => JSON.parse(JSON.stringify(b));
const stripSig = (o) => Object.fromEntries(Object.entries(o).filter(([k]) => k !== 'signature'));
const signReceipt = (unsigned) => ({ ...unsigned, signature: signer.sign(canonicalize(stripSig(unsigned))) });
const receiptBody = (i, prevLeaf, over = {}) => ({
  receipt_id: `sgn-${String(i).padStart(4, '0')}`, receipt_version: SEP_RECEIPT_VERSION, algorithm: ALG_HYBRID,
  timestamp: `2026-05-01T00:00:0${i}.000Z`, request_id: `g${i}`, method: 'tools/call',
  tool_name: i % 2 === 0 ? 'measure_integrity' : 'revoke_artifact', decision: i % 2 === 0 ? 'PERMITTED' : 'DENIED',
  reason: `signed-${i}`, policy_reference: '', arguments_hash: '', previous_receipt_hash: prevLeaf,
  gateway_id: GW, public_key: pub, ...over,
});
const buildSigned = (bodies, mutate = {}) => {
  let prev = '';
  const receipts = bodies.map((b, i) => {
    const body = typeof b === 'function' ? b(prev, i) : { ...b, previous_receipt_hash: prev };
    const r = signReceipt(body);
    if (mutate.receipt) mutate.receipt(r, i);
    prev = leafHash(r);
    return r;
  });
  const leaves = receipts.map(leafHash);
  const root = merkleRoot(leaves);
  const proofs = leaves.map((_, i) => merkleProof(leaves, i));
  const cpBody = {
    algorithm: ALG_HYBRID, gateway_id: GW, generated_at: '2026-05-01T00:00:09.000Z',
    head_leaf_hash: leaves[leaves.length - 1], leaf_count: receipts.length, merkle_root: root,
  };
  const checkpoint = { ...cpBody, signature: signer.sign(canonicalize(cpBody)) };
  const b = {
    schema_version: '2.0', bundle_id: 'sgn-bundle-v2', algorithm: ALG_HYBRID,
    generated_at: '2026-05-01T00:00:09.000Z', gateway_id: GW, public_key: pub, policy_reference: '',
    receipts, merkle_root: root, merkle_proofs: proofs, checkpoint, offline_capable: true,
  };
  if (mutate.envelope) mutate.envelope(b);
  return b;
};

const two = [(p, i) => receiptBody(i, p), (p, i) => receiptBody(i, p)];

// ── adversarial: profile-INVARIANT hardening classes, re-expressed under v2 ───────────────────────
// (each MUST behave exactly as its v1 twin in the 56-case corpus; the only changed input is the
//  signature primitive + composite key)
const signed_extra_receipt_field = buildSigned([(p, i) => receiptBody(i, p, { surprise: 'extra' }), (p, i) => receiptBody(i, p)]);
const signed_missing_receipt_field = buildSigned([(p, i) => receiptBody(i, p), (p, i) => { const r = receiptBody(i, p); delete r.reason; return r; }]);
const signed_proto_receipt_key = buildSigned([
  (p, i) => { const r = receiptBody(i, p); Object.defineProperty(r, '__proto__', { value: 'x', enumerable: true, writable: true, configurable: true }); return r; },
  (p, i) => receiptBody(i, p),
]);
const signed_extra_checkpoint_field = (() => {
  const b = buildSigned(two);
  const cpBody = { ...stripSig(b.checkpoint), surprise: 'extra' };
  b.checkpoint = { ...cpBody, signature: signer.sign(canonicalize(cpBody)) };
  return b;
})();
const tamperedCheckpointAlg = (() => { const b = buildSigned(two); b.checkpoint.algorithm = 'Ed25519-SHA256-RFC8785'; return b; })();
const envelope_gateway_id_lie = buildSigned(two, { envelope: (b) => { b.gateway_id = 'attacker-gw'; } });
const envelope_merkle_root_lie = buildSigned(two, { envelope: (b) => { b.merkle_root = 'a'.repeat(64); } });
const envelope_generated_at_lie = buildSigned(two, { envelope: (b) => { b.generated_at = '2026-05-01T00:00:08.000Z'; } });
const signed_unparseable_timestamp = buildSigned([(p, i) => receiptBody(i, p), (p, i) => receiptBody(i, p, { timestamp: 'not-a-date' })]);
const signed_decreasing_timestamp = buildSigned([
  (p, i) => receiptBody(i, p, { timestamp: '2026-05-01T00:00:05.000Z' }),
  (p, i) => receiptBody(i, p, { timestamp: '2026-05-01T00:00:01.000Z' }),
]);
const ts_invalid_calendar = buildSigned([
  (p, i) => receiptBody(i, p, { timestamp: '2026-05-01T00:00:00.000Z' }),
  (p, i) => receiptBody(i, p, { timestamp: '2026-02-29T00:00:00.000Z' }), // 2026 is not a leap year
]);

// merkle directions/siblings strictness (UNSIGNED edits on a valid 2-leaf bundle; proof[0].directions === ["right"])
const mtBase = buildSigned(two);
const mt_direction_token = (() => { const b = wire(mtBase); b.merkle_proofs[0].directions[0] = 'RIGHT'; return b; })();
const mt_sibling_uppercase = (() => { const b = wire(mtBase); b.merkle_proofs[0].siblings[0] = b.merkle_proofs[0].siblings[0].toUpperCase(); return b; })();

// robustness: depth-bomb in a receipt field (NOT re-signed); depth-bounded canon -> controlled FAILED.
const depthBomb = (() => { let nest = 0; for (let i = 0; i < 3000; i++) nest = [nest]; const b = buildSigned(two); b.receipts[0].reason = nest; return b; })();

// tamper: flip one hex nibble of a receipt's composite signature -> AND-verify FAILS.
const tamperReceiptSig = (() => {
  const b = wire(bundle);
  const s = b.receipts[0].signature;
  b.receipts[0].signature = s.slice(0, -1) + (s.slice(-1) === '0' ? '1' : '0');
  return b;
})();
// tamper: flip one hex nibble of the checkpoint composite signature.
const tamperCheckpointSig = (() => {
  const b = wire(bundle);
  const s = b.checkpoint.signature;
  b.checkpoint.signature = s.slice(0, -1) + (s.slice(-1) === '0' ? '1' : '0');
  return b;
})();

// ── v2-specific: composite codec + composite key well-formedness ──────────────────────────────────
// trailing byte appended to a receipt composite signature -> decodeComposite rejects trailing bytes.
const composite_sig_trailing_byte = (() => { const b = wire(bundle); b.receipts[0].signature = b.receipts[0].signature + 'ab'; return b; })();
// truncate a receipt composite signature by one byte -> component length mismatch / decode fail.
const composite_sig_truncated = (() => { const b = wire(bundle); const s = b.receipts[0].signature; b.receipts[0].signature = s.slice(0, -2); return b; })();
// all-zero composite public key (right length) -> validPublicKeyForProfile rejects all-zero.
const composite_key_all_zero = (() => { const b = wire(bundle); b.public_key = '0'.repeat(pub.length); b.receipts.forEach((r) => { r.public_key = b.public_key; }); return b; })();
// wrong-length composite public key -> structural floor fails.
const composite_key_wrong_length = (() => { const b = wire(bundle); b.public_key = pub.slice(0, -2); b.receipts.forEach((r) => { r.public_key = b.public_key; }); return b; })();

// ── cross-profile / downgrade / identifier-mismatch ───────────────────────────────────────────────
// identifier mismatch: bundle.algorithm = v2 but checkpoint.algorithm = v1 -> checkpoint binding fails
// (the verifier requires cp.algorithm === bundle.algorithm).
const identifier_mismatch_checkpoint = (() => { const b = wire(bundle); b.checkpoint.algorithm = ALG_ED25519; return b; })();
// downgrade: relabel a composite-signed bundle's algorithm to v1. On the agile engine the v1 key
// well-formedness fails (a 3984-hex composite key is not a 64-hex Ed25519 key) -> FAILED. On a v1-only
// verifier this is simply a v1 bundle with a malformed key + non-Ed25519 signatures -> FAILED.
const downgrade_relabel_v1 = (() => {
  const b = wire(bundle);
  b.algorithm = ALG_ED25519;
  b.checkpoint.algorithm = ALG_ED25519;
  b.receipts.forEach((r) => { r.algorithm = ALG_ED25519; });
  return b;
})();

const adversarial = [
  { desc: 'v2 signed_extra_receipt_field — 16th own key on a validly-composite-signed receipt; rebuilt+resigned', expect: 'FAILED', failing_step: 'structural', bundle: signed_extra_receipt_field },
  { desc: "v2 signed_missing_receipt_field — composite-signed receipt missing 'reason'; rebuilt+resigned", expect: 'FAILED', failing_step: 'structural', bundle: signed_missing_receipt_field },
  { desc: "v2 signed_proto_receipt_key — '__proto__' own key on a composite-signed receipt; rebuilt+resigned", expect: 'FAILED', failing_step: 'structural', bundle: signed_proto_receipt_key },
  { desc: 'v2 signed_extra_checkpoint_field — 8th key on the checkpoint, checkpoint re-signed (composite) over the 8-key body', expect: 'FAILED', failing_step: 'signed_checkpoint', bundle: signed_extra_checkpoint_field },
  { desc: 'v2 tampered checkpoint algorithm value', expect: 'FAILED', failing_step: 'signed_checkpoint', bundle: tamperedCheckpointAlg },
  { desc: 'v2 envelope_gateway_id_lie — UNSIGNED bundle.gateway_id differs; all composite-signed objects intact', expect: 'FAILED', failing_step: 'envelope_consistency', bundle: envelope_gateway_id_lie },
  { desc: 'v2 envelope_merkle_root_lie — UNSIGNED bundle.merkle_root wrong 64-hex; signed objects intact', expect: 'FAILED', failing_step: 'envelope_consistency', bundle: envelope_merkle_root_lie },
  { desc: 'v2 envelope_generated_at_lie — UNSIGNED bundle.generated_at differs from signed checkpoint.generated_at', expect: 'FAILED', failing_step: 'envelope_consistency', bundle: envelope_generated_at_lie },
  { desc: 'v2 signed_unparseable_timestamp — composite-signed receipt timestamp "not-a-date"; rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: signed_unparseable_timestamp },
  { desc: 'v2 signed_decreasing_timestamp — two composite-signed receipts with decreasing timestamps; rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: signed_decreasing_timestamp },
  { desc: 'v2 ts_invalid_calendar — Feb 29 2026 (not a leap year); regex passes, integer calendar check fails; rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: ts_invalid_calendar },
  { desc: 'v2 mt_direction_token — directions[0] "right"->"RIGHT" (UNSIGNED edit; NOT re-signed)', expect: 'FAILED', failing_step: 'merkle_and_bijection', bundle: mt_direction_token },
  { desc: 'v2 mt_sibling_uppercase — siblings[0] hex UPPERCASED (UNSIGNED edit; NOT re-signed); lowercase-64-hex guard rejects', expect: 'FAILED', failing_step: 'merkle_and_bijection', bundle: mt_sibling_uppercase },
  { desc: 'v2 depth_bomb — receipt field is a ~3000-deep nested array (NOT re-signed); depth-bounded canon -> FAILED, never crash', expect: 'FAILED', failing_step: 'verifier_exception', bundle: depthBomb },
  { desc: 'v2 tamper_receipt_signature — flip one nibble of a receipt composite signature -> AND-verify FAILS', expect: 'FAILED', failing_step: 'receipt_signatures', bundle: tamperReceiptSig },
  { desc: 'v2 tamper_checkpoint_signature — flip one nibble of the checkpoint composite signature', expect: 'FAILED', failing_step: 'signed_checkpoint', bundle: tamperCheckpointSig },
  { desc: 'v2 composite_sig_trailing_byte — extra byte appended to a receipt composite signature; decodeComposite rejects trailing bytes', expect: 'FAILED', failing_step: 'receipt_signatures', bundle: composite_sig_trailing_byte },
  { desc: 'v2 composite_sig_truncated — a receipt composite signature truncated by one byte; component-length / decode fail', expect: 'FAILED', failing_step: 'receipt_signatures', bundle: composite_sig_truncated },
  { desc: 'v2 composite_key_all_zero — all-zero composite public key (right length); rejected by composite key well-formedness', expect: 'FAILED', failing_step: 'structural', bundle: composite_key_all_zero },
  { desc: 'v2 composite_key_wrong_length — composite public key one byte short; structural floor fails', expect: 'FAILED', failing_step: 'structural', bundle: composite_key_wrong_length },
  { desc: 'v2 identifier_mismatch_checkpoint — bundle.algorithm=v2 but checkpoint.algorithm=v1; checkpoint binding requires cp.algorithm === bundle.algorithm', expect: 'FAILED', failing_step: 'signed_checkpoint', bundle: identifier_mismatch_checkpoint },
  { desc: 'v2 downgrade_relabel_v1 — a composite-signed bundle relabeled algorithm=v1; the v1 key well-formedness rejects the 3984-hex composite key', expect: 'FAILED', failing_step: 'structural', bundle: downgrade_relabel_v1 },
];

// ── self-check against the agile engine before writing ────────────────────────────────────────────
const vok = verifySepBundle(bundle, pub);
if (vok.verdict !== 'VERIFIED' || !vok.issuerVerified) throw new Error('v2 valid bundle did not verify');
for (const v of valid_variants) {
  const r = verifySepBundle(v.bundle, pub);
  if (r.verdict !== 'VERIFIED' || !r.issuerVerified) throw new Error(`v2 valid variant did not verify: ${v.desc}`);
}
for (const a of adversarial) {
  const r = verifySepBundle(a.bundle, pub);
  if (r.verdict !== 'FAILED') throw new Error(`v2 adversarial vector unexpectedly passed: ${a.desc}`);
  const step = r.steps.find((s) => s.name === a.failing_step);
  if (!step || step.ok) throw new Error(`v2 adversarial "${a.desc}" did not fail at step ${a.failing_step} (steps: ${JSON.stringify(r.steps)})`);
}

// Trichotomy self-check: the valid v2 bundle on a v1-only engine -> UNSUPPORTED_PROFILE (not FAILED).
const tri = verifySepBundle(bundle, undefined, { supportedProfiles: [ALG_ED25519] });
if (tri.verdict !== 'UNSUPPORTED_PROFILE') throw new Error(`trichotomy self-check failed: expected UNSUPPORTED_PROFILE, got ${tri.verdict}`);

const vectors = {
  algorithm: ALG_HYBRID,
  profile_version: 2,
  note: 'Portable cross-stack v2 (ML-DSA-65+Ed25519 composite) conformance vectors. The construction is '
    + 'profile-invariant; each hardening fixture must render the SAME verdict as its v1 twin. The agile '
    + 'engine (noble/JS) and the agile Go oracle (CIRCL) must agree byte-for-byte. A v1-only verifier '
    + 'must return UNSUPPORTED_PROFILE (exit 3) on the valid v2 bundle — proven in run-v2-stacks.mjs.',
  generated_by: 'fixtures/cross-stack/generate-v2.mjs (deterministic: mldsa_seed=32x0x0b, ed_seed=32x0x0d, fixed clock/idGen)',
  valid_bundle: { pinned_public_key: pub, expect: 'VERIFIED', bundle },
  valid_variants,
  adversarial,
  trichotomy: {
    desc: 'the valid v2 bundle handed to a v1-only verifier must return UNSUPPORTED_PROFILE (exit 3), NOT FAILED',
    expect: 'UNSUPPORTED_PROFILE',
    pinned_public_key: pub,
    bundle,
  },
};

const out = JSON.stringify(vectors, null, 2) + '\n';
writeFileSync(new URL('./vectors-v2.json', import.meta.url), out);
const digest = createHash('sha256').update(Buffer.from(out, 'utf8')).digest('hex');
writeFileSync(new URL('./vectors-v2.sha256', import.meta.url), `${digest}  vectors-v2.json\n`);
console.log(`wrote vectors-v2.json: ${1 + valid_variants.length} valid + ${adversarial.length} adversarial + 1 trichotomy (self-check passed)`);
console.log(`sha256(vectors-v2.json) = ${digest}`);
