/**
 * Cross-stack vector generator (deterministic).
 *
 *   npx tsx fixtures/cross-stack/generate.mjs
 *
 * Emits vectors.json: canonicalization input→output pairs, valid bundles (+ variants), and a
 * named adversarial set with expected verdicts — one fixture per historical finding. These are
 * the portable contract that EVERY conformant SEP verifier (src/sep engine, the reference
 * verify-sep.mjs, aga-verify, Go, Python) must satisfy identically — see README.md. The
 * committed vectors.json is the source of truth consumed by the test suite + run-all-stacks.mjs.
 * Regenerate only intentionally; this self-checks against the engine before writing.
 */
import { writeFileSync } from 'node:fs';
import { SepGateway, signerFromSeed, verifySepBundle, leafHash, merkleRoot, merkleProof, SEP_ALGORITHM, SEP_RECEIPT_VERSION } from '../../src/sep/index.ts';
import { canonicalize } from '../../src/sep/canonical.ts';

const seed = new Uint8Array(32).fill(7);
const signer = signerFromSeed(seed); // same gateway signer the SepGateway uses (deterministic)
const mkGw = (clock, idPrefix) => {
  let n = 0;
  return new SepGateway({ gatewayId: 'cross-stack-gw', signer: signerFromSeed(seed), clock, idGen: () => `${idPrefix}-${String(n++).padStart(4, '0')}` });
};

// Main 3-receipt bundle (odd leaf count → exercises odd-node Merkle promotion).
let t = 0;
const gw = mkGw(() => `2026-01-01T00:00:${String(t++).padStart(2, '0')}.000Z`, 'rcpt');
gw.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'ok', arguments: { x: 1 }, request_id: 'r1' });
gw.record({ tool_name: 'revoke_artifact', decision: 'DENIED', reason: 'blocked', arguments: { y: 2 }, request_id: 'r2' });
gw.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'ok2', arguments: { z: 3 }, request_id: 'r3' });
const bundle = gw.exportBundle();
const pub = gw.publicKeyHex;

// ── canonicalization vectors (input → canonical bytes) ─────────────────────
const canonInputs = [
  { desc: 'flat object is key-sorted', input: { z: 1, a: 'x', m: true } },
  { desc: 'nested objects + arrays (arrays keep order)', input: { b: [3, 2, 1], a: { d: 4, c: 3 } } },
  { desc: '"__proto__" is an ordinary key (injective canon)', input: JSON.parse('{"a":1,"__proto__":{"e":true}}') },
  { desc: 'unicode is preserved', input: { s: 'café ✓ é' } },
  { desc: 'null and boolean scalars', input: { a: null, b: false, c: true } },
  { desc: 'integer-like keys sort LEXICOGRAPHICALLY, not numerically', input: JSON.parse('{"22":"a","3":"b","100":"c"}') },
  { desc: 'nested integer-like keys (e.g. a port map in tool args)', input: JSON.parse('{"ports":{"22":"ssh","8":"x","100":"y","9":"z"}}') },
];
const canonical = canonInputs.map((v) => ({ ...v, canonical: canonicalize(v.input) }));

// ── valid bundles + variants (every verifier MUST return VERIFIED) ─────────
const single = mkGw(() => '2026-02-01T00:00:00.000Z', 'rs');
single.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'single', arguments: {}, request_id: 's1' });
const singleLeaf = single.exportBundle();

const uni = mkGw(() => '2026-03-01T00:00:00.000Z', 'ru');
uni.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'café ✓ é — 日本語 — é', arguments: { 'k': 'v' }, request_id: 'u1' });
const unicodeReason = uni.exportBundle();

// ROUND-5 C2 companion: a VALID surrogate PAIR (an astral emoji, U+1F6E1 SHIELD = D83D DEE1) in a
// signed reason. The lone-surrogate rejection must NOT false-reject valid astral text — this bundle
// is built+signed authentically over the emoji and MUST VERIFY on all six. (signed_lone_surrogate is
// its adversarial twin: an UNPAIRED surrogate that every stack rejects.)
const astral = mkGw(() => '2026-03-02T00:00:00.000Z', 'rae');
astral.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'blocked ' + String.fromCodePoint(0x1F6E1), arguments: { 'k': 'v' }, request_id: 'ae1' });
const astralEmojiReason = astral.exportBundle();

// ROUND-6 reachable-string closure: a signed reason containing U+2028 LINE SEPARATOR + U+2029
// PARAGRAPH SEPARATOR. Go encoding/json escapes those two code points even with SetEscapeHTML(false);
// the Go verifier now un-escapes them so its canon is byte-identical to JS/Python. An exhaustive
// 0..0x10FFFF code-point sweep proved these are the ONLY chars Go diverged on, so this closes the
// reachable string-content divergence space. MUST VERIFY on all six. (The separators appear only
// inside String.fromCharCode below — never in source/comments, where they are JS line terminators.)
const lsep = mkGw(() => '2026-03-03T00:00:00.000Z', 'rls');
lsep.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'line1' + String.fromCharCode(0x2028) + 'line2' + String.fromCharCode(0x2029) + 'p2', arguments: { 'k': 'v' }, request_id: 'ls1' });
const lineSepReason = lsep.exportBundle();

// JCS-equivalent numeric re-encodings (T2/T3/T4). These are freshly-built AUTHENTIC bundles that are
// NOT re-signed: a SEP signed numeric field (checkpoint.leaf_count) / a proof's leaf_index is re-encoded
// in the SERIALIZED JSON as an integral float ("2" -> "2.0", "0" -> "0.0"). Per RFC-8785 (JCS) the canon
// collapses an integral float back to its shortest integer form, so the signature/Merkle bijection still
// hold and every verifier MUST return VERIFIED. The float surgery is performed on the OUTPUT TEXT after
// JSON.stringify (a JS number cannot retain a trailing ".0"); the in-memory object stays the integer form
// so the generator self-check verifies the authentic bundle. Each variant uses a UNIQUE idGen prefix so
// its auto-assigned bundle_id ("lcf-0002" / "lif-0002") is a unique anchor for that scoped edit.
const lcf = mkGw(() => '2026-06-01T00:00:00.000Z', 'lcf');
lcf.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'leaf-count-float-a', arguments: {}, request_id: 'lcf1' });
lcf.record({ tool_name: 'revoke_artifact', decision: 'DENIED', reason: 'leaf-count-float-b', arguments: {}, request_id: 'lcf2' });
const leafCountFloat = lcf.exportBundle(); // bundle_id = lcf-0002 ; checkpoint.leaf_count = 2

const lif = mkGw(() => '2026-06-02T00:00:00.000Z', 'lif');
lif.record({ tool_name: 'measure_integrity', decision: 'PERMITTED', reason: 'leaf-index-float-a', arguments: {}, request_id: 'lif1' });
lif.record({ tool_name: 'revoke_artifact', decision: 'DENIED', reason: 'leaf-index-float-b', arguments: {}, request_id: 'lif2' });
const leafIndexFloat = lif.exportBundle(); // bundle_id = lif-0002 ; merkle_proofs[0].leaf_index = 0

const valid_variants = [
  { desc: 'single-leaf bundle (1 receipt)', expect: 'VERIFIED', pinned_public_key: pub, bundle: singleLeaf },
  { desc: 'unicode non-ASCII signed reason field', expect: 'VERIFIED', pinned_public_key: pub, bundle: unicodeReason },
  { desc: 'leaf_count_float — checkpoint.leaf_count re-encoded as integral float (2 -> 2.0) in the serialized JSON; JCS canon collapses it to 2 so the checkpoint signature/binding still verify (NOT re-signed)', expect: 'VERIFIED', pinned_public_key: pub, bundle: leafCountFloat },
  { desc: 'leaf_index_float — one proof leaf_index re-encoded as integral float (0 -> 0.0) in the serialized JSON; the merkle bijection accepts the integral float (NOT re-signed)', expect: 'VERIFIED', pinned_public_key: pub, bundle: leafIndexFloat },
  { desc: 'valid_astral_emoji — signed reason carries a VALID surrogate PAIR (an astral SHIELD emoji U+1F6E1); the lone-surrogate rejection must NOT false-reject valid astral text — every verifier must return VERIFIED', expect: 'VERIFIED', pinned_public_key: pub, bundle: astralEmojiReason },
  { desc: 'valid_line_separators — signed reason carries U+2028 LINE SEPARATOR + U+2029 PARAGRAPH SEPARATOR; Go encoding/json escapes these unless the verifier un-escapes them, so this guards cross-stack canon byte-identity (an exhaustive 0..0x10FFFF sweep proved they were the only divergent chars) — every verifier must return VERIFIED', expect: 'VERIFIED', pinned_public_key: pub, bundle: lineSepReason },
];

// ── adversarial bundles (every verifier MUST return FAILED) ────────────────
const wire = (b) => JSON.parse(JSON.stringify(b));
const keySwap = (k) => { const b = wire(bundle); b.public_key = k; return b; };

const protoInjected = wire(bundle);
Object.defineProperty(protoInjected.receipts[0], '__proto__', { value: { evil: true }, enumerable: true, writable: true, configurable: true });
const extraReceiptField = wire(bundle); extraReceiptField.receipts[0].surprise = 'extra';
const missingReceiptField = wire(bundle); delete missingReceiptField.receipts[1].reason;
const extraCheckpointField = wire(bundle); extraCheckpointField.checkpoint.surprise = 'extra';
const tamperedCheckpointAlg = wire(bundle); tamperedCheckpointAlg.checkpoint.algorithm = 'Ed25519-SHA256-RFC8785';
const truncated = wire(bundle); truncated.receipts.pop(); truncated.merkle_proofs.pop(); // checkpoint still claims leaf_count=3
const reordered = wire(bundle); [reordered.receipts[0], reordered.receipts[1]] = [reordered.receipts[1], reordered.receipts[0]];
const wrongRoot = wire(bundle); wrongRoot.checkpoint.merkle_root = 'f'.repeat(64);

// ── VALIDLY-SIGNED but NON-CONFORMANT bundles ──────────────────────────────
// The "tamper after signing" fixtures above all fail on the SIGNATURE first, so they never
// isolate the STRICT schema / envelope / timestamp checks (every stack just rejects the bad
// signature). These fixtures instead build a COMPLETE, internally self-consistent SIGNED bundle
// in which exactly ONE strict invariant is violated and ALL dependent values (each receipt
// signature, leaves, proofs, checkpoint signature) are re-derived with the SAME gateway signer —
// so the only defect is the intended one, and a conformant verifier fails at exactly one step.
//
// Mirrors the engine EXACTLY: receipt signature = sign(canon(receipt minus "signature"));
// leaf = sha256(canon(full receipt incl. signature)); checkpoint signed = sign(canon(body minus
// "signature")); chain previous_receipt_hash[i] = leaf[i-1] (or "" for i=0).
const GW = 'cross-stack-gw';
const stripSig = (o) => Object.fromEntries(Object.entries(o).filter(([k]) => k !== 'signature'));
const signReceipt = (unsigned) => ({ ...unsigned, signature: signer.sign(canonicalize(stripSig(unsigned))) });
// Build a signed receipt body (15 canonical fields, no signature) for chain position i.
const receiptBody = (i, prevLeaf, over = {}) => ({
  receipt_id: `sgn-${String(i).padStart(4, '0')}`, receipt_version: SEP_RECEIPT_VERSION, algorithm: SEP_ALGORITHM,
  timestamp: `2026-05-01T00:00:0${i}.000Z`, request_id: `g${i}`, method: 'tools/call',
  tool_name: i % 2 === 0 ? 'measure_integrity' : 'revoke_artifact', decision: i % 2 === 0 ? 'PERMITTED' : 'DENIED',
  reason: `signed-${i}`, policy_reference: '', arguments_hash: '', previous_receipt_hash: prevLeaf,
  gateway_id: GW, public_key: pub, ...over,
});
// Assemble a fully self-consistent signed bundle from a list of UNSIGNED receipt bodies.
// `mutate.receipt(signedReceipt, i)` may mutate a receipt AFTER it is signed (keeping its
// signature valid over the pre-mutation canon — used for envelope/proto cases where the defect
// must NOT change the signed bytes). `mutate.envelope(bundle)` mutates the UNSIGNED envelope.
const buildSigned = (bodies, mutate = {}) => {
  let prev = '';
  const receipts = bodies.map((b, i) => {
    const body = typeof b === 'function' ? b(prev, i) : { ...b, previous_receipt_hash: prev };
    const r = signReceipt(body);
    if (mutate.receipt) mutate.receipt(r, i); // post-sign tweak (e.g. inject __proto__ own key)
    prev = leafHash(r);
    return r;
  });
  const leaves = receipts.map(leafHash);
  const root = merkleRoot(leaves);
  const proofs = leaves.map((_, i) => merkleProof(leaves, i));
  const cpBody = {
    algorithm: SEP_ALGORITHM, gateway_id: GW, generated_at: '2026-05-01T00:00:09.000Z',
    head_leaf_hash: leaves[leaves.length - 1], leaf_count: receipts.length, merkle_root: root,
  };
  const checkpoint = { ...cpBody, signature: signer.sign(canonicalize(cpBody)) };
  const b = {
    schema_version: '2.0', bundle_id: 'sgn-bundle', algorithm: SEP_ALGORITHM,
    generated_at: '2026-05-01T00:00:09.000Z', gateway_id: GW, public_key: pub, policy_reference: '',
    receipts, merkle_root: root, merkle_proofs: proofs, checkpoint, offline_capable: true,
  };
  if (mutate.envelope) mutate.envelope(b);
  return b;
};

// D1 structural: a 16th OWN key on an otherwise valid, validly-signed receipt.
const signed_extra_receipt_field = buildSigned([
  (p, i) => receiptBody(i, p, { surprise: 'extra' }), (p, i) => receiptBody(i, p),
]);
// D1 structural: a receipt MISSING the canonical 'reason' field (signed without it → 14 keys).
const signed_missing_receipt_field = buildSigned([
  (p, i) => receiptBody(i, p), (p, i) => { const r = receiptBody(i, p); delete r.reason; return r; },
]);
// D1 structural: 'reason' RENAMED to 'note' (still 15 keys, but 'reason' absent → exact-keys fail).
const signed_renamed_receipt_field = buildSigned([
  (p, i) => { const r = receiptBody(i, p); delete r.reason; r.note = 'renamed'; return r; }, (p, i) => receiptBody(i, p),
]);
// D1 structural: '__proto__' as an OWN enumerable key on a validly-signed receipt. Injected
// post-sign via defineProperty AND included in the signed canon (canonicalize treats it as an
// ordinary key) so the signature stays valid; Object.keys counts it → 16 keys → exact-keys fail.
const signed_proto_receipt_key = buildSigned([
  (p, i) => { const r = receiptBody(i, p); Object.defineProperty(r, '__proto__', { value: 'x', enumerable: true, writable: true, configurable: true }); return r; },
  (p, i) => receiptBody(i, p),
]);
// D2 signed_checkpoint: an 8th key on the checkpoint, with the checkpoint RE-SIGNED over the
// 8-key body (so the signature is valid; only the exact-keys count is wrong).
const signed_extra_checkpoint_field = (() => {
  const b = buildSigned([(p, i) => receiptBody(i, p), (p, i) => receiptBody(i, p)]);
  const cpBody = { ...stripSig(b.checkpoint), surprise: 'extra' };
  b.checkpoint = { ...cpBody, signature: signer.sign(canonicalize(cpBody)) };
  return b;
})();
// D5 envelope_consistency: the UNSIGNED bundle.gateway_id lies; all SIGNED objects (receipts,
// checkpoint) keep gateway_id='cross-stack-gw' and valid signatures.
const envelope_gateway_id_lie = buildSigned(
  [(p, i) => receiptBody(i, p), (p, i) => receiptBody(i, p)],
  { envelope: (b) => { b.gateway_id = 'attacker-gw'; } },
);
// D5 envelope_consistency: the UNSIGNED bundle.merkle_root lies (wrong 64-hex); signed objects intact.
const envelope_merkle_root_lie = buildSigned(
  [(p, i) => receiptBody(i, p), (p, i) => receiptBody(i, p)],
  { envelope: (b) => { b.merkle_root = 'a'.repeat(64); } },
);
// D3 chain_and_ordering: a validly-signed receipt whose timestamp is unparseable (Date.parse→NaN).
const signed_unparseable_timestamp = buildSigned([
  (p, i) => receiptBody(i, p), (p, i) => receiptBody(i, p, { timestamp: 'not-a-date' }),
]);
// D3 chain_and_ordering: two validly-signed receipts with DECREASING timestamps.
const signed_decreasing_timestamp = buildSigned([
  (p, i) => receiptBody(i, p, { timestamp: '2026-05-01T00:00:05.000Z' }),
  (p, i) => receiptBody(i, p, { timestamp: '2026-05-01T00:00:01.000Z' }),
]);
// T1 chain_and_ordering — CANONICAL TIMESTAMP rejection. Each bundle is fully rebuilt + RE-SIGNED with
// the gateway seed so EVERY signature/leaf/proof/checkpoint is valid and the ONLY defect is a single
// receipt timestamp that violates the mandated canonical SEP form
// (^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$ + in-range calendar fields).
// The first receipt keeps a valid canonical timestamp; the second carries the defect, so the step fails
// purely on timestamp VALIDITY (not ordering). buildSigned signs over the bad string → signature valid.
const tsAdversarial = (badTs) => buildSigned([
  (p, i) => receiptBody(i, p, { timestamp: '2026-05-01T00:00:00.000Z' }),
  (p, i) => receiptBody(i, p, { timestamp: badTs }),
]);
const ts_comma_fraction   = tsAdversarial('2026-05-01T00:00:00,500Z');       // comma decimal separator
const ts_date_only        = tsAdversarial('2026-05-01');                      // no time component
const ts_no_timezone      = tsAdversarial('2026-05-01T00:00:00.000');        // missing 'Z'
const ts_space_separator  = tsAdversarial('2026-05-01 00:00:00.000Z');       // space instead of 'T'
const ts_lowercase_z      = tsAdversarial('2026-05-01T00:00:00.000z');       // lowercase 'z'
const ts_basic_format     = tsAdversarial('20260501T000000Z');               // ISO basic (no separators, no ms)
const ts_week_date        = tsAdversarial('2026-W18-5');                      // ISO week date
// Calendar out-of-range: regex PASSES but Feb 29 2026 is invalid (2026 is not a leap year) → (b) fails.
const ts_invalid_calendar = tsAdversarial('2026-02-29T00:00:00.000Z');
// Trailing newline: Python's re `$`/.match() treats a single trailing '\n' as end-of-string and would
// WRONGLY accept "...Z\n" (JS/Go reject it). Pins all six to reject a trailing-newline timestamp identically.
const ts_trailing_newline = tsAdversarial('2026-05-01T00:00:00.000Z\n');

// T6 envelope_consistency — the UNSIGNED bundle.generated_at lies: set to a DIFFERENT valid canonical
// .sssZ value than checkpoint.generated_at. All signed objects (receipts, checkpoint) are intact, so the
// only failing step is the new envelope generated_at binding (bundle.generated_at === checkpoint.generated_at).
const envelope_generated_at_lie = buildSigned(
  [(p, i) => receiptBody(i, p), (p, i) => receiptBody(i, p)],
  { envelope: (b) => { b.generated_at = '2026-05-01T00:00:08.000Z'; } }, // checkpoint.generated_at is ...:09.000Z
);

// D6/D7 robustness: a receipt field VALUE replaced with a ~3000-deep nested array (depth bomb),
// NOT re-signed. Its purpose is robustness: every verifier MUST return FAILED (caught by the
// depth-bounded canon → controlled failure), NEVER crash with a stack overflow / RangeError.
const depthBomb = (() => {
  let nest = 0; for (let i = 0; i < 3000; i++) nest = [nest];
  const b = buildSigned([(p, i) => receiptBody(i, p), (p, i) => receiptBody(i, p)]);
  b.receipts[0].reason = nest; // deeply-nested value where a string is expected
  return b;
})();

// Identity-key UNIVERSAL FORGERY (from nothing, no private key): under the Ed25519 identity point
// the signature encode(identity)||0 verifies for ANY message. This bundle is fully self-consistent
// (chain + Merkle + checkpoint all recomputed) and EVERY signature "verifies" under the identity key
// — so it is caught ONLY by small-order rejection at the structural floor. Removing that rejection in
// any verifier makes this VERIFY; that is exactly what the mutation test exercises.
const IDENTITY = '01' + '00'.repeat(31);
const FORGED_SIG = '01' + '00'.repeat(63); // R = identity encoding (32B) || S = 0 (32B)
const forgedReceipt = (prevLeaf, i) => ({
  receipt_id: `forge-${i}`, receipt_version: SEP_RECEIPT_VERSION, algorithm: SEP_ALGORITHM,
  timestamp: `2026-04-01T00:00:0${i}.000Z`, request_id: `f${i}`, method: 'tools/call',
  tool_name: 'exfiltrate_secrets', decision: 'PERMITTED', reason: 'forged', policy_reference: '',
  arguments_hash: '', previous_receipt_hash: prevLeaf, gateway_id: 'cross-stack-gw',
  public_key: IDENTITY, signature: FORGED_SIG,
});
const fReceipts = [];
{ let prev = ''; for (let i = 0; i < 2; i++) { const r = forgedReceipt(prev, i); fReceipts.push(r); prev = leafHash(r); } }
const fLeaves = fReceipts.map(leafHash);
const identityForgery = {
  schema_version: '2.0', bundle_id: 'forge-bundle', algorithm: SEP_ALGORITHM,
  generated_at: '2026-04-01T00:00:09.000Z', gateway_id: 'cross-stack-gw', public_key: IDENTITY,
  policy_reference: '', receipts: fReceipts, merkle_root: merkleRoot(fLeaves),
  merkle_proofs: fLeaves.map((_, i) => merkleProof(fLeaves, i)),
  checkpoint: { algorithm: SEP_ALGORITHM, gateway_id: 'cross-stack-gw', generated_at: '2026-04-01T00:00:09.000Z', head_leaf_hash: fLeaves[fLeaves.length - 1], leaf_count: fReceipts.length, merkle_root: merkleRoot(fLeaves), signature: FORGED_SIG },
  offline_capable: true,
};

// Ed25519 small-order encodings (order | 8) + a non-canonical (y >= p) encoding.
const SMALL_ORDER = [
  '00'.repeat(32), '00'.repeat(31) + '80', '01' + '00'.repeat(31), '01' + '00'.repeat(30) + '80',
  'ec' + 'ff'.repeat(30) + '7f', 'ec' + 'ff'.repeat(31),
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
];

// ── ROUND-5 cross-stack closures (two verdict-disagreements; neither is a forgery) ─────────────
// C1 MERKLE DIRECTIONS STRICTNESS. `directions` is UNSIGNED, and JS/Go previously treated any
// non-"left" token as a "right" fallthrough and looped only over `siblings`, so a rewritten token
// ("right"->"RIGHT") or a length-mismatched array still walked to the correct root and VERIFIED on
// JS/Go while Python FAILED. Both fixtures start from a VALID 2-leaf bundle whose proof[0] direction
// is genuinely "right" (so the lax fallthrough would otherwise still walk correctly — the exact case
// that exposed the split) and apply ONE UNSIGNED edit (directions is not signed → do NOT re-sign).
// After the port, every stack rejects them at the merkle step.
const mtBase = buildSigned([(p, i) => receiptBody(i, p), (p, i) => receiptBody(i, p)]); // proof[0].directions === ["right"]
const mt_direction_token = (() => { const b = wire(mtBase); b.merkle_proofs[0].directions[0] = 'RIGHT'; return b; })();
const mt_direction_length = (() => { const b = wire(mtBase); b.merkle_proofs[0].directions = []; return b; })(); // len 0 != siblings len 1
const mt_sibling_uppercase = (() => { const b = wire(mtBase); b.merkle_proofs[0].siblings[0] = b.merkle_proofs[0].siblings[0].toUpperCase(); return b; })(); // siblings hex-decode is case-insensitive

// C2 LONE-SURROGATE REJECTION (JS canon only; Go + Python already reject). A signed string carrying
// an UNPAIRED UTF-16 surrogate is INVALID Unicode that Go/Python cannot UTF-8-encode → they reject
// the bundle; JS previously mapped it to U+FFFD self-consistently and VERIFIED (a 3-vs-3 split). The
// JS canon now THROWS on a lone surrogate (caught by the never-throw try/catch → verdict FAILED).
// Because canon throws, the bundle cannot be SIGNED over the surrogate — so (like depth_bomb) it is
// built+signed clean and the lone high surrogate is injected into a receipt reason POST-SIGN. The
// engine throws in canon during verification → the single step surfaced is 'verifier_exception';
// the portable contract for every stack is verdict=FAILED.
const signed_lone_surrogate = (() => {
  const b = buildSigned([(p, i) => receiptBody(i, p), (p, i) => receiptBody(i, p)]);
  b.receipts[0].reason = 'blocked ' + String.fromCharCode(0xD800); // unpaired high surrogate
  return b;
})();

const adversarial = [
  { desc: 'identity-key UNIVERSAL forgery (from nothing; all sigs verify under identity — caught ONLY by small-order rejection)', expect: 'FAILED', failing_step: 'structural', bundle: identityForgery },
  { desc: '"__proto__"-injected receipt', expect: 'FAILED', failing_step: 'structural', bundle: protoInjected },
  { desc: 'extra/unknown field on a receipt', expect: 'FAILED', failing_step: 'structural', bundle: extraReceiptField },
  { desc: 'receipt missing a canonical field', expect: 'FAILED', failing_step: 'structural', bundle: missingReceiptField },
  { desc: 'extra/unknown field on the checkpoint', expect: 'FAILED', failing_step: 'signed_checkpoint', bundle: extraCheckpointField },
  { desc: 'checkpoint with tampered algorithm value', expect: 'FAILED', failing_step: 'signed_checkpoint', bundle: tamperedCheckpointAlg },
  { desc: 'truncated bundle (dropped a receipt; checkpoint leaf_count/head no longer match)', expect: 'FAILED', failing_step: 'signed_checkpoint', bundle: truncated },
  { desc: 'reordered receipts (chain linkage broken)', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: reordered },
  { desc: 'tampered checkpoint merkle_root', expect: 'FAILED', failing_step: 'signed_checkpoint', bundle: wrongRoot },
  { desc: 'non-canonical public key (y >= p)', expect: 'FAILED', failing_step: 'structural', bundle: keySwap('ed' + 'ff'.repeat(30) + '7f') },
  ...SMALL_ORDER.map((k, i) => ({ desc: `small-order public key #${i} (${k.slice(0, 8)}…) — identity/from-nothing-forgery class`, expect: 'FAILED', failing_step: 'structural', bundle: keySwap(k) })),
  // VALIDLY-SIGNED but NON-CONFORMANT: every signature/leaf/proof/checkpoint is re-derived so the
  // ONLY defect is the named one — these isolate the strict schema / envelope / timestamp checks
  // (the "tamper-after-signing" fixtures above instead fail on the signature for every stack).
  { desc: 'signed_extra_receipt_field — a 16th own key on a validly-signed receipt; whole bundle rebuilt+resigned', expect: 'FAILED', failing_step: 'structural', bundle: signed_extra_receipt_field },
  { desc: "signed_missing_receipt_field — a validly-signed receipt missing 'reason'; rebuilt+resigned", expect: 'FAILED', failing_step: 'structural', bundle: signed_missing_receipt_field },
  { desc: "signed_renamed_receipt_field — 'reason' renamed to 'note' on a validly-signed receipt; rebuilt+resigned", expect: 'FAILED', failing_step: 'structural', bundle: signed_renamed_receipt_field },
  { desc: "signed_proto_receipt_key — '__proto__' as an own key on a validly-signed receipt; rebuilt+resigned", expect: 'FAILED', failing_step: 'structural', bundle: signed_proto_receipt_key },
  { desc: 'signed_extra_checkpoint_field — an 8th key on the checkpoint, checkpoint re-signed over the 8-key body', expect: 'FAILED', failing_step: 'signed_checkpoint', bundle: signed_extra_checkpoint_field },
  { desc: 'envelope_gateway_id_lie — UNSIGNED bundle.gateway_id set to a different value; all signed objects intact', expect: 'FAILED', failing_step: 'envelope_consistency', bundle: envelope_gateway_id_lie },
  { desc: 'envelope_merkle_root_lie — UNSIGNED bundle.merkle_root set to a wrong 64-hex; signed objects intact', expect: 'FAILED', failing_step: 'envelope_consistency', bundle: envelope_merkle_root_lie },
  { desc: 'signed_unparseable_timestamp — a validly-signed receipt timestamp set to "not-a-date"; rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: signed_unparseable_timestamp },
  { desc: 'signed_decreasing_timestamp — two validly-signed receipts with decreasing timestamps; rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: signed_decreasing_timestamp },
  // T1 canonical-timestamp rejections (rebuilt+resigned; ONLY defect is the non-canonical timestamp string).
  { desc: 'ts_comma_fraction — receipt timestamp uses a comma decimal separator (2026-05-01T00:00:00,500Z); rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: ts_comma_fraction },
  { desc: 'ts_date_only — receipt timestamp is a bare date with no time component (2026-05-01); rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: ts_date_only },
  { desc: 'ts_no_timezone — receipt timestamp omits the trailing Z (2026-05-01T00:00:00.000); rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: ts_no_timezone },
  { desc: 'ts_space_separator — receipt timestamp uses a space instead of T ("2026-05-01 00:00:00.000Z"); rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: ts_space_separator },
  { desc: 'ts_lowercase_z — receipt timestamp uses a lowercase z (2026-05-01T00:00:00.000z); rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: ts_lowercase_z },
  { desc: 'ts_basic_format — receipt timestamp is ISO basic format with no separators/ms (20260501T000000Z); rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: ts_basic_format },
  { desc: 'ts_week_date — receipt timestamp is an ISO week date (2026-W18-5); rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: ts_week_date },
  { desc: 'ts_invalid_calendar — receipt timestamp is calendar-invalid (Feb 29 2026 is not a leap year: 2026-02-29T00:00:00.000Z); regex passes but the integer calendar check fails; rebuilt+resigned', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: ts_invalid_calendar },
  { desc: 'ts_trailing_newline — canonical timestamp with a single trailing newline (2026-05-01T00:00:00.000Z\\n); rebuilt+resigned; pins the Python re $-vs-fullmatch divergence closed', expect: 'FAILED', failing_step: 'chain_and_ordering', bundle: ts_trailing_newline },
  // T6 envelope_consistency — the UNSIGNED bundle.generated_at lies (differs from the signed checkpoint.generated_at); all signed objects intact.
  { desc: 'envelope_generated_at_lie — UNSIGNED bundle.generated_at set to a different valid .sssZ value than checkpoint.generated_at; all signed objects intact', expect: 'FAILED', failing_step: 'envelope_consistency', bundle: envelope_generated_at_lie },
  // depth_bomb is a ROBUSTNESS case (NOT re-signed): a ~3000-deep nested array in a receipt field.
  // The depth-bounded canon throws a CONTROLLED error → the verifier returns FAILED (never a stack
  // overflow / crash). On this engine the throw happens during canonicalization, surfacing as the
  // try/catch step 'verifier_exception'; the portable contract for every stack is verdict=FAILED.
  { desc: 'depth_bomb — receipt field value is a ~3000-deep nested array (NOT re-signed); every verifier must return FAILED, never crash', expect: 'FAILED', failing_step: 'verifier_exception', bundle: depthBomb },
  // ROUND-5 C1 merkle directions strictness — UNSIGNED `directions` edits on a valid 2-leaf bundle
  // whose proof[0] direction is genuinely "right"; the lax JS/Go fallthrough would otherwise still
  // walk correctly and VERIFY. After the port every stack fails at the merkle step.
  { desc: 'mt_direction_token — one merkle_proofs[0].directions[0] rewritten "right"->"RIGHT" (UNSIGNED edit; directions is not signed; NOT re-signed); a non-literal direction token must fail the merkle step on every stack', expect: 'FAILED', failing_step: 'merkle_and_bijection', bundle: mt_direction_token },
  { desc: 'mt_direction_length — one proof\'s directions array length != its siblings length (directions[0] dropped; UNSIGNED edit; NOT re-signed); a length-mismatched directions array must fail the merkle step on every stack', expect: 'FAILED', failing_step: 'merkle_and_bijection', bundle: mt_direction_length },
  { desc: 'mt_sibling_uppercase - one merkle_proofs[0].siblings[0] hex UPPERCASED (UNSIGNED edit, NOT re-signed). Siblings flow through a case-insensitive hex decode, so the uppercase yields identical bytes; JS/Go/aga-verify previously VERIFIED while Python (lowercase is_hex guard) FAILED - a cross-stack verdict split. After adding the lowercase 64-hex sibling guard to every stack, all six FAIL the merkle step.', expect: 'FAILED', failing_step: 'merkle_and_bijection', bundle: mt_sibling_uppercase },
  // ROUND-5 C2 lone-surrogate rejection — a receipt reason with an unpaired UTF-16 high surrogate.
  // Go/Python cannot UTF-8-encode it (reject); the JS canon now throws (caught -> FAILED). The engine
  // throws in canon during verification, surfacing as 'verifier_exception'; portable contract is FAILED.
  { desc: 'signed_lone_surrogate — receipt reason contains an unpaired UTF-16 high surrogate (String.fromCharCode(0xD800)); injected POST-SIGN (canon throws over it so it cannot be re-signed); invalid Unicode that Go/Python cannot encode and the JS canon now rejects; verdict=FAILED on every stack', expect: 'FAILED', failing_step: 'verifier_exception', bundle: signed_lone_surrogate },
];

// Map every historical finding to the fixture/test that permanently locks it.
const finding_map = {
  'identity-key / from-nothing forgery': 'adversarial: identity-key UNIVERSAL forgery (self-consistent, all sigs verify under identity — isolates the small-order rejection; flips the mutation test)',
  'all 10 small-order key encodings': 'adversarial: small-order public key #0..#9 (encoding rejection at the structural floor)',
  'non-canonical key (y >= p)': 'adversarial: non-canonical public key (y >= p)',
  '__proto__ injection': 'adversarial: "__proto__"-injected receipt',
  'extra/unknown receipt field': 'adversarial: extra/unknown field on a receipt',
  'missing canonical field': 'adversarial: receipt missing a canonical field',
  'extra checkpoint field / tampered algorithm / tampered merkle_root': 'adversarial: 3 checkpoint fixtures',
  'truncation': 'adversarial: truncated bundle',
  'reordering': 'adversarial: reordered receipts',
  'integer-key canon divergence': 'canonical[]: integer-like + nested integer-like vectors (byte-equality; tests/sep/cross-stack-vectors.test.ts + reaudit-fixes.test.ts) — canon-level, not a bundle-verdict case',
  'tool-argument depth-bomb (uncanonicalizable -> DENIED+recorded, never dropped/forwarded)': 'server-side fail-closed: tests/proxy/dos-failclosed.test.ts — emit-path behavior, not a verify-bundle case',
  'strict-timestamp rejection (NaN / decreasing)': 'tests/sep/reaudit-fixes.test.ts — re-signed timestamps; verdict locked in-repo',
  'validly-signed-but-non-conformant: strict receipt schema (extra/missing/renamed/__proto__ field)': 'adversarial: signed_extra_receipt_field, signed_missing_receipt_field, signed_renamed_receipt_field, signed_proto_receipt_key — fully re-signed so the signature is valid and only the strict exact-keys check fails (structural)',
  'validly-signed-but-non-conformant: strict checkpoint schema (extra field)': 'adversarial: signed_extra_checkpoint_field — checkpoint re-signed over its 8-key body; only the exact-keys check fails (signed_checkpoint)',
  'validly-signed-but-non-conformant: envelope consistency (unsigned gateway_id / merkle_root lie)': 'adversarial: envelope_gateway_id_lie, envelope_merkle_root_lie — all signed objects intact; only the UNSIGNED envelope disagrees with the signed/recomputed values (envelope_consistency)',
  'validly-signed-but-non-conformant: strict timestamps (unparseable / decreasing)': 'adversarial: signed_unparseable_timestamp, signed_decreasing_timestamp — re-signed receipts whose timestamps are NaN / decreasing (chain_and_ordering)',
  'robustness: receipt-field depth bomb (must FAIL, never crash)': 'adversarial: depth_bomb — ~3000-deep nested value; depth-bounded canon → controlled FAILED (never a stack overflow). Portable contract is verdict=FAILED on every stack.',
  'cross-stack timestamp unification (native date parsers disagreed)': 'adversarial: ts_comma_fraction, ts_date_only, ts_no_timezone, ts_space_separator, ts_lowercase_z, ts_basic_format, ts_week_date, ts_invalid_calendar — re-signed receipts whose ONLY defect is a non-canonical timestamp string; every stack rejects identically via the [0-9]-class regex + pure-integer calendar check (chain_and_ordering).',
  'cross-stack numeric unification (JCS integral-float collapse; Go/Python kept 2.0)': 'valid_variants: leaf_count_float (checkpoint.leaf_count 2 -> 2.0) and leaf_index_float (a proof leaf_index 0 -> 0.0) — JCS-equivalent re-encodings injected by raw-JSON surgery on the serialized output (NOT re-signed); every stack canonicalizes the integral float to its shortest integer form so the signature/binding/bijection still verify (VERIFIED).',
  'unsigned envelope generated_at lie': 'adversarial: envelope_generated_at_lie — UNSIGNED bundle.generated_at differs from the signed checkpoint.generated_at; all signed objects intact; the extended envelope binding (bundle.generated_at === checkpoint.generated_at) catches it (envelope_consistency).',
  'round-5 C1: merkle directions strictness (UNSIGNED directions; JS/Go non-"left" fallthrough vs Python strict)': 'adversarial: mt_direction_token (one "right"->"RIGHT") and mt_direction_length (directions length != siblings length) — UNSIGNED edits on a valid 2-leaf bundle whose proof[0] direction is genuinely "right"; before the port JS/Go still walked to the correct root and VERIFIED while Python FAILED; after requiring directions to be a same-length array of literal "left"/"right" tokens, every stack fails at the merkle step (merkle_and_bijection).',
  'round-5 C2: lone-surrogate rejection (JS canon mapped to U+FFFD and VERIFIED; Go/Python could not UTF-8-encode and rejected)': 'adversarial: signed_lone_surrogate — a receipt reason carrying an unpaired UTF-16 high surrogate (injected post-sign because canon throws over it); the JS canon now throws on a lone surrogate (caught -> verdict FAILED, surfaced as verifier_exception), matching Go/Python; the companion valid_variant valid_astral_emoji proves a VALID surrogate PAIR (astral emoji) still VERIFIES — the fix does not false-reject valid astral text.',
};

// ── self-check before writing ──────────────────────────────────────────────
const vok = verifySepBundle(bundle, pub);
if (vok.verdict !== 'VERIFIED' || !vok.issuerVerified) throw new Error('valid bundle did not verify');
for (const v of valid_variants) {
  const r = verifySepBundle(v.bundle, pub);
  if (r.verdict !== 'VERIFIED' || !r.issuerVerified) throw new Error(`valid variant did not verify: ${v.desc}`);
}
for (const a of adversarial) {
  const r = verifySepBundle(a.bundle, pub);
  if (r.verdict !== 'FAILED') throw new Error(`adversarial vector unexpectedly passed: ${a.desc}`);
  const step = r.steps.find((s) => s.name === a.failing_step);
  if (!step || step.ok) throw new Error(`adversarial "${a.desc}" did not fail at step ${a.failing_step}`);
}

const vectors = {
  algorithm: 'Ed25519-SHA256-JCS',
  note: 'Portable cross-stack conformance vectors: every conformant SEP verifier must reproduce identical canonical bytes and identical verdicts. Some findings (integer-key canon, depth-bomb, timestamp) are locked by canon vectors / in-repo tests rather than bundle-verdict fixtures — see finding_map.',
  generated_by: 'fixtures/cross-stack/generate.mjs (deterministic: seed=32x0x07, fixed clock/idGen)',
  canonical,
  valid_bundle: { pinned_public_key: pub, expect: 'VERIFIED', bundle },
  valid_variants,
  adversarial,
  finding_map,
};

// ── JCS integral-float surgery on the SERIALIZED output (T2/T3/T4) ──────────
// A JS number cannot retain a trailing ".0", so leaf_count_float / leaf_index_float are injected by
// raw-JSON string surgery on the pretty-printed output text (not on the in-memory objects, which stay
// integer-valued so the self-check above verifies the AUTHENTIC bundle). Each edit is SCOPED to its
// variant bundle via that bundle's UNIQUE auto-assigned bundle_id, and asserts exactly one substitution
// so an ambiguous/no-op edit fails loudly. The committed vectors.json then literally carries "2.0"/"0.0",
// the JCS-equivalent value every conformant verifier must canonicalize back to the signed integer.
let out = JSON.stringify(vectors, null, 2);
const floatEdit = (text, anchor, find, repl) => {
  const at = text.indexOf(anchor);
  if (at < 0) throw new Error(`float surgery: anchor not found: ${anchor}`);
  const rel = text.slice(at).indexOf(find);
  if (rel < 0) throw new Error(`float surgery: target not found after anchor: ${find}`);
  const idx = at + rel;
  // Guard against ambiguity: the target must not also occur AFTER this bundle within the next bundle.
  return text.slice(0, idx) + repl + text.slice(idx + find.length);
};
// leaf_count_float: checkpoint.leaf_count 2 -> 2.0 (leaf_count appears once per bundle).
out = floatEdit(out, '"bundle_id": "lcf-0002"', '"leaf_count": 2', '"leaf_count": 2.0');
// leaf_index_float: the first proof's leaf_index 0 -> 0.0.
out = floatEdit(out, '"bundle_id": "lif-0002"', '"leaf_index": 0', '"leaf_index": 0.0');
// Verify the surgery landed exactly once each and the parsed result is still well-formed JSON.
if ((out.match(/"leaf_count": 2\.0/g) || []).length !== 1) throw new Error('leaf_count_float surgery: expected exactly one "2.0"');
if ((out.match(/"leaf_index": 0\.0/g) || []).length !== 1) throw new Error('leaf_index_float surgery: expected exactly one "0.0"');
JSON.parse(out); // must remain parseable (2.0 / 0.0 are valid JSON numbers)

writeFileSync(new URL('./vectors.json', import.meta.url), out + '\n');
console.log(`wrote vectors.json: ${canonical.length} canonical + ${1 + valid_variants.length} valid + ${adversarial.length} adversarial (self-check passed)`);
