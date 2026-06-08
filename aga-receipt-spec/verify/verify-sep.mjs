/**
 * Reference verifier for the canonical AGA SEP Evidence Bundle.
 * Normative implementation of CANONICAL_CONSTRUCTION_v2.md §6 over §1-5.
 * Zero external deps (Node 18+ crypto: Ed25519 + SHA-256). This is the reference
 * the published @attested-intelligence/aga-verify@2.0.0 mirrors.
 *
 * Library:  import { verifySepBundle } from './verify-sep.mjs'
 * CLI:      node verify/verify-sep.mjs <bundle.json> [--pubkey <64-hex>]
 */
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';

const ALGO = 'Ed25519-SHA256-JCS';
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');

// Exact canonical field sets — strict-schema floor (mirrors src/sep/receipt.ts + checkpoint.ts).
const RECEIPT_FIELDS = [
  'receipt_id', 'receipt_version', 'algorithm', 'timestamp', 'request_id',
  'method', 'tool_name', 'decision', 'reason', 'policy_reference',
  'arguments_hash', 'previous_receipt_hash', 'gateway_id', 'public_key', 'signature',
];
const CHECKPOINT_FIELDS = [
  'algorithm', 'gateway_id', 'generated_at', 'head_leaf_hash', 'leaf_count', 'merkle_root', 'signature',
];

// Depth-bounded canon (anti-DoS): input nested beyond MAX_CANON_DEPTH throws a CONTROLLED error
// well before a native stack overflow, so verifySepBundle's try/catch turns it into a FAILED verdict
// instead of crashing. Mirrors src/sep/canonical.ts byte-for-byte (string concat, lexicographic keys).
const MAX_CANON_DEPTH = 100;
// Lone (unpaired) UTF-16 surrogate detector: a high surrogate not followed by a low surrogate, or a
// low surrogate not preceded by a high surrogate. Such a string is INVALID Unicode that Go and Python
// cannot UTF-8-encode (so they reject the bundle). JS would otherwise map it to U+FFFD self-consistently
// and VERIFY — a cross-stack split. Throw on it (caught by verifySepBundle's try/catch -> FAILED) so all
// six agree. Valid surrogate PAIRS (astral chars / emoji) do NOT match and canonicalize unchanged. [C2]
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const canon = (o) => {
  const rec = (v, depth) => {
    if (depth > MAX_CANON_DEPTH) throw new Error(`canon: input nesting exceeds ${MAX_CANON_DEPTH} levels`);
    if (typeof v === 'string' && LONE_SURROGATE.test(v)) throw new Error('canonicalize: lone surrogate');
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map((e) => rec(e, depth + 1)).join(',') + ']';
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + rec(v[k], depth + 1)).join(',') + '}';
  };
  return rec(o, 0);
};
const sha = (b) => createHash('sha256').update(b).digest('hex');
const u8 = (s) => Buffer.from(s, 'utf8');
const leaf = (r) => sha(u8(canon(r)));                                   // §3 no-prefix, full receipt
const node = (l, r) => sha(Buffer.concat([Buffer.from(l, 'hex'), Buffer.from(r, 'hex')])); // §5 raw bytes
const strip = (o, f) => Object.fromEntries(Object.entries(o).filter(([k]) => k !== f));
const isHex = (h, n) => typeof h === 'string' && new RegExp(`^[0-9a-f]{${n}}$`).test(h);

// Canonical SEP timestamp validation (T1) — NO native date parsing (Date.parse/etc diverge across
// stacks). A timestamp is VALID iff it matches the exact fixed-width UTC .sssZ form AND its calendar
// fields are in range, checked with PURE INTEGER ARITHMETIC. This is exactly what Date.prototype
// .toISOString() emits. [0-9] literal class (NOT \d, which matches Unicode digits in some engines).
const TS_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const isLeap = (y) => (y % 4 === 0) && ((y % 100 !== 0) || (y % 400 === 0));
const daysInMonth = (y, m) => [31, isLeap(y) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];
const isValidTimestamp = (ts) => {
  if (typeof ts !== 'string' || !TS_RE.test(ts)) return false;
  const year = +ts.slice(0, 4);
  const month = +ts.slice(5, 7);
  const day = +ts.slice(8, 10);
  const hour = +ts.slice(11, 13);
  const minute = +ts.slice(14, 16);
  const second = +ts.slice(17, 19);
  if (month < 1 || month > 12) return false;
  if (day < 1 || day > daysInMonth(year, month)) return false;
  if (hour > 23) return false;
  if (minute > 59) return false;
  if (second > 59) return false;
  return true;
};

/**
 * Strict-schema floor: the object must carry EXACTLY the canonical fields — no extra, missing,
 * renamed, duplicate, or "__proto__"-injected key. Object.keys counts a JSON-parsed "__proto__"
 * as an own key, so a 16th key fails the count. Cross-stack-robust: every conformant verifier
 * rejects the identical bundles.
 */
const hasExactKeys = (o, fields) => {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  const keys = Object.keys(o);
  return keys.length === fields.length && fields.every((f) => Object.prototype.hasOwnProperty.call(o, f));
};

// Ed25519 points of order dividing 8 are trivially forgeable (e.g. identity admits R=A,S=0
// universal forgery); reject them. 10 canonical encodings + non-canonical (y>=p) via isCanonicalY.
const SMALL_ORDER_KEYS = new Set([
  '00'.repeat(32), '00'.repeat(31) + '80',
  '01' + '00'.repeat(31), '01' + '00'.repeat(30) + '80',
  'ec' + 'ff'.repeat(30) + '7f', 'ec' + 'ff'.repeat(31),
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
]);
const ED25519_P = (1n << 255n) - 19n;
const isCanonicalY = (hex) => {
  const b = Buffer.from(hex, 'hex');
  let y = 0n;
  for (let i = 0; i < 32; i++) y |= BigInt(i === 31 ? (b[i] & 0x7f) : b[i]) << BigInt(8 * i);
  return y < ED25519_P;
};
function wellFormedKey(hex) {
  if (!isHex(hex, 64) || SMALL_ORDER_KEYS.has(hex) || !isCanonicalY(hex)) return false;
  try { createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(hex, 'hex')]), format: 'der', type: 'spki' }); return true; }
  catch { return false; }
}
function sigOk(pubHex, msg, sigHex) {
  if (!wellFormedKey(pubHex) || !isHex(sigHex, 128) || /^0+$/.test(sigHex)) return false;
  try { return edVerify(null, u8(msg), createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(pubHex, 'hex')]), format: 'der', type: 'spki' }), Buffer.from(sigHex, 'hex')); }
  catch { return false; }
}

/** Returns { verdict:'VERIFIED'|'FAILED', issuerVerified, pinned, steps:{name,ok}[] }. */
export function verifySepBundle(bundle, expectedPublicKey) {
  // Robust contract (D6): a malformed/hostile bundle (depth bomb, type confusion, missing
  // structure, non-string where string expected) yields a FAILED verdict — NEVER a thrown
  // exception / crash / stack overflow.
  const pinned = isHex(expectedPublicKey, 64);
  try {
    const steps = [];
    const add = (name, ok) => { steps.push({ name, ok }); return ok; };
    const receipts = Array.isArray(bundle?.receipts) ? bundle.receipts : [];
    const proofs = Array.isArray(bundle?.merkle_proofs) ? bundle.merkle_proofs : [];
    const pub = bundle?.public_key;

    // §6.1 structural floor — incl. STRICT receipt schema (exactly the 15 canonical fields;
    // rejects extra/unknown keys and "__proto__" injection on every signed receipt). [D1]
    add('structural',
      bundle?.algorithm === ALGO && wellFormedKey(pub)
      && receipts.length > 0 && proofs.length === receipts.length
      && receipts.every((r) => hasExactKeys(r, RECEIPT_FIELDS)));

    // §6.2 receipt signatures (against the bundle key; provenance handled in §6.6)
    add('receipt_signatures', receipts.length > 0 && receipts.every((r) => sigOk(pub, canon(strip(r, 'signature')), r.signature)));

    // §6.3 chain + ordering — canonical timestamps (T1): must match the exact .sssZ UTC form with
    // in-range calendar fields (pure integer arithmetic, NO native date parser), and be
    // non-decreasing. [D3]
    const leaves = receipts.map(leaf);
    let chain = receipts.length > 0;
    let prevTs = null;
    for (let i = 0; i < receipts.length; i++) {
      const expectPrev = i === 0 ? '' : leaves[i - 1];
      if ((receipts[i].previous_receipt_hash || '') !== expectPrev) chain = false;
      // Ordering is enforced cryptographically by the chain linkage above. request_id is the
      // upstream request id (string|number|null), informational, NOT a sequence counter.
      // Canonical timestamps: a ts that fails the regex or calendar-range check is a failure, and
      // because the form is fixed-width zero-padded UTC, ordering is a PLAIN STRING (lexicographic)
      // compare — ts[i] >= ts[i-1], EQUAL allowed. The first receipt only needs to be VALID.
      const ts = receipts[i].timestamp;
      if (!isValidTimestamp(ts)) chain = false;
      else {
        if (prevTs !== null && ts < prevTs) chain = false;
        prevTs = ts;
      }
    }
    add('chain_and_ordering', chain);

    // §6.4 merkle: recompute leaf from content, walk proof, single root, index bijection,
    // and require each proof's OWN claimed merkle_root to equal what it walks to. [D4]
    let root = null, merkle = proofs.length === receipts.length && proofs.length > 0;
    const seen = new Set();
    for (let i = 0; i < proofs.length; i++) {
      const p = proofs[i]; seen.add(p.leaf_index);
      const recomputed = receipts[p.leaf_index] !== undefined ? leaves[p.leaf_index] : null;
      if (recomputed === null || recomputed !== p.leaf_hash) merkle = false;
      let cur = p.leaf_hash;
      // directions is UNSIGNED. Require it to be a well-formed array: same length as siblings and every
      // element exactly the literal "left" or "right" (reject "RIGHT", "", 0, null, missing, any other
      // token). Without this, a non-"left" token falls through the ternary to the "right" branch and a
      // rewritten "right"->"RIGHT" still walks to the correct root and VERIFIES on JS/Go while Python
      // FAILS — a cross-stack split. After this guard a malformed directions array FAILS on all six. [C1]
      const sib = Array.isArray(p.siblings) ? p.siblings : [];
      const dir = Array.isArray(p.directions) ? p.directions : [];
      if (dir.length !== sib.length || !dir.every((d) => d === 'left' || d === 'right')) merkle = false;
      for (let j = 0; j < sib.length; j++) cur = dir[j] === 'left' ? node(sib[j], cur) : node(cur, sib[j]);
      if (p.merkle_root !== cur) merkle = false;          // the proof's own claimed root must match what it walks to (L-7)
      if (root === null) root = cur; else if (root !== cur) merkle = false;
    }
    const bijection = seen.size === receipts.length && [...seen].every((n) => Number.isInteger(n) && n >= 0 && n < receipts.length);
    add('merkle_and_bijection', merkle && bijection);

    // §6.5 mandatory signed checkpoint — STRICT schema (exactly the 7 canonical fields) + the
    // bound algorithm value, then signature + root/count/head binding. [D2]
    const cp = bundle?.checkpoint;
    let cpOk = false;
    if (hasExactKeys(cp, CHECKPOINT_FIELDS)) {
      cpOk = cp.algorithm === ALGO
        && sigOk(pub, canon(strip(cp, 'signature')), cp.signature)
        && root !== null && cp.merkle_root === root
        && cp.leaf_count === receipts.length
        && cp.head_leaf_hash === (leaves.length ? leaves[leaves.length - 1] : '');
    }
    add('signed_checkpoint', cpOk);

    // §6.5b envelope consistency: per-receipt identity + the UNSIGNED envelope must agree with
    // the signed/recomputed values, so nothing outside the signed objects can mislead a consumer
    // that reads the envelope (M-1/M-2/L-3). [D5]
    const cpGatewayId = (cp && typeof cp === 'object') ? cp.gateway_id : undefined;
    const cpGeneratedAt = (cp && typeof cp === 'object') ? cp.generated_at : undefined;
    add('envelope_consistency',
      receipts.length > 0
      && receipts.every((r) => r.public_key === pub)               // every receipt is signed under the bundle key (L-3)
      && receipts.every((r) => r.gateway_id === bundle?.gateway_id) // receipts <-> envelope gateway_id
      && cpGatewayId === bundle?.gateway_id                         // checkpoint <-> envelope gateway_id (M-2)
      && cpGeneratedAt === bundle?.generated_at                     // checkpoint <-> envelope generated_at (T6: closes unsigned-envelope generated_at lie)
      && root !== null && bundle?.merkle_root === root);            // envelope merkle_root <-> recomputed (M-1)

    // §6.6 provenance (only when pinned)
    const issuerVerified = pinned && pub === expectedPublicKey;
    if (pinned) add('gateway_key_match', issuerVerified);

    const verdict = steps.every((s) => s.ok) ? 'VERIFIED' : 'FAILED';
    return { verdict, issuerVerified, pinned, steps };
  } catch (e) {
    return { verdict: 'FAILED', issuerVerified: false, pinned, steps: [{ name: 'verifier_exception', ok: false }] };
  }
}

// CLI — exit 0 IFF VERIFIED, exit 1 IFF FAILED. Malformed JSON / unreadable content / any
// exception on the parse+verify path => FAILED line + exit 1 (never an uncaught stack trace,
// never exit 2). A missing bundle argument is a usage error and MAY exit 2. [D8]
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('verify-sep.mjs')) {
  const args = process.argv.slice(2);
  const file = args.find((a) => !a.startsWith('--'));
  const pk = args.includes('--pubkey') ? args[args.indexOf('--pubkey') + 1] : undefined;
  if (!file) { console.error('usage: node verify/verify-sep.mjs <bundle.json> [--pubkey <64-hex>]'); process.exit(2); }
  try {
    const { readFileSync } = await import('node:fs');
    const r = verifySepBundle(JSON.parse(readFileSync(file, 'utf8')), pk);
    for (const s of r.steps) console.log(`  ${s.ok ? 'PASS' : 'FAIL'}  ${s.name}`);
    // Suffix reflects the VERDICT: only a VERIFIED bundle gets a provenance/integrity tag; a FAILED
    // bundle prints just "FAILED" (never "FAILED (provenance verified)").
    const tail = r.verdict === 'VERIFIED' ? (r.pinned ? ' (provenance verified)' : ' (integrity only; no key pinned)') : '';
    console.log(`OVERALL: ${r.verdict}${tail}`);
    process.exit(r.verdict === 'VERIFIED' ? 0 : 1);
  } catch (e) {
    console.log('OVERALL: FAILED (could not parse/verify bundle)');
    process.exit(1);
  }
}
