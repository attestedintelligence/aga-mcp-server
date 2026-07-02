/**
 * AGA Independent Verifier (@attested-intelligence/aga-verify)
 *
 * Standalone, dependency-FREE verification of canonical AGA SEP Evidence Bundles.
 * Imports ZERO modules from the AGA codebase and ZERO third-party packages — only
 * Node's built-in crypto (Ed25519 + SHA-256). The trust chain dead-ends at the
 * Node runtime and the gateway public key you pin; nothing else.
 *
 * Normative construction: aga-receipt-spec/CANONICAL_CONSTRUCTION_v2.md.
 * What a PASS proves: every PRESENT receipt is authentic, correctly chained,
 * Merkle-included under a gateway-SIGNED checkpoint, and (when --pubkey is given)
 * issued by that pinned key. A PASS does NOT prove non-omission — it cannot show
 * the signer logged every action it took.
 *
 * CLI:  npx @attested-intelligence/aga-verify <bundle.json> [--pubkey <64-hex>]
 * Lib:  import { verifyEvidenceBundle } from '@attested-intelligence/aga-verify'
 *
 * Attested Intelligence Holdings LLC · MIT
 */
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';

const ALGORITHM = 'Ed25519-SHA256-JCS';
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex'); // Ed25519 SPKI DER prefix
const MAX_CANON_DEPTH = 100; // anti-DoS: deeper nesting fails closed, never stack-overflows

// EXACT canonical field sets (single source of truth, mirrors src/sep/receipt.ts + checkpoint.ts).
// The strict-schema floor requires an object to carry EXACTLY these keys — no extra, no missing,
// no renamed, no duplicate, no "__proto__"-injected key (Object.keys counts a JSON-parsed
// "__proto__" as an own key, so a 16th/8th key fails the count). Every conformant stack rejects
// the identical bundles.
const SEP_RECEIPT_FIELDS = [
  'receipt_id', 'receipt_version', 'algorithm', 'timestamp', 'request_id',
  'method', 'tool_name', 'decision', 'reason', 'policy_reference',
  'arguments_hash', 'previous_receipt_hash', 'gateway_id', 'public_key', 'signature',
] as const;
const SEP_CHECKPOINT_FIELDS = [
  'algorithm', 'gateway_id', 'generated_at', 'head_leaf_hash', 'leaf_count', 'merkle_root', 'signature',
] as const;

export interface VerificationStep { name: string; ok: boolean; }
export interface VerificationResult {
  verdict: 'VERIFIED' | 'FAILED';
  /** True only when a key was pinned AND the bundle key matched it. */
  issuerVerified: boolean;
  /** Whether a key was supplied to check provenance. */
  pinned: boolean;
  steps: VerificationStep[];
  errors: string[];
}

interface SepReceipt extends Record<string, unknown> { signature: string; previous_receipt_hash?: string; request_id?: string | number; timestamp?: string; gateway_id?: string; public_key?: string; }
interface SepProof { leaf_hash: string; leaf_index: number; siblings: string[]; directions: Array<'left' | 'right'>; merkle_root: string; }
interface SepCheckpoint extends Record<string, unknown> { signature: string; merkle_root: string; leaf_count: number; head_leaf_hash: string; gateway_id?: string; algorithm?: string; }
interface SepBundle {
  algorithm: string; public_key: string; gateway_id?: string; merkle_root?: string;
  receipts: SepReceipt[]; merkle_proofs: SepProof[]; checkpoint: SepCheckpoint;
}

// ── primitives (CANONICAL_CONSTRUCTION_v2.md §1,§3,§5) ────────────────────────
// Lone (unpaired) UTF-16 surrogate detector: a high surrogate U+D800..U+DBFF not immediately
// followed by a low surrogate, or a low surrogate not immediately preceded by a high surrogate.
// Such a string is INVALID Unicode that Go and Python cannot UTF-8-encode (they reject the
// bundle); JS would otherwise silently map it to U+FFFD and self-consistently VERIFY — a cross-
// stack split. We throw a CONTROLLED error so the never-throw try/catch -> FAILED on all six.
// Valid surrogate PAIRS (astral chars / emoji) are NOT matched and canonicalize unchanged.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

// Depth-bounded JCS-profile canon: input nested beyond MAX_CANON_DEPTH throws a CONTROLLED
// error well before a native stack overflow (anti-DoS). verifySepBundle's try/catch turns that
// into a FAILED verdict — a depth bomb can never crash the verifier. Mirrors src/sep/canonical.ts.
function canon(o: unknown): string {
  const rec = (v: unknown, depth: number): string => {
    if (depth > MAX_CANON_DEPTH) throw new Error(`canon: input nesting exceeds ${MAX_CANON_DEPTH} levels`);
    if (typeof v === 'string' && LONE_SURROGATE.test(v)) throw new Error('canonicalize: lone surrogate');
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map((x) => rec(x, depth + 1)).join(',') + ']';
    const m = v as Record<string, unknown>;
    return '{' + Object.keys(m).sort().map((k) => JSON.stringify(k) + ':' + rec(m[k], depth + 1)).join(',') + '}';
  };
  return rec(o, 0);
}

/**
 * Strict-schema floor: the object must carry EXACTLY the canonical fields — no extra, unknown,
 * missing, or "__proto__"-injected keys. own-key-count === fields.length AND every canonical
 * field present as an own property. Mirrors src/sep/verify.ts hasExactKeys exactly.
 */
function hasExactKeys(o: unknown, fields: readonly string[]): boolean {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  const keys = Object.keys(o as Record<string, unknown>);
  return keys.length === fields.length && fields.every((f) => Object.prototype.hasOwnProperty.call(o, f));
}
const sha = (b: Buffer): string => createHash('sha256').update(b).digest('hex');
const u8 = (s: string): Buffer => Buffer.from(s, 'utf8');
const leafHash = (r: unknown): string => sha(u8(canon(r)));                                   // no-prefix, full receipt
const nodeHash = (l: string, r: string): string => sha(Buffer.concat([Buffer.from(l, 'hex'), Buffer.from(r, 'hex')])); // raw bytes
const stripField = (o: Record<string, unknown>, f: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).filter(([k]) => k !== f));
const isHex = (h: unknown, n: number): h is string => typeof h === 'string' && new RegExp(`^[0-9a-f]{${n}}$`).test(h);

// Ed25519 points of order dividing 8 — a signature is trivially forgeable under such a key
// (e.g. the identity point admits R=A,S=0 universal forgery), so reject them. 10 canonical
// encodings; non-canonical (y >= p) caught by isCanonicalY. Mirrors src/sep/crypto.ts and the
// reference verifier so every conformant stack renders identical verdicts.
const SMALL_ORDER_KEYS = new Set<string>([
  '00'.repeat(32), '00'.repeat(31) + '80',
  '01' + '00'.repeat(31), '01' + '00'.repeat(30) + '80',
  'ec' + 'ff'.repeat(30) + '7f', 'ec' + 'ff'.repeat(31),
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
]);
const ED25519_P = (1n << 255n) - 19n;
function isCanonicalY(hex: string): boolean {
  const b = Buffer.from(hex, 'hex');
  let y = 0n;
  for (let i = 0; i < 32; i++) y |= BigInt(i === 31 ? (b[i] & 0x7f) : b[i]) << BigInt(8 * i);
  return y < ED25519_P;
}

// ── canonical SEP timestamp (CANONICAL_CONSTRUCTION_v2.md §6.3) ────────────────
// The mandated canonical form is EXACTLY what Date.prototype.toISOString() emits:
// fixed-width zero-padded UTC with exactly 3 fractional digits and a literal 'Z'.
// Validation uses NO date library — a literal [0-9] class (NOT \d, which matches
// Unicode digits) plus PURE INTEGER calendar-range arithmetic, so every verifier
// (JS/Go/Python) reaches a byte-identical verdict. Ordering is a plain lexicographic
// string compare because the form is fixed-width zero-padded UTC.
const TS_CANONICAL = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const isLeap = (y: number): boolean => y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
const daysInMonth = (y: number, m: number): number =>
  [31, isLeap(y) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];
function isCanonicalTimestamp(ts: unknown): ts is string {
  if (typeof ts !== 'string' || !TS_CANONICAL.test(ts)) return false;
  const year = parseInt(ts.slice(0, 4), 10);
  const month = parseInt(ts.slice(5, 7), 10);
  const day = parseInt(ts.slice(8, 10), 10);
  const hour = parseInt(ts.slice(11, 13), 10);
  const minute = parseInt(ts.slice(14, 16), 10);
  const second = parseInt(ts.slice(17, 19), 10);
  if (month < 1 || month > 12) return false;
  if (day < 1 || day > daysInMonth(year, month)) return false;
  if (hour > 23) return false;       // hour parsed from [0-9]{2} is always >= 0
  if (minute > 59) return false;
  if (second > 59) return false;
  return true;
}

function wellFormedKey(hex: unknown): hex is string {
  if (!isHex(hex, 64)) return false;
  if (SMALL_ORDER_KEYS.has(hex) || !isCanonicalY(hex)) return false;
  try { createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(hex, 'hex')]), format: 'der', type: 'spki' }); return true; }
  catch { return false; }
}
function sigOk(pubHex: string, msg: string, sigHex: unknown): boolean {
  if (!wellFormedKey(pubHex) || !isHex(sigHex, 128) || /^0+$/.test(sigHex)) return false;
  try {
    const pk = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(pubHex, 'hex')]), format: 'der', type: 'spki' });
    return edVerify(null, u8(msg), pk, Buffer.from(sigHex, 'hex'));
  } catch { return false; }
}

/** Returns a human-readable reason if `b` is not a canonical SEP bundle, else null. */
function validateShape(b: any): string | null {
  if (b === null || typeof b !== 'object' || Array.isArray(b)) return 'not a JSON object';
  if (b.algorithm !== ALGORITHM) return `algorithm must be "${ALGORITHM}"`;
  if (typeof b.public_key !== 'string') return 'missing "public_key"';
  if (!Array.isArray(b.receipts)) return 'missing "receipts" array';
  if (!Array.isArray(b.merkle_proofs)) return 'missing "merkle_proofs" array';
  if (typeof b.checkpoint !== 'object' || b.checkpoint === null || typeof b.checkpoint.signature !== 'string')
    return 'missing signed "checkpoint"';
  return null;
}

/** Verify a parsed canonical SEP Evidence Bundle (CANONICAL_CONSTRUCTION_v2.md §6). */
export function verifySepBundle(bundle: SepBundle, expectedPublicKey?: string): VerificationResult {
  // Robust contract (D6): a malformed/hostile bundle — a depth bomb that overflows the
  // depth-bounded canon, a type confusion, a missing structure, a non-string where a string
  // is expected — yields a FAILED verdict, NEVER a thrown exception / crash / stack overflow.
  const pinned = isHex(expectedPublicKey, 64);
  try {
  const steps: VerificationStep[] = [];
  const errors: string[] = [];
  const add = (name: string, ok: boolean, err?: string) => { steps.push({ name, ok }); if (!ok && err) errors.push(err); return ok; };

  const receipts = Array.isArray((bundle as any)?.receipts) ? (bundle as any).receipts : [];
  const proofs = Array.isArray((bundle as any)?.merkle_proofs) ? (bundle as any).merkle_proofs : [];
  const pub = (bundle as any)?.public_key;

  // §6.1 structural floor — incl. STRICT receipt schema (D1): every receipt must carry EXACTLY
  // the 15 canonical fields (rejects extra/unknown/missing/renamed and "__proto__" injection).
  add('structural',
    (bundle as any)?.algorithm === ALGORITHM && wellFormedKey(pub)
    && receipts.length > 0 && proofs.length === receipts.length
    && receipts.every((r: unknown) => hasExactKeys(r, SEP_RECEIPT_FIELDS)),
    'structural floor failed (algorithm/key/receipt-count/receipt-schema)');

  // §6.2 receipt signatures
  add('receipt_signatures',
    receipts.length > 0 && receipts.every((r: SepReceipt) => sigOk(pub, canon(stripField(r, 'signature')), r.signature)),
    'one or more receipt signatures invalid');

  // §6.3 chain + ordering — CANONICAL timestamps (D3/T1): every receipt's timestamp must match
  // the canonical .sssZ form AND have in-range calendar fields (pure-integer check, NO date
  // library), and timestamps must be NON-DECREASING across the chain.
  const leaves = receipts.map(leafHash);
  let chain = receipts.length > 0;
  let prevTs = '';
  for (let i = 0; i < receipts.length; i++) {
    if ((receipts[i].previous_receipt_hash || '') !== (i === 0 ? '' : leaves[i - 1])) chain = false;
    // request_id is the upstream request id (string|number|null), informational, NOT a sequence
    // counter. Ordering is enforced cryptographically by the chain linkage above; timestamps add
    // a strict non-decreasing check. A non-canonical ts is a FAILURE, not silently skipped.
    // Because the form is fixed-width zero-padded UTC, ordering is a plain lexicographic string
    // compare (NOT epoch/Date conversion); EQUAL is allowed. The first receipt only needs validity.
    const ts = receipts[i].timestamp;
    if (!isCanonicalTimestamp(ts)) chain = false;
    else { if (i > 0 && ts < prevTs) chain = false; prevTs = ts; }
  }
  add('chain_and_ordering', chain, 'chain linkage, non-canonical timestamp, or ordering broken');

  // §6.4 merkle: recompute leaf from content, walk proof, per-proof root, single root, bijection
  let root: string | null = null, merkle = proofs.length === receipts.length && proofs.length > 0;
  const seen = new Set<number>();
  for (const p of proofs) {
    seen.add(p.leaf_index);
    if (receipts[p.leaf_index] === undefined || leaves[p.leaf_index] !== p.leaf_hash) merkle = false;
    let cur = p.leaf_hash;
    // C1: directions is UNSIGNED. Require it to be a well-formed array — same length as siblings and
    // EVERY element exactly the literal "left" or "right". A rewritten token ("right"->"RIGHT") must
    // FAIL the merkle step, not fall through an else/ternary to "right" and still walk to the root.
    const sib: string[] = Array.isArray(p.siblings) ? p.siblings : [];
    const dir: string[] = Array.isArray(p.directions) ? p.directions : [];
    if (dir.length !== sib.length || !dir.every((d) => d === 'left' || d === 'right') || !sib.every((s) => isHex(s, 64))) merkle = false;
    for (let j = 0; j < sib.length; j++) cur = dir[j] === 'left' ? nodeHash(sib[j], cur) : nodeHash(cur, sib[j]);
    if (p.merkle_root !== cur) merkle = false;          // D4: the proof's own claimed root must equal what it walks to
    if (root === null) root = cur; else if (root !== cur) merkle = false;
  }
  const bijection = seen.size === receipts.length && [...seen].every((n) => Number.isInteger(n) && n >= 0 && n < receipts.length);
  add('merkle_and_bijection', merkle && bijection, 'Merkle proof, per-proof root, leaf recompute, or index bijection failed');

  // §6.5 mandatory signed checkpoint — STRICT schema (D2): EXACTLY the 7 canonical fields AND
  // checkpoint.algorithm === ALGORITHM, then signature + root/count/head binding.
  const cp = bundle.checkpoint as any;
  let cpOk = false;
  if (hasExactKeys(cp, SEP_CHECKPOINT_FIELDS)) {
    cpOk = cp.algorithm === ALGORITHM
      && sigOk(pub, canon(stripField(cp as Record<string, unknown>, 'signature')), cp.signature)
      && root !== null && cp.merkle_root === root
      && cp.leaf_count === receipts.length
      && cp.head_leaf_hash === (leaves.length ? leaves[leaves.length - 1] : '');
  }
  add('signed_checkpoint', cpOk, 'signed checkpoint missing, mis-schema, wrong algorithm, or does not anchor the bundle');

  // §6.5b ENVELOPE CONSISTENCY (D5): the per-receipt identity and the UNSIGNED envelope must agree
  // with the signed/recomputed values, so nothing outside the signed objects can mislead a consumer
  // that reads the envelope.
  const cpGatewayId = (cp && typeof cp === 'object') ? cp.gateway_id : undefined;
  const cpGeneratedAt = (cp && typeof cp === 'object') ? cp.generated_at : undefined;
  add('envelope_consistency',
    receipts.length > 0
    && receipts.every((r: any) => r.public_key === pub)                       // every receipt signed under the bundle key
    && receipts.every((r: any) => r.gateway_id === (bundle as any)?.gateway_id) // receipts <-> envelope gateway_id
    && cpGatewayId === (bundle as any)?.gateway_id                            // checkpoint <-> envelope gateway_id
    && cpGeneratedAt === (bundle as any)?.generated_at                        // T6: envelope generated_at <-> signed checkpoint generated_at
    && root !== null && (bundle as any)?.merkle_root === root,                // envelope merkle_root <-> recomputed
    'envelope gateway_id/generated_at/merkle_root or a receipt public_key/gateway_id disagrees with the signed/recomputed values');

  // §6.6 provenance (only when pinned)
  const issuerVerified = pinned && pub === expectedPublicKey;
  if (pinned) add('gateway_key_match', issuerVerified, 'bundle key does not match the pinned gateway key');

  return { verdict: steps.every((s) => s.ok) ? 'VERIFIED' : 'FAILED', issuerVerified, pinned, steps, errors };
  } catch (e) {
    return {
      verdict: 'FAILED', issuerVerified: false, pinned,
      steps: [{ name: 'verifier_exception', ok: false }],
      errors: [`verifier rejected a malformed bundle: ${String(e)}`],
    };
  }
}

/** Parse + shape-check + verify. Fails cleanly (no throw) on bad JSON or wrong format. */
export function verifyEvidenceBundle(bundleJson: string, expectedPublicKey?: string): VerificationResult {
  let parsed: unknown;
  try { parsed = JSON.parse(bundleJson); }
  catch { return { verdict: 'FAILED', issuerVerified: false, pinned: false, steps: [], errors: ['failed to parse bundle JSON'] }; }
  const shapeErr = validateShape(parsed);
  if (shapeErr) return { verdict: 'FAILED', issuerVerified: false, pinned: false, steps: [], errors: [`unrecognized evidence-bundle format: ${shapeErr}`] };
  return verifySepBundle(parsed as SepBundle, expectedPublicKey);
}

// ── CLI ──────────────────────────────────────────────────────────────────────
if (typeof process !== 'undefined' && process.argv[1]?.includes('verify')) {
  const { readFileSync, existsSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const resolveNear = (rel: string): string | null => {
    try {
      const p = fileURLToPath(new URL(rel, import.meta.url));
      return existsSync(p) ? p : null;
    } catch { return null; }
  };
  const pkgPath = resolveNear('../package.json') ?? resolveNear('./package.json');
  const pkgVersion = pkgPath ? (JSON.parse(readFileSync(pkgPath, 'utf-8')).version as string) : 'unknown';
  const USAGE = [
    'Usage: aga-verify <bundle.json> [--pubkey <64-hex-gateway-key>]',
    '       aga-verify --sample [--pubkey <key>]    verify the packaged sample bundle',
    '       aga-verify --version | --help',
    '',
    'Checks: structural, receipt signatures, chain + ordering, Merkle + index bijection,',
    'signed checkpoint, envelope consistency, and (with --pubkey) gateway key match.',
    '',
    'Exit codes: 0 VERIFIED; 1 FAILED (including an unreadable file, and v2/post-quantum',
    'bundles, which this CLI does not implement and reports as FAILED); 2 usage error.',
  ].join('\n');
  const args = process.argv.slice(2);
  if (args.includes('--version')) { console.log(pkgVersion); process.exit(0); }
  if (args.includes('--help')) { console.log(USAGE); process.exit(0); }
  const useSample = args.includes('--sample');
  let file = args.find((a) => !a.startsWith('--'));
  const pk = args.includes('--pubkey') ? args[args.indexOf('--pubkey') + 1] : undefined;
  if (useSample) {
    const sample = resolveNear('../example-bundle.json') ?? resolveNear('./example-bundle.json');
    if (!sample) { console.error('The packaged sample bundle was not found next to the installed package.'); process.exit(2); }
    file = sample;
  }
  if (!file) { console.error(USAGE); process.exit(2); }
  // D8: any failure on the read/parse/verify path => a FAILED line + exit 1 (never an uncaught
  // stack trace, never exit 2). Usage/--version/--help above are the only non-0/1 exits.
  let raw: string;
  try { raw = readFileSync(file, 'utf-8'); }
  catch (e) {
    console.log(`\nAGA Offline Verifier v${pkgVersion}\n`);
    console.log('OVERALL: FAILED (could not read bundle file)');
    console.log(`\nErrors:\n  - ${String(e)}`);
    console.log('\nHint: pass a path to a bundle you exported, or run with --sample to verify');
    console.log('the packaged example (a real signed bundle shipped inside this package).');
    process.exit(1);
  }
  const result = verifyEvidenceBundle(raw, pk);
  console.log(`\nAGA Offline Verifier v${pkgVersion}${useSample ? ' (packaged sample)' : ''}\n`);
  for (const s of result.steps) console.log(`  ${s.ok ? 'PASS' : 'FAIL'}  ${s.name}`);
  // Suffix reflects the VERDICT: only a VERIFIED bundle gets a provenance/integrity tag; a FAILED
  // bundle prints just "FAILED" (never "FAILED (provenance verified)").
  const prov = result.verdict === 'VERIFIED' ? (result.pinned ? ' (provenance verified)' : ' (integrity only — no --pubkey given)') : '';
  console.log(`\nOVERALL: ${result.verdict}${prov}`);
  if (!result.pinned && result.verdict === 'VERIFIED') {
    console.log('NOTE: integrity + self-consistency proven, but NOT provenance. Re-run with --pubkey <gateway-key> to prove WHO issued it.');
  }
  if (result.errors.length) { console.log('\nErrors:'); result.errors.forEach((e) => console.log(`  - ${e}`)); }
  process.exit(result.verdict === 'VERIFIED' ? 0 : 1);
}
