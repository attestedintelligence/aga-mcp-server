/**
 * SEP §6 verifier — a faithful TypeScript port of the normative reference
 * aga-receipt-spec/verify/verify-sep.mjs. Same six steps, same semantics, same crypto
 * (node:crypto), so its verdicts match the reference byte-for-byte. See SPEC_PRECEDENCE.md.
 */
import { canonicalize } from './canonical.js';
import { sha256Hex, wellFormedKey, verifyHex, isHex } from './crypto.js';
import { nodeHash } from './merkle.js';
import { SEP_ALGORITHM, SEP_RECEIPT_FIELDS } from './receipt.js';
import { SEP_CHECKPOINT_FIELDS } from './checkpoint.js';

export interface VerifyStep { name: string; ok: boolean; }
export interface SepVerificationResult {
  verdict: 'VERIFIED' | 'FAILED';
  /** Human-readable headline — makes integrity-only vs provenance-verified unmistakable. */
  summary: string;
  issuerVerified: boolean;
  pinned: boolean;
  steps: VerifyStep[];
}

const leaf = (r: unknown): string => sha256Hex(canonicalize(r));
const strip = (o: Record<string, unknown>, f: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).filter(([k]) => k !== f));

/**
 * Canonical SEP timestamp validation (cross-stack unified). A timestamp is VALID iff it
 * matches the EXACT fixed-width UTC form Date.prototype.toISOString() emits AND its calendar
 * fields are in range — computed with PURE INTEGER ARITHMETIC, no Date/parser, so every
 * verifier reaches a byte-identical verdict. Uses the literal [0-9] class (not \d, which
 * matches Unicode digits and would diverge from the other stacks).
 */
const TS_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const isLeap = (y: number): boolean => y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
const daysInMonth = (y: number, m: number): number =>
  [31, isLeap(y) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];
const isValidTimestamp = (ts: unknown): boolean => {
  if (typeof ts !== 'string' || !TS_RE.test(ts)) return false;
  const year = Number(ts.slice(0, 4));
  const month = Number(ts.slice(5, 7));
  const day = Number(ts.slice(8, 10));
  const hour = Number(ts.slice(11, 13));
  const minute = Number(ts.slice(14, 16));
  const second = Number(ts.slice(17, 19));
  return month >= 1 && month <= 12
    && day >= 1 && day <= daysInMonth(year, month)
    && hour >= 0 && hour <= 23
    && minute >= 0 && minute <= 59
    && second >= 0 && second <= 59;
};

/**
 * Strict-schema floor: the object must carry EXACTLY the canonical fields — no extra,
 * unknown, or "__proto__"-injected keys (Object.keys counts a JSON-parsed "__proto__" as
 * an own key, so a 16th key fails the count). This is the cross-stack-robust rule: every
 * conformant verifier rejects the identical bundles.
 */
const hasExactKeys = (o: unknown, fields: readonly string[]): boolean => {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  const keys = Object.keys(o as Record<string, unknown>);
  return keys.length === fields.length && fields.every((f) => Object.prototype.hasOwnProperty.call(o, f));
};

export function verifySepBundle(bundle: any, expectedPublicKey?: string): SepVerificationResult {
  // Robust contract: a malformed/hostile bundle (e.g. a receipt with a deeply-nested value
  // that overflows the depth-bounded canonicalize) yields FAILED, never a thrown exception.
  const pinned = isHex(expectedPublicKey, 64);
  try {
  const steps: VerifyStep[] = [];
  const add = (name: string, ok: boolean): boolean => { steps.push({ name, ok }); return ok; };
  const receipts: any[] = Array.isArray(bundle?.receipts) ? bundle.receipts : [];
  const proofs: any[] = Array.isArray(bundle?.merkle_proofs) ? bundle.merkle_proofs : [];
  const pub: string = bundle?.public_key;

  // §6.1 structural floor — incl. STRICT receipt schema (exactly the canonical fields;
  // rejects extra/unknown keys and "__proto__" injection on every signed receipt).
  add('structural',
    bundle?.algorithm === SEP_ALGORITHM && wellFormedKey(pub)
    && receipts.length > 0 && proofs.length === receipts.length
    && receipts.every((r) => hasExactKeys(r, SEP_RECEIPT_FIELDS)));

  // §6.2 receipt signatures (against the bundle key; provenance handled in §6.6)
  add('receipt_signatures', receipts.length > 0 && receipts.every((r) => verifyHex(pub, canonicalize(strip(r, 'signature')), r.signature)));

  // §6.3 chain + ordering
  const leaves = receipts.map(leaf);
  let chain = receipts.length > 0;
  let prevTs: string | null = null;
  for (let i = 0; i < receipts.length; i++) {
    const expectPrev = i === 0 ? '' : leaves[i - 1];
    if ((receipts[i].previous_receipt_hash || '') !== expectPrev) chain = false;
    // Canonical timestamps: each must match the fixed-width UTC form and be calendar-valid
    // (pure integer arithmetic, no Date parser). Because the form is fixed-width zero-padded
    // UTC, non-decreasing ordering is a PLAIN STRING (lexicographic) compare; EQUAL allowed.
    const ts = receipts[i].timestamp;
    if (!isValidTimestamp(ts)) chain = false;
    else { if (prevTs !== null && ts < prevTs) chain = false; prevTs = ts; }
  }
  add('chain_and_ordering', chain);

  // §6.4 merkle: recompute leaf from content, walk proof, single root, index bijection
  let root: string | null = null;
  let merkle = proofs.length === receipts.length && proofs.length > 0;
  const seen = new Set<number>();
  for (let i = 0; i < proofs.length; i++) {
    const p = proofs[i];
    seen.add(p.leaf_index);
    const recomputed = receipts[p.leaf_index] !== undefined ? leaves[p.leaf_index] : null;
    if (recomputed === null || recomputed !== p.leaf_hash) merkle = false;
    let cur = p.leaf_hash;
    // directions is UNSIGNED, so it must be a well-formed array of EXACTLY "left"/"right" tokens
    // (same length as siblings). Otherwise the merkle step FAILS — without this, JS/Go would treat a
    // rewritten token (e.g. "right"->"RIGHT") as a "right" fallthrough and still walk to the correct
    // root and VERIFY, while Python FAILS: a cross-stack disagreement. (Matches Python's strictness.)
    const sib: string[] = Array.isArray(p.siblings) ? p.siblings : [];
    const dir: string[] = Array.isArray(p.directions) ? p.directions : [];
    if (dir.length !== sib.length || !dir.every((d) => d === 'left' || d === 'right') || !sib.every((s) => isHex(s, 64))) merkle = false;
    for (let j = 0; j < sib.length; j++) cur = dir[j] === 'left' ? nodeHash(sib[j], cur) : nodeHash(cur, sib[j]);
    if (p.merkle_root !== cur) merkle = false;          // the proof's own claimed root must match what it walks to (L-7)
    if (root === null) root = cur; else if (root !== cur) merkle = false;
  }
  const bijection = seen.size === receipts.length && [...seen].every((n) => Number.isInteger(n) && n >= 0 && n < receipts.length);
  add('merkle_and_bijection', merkle && bijection);

  // §6.5 mandatory signed checkpoint — STRICT schema (exactly the canonical fields) + the
  // bound algorithm value, then signature + root/count/head binding.
  const cp = bundle?.checkpoint;
  let cpOk = false;
  if (hasExactKeys(cp, SEP_CHECKPOINT_FIELDS)) {
    cpOk = cp.algorithm === SEP_ALGORITHM
      && verifyHex(pub, canonicalize(strip(cp, 'signature')), cp.signature)
      && root !== null && cp.merkle_root === root
      && cp.leaf_count === receipts.length
      && cp.head_leaf_hash === (leaves.length ? leaves[leaves.length - 1] : '');
  }
  add('signed_checkpoint', cpOk);

  // §6.5b cross-field consistency: per-receipt identity + the UNSIGNED envelope must agree
  // with the signed/recomputed values, so nothing outside the signed objects can mislead a
  // consumer that reads the envelope (M-1/M-2/L-3).
  const cpGatewayId = (cp && typeof cp === 'object') ? (cp as Record<string, unknown>).gateway_id : undefined;
  const cpGeneratedAt = (cp && typeof cp === 'object') ? (cp as Record<string, unknown>).generated_at : undefined;
  add('envelope_consistency',
    receipts.length > 0
    && receipts.every((r) => r.public_key === pub)               // every receipt is signed under the bundle key (L-3)
    && receipts.every((r) => r.gateway_id === bundle?.gateway_id) // receipts ↔ envelope gateway_id
    && cpGatewayId === bundle?.gateway_id                         // checkpoint ↔ envelope gateway_id (M-2)
    && bundle?.generated_at === cpGeneratedAt                     // envelope generated_at ↔ signed checkpoint (T6)
    && root !== null && bundle?.merkle_root === root);            // envelope merkle_root ↔ recomputed (M-1)

  // §6.6 provenance (only when a key is pinned)
  const issuerVerified = pinned && pub === expectedPublicKey;
  if (pinned) add('gateway_key_match', issuerVerified);

  const verdict = steps.every((s) => s.ok) ? 'VERIFIED' : 'FAILED';
  const failed = steps.filter((s) => !s.ok).map((s) => s.name);
  const summary = verdict === 'FAILED'
    ? `FAILED — bundle did not verify (failed: ${failed.join(', ') || 'unknown'})`
    : pinned
      ? 'VERIFIED (provenance verified — issued by the pinned gateway key)'
      : 'VERIFIED (integrity only — NOT provenance; pass the gateway key to prove who issued it)';
  return { verdict, summary, issuerVerified, pinned, steps };
  } catch (e) {
    return { verdict: 'FAILED', summary: `FAILED — verifier rejected a malformed bundle (${String(e)})`, issuerVerified: false, pinned, steps: [{ name: 'verifier_exception', ok: false }] };
  }
}
