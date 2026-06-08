/**
 * Canonical JSON for the AGA SEP profile (JCS-profile, sorted-key).
 *
 * Built by STRING CONCATENATION in lexicographic key order — BYTE-IDENTICAL to the normative
 * reference verifier (aga-receipt-spec/verify/verify-sep.mjs §canon) and to the Python/Go
 * stacks (all sort keys lexicographically). It deliberately does NOT route through
 * `JSON.stringify` of a rebuilt object: V8 re-orders integer-like keys NUMERICALLY (own-property
 * enumeration), so `{"22":..,"3":..}` would serialize as 3,22 here but 22,3 (lexicographic)
 * everywhere else — a cross-stack divergence on legitimate data (e.g. a port map in tool args).
 * Concatenation also keeps a "__proto__" key as an ordinary key (injective; no prototype-setter
 * pitfall). `JSON.stringify` is used only for the atomic pieces (keys, string/number/bool/null
 * leaves) so escaping matches JS exactly.
 *
 * Depth-bounded: input nested beyond MAX_CANON_DEPTH throws a CONTROLLED error well before a
 * stack overflow, so emit/verify can fail closed instead of crashing (anti-DoS).
 */
export const MAX_CANON_DEPTH = 100;

/**
 * Lone (unpaired) UTF-16 surrogate detector. A signed string carrying an unpaired surrogate is
 * INVALID Unicode that Go/Python cannot UTF-8-encode (they reject the bundle). JS would otherwise
 * map it to U+FFFD self-consistently and VERIFY — a cross-stack split. Rejecting it here (throw,
 * caught by the verifier's never-throw try/catch -> FAILED) makes all six stacks reject it. Valid
 * surrogate PAIRS (astral chars / emoji) are unaffected.
 */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export function canonicalize(obj: unknown): string {
  const rec = (o: unknown, depth: number): string => {
    if (depth > MAX_CANON_DEPTH) throw new Error(`canonicalize: input nesting exceeds ${MAX_CANON_DEPTH} levels`);
    if (typeof o === 'string' && LONE_SURROGATE.test(o)) throw new Error('canonicalize: lone surrogate');
    if (o === null || typeof o !== 'object') return JSON.stringify(o);
    if (Array.isArray(o)) return '[' + o.map((v) => rec(v, depth + 1)).join(',') + ']';
    const m = o as Record<string, unknown>;
    return '{' + Object.keys(m).sort().map((k) => JSON.stringify(k) + ':' + rec(m[k], depth + 1)).join(',') + '}';
  };
  return rec(obj, 0);
}

/**
 * SEP escape hatch (emit-side only): every SIGNED RECEIPT field must be string | boolean | null,
 * never a raw number — so the JCS-profile vs strict-RFC-8785 number-serialization gap can never
 * diverge across language stacks. Verifiers do NOT apply this (they canonicalize whatever is present).
 * Note: the signed checkpoint's `leaf_count` is a deliberate exception — it is a small non-negative
 * integer the reference verifier compares numerically (`cp.leaf_count === receipts.length`), and small
 * integers serialize identically under JSON.stringify and RFC-8785, so it carries no divergence risk.
 */
export function assertSignedReceiptFieldsAreStrings(obj: Record<string, unknown>, where = 'receipt'): void {
  for (const [k, v] of Object.entries(obj)) {
    if (v === null) continue;
    const t = typeof v;
    if (t === 'number' || t === 'bigint') {
      throw new Error(`SEP signed-field guard: ${where}.${k} is ${t}; signed receipt fields must be string|boolean|null (emit numbers as strings).`);
    }
    if (t === 'object') {
      throw new Error(`SEP signed-field guard: ${where}.${k} is an object; SEP ${where} fields must be flat scalars.`);
    }
  }
}
