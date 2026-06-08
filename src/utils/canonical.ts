export function deepSortKeys(obj: unknown): unknown {
  if (obj === null || obj === undefined || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(deepSortKeys);
  if (obj instanceof Uint8Array) return obj;
  // Null-prototype accumulator: injective + pollution-proof (a plain {} would let a
  // "__proto__" key invoke the prototype setter and be silently dropped).
  //
  // NOTE: this is the INTERNAL continuity-format canonicalizer (used by core/* artifact, chain,
  // portal, disclosure, receipt, subject) — it is internally consistent (sign and verify use it
  // identically) but it is NOT the cross-stack SEP canonicalizer. Because canonicalize() below
  // re-stringifies this rebuilt object, V8 reorders integer-like keys numerically, so for integer
  // keys it does NOT match src/sep/canonical.ts (which concatenates lexicographically). The
  // continuity chain is not a cross-stack-verified format, so this is safe; the canonical,
  // cross-stack-authoritative serializer is src/sep/canonical.ts. Do not use this for SEP.
  const sorted = Object.create(null) as Record<string, unknown>;
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    sorted[key] = deepSortKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

export function canonicalize(obj: unknown): string {
  return JSON.stringify(deepSortKeys(obj));
}
