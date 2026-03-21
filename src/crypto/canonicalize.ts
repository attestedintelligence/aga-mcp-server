/**
 * Deterministic JSON serialization (RFC 8785 aligned).
 * Moved from src/utils/canonical.ts for directive structure alignment.
 */
export function deepSortKeys(obj: unknown): unknown {
  if (obj === null || obj === undefined || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(deepSortKeys);
  if (obj instanceof Uint8Array) return obj;
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    sorted[key] = deepSortKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

export function canonicalize(obj: unknown): string {
  return JSON.stringify(deepSortKeys(obj));
}
