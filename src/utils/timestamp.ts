export function utcNow(): string { return new Date().toISOString(); }

export function isWithinPeriod(now: string, effective: string, expiration?: string | null): boolean {
  const n = Date.parse(now);
  if (n < Date.parse(effective)) return false;
  if (expiration && n > Date.parse(expiration)) return false;
  return true;
}

export function isExpired(issuedAt: string, ttlSeconds: number): boolean {
  // Half-open validity window [issued, issued + ttl): the artifact is expired the instant the TTL
  // elapses, so a zero-TTL artifact is born expired. ">=" (not ">") makes this deterministic at the
  // boundary — otherwise a zero-TTL check landing in the same millisecond as issuance reads as live.
  return Date.now() >= Date.parse(issuedAt) + ttlSeconds * 1000;
}
