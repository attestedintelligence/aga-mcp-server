export function utcNow(): string { return new Date().toISOString(); }

export function isWithinPeriod(now: string, effective: string, expiration?: string | null): boolean {
  const n = Date.parse(now);
  if (n < Date.parse(effective)) return false;
  if (expiration && n > Date.parse(expiration)) return false;
  return true;
}

export function isExpired(issuedAt: string, ttlSeconds: number): boolean {
  return Date.now() > Date.parse(issuedAt) + ttlSeconds * 1000;
}
