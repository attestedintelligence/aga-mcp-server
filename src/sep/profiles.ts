/**
 * SEP profile registry + verification dispatch (ALGORITHM_AGILITY_SPEC.md).
 *
 * The construction (canon / leaf / Merkle / signed checkpoint / 6-step verify) is profile-INVARIANT;
 * only the signature primitive and the public-key well-formedness change. This module is the single
 * dispatch seam the verifier consults, so verify.ts never branches on a literal algorithm string:
 *
 *   v1  Ed25519-SHA256-JCS            -> ./crypto  (Ed25519, RFC 8032, node:crypto, small-order-rejected)
 *   v2  ML-DSA-65+Ed25519-SHA256-JCS  -> ./hybrid  (composite, AND-verify, no partial acceptance)
 *
 * Adding a profile is an additive registry edit; existing profiles are never altered (frozen).
 */
import { verifyHex, wellFormedKey } from './crypto.js';
import { verifyHybrid, ALG_HYBRID } from './hybrid.js';
import { SEP_ALGORITHM } from './receipt.js';

export { ALG_HYBRID };
/** v1 classical profile identifier (same literal as SEP_ALGORITHM). */
export const ALG_ED25519 = SEP_ALGORITHM; // 'Ed25519-SHA256-JCS'

/** Registered profiles -> profile_version. The authoritative registry the dispatch consults. */
export const REGISTERED_PROFILES: Readonly<Record<string, string>> = {
  [ALG_ED25519]: '1',
  [ALG_HYBRID]: '2',
};

/** The profiles the agile engine implements (both). A v1-only verifier passes a restricted set. */
export const ALL_PROFILES: readonly string[] = [ALG_ED25519, ALG_HYBRID];

/** Composite public key = len32(1952)||mldsa||len32(32)||ed = 1992 bytes -> 3984 lower-hex chars. */
const COMPOSITE_PUBLIC_KEY_HEX_LEN = 1992 * 2;
const COMPOSITE_PUBKEY_RE = new RegExp(`^[0-9a-f]{${COMPOSITE_PUBLIC_KEY_HEX_LEN}}$`);

/** True iff `algorithm` is a profile the registry knows about (regardless of which verifier implements it). */
export function isRegisteredProfile(algorithm: unknown): boolean {
  return typeof algorithm === 'string' && Object.prototype.hasOwnProperty.call(REGISTERED_PROFILES, algorithm);
}

/**
 * Profile-parameterized public-key well-formedness (the H1 floor, per profile):
 *  - v1: 64 lower-hex, canonical-y, small-order rejected (node:crypto wellFormedKey).
 *  - v2: 3984 lower-hex, non-zero (the composite's component small-order rejection is enforced at verify).
 */
export function validPublicKeyForProfile(algorithm: string, pub: unknown): boolean {
  if (algorithm === ALG_ED25519) return wellFormedKey(pub);
  if (algorithm === ALG_HYBRID) return typeof pub === 'string' && !/^0+$/.test(pub) && COMPOSITE_PUBKEY_RE.test(pub);
  return false;
}

/**
 * Verify a lower-hex signature over a canonical message under the named profile's primitive.
 * Never throws; an unknown profile fails closed (false). v2 is composite AND-verify (no partial accept).
 */
export function verifyForProfile(algorithm: string, pub: string, message: string, sig: unknown): boolean {
  if (algorithm === ALG_ED25519) return typeof sig === 'string' && verifyHex(pub, message, sig);
  if (algorithm === ALG_HYBRID) return verifyHybrid(pub, message, sig);
  return false;
}
