/**
 * SEP crypto primitives — node:crypto only, to mirror the normative reference verifier
 * (aga-receipt-spec/verify/verify-sep.mjs) byte-for-byte. Ed25519 (RFC 8032) + SHA-256.
 *
 * Keys use the raw 32-byte RFC-8032 Ed25519 seed: signerFromSeed(seed) yields the public key
 * and signatures, interoperable with any standard Ed25519 library that uses the seed encoding.
 */
import {
  createHash, createPrivateKey, createPublicKey, randomBytes, randomUUID,
  sign as nodeSign, verify as nodeVerify,
} from 'node:crypto';

const SPKI = Buffer.from('302a300506032b6570032100', 'hex'); // Ed25519 SubjectPublicKeyInfo prefix
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex'); // Ed25519 PKCS8 seed prefix

export function sha256Hex(s: string): string {
  return createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');
}

export function isHex(h: unknown, n: number): boolean {
  return typeof h === 'string' && new RegExp(`^[0-9a-f]{${n}}$`).test(h);
}

export interface SepSigner {
  /** Profile algorithm id this signer emits — v1 'Ed25519-SHA256-JCS' or v2 'ML-DSA-65+Ed25519-SHA256-JCS'. */
  readonly algorithm: string;
  readonly publicKeyHex: string;
  sign(message: string): string; // returns the lower-hex signature for this signer's algorithm
}

/** Build a deterministic signer from a 32-byte Ed25519 seed (e.g. a @noble secretKey). */
export function signerFromSeed(seed: Uint8Array): SepSigner {
  if (seed.length !== 32) throw new Error(`Ed25519 seed must be 32 bytes, got ${seed.length}`);
  const sk = createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
  const publicKeyHex = createPublicKey(sk).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  return { algorithm: 'Ed25519-SHA256-JCS', publicKeyHex, sign: (m) => nodeSign(null, Buffer.from(m, 'utf8'), sk).toString('hex') };
}

/** Generate a fresh signer; returns the seed so callers can persist it. */
export function generateSigner(): { signer: SepSigner; seed: Uint8Array } {
  const seed = new Uint8Array(randomBytes(32));
  return { signer: signerFromSeed(seed), seed };
}

/** Parse a 64-hex (32-byte) Ed25519 seed, e.g. from AGA_GATEWAY_KEY. Throws on malformed input. */
export function seedFromHex(hex: string): Uint8Array {
  const h = String(hex).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('gateway key must be 64 lowercase hex chars (a 32-byte Ed25519 seed)');
  return Uint8Array.from(Buffer.from(h, 'hex'));
}

/**
 * Small-order Ed25519 public-key encodings (order dividing 8). A signature can be forged
 * trivially under such a key, so they are rejected outright. The structured entries are
 * built from parts (no length to mis-transcribe); the order-8 entries are the standard
 * blocklist values (cf. libsodium / ZIP-215). A fail-fast guard rejects any malformed entry.
 */
// The 10 CANONICAL (y < p) encodings of the Ed25519 points of order dividing 8. A signature
// can be forged trivially under such a key, so they are rejected. The two x=0 points (identity
// y=1, order-2 y=-1) each have a sign-bit-CLEAR and a sign-bit-SET encoding (x=0 ⇒ ±x=0, both
// decode to the same point), so all four x=0 variants are listed. NON-canonical (y ≥ p)
// encodings of these points are caught separately by isCanonicalY below. Structured constants
// (no length to mis-transcribe) + a fail-fast guard.
const SMALL_ORDER_KEYS = new Set<string>([
  '00'.repeat(32),                 // y = 0 (order 4)
  '00'.repeat(31) + '80',          // y = 0, sign bit set (order 4)
  '01' + '00'.repeat(31),          // y = 1 identity (order 1)
  '01' + '00'.repeat(30) + '80',   // y = 1 identity, sign bit set
  'ec' + 'ff'.repeat(30) + '7f',   // y = -1 (order 2)
  'ec' + 'ff'.repeat(31),          // y = -1, sign bit set
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', // order 8
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', // order 8
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85', // order 8 (sign bit)
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa', // order 8 (sign bit)
]);
for (const k of SMALL_ORDER_KEYS) {
  if (!/^[0-9a-f]{64}$/.test(k)) throw new Error(`malformed small-order key constant: "${k}"`);
}

const ED25519_P = (1n << 255n) - 19n;
/** A valid Ed25519 public key encodes y < p (the sign bit is bit 255). Reject non-canonical
 *  encodings (y >= p) — this also rejects the non-canonical encodings of the small-order points. */
function isCanonicalY(hex: string): boolean {
  const b = Buffer.from(hex, 'hex');
  let y = 0n;
  for (let i = 0; i < 32; i++) y |= BigInt(i === 31 ? (b[i] & 0x7f) : b[i]) << BigInt(8 * i);
  return y < ED25519_P;
}

/** §6.1 structural floor: reject malformed, non-canonical, non-decodable, and small-order keys. */
export function wellFormedKey(hex: unknown): boolean {
  if (!isHex(hex, 64)) return false;
  if (SMALL_ORDER_KEYS.has(hex as string)) return false;   // canonical small-order encodings
  if (!isCanonicalY(hex as string)) return false;          // non-canonical (y >= p), incl. non-canonical small-order
  try {
    createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(hex as string, 'hex')]), format: 'der', type: 'spki' });
    return true;
  } catch {
    return false;
  }
}

export function verifyHex(pubHex: string, message: string, sigHex: string): boolean {
  if (!wellFormedKey(pubHex) || !isHex(sigHex, 128) || /^0+$/.test(sigHex)) return false;
  try {
    return nodeVerify(
      null,
      Buffer.from(message, 'utf8'),
      createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(pubHex, 'hex')]), format: 'der', type: 'spki' }),
      Buffer.from(sigHex, 'hex'),
    );
  } catch {
    return false;
  }
}

export function newId(prefix = 'rcpt'): string {
  return `${prefix}-${randomUUID()}`;
}
