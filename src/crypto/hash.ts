import { sha256 } from '@noble/hashes/sha256';
import { blake2b } from '@noble/hashes/blake2b';
import { bytesToHex } from '@noble/hashes/utils';
import type { HashHex } from './types.js';

const enc = new TextEncoder();

export function sha256Bytes(data: Uint8Array): HashHex {
  return bytesToHex(sha256(data));
}

export function sha256Str(data: string): HashHex {
  return sha256Bytes(enc.encode(data));
}

export function blake2b256(data: Uint8Array): HashHex {
  return bytesToHex(blake2b(data, { dkLen: 32 }));
}

/** Concatenate inputs (NO delimiter) and SHA-256. No delimiters per protocol spec. */
export function sha256Cat(...parts: (Uint8Array | string)[]): HashHex {
  const bufs = parts.map(p => typeof p === 'string' ? enc.encode(p) : p);
  const total = bufs.reduce((n, b) => n + b.length, 0);
  const combined = new Uint8Array(total);
  let off = 0;
  for (const b of bufs) { combined.set(b, off); off += b.length; }
  return sha256Bytes(combined);
}

/** Concatenate hex strings as text (no decode) and hash. For sealed_hash computation. */
export function sha256HexCat(...hexes: string[]): HashHex {
  return sha256Str(hexes.join(''));
}
