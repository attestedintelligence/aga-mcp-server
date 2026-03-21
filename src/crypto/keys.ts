/**
 * Key utilities: fingerprints, hex encoding, validation.
 */
import { sha256Str } from './hash.js';
import { generateKeyPair, pkToHex, hexToPk } from './sign.js';
import type { KeyPair, HashHex } from '../types.js';

/** SHA-256 fingerprint of a public key (first 16 hex chars). */
export function keyFingerprint(pk: Uint8Array): string {
  return sha256Str(pkToHex(pk)).slice(0, 16);
}

/** Check if a hex-encoded public key is valid (64 hex chars for Ed25519). */
export function isKeyValid(hexKey: string): boolean {
  return /^[0-9a-f]{64}$/.test(hexKey);
}

/** Rotate a keypair - returns new keypair. Old keypair should be revoked. */
export function rotateKeyPair(): KeyPair {
  return generateKeyPair();
}

export { pkToHex, hexToPk };
