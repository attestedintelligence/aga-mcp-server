/**
 * Identity operations: key fingerprinting, validation, rotation.
 */
import { keyFingerprint, isKeyValid, rotateKeyPair } from '../crypto/keys.js';
import { generateKeyPair, pkToHex } from '../crypto/sign.js';
import type { KeyPair } from '../types.js';

export { keyFingerprint, isKeyValid };

export interface KeyRotationResult {
  newKeyPair: KeyPair;
  newPublicKeyHex: string;
  oldPublicKeyHex: string;
  rotatedAt: string;
}

export function rotateKeys(oldKP: KeyPair): KeyRotationResult {
  const newKP = rotateKeyPair();
  return {
    newKeyPair: newKP,
    newPublicKeyHex: pkToHex(newKP.publicKey),
    oldPublicKeyHex: pkToHex(oldKP.publicKey),
    rotatedAt: new Date().toISOString(),
  };
}
