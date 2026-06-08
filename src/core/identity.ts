/**
 * Identity and Key Lifecycle.
 *
 * Non-biometric cryptographic identity: agent identity derived from
 * cryptographic key pair bound to append-only attestation history in
 * continuity chain. Authority from valid signature history, not biometric traits.
 *
 * Functions:
 * - keyFingerprint: re-exported from crypto/sign.ts for convenience
 * - isKeyValid: check key TTL expiry
 * - rotateKeyPair: generate new key pair for rotation
 * - recordKeyRotation: append KEY_ROTATION event to chain
 */
import { generateKeyPair, keyFingerprint, pkToHex } from '../crypto/sign.js';
import { isExpired } from '../utils/timestamp.js';
import { appendEvent } from './chain.js';
import type { KeyPair } from '../crypto/types.js';
import type { ContinuityEvent, KeyRotationRecord } from './types.js';

// Re-export keyFingerprint for identity module consumers (NCCoE §2)
export { keyFingerprint } from '../crypto/sign.js';

/**
 * Check whether a key is still valid given its issuance time and TTL.
 * NCCoE §2: non-biometric identity validity check.
 */
export function isKeyValid(issuedAt: string, ttlSeconds: number): boolean {
  return !isExpired(issuedAt, ttlSeconds);
}

/**
 * Generate a new key pair for rotation, returning both old and new for
 * a transition period defined by policy. NCCoE §3: key rotation.
 */
export function rotateKeyPair(currentKeyPair: KeyPair): { oldKeyPair: KeyPair; newKeyPair: KeyPair } {
  const newKeyPair = generateKeyPair();
  return { oldKeyPair: currentKeyPair, newKeyPair };
}

/**
 * Record a key rotation event on the continuity chain.
 * NCCoE §3: "Key rotation is handled by including both old and new public keys
 * during a transition period defined by policy."
 */
export function recordKeyRotation(
  prevEvent: ContinuityEvent,
  keypairType: string,
  oldPublicKeyHex: string,
  newPublicKeyHex: string,
  reason: string,
  signingKeyPair: KeyPair,
): ContinuityEvent {
  const payload: KeyRotationRecord = {
    keypair_type: keypairType,
    old_public_key: oldPublicKeyHex,
    new_public_key: newPublicKeyHex,
    reason,
    rotation_timestamp: new Date().toISOString(),
    chain_sequence: prevEvent.sequence_number + 1,
  };
  return appendEvent('KEY_ROTATION', payload, prevEvent, signingKeyPair);
}
