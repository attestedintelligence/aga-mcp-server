import { describe, it, expect } from 'vitest';
import { generateKeyPair, pkToHex } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { createGenesisEvent } from '../../src/core/chain.js';
import { keyFingerprint, isKeyValid, rotateKeyPair, recordKeyRotation } from '../../src/core/identity.js';

describe('identity and key lifecycle (NCCoE §§2-3)', () => {
  const kp = generateKeyPair();
  const chainKP = generateKeyPair();

  it('keyFingerprint returns 16-char hex (NCCoE §2)', () => {
    const fp = keyFingerprint(pkToHex(kp.publicKey));
    expect(fp).toMatch(/^[0-9a-f]{16}$/);
    expect(fp).toHaveLength(16);
  });

  it('keyFingerprint is deterministic', () => {
    const hex = pkToHex(kp.publicKey);
    expect(keyFingerprint(hex)).toBe(keyFingerprint(hex));
  });

  it('different keys produce different fingerprints', () => {
    const kp2 = generateKeyPair();
    expect(keyFingerprint(pkToHex(kp.publicKey))).not.toBe(keyFingerprint(pkToHex(kp2.publicKey)));
  });

  it('isKeyValid returns true for fresh key', () => {
    expect(isKeyValid(new Date().toISOString(), 3600)).toBe(true);
  });

  it('isKeyValid returns false for expired key', () => {
    const past = new Date(Date.now() - 7200_000).toISOString();
    expect(isKeyValid(past, 3600)).toBe(false);
  });

  it('rotateKeyPair returns old and new distinct pairs', () => {
    const { oldKeyPair, newKeyPair } = rotateKeyPair(kp);
    expect(oldKeyPair).toBe(kp);
    expect(pkToHex(newKeyPair.publicKey)).not.toBe(pkToHex(oldKeyPair.publicKey));
  });

  it('recordKeyRotation appends KEY_ROTATION event to chain', () => {
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const { oldKeyPair, newKeyPair } = rotateKeyPair(kp);
    const event = recordKeyRotation(
      genesis, 'portal',
      pkToHex(oldKeyPair.publicKey), pkToHex(newKeyPair.publicKey),
      'scheduled rotation', chainKP,
    );
    expect(event.event_type).toBe('KEY_ROTATION');
    expect(event.sequence_number).toBe(1);
    const payload = event.payload as { keypair_type: string; old_public_key: string; new_public_key: string };
    expect(payload.keypair_type).toBe('portal');
    expect(payload.old_public_key).toBe(pkToHex(oldKeyPair.publicKey));
    expect(payload.new_public_key).toBe(pkToHex(newKeyPair.publicKey));
  });
});
