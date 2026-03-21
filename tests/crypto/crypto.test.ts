/**
 * Crypto test suite - 11 tests per spec.
 * Known-answer vectors, roundtrips, RFC 8785.
 */
import { describe, it, expect } from 'vitest';
import { sha256Str, sha256Bytes, sha256Cat, sha256HexCat, blake2b256 } from '../../src/crypto/hash.js';
import { generateKeyPair, sign, signStr, verify, verifyStr, sigToB64, b64ToSig, pkToHex, hexToPk } from '../../src/crypto/sign.js';
import { canonicalize } from '../../src/crypto/canonicalize.js';
import { keyFingerprint, isKeyValid } from '../../src/crypto/keys.js';
import { generateSalt } from '../../src/crypto/salt.js';

describe('crypto - known-answer vectors + roundtrips', () => {
  // 1. SHA-256 known answer
  it('SHA-256 empty string matches NIST vector', () => {
    expect(sha256Str('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  // 2. SHA-256 "hello" known answer
  it('SHA-256 "hello" matches known vector', () => {
    expect(sha256Str('hello')).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });

  // 3. BLAKE2b-256 produces 64-char hex
  it('BLAKE2b-256 produces valid hex', () => {
    const h = blake2b256(new TextEncoder().encode('test'));
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  // 4. sha256HexCat concatenates then hashes
  it('sha256HexCat is SHA-256(concat(hex strings))', () => {
    expect(sha256HexCat('abcd', 'ef01')).toBe(sha256Str('abcdef01'));
  });

  // 5. Ed25519 sign/verify roundtrip
  it('Ed25519 sign+verify roundtrip', () => {
    const kp = generateKeyPair();
    const msg = new TextEncoder().encode('test message');
    const sig = sign(msg, kp.secretKey);
    expect(verify(sig, msg, kp.publicKey)).toBe(true);
  });

  // 6. Ed25519 rejects wrong key
  it('Ed25519 rejects signature with wrong key', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const sig = signStr('test', kp1.secretKey);
    expect(verifyStr(sig, 'test', kp2.publicKey)).toBe(false);
  });

  // 7. Base64 signature roundtrip
  it('Signature base64 roundtrip', () => {
    const kp = generateKeyPair();
    const sig = signStr('data', kp.secretKey);
    const b64 = sigToB64(sig);
    const back = b64ToSig(b64);
    expect(verifyStr(back, 'data', kp.publicKey)).toBe(true);
  });

  // 8. Public key hex roundtrip
  it('Public key hex roundtrip', () => {
    const kp = generateKeyPair();
    const hex = pkToHex(kp.publicKey);
    const back = hexToPk(hex);
    expect(Buffer.from(back).equals(Buffer.from(kp.publicKey))).toBe(true);
  });

  // 9. RFC 8785 canonical serialization - sorted keys
  it('Canonicalize sorts keys deterministically', () => {
    const a = canonicalize({ z: 1, a: 2, m: 3 });
    const b = canonicalize({ a: 2, z: 1, m: 3 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"m":3,"z":1}');
  });

  // 10. Key fingerprint produces 16-char hex
  it('keyFingerprint produces 16-char hex prefix', () => {
    const kp = generateKeyPair();
    const fp = keyFingerprint(kp.publicKey);
    expect(fp).toMatch(/^[0-9a-f]{16}$/);
  });

  // 11. isKeyValid validates hex format
  it('isKeyValid accepts valid hex, rejects invalid', () => {
    const kp = generateKeyPair();
    expect(isKeyValid(pkToHex(kp.publicKey))).toBe(true);
    expect(isKeyValid('not-a-key')).toBe(false);
    expect(isKeyValid('ABCD')).toBe(false);
  });
});
