import { describe, it, expect } from 'vitest';
import { generateKeyPair, signStr, verifyStr, sign, verify, sigToB64, b64ToSig, pkToHex, hexToPk } from '../../src/crypto/sign.js';

describe('Ed25519', () => {
  it('keypair sizes', () => {
    const kp = generateKeyPair();
    expect(kp.publicKey.length).toBe(32);
    expect(kp.secretKey.length).toBe(32);
  });
  it('sign+verify bytes', () => {
    const kp = generateKeyPair();
    const msg = new TextEncoder().encode('test');
    expect(verify(sign(msg, kp.secretKey), msg, kp.publicKey)).toBe(true);
  });
  it('sign+verify string', () => {
    const kp = generateKeyPair();
    expect(verifyStr(signStr('hello', kp.secretKey), 'hello', kp.publicKey)).toBe(true);
  });
  it('rejects tampered', () => {
    const kp = generateKeyPair();
    expect(verifyStr(signStr('a', kp.secretKey), 'b', kp.publicKey)).toBe(false);
  });
  it('rejects wrong key', () => {
    const kp1 = generateKeyPair(), kp2 = generateKeyPair();
    expect(verifyStr(signStr('x', kp1.secretKey), 'x', kp2.publicKey)).toBe(false);
  });
  it('sig base64 roundtrip', () => {
    const kp = generateKeyPair();
    const sig = signStr('m', kp.secretKey);
    expect(verifyStr(b64ToSig(sigToB64(sig)), 'm', kp.publicKey)).toBe(true);
  });
  it('pk hex roundtrip', () => {
    const kp = generateKeyPair();
    expect(hexToPk(pkToHex(kp.publicKey))).toEqual(kp.publicKey);
  });
});
