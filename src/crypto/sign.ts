/**
 * Ed25519 signing — node:crypto only (no third-party Ed25519 library), so the package ships ONE
 * Ed25519 implementation (the canonical src/sep engine uses node:crypto too). Byte-for-byte
 * compatible with the prior implementation: a 32-byte secretKey IS the RFC-8032 seed, and
 * Ed25519 signatures are deterministic, so existing keys/signatures verify unchanged.
 *
 * (@noble/hashes is still used elsewhere for blake2b, which node:crypto does not expose.)
 */
import {
  createHash, createPrivateKey, createPublicKey, generateKeyPairSync,
  sign as nodeSign, verify as nodeVerify,
} from 'node:crypto';
import type { KeyPair, Signature, SignatureBase64 } from './types.js';

const SPKI = Buffer.from('302a300506032b6570032100', 'hex');        // Ed25519 SubjectPublicKeyInfo prefix
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex'); // Ed25519 PKCS8 seed prefix
const enc = new TextEncoder();

const privFromSeed = (sk: Uint8Array) =>
  createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(sk)]), format: 'der', type: 'pkcs8' });
const pubFromRaw = (pk: Uint8Array) =>
  createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(pk)]), format: 'der', type: 'spki' });

export function generateKeyPair(): KeyPair {
  const { privateKey } = generateKeyPairSync('ed25519');
  const secretKey = new Uint8Array(privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32));
  const publicKey = new Uint8Array(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32));
  return { publicKey, secretKey };
}

export function sign(msg: Uint8Array, sk: Uint8Array): Signature {
  return new Uint8Array(nodeSign(null, Buffer.from(msg), privFromSeed(sk)));
}
export function signStr(msg: string, sk: Uint8Array): Signature { return sign(enc.encode(msg), sk); }

export function verify(sig: Signature, msg: Uint8Array, pk: Uint8Array): boolean {
  try { return nodeVerify(null, Buffer.from(msg), pubFromRaw(pk), Buffer.from(sig)); } catch { return false; }
}
export function verifyStr(sig: Signature, msg: string, pk: Uint8Array): boolean {
  return verify(sig, enc.encode(msg), pk);
}

export const sigToB64 = (s: Signature): SignatureBase64 => Buffer.from(s).toString('base64');
export const b64ToSig = (b: SignatureBase64): Signature => new Uint8Array(Buffer.from(b, 'base64'));
export const pkToHex = (pk: Uint8Array): string => Buffer.from(pk).toString('hex');
export const hexToPk = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, 'hex'));

/** Key fingerprint: SHA-256 prefix of public key hex, 16-char hex identifier. */
export function keyFingerprint(publicKeyHex: string): string {
  return createHash('sha256').update(Buffer.from(publicKeyHex, 'utf8')).digest('hex').slice(0, 16);
}
