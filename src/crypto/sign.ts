import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import type { KeyPair, Signature, SignatureBase64 } from './types.js';

// Set sha512 sync ONCE at module load
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const total = m.reduce((n, a) => n + a.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const a of m) { buf.set(a, off); off += a.length; }
  return sha512(buf);
};

const enc = new TextEncoder();

export function generateKeyPair(): KeyPair {
  const secretKey = ed.utils.randomPrivateKey();
  return { publicKey: ed.getPublicKey(secretKey), secretKey };
}

export function sign(msg: Uint8Array, sk: Uint8Array): Signature { return ed.sign(msg, sk); }
export function signStr(msg: string, sk: Uint8Array): Signature { return sign(enc.encode(msg), sk); }

export function verify(sig: Signature, msg: Uint8Array, pk: Uint8Array): boolean {
  try { return ed.verify(sig, msg, pk); } catch { return false; }
}
export function verifyStr(sig: Signature, msg: string, pk: Uint8Array): boolean {
  return verify(sig, enc.encode(msg), pk);
}

export const sigToB64 = (s: Signature): SignatureBase64 => Buffer.from(s).toString('base64');
export const b64ToSig = (b: SignatureBase64): Signature => new Uint8Array(Buffer.from(b, 'base64'));
export const pkToHex = (pk: Uint8Array): string => bytesToHex(pk);
export const hexToPk = (h: string): Uint8Array => hexToBytes(h);
