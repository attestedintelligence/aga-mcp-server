/**
 * ML-DSA-65 + Ed25519 composite hybrid signature (SHARED_CRYPTO_FOUNDATION.md §2) — v2 profile.
 *
 * Byte-for-byte counterpart of the AGA Go/CIRCL construction in
 * aga-k8s/internal/crypto/backends/hybrid.go AND of VerifyBundle's packages/integrity/src/hybrid.ts
 * (this file is ported verbatim from the latter; only the hex/utf8 util import path differs). A
 * signature produced by any of the three verifies under the others. Proven byte-identical Go<->JS by
 * aga-k8s/internal/crypto/hybrid_xverify_test.go against the pinned cross-verify fixtures.
 *
 *   algorithm id : "ML-DSA-65+Ed25519-SHA256-JCS"
 *   composite    : len32(a) || a || len32(b) || b   (len32 = 4-byte big-endian uint32)
 *                  a = ML-DSA-65 component, b = Ed25519 component (for both keys and signatures)
 *   ML-DSA-65    : FIPS 204, EXTERNAL interface, EMPTY context, DETERMINISTIC (rnd = zeros).
 *   Ed25519      : RFC 8032, strict (zip215:false) with small-order public-key rejection.
 *   acceptance   : AND — both component signatures must verify; no partial acceptance.
 *
 * The v1 zero-dependency reference verifier (aga-receipt-spec/verify/verify-sep.mjs, node:crypto only)
 * does NOT import this; v2 lives in the agile engine, which carries the @noble dependency.
 */
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import type { SepSigner } from './crypto.js';

// @noble/ed25519 v2 needs a synchronous SHA-512 hook for synchronous sign/verify. Wiring it from
// @noble/hashes keeps the stack dependency-pure (no node:crypto in the composite path).
ed.etc.sha512Sync = (...m: Uint8Array[]): Uint8Array => sha512(ed.etc.concatBytes(...m));

/** The composite algorithm identifier, shared with AGA Go + VerifyBundle. */
export const ALG_HYBRID = 'ML-DSA-65+Ed25519-SHA256-JCS';

/** FIPS 204 ML-DSA-65 component byte lengths. */
export const MLDSA65_PUBLIC_KEY_BYTES = 1952;
export const MLDSA65_SECRET_KEY_BYTES = 4032;
export const MLDSA65_SIGNATURE_BYTES = 3309;
export const MLDSA65_SEED_BYTES = 32;
/** Ed25519 component byte lengths (RFC 8032). */
export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_SEED_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;

/** An ephemeral composite secret key. `mldsa` is the expanded ML-DSA-65 secret key; `ed` the 32-byte seed. */
export interface HybridSecretKey {
  mldsa: Uint8Array;
  ed: Uint8Array;
}

/** Encode two byte strings as len32(a) || a || len32(b) || b (4-byte big-endian lengths). */
export function encodeComposite(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + a.length + 4 + b.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, a.length, false); // big-endian
  out.set(a, 4);
  dv.setUint32(4 + a.length, b.length, false);
  out.set(b, 8 + a.length);
  return out;
}

/**
 * Decode len32(a) || a || len32(b) || b into [a, b]. Fails closed: throws on a short buffer, a length
 * prefix that overruns the data, or trailing bytes after b (extra bytes are rejected to remove a
 * malleability surface — matches the Go DecodeComposite trailing-byte reject).
 */
export function decodeComposite(data: Uint8Array): [Uint8Array, Uint8Array] {
  if (data.length < 8) throw new Error('composite too short');
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const aLen = dv.getUint32(0, false);
  if (4 + aLen + 4 > data.length) throw new Error('first component length exceeds data');
  const a = data.subarray(4, 4 + aLen);
  const bLenOffset = 4 + aLen;
  const bLen = dv.getUint32(bLenOffset, false);
  const bStart = bLenOffset + 4;
  if (bStart + bLen > data.length) throw new Error('second component length exceeds data');
  if (bStart + bLen !== data.length) throw new Error('trailing bytes after composite');
  const b = data.subarray(bStart, bStart + bLen);
  return [a, b];
}

/** Derive the composite public key bytes from a hybrid secret key. */
function compositePublicKey(sk: HybridSecretKey): Uint8Array {
  const mldsaPub = ml_dsa65.getPublicKey(sk.mldsa);
  const edPub = ed.getPublicKey(sk.ed);
  return encodeComposite(mldsaPub, edPub);
}

/** Lower-hex composite public key for a hybrid secret key. */
export function hybridPublicKeyHex(sk: HybridSecretKey): string {
  return bytesToHex(compositePublicKey(sk));
}

/** Generate a fresh ephemeral hybrid keypair. The secret key never leaves the caller. */
export function generateHybridKeypair(): { secretKey: HybridSecretKey; publicKeyHex: string } {
  const seed = ml_dsa65.keygen();
  const secretKey: HybridSecretKey = { mldsa: seed.secretKey, ed: ed.utils.randomPrivateKey() };
  return { secretKey, publicKeyHex: hybridPublicKeyHex(secretKey) };
}

/** Deterministically derive a hybrid keypair from two 32-byte seeds (used by the cross-verify fixtures). */
export function hybridKeypairFromSeeds(
  mldsaSeed: Uint8Array,
  edSeed: Uint8Array,
): { secretKey: HybridSecretKey; publicKeyHex: string } {
  if (mldsaSeed.length !== MLDSA65_SEED_BYTES) throw new Error('ML-DSA seed must be 32 bytes');
  if (edSeed.length !== ED25519_SEED_BYTES) throw new Error('Ed25519 seed must be 32 bytes');
  const secretKey: HybridSecretKey = { mldsa: ml_dsa65.keygen(mldsaSeed).secretKey, ed: edSeed };
  return { secretKey, publicKeyHex: hybridPublicKeyHex(secretKey) };
}

/** Sign raw message bytes, returning the composite signature bytes (trusted-input signing path). */
export function signHybridBytes(message: Uint8Array, sk: HybridSecretKey): Uint8Array {
  const mldsaSig = ml_dsa65.sign(message, sk.mldsa, { extraEntropy: false }); // empty ctx, deterministic
  const edSig = ed.sign(message, sk.ed);
  return encodeComposite(mldsaSig, edSig);
}

/** Sign a UTF-8 message; returns the lower-hex composite signature. */
export function signHybrid(message: string, sk: HybridSecretKey): string {
  return bytesToHex(signHybridBytes(utf8ToBytes(message), sk));
}

/** Strict, hardened Ed25519 verification over bytes (mirrors the v1 verifyHex hardening). */
function edVerifyHardened(edPub: Uint8Array, message: Uint8Array, edSig: Uint8Array): boolean {
  if (edPub.length !== ED25519_PUBLIC_KEY_BYTES || edSig.length !== ED25519_SIGNATURE_BYTES) return false;
  if (edPub.every((x) => x === 0)) return false; // reject the all-zero (identity) key
  try {
    if (ed.ExtendedPoint.fromHex(edPub).isSmallOrder()) return false; // reject small-order
    return ed.verify(edSig, message, edPub, { zip215: false });
  } catch {
    return false;
  }
}

/**
 * Verify a composite signature over raw message bytes under a composite public key. Returns true only
 * if BOTH the ML-DSA-65 and the Ed25519 components verify. Fails closed on any malformed/short/over-long
 * composite or wrong component length.
 */
export function verifyHybridBytes(
  compositePub: Uint8Array,
  message: Uint8Array,
  compositeSig: Uint8Array,
): boolean {
  let mldsaPub: Uint8Array;
  let edPub: Uint8Array;
  let mldsaSig: Uint8Array;
  let edSig: Uint8Array;
  try {
    [mldsaPub, edPub] = decodeComposite(compositePub);
    [mldsaSig, edSig] = decodeComposite(compositeSig);
  } catch {
    return false;
  }
  if (mldsaPub.length !== MLDSA65_PUBLIC_KEY_BYTES) return false;
  if (mldsaSig.length !== MLDSA65_SIGNATURE_BYTES) return false;
  if (edPub.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (edSig.length !== ED25519_SIGNATURE_BYTES) return false;
  let mldsaOk: boolean;
  try {
    mldsaOk = ml_dsa65.verify(mldsaSig, message, mldsaPub); // empty context (default)
  } catch {
    return false;
  }
  if (!mldsaOk) return false;
  return edVerifyHardened(edPub, message, edSig);
}

/**
 * Verify a lower-hex composite signature over a UTF-8 message under a lower-hex composite public key.
 * Rejects malformed hex before touching the curve/lattice; never throws.
 */
export function verifyHybrid(pubHex: unknown, message: string, sigHex: unknown): boolean {
  if (typeof pubHex !== 'string' || typeof sigHex !== 'string') return false;
  if (!/^[0-9a-fA-F]+$/.test(pubHex) || pubHex.length % 2 !== 0) return false;
  if (!/^[0-9a-fA-F]+$/.test(sigHex) || sigHex.length % 2 !== 0) return false;
  try {
    return verifyHybridBytes(hexToBytes(pubHex.toLowerCase()), utf8ToBytes(message), hexToBytes(sigHex.toLowerCase()));
  } catch {
    return false;
  }
}

/** A v2 composite SepSigner from two 32-byte seeds (deterministic; for the producer + cross-verify tests). */
export function hybridSignerFromSeeds(mldsaSeed: Uint8Array, edSeed: Uint8Array): SepSigner {
  const { secretKey, publicKeyHex } = hybridKeypairFromSeeds(mldsaSeed, edSeed);
  return { algorithm: ALG_HYBRID, publicKeyHex, sign: (m) => signHybrid(m, secretKey) };
}

/** A v2 composite SepSigner from a fresh ephemeral keypair (the secret key is returned for persistence). */
export function generateHybridSigner(): { signer: SepSigner; secretKey: HybridSecretKey } {
  const { secretKey, publicKeyHex } = generateHybridKeypair();
  return { signer: { algorithm: ALG_HYBRID, publicKeyHex, sign: (m) => signHybrid(m, secretKey) }, secretKey };
}
