/**
 * AGA Gateway Bundle Verifier
 * Verifies Ed25519-SHA256-JCS evidence bundles.
 * Uses ONLY @noble crypto - zero imports from ../core/ or ../crypto/.
 *
 * 5-step verification matching gateway, Python SDK, and browser verifier:
 * 1. Algorithm check
 * 2. Receipt signature verification
 * 3. Chain integrity (previous_receipt_hash linkage)
 * 4. Merkle inclusion proofs
 * 5. Bundle consistency (leaf hashes match receipts)
 *
 * Patent: USPTO App. No. 19/433,835
 * Copyright (c) 2026 Attested Intelligence Holdings LLC
 * SPDX-License-Identifier: MIT
 */

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Ed25519 setup
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const total = m.reduce((n, a) => n + a.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const a of m) { buf.set(a, off); off += a.length; }
  return sha512(buf);
};

const enc = new TextEncoder();

// ── RFC 8785 Canonicalization ────────────────────────────────

function deepSortKeys(obj: unknown): unknown {
  if (obj === null || obj === undefined || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(deepSortKeys);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    sorted[key] = deepSortKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

function canonicalize(obj: unknown): string {
  return JSON.stringify(deepSortKeys(obj));
}

function sha256Hex(data: string): string {
  return bytesToHex(sha256(enc.encode(data)));
}

function merkleNodeHash(leftHex: string, rightHex: string): string {
  const left = hexToBytes(leftHex);
  const right = hexToBytes(rightHex);
  const combined = new Uint8Array(left.length + right.length);
  combined.set(left, 0);
  combined.set(right, left.length);
  return bytesToHex(sha256(combined));
}

// ── Verification result ─────────────────────────────────────

export interface GatewayVerificationResult {
  algorithm_valid: boolean;
  receipt_signatures_valid: boolean;
  chain_integrity_valid: boolean;
  merkle_proofs_valid: boolean;
  bundle_consistent: boolean;
  overall_valid: boolean;
  receipts_checked: number;
  algorithm: string;
  error?: string;
}

// ── 5-step verification ─────────────────────────────────────

export async function verifyGatewayBundle(bundleJson: string): Promise<GatewayVerificationResult> {
  let bundle: any;
  try {
    bundle = JSON.parse(bundleJson);
  } catch {
    return {
      algorithm_valid: false, receipt_signatures_valid: false,
      chain_integrity_valid: false, merkle_proofs_valid: false,
      bundle_consistent: false, overall_valid: false,
      receipts_checked: 0, algorithm: '', error: 'Invalid JSON',
    };
  }

  const result: GatewayVerificationResult = {
    algorithm_valid: false, receipt_signatures_valid: false,
    chain_integrity_valid: false, merkle_proofs_valid: false,
    bundle_consistent: false, overall_valid: false,
    receipts_checked: bundle.receipts?.length ?? 0,
    algorithm: bundle.algorithm ?? '',
  };

  // Step 1: Algorithm
  if (bundle.algorithm !== 'Ed25519-SHA256-JCS') {
    result.error = `unsupported algorithm: ${bundle.algorithm}`;
    return result;
  }
  for (const r of bundle.receipts) {
    if (r.algorithm !== 'Ed25519-SHA256-JCS') {
      result.error = `receipt has wrong algorithm: ${r.algorithm}`;
      return result;
    }
  }
  result.algorithm_valid = true;

  // Step 2: Receipt signatures
  try {
    for (const receipt of bundle.receipts) {
      const { signature, ...unsigned } = receipt;
      const canonical = canonicalize(unsigned);
      const sig = hexToBytes(signature);
      const pk = hexToBytes(receipt.public_key);
      if (!ed.verify(sig, enc.encode(canonical), pk)) {
        result.error = `Receipt ${receipt.receipt_id} signature failed`;
        return result;
      }
    }
    result.receipt_signatures_valid = true;
  } catch (e) {
    result.error = `signature verification error: ${e}`;
    return result;
  }

  // Step 3: Chain integrity
  try {
    const receipts = bundle.receipts;
    if (receipts.length > 0 && receipts[0].previous_receipt_hash !== '') {
      result.error = 'First receipt previous_receipt_hash must be empty';
      return result;
    }
    for (let i = 1; i < receipts.length; i++) {
      const expectedHash = sha256Hex(canonicalize(receipts[i - 1]));
      if (receipts[i].previous_receipt_hash !== expectedHash) {
        result.error = `Chain break at receipt ${i}`;
        return result;
      }
    }
    result.chain_integrity_valid = true;
  } catch (e) {
    result.error = `chain integrity error: ${e}`;
    return result;
  }

  // Step 4: Merkle proofs
  try {
    for (const proof of bundle.merkle_proofs) {
      let currentHash = proof.leaf_hash;
      for (let i = 0; i < proof.siblings.length; i++) {
        if (proof.directions[i] === 'left') {
          currentHash = merkleNodeHash(proof.siblings[i], currentHash);
        } else {
          currentHash = merkleNodeHash(currentHash, proof.siblings[i]);
        }
      }
      if (currentHash !== bundle.merkle_root) {
        result.error = `Merkle proof failed for leaf ${proof.leaf_index}`;
        return result;
      }
      if (proof.merkle_root !== bundle.merkle_root) {
        result.error = `Proof root mismatch at leaf ${proof.leaf_index}`;
        return result;
      }
    }
    result.merkle_proofs_valid = true;
  } catch (e) {
    result.error = `merkle proof error: ${e}`;
    return result;
  }

  // Step 5: Bundle consistency
  try {
    if (bundle.merkle_proofs.length !== bundle.receipts.length) {
      result.error = 'Proof count != receipt count';
      return result;
    }
    for (let i = 0; i < bundle.receipts.length; i++) {
      const leafHash = sha256Hex(canonicalize(bundle.receipts[i]));
      if (bundle.merkle_proofs[i].leaf_hash !== leafHash) {
        result.error = `Leaf hash mismatch at receipt ${i}`;
        return result;
      }
      if (bundle.merkle_proofs[i].leaf_index !== i) {
        result.error = `Leaf index mismatch at receipt ${i}`;
        return result;
      }
    }
    result.bundle_consistent = true;
  } catch (e) {
    result.error = `consistency error: ${e}`;
    return result;
  }

  result.overall_valid = true;
  return result;
}
