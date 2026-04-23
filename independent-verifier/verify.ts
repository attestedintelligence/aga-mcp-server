/**
 * AGA Independent Verifier
 *
 * Standalone verification of AGA Evidence Bundles using ONLY standard
 * cryptographic libraries. This verifier imports ZERO modules from the
 * AGA codebase (../src/).
 *
 * Implements the full 4-step verification process:
 * 1. Verify artifact signature (Ed25519 over RFC 8785 canonical JSON)
 * 2. Verify each receipt signature (Ed25519)
 * 3. Verify Merkle inclusion proofs (structural metadata leaf hashes vs checkpoint root)
 * 4. (Optional) Verify checkpoint anchor
 *
 * Steps 1-3 work fully offline. Step 4 is optional.
 *
 * Attested Intelligence Holdings LLC
 */
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// ── Ed25519 setup ────────────────────────────────────────────
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const total = m.reduce((n, a) => n + a.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const a of m) { buf.set(a, off); off += a.length; }
  return sha512(buf);
};

const enc = new TextEncoder();

// ── Types (reimplemented, no AGA imports) ────────────────────

export interface VerificationResult {
  step1_artifact_sig: boolean;
  step2_receipt_sigs: boolean;
  step3_merkle_proofs: boolean;
  step4_anchor: 'VERIFIED' | 'SKIPPED';
  overall: boolean;
  errors: string[];
  details: {
    receipt_results: boolean[];
    proof_results: boolean[];
  };
}

interface MerkleProof {
  leafHash: string;
  leafIndex: number;
  siblings: Array<{ hash: string; position: 'left' | 'right' }>;
  root: string;
}

interface EvidenceBundle {
  artifact: Record<string, unknown> & { signature: string; issuer_identifier: string };
  receipts: Array<Record<string, unknown> & { portal_signature: string; receipt_id: string }>;
  merkle_proofs: MerkleProof[];
  checkpoint_reference: { merkle_root: string; [key: string]: unknown };
  public_key: string;
  bundle_signature: string;
  verification_tier?: string;
}

// ── Crypto helpers (reimplemented from scratch) ──────────────

function deepSortKeys(obj: unknown): unknown {
  if (obj === null || obj === undefined || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(deepSortKeys);
  if (obj instanceof Uint8Array) return obj;
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

function verifyEd25519(sigBase64: string, message: string, publicKeyHex: string): boolean {
  try {
    const sig = new Uint8Array(Buffer.from(sigBase64, 'base64'));
    const pk = hexToBytes(publicKeyHex);
    return ed.verify(sig, enc.encode(message), pk);
  } catch { return false; }
}

function merkleParentHash(left: string, right: string): string {
  return sha256Hex(left + right);
}

// ── Step 1: Verify artifact signature (Ed25519) ─────────────

export function verifyArtifactSignature(artifact: EvidenceBundle['artifact']): boolean {
  const { signature, ...unsigned } = artifact;
  const canonical = canonicalize(unsigned);
  return verifyEd25519(signature, canonical, artifact.issuer_identifier);
}

// ── Step 2: Verify each receipt signature (Ed25519) ──────────

export function verifyReceiptSignatures(receipts: EvidenceBundle['receipts'], portalPublicKey: string): boolean[] {
  return receipts.map(receipt => {
    const { portal_signature, ...unsigned } = receipt;
    const canonical = canonicalize(unsigned);
    return verifyEd25519(portal_signature, canonical, portalPublicKey);
  });
}

// ── Step 3: Verify Merkle inclusion proofs ───────────────────

export function verifyMerkleProofs(proofs: MerkleProof[], checkpointRoot: string): boolean[] {
  return proofs.map(proof => {
    let hash = proof.leafHash;
    for (const sibling of proof.siblings) {
      hash = sibling.position === 'left'
        ? merkleParentHash(sibling.hash, hash)
        : merkleParentHash(hash, sibling.hash);
    }
    return hash === checkpointRoot;
  });
}

// ── Step 4 (optional): Verify checkpoint anchor ─────────────

export function verifyCheckpointAnchor(_checkpoint: Record<string, unknown>): 'VERIFIED' | 'SKIPPED' {
  // Offline mode - no network access to verify on-chain anchor
  return 'SKIPPED';
}

// ── Main entry point ─────────────────────────────────────────

export function verifyEvidenceBundle(bundleJson: string): VerificationResult {
  const errors: string[] = [];
  let bundle: EvidenceBundle;

  try {
    bundle = JSON.parse(bundleJson);
  } catch {
    return {
      step1_artifact_sig: false, step2_receipt_sigs: false,
      step3_merkle_proofs: false, step4_anchor: 'SKIPPED',
      overall: false, errors: ['Failed to parse bundle JSON'],
      details: { receipt_results: [], proof_results: [] },
    };
  }

  // Step 1: Artifact signature
  const step1 = verifyArtifactSignature(bundle.artifact);
  if (!step1) errors.push('Artifact signature verification failed');

  // Step 2: Receipt signatures
  const receiptResults = verifyReceiptSignatures(bundle.receipts, bundle.public_key);
  const step2 = receiptResults.every(r => r);
  receiptResults.forEach((r, i) => {
    if (!r) errors.push(`Receipt ${bundle.receipts[i].receipt_id} signature failed`);
  });

  // Step 3: Merkle inclusion proofs
  const proofResults = verifyMerkleProofs(bundle.merkle_proofs, bundle.checkpoint_reference.merkle_root);
  const step3 = proofResults.length === 0 ? true : proofResults.every(r => r);
  proofResults.forEach((r, i) => {
    if (!r) errors.push(`Merkle proof ${i} failed`);
  });

  // Step 4: Checkpoint anchor
  const step4 = verifyCheckpointAnchor(bundle.checkpoint_reference as Record<string, unknown>);

  return {
    step1_artifact_sig: step1,
    step2_receipt_sigs: step2,
    step3_merkle_proofs: step3,
    step4_anchor: step4,
    overall: step1 && step2 && step3,
    errors,
    details: { receipt_results: receiptResults, proof_results: proofResults },
  };
}

// ── CLI mode ─────────────────────────────────────────────────

if (typeof process !== 'undefined' && process.argv[1]?.includes('verify')) {
  const { readFileSync } = await import('node:fs');
  const bundlePath = process.argv[2];
  if (!bundlePath) {
    console.error('Usage: npx tsx verify.ts <bundle.json>');
    process.exit(1);
  }
  const bundleJson = readFileSync(bundlePath, 'utf-8');
  const result = verifyEvidenceBundle(bundleJson);

  console.log('\nAGA Independent Verifier\n');
  console.log(`Step 1 - Artifact signature:     ${result.step1_artifact_sig ? 'PASS' : 'FAIL'}`);
  console.log(`Step 2 - Receipt signatures:     ${result.step2_receipt_sigs ? 'PASS' : 'FAIL'} (${result.details.receipt_results.filter(r => r).length}/${result.details.receipt_results.length})`);
  console.log(`Step 3 - Merkle inclusion proofs: ${result.step3_merkle_proofs ? 'PASS' : 'FAIL'} (${result.details.proof_results.filter(r => r).length}/${result.details.proof_results.length})`);
  console.log(`Step 4 - Checkpoint anchor:      ${result.step4_anchor}`);
  console.log(`\nOVERALL: ${result.overall ? 'VERIFIED' : 'FAILED'}`);
  if (result.errors.length) {
    console.log('\nErrors:');
    result.errors.forEach(e => console.log(`  - ${e}`));
  }

  process.exit(result.overall ? 0 : 1);
}
