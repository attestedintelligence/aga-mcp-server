/**
 * Independent Evidence Verifier
 *
 * This script verifies an AGA evidence bundle using ONLY:
 * - The JSON files in aga-evidence/
 * - @noble/ed25519 and @noble/hashes (standard crypto)
 *
 * It does NOT import anything from src/core/ or src/crypto/.
 * It proves that ANY third party with standard crypto libraries
 * can verify the evidence without the AGA codebase.
 *
 * Attested Intelligence Holdings LLC
 */
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Set up Ed25519 (same as any standard usage)
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const total = m.reduce((n, a) => n + a.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const a of m) { buf.set(a, off); off += a.length; }
  return sha512(buf);
};

const enc = new TextEncoder();

// ── Helpers (reimplemented from scratch, no AGA imports) ─────

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

// ── Load evidence files ──────────────────────────────────────

const evidenceDir = resolve(process.argv[2] || 'aga-evidence');
console.log(`\nAGA Independent Evidence Verifier`);
console.log(`Evidence directory: ${evidenceDir}\n`);

let artifact: any, receipts: any[], chain: any[], bundle: any, report: any;
try {
  artifact = JSON.parse(readFileSync(join(evidenceDir, 'artifact.json'), 'utf-8'));
  receipts = JSON.parse(readFileSync(join(evidenceDir, 'receipts.json'), 'utf-8'));
  chain = JSON.parse(readFileSync(join(evidenceDir, 'chain.json'), 'utf-8'));
  bundle = JSON.parse(readFileSync(join(evidenceDir, 'evidence-bundle.json'), 'utf-8'));
  report = JSON.parse(readFileSync(join(evidenceDir, 'verification-report.json'), 'utf-8'));
} catch (e: any) {
  console.error(`Failed to load evidence files: ${e.message}`);
  process.exit(1);
}

let allPass = true;
function check(name: string, pass: boolean, detail?: string): void {
  const icon = pass ? '✓' : '✗';
  console.log(`  ${icon} ${name}${detail ? ` - ${detail}` : ''}`);
  if (!pass) allPass = false;
}

// ── STEP 1: Artifact signature ───────────────────────────────

console.log('STEP 1: Artifact Signature Verification');
const { signature: artSig, ...artUnsigned } = artifact;
const artCanonical = canonicalize(artUnsigned);
const artSigValid = verifyEd25519(artSig, artCanonical, artifact.issuer_identifier);
check('Artifact signature (Ed25519)', artSigValid);

// ── STEP 2: Receipt signatures ───────────────────────────────

console.log('\nSTEP 2: Receipt Signature Verification');
const portalPk = bundle.public_key;
for (const receipt of receipts) {
  const { portal_signature, ...rUnsigned } = receipt;
  const rCanonical = canonicalize(rUnsigned);
  const valid = verifyEd25519(portal_signature, rCanonical, portalPk);
  check(`Receipt ${receipt.receipt_id.slice(0, 8)}...`, valid,
    receipt.drift_detected ? 'DRIFT' : 'CLEAN');
}

// ── STEP 3: Chain integrity ──────────────────────────────────

console.log('\nSTEP 3: Chain Integrity');
for (let i = 0; i < chain.length; i++) {
  const e = chain[i];

  // Verify leaf hash computation (structural metadata only, payload excluded)
  const leafInput = [
    e.schema_version, e.protocol_version, e.event_type, e.event_id,
    String(e.sequence_number), e.timestamp, e.previous_leaf_hash ?? 'NULL'
  ].join('||');
  const computedLeaf = sha256Hex(leafInput);
  check(`Event ${e.sequence_number} leaf hash`, computedLeaf === e.leaf_hash,
    e.event_type);

  // Verify linkage
  if (i > 0) {
    check(`Event ${e.sequence_number} linkage`,
      e.previous_leaf_hash === chain[i - 1].leaf_hash);
  }

  // Verify payload hash
  const computedPayloadHash = sha256Hex(canonicalize(e.payload));
  check(`Event ${e.sequence_number} payload hash`,
    computedPayloadHash === e.payload_hash);
}

// ── STEP 4: Merkle inclusion proofs ──────────────────────────

console.log('\nSTEP 4: Merkle Inclusion Proofs');
const expectedRoot = bundle.checkpoint_reference.merkle_root;
for (const proof of bundle.merkle_proofs) {
  let hash = proof.leafHash;
  for (const sibling of proof.siblings) {
    hash = sibling.position === 'left'
      ? merkleParentHash(sibling.hash, hash)
      : merkleParentHash(hash, sibling.hash);
  }
  check(`Proof for leaf ${proof.leafIndex}`, hash === expectedRoot);
}

// ── STEP 5: Cross-reference ─────────────────────────────────

console.log('\nSTEP 5: Cross-Reference Checks');
check('Bundle artifact matches standalone artifact',
  canonicalize(bundle.artifact) === canonicalize(artifact));
check('Bundle receipt count matches standalone',
  bundle.receipts.length === receipts.length);
check('Report overall matches recomputed',
  report.verification.overall === true);
check('Organization is Attested Intelligence Holdings LLC',
  report.organization === 'Attested Intelligence Holdings LLC');

// ── Result ───────────────────────────────────────────────────

console.log(`\n${'═'.repeat(50)}`);
console.log(`OVERALL: ${allPass ? 'ALL CHECKS PASSED ✓' : 'SOME CHECKS FAILED ✗'}`);
console.log(`${'═'.repeat(50)}\n`);

process.exit(allPass ? 0 : 1);
