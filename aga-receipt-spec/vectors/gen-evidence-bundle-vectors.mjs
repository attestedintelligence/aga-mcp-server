#!/usr/bin/env node
/**
 * Canonical SEP Evidence Bundle conformance-corpus generator.
 * See ../CANONICAL_CONSTRUCTION_v2.md. Zero external deps — Node 18+ crypto only
 * (Ed25519 + SHA-256). Deterministic: fixed seed + fixed timestamps => reproducible
 * vectors. Every produced bundle is self-verified (signatures + Merkle + checkpoint)
 * and each Merkle root is corroborated by an INDEPENDENT hand-coded computation,
 * never re-baselined from the tree-builder under test.
 *
 * Run: node vectors/gen-evidence-bundle-vectors.mjs   (writes aga_evidence_bundle_vectors.json)
 */
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ALGO = 'Ed25519-SHA256-JCS';
const GATEWAY_ID = 'aga-demo-001';
const BASE_TS = Date.parse('2026-06-03T00:00:00Z');

// ── primitives (CANONICAL_CONSTRUCTION_v2.md §1,§3,§5) ───────────────────────
const canon = (o) => o === null || typeof o !== 'object' ? JSON.stringify(o)
  : Array.isArray(o) ? '[' + o.map(canon).join(',') + ']'
  : '{' + Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
const sha = (b) => createHash('sha256').update(b).digest('hex');
const u8 = (s) => Buffer.from(s, 'utf8');
const leaf = (r) => sha(u8(canon(r)));                                  // no-prefix, full receipt
const node = (l, r) => sha(Buffer.concat([Buffer.from(l, 'hex'), Buffer.from(r, 'hex')])); // raw-byte concat

// ── deterministic Ed25519 key from a 32-byte seed (node crypto, no deps) ─────
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const sk = createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.alloc(32, 7)]), format: 'der', type: 'pkcs8' });
const pubRaw = createPublicKey(sk).export({ type: 'spki', format: 'der' }).subarray(-32);
const pubHex = Buffer.from(pubRaw).toString('hex');
const pk = createPublicKey({ key: Buffer.concat([SPKI, pubRaw]), format: 'der', type: 'spki' });
const signHex = (msg) => Buffer.from(edSign(null, u8(msg), sk)).toString('hex');
const verifyHex = (msg, sigHex) => edVerify(null, u8(msg), pk, Buffer.from(sigHex, 'hex'));

const POLICY_REF = sha(u8('aga-demo-policy/allow:read_file,search_web/deny:execute_command/prefix:/data/'));

function receipt(i, tool, decision, reason, args, prevLeaf) {
  const body = {
    receipt_id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
    receipt_version: '1.0', algorithm: ALGO,
    timestamp: new Date(BASE_TS + i * 1000).toISOString(),
    request_id: String(i + 1), method: 'tools/call',
    tool_name: tool, decision, reason, policy_reference: POLICY_REF,
    arguments_hash: sha(u8(canon(args))), previous_receipt_hash: prevLeaf,
    gateway_id: GATEWAY_ID, public_key: pubHex,
  };
  return { ...body, signature: signHex(canon(body)) };
}

function buildTree(leaves) {
  const levels = [leaves.slice()];
  while (levels[levels.length - 1].length > 1) {
    const cur = levels[levels.length - 1], next = [];
    for (let i = 0; i < cur.length; i += 2) next.push(i + 1 < cur.length ? node(cur[i], cur[i + 1]) : cur[i]);
    levels.push(next);
  }
  return levels;
}
function proofFor(levels, leaves, index) {
  const siblings = [], directions = []; let idx = index;
  for (let l = 0; l < levels.length - 1; l++) {
    const level = levels[l], isRight = idx % 2 === 1, sib = isRight ? idx - 1 : idx + 1;
    if (sib < level.length) {            // sibling exists at this level
      siblings.push(level[sib]);
      directions.push(isRight ? 'left' : 'right');
    } // else: this node is promoted (no sibling) — emit no proof entry for this level
    idx = Math.floor(idx / 2);
  }
  return { leaf_hash: leaves[index], leaf_index: index, siblings, directions, merkle_root: levels[levels.length - 1][0] };
}

// INDEPENDENT root: explicit hand-coded formulas per leaf count (corroboration, §7)
function independentRoot(L) {
  if (L.length === 1) return L[0];
  if (L.length === 3) return node(node(L[0], L[1]), L[2]);                 // L2 promoted
  if (L.length === 5) return node(node(node(L[0], L[1]), node(L[2], L[3])), L[4]); // L4 promoted twice
  throw new Error('no independent formula for length ' + L.length);
}

function makeBundle(session) {
  const receipts = []; const leaves = []; let prev = '';
  session.forEach((s, i) => { const r = receipt(i, s.tool, s.decision, s.reason, s.args, prev); const lh = leaf(r); receipts.push(r); leaves.push(lh); prev = lh; });
  const levels = buildTree(leaves);
  const root = levels[levels.length - 1][0];
  const proofs = leaves.map((_, i) => proofFor(levels, leaves, i));
  const cpBody = { algorithm: ALGO, gateway_id: GATEWAY_ID, generated_at: new Date(BASE_TS).toISOString(), head_leaf_hash: leaves[leaves.length - 1], leaf_count: receipts.length, merkle_root: root };
  const checkpoint = { ...cpBody, signature: signHex(canon(cpBody)) };
  const bundle = { schema_version: '2.0', bundle_id: `bundle-${receipts.length}`, algorithm: ALGO, generated_at: cpBody.generated_at, gateway_id: GATEWAY_ID, public_key: pubHex, policy_reference: POLICY_REF, receipts, merkle_root: root, merkle_proofs: proofs, checkpoint, offline_capable: true };
  // ── self-verify + independent corroboration ──
  for (const r of receipts) { const { signature, ...b } = r; if (!verifyHex(canon(b), signature)) throw new Error('receipt sig fail'); }
  if (!verifyHex(canon(cpBody), checkpoint.signature)) throw new Error('checkpoint sig fail');
  for (let i = 1; i < receipts.length; i++) if (receipts[i].previous_receipt_hash !== leaves[i - 1]) throw new Error('chain fail');
  for (const p of proofs) { let c = p.leaf_hash; for (let j = 0; j < p.siblings.length; j++) c = p.directions[j] === 'left' ? node(p.siblings[j], c) : node(c, p.siblings[j]); if (c !== root) throw new Error('proof fail'); }
  const indep = independentRoot(leaves);
  if (indep !== root) throw new Error(`INDEPENDENT ROOT MISMATCH len=${leaves.length}: ${indep} != ${root}`);
  return { bundle, expected_merkle_root: root, independently_corroborated: true };
}

const SESS = [
  { tool: 'search_web', decision: 'PERMITTED', reason: 'tool permitted by allowlist', args: { query: 'aga' } },
  { tool: 'read_file', decision: 'PERMITTED', reason: 'tool permitted by allowlist', args: { path: '/data/a.md' } },
  { tool: 'execute_command', decision: 'DENIED', reason: 'tool explicitly disallowed by policy', args: { cmd: 'rm -rf /' } },
  { tool: 'read_file', decision: 'PERMITTED', reason: 'tool permitted by allowlist', args: { path: '/data/b.md' } },
  { tool: 'write_file', decision: 'DENIED', reason: 'path "/etc/x" is outside the allowed prefix "/data/"', args: { path: '/etc/x' } },
];

const vectors = {
  spec: 'AGA Evidence Bundle SEP profile, CANONICAL_CONSTRUCTION_v2.md',
  algorithm: ALGO, public_key: pubHex,
  note: 'Deterministic. Each merkle_root independently corroborated by a hand-coded per-arity formula. Negative mutations (tamper any field, drop a trailing receipt, re-point a proof, wrong pinned key) MUST flip a conformant verifier to FAIL.',
  bundles: {
    'len-1': makeBundle(SESS.slice(0, 1)),
    'len-3-odd-with-deny': makeBundle(SESS.slice(0, 3)),
    'len-5-odd-multilevel-with-deny': makeBundle(SESS.slice(0, 5)),
  },
};
writeFileSync(join(HERE, 'aga_evidence_bundle_vectors.json'), JSON.stringify(vectors, null, 2));
console.log('OK wrote aga_evidence_bundle_vectors.json (public_key', pubHex.slice(0, 16) + '...)');
for (const [k, v] of Object.entries(vectors.bundles)) console.log(`  ${k}: root ${v.expected_merkle_root.slice(0, 16)}... (independently corroborated)`);
