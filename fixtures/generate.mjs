/**
 * Conformance fixture generator — now produced BY the production engine (src/sep, compiled to dist/sep).
 * Deterministic (fixed Ed25519 seed + injected clock/idGen) so fixtures are byte-reproducible.
 *   npm run build && node fixtures/generate.mjs
 */
import { SepGateway, signerFromSeed } from '../dist/sep/index.js';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const sha = (s) => createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');
const canon = (o) => o === null || typeof o !== 'object' ? JSON.stringify(o)
  : Array.isArray(o) ? '[' + o.map(canon).join(',') + ']'
  : '{' + Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';

const signer = signerFromSeed(Buffer.from('01'.repeat(32), 'hex'));
const otherPub = signerFromSeed(Buffer.from('02'.repeat(32), 'hex')).publicKeyHex;
const GID = 'aga-fixtures';
const POL = sha(canon({ mode: 'standard' }));
const seq = (list) => { let i = 0; return () => list[i++]; };

function makeBundle(specs, clockList, idList) {
  const gw = new SepGateway({ gatewayId: GID, signer, policyReference: POL, clock: seq(clockList), idGen: seq(idList) });
  for (const s of specs) gw.record({ tool_name: s.tool, decision: s.decision, reason: s.reason, arguments: s.args, request_id: s.req });
  return gw.exportBundle();
}
const out = (name, obj) => writeFileSync(new URL(`./${name}`, import.meta.url), JSON.stringify(obj, null, 2) + '\n');

const minimal = makeBundle(
  [{ tool: 'read_file', decision: 'PERMITTED', reason: 'tool in allowlist', args: { path: '/p/x' }, req: 'req-1' }],
  ['2026-06-06T10:00:00.000Z', '2026-06-06T12:00:00.000Z'], ['r-1', 'fixture-min']);

const denied = makeBundle(
  [
    { tool: 'read_file', decision: 'PERMITTED', reason: 'tool in allowlist', args: { path: '/p/x' }, req: 'req-1' },
    { tool: 'delete_all', decision: 'DENIED', reason: 'destructive op blocked by policy', args: { target: '/' }, req: 'req-2' },
  ],
  ['2026-06-06T10:00:00.000Z', '2026-06-06T10:00:01.000Z', '2026-06-06T12:00:00.000Z'], ['r-1', 'r-2', 'fixture-den']);

out('valid_minimal.json', minimal);
out('valid_denied.json', denied);
const tampered = JSON.parse(JSON.stringify(denied)); tampered.receipts[1].reason = 'allowed'; out('tampered.json', tampered);
const truncated = JSON.parse(JSON.stringify(denied)); truncated.receipts.pop(); truncated.merkle_proofs.pop(); out('truncated.json', truncated);
const wrongKey = JSON.parse(JSON.stringify(denied)); wrongKey.public_key = otherPub; out('wrong_key.json', wrongKey);

console.log('fixtures regenerated from src/sep; gateway pubkey =', signer.publicKeyHex);
