// Execute only in the bounded qualification container. /consumer is a fresh install of the archive.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
const require = createRequire('/consumer/package.json');
const pkg = require('@attested-intelligence/aga-mcp-server/package.json');
const { verifySepBundle } = await import(pathToFileURL(require.resolve('@attested-intelligence/aga-mcp-server/verify')));
const sep = await import(pathToFileURL(require.resolve('@attested-intelligence/aga-mcp-server/sep')));
for (const [file, verdict] of [['valid_minimal','VERIFIED'],['valid_denied','VERIFIED'],['tampered','FAILED'],['truncated','FAILED'],['wrong_key','FAILED'],['small_order_key','FAILED']]) {
  const bundle = JSON.parse(fs.readFileSync(`/subject/fixtures/${file}.json`, 'utf8'));
  const result = verifySepBundle(bundle, verdict === 'VERIFIED' ? bundle.public_key : undefined);
  assert.equal(result.verdict, verdict, file);
  if (verdict === 'VERIFIED') assert.equal(result.issuerVerified, true);
}
// Exercise the installed producer, including odd-leaf promotion, against the retained single-proof API.
let serial = 0;
const signer = sep.signerFromSeed(new Uint8Array(32).fill(53));
const gateway = new sep.SepGateway({ gatewayId: 'synthetic-consumer', signer,
  clock: () => '2026-10-03T00:00:00.000Z', idGen: () => `synthetic-consumer-${serial++}` });
for (let i = 0; i < 257; i++) gateway.record({ tool_name: 'read_document', decision: i % 2 ? 'DENIED' : 'PERMITTED', reason: 'synthetic installed-export control', request_id: i });
const exported = gateway.exportBundle();
const leaves = exported.receipts.map(sep.leafHash);
assert.deepEqual(exported.merkle_proofs, leaves.map((_, index) => sep.merkleProof(leaves, index)));
assert.equal(exported.merkle_root, sep.merkleRoot(leaves));
assert.deepEqual(exported.checkpoint, sep.buildCheckpoint(exported.receipts, exported.gateway_id, exported.generated_at, signer));
const exportedResult = verifySepBundle(exported, signer.publicKeyHex);
assert.equal(exportedResult.verdict, 'VERIFIED');assert.equal(exportedResult.issuerVerified, true);
const root = require.resolve('@attested-intelligence/aga-mcp-server/package.json').replace(/package\.json$/, '');
const help = execFileSync(process.execPath, [root + pkg.bin['aga-proxy'], '--help'], { encoding: 'utf8', timeout: 10000 });
assert.match(help, /Usage:/);
const archive = `/evidence/attested-intelligence-aga-mcp-server-${pkg.version}.tgz`;
fs.writeFileSync('/evidence/consumer-result.json', JSON.stringify({ passed: true, version: pkg.version, packageSHA256: crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex'), exportCompatibility: { receipts: 257, legacyProofsMatched: true, checkpointMatched: true, verifiedWithExpectedKey: true }, scope: 'fresh consumer install, verify and sep exports, six fixtures, 257-receipt producer comparison and proxy help; optional native dependencies omitted; runtime deployment not qualified' }, null, 2));
