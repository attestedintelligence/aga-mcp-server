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
// Exercise ownership through the installed public package, not only source imports.
const ownershipSurfaces = ['record', 'getReceipts', 'exportBundle'];
for (const surface of ownershipSurfaces) {
  const owned = new sep.SepGateway({ gatewayId: 'synthetic-consumer-ownership', signer });
  const recorded = owned.record({ tool_name: 'read', decision: 'PERMITTED', reason: 'retained original' });
  const detached = surface === 'record' ? recorded : surface === 'getReceipts' ? owned.getReceipts()[0] : owned.exportBundle().receipts[0];
  detached.reason = 'consumer attempted mutation';
  owned.record({ tool_name: 'read', decision: 'DENIED', reason: 'next decision' });
  const snapshot = owned.exportBundle();
  assert.equal(snapshot.receipts[0].reason, 'retained original');
  assert.equal(verifySepBundle(snapshot, signer.publicKeyHex).verdict, 'VERIFIED');
}
const root = require.resolve('@attested-intelligence/aga-mcp-server/package.json').replace(/package\.json$/, '');
// Exercise the shipped writer used by the CLI, including exclusive publication
// and preservation of other links during explicit replacement.
const { exportBundleToFile } = await import(pathToFileURL(root + 'dist/proxy/control.js'));
const outputDir = fs.mkdtempSync('/tmp/aga-consumer-export-');
const output = outputDir + '/record.json';
await exportBundleToFile({ proxy: gateway, dataDir: outputDir, output });
assert.equal(verifySepBundle(JSON.parse(fs.readFileSync(output, 'utf8')), signer.publicKeyHex).verdict, 'VERIFIED');
const firstBytes = fs.readFileSync(output);
await assert.rejects(exportBundleToFile({ proxy: gateway, dataDir: outputDir, output }), { name: 'ExportTargetExistsError' });
assert.deepEqual(fs.readFileSync(output), firstBytes);
fs.linkSync(output, outputDir + '/retained.json');
gateway.record({ tool_name: 'read_document', decision: 'DENIED', reason: 'later installed export' });
await exportBundleToFile({ proxy: gateway, dataDir: outputDir, output, force: true });
assert.deepEqual(fs.readFileSync(outputDir + '/retained.json'), firstBytes);
assert.equal(JSON.parse(fs.readFileSync(output, 'utf8')).receipts.length, 258);
assert.equal(verifySepBundle(JSON.parse(fs.readFileSync(output, 'utf8')), signer.publicKeyHex).verdict, 'VERIFIED');
assert.deepEqual(fs.readdirSync(outputDir).sort(), ['record.json', 'retained.json']);
fs.unlinkSync(output); fs.unlinkSync(outputDir + '/retained.json'); fs.rmdirSync(outputDir);
const help = execFileSync(process.execPath, [root + pkg.bin['aga-proxy'], '--help'], { encoding: 'utf8', timeout: 10000 });
assert.match(help, /Usage:/);
const archive = `/evidence/attested-intelligence-aga-mcp-server-${pkg.version}.tgz`;
fs.writeFileSync('/evidence/consumer-result.json', JSON.stringify({ passed: true, version: pkg.version, packageSHA256: crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex'), exportCompatibility: { receipts: 257, legacyProofsMatched: true, checkpointMatched: true, verifiedWithExpectedKey: true }, detachedReceiptSurfaces: ownershipSurfaces, installedWriter: { verifiedExport: true, existingTargetPreserved: true, forcedReplacementPreservesOtherLinks: true, stagingCleaned: true }, scope: 'fresh consumer install, verify and sep exports, six fixtures, 257-receipt producer comparison, three receipt ownership paths, installed export publication/replacement and proxy help; optional native dependencies omitted; runtime deployment not qualified' }, null, 2));
