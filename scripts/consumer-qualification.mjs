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
await import(pathToFileURL(require.resolve('@attested-intelligence/aga-mcp-server/sep')));
for (const [file, verdict] of [['valid_minimal','VERIFIED'],['valid_denied','VERIFIED'],['tampered','FAILED'],['truncated','FAILED'],['wrong_key','FAILED'],['small_order_key','FAILED']]) {
  const bundle = JSON.parse(fs.readFileSync(`/subject/fixtures/${file}.json`, 'utf8'));
  const result = verifySepBundle(bundle, verdict === 'VERIFIED' ? bundle.public_key : undefined);
  assert.equal(result.verdict, verdict, file);
  if (verdict === 'VERIFIED') assert.equal(result.issuerVerified, true);
}
const root = require.resolve('@attested-intelligence/aga-mcp-server/package.json').replace(/package\.json$/, '');
const help = execFileSync(process.execPath, [root + pkg.bin['aga-proxy'], '--help'], { encoding: 'utf8', timeout: 10000 });
assert.match(help, /Usage:/);
const archive = `/evidence/attested-intelligence-aga-mcp-server-${pkg.version}.tgz`;
fs.writeFileSync('/evidence/consumer-result.json', JSON.stringify({ passed: true, version: pkg.version, packageSHA256: crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex'), scope: 'fresh consumer install, verify and sep exports, six fixtures, proxy help; optional native dependencies omitted; runtime deployment not qualified' }, null, 2));
