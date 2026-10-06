import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
assert.equal(process.platform, 'win32');
assert.equal(process.env.GITHUB_ACTIONS, 'true', 'Run only on the disposable hosted runner');
assert.match(process.env.QUALIFIED_COMMIT ?? '', /^[0-9a-f]{40}$/);
const output = path.resolve(process.argv[2]);
const env = {};
for (const [key, value] of Object.entries(process.env)) {
  if (['path', 'systemroot', 'windir', 'comspec', 'temp', 'tmp'].includes(key.toLowerCase())) env[key] = value;
}
env.CI = 'true'; env.NODE_OPTIONS = '--max-old-space-size=768';
const result = spawnSync(process.execPath, ['node_modules/vitest/vitest.mjs', 'run',
  'tests/proxy/export-no-clobber.test.ts', 'tests/proxy/export-write-integrity.test.ts',
  'tests/proxy/openclaw-adapter.test.ts',
  '--no-cache', '--maxWorkers=1', '--no-file-parallelism', '--reporter=default', '--reporter=json',
  '--outputFile.json=' + path.join(output, 'tests.json')], {
  env, encoding: 'utf8', timeout: 120000, maxBuffer: 4 * 1024 * 1024, windowsHide: true,
});
fs.writeFileSync(path.join(output, 'test.log'), (result.stdout ?? '') + (result.stderr ?? ''));
fs.writeFileSync(path.join(output, 'run.json'), JSON.stringify({ source: process.env.QUALIFIED_COMMIT,
  node: process.version, platform: process.platform, status: result.status, signal: result.signal,
  error: result.error?.message, childEnvironmentNames: Object.keys(env),
  scope: 'Filesystem-only synthetic fault and legacy-adapter refusal cases on a disposable Windows runner. Network is not disabled. POSIX permissions and symlink case explicitly skipped. No production files or keys supplied.',
}, null, 2));
process.stdout.write(result.stdout ?? ''); process.stderr.write(result.stderr ?? '');
if (result.error || result.status !== 0) process.exit(1);
