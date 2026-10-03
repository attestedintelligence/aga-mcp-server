import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateEvidence } from './runtime-release-evidence.mjs';

function evidence(version = '3.6.6') {
  const commit = 'a'.repeat(40), digest = 'b'.repeat(64);
  return { commit, pkg: { name: '@attested-intelligence/aga-mcp-server', version },
    run: { head_sha: commit, head_repository: { full_name: 'attestedintelligence/aga-mcp-server' }, path: '.github/workflows/runtime-qualification.yml', event: 'push', status: 'completed', conclusion: 'success' },
    jobs: [22,24].map(n => ({ name: `qualification (${n})`, conclusion: 'success' })),
    rows: [22,24].map(node => ({ node, commit, packageName: '@attested-intelligence/aga-mcp-server', packageVersion: version, sha256: digest, declaredSHA256: digest,
      consumer: { passed: true, version, packageSHA256: digest },
      tests: { success: true, numTotalTests: 461, numPassedTests: 461, numFailedTests: 0, numPendingTests: 0, testResults: [{ assertionResults: Array.from({ length: 461 }, (_, n) => ({ fullName: `test ${n}`, status: 'passed' })) }] },
      container: { State: { ExitCode: 0, OOMKilled: false }, Config: { User: 'node' }, HostConfig: { NetworkMode: 'none', ReadonlyRootfs: true, CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges'], PidsLimit: 128, Memory: 1536*1024*1024 } },
      log: ['valid_minimal','valid_denied','tampered','truncated','wrong_key','small_order_key'].map(x => `OK  ${x}.json:`).join('\n') })) };
}
test('valid evidence is accepted for current and future versions', () => {
  for (const version of ['3.6.5','3.6.6','4.0.0-rc.1']) assert.equal(validateEvidence(evidence(version)), true);
});
for (const [name, mutate] of [
  ['wrong source', e => { e.run.head_sha = 'c'.repeat(40); }],
  ['foreign repository', e => { e.run.head_repository.full_name = 'other/repo'; }],
  ['wrong workflow', e => { e.run.path = '.github/workflows/ci.yml'; }],
  ['PR evidence', e => { e.run.event = 'pull_request'; }],
  ['missing matrix leg', e => { e.jobs.pop(); }],
  ['failed matrix leg', e => { e.jobs[0].conclusion = 'failure'; }],
  ['missing artifact', e => { e.rows.pop(); }],
  ['corrupt digest', e => { e.rows[0].declaredSHA256 = 'c'.repeat(64); }],
  ['different archive', e => { e.rows[1].sha256 = 'c'.repeat(64); }],
  ['wrong package', e => { e.rows[0].packageName = 'other'; }],
  ['wrong version', e => { e.rows[0].packageVersion = '3.6.4'; }],
  ['missing consumer evidence', e => { delete e.rows[0].consumer; }],
  ['skipped tests', e => { e.rows[0].tests.numPendingTests = 1; }],
  ['missing test identities', e => { e.rows[0].tests.testResults = []; }],
  ['missing control', e => { e.rows[0].log = ''; }],
  ['network access', e => { e.rows[0].container.HostConfig.NetworkMode = 'bridge'; }],
]) test(`rejects ${name}`, () => { const value = evidence(); mutate(value); assert.throws(() => validateEvidence(value)); });
