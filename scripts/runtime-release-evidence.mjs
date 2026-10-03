import assert from 'node:assert/strict';

export const NODE_MATRIX = [22, 24];
export const PACKAGE_NAME = '@attested-intelligence/aga-mcp-server';
export function validateEvidence({ commit, pkg, run, jobs, rows }) {
  assert.match(commit, /^[a-f0-9]{40}$/);
  assert.equal(pkg.name, PACKAGE_NAME);
  assert.match(pkg.version, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
  assert.equal(run.head_sha, commit, 'Wrong source commit');
  assert.equal(run.head_repository?.full_name, 'attestedintelligence/aga-mcp-server', 'Foreign source repository');
  assert.equal(run.path, '.github/workflows/runtime-qualification.yml', 'Wrong workflow');
  assert(['push', 'workflow_dispatch'].includes(run.event), 'Unapproved qualification event');
  assert.equal(run.status, 'completed');
  assert.equal(run.conclusion, 'success');
  assert(NODE_MATRIX.every(n => jobs.some(j => j.name === `qualification (${n})` && j.conclusion === 'success')), 'Incomplete Node matrix');
  assert.equal(rows.length, NODE_MATRIX.length);
  for (const n of NODE_MATRIX) {
    const row = rows.find(r => r.node === n);
    assert(row, `Missing Node ${n} evidence`);
    assert.equal(row.commit, commit);
    assert.equal(row.packageName, pkg.name);
    assert.equal(row.packageVersion, pkg.version);
    assert.match(row.sha256, /^[a-f0-9]{64}$/);
    assert.equal(row.sha256, row.declaredSHA256, 'Archive digest mismatch');
    assert.equal(row.consumer?.passed, true, 'Extracted package consumer check missing');
    assert.equal(row.consumer.version, pkg.version);
    assert.equal(row.consumer.packageSHA256, row.sha256, 'Consumer tested another archive');
    const tests = row.tests;
    assert.equal(tests.success, true);
    assert(tests.numTotalTests >= 461 && tests.numPassedTests === tests.numTotalTests, 'Test set incomplete');
    assert.equal(tests.numFailedTests, 0);
    assert.equal(tests.numPendingTests, 0);
    assert.equal(tests.numTodoTests ?? 0, 0);
    const assertions = tests.testResults.flatMap(s => s.assertionResults);
    assert.equal(assertions.length, tests.numTotalTests);
    assert(assertions.every(t => t.status === 'passed' && typeof t.fullName === 'string' && t.fullName.length), 'Missing test identities');
    assert.equal(new Set(assertions.map(t => t.fullName)).size, assertions.length, 'Duplicate test identities');
    const c = row.container, h = c.HostConfig;
    assert.equal(c.State.ExitCode, 0); assert.equal(c.State.OOMKilled, false);
    assert.equal(h.NetworkMode, 'none'); assert.equal(h.ReadonlyRootfs, true);
    assert.equal(c.Config.User, 'node'); assert(h.CapDrop.includes('ALL'));
    assert(h.SecurityOpt.includes('no-new-privileges'));
    assert(h.PidsLimit > 0 && h.PidsLimit <= 128 && h.Memory > 0 && h.Memory <= 1536 * 1024 * 1024);
    for (const file of ['valid_minimal','valid_denied','tampered','truncated','wrong_key','small_order_key']) {
      assert(row.log.includes(`OK  ${file}.json:`), `Missing conformance control ${file}`);
    }
  }
  assert.equal(rows[0].sha256, rows[1].sha256, 'Independent package bytes differ');
  return true;
}
