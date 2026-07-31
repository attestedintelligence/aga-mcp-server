// REL-04 (warning half): unknown --profile is a hard error (exit 2), and an
// audit_only start prints a loud multi-line stderr banner. The DEFAULT profile
// itself is unchanged ('permissive', audit_only) — founder decision.
import { describe, it, expect } from 'vitest';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { PROFILES, PERMISSIVE, STANDARD, RESTRICTIVE, resolveProfile, auditOnlyWarningBanner } from '../../src/proxy/profiles.js';

const CLI = fileURLToPath(new URL('../../src/proxy/index.ts', import.meta.url));

/** Spawn the CLI source via tsx; resolve on close OR once a stderr predicate matches (then kill). */
function runCli(args: string[], opts: { untilStderr?: RegExp; timeoutMs?: number } = {}) {
  return new Promise<{ code: number | null; stdout: string; stderr: string; matched: boolean }>((resolvePromise) => {
    const child = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    let matched = false;
    let done = false;
    const finish = (code: number | null) => {
      if (done) return;
      done = true;
      clearTimeout(killer);
      resolvePromise({ code, stdout: out, stderr: err, matched });
    };
    const killer = setTimeout(() => { child.kill(); finish(null); }, opts.timeoutMs ?? 20_000);
    child.stdout.on('data', (d) => { out += d.toString(); });
    child.stderr.on('data', (d) => {
      err += d.toString();
      if (opts.untilStderr && opts.untilStderr.test(err)) {
        matched = true;
        child.kill(); // banner seen — no need to let the proxy keep running
      }
    });
    child.on('close', (code) => finish(code));
  });
}

describe('resolveProfile (REL-04)', () => {
  it('resolves the three built-in profiles', () => {
    expect(resolveProfile('permissive')).toBe(PERMISSIVE);
    expect(resolveProfile('standard')).toBe(STANDARD);
    expect(resolveProfile('restrictive')).toBe(RESTRICTIVE);
  });

  it('returns undefined for unknown names', () => {
    expect(resolveProfile('bogus')).toBeUndefined();
    expect(resolveProfile('')).toBeUndefined();
    expect(resolveProfile('Permissive')).toBeUndefined(); // case-sensitive, no fuzzy match
  });

  it('never resolves prototype-chain names to garbage', () => {
    expect(resolveProfile('constructor')).toBeUndefined();
    expect(resolveProfile('toString')).toBeUndefined();
    expect(resolveProfile('__proto__')).toBeUndefined();
  });
});

describe('auditOnlyWarningBanner (REL-04)', () => {
  it('is loud, multi-line, names the source, and scopes denial to allowlist mode', () => {
    const banner = auditOnlyWarningBanner('--profile permissive');
    const lines = banner.split('\n');
    expect(lines.length).toBeGreaterThanOrEqual(8);
    expect(banner).toContain('AUDIT-ONLY MODE');
    expect(banner).toContain('--profile permissive'); // the source is named
    expect(banner).toMatch(/No call is denied/i);     // honest about what this mode does NOT do
    expect(banner).toMatch(/allowlist/);              // points at the enforcing alternative
  });
});

describe('aga-proxy start CLI (separate process)', () => {
  it("unknown --profile exits 2 with a clear message (no silent 'permissive' fallback)", async () => {
    const r = await runCli(['start', '--profile', 'bogus', '--port', '0', '--control-port', '0']);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("unknown --profile 'bogus'");
    expect(r.stderr).toContain('permissive, standard, restrictive'); // lists the valid names
    expect(r.stdout).not.toContain('AGA Governance Proxy started');  // it never started
  });

  it('starting with --profile permissive prints the audit_only banner on stderr', async () => {
    const r = await runCli(
      ['start', '--profile', 'permissive', '--port', '0', '--control-port', '0'],
      { untilStderr: /AUDIT-ONLY MODE/ },
    );
    expect(r.matched).toBe(true);
    expect(r.stderr).toContain('AUDIT-ONLY MODE');
    expect(r.stderr).toContain('--profile permissive');
  }, 30_000);
});
