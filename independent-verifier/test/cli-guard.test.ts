// REL-03 regression: the CLI must fire ONLY when verify.ts itself is the executed
// entry script. The old guard (argv[1].includes('verify')) ran the CLI whenever the
// ENTRY SCRIPT'S PATH merely contained the substring 'verify' — so a consumer app at
// e.g. C:\projects\verify-app\main.js that imported this library got the CLI's
// stdout output and a process.exit() on import.
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VERIFY_TS = join(ROOT, 'verify.ts');

function runNode(args: string[]): { status: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync(process.execPath, args, {
      cwd: ROOT, // 'tsx' resolves from independent-verifier/node_modules
      encoding: 'utf8',
      timeout: 25_000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { status: 0, stdout, stderr: '' };
  } catch (e) {
    const err = e as { status?: number; stdout?: unknown; stderr?: unknown };
    return { status: err.status ?? -1, stdout: String(err.stdout ?? ''), stderr: String(err.stderr ?? '') };
  }
}

describe('CLI entry guard (REL-03)', () => {
  it("importing the module from an entry script whose path contains 'verify' triggers ZERO CLI side effects", () => {
    // Both the directory and the file name contain 'verify' — the exact shape the
    // old substring guard misfired on.
    const dir = mkdtempSync(join(tmpdir(), 'aga-verify-guard-'));
    try {
      const probe = join(dir, 'verify-import-probe.mjs');
      writeFileSync(probe, [
        `await import(${JSON.stringify(pathToFileURL(VERIFY_TS).href)});`,
        `console.log('IMPORT_CLEAN');`,
        '',
      ].join('\n'));
      const r = runNode(['--import', 'tsx', probe]);
      expect(r.status).toBe(0);                            // old guard: process.exit(2)
      expect(r.stdout).toContain('IMPORT_CLEAN');          // probe reached its own code
      expect(r.stdout).not.toContain('AGA Offline Verifier'); // no CLI banner
      expect(r.stderr).not.toContain('Usage:');            // no CLI usage dump
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('direct execution of verify.ts still runs the CLI (--version exits 0 with a semver)', () => {
    const r = runNode(['--import', 'tsx', VERIFY_TS, '--version']);
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('direct execution with no arguments still prints usage and exits 2', () => {
    const r = runNode(['--import', 'tsx', VERIFY_TS]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Usage:');
  });
});
