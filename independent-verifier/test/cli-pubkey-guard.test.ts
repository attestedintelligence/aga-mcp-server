// Malformed --pubkey must be a hard usage error (exit 2), never a silent downgrade to an
// integrity-only check. Before this fix, verify.ts's CLI passed a malformed pin straight
// into verifyEvidenceBundle, where isHex(expectedPublicKey, 64) === false made `pinned`
// false and skipped the gateway_key_match step entirely — an operator who fat-fingered
// --pubkey got a green "VERIFIED (integrity only)" exit 0 instead of the error they'd get
// from aga-receipt-spec/verify/verify-sep.mjs, which has always guarded this correctly.
// REVIEWER_GUIDE.md's "a malformed --pubkey is a hard error, not a silent downgrade" claim
// was false for this file until this test locked the guard in.
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VERIFY_TS = join(ROOT, 'verify.ts');

function runNode(args: string[]): { status: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync(process.execPath, args, {
      cwd: ROOT,
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

describe('CLI --pubkey malformation guard', () => {
  it('a too-short/non-hex --pubkey is a hard error: exit 2, refuses to run the check at all', () => {
    const r = runNode(['--import', 'tsx', VERIFY_TS, '--sample', '--pubkey', 'deadbeef']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('refusing to silently downgrade');
    expect(r.stdout).not.toContain('VERIFIED');
  });

  it('a well-formed but wrong 64-hex --pubkey still runs the check and correctly FAILS provenance', () => {
    const r = runNode(['--import', 'tsx', VERIFY_TS, '--sample', '--pubkey', 'a'.repeat(64)]);
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('FAIL  gateway_key_match');
    expect(r.stdout).toContain('OVERALL: FAILED');
  });

  it('no --pubkey at all still verifies integrity-only and exits 0 (control, unchanged)', () => {
    const r = runNode(['--import', 'tsx', VERIFY_TS, '--sample']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('OVERALL: VERIFIED (integrity only — no --pubkey given)');
  });
});
