/**
 * B4 (integration): the key contract as an OPERATOR experiences it, driven through the BUILT
 * artifact — `dist/proxy/index.js`, the exact file the `aga-proxy` bin points at — not through the
 * TypeScript source.
 *
 * Why the built artifact: a control is not shipped until the entry point calls it. `describeKey()`
 * and `--ephemeral` both existed in the 3.5.0 tree and neither was reachable from
 * `dist/proxy/index.js`, so the shipped binary was silent about its own signing key and the flag
 * did nothing. A test against `src/` would have passed against that binary. These tests spawn the
 * real process and read its real stdout/stderr.
 *
 * The central claim: one key file, two separate processes, IDENTICAL public key on the banner and
 * ZERO warnings. That is what "provenance is pinnable across restarts" means operationally, and it
 * is the difference between a key an operator can pin out of band and one they cannot.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signerFromSeed, seedFromHex } from '../../src/sep/index.js';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const BUILT_PROXY = join(REPO_ROOT, 'dist', 'proxy', 'index.js');

const SEED_HEX = '5e'.repeat(32);
const SEED_PUB = signerFromSeed(seedFromHex(SEED_HEX)).publicKeyHex;

let workDir: string;
let keyPath: string;

/**
 * Ports are per-run so a stray proxy from another suite cannot make this one flaky, and the control
 * channel is NON-FATAL on bind failure, so a collision degrades to a missing line rather than a hang.
 */
let nextPort = 19810;

interface Run { stdout: string; stderr: string; }

/** Start the BUILT proxy, let it announce itself, stop it, and return what it printed. */
async function runProxy(env: Record<string, string | undefined>, args: string[] = []): Promise<Run> {
  const port = nextPort++;
  const controlPort = nextPort++;
  const childEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined) childEnv[k] = v;
  // Start from a clean slate every time: a leaked variable from another test would silently turn
  // an "unconfigured" case into a configured one and the assertion would still pass.
  delete childEnv.AGA_GATEWAY_KEY;
  delete childEnv.AGA_GATEWAY_KEY_FILE;
  for (const [k, v] of Object.entries(env)) { if (v === undefined) delete childEnv[k]; else childEnv[k] = v; }
  childEnv.AGA_DATA_DIR = join(workDir, `data-${port}`);

  return await new Promise<Run>((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [BUILT_PROXY, 'start', '--port', String(port), '--control-port', String(controlPort), ...args],
      { env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    let stdout = '';
    let stderr = '';
    let settled = false;
    child.stdout.on('data', (d) => { stdout += String(d); });
    child.stderr.on('data', (d) => { stderr += String(d); });
    child.on('error', (e) => { if (!settled) { settled = true; reject(e); } });

    const finish = () => {
      if (settled) return;
      settled = true;
      child.kill('SIGTERM');
      setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* already gone */ } resolve({ stdout, stderr }); }, 400);
    };
    // The banner is complete once the proxy has announced its port; give the remaining synchronous
    // lines a moment, then shut down.
    const poll = setInterval(() => {
      if (/AGA Governance Proxy started on port/.test(stdout)) { clearInterval(poll); setTimeout(finish, 250); }
    }, 50);
    setTimeout(() => { clearInterval(poll); finish(); }, 8000);
  });
}

/** The banner's signing line, or null when the binary printed none. */
function bannerKeyLine(stdout: string): string | null {
  const m = stdout.split(/\r?\n/).find((l) => /gateway key/i.test(l));
  return m ?? null;
}

/** The 64-hex public key on the banner's signing line, or null. */
function bannerPublicKey(stdout: string): string | null {
  const line = bannerKeyLine(stdout);
  const m = line?.match(/\b([0-9a-f]{64})\b/);
  return m ? m[1] : null;
}

/** Key-contract warnings only — the audit-only policy banner is a different, expected warning. */
function keyWarnings(stderr: string): string[] {
  return stderr.split(/\r?\n/).filter((l) => /EPHEMERAL|gateway key .* is invalid/i.test(l));
}

beforeAll(() => {
  // Fail loudly rather than silently testing nothing: `npm run check` builds before it tests, and a
  // stale or missing dist/ would make every assertion below meaningless.
  if (!existsSync(BUILT_PROXY)) {
    throw new Error(`BUILT artifact missing: ${BUILT_PROXY}. Run \`npm run build\` first — these tests drive dist/, not src/.`);
  }
  workDir = mkdtempSync(join(tmpdir(), 'aga-proxy-key-'));
  keyPath = join(workDir, 'gateway.key');
  writeFileSync(keyPath, `${SEED_HEX}\n`, 'utf8');
});

afterAll(() => {
  if (workDir) rmSync(workDir, { recursive: true, force: true });
});

describe('B4 (built artifact): aga-proxy honours the gateway key contract', () => {
  it('ONE key file, TWO processes: identical public key on the banner, zero warnings', async () => {
    const first = await runProxy({ AGA_GATEWAY_KEY_FILE: keyPath });
    const second = await runProxy({ AGA_GATEWAY_KEY_FILE: keyPath });

    const a = bannerPublicKey(first.stdout);
    const b = bannerPublicKey(second.stdout);

    // The banner must actually name a key. Before this was wired, both of these were null and the
    // operator had nothing to pin.
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();

    // Stable across restarts...
    expect(a).toBe(b);
    // ...and it is the key file's identity, not some other stable-looking value.
    expect(a).toBe(SEED_PUB);

    // A correctly-configured operator is not warned. Zero, on both runs.
    expect(keyWarnings(first.stderr)).toEqual([]);
    expect(keyWarnings(second.stderr)).toEqual([]);

    // The banner names the source so the operator knows WHICH variable took effect.
    expect(bannerKeyLine(first.stdout)).toContain('AGA_GATEWAY_KEY_FILE');
    expect(bannerKeyLine(first.stdout)).toContain('persisted');
  }, 40000);

  it('AGA_GATEWAY_KEY (env) gives the SAME identity as the key file holding that seed', async () => {
    const viaEnv = await runProxy({ AGA_GATEWAY_KEY: SEED_HEX });
    expect(bannerPublicKey(viaEnv.stdout)).toBe(SEED_PUB);
    expect(bannerKeyLine(viaEnv.stdout)).toContain('AGA_GATEWAY_KEY');
    expect(keyWarnings(viaEnv.stderr)).toEqual([]);
  }, 30000);

  it('unconfigured: the banner says the key is ephemeral, warns, and the key CHANGES between runs', async () => {
    const first = await runProxy({});
    const second = await runProxy({});
    const a = bannerPublicKey(first.stdout);
    const b = bannerPublicKey(second.stdout);
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    // The honest claim is "rotates on restart" — proven, not quoted.
    expect(a).not.toBe(b);
    expect(bannerKeyLine(first.stdout)).toMatch(/ephemeral/i);
    expect(keyWarnings(first.stderr).join('\n')).toMatch(/EPHEMERAL/);
    // And the operator is told not to pin it.
    expect(first.stdout).toMatch(/do not pin it/i);
  }, 40000);

  it('--ephemeral overrides a perfectly good configured key (the flag reaches the proxy)', async () => {
    const run = await runProxy({ AGA_GATEWAY_KEY_FILE: keyPath }, ['--ephemeral']);
    const pub = bannerPublicKey(run.stdout);
    expect(pub).not.toBeNull();
    // The whole point: the configured key is NOT used.
    expect(pub).not.toBe(SEED_PUB);
    expect(bannerKeyLine(run.stdout)).toMatch(/ephemeral/i);
    expect(keyWarnings(run.stderr).join('\n')).toContain('--ephemeral');
  }, 30000);

  it('an invalid key warns, falls back, and still announces the key it ended up with', async () => {
    const run = await runProxy({ AGA_GATEWAY_KEY: 'obviously-not-a-seed' });
    const warns = keyWarnings(run.stderr);
    expect(warns.join('\n')).toMatch(/invalid/i);
    expect(warns.join('\n')).toContain('AGA_GATEWAY_KEY');
    expect(warns.join('\n')).toMatch(/EPHEMERAL/);
    // Fell back rather than exiting: the proxy is up and told the operator what it is signing with.
    expect(run.stdout).toMatch(/AGA Governance Proxy started on port/);
    expect(bannerPublicKey(run.stdout)).not.toBeNull();
    expect(bannerKeyLine(run.stdout)).toMatch(/ephemeral/i);
  }, 30000);

  it('never prints key material: the seed appears in NO stream, on any path', async () => {
    const configured = await runProxy({ AGA_GATEWAY_KEY: SEED_HEX });
    const fromFile = await runProxy({ AGA_GATEWAY_KEY_FILE: keyPath });
    for (const run of [configured, fromFile]) {
      const all = `${run.stdout}\n${run.stderr}`;
      expect(all).not.toContain(SEED_HEX);
      expect(all).not.toContain(SEED_HEX.slice(0, 16));
      // The PUBLIC key is present and is a different value from the seed — that is the point.
      expect(all).toContain(SEED_PUB);
      expect(SEED_PUB).not.toBe(SEED_HEX);
    }
  }, 40000);

  it('the key line goes to STDOUT, and the ephemeral warning to STDERR (streams stay separated)', async () => {
    const run = await runProxy({});
    expect(bannerKeyLine(run.stdout)).not.toBeNull();
    // The warning must not be duplicated onto stdout...
    expect(run.stdout).not.toMatch(/it rotates on restart, so evidence-bundle provenance/);
    // ...and it must be on stderr.
    expect(run.stderr).toMatch(/it rotates on restart, so evidence-bundle provenance/);
  }, 30000);
});
