/**
 * B4: the gateway signing-key contract (src/sep/gateway-key.ts).
 *
 * This module is the ONE place both shipped binaries read AGA_GATEWAY_KEY / AGA_GATEWAY_KEY_FILE.
 * Before it existed, `aga-proxy` called generateSigner() unconditionally and silently ignored a
 * correctly-set variable. These tests hold the contract that removed that divergence:
 *
 *   1. AGA_GATEWAY_KEY is honoured and yields the seed's identity, not a fresh one.
 *   2. AGA_GATEWAY_KEY_FILE yields the SAME identity as the env var for the same seed.
 *   3. AGA_GATEWAY_KEY wins when both are set (documented precedence, not incidental).
 *   4. An invalid or unreadable key WARNS AND FALLS BACK — it does not throw and does not exit.
 *      That trade is deliberate (a governed boundary must not go offline over a pinning key) and
 *      is load-bearing for both bins, so it is pinned by a test rather than left to comments.
 *   5. forceEphemeral ignores a perfectly good configured key and says so.
 *   6. fallbackSeed makes the unconfigured case byte-identical to the caller's existing identity —
 *      the MCP server passes its portal keypair secret, and extracting the resolver must not have
 *      silently rotated that binary's key.
 *   7. No warning, at any path, ever contains key material.
 *
 * Every assertion below is on OBSERVABLE output (the returned publicKeyHex, `source`, `ephemeral`,
 * and the captured warn lines), never on internals.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveGatewaySigner, describeGatewayKey, signerFromSeed, seedFromHex } from '../../src/sep/index.js';

const SEED_HEX = 'ab'.repeat(32);
const SEED_PUB = signerFromSeed(seedFromHex(SEED_HEX)).publicKeyHex;

const OTHER_HEX = '3c'.repeat(32);
const OTHER_PUB = signerFromSeed(seedFromHex(OTHER_HEX)).publicKeyHex;

/** Run the resolver with an exactly-specified environment, capturing warnings. Always restores. */
function resolveWith(
  env: Record<string, string | undefined>,
  opts: Parameters<typeof resolveGatewaySigner>[0] = {},
) {
  const keys = ['AGA_GATEWAY_KEY', 'AGA_GATEWAY_KEY_FILE'];
  const saved: Record<string, string | undefined> = {};
  for (const k of keys) {
    saved[k] = process.env[k];
    const v = env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  const warnings: string[] = [];
  try {
    const resolved = resolveGatewaySigner({ ...opts, warn: (m) => warnings.push(m) });
    return { resolved, warnings };
  } finally {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

const tmpDirs: string[] = [];
function keyFile(contents: string, name = 'gateway.key'): string {
  const dir = mkdtempSync(join(tmpdir(), 'aga-gwkey-'));
  tmpDirs.push(dir);
  const p = join(dir, name);
  writeFileSync(p, contents, 'utf8');
  return p;
}

afterEach(() => {
  while (tmpDirs.length) rmSync(tmpDirs.pop() as string, { recursive: true, force: true });
});

describe('B4: resolveGatewaySigner — one key contract for both bins', () => {
  it('AGA_GATEWAY_KEY is honoured: the identity is the seed’s, the source is named, and it is NOT ephemeral', () => {
    const { resolved, warnings } = resolveWith({ AGA_GATEWAY_KEY: SEED_HEX });
    expect(resolved.signer.publicKeyHex).toBe(SEED_PUB);
    expect(resolved.source).toBe('AGA_GATEWAY_KEY');
    expect(resolved.ephemeral).toBe(false);
    // A correctly-configured operator gets NO warning. The defect this module fixed was silence on
    // the wrong side: noise here would train operators to ignore the ephemeral warning that matters.
    expect(warnings).toEqual([]);
    // The seed is never handed back for a configured key (nothing to persist, nothing to leak).
    expect(resolved.seed).toBeUndefined();
  });

  it('AGA_GATEWAY_KEY_FILE yields the SAME identity as the env var for the same seed', () => {
    const p = keyFile(SEED_HEX);
    const { resolved, warnings } = resolveWith({ AGA_GATEWAY_KEY_FILE: p });
    expect(resolved.signer.publicKeyHex).toBe(SEED_PUB);
    expect(resolved.source).toBe('AGA_GATEWAY_KEY_FILE');
    expect(resolved.ephemeral).toBe(false);
    expect(warnings).toEqual([]);
  });

  it('a key file with trailing whitespace/newline resolves to the same identity', () => {
    const p = keyFile(`${SEED_HEX}\n`);
    const { resolved } = resolveWith({ AGA_GATEWAY_KEY_FILE: p });
    expect(resolved.signer.publicKeyHex).toBe(SEED_PUB);
    expect(resolved.ephemeral).toBe(false);
  });

  it('AGA_GATEWAY_KEY takes precedence when BOTH variables are set', () => {
    const p = keyFile(OTHER_HEX);
    const { resolved } = resolveWith({ AGA_GATEWAY_KEY: SEED_HEX, AGA_GATEWAY_KEY_FILE: p });
    expect(resolved.signer.publicKeyHex).toBe(SEED_PUB);
    expect(resolved.signer.publicKeyHex).not.toBe(OTHER_PUB);
    expect(resolved.source).toBe('AGA_GATEWAY_KEY');
  });

  it('an INVALID AGA_GATEWAY_KEY warns and falls back — it does not throw and does not exit', () => {
    const { resolved, warnings } = resolveWith({ AGA_GATEWAY_KEY: 'not-a-64-hex-seed' });
    expect(resolved.ephemeral).toBe(true);
    expect(resolved.source).toBe('ephemeral-after-error');
    // Two lines: what was wrong, and what the operator now has. Both name AGA_GATEWAY_KEY.
    expect(warnings).toHaveLength(2);
    expect(warnings[0]).toContain('AGA_GATEWAY_KEY');
    expect(warnings[0]).toMatch(/invalid/i);
    expect(warnings[1]).toMatch(/EPHEMERAL/);
    // A fresh key, not the invalid value coerced into one.
    expect(resolved.signer.publicKeyHex).not.toBe(SEED_PUB);
  });

  it('an UNREADABLE AGA_GATEWAY_KEY_FILE warns and falls back, naming the file variable', () => {
    const dir = mkdtempSync(join(tmpdir(), 'aga-gwkey-'));
    tmpDirs.push(dir);
    const missing = join(dir, 'does-not-exist.key');
    const { resolved, warnings } = resolveWith({ AGA_GATEWAY_KEY_FILE: missing });
    expect(resolved.ephemeral).toBe(true);
    expect(resolved.source).toBe('ephemeral-after-error');
    expect(warnings[0]).toContain('AGA_GATEWAY_KEY_FILE');
    expect(warnings[0]).not.toContain('AGA_GATEWAY_KEY is');
  });

  it('a key file whose CONTENTS are malformed warns and falls back (not just a missing file)', () => {
    const p = keyFile('zz'.repeat(32));
    const { resolved, warnings } = resolveWith({ AGA_GATEWAY_KEY_FILE: p });
    expect(resolved.ephemeral).toBe(true);
    expect(resolved.source).toBe('ephemeral-after-error');
    expect(warnings[0]).toContain('AGA_GATEWAY_KEY_FILE');
  });

  it('unconfigured: an ephemeral key, warned once, and two calls give DIFFERENT identities', () => {
    const a = resolveWith({ AGA_GATEWAY_KEY: undefined, AGA_GATEWAY_KEY_FILE: undefined });
    const b = resolveWith({ AGA_GATEWAY_KEY: undefined, AGA_GATEWAY_KEY_FILE: undefined });
    expect(a.resolved.ephemeral).toBe(true);
    expect(a.resolved.source).toBe('ephemeral');
    expect(a.warnings).toHaveLength(1);
    expect(a.warnings[0]).toMatch(/EPHEMERAL/);
    expect(a.warnings[0]).toContain('AGA_GATEWAY_KEY');
    // "rotates on restart" is the operative claim; prove it rather than asserting the sentence.
    expect(b.resolved.signer.publicKeyHex).not.toBe(a.resolved.signer.publicKeyHex);
    // The generated seed IS returned so a caller can persist it.
    expect(a.resolved.seed).toBeInstanceOf(Uint8Array);
    expect(a.resolved.seed).toHaveLength(32);
  });

  it('forceEphemeral ignores a perfectly good configured key and says so', () => {
    const { resolved, warnings } = resolveWith({ AGA_GATEWAY_KEY: SEED_HEX }, { forceEphemeral: true });
    expect(resolved.ephemeral).toBe(true);
    expect(resolved.source).toBe('ephemeral-requested');
    expect(resolved.signer.publicKeyHex).not.toBe(SEED_PUB);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('--ephemeral');
    expect(warnings[0]).toMatch(/by request/i);
  });

  it('fallbackSeed IDENTITY: the unconfigured case uses the caller’s seed, not a fresh key', () => {
    const fallback = seedFromHex(OTHER_HEX);
    const { resolved } = resolveWith(
      { AGA_GATEWAY_KEY: undefined, AGA_GATEWAY_KEY_FILE: undefined },
      { fallbackSeed: fallback },
    );
    // This is the assertion that stops the resolver extraction from silently rotating the MCP
    // server's key: same seed in, same public key out, across two separate resolutions.
    expect(resolved.signer.publicKeyHex).toBe(OTHER_PUB);
    const again = resolveWith(
      { AGA_GATEWAY_KEY: undefined, AGA_GATEWAY_KEY_FILE: undefined },
      { fallbackSeed: fallback },
    );
    expect(again.resolved.signer.publicKeyHex).toBe(OTHER_PUB);
    // Still flagged ephemeral: the identity is stable only for as long as the caller's own
    // fallback is, so provenance must not be advertised as pinnable.
    expect(resolved.ephemeral).toBe(true);
    // Nothing to persist: the seed came from the caller.
    expect(resolved.seed).toBeUndefined();
  });

  it('fallbackSeed is honoured on the ERROR path too, not just the unconfigured one', () => {
    const { resolved } = resolveWith(
      { AGA_GATEWAY_KEY: 'garbage' },
      { fallbackSeed: seedFromHex(OTHER_HEX) },
    );
    expect(resolved.signer.publicKeyHex).toBe(OTHER_PUB);
    expect(resolved.source).toBe('ephemeral-after-error');
  });

  it('fallbackSeed is honoured on the forceEphemeral path too', () => {
    const { resolved } = resolveWith(
      { AGA_GATEWAY_KEY: SEED_HEX },
      { forceEphemeral: true, fallbackSeed: seedFromHex(OTHER_HEX) },
    );
    expect(resolved.signer.publicKeyHex).toBe(OTHER_PUB);
    expect(resolved.source).toBe('ephemeral-requested');
  });

  it('NEVER logs key material, on any path, for the env var or the file contents', () => {
    const p = keyFile(SEED_HEX);
    const all: string[] = [];
    all.push(...resolveWith({ AGA_GATEWAY_KEY: SEED_HEX }).warnings);
    all.push(...resolveWith({ AGA_GATEWAY_KEY_FILE: p }).warnings);
    all.push(...resolveWith({ AGA_GATEWAY_KEY: SEED_HEX }, { forceEphemeral: true }).warnings);
    all.push(...resolveWith({ AGA_GATEWAY_KEY: undefined, AGA_GATEWAY_KEY_FILE: undefined }).warnings);
    // An invalid value is the one case where the raw input reaches an error string, so it gets a
    // value that is recognisable if it ever leaks.
    all.push(...resolveWith({ AGA_GATEWAY_KEY: `${SEED_HEX}deadbeef` }).warnings);

    const joined = all.join('\n');
    expect(joined).not.toContain(SEED_HEX);
    // Not even a prefix of the seed: 16 hex chars is already too much to print.
    expect(joined).not.toContain(SEED_HEX.slice(0, 16));
    // And the secret half of a generated key is never printed either.
    const gen = resolveWith({ AGA_GATEWAY_KEY: undefined, AGA_GATEWAY_KEY_FILE: undefined });
    const seedHex = Buffer.from(gen.resolved.seed as Uint8Array).toString('hex');
    expect(gen.warnings.join('\n')).not.toContain(seedHex);
  });

  it('the DEFAULT warning sink is console.error, never console.log', () => {
    // The MCP server speaks JSON-RPC on stdout; a stray byte there corrupts the stream, so the
    // default sink must be console.error. (The real two-stream separation of the shipped binary is
    // proven end-to-end in tests/integration/proxy-gateway-key.test.ts, which reads a child
    // process's actual stdout and stderr; this asserts the module-level contract.)
    const errLines: string[] = [];
    const outLines: string[] = [];
    const realErr = console.error;
    const realLog = console.log;
    const savedKey = process.env.AGA_GATEWAY_KEY;
    const savedFile = process.env.AGA_GATEWAY_KEY_FILE;
    delete process.env.AGA_GATEWAY_KEY;
    delete process.env.AGA_GATEWAY_KEY_FILE;
    console.error = (...a: unknown[]) => { errLines.push(a.map(String).join(' ')); };
    console.log = (...a: unknown[]) => { outLines.push(a.map(String).join(' ')); };
    try {
      resolveGatewaySigner();   // no `warn` override: exercise the DEFAULT sink
    } finally {
      console.error = realErr;
      console.log = realLog;
      if (savedKey === undefined) delete process.env.AGA_GATEWAY_KEY; else process.env.AGA_GATEWAY_KEY = savedKey;
      if (savedFile === undefined) delete process.env.AGA_GATEWAY_KEY_FILE; else process.env.AGA_GATEWAY_KEY_FILE = savedFile;
    }
    expect(errLines.join('\n')).toMatch(/EPHEMERAL/);
    expect(outLines).toEqual([]);
  });

  it('the logPrefix names the binary, so an operator can tell which bin warned', () => {
    const { warnings } = resolveWith(
      { AGA_GATEWAY_KEY: undefined, AGA_GATEWAY_KEY_FILE: undefined },
      { logPrefix: 'aga-proxy' },
    );
    expect(warnings[0]).toContain('[aga-proxy]');
  });
});

describe('B4: describeGatewayKey — the one line an operator pins against', () => {
  it('names the PUBLIC key and the variable it came from for a persisted key', () => {
    const { resolved } = resolveWith({ AGA_GATEWAY_KEY: SEED_HEX });
    const line = describeGatewayKey(resolved);
    expect(line).toContain(SEED_PUB);
    expect(line).toContain('AGA_GATEWAY_KEY');
    expect(line).toContain('persisted');
    expect(line).not.toContain(SEED_HEX);   // public key only, never the seed
  });

  it('says a throwaway key rotates on restart, so nobody pins it by mistake', () => {
    const { resolved } = resolveWith({ AGA_GATEWAY_KEY: undefined, AGA_GATEWAY_KEY_FILE: undefined });
    const line = describeGatewayKey(resolved);
    expect(line).toContain(resolved.signer.publicKeyHex);
    expect(line).toMatch(/ephemeral/i);
    expect(line).toMatch(/rotates on restart/i);
    expect(line).not.toMatch(/persisted/);
  });
});
