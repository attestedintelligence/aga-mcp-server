/**
 * Loopback control channel + out-of-process export.
 *
 * Reproduces and closes the sprint50 gap: the GovernanceProxy keeps its SEP ledger in memory, and
 * exportBundle() works inside the running process, but a SEPARATE `aga-proxy export` invocation had
 * no handle to the live ledger. These tests assert:
 *   - the control listener binds 127.0.0.1 ONLY (never a routable interface),
 *   - export over the control channel returns the same signed bundle the verifier ACCEPTS (VERIFIED),
 *   - a tampered fetched bundle FAILS,
 *   - a separate invocation (proxy=null) resolves the live ledger via the published control port,
 *   - export with no running proxy fails loudly (never an empty bundle), exit nonzero at the CLI.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as net from 'node:net';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { GovernanceProxy } from '../../src/proxy/server.js';
import { verifySepBundle } from '../../src/sep/index.js';
import {
  ProxyControlServer, CONTROL_HOST, NO_PROXY_MESSAGE, ExportUnavailableError,
  exportBundleToFile, writeControlFile, readControlFile, isSepBundleShape,
} from '../../src/proxy/control.js';
import type { ToolPolicy } from '../../src/proxy/types.js';

const PROXY_PORT = 19960 + Math.floor(Math.random() * 30);

const policy: ToolPolicy = {
  mode: 'allowlist',
  constraints: {
    filesystem_read: { name: 'filesystem_read', allowed: true, max_calls_per_minute: 100 },
    web_search: { name: 'web_search', allowed: true, max_calls_per_minute: 100 },
  },
};

let proxy: GovernanceProxy;
let control: ProxyControlServer;
let controlPort: number;

function sendToolCall(port: number, id: number, name: string, args: Record<string, unknown>): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ port }, () => {
      socket.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } }) + '\n');
    });
    let buf = '';
    socket.on('data', (chunk) => { buf += chunk.toString(); if (buf.includes('\n')) { socket.destroy(); resolve(); } });
    socket.on('error', reject);
    setTimeout(() => { socket.destroy(); resolve(); }, 3000);
  });
}

beforeAll(async () => {
  proxy = new GovernanceProxy({ port: PROXY_PORT, policy });
  await proxy.start();
  await sendToolCall(PROXY_PORT, 1, 'filesystem_read', { path: '/tmp/a.txt' });
  await sendToolCall(PROXY_PORT, 2, 'web_search', { query: 'aga control channel' });
  control = new ProxyControlServer(proxy);
  const bound = await control.start(0); // ephemeral free port — avoids collision with a real proxy
  controlPort = bound.port;
});

afterAll(async () => {
  await control.stop();
  await proxy.stop();
});

describe('ProxyControlServer — loopback bind + read-only surface', () => {
  it('binds to 127.0.0.1 ONLY (never 0.0.0.0 or a routable interface)', () => {
    expect(control.address()).toBe(CONTROL_HOST);
    expect(control.address()).toBe('127.0.0.1');
    expect(controlPort).toBeGreaterThan(0);
    expect(controlPort).not.toBe(PROXY_PORT); // distinct from the agent-facing proxy port
  });

  it('GET /export returns a bundle the canonical verifier ACCEPTS (VERIFIED, provenance-pinned)', async () => {
    const res = await fetch(`http://127.0.0.1:${controlPort}/export`);
    expect(res.status).toBe(200);
    const bundle = await res.json();
    expect(bundle.algorithm).toBe('Ed25519-SHA256-JCS');
    expect(bundle.receipts.length).toBeGreaterThan(0);
    const result = verifySepBundle(bundle, proxy.getPublicKey());
    expect(result.verdict).toBe('VERIFIED');
    expect(result.issuerVerified).toBe(true);
  });

  it('a TAMPERED fetched bundle FAILS verification', async () => {
    const res = await fetch(`http://127.0.0.1:${controlPort}/export`);
    const bundle = await res.json();
    bundle.merkle_root = bundle.merkle_root.replace(/./, (c: string) => (c === 'a' ? 'b' : 'a'));
    const result = verifySepBundle(bundle, proxy.getPublicKey());
    expect(result.verdict).toBe('FAILED');
  });

  it('GET /status and GET /receipts expose read-only state', async () => {
    const status = await (await fetch(`http://127.0.0.1:${controlPort}/status`)).json();
    expect(status.running).toBe(true);
    expect(status.public_key).toBe(proxy.getPublicKey());
    const receipts = await (await fetch(`http://127.0.0.1:${controlPort}/receipts`)).json();
    expect(Array.isArray(receipts)).toBe(true);
    expect(receipts.length).toBeGreaterThan(0);
  });

  it('is READ-ONLY: rejects non-GET and unknown routes (no mutation surface)', async () => {
    const post = await fetch(`http://127.0.0.1:${controlPort}/export`, { method: 'POST' });
    expect(post.status).toBe(405);
    const unknown = await fetch(`http://127.0.0.1:${controlPort}/policy`);
    expect(unknown.status).toBe(404);
  });
});

describe('exportBundleToFile — a SEPARATE invocation resolves the live ledger', () => {
  let dataDir: string;
  let outFile: string;

  beforeAll(() => {
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aga-ctl-'));
    outFile = path.join(dataDir, 'evidence.json');
  });
  afterAll(() => {
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* ok */ }
  });

  it('REPRODUCES the gap fix: proxy=null + published control port → exports the live ledger, VERIFIED', async () => {
    // This is the failing-before/passing-after case: with no in-process proxy handle (a fresh
    // `aga-proxy export` process), the only way to export is via the control port the running proxy
    // published to the data dir.
    writeControlFile(dataDir, { host: CONTROL_HOST, port: controlPort, pid: process.pid });
    expect(readControlFile(dataDir)?.port).toBe(controlPort);

    const res = await exportBundleToFile({ proxy: null, dataDir, output: outFile });
    expect(res.source).toBe('control-channel');
    expect(res.receiptCount).toBeGreaterThan(0);

    const written = JSON.parse(fs.readFileSync(outFile, 'utf-8'));
    const result = verifySepBundle(written, proxy.getPublicKey());
    expect(result.verdict).toBe('VERIFIED');
    expect(result.issuerVerified).toBe(true);
  });

  it('the in-process path still works (source = in-process)', async () => {
    // Distinct output path: the preceding test already wrote `outFile`, and since RC9-06 the
    // exporter refuses an existing destination by default (exclusive-create, D-21.7). This test
    // asserts source resolution and receipt count — it never asserted overwrite semantics, so it
    // gets its own path rather than depending on the destructive behavior that was just removed.
    const freshOut = path.join(dataDir, 'evidence-in-process.json');
    const res = await exportBundleToFile({ proxy, dataDir, output: freshOut });
    expect(res.source).toBe('in-process');
    expect(res.receiptCount).toBeGreaterThan(0);
  });

  it('with NO running proxy, throws the clear message and writes NO file (never an empty bundle)', async () => {
    const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aga-noproxy-'));
    const out = path.join(emptyDir, 'should-not-exist.json');
    await expect(exportBundleToFile({ proxy: null, dataDir: emptyDir, output: out }))
      .rejects.toThrowError(ExportUnavailableError);
    await expect(exportBundleToFile({ proxy: null, dataDir: emptyDir, output: out }))
      .rejects.toThrowError(NO_PROXY_MESSAGE);
    expect(fs.existsSync(out)).toBe(false);
    fs.rmSync(emptyDir, { recursive: true, force: true });
  });

  it('a stale control file (dead port) is treated as no-proxy, not a silent empty bundle', async () => {
    const staleDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aga-stale-'));
    writeControlFile(staleDir, { host: CONTROL_HOST, port: 6, pid: 999999 }); // port 6 has no listener
    const out = path.join(staleDir, 'nope.json');
    await expect(exportBundleToFile({ proxy: null, dataDir: staleDir, output: out }))
      .rejects.toThrowError(NO_PROXY_MESSAGE);
    expect(fs.existsSync(out)).toBe(false);
    fs.rmSync(staleDir, { recursive: true, force: true });
  });

  it('a recycled port held by a FOREIGN service (valid JSON, no AGA header) is treated as no-proxy — no file written', async () => {
    // Simulate a stale control.json pointing at a port now held by an unrelated local HTTP service
    // that returns valid JSON. Without the AGA identity header, export must refuse (ExportUnavailable).
    const foreign = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ hello: 'i am not aga', data: [1, 2, 3] }));
    });
    await new Promise<void>((r) => foreign.listen(0, CONTROL_HOST, () => r()));
    const fport = (foreign.address() as net.AddressInfo).port;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aga-foreign-'));
    writeControlFile(dir, { host: CONTROL_HOST, port: fport, pid: 999999 });
    const out = path.join(dir, 'nope.json');
    await expect(exportBundleToFile({ proxy: null, dataDir: dir, output: out }))
      .rejects.toThrowError(NO_PROXY_MESSAGE);
    expect(fs.existsSync(out)).toBe(false);
    await new Promise<void>((r) => foreign.close(() => r()));
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('an AGA channel that returns a non-bundle is refused, not written as evidence', async () => {
    // A server that sets the AGA identity header but returns a non-SepBundle object: the shape
    // guard must refuse to write it (an evidence tool never labels foreign JSON as evidence).
    const bad = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'x-aga-control': 'aga-proxy' });
      res.end(JSON.stringify({ algorithm: 'Ed25519-SHA256-JCS' /* no receipts, no checkpoint */ }));
    });
    await new Promise<void>((r) => bad.listen(0, CONTROL_HOST, () => r()));
    const bport = (bad.address() as net.AddressInfo).port;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aga-badshape-'));
    writeControlFile(dir, { host: CONTROL_HOST, port: bport, pid: 999999 });
    const out = path.join(dir, 'nope.json');
    await expect(exportBundleToFile({ proxy: null, dataDir: dir, output: out }))
      .rejects.toThrow(/not a SEP evidence bundle/);
    expect(fs.existsSync(out)).toBe(false);
    await new Promise<void>((r) => bad.close(() => r()));
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('isSepBundleShape accepts a real exported bundle and rejects foreign/partial objects', () => {
    expect(isSepBundleShape(proxy.exportBundle())).toBe(true);
    expect(isSepBundleShape({ hello: 'world' })).toBe(false);
    expect(isSepBundleShape({ algorithm: 'Ed25519-SHA256-JCS' })).toBe(false); // no receipts/checkpoint
    expect(isSepBundleShape(null)).toBe(false);
  });
});

describe('aga-proxy export CLI (separate process) — no running proxy exits nonzero', () => {
  it('exits 1 and prints the clear message when no proxy is running', async () => {
    // Point the child's home (getDataDir uses os.homedir()) at an empty dir so no control file exists.
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'aga-home-'));
    // Run the CLI SOURCE via tsx so the test does not depend on a prior `npm run build`.
    const cli = fileURLToPath(new URL('../../src/proxy/index.ts', import.meta.url));
    const out = path.join(home, 'e.json');
    const { code, stderr } = await new Promise<{ code: number | null; stderr: string }>((resolve) => {
      const child = spawn(process.execPath, ['--import', 'tsx', cli, 'export', '-o', out], {
        env: { ...process.env, HOME: home, USERPROFILE: home },
      });
      let err = '';
      child.stderr.on('data', (d) => { err += d.toString(); });
      child.on('close', (code) => resolve({ code, stderr: err }));
    });
    expect(code).toBe(1);
    expect(stderr).toContain(NO_PROXY_MESSAGE);
    expect(fs.existsSync(out)).toBe(false);
    fs.rmSync(home, { recursive: true, force: true });
  });
});
