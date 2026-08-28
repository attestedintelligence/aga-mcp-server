/**
 * AGA Governance Proxy — loopback-only control channel.
 *
 * The governance proxy keeps its SEP evidence ledger in memory (SepGateway) and can already
 * assemble the canonical signed bundle via GovernanceProxy.exportBundle(). Before this module,
 * that method was only reachable from inside the running `start` process; a SEPARATE
 * `aga-proxy export` invocation had no handle to the live ledger and failed.
 *
 * This adds a tiny HTTP control listener bound to 127.0.0.1 ONLY (never 0.0.0.0), on its own
 * port distinct from the agent-facing proxy port. It exposes READ-ONLY routes over the already-
 * signed artifact: GET /export (the same SepBundle exportBundle() returns), GET /status, and
 * GET /receipts. There is NO route that mutates policy or ledger state.
 *
 * Trust surface: the channel adds none. The bundle it returns is the identical signed artifact
 * exportBundle() already produces — anyone who can read the written file gets the same thing. The
 * off-host guarantee is the loopback bind itself, not auth theater; a shared-host deployment must
 * treat any local user as able to read the (already-signed, already-exportable) evidence.
 *
 * Copyright (c) 2026 Attested Intelligence Holdings LLC
 * SPDX-License-Identifier: MIT
 */

import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';

/** Loopback address the control listener binds to. Never 0.0.0.0. */
export const CONTROL_HOST = '127.0.0.1';
/** Default control port; distinct from the agent-facing proxy port (18800). Overridable via CLI. */
export const DEFAULT_CONTROL_PORT = 18801;
/** Identity header set on every control response; checked by the CLI to reject foreign services. */
export const CONTROL_HEADER = 'x-aga-control';
export const CONTROL_HEADER_VALUE = 'aga-proxy';

/**
 * Structural guard: is `b` a well-formed SepBundle? A stale control port can be recycled by an
 * unrelated local service that returns valid-but-foreign JSON; for an evidence tool, writing that
 * as "evidence" (even though it would fail verification) is a workflow-integrity defect. Combined
 * with the identity header, this ensures `export` only ever writes an actual SEP bundle.
 */
export function isSepBundleShape(b: unknown): boolean {
  if (!b || typeof b !== 'object') return false;
  const o = b as Record<string, unknown>;
  // v1 "Ed25519-SHA256-JCS" and v2 composite "ML-DSA-65+Ed25519-SHA256-JCS" both name Ed25519.
  if (typeof o.algorithm !== 'string' || !o.algorithm.includes('Ed25519')) return false;
  if (!Array.isArray(o.receipts)) return false;
  const cp = o.checkpoint as Record<string, unknown> | undefined;
  if (!cp || typeof cp !== 'object') return false;
  if (typeof cp.merkle_root !== 'string' || typeof cp.signature !== 'string') return false;
  return true;
}

/** The read-only surface the control listener exposes from the running proxy. */
export interface ProxyControlTarget {
  exportBundle(): unknown;
  getStatus(): unknown;
  getReceipts(): unknown;
}

/**
 * Loopback HTTP control listener over a running proxy's read-only evidence surface.
 * Bind is forced to 127.0.0.1 — a caller cannot widen it to a routable interface.
 */
export class ProxyControlServer {
  private server: http.Server | null = null;
  private boundPort = 0;
  private readonly target: ProxyControlTarget;

  constructor(target: ProxyControlTarget) {
    this.target = target;
  }

  /** Start the listener on 127.0.0.1:<port>. Rejects (e.g. EADDRINUSE) if the port is taken. */
  async start(port: number = DEFAULT_CONTROL_PORT): Promise<{ address: string; port: number }> {
    if (this.server) throw new Error('control server already running');
    const server = http.createServer((req, res) => this.handle(req, res));
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => reject(err);
      server.once('error', onError);
      // LOOPBACK BIND — the second argument to listen() is the host. Hardcoded to 127.0.0.1 so the
      // control channel is unreachable off-host by construction (never 0.0.0.0 / a routable NIC).
      server.listen(port, CONTROL_HOST, () => {
        server.removeListener('error', onError);
        resolve();
      });
    });
    const addr = server.address();
    this.boundPort = typeof addr === 'object' && addr ? addr.port : port;
    return { address: this.address(), port: this.boundPort };
  }

  /** The address the listener is actually bound to (asserted in tests to be loopback). */
  address(): string {
    const addr = this.server?.address();
    return typeof addr === 'object' && addr ? addr.address : CONTROL_HOST;
  }

  get port(): number {
    return this.boundPort;
  }

  private handle(req: http.IncomingMessage, res: http.ServerResponse): void {
    // READ-ONLY: only GET is accepted; no route mutates policy or ledger state.
    if (req.method !== 'GET') {
      this.json(res, 405, { error: 'method not allowed; the control channel is read-only (GET only)' });
      return;
    }
    const route = (req.url ?? '').split('?')[0];
    try {
      if (route === '/export') {
        let bundle: unknown;
        try {
          bundle = this.target.exportBundle();
        } catch (e) {
          // exportBundle() throws when the ledger is empty — that is a live, running proxy with
          // nothing to export yet, NOT an absent proxy. Report it distinctly (409) so the CLI does
          // not misreport it as "no running proxy".
          this.json(res, 409, { error: e instanceof Error ? e.message : 'no receipts to export' });
          return;
        }
        this.json(res, 200, bundle);
      } else if (route === '/status') {
        this.json(res, 200, this.target.getStatus());
      } else if (route === '/receipts') {
        this.json(res, 200, this.target.getReceipts());
      } else {
        this.json(res, 404, { error: 'not found; the control channel exposes only GET /export, /status, /receipts' });
      }
    } catch (e) {
      this.json(res, 500, { error: e instanceof Error ? e.message : 'internal error' });
    }
  }

  private json(res: http.ServerResponse, status: number, body: unknown): void {
    // Identity header: lets a separate `aga-proxy export` confirm it reached an actual AGA control
    // channel and not some unrelated local service that happens to hold a recycled control port
    // (stale ~/.aga-proxy/control.json). A foreign HTTP service will not set this.
    res.writeHead(status, { 'content-type': 'application/json', [CONTROL_HEADER]: CONTROL_HEADER_VALUE });
    res.end(JSON.stringify(body));
  }

  /** Stop the listener. Idempotent. */
  async stop(): Promise<void> {
    const s = this.server;
    if (!s) return;
    this.server = null;
    this.boundPort = 0;
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
}

// ── Control-file locator (written alongside proxy.pid so a separate process can find the port) ──

/** Where the running proxy publishes its control-channel coordinates. */
export interface ControlLocator {
  host: string;
  port: number;
  pid: number;
}

export function controlFilePath(dataDir: string): string {
  return path.join(dataDir, 'control.json');
}

export function writeControlFile(dataDir: string, loc: ControlLocator): void {
  fs.writeFileSync(controlFilePath(dataDir), JSON.stringify(loc));
}

export function readControlFile(dataDir: string): ControlLocator | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(controlFilePath(dataDir), 'utf-8')) as Record<string, unknown>;
    if (typeof parsed.port !== 'number') return null;
    return {
      host: typeof parsed.host === 'string' ? parsed.host : CONTROL_HOST,
      port: parsed.port,
      pid: typeof parsed.pid === 'number' ? parsed.pid : 0,
    };
  } catch {
    return null;
  }
}

export function removeControlFile(dataDir: string): void {
  try {
    fs.unlinkSync(controlFilePath(dataDir));
  } catch {
    /* already gone */
  }
}

// ── Export resolution (in-process proxy OR the live proxy over the control channel) ──

/** Stable message when no live proxy can be reached — never emit an empty bundle instead. */
export const NO_PROXY_MESSAGE =
  'no running proxy found; start it first, or export from within the session';

/** Thrown when export cannot reach a live proxy. Carries {@link NO_PROXY_MESSAGE}. */
export class ExportUnavailableError extends Error {
  constructor(message: string = NO_PROXY_MESSAGE) {
    super(message);
    this.name = 'ExportUnavailableError';
  }
}

/**
 * Fetch the signed bundle from a live proxy over its loopback control channel.
 * A connection failure (proxy not running) → {@link ExportUnavailableError}. An empty ledger
 * (409) or other HTTP error → a distinct Error so the caller does not misreport it as "no proxy".
 */
export async function fetchBundleViaControl(loc: ControlLocator): Promise<unknown> {
  const url = `http://${loc.host}:${loc.port}/export`;
  let res: Response;
  try {
    res = await fetch(url);
  } catch {
    // ECONNREFUSED / DNS / etc. — the recorded control port has no live listener.
    throw new ExportUnavailableError();
  }
  if (res.status === 409) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? 'the proxy has no receipts to export yet');
  }
  if (!res.ok) {
    throw new Error(`control channel returned HTTP ${res.status}`);
  }
  // Identity guard: a recycled/stale control port could be held by an unrelated local service that
  // returns valid JSON. Require the AGA control header before trusting the response at all.
  if (res.headers.get(CONTROL_HEADER) !== CONTROL_HEADER_VALUE) {
    throw new ExportUnavailableError();
  }
  const body = await res.json();
  // Shape guard: never write foreign JSON labeled as evidence. (Verification would reject it, but
  // an evidence tool must not report success on a non-bundle.)
  if (!isSepBundleShape(body)) {
    throw new Error('control channel returned a response that is not a SEP evidence bundle; refusing to write it');
  }
  return body;
}

/**
 * Resolve and write an evidence bundle: from an in-process proxy if one exists, otherwise from the
 * live proxy over its loopback control channel. Never writes an empty/placeholder bundle — if no
 * live proxy can be reached it throws {@link ExportUnavailableError}.
 */
export class ExportTargetExistsError extends Error {
  constructor(public readonly output: string) {
    super(
      `Refusing to overwrite an existing file: ${output}\n` +
      `Export writes with exclusive-create by default so it can never destroy an operator's file.\n` +
      `Choose a different --output path, or pass --force to replace this file deliberately.`
    );
    this.name = 'ExportTargetExistsError';
  }
}

export async function exportBundleToFile(opts: {
  proxy: { exportBundle(): unknown } | null;
  dataDir: string;
  output: string;
  /** RC9-06 / D-21.7: replacement is opt-in only. Default refuses an existing destination. */
  force?: boolean;
  writeFile?: (filePath: string, data: string) => void;
}): Promise<{ source: 'in-process' | 'control-channel'; output: string; receiptCount: number }> {
  // RC9-06 (founder ruling D-21.7): this previously called fs.writeFileSync unconditionally, so
  // `export --output <existing-file>` silently TRUNCATED whatever the operator pointed at — a
  // config, a key file, a prior bundle — and exited 0 reporting success. No attacker and no
  // unusual deployment required, on the exact artifact a verifier consumes. Default is now
  // exclusive-create ('wx', which fails if the path exists); replacement requires --force.
  const write = opts.writeFile ?? ((p: string, d: string) => {
    try {
      fs.writeFileSync(p, d, opts.force ? undefined : { flag: 'wx' });
    } catch (e) {
      if (!opts.force && (e as NodeJS.ErrnoException)?.code === 'EEXIST') throw new ExportTargetExistsError(p);
      throw e;
    }
  });
  let bundle: unknown;
  let source: 'in-process' | 'control-channel';

  if (opts.proxy) {
    bundle = opts.proxy.exportBundle();
    source = 'in-process';
  } else {
    const loc = readControlFile(opts.dataDir);
    if (!loc) throw new ExportUnavailableError();
    bundle = await fetchBundleViaControl(loc);
    source = 'control-channel';
  }

  write(opts.output, JSON.stringify(bundle, null, 2));
  const receipts = (bundle as { receipts?: unknown }).receipts;
  const receiptCount = Array.isArray(receipts) ? receipts.length : 0;
  return { source, output: opts.output, receiptCount };
}
