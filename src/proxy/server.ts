/**
 * AGA Governance Proxy Server
 * TCP proxy that intercepts MCP JSON-RPC 2.0 tool calls,
 * evaluates them against a sealed policy, and produces
 * Ed25519-signed governance receipts.
 *
 * Receipt format: Ed25519-SHA256-JCS (canonical across TS gateway,
 * Python SDK, Go CLI, and browser verifier).
 *
 * Architecture: Client → Proxy (:18800) → Downstream MCP Server
 * The proxy holds ALL signing keys. The client holds NONE.
 *
 * Copyright (c) 2026 Attested Intelligence Holdings LLC
 * SPDX-License-Identifier: MIT
 */

import * as net from 'node:net';
import { EventEmitter } from 'node:events';
import { evaluate, resetRateLimits } from './evaluator.js';
import { StdioBridge, type StdioBridgeOptions } from './stdio-bridge.js';
import { PERMISSIVE } from './profiles.js';
import type { ToolPolicy } from './types.js';
// ONE canonical evidence engine (src/sep, node:crypto). The proxy no longer carries a
// parallel receipt/Merkle/canonical/@noble implementation; it records governed decisions
// through a SepGateway and exports the canonical SEP bundle, verified by the one verifier.
import {
  SepGateway, generateSigner, derivePolicyReference, safeArgumentsHash,
  type SepSigner, type SepReceipt, type SepBundle, type MerkleProof,
} from '../sep/index.js';

// ── Evidence types ARE the canonical src/sep types (no parallel definitions) ──
export type GovernanceReceipt = SepReceipt;
export type EvidenceBundle = SepBundle;
export type { MerkleProof };

// Upper bound on a single newline-delimited JSON-RPC message (and the incomplete-line buffer). A client
// streaming bytes with no newline must not grow the buffer without limit (memory-exhaustion DoS). Legit
// messages are far below this; the stdio bridge applies the same bound on the downstream side.
export const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;

// ── Proxy options ───────────────────────────────────────────

/** Benign MCP protocol methods forwarded WITHOUT a passthrough receipt (no side effects). */
export const DEFAULT_PASSTHROUGH_EXCLUDE = [
  'initialize', 'initialized', 'ping',
  'tools/list', 'prompts/list', 'resources/list', 'resources/templates/list',
  'logging/setLevel', 'completion/complete',
];

export interface ProxyServerOptions {
  port?: number;
  policy?: ToolPolicy;
  upstream?: StdioBridgeOptions;
  upstreamUrl?: string;
  gatewayId?: string;
  /** Override the benign-method exclusion list (excluded methods are forwarded with NO passthrough receipt). */
  passthroughExclude?: string[];
  /** Optional denylist: non-tools/call methods to reject (records a DENIED passthrough receipt; does not forward). */
  denyMethods?: string[];
}

export class GovernanceProxy extends EventEmitter {
  private server: net.Server | null = null;
  private bridge: StdioBridge | null = null;

  // Gateway signing key (node:crypto) — never leaves this process.
  private signer: SepSigner;
  // Canonical SEP evidence ledger: records + chain + Merkle + mandatory signed checkpoint.
  private sep: SepGateway;

  // State
  private policy: ToolPolicy;
  private port: number;
  private started = false;
  private upstreamOptions: StdioBridgeOptions | null;
  private upstreamUrl: string | null;
  private gatewayId: string;
  private passthroughExclude: Set<string>;
  private denyMethods: Set<string>;

  private policyHash: string = '';

  // Stats
  private stats = { permitted: 0, denied: 0, total: 0, started_at: '' };

  constructor(options: ProxyServerOptions = {}) {
    super();
    this.port = options.port ?? 18800;
    this.policy = options.policy ?? PERMISSIVE;
    this.upstreamOptions = options.upstream ?? null;
    this.upstreamUrl = options.upstreamUrl ?? null;
    this.gatewayId = options.gatewayId ?? 'aga-proxy';
    this.passthroughExclude = new Set(options.passthroughExclude ?? DEFAULT_PASSTHROUGH_EXCLUDE);
    this.denyMethods = new Set(options.denyMethods ?? []);
    this.signer = generateSigner().signer;
    this.sep = new SepGateway({ gatewayId: this.gatewayId, signer: this.signer });
  }

  // ── Start / Stop ───────────────────────────────────────────

  async start(): Promise<void> {
    if (this.started) throw new Error('Proxy already running');

    this.policyHash = derivePolicyReference(this.policy);
    this.sep.setPolicyReference(this.policyHash);

    // Start downstream bridge if configured
    if (this.upstreamOptions) {
      this.bridge = new StdioBridge(this.upstreamOptions);
      await this.bridge.start();
      this.bridge.on('error', (err) => this.emit('error', err));
      this.bridge.on('exit', (code: number) => {
        process.stderr.write(`[aga-proxy] Downstream exited with code ${code}\n`);
      });
    }

    if (this.upstreamUrl && !this.bridge) {
      process.stderr.write('[aga-proxy] HTTP upstream mode: the upstream URL is directly reachable — governance is BYPASSABLE unless the agent is network-isolated from it. Prefer stdio upstream. See DEPLOYMENT.md §1.\n');
    }

    // Start TCP server
    this.server = net.createServer((socket) => this.handleConnection(socket));
    await new Promise<void>((resolve, reject) => {
      this.server!.listen(this.port, () => resolve());
      this.server!.on('error', reject);
    });

    this.started = true;
    this.stats.started_at = new Date().toISOString();
    resetRateLimits();
    this.emit('started', { port: this.port });
  }

  async stop(): Promise<void> {
    if (!this.started) return;

    if (this.bridge) {
      await this.bridge.stop();
      this.bridge = null;
    }

    if (this.server) {
      await new Promise<void>((resolve) => {
        this.server!.close(() => resolve());
      });
      this.server = null;
    }

    this.started = false;
    this.emit('stopped');
  }

  // ── Connection handler ─────────────────────────────────────

  private handleConnection(socket: net.Socket): void {
    let buffer = '';

    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      // Fail-closed on a flood with no line terminator: bound the incomplete-line buffer so a client cannot
      // exhaust memory by streaming bytes without a newline. Reject and close rather than keep accumulating.
      if (buffer.length > MAX_MESSAGE_BYTES) {
        this.respond(socket, { jsonrpc: '2.0', error: { code: -32600, message: 'Message too large' }, id: null });
        buffer = '';
        socket.destroy();
        return;
      }
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        this.handleMessage(trimmed, socket).catch((err) => {
          process.stderr.write(`[aga-proxy] Error handling message: ${err}\n`);
        });
      }
    });

    socket.on('error', () => { /* client disconnected */ });
  }

  private async handleMessage(raw: string, socket: net.Socket): Promise<void> {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(raw);
    } catch {
      this.respond(socket, { jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' }, id: null });
      return;
    }

    if (parsed.jsonrpc !== '2.0') {
      this.respond(socket, { jsonrpc: '2.0', error: { code: -32600, message: 'Invalid Request: missing jsonrpc 2.0' }, id: null });
      return;
    }

    const requestId = (parsed.id as string | number | null) ?? null;
    const method = parsed.method as string | undefined;

    // Non-tools/call methods: NOT policy-evaluated, but recorded for AUDITABILITY as a signed
    // passthrough receipt so they are visible in the evidence bundle — unless they are benign
    // protocol methods (excluded) or notifications. An optional denylist rejects known side-effecting
    // methods. This buys VISIBILITY, not governance: the method still executes (unless denylisted),
    // and a direct-to-upstream call still bypasses entirely. See THREAT_BOUNDARY.md §3.2.
    if (method !== 'tools/call') {
      const m = method ?? '';
      const passParams = parsed.params as Record<string, unknown> | undefined;
      if (m && this.denyMethods.has(m)) {
        const receipt = this.generateReceipt('(passthrough)', 'DENIED', `non-tools/call method on denylist: ${m}`, requestId, passParams, m);
        this.respond(socket, { jsonrpc: '2.0', error: { code: -32600, message: `Method denied by policy: ${m}`, data: { receipt_id: receipt.receipt_id, decision: 'DENIED' } }, id: requestId });
        return;
      }
      const benign = !m || m.startsWith('notifications/') || this.passthroughExclude.has(m);
      if (!benign) {
        this.generateReceipt('(passthrough)', 'PERMITTED', `forwarded, not policy-evaluated: ${m}`, requestId, passParams, m);
      }
      if (this.bridge) {
        try {
          const response = await this.bridge.send(parsed);
          this.respond(socket, response);
        } catch (err) {
          this.respond(socket, {
            jsonrpc: '2.0',
            error: { code: -32603, message: `Downstream error: ${err}` },
            id: requestId,
          });
        }
      } else if (this.upstreamUrl) {
        await this.forwardHttp(raw, socket, requestId);
      } else {
        this.respond(socket, {
          jsonrpc: '2.0',
          error: { code: -32603, message: 'No upstream configured' },
          id: requestId,
        });
      }
      return;
    }

    // tools/call - governance intercept
    await this.interceptToolCall(parsed, socket, requestId);
  }

  // ── Tool call interception ─────────────────────────────────

  private async interceptToolCall(
    parsed: Record<string, unknown>,
    socket: net.Socket,
    requestId: string | number | null,
  ): Promise<void> {
    const params = parsed.params as Record<string, unknown> | undefined;
    const toolName = params?.name as string | undefined;
    const toolArgs = params?.arguments as Record<string, unknown> | undefined;

    this.stats.total++;

    // Fail-closed: no tool name
    if (!toolName) {
      const receipt = this.generateReceipt('UNKNOWN', 'DENIED', 'tool name extraction failed, fail-closed', requestId, undefined);
      this.stats.denied++;
      this.respond(socket, {
        jsonrpc: '2.0',
        error: {
          code: -32600,
          message: 'Missing tool name',
          data: { receipt_id: receipt.receipt_id, decision: 'DENIED' },
        },
        id: requestId,
      });
      return;
    }

    // Fail-closed: arguments that cannot be canonicalized (depth-bomb / hostile payload) are
    // DENIED and recorded — never silently dropped or forwarded. Done BEFORE policy evaluation
    // so the evaluator never sees an unbounded structure either.
    const { hash: argsHash, ok: argsOk } = safeArgumentsHash(toolArgs);
    if (!argsOk) {
      const receipt = this.generateReceipt(toolName, 'DENIED', 'fail-closed: arguments could not be canonicalized (too deeply nested or invalid)', requestId, undefined, 'tools/call', argsHash);
      this.stats.denied++;
      this.respond(socket, {
        jsonrpc: '2.0',
        error: { code: -32600, message: 'Tool denied: uncanonicalizable arguments', data: { receipt_id: receipt.receipt_id, decision: 'DENIED' } },
        id: requestId,
      });
      return;
    }

    // Evaluate against policy
    const decision = evaluate(this.policy, toolName, toolArgs);
    const receipt = this.generateReceipt(
      toolName,
      decision.allowed ? 'PERMITTED' : 'DENIED',
      decision.reason,
      requestId,
      toolArgs,
      'tools/call',
      argsHash,
    );

    if (!decision.allowed) {
      this.stats.denied++;
      this.respond(socket, {
        jsonrpc: '2.0',
        error: {
          code: -32600,
          message: `Tool denied: ${decision.reason}`,
          data: { receipt_id: receipt.receipt_id, decision: 'DENIED', reason: decision.reason },
        },
        id: requestId,
      });
      return;
    }

    // Permitted - forward to downstream
    this.stats.permitted++;

    if (this.bridge) {
      try {
        const response = await this.bridge.send(parsed);
        this.respond(socket, response);
      } catch (err) {
        this.respond(socket, {
          jsonrpc: '2.0',
          error: { code: -32603, message: `Downstream error: ${err}` },
          id: requestId,
        });
      }
    } else if (this.upstreamUrl) {
      await this.forwardHttp(JSON.stringify(parsed), socket, requestId);
    } else {
      // No upstream - return success with receipt info
      this.respond(socket, {
        jsonrpc: '2.0',
        result: {
          content: [{ type: 'text', text: JSON.stringify({ permitted: true, receipt_id: receipt.receipt_id, tool: toolName }) }],
        },
        id: requestId,
      });
    }
  }

  // ── Receipt generation (Ed25519-SHA256-JCS canonical format) ─

  /** Record a governed decision as a canonical SEP receipt via the shared engine. */
  private generateReceipt(
    toolName: string,
    decision: 'PERMITTED' | 'DENIED',
    reason: string,
    requestId: string | number | null,
    toolArgs: Record<string, unknown> | undefined,
    method: string = 'tools/call',
    argsHashOverride?: string,
  ): SepReceipt {
    // SepGateway owns canonicalization, the arguments_hash tri-state, request_id coercion
    // (string|null), chain linkage, and signing — one source of truth for receipt construction.
    // safeArgumentsHash never throws (depth-bomb -> sentinel), so recording can never crash and
    // silently drop a governed decision; callers may pass a precomputed hash to avoid re-hashing.
    const argumentsHash = argsHashOverride ?? safeArgumentsHash(toolArgs).hash;
    return this.sep.record({
      tool_name: toolName,
      decision,
      reason,
      request_id: requestId,
      method,
      argumentsHash,
      policy_reference: this.policyHash,
    });
  }

  // ── HTTP forwarding ────────────────────────────────────────

  private async forwardHttp(body: string, socket: net.Socket, requestId: string | number | null): Promise<void> {
    try {
      const resp = await fetch(this.upstreamUrl!, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      });
      const data = await resp.json();
      this.respond(socket, data as Record<string, unknown>);
    } catch (err) {
      this.respond(socket, {
        jsonrpc: '2.0',
        error: { code: -32603, message: `HTTP upstream error: ${err}` },
        id: requestId,
      });
    }
  }

  // ── Response helper ────────────────────────────────────────

  private respond(socket: net.Socket, msg: Record<string, unknown>): void {
    if (socket.destroyed) return;
    const ok = socket.write(JSON.stringify(msg) + '\n');
    // Backpressure: a client that does not read its responses must not grow the outbound buffer without
    // bound (slow-reader memory-exhaustion DoS). If the socket's write buffer is backed up past the cap,
    // drop the connection rather than accumulate.
    if (!ok && socket.writableLength > MAX_MESSAGE_BYTES) {
      socket.destroy();
    }
  }

  // ── Public API ─────────────────────────────────────────────

  async switchPolicy(newPolicy: ToolPolicy): Promise<void> {
    this.policy = newPolicy;
    this.policyHash = derivePolicyReference(newPolicy);
    this.sep.setPolicyReference(this.policyHash);
    resetRateLimits();
    this.emit('policy_switched');
  }

  /** Export the canonical SEP evidence bundle (receipts + Merkle proofs + signed checkpoint). */
  exportBundle(): SepBundle {
    return this.sep.exportBundle();
  }

  getStatus() {
    return {
      running: this.started,
      port: this.port,
      policy_mode: this.policy.mode,
      receipt_count: this.sep.count,
      ...this.stats,
      public_key: this.signer.publicKeyHex,
    };
  }

  getPublicKey(): string { return this.signer.publicKeyHex; }
  getReceipts(): SepReceipt[] { return [...this.sep.getReceipts()]; }
}
