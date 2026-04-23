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
import { generateKeyPair, pkToHex, signStr } from '../crypto/sign.js';
import { bytesToHex, hexToBytes as utilHexToBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import { sha256Str } from '../crypto/hash.js';
import { canonicalize } from '../utils/canonical.js';
import { evaluate, resetRateLimits } from './evaluator.js';
import { StdioBridge, type StdioBridgeOptions } from './stdio-bridge.js';
import { PERMISSIVE } from './profiles.js';
import { utcNow } from '../utils/timestamp.js';
import { uuid } from '../utils/uuid.js';
import type { ToolPolicy } from './types.js';
import type { KeyPair } from '../crypto/types.js';

// ── Gateway-format receipt (canonical across all SDKs) ──────

export interface GovernanceReceipt {
  receipt_id: string;
  receipt_version: string;
  algorithm: string;
  timestamp: string;
  request_id: string | number | null;
  method: string;
  tool_name: string;
  decision: 'PERMITTED' | 'DENIED';
  reason: string;
  policy_reference: string;
  arguments_hash: string;
  previous_receipt_hash: string;
  gateway_id: string;
  signature: string;
  public_key: string;
}

export interface EvidenceBundle {
  schema_version: string;
  bundle_id: string;
  algorithm: string;
  generated_at: string;
  gateway_id: string;
  public_key: string;
  policy_reference: string;
  receipts: GovernanceReceipt[];
  merkle_root: string;
  merkle_proofs: MerkleProof[];
  offline_capable: boolean;
}

export interface MerkleProof {
  leaf_hash: string;
  leaf_index: number;
  siblings: string[];
  directions: ('left' | 'right')[];
  merkle_root: string;
}

// ── Proxy options ───────────────────────────────────────────

export interface ProxyServerOptions {
  port?: number;
  policy?: ToolPolicy;
  upstream?: StdioBridgeOptions;
  upstreamUrl?: string;
  gatewayId?: string;
}

export class GovernanceProxy extends EventEmitter {
  private server: net.Server | null = null;
  private bridge: StdioBridge | null = null;

  // Crypto key - never leaves this process
  private signingKP: KeyPair;

  // State
  private policy: ToolPolicy;
  private port: number;
  private started = false;
  private upstreamOptions: StdioBridgeOptions | null;
  private upstreamUrl: string | null;
  private gatewayId: string;

  // Receipt chain
  private receipts: GovernanceReceipt[] = [];
  private lastReceiptHash: string = '';
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
    this.signingKP = generateKeyPair();
  }

  // ── Start / Stop ───────────────────────────────────────────

  async start(): Promise<void> {
    if (this.started) throw new Error('Proxy already running');

    this.policyHash = sha256Str(canonicalize(this.policy));

    // Start downstream bridge if configured
    if (this.upstreamOptions) {
      this.bridge = new StdioBridge(this.upstreamOptions);
      await this.bridge.start();
      this.bridge.on('error', (err) => this.emit('error', err));
      this.bridge.on('exit', (code: number) => {
        process.stderr.write(`[aga-proxy] Downstream exited with code ${code}\n`);
      });
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

    // Non-tools/call methods: forward transparently
    if (method !== 'tools/call') {
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

    // Evaluate against policy
    const decision = evaluate(this.policy, toolName, toolArgs);
    const receipt = this.generateReceipt(
      toolName,
      decision.allowed ? 'PERMITTED' : 'DENIED',
      decision.reason,
      requestId,
      toolArgs,
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

  private generateReceipt(
    toolName: string,
    decision: 'PERMITTED' | 'DENIED',
    reason: string,
    requestId: string | number | null,
    toolArgs: Record<string, unknown> | undefined,
  ): GovernanceReceipt {
    const pubKeyHex = pkToHex(this.signingKP.publicKey);

    // Arguments hash tri-state per spec Section 3.5
    let argumentsHash: string;
    if (toolArgs === undefined) {
      argumentsHash = '';
    } else {
      argumentsHash = sha256Str(canonicalize(toolArgs));
    }

    const unsigned = {
      receipt_id: uuid(),
      receipt_version: '1.0',
      algorithm: 'Ed25519-SHA256-JCS',
      timestamp: utcNow(),
      request_id: requestId,
      method: 'tools/call',
      tool_name: toolName,
      decision,
      reason,
      policy_reference: this.policyHash,
      arguments_hash: argumentsHash,
      previous_receipt_hash: this.lastReceiptHash,
      gateway_id: this.gatewayId,
      public_key: pubKeyHex,
    };

    const sig = signStr(canonicalize(unsigned), this.signingKP.secretKey);
    const receipt: GovernanceReceipt = { ...unsigned, signature: bytesToHex(sig) };

    this.receipts.push(receipt);
    this.lastReceiptHash = sha256Str(canonicalize(receipt));

    return receipt;
  }

  // ── Merkle tree (binary, odd-node promotion, binary concat) ─

  private merkleNodeHash(leftHex: string, rightHex: string): string {
    const left = utilHexToBytes(leftHex);
    const right = utilHexToBytes(rightHex);
    const combined = new Uint8Array(left.length + right.length);
    combined.set(left, 0);
    combined.set(right, left.length);
    return bytesToHex(sha256(combined));
  }

  private computeMerkleRoot(leaves: string[]): string {
    if (leaves.length === 0) return '';
    if (leaves.length === 1) return leaves[0];
    let level = [...leaves];
    while (level.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < level.length; i += 2) {
        if (i + 1 < level.length) {
          next.push(this.merkleNodeHash(level[i], level[i + 1]));
        } else {
          next.push(level[i]);
        }
      }
      level = next;
    }
    return level[0];
  }

  private computeMerkleProof(leaves: string[], leafIndex: number): MerkleProof {
    const siblings: string[] = [];
    const directions: ('left' | 'right')[] = [];
    let level = [...leaves];
    let idx = leafIndex;

    while (level.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < level.length; i += 2) {
        if (i + 1 < level.length) {
          next.push(this.merkleNodeHash(level[i], level[i + 1]));
        } else {
          next.push(level[i]);
        }
      }
      if (idx % 2 === 0) {
        if (idx + 1 < level.length) {
          siblings.push(level[idx + 1]);
          directions.push('right');
        }
      } else {
        siblings.push(level[idx - 1]);
        directions.push('left');
      }
      idx = Math.floor(idx / 2);
      level = next;
    }

    return {
      leaf_hash: leaves[leafIndex],
      leaf_index: leafIndex,
      siblings,
      directions,
      merkle_root: level[0],
    };
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
    if (!socket.destroyed) {
      socket.write(JSON.stringify(msg) + '\n');
    }
  }

  // ── Public API ─────────────────────────────────────────────

  async switchPolicy(newPolicy: ToolPolicy): Promise<void> {
    this.policy = newPolicy;
    this.policyHash = sha256Str(canonicalize(newPolicy));
    resetRateLimits();
    this.emit('policy_switched');
  }

  exportBundle(): EvidenceBundle {
    if (this.receipts.length === 0) throw new Error('No receipts');

    const leafHashes = this.receipts.map(r => sha256Str(canonicalize(r)));
    const root = this.computeMerkleRoot(leafHashes);
    const proofs = leafHashes.map((_, i) => this.computeMerkleProof(leafHashes, i));

    return {
      schema_version: '1.0',
      bundle_id: uuid(),
      algorithm: 'Ed25519-SHA256-JCS',
      generated_at: utcNow(),
      gateway_id: this.gatewayId,
      public_key: pkToHex(this.signingKP.publicKey),
      policy_reference: this.policyHash,
      receipts: this.receipts,
      merkle_root: root,
      merkle_proofs: proofs,
      offline_capable: true,
    };
  }

  getStatus() {
    return {
      running: this.started,
      port: this.port,
      policy_mode: this.policy.mode,
      receipt_count: this.receipts.length,
      ...this.stats,
      public_key: pkToHex(this.signingKP.publicKey),
    };
  }

  getPublicKey(): string { return pkToHex(this.signingKP.publicKey); }
  getReceipts(): GovernanceReceipt[] { return this.receipts; }
}
