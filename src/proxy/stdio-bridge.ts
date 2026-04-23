/**
 * AGA Governance Proxy - Stdio Bridge
 * Spawns a downstream MCP server as a child process and manages
 * JSON-RPC message framing over stdin/stdout.
 *
 * Copyright (c) 2026 Attested Intelligence Holdings LLC
 * SPDX-License-Identifier: MIT
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';

export interface StdioBridgeOptions {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

/**
 * Bridges JSON-RPC messages to/from a child process via stdio.
 * Handles newline-delimited JSON framing.
 */
export class StdioBridge extends EventEmitter {
  private child: ChildProcess | null = null;
  private buffer = '';
  private pendingRequests = new Map<string | number, {
    resolve: (response: Record<string, unknown>) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }>();

  constructor(private options: StdioBridgeOptions) {
    super();
  }

  async start(): Promise<void> {
    const { command, args = [], env, cwd } = this.options;

    this.child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...env },
      cwd,
      shell: process.platform === 'win32',
    });

    this.child.stdout!.on('data', (chunk: Buffer) => {
      this.buffer += chunk.toString();
      this.processBuffer();
    });

    this.child.stderr!.on('data', (chunk: Buffer) => {
      // Log downstream stderr but don't treat as JSON-RPC
      process.stderr.write(`[downstream] ${chunk.toString()}`);
    });

    this.child.on('exit', (code, signal) => {
      this.emit('exit', code, signal);
      this.rejectAllPending(new Error(`Downstream process exited: code=${code} signal=${signal}`));
    });

    this.child.on('error', (err) => {
      this.emit('error', err);
      this.rejectAllPending(err);
    });
  }

  private processBuffer(): void {
    const lines = this.buffer.split('\n');
    // Keep the last (possibly incomplete) line in the buffer
    this.buffer = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      try {
        const msg = JSON.parse(trimmed) as Record<string, unknown>;
        this.handleMessage(msg);
      } catch {
        // Not valid JSON - skip
      }
    }
  }

  private handleMessage(msg: Record<string, unknown>): void {
    // If it has an id and either result or error, it's a response
    if ('id' in msg && ('result' in msg || 'error' in msg)) {
      const id = msg.id as string | number;
      const pending = this.pendingRequests.get(id);
      if (pending) {
        clearTimeout(pending.timer);
        this.pendingRequests.delete(id);
        pending.resolve(msg);
      }
      return;
    }

    // Notifications from downstream (no id, or has method) - emit for proxy to handle
    this.emit('notification', msg);
  }

  /**
   * Send a JSON-RPC request to the downstream server and wait for a response.
   */
  async send(message: Record<string, unknown>, timeoutMs = 30_000): Promise<Record<string, unknown>> {
    if (!this.child?.stdin?.writable) {
      throw new Error('Downstream process not running');
    }

    const id = message.id as string | number | undefined;

    // Notifications (no id) - fire and forget
    if (id === undefined || id === null) {
      this.child.stdin.write(JSON.stringify(message) + '\n');
      return { jsonrpc: '2.0', result: null, id: null };
    }

    return new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`Timeout waiting for response to request ${id}`));
      }, timeoutMs);

      this.pendingRequests.set(id, { resolve, reject, timer });
      this.child!.stdin!.write(JSON.stringify(message) + '\n');
    });
  }

  /**
   * Send a raw message without waiting for a response.
   */
  sendRaw(message: Record<string, unknown>): void {
    if (!this.child?.stdin?.writable) {
      throw new Error('Downstream process not running');
    }
    this.child.stdin.write(JSON.stringify(message) + '\n');
  }

  async stop(): Promise<void> {
    this.rejectAllPending(new Error('Bridge stopped'));
    if (this.child) {
      this.child.kill('SIGTERM');
      // Give it a moment, then force kill
      await new Promise<void>(resolve => {
        const timer = setTimeout(() => {
          this.child?.kill('SIGKILL');
          resolve();
        }, 3000);
        this.child!.on('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
      this.child = null;
    }
  }

  get running(): boolean {
    return this.child !== null && this.child.exitCode === null;
  }

  private rejectAllPending(err: Error): void {
    for (const [id, pending] of this.pendingRequests) {
      clearTimeout(pending.timer);
      pending.reject(err);
    }
    this.pendingRequests.clear();
  }
}
