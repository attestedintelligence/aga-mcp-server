/**
 * Integration test: governance proxy round-trip.
 * Starts the proxy, sends tool calls over TCP, asserts:
 * - Permitted calls succeed
 * - Denied calls return JSON-RPC errors with receipt IDs
 * - Every tool call produces a signed receipt
 * - Evidence bundle exports and verifies (Ed25519-SHA256-JCS format)
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as net from 'node:net';
import { GovernanceProxy } from '../../src/proxy/server.js';
import { verifyGatewayBundle } from '../../src/proxy/verify.js';
import type { ToolPolicy } from '../../src/proxy/types.js';

const TEST_PORT = 19900 + Math.floor(Math.random() * 100);

const policy: ToolPolicy = {
  mode: 'allowlist',
  constraints: {
    filesystem_read: { name: 'filesystem_read', allowed: true, max_calls_per_minute: 100 },
    web_search: { name: 'web_search', allowed: true, max_calls_per_minute: 100 },
    shell_execute: { name: 'shell_execute', allowed: false },
  },
};

let proxy: GovernanceProxy;

async function sendJsonRpc(port: number, msg: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ port }, () => {
      socket.write(JSON.stringify(msg) + '\n');
    });
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try { const p = JSON.parse(trimmed); socket.destroy(); resolve(p); return; } catch { /* wait */ }
      }
    });
    socket.on('error', reject);
    setTimeout(() => { socket.destroy(); reject(new Error('Timeout')); }, 5000);
  });
}

beforeAll(async () => {
  proxy = new GovernanceProxy({ port: TEST_PORT, policy });
  await proxy.start();
});

afterAll(async () => {
  await proxy.stop();
});

describe('Governance Proxy Round-Trip', () => {

  it('denies tools not in allowlist', async () => {
    const resp = await sendJsonRpc(TEST_PORT, {
      jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'unknown_tool', arguments: {} },
    });
    expect(resp.error).toBeDefined();
    expect((resp.error as any).code).toBe(-32600);
    expect((resp.error as any).data.decision).toBe('DENIED');
    expect((resp.error as any).data.receipt_id).toBeDefined();
  });

  it('denies explicitly disallowed tools', async () => {
    const resp = await sendJsonRpc(TEST_PORT, {
      jsonrpc: '2.0', id: 2, method: 'tools/call',
      params: { name: 'shell_execute', arguments: { cmd: 'ls' } },
    });
    expect(resp.error).toBeDefined();
    expect((resp.error as any).message).toContain('denied');
  });

  it('permits allowed tools (no upstream = returns receipt info)', async () => {
    const resp = await sendJsonRpc(TEST_PORT, {
      jsonrpc: '2.0', id: 3, method: 'tools/call',
      params: { name: 'filesystem_read', arguments: { path: '/home/test.txt' } },
    });
    expect(resp.result).toBeDefined();
    const content = (resp.result as any).content as Array<{ type: string; text: string }>;
    const parsed = JSON.parse(content[0].text);
    expect(parsed.permitted).toBe(true);
    expect(parsed.receipt_id).toBeDefined();
  });

  it('handles missing tool name fail-closed', async () => {
    const resp = await sendJsonRpc(TEST_PORT, {
      jsonrpc: '2.0', id: 4, method: 'tools/call',
      params: { arguments: {} },
    });
    expect(resp.error).toBeDefined();
    expect((resp.error as any).code).toBe(-32600);
  });

  it('passes through non-tools/call methods (returns no-upstream error)', async () => {
    const resp = await sendJsonRpc(TEST_PORT, {
      jsonrpc: '2.0', id: 5, method: 'tools/list', params: {},
    });
    expect(resp.error).toBeDefined();
    expect((resp.error as any).message).toContain('No upstream');
  });

  it('handles invalid JSON gracefully', async () => {
    const resp = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const socket = net.createConnection({ port: TEST_PORT }, () => {
        socket.write('not valid json\n');
      });
      let buffer = '';
      socket.on('data', (chunk) => {
        buffer += chunk.toString();
        try { resolve(JSON.parse(buffer.trim().split('\n')[0])); socket.destroy(); } catch { /* wait */ }
      });
      socket.on('error', reject);
      setTimeout(() => { socket.destroy(); reject(new Error('Timeout')); }, 3000);
    });
    expect(resp.error).toBeDefined();
    expect((resp.error as any).code).toBe(-32700);
  });

  it('produces receipts for every tool call', async () => {
    for (let i = 10; i < 15; i++) {
      await sendJsonRpc(TEST_PORT, {
        jsonrpc: '2.0', id: i, method: 'tools/call',
        params: { name: 'web_search', arguments: { query: `test ${i}` } },
      });
    }
    const status = proxy.getStatus();
    expect(status.total).toBeGreaterThanOrEqual(5);
    expect(status.receipt_count).toBeGreaterThan(0);
  });

  it('exports and verifies evidence bundle (Ed25519-SHA256-JCS)', async () => {
    const bundle = proxy.exportBundle();
    expect(bundle.algorithm).toBe('Ed25519-SHA256-JCS');
    expect(bundle.receipts.length).toBeGreaterThan(0);
    expect(bundle.merkle_proofs.length).toBe(bundle.receipts.length);
    expect(bundle.merkle_root).toBeDefined();

    // Verify with standalone verifier (zero ../core/ imports)
    const result = await verifyGatewayBundle(JSON.stringify(bundle));
    expect(result.algorithm_valid).toBe(true);
    expect(result.receipt_signatures_valid).toBe(true);
    expect(result.chain_integrity_valid).toBe(true);
    expect(result.merkle_proofs_valid).toBe(true);
    expect(result.bundle_consistent).toBe(true);
    expect(result.overall_valid).toBe(true);
  });

  it('getStatus returns correct shape', () => {
    const status = proxy.getStatus();
    expect(status.running).toBe(true);
    expect(status.port).toBe(TEST_PORT);
    expect(status.policy_mode).toBe('allowlist');
    expect(status.public_key).toBeDefined();
  });
});
