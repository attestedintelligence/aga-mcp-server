/**
 * Cross-verification test:
 * 1. Start proxy with allowlist policy
 * 2. Send 20 tool calls (mix of permitted + denied)
 * 3. Export evidence bundle (Ed25519-SHA256-JCS format)
 * 4. Verify with proxy's own verifier (zero ../core/ imports)
 * 5. Verify bundle is consistent with gateway format
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as net from 'node:net';
import { GovernanceProxy } from '../../src/proxy/server.js';
import { verifyGatewayBundle } from '../../src/proxy/verify.js';
import type { ToolPolicy } from '../../src/proxy/types.js';

const TEST_PORT = 19800 + Math.floor(Math.random() * 100);

const policy: ToolPolicy = {
  mode: 'allowlist',
  constraints: {
    filesystem_read:  { name: 'filesystem_read',  allowed: true, max_calls_per_minute: 100 },
    web_search:       { name: 'web_search',       allowed: true, max_calls_per_minute: 100 },
    shell_execute:    { name: 'shell_execute',     allowed: false },
    send_message:     { name: 'send_message',      allowed: true, max_calls_per_minute: 100 },
  },
};

let proxy: GovernanceProxy;

async function sendToolCall(port: number, id: number, toolName: string, args: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ port }, () => {
      socket.write(JSON.stringify({
        jsonrpc: '2.0', id, method: 'tools/call',
        params: { name: toolName, arguments: args },
      }) + '\n');
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

describe('Cross-Verification: Proxy → Bundle → Verifier', () => {

  it('generates receipts for 20 tool calls (mix of permitted and denied)', async () => {
    const calls = [
      { tool: 'filesystem_read', args: { path: '/home/test.txt' } },
      { tool: 'web_search', args: { query: 'AGA protocol' } },
      { tool: 'filesystem_read', args: { path: '/home/data.csv' } },
      { tool: 'send_message', args: { to: 'alice', body: 'hello' } },
      { tool: 'web_search', args: { query: 'MCP specification' } },
      { tool: 'filesystem_read', args: { path: '/home/config.json' } },
      { tool: 'web_search', args: { query: 'Ed25519 signing' } },
      { tool: 'send_message', args: { to: 'bob', body: 'meeting?' } },
      { tool: 'filesystem_read', args: { path: '/home/readme.md' } },
      { tool: 'web_search', args: { query: 'RFC 8785' } },
      { tool: 'shell_execute', args: { cmd: 'ls' } },
      { tool: 'shell_execute', args: { cmd: 'cat /etc/passwd' } },
      { tool: 'shell_execute', args: { cmd: 'rm -rf /' } },
      { tool: 'database_query', args: { sql: 'SELECT 1' } },
      { tool: 'deploy_production', args: {} },
      { tool: 'filesystem_read', args: { path: '/home/logs/app.log' } },
      { tool: 'web_search', args: { query: 'OpenClaw agent' } },
      { tool: 'send_message', args: { to: 'charlie', body: 'done' } },
      { tool: 'filesystem_read', args: { path: '/home/src/index.ts' } },
      { tool: 'web_search', args: { query: 'Merkle tree proof' } },
    ];

    let permitted = 0, denied = 0;
    for (let i = 0; i < calls.length; i++) {
      const resp = await sendToolCall(TEST_PORT, i + 100, calls[i].tool, calls[i].args);
      if (resp.result) permitted++;
      if (resp.error) denied++;
    }

    expect(permitted).toBe(15);
    expect(denied).toBe(5);
  });

  it('exports bundle with all 20 receipts', () => {
    const bundle = proxy.exportBundle();
    expect(bundle.receipts.length).toBe(20);
    expect(bundle.merkle_proofs.length).toBe(20);
    expect(bundle.algorithm).toBe('Ed25519-SHA256-JCS');
    expect(bundle.merkle_root).toBeDefined();
    expect(bundle.public_key).toBeDefined();
  });

  it('all 5 verification steps pass', async () => {
    const bundle = proxy.exportBundle();
    const result = await verifyGatewayBundle(JSON.stringify(bundle));

    console.log('\n=== Verification Result ===');
    console.log(JSON.stringify(result, null, 2));

    expect(result.algorithm_valid).toBe(true);
    expect(result.receipt_signatures_valid).toBe(true);
    expect(result.chain_integrity_valid).toBe(true);
    expect(result.merkle_proofs_valid).toBe(true);
    expect(result.bundle_consistent).toBe(true);
    expect(result.overall_valid).toBe(true);
    expect(result.receipts_checked).toBe(20);
    expect(result.error).toBeUndefined();
  });

  it('receipt chain has correct linkage', () => {
    const receipts = proxy.getReceipts();
    expect(receipts[0].previous_receipt_hash).toBe('');
    for (let i = 1; i < receipts.length; i++) {
      expect(receipts[i].previous_receipt_hash).not.toBe('');
      expect(receipts[i].previous_receipt_hash.length).toBe(64);
    }
  });

  it('every receipt has consistent fields', () => {
    const receipts = proxy.getReceipts();
    const pubKey = proxy.getPublicKey();
    for (const r of receipts) {
      expect(r.algorithm).toBe('Ed25519-SHA256-JCS');
      expect(r.receipt_version).toBe('1.0');
      expect(r.method).toBe('tools/call');
      expect(r.public_key).toBe(pubKey);
      expect(r.signature.length).toBe(128); // 64 bytes hex
      expect(['PERMITTED', 'DENIED']).toContain(r.decision);
    }
  });
});
