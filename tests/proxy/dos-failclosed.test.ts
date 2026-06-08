/**
 * Phase 10 / FIX-2 regression — the DoS-driven silent-erasure the final re-audit reproduced.
 * A tools/call with deeply-nested arguments must NOT crash record() and silently drop the
 * governed decision. It must fail closed: a DENIED response + a DENIED receipt in the bundle,
 * and the tool is never forwarded. The bundle must still verify.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as net from 'node:net';
import { GovernanceProxy } from '../../src/proxy/server.js';
import { verifySepBundle } from '../../src/sep/index.js';

const TEST_PORT = 19950 + Math.floor(Math.random() * 40);
let proxy: GovernanceProxy;

function deepArgs(depth: number): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  let cur = root;
  for (let i = 0; i < depth; i++) { const next: Record<string, unknown> = {}; cur.x = next; cur = next; }
  return root;
}

function sendToolCall(port: number, id: number, toolName: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ port }, () => {
      socket.write(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: toolName, arguments: args } }) + '\n');
    });
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      for (const line of buffer.split('\n')) {
        const t = line.trim();
        if (!t) continue;
        try { const p = JSON.parse(t); socket.destroy(); resolve(p); return; } catch { /* wait */ }
      }
    });
    socket.on('error', reject);
    setTimeout(() => { socket.destroy(); reject(new Error('TIMEOUT — proxy gave no response (silent drop?)')); }, 5000);
  });
}

beforeAll(async () => { proxy = new GovernanceProxy({ port: TEST_PORT }); await proxy.start(); });
afterAll(async () => { await proxy.stop(); });

describe('DoS fail-closed (no silent erasure of a governed decision)', () => {
  it('deeply-nested arguments yield a DENIED response, not a timeout/silent drop', async () => {
    const resp = await sendToolCall(TEST_PORT, 1, 'web_search', deepArgs(500));
    expect(resp.error).toBeDefined();
    expect((resp.error as { code: number }).code).toBe(-32600);
  });

  it('records the denied decision (not erased) and the bundle still verifies', async () => {
    await sendToolCall(TEST_PORT, 2, 'web_search', { query: 'ok' }); // a normal call after the bomb
    const bundle = proxy.exportBundle();
    const denied = bundle.receipts.filter((r) => r.decision === 'DENIED');
    expect(denied.length).toBeGreaterThanOrEqual(1); // the depth-bomb decision survives as a receipt
    const res = verifySepBundle(bundle, proxy.getPublicKey());
    expect(res.verdict).toBe('VERIFIED');
    expect(res.issuerVerified).toBe(true);
  });
});
