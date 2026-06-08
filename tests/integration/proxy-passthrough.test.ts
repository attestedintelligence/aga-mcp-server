/**
 * P2: non-tools/call methods forwarded through the proxy get a signed PASSTHROUGH receipt for
 * auditability (visibility, not governance); benign protocol methods are excluded; an optional
 * denylist rejects known side-effecting methods. The exported bundle still verifies.
 */
import { describe, it, expect } from 'vitest';
import * as net from 'node:net';
import { GovernanceProxy } from '../../src/proxy/server.js';
import { verifySepBundle } from '../../src/sep/index.js';

function sendRpc(port: number, msg: unknown): Promise<any> {
  return new Promise((resolve) => {
    const sock = net.connect(port, '127.0.0.1', () => sock.write(JSON.stringify(msg) + '\n'));
    let buf = '';
    sock.on('data', (d) => { buf += d.toString(); const i = buf.indexOf('\n'); if (i >= 0) { sock.end(); resolve(JSON.parse(buf.slice(0, i))); } });
    sock.on('error', () => resolve(null));
    setTimeout(() => { try { sock.end(); } catch { /* noop */ } resolve(null); }, 1500);
  });
}

describe('P2: proxy passthrough receipts for non-tools/call methods', () => {
  it('excludes benign methods, records side-effecting passthroughs, denylists, and still verifies', async () => {
    const port = 18931;
    const proxy = new GovernanceProxy({ port, gatewayId: 'aga-proxy', denyMethods: ['admin/deleteAll'] });
    await proxy.start();
    try {
      // 1. benign protocol method -> NO receipt
      await sendRpc(port, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
      expect(proxy.getReceipts().length).toBe(0);

      // 2. side-effecting non-tools/call method -> signed PASSTHROUGH receipt (PERMITTED, still forwarded)
      await sendRpc(port, { jsonrpc: '2.0', id: 2, method: 'resources/read', params: { uri: 'file:///x' } });
      let rs = proxy.getReceipts();
      expect(rs.length).toBe(1);
      expect(rs[0].method).toBe('resources/read');
      expect(rs[0].decision).toBe('PERMITTED');
      expect(rs[0].tool_name).toBe('(passthrough)');
      expect(rs[0].reason).toContain('not policy-evaluated');

      // 3. denylisted method -> DENIED passthrough receipt + error, not forwarded
      const denied = await sendRpc(port, { jsonrpc: '2.0', id: 3, method: 'admin/deleteAll', params: {} });
      expect(denied.error?.data?.decision).toBe('DENIED');
      rs = proxy.getReceipts();
      expect(rs.length).toBe(2);
      expect(rs[1].method).toBe('admin/deleteAll');
      expect(rs[1].decision).toBe('DENIED');

      // 4. a normal tools/call still gets its governed receipt
      await sendRpc(port, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'read_file', arguments: { path: '/x' } } });
      rs = proxy.getReceipts();
      expect(rs.length).toBe(3);
      expect(rs[2].method).toBe('tools/call');

      // 5. the exported bundle (with passthrough receipts in the chain) still verifies with provenance
      const bundle = proxy.exportBundle();
      const res = verifySepBundle(bundle, proxy.getPublicKey());
      expect(res.verdict).toBe('VERIFIED');
      expect(res.issuerVerified).toBe(true);
    } finally {
      await proxy.stop();
    }
  });
});
