/**
 * Export an evidence bundle from the proxy.
 * Generates 20 tool calls, exports to proxy-evidence-bundle.json.
 */
import * as net from 'node:net';
import * as fs from 'node:fs';
import { GovernanceProxy } from '../src/proxy/server.js';
import { verifyGatewayBundle } from '../src/proxy/verify.js';
import type { ToolPolicy } from '../src/proxy/types.js';

const PORT = 19700;

const policy: ToolPolicy = {
  mode: 'allowlist',
  constraints: {
    filesystem_read: { name: 'filesystem_read', allowed: true, max_calls_per_minute: 100 },
    web_search: { name: 'web_search', allowed: true, max_calls_per_minute: 100 },
    shell_execute: { name: 'shell_execute', allowed: false },
    send_message: { name: 'send_message', allowed: true, max_calls_per_minute: 100 },
  },
};

async function sendToolCall(port: number, id: number, toolName: string, args: Record<string, unknown>): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ port }, () => {
      socket.write(JSON.stringify({
        jsonrpc: '2.0', id, method: 'tools/call',
        params: { name: toolName, arguments: args },
      }) + '\n');
    });
    let buf = '';
    socket.on('data', (chunk) => {
      buf += chunk.toString();
      if (buf.includes('\n')) { socket.destroy(); resolve(); }
    });
    socket.on('error', reject);
    setTimeout(() => { socket.destroy(); resolve(); }, 2000);
  });
}

async function main() {
  const proxy = new GovernanceProxy({ port: PORT, policy });
  await proxy.start();
  console.log('Proxy started, sending 20 tool calls...');

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

  for (let i = 0; i < calls.length; i++) {
    await sendToolCall(PORT, i + 1, calls[i].tool, calls[i].args);
  }

  console.log(`Status: ${JSON.stringify(proxy.getStatus(), null, 2)}`);

  const bundle = proxy.exportBundle();
  const outPath = 'proxy-evidence-bundle.json';
  fs.writeFileSync(outPath, JSON.stringify(bundle, null, 2));
  console.log(`\nBundle exported to ${outPath} (${bundle.receipts.length} receipts)`);

  // Self-verify
  const result = await verifyGatewayBundle(JSON.stringify(bundle));
  console.log(`Self-verify: ${result.overall_valid ? 'PASS' : 'FAIL'}`);

  await proxy.stop();
  process.exit(result.overall_valid ? 0 : 1);
}

main().catch(e => { console.error(e); process.exit(1); });
