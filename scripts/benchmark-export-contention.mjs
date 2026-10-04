// Synthetic observations only. Run inside the existing bounded, network-none container.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { performance, monitorEventLoopDelay } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import { GovernanceProxy } from '../dist/proxy/server.js';
import { ProxyControlServer } from '../dist/proxy/control.js';
import { verifySepBundle } from '../dist/sep/index.js';

assert.equal(process.env.AGA_DISPOSABLE_CHECK, '1', 'Disposable qualification container required');
const mode = process.argv[2];
const send = data => process.send?.(data);
const shutdown = () => { process.disconnect?.(); };
if (mode === 'upstream') {
  let count = 0;
  const ids = new Set();
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) { body += chunk; assert(body.length < 8192); }
    const rpc = JSON.parse(body);
    count++; ids.add(rpc.id);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: { observed: count } }));
  });
  server.listen(0, '127.0.0.1', () => send({ ready: server.address().port }));
  process.on('message', message => {
    if (message === 'snapshot') send({ count, unique: ids.size });
    if (message === 'stop') { server.closeAllConnections(); server.close(shutdown); }
  });
} else if (mode === 'calls') {
  const [port, count, startId, pause] = process.argv.slice(3).map(Number);
  const socket = net.createConnection({ host: '127.0.0.1', port });
  socket.setTimeout(10000, () => socket.destroy(new Error('synthetic client deadline')));
  let pending = '', index = 0, started = 0;
  const latencies = [], failures = [];
  const write = () => {
    started = performance.now();
    socket.write(JSON.stringify({ jsonrpc: '2.0', id: startId + index, method: 'tools/call', params: { name: 'synthetic_read', arguments: { marker: index } } }) + '\n');
  };
  socket.on('connect', () => { send({ ready: true }); write(); });
  socket.on('error', error => { send({ error: String(error) }); process.exitCode = 1; shutdown(); });
  socket.on('data', chunk => {
    pending += chunk.toString();
    if (!pending.includes('\n')) return;
    const line = pending.slice(0, pending.indexOf('\n')); pending = pending.slice(pending.indexOf('\n') + 1);
    const rpc = JSON.parse(line);
    latencies.push(performance.now() - started);
    if (rpc.error || rpc.id !== startId + index) failures.push({ index, rpc });
    if (++index === count) { socket.end(); send({ done: true, latencies, failures, completed: index }); shutdown(); }
    else if (pause) setTimeout(write, pause); else write();
  });
} else if (mode === 'export') {
  const [port, expectedKey] = process.argv.slice(3);
  const start = performance.now();
  const response = await fetch(`http://127.0.0.1:${port}/export`, { signal: AbortSignal.timeout(15000) });
  assert.equal(response.status, 200);
  const bytes = new Uint8Array(await response.arrayBuffer());
  const received = performance.now();
  assert(bytes.length <= 32 * 1024 * 1024);
  const bundle = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  const verification = verifySepBundle(bundle, expectedKey);
  assert.equal(verification.verdict, 'VERIFIED'); assert.equal(verification.issuerVerified, true);
  send({ done: true, elapsedMs: received - start, bytes: bytes.length, receipts: bundle.receipts.length, sha256: createHash('sha256').update(bytes).digest('hex'), verified: true });
  shutdown();
} else {
  const children = new Set();
  function child(mode, args = []) {
    const cp = fork(fileURLToPath(import.meta.url), [mode, ...args.map(String)], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
    children.add(cp); cp.once('exit', () => children.delete(cp));
    return cp;
  }
  function message(cp, predicate) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => finish(new Error('observer deadline')), 20000);
      const receive = value => { if (value.error) finish(new Error(value.error)); else if (predicate(value)) finish(undefined, value); };
      const exit = code => finish(new Error(`observer exited before result: ${code}`));
      const finish = (error, value) => { clearTimeout(timer); cp.off('message', receive); cp.off('exit', exit); error ? reject(error) : resolve(value); };
      cp.on('message', receive); cp.on('exit', exit);
    });
  }
  const summarize = values => { const sorted = [...values].sort((a, b) => a - b); return { count: values.length, median: sorted[Math.floor(sorted.length / 2)], p95: sorted[Math.ceil(sorted.length * .95) - 1], max: sorted.at(-1) }; };
  const rows = [];
  try {
    for (const receipts of [128, 512, 2048]) {
      for (let repeat = 0; repeat < 3; repeat++) {
        const upstream = child('upstream');
        const { ready: upstreamPort } = await message(upstream, x => x.ready);
        const proxy = new GovernanceProxy({ port: 0, ephemeral: true, upstreamUrl: `http://127.0.0.1:${upstreamPort}`, policy: { mode: 'allowlist', constraints: { synthetic_read: { name: 'synthetic_read', allowed: true, max_calls_per_minute: 100000 } } } });
        let assemblyMs = 0, peakObservedRss = 0;
        const control = new ProxyControlServer({ exportBundle: () => {
          const start = performance.now(), bundle = proxy.exportBundle();
          assemblyMs = performance.now() - start;
          peakObservedRss = Math.max(peakObservedRss, process.memoryUsage().rss);
          return bundle;
        }, getStatus: () => proxy.getStatus(), getReceipts: () => proxy.getReceipts() });
        try {
          await proxy.start(); const port = proxy.getStatus().port;
          const { port: controlPort } = await control.start(0);
          const warm = await message(child('calls', [port, receipts, 0, 0]), x => x.done);
          assert.equal(warm.failures.length, 0);
          const baseline = await message(child('calls', [port, 40, receipts, 2]), x => x.done);
          assert.equal(baseline.failures.length, 0);
          const loop = monitorEventLoopDelay({ resolution: 1 }); loop.enable();
          const calls = child('calls', [port, 80, receipts + 40, 2]);
          const callsDone = message(calls, x => x.done);
          await message(calls, x => x.ready);
          const exporter = child('export', [controlPort, proxy.getPublicKey()]);
          const [concurrent, exported] = await Promise.all([callsDone, message(exporter, x => x.done)]);
          loop.disable();
          const observed = message(upstream, x => Number.isInteger(x.count)); upstream.send('snapshot');
          const upstreamResult = await observed;
          assert.equal(concurrent.failures.length, 0);
          assert.equal(upstreamResult.count, receipts + 120); assert.equal(upstreamResult.unique, receipts + 120);
          assert.equal(proxy.getReceipts().length, receipts + 120);
          rows.push({ initialReceipts: receipts, repeat, baselineCallMs: summarize(baseline.latencies), concurrentCallMs: summarize(concurrent.latencies), allBaselineCallMs: baseline.latencies, allConcurrentCallMs: concurrent.latencies, export: exported, assemblyMs, eventLoopDelayMs: { max: loop.max / 1e6, mean: loop.mean / 1e6 }, observedRssBytes: Math.max(peakObservedRss, process.memoryUsage().rss), upstream: upstreamResult, timedOutCalls: 0 });
        } finally { await control.stop(); await proxy.stop(); upstream.send('stop'); }
      }
    }
    fs.writeFileSync('/evidence/export-contention.json', JSON.stringify({ checkedAt: new Date().toISOString(), source: process.env.QUALIFIED_COMMIT ?? null, node: process.version, platform: process.platform, cpu: os.cpus()[0]?.model, rows, passed: true, scope: 'Classical profile, synthetic loopback HTTP upstream and separate client/observer processes. Three observations per size in the constrained container. Measures assembly, complete HTTP export and call contention. RSS is sampled, not peak allocation. No denial/bypass/authentication/durability or production throughput claim. No saturation or hybrid profile qualification.' }, null, 2));
    console.log('PASS: full exports verify and independent upstream observations match all completed synthetic calls');
  } finally { for (const cp of children) cp.kill('SIGTERM'); }
}
