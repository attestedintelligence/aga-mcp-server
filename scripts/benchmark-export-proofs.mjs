// Run only inside the disposable, credential-free runtime qualification container.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import { performance } from 'node:perf_hooks';
import { merkleProof, merkleProofs } from '../dist/sep/merkle.js';

assert.equal(process.env.AGA_DISPOSABLE_CHECK, '1', 'Disposable qualification container required');
const rows = [];
for (const count of [128, 512, 1024]) {
  const leaves = Array.from({ length: count }, (_, i) => createHash('sha256').update(`synthetic-export-${i}`).digest('hex'));
  const timings = { legacy: [], batch: [] };
  let expected;
  for (let repeat = 0; repeat < 3; repeat++) {
    const legacyStart = performance.now();
    const legacy = leaves.map((_, i) => merkleProof(leaves, i));
    timings.legacy.push(performance.now() - legacyStart);
    const batchStart = performance.now();
    const batch = merkleProofs(leaves);
    timings.batch.push(performance.now() - batchStart);
    assert.deepEqual(batch, legacy);
    expected = batch;
  }
  const median = values => [...values].sort((a, b) => a - b)[1];
  rows.push({ leaves: count, proofs: expected.length, equal: true,
    outputSHA256: createHash('sha256').update(JSON.stringify(expected)).digest('hex'),
    milliseconds: timings, medianLegacyMilliseconds: median(timings.legacy), medianBatchMilliseconds: median(timings.batch) });
}
fs.writeFileSync('/evidence/export-proof-benchmark.json', JSON.stringify({
  checkedAt: new Date().toISOString(), node: process.version, platform: process.platform,
  cpu: os.cpus()[0]?.model, rows, passed: true,
  scope: 'Synthetic proof construction in the bounded qualification container. Equality is a gate; timings are observations, not a throughput promise. Does not measure signing, JSON encoding, proxy contention, transport, arbitrary workloads or independent deployment behavior.',
}, null, 2));
console.log('PASS: batch and legacy proof outputs match at all benchmark sizes');
