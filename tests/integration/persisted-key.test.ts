/**
 * P3: a persisted gateway key (AGA_GATEWAY_KEY) makes provenance pinnable + stable across restarts;
 * the verifier result carries a prominent summary distinguishing provenance-verified vs integrity-only.
 */
import { describe, it, expect } from 'vitest';
import { createAGAServer } from '../../src/server.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { signerFromSeed, seedFromHex } from '../../src/sep/index.js';

const SEED = 'ab'.repeat(32);
const PUB = signerFromSeed(seedFromHex(SEED)).publicKeyHex;

async function connectWith(env: Record<string, string | undefined>) {
  const saved: Record<string, string | undefined> = {};
  for (const k of Object.keys(env)) { saved[k] = process.env[k]; if (env[k] === undefined) delete process.env[k]; else process.env[k] = env[k]; }
  const server = await createAGAServer();
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: 'test', version: '1.0.0' }, { capabilities: {} });
  await client.connect(ct);
  const call = async (n: string, a: Record<string, unknown> = {}) => JSON.parse((await client.callTool({ name: n, arguments: a }) as { content: Array<{ text: string }> }).content[0].text);
  const cleanup = async () => {
    await client.close(); await server.close();
    for (const k of Object.keys(saved)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  };
  return { call, cleanup };
}

describe('P3: persisted gateway key + verifier UX', () => {
  it('loads a persisted key from AGA_GATEWAY_KEY so gateway_public_key is stable + pinnable', async () => {
    const { call, cleanup } = await connectWith({ AGA_GATEWAY_KEY: SEED });
    const info = await call('get_server_info');
    expect(info.gateway_public_key).toBe(PUB);
    await cleanup();
  });

  it('verifier UX: pinned => provenance verified; unpinned => integrity-only (with a clear summary)', async () => {
    const { call, cleanup } = await connectWith({ AGA_GATEWAY_KEY: SEED });
    const meta = { filename: 'f' };
    await call('attest_subject', { subject_content: 'x', subject_metadata: meta });
    await call('measure_integrity', { subject_content: 'x', subject_metadata: meta });
    const bundle = await call('generate_evidence_bundle');

    const pinned = await call('verify_bundle_offline', { bundle, pinned_public_key: PUB });
    expect(pinned.verdict).toBe('VERIFIED');
    expect(pinned.issuerVerified).toBe(true);
    expect(pinned.summary).toContain('provenance verified');

    const unpinned = await call('verify_bundle_offline', { bundle });
    expect(unpinned.verdict).toBe('VERIFIED');
    expect(unpinned.issuerVerified).toBe(false);
    expect(unpinned.summary).toContain('integrity only');

    await cleanup();
  });
});
