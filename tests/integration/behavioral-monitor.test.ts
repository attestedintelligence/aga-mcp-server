/**
 * CP2: behavioral monitor is detective-only by default; drift detection is provable (signed SEP
 * receipt); enforcement (drift -> quarantine) is opt-in via enforce=true and off by default.
 */
import { describe, it, expect } from 'vitest';
import { createAGAServer } from '../../src/server.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { verifyEvidenceBundle } from '../../independent-verifier/verify.js';

async function connect() {
  const server = await createAGAServer();
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: 'test', version: '1.0.0' }, { capabilities: {} });
  await client.connect(ct);
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = await client.callTool({ name, arguments: args });
    return JSON.parse((r as { content: Array<{ text: string }> }).content[0].text);
  };
  return { server, client, call };
}

describe('CP2: detective-only behavioral monitor', () => {
  it('detects drift provably (detective by default), enforces only when opted in, and the bundle verifies', async () => {
    const { server, client, call } = await connect();
    const meta = { filename: 'subject.txt' };

    // Baseline permits only a tool the agent will not call -> any governed call is "unauthorized".
    await call('attest_subject', {
      subject_content: 'hello', subject_metadata: meta,
      behavioral_baseline: { permitted_tools: ['read_sensors'], rate_limits: {}, forbidden_sequences: [], window_ms: 600000 },
    });

    await call('measure_integrity', { subject_content: 'hello', subject_metadata: meta }); // records 'measure_integrity' (unauthorized)

    // Detective-only (default): drift detected, NOT enforced.
    const det = await call('measure_behavior');
    expect(det.drift_detected).toBe(true);
    expect(det.mode).toBe('detective-only');
    expect(det.enforced).toBe(false);

    // Opt-in enforcement: drift -> quarantine.
    const enf = await call('measure_behavior', { enforce: true });
    expect(enf.enforced).toBe(true);

    // Now a governed call is blocked by quarantine.
    const blocked = await call('measure_integrity', { subject_content: 'hello', subject_metadata: meta });
    expect(String(blocked.error)).toContain('GOVERNANCE_QUARANTINED');

    // The drift findings are provable in the signed bundle.
    const info = await call('get_server_info');
    const bundle = await call('generate_evidence_bundle');
    const res = verifyEvidenceBundle(JSON.stringify(bundle), info.gateway_public_key);
    expect(res.verdict).toBe('VERIFIED');
    expect(res.issuerVerified).toBe(true);

    const reasons = bundle.receipts.map((r: { reason: string }) => r.reason);
    expect(reasons.some((x: string) => x.includes('BEHAVIORAL_DRIFT_DETECTED') && x.includes('detective-only'))).toBe(true);
    expect(reasons.some((x: string) => x.includes('BEHAVIORAL_DRIFT_DETECTED') && x.includes('ENFORCED'))).toBe(true);

    await client.close();
    await server.close();
  });
});
