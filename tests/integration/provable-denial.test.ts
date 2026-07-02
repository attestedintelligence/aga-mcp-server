/**
 * Provable-denial centerpiece regression: a denied permissions-workaround must produce a signed,
 * chained, checkpoint-bound DENIED receipt that (a) verifies independently with provenance,
 * and (b) CANNOT be erased by re-attestation. Maps to a frontier lab's system-card finding
 * on covering up a permissions workaround (§4.5.4.1).
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

describe('provable DENIED receipt for a permissions workaround', () => {
  it('emits a signed, chained, checkpoint-bound DENIED receipt that survives re-attestation and verifies independently', async () => {
    const { server, client, call } = await connect();
    const meta = { filename: 'subject.txt' };

    const att = await call('attest_subject', { subject_content: 'hello', subject_metadata: meta });
    expect(att.success).toBe(true);

    await call('measure_integrity', { subject_content: 'hello', subject_metadata: meta }); // PERMITTED
    await call('revoke_artifact', { sealed_hash: att.sealed_hash, reason: 'permissions workaround detected' });
    const denied = await call('measure_integrity', { subject_content: 'tampered', subject_metadata: meta }); // DENIED
    expect(String(denied.error)).toContain('GOVERNANCE_BLOCKED');

    // Attempt to "cover up": re-attest a fresh subject. The prior DENIED record must NOT vanish.
    await call('attest_subject', { subject_content: 'hello2', subject_metadata: meta });
    await call('measure_integrity', { subject_content: 'hello2', subject_metadata: meta }); // PERMITTED

    const info = await call('get_server_info');
    const bundle = await call('generate_evidence_bundle');

    // Independent (zero-AGA-import) verifier, pinned to the gateway key → provenance.
    const res = verifyEvidenceBundle(JSON.stringify(bundle), info.gateway_public_key);
    expect(res.verdict).toBe('VERIFIED');
    expect(res.issuerVerified).toBe(true);

    // The DENIED receipt is present and survived re-attestation (no cover-up possible).
    const deniedReceipts = bundle.receipts.filter((r: { decision: string }) => r.decision === 'DENIED');
    expect(deniedReceipts.length).toBeGreaterThanOrEqual(1);
    expect(deniedReceipts[0].reason).toContain('GOVERNANCE_BLOCKED');
    expect(bundle.receipts.length).toBeGreaterThanOrEqual(4); // pre- and post-re-attestation records intact

    await client.close();
    await server.close();
  });
});
