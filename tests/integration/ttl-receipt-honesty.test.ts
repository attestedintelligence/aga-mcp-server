/**
 * TTL RECEIPT HONESTY — regression guard.
 *
 * The defect this locks out: on TTL expiry, `measure_integrity` sealed
 * `enforcement_action: 'TERMINATE'` into a signed receipt and described itself as
 * "TTL expired - fail-closed termination". No termination occurred.
 *
 *   - core/portal.ts `measure()` degrades the portal to SAFE_STATE on TTL expiry
 *     ("Graceful degradation") and keeps accepting measurements.
 *   - `portal.enforce()` is never called on that branch, and CANNOT be: it throws
 *     unless state is DRIFT_DETECTED.
 *   - The `measure_integrity` entry guard rejects only TERMINATED, so post-expiry
 *     calls keep succeeding and kept minting fresh receipts, each asserting a
 *     termination that never happened.
 *
 * A signed receipt asserting an enforcement that did not occur is precisely the failure
 * this product exists to prevent, which is why this is an integration test against the
 * REAL server (createAGAServer + MCP client), not a re-implementation of the branch.
 *
 * NOTE ON SCOPE: these tests pin the receipt to the TRUTH, not to a desired behavior.
 * Whether TTL expiry SHOULD hard-terminate and force re-attestation is an open product
 * decision. If that is later ruled YES, the correct change is to make the portal really
 * terminate — and then `expects a non-TERMINATE seal` below must be revisited deliberately,
 * not deleted to make a build green.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { createAGAServer } from '../../src/server.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

// Fake ONLY Date. The MCP in-memory transport is async and needs real timers to settle.
const useFakeClock = () => vi.useFakeTimers({ toFake: ['Date'] });

async function connect() {
  const server = await createAGAServer();
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: 'ttl-test', version: '1.0.0' }, { capabilities: {} });
  await client.connect(ct);
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const r = await client.callTool({ name, arguments: args });
    return JSON.parse((r as { content: Array<{ text: string }> }).content[0].text);
  };
  return { call };
}

/** Default artifact TTL is 3600s (server.ts DEFAULT_ENFORCEMENT); jump well past it. */
const PAST_TTL_MS = 3601 * 1000;

describe('TTL expiry receipt honesty', () => {
  afterEach(() => { vi.useRealTimers(); });

  it('does NOT seal enforcement_action TERMINATE when nothing was terminated', async () => {
    const { call } = await connect();
    const meta = { filename: 'subject.txt' };

    const att = await call('attest_subject', { subject_content: 'hello', subject_metadata: meta });
    expect(att.success).toBe(true);

    useFakeClock();
    vi.setSystemTime(new Date(Date.now() + PAST_TTL_MS));

    const expired = await call('measure_integrity', { subject_content: 'hello', subject_metadata: meta });

    // The TTL really did lapse — otherwise this test proves nothing.
    expect(expired.ttl_ok).toBe(false);

    // THE GUARD: the signed receipt must not claim a termination that did not occur.
    expect(expired.enforcement_action).not.toBe('TERMINATE');

    // And the portal must not be reported as terminated, because it isn't.
    expect(expired.portal_state).not.toBe('TERMINATED');
  });

  it('reports the portal state it is actually in after TTL expiry (SAFE_STATE, still serving)', async () => {
    const { call } = await connect();
    const meta = { filename: 'subject.txt' };
    await call('attest_subject', { subject_content: 'hello', subject_metadata: meta });

    useFakeClock();
    vi.setSystemTime(new Date(Date.now() + PAST_TTL_MS));

    const first = await call('measure_integrity', { subject_content: 'hello', subject_metadata: meta });
    expect(first.ttl_ok).toBe(false);
    expect(first.portal_state).toBe('SAFE_STATE');

    // Documents the real fail-OPEN behavior: a second post-expiry call still succeeds.
    // This is pinned deliberately. If TTL is ever made genuinely fail-closed, THIS is the
    // assertion that should go red and force the public claims to be revisited with it.
    const second = await call('measure_integrity', { subject_content: 'hello', subject_metadata: meta });
    expect(second.success).toBe(true);
    expect(second.enforcement_action).not.toBe('TERMINATE');
  });

  it('still seals TERMINATE for revocation, which genuinely does terminate (negative control)', async () => {
    const { call } = await connect();
    const meta = { filename: 'subject.txt' };
    const att = await call('attest_subject', { subject_content: 'hello', subject_metadata: meta });

    await call('revoke_artifact', { sealed_hash: att.sealed_hash, reason: 'control' });
    const revoked = await call('measure_integrity', { subject_content: 'hello', subject_metadata: meta });

    // Proves the honesty fix was surgical: it corrected the hollow TTL branch without
    // weakening the sibling branch where the termination is real.
    const sealedTerminate = revoked.enforcement_action === 'TERMINATE';
    const guardRejected = typeof revoked.error === 'string' && revoked.error.length > 0;
    expect(sealedTerminate || guardRejected).toBe(true);
  });
});
