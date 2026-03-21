/**
 * Lifecycle integration tests - 3 tests.
 * Full end-to-end flows using tool handlers.
 */
import { describe, it, expect } from 'vitest';
import { createContext } from '../../src/context.js';
import { handleCreateArtifact } from '../../src/tools/create-artifact.js';
import { handleMeasureSubject } from '../../src/tools/measure-subject.js';
import { handleRevokeArtifact } from '../../src/tools/revoke-artifact.js';
import { handleGetChain } from '../../src/tools/get-chain.js';

function parse(result: { content: Array<{ type: string; text: string }> }) {
  return JSON.parse(result.content[0].text);
}

describe('lifecycle integration - 3 tests', () => {
  it('attest → measure → match → clean receipt', async () => {
    const ctx = await createContext();
    const a = parse(await handleCreateArtifact({ subject_content: 'code', subject_metadata: { filename: 'f.py' } }, ctx));
    expect(a.success).toBe(true);
    const m = parse(await handleMeasureSubject({ subject_content: 'code', subject_metadata: { filename: 'f.py' } }, ctx));
    expect(m.match).toBe(true);
    expect(m.receipt_id).toBeTruthy();
  });

  it('attest → drift → quarantine → revoke → terminated', async () => {
    const ctx = await createContext();
    const a = parse(await handleCreateArtifact({ subject_content: 'code', subject_metadata: { filename: 'f.py' } }, ctx));
    // Drift
    const m = parse(await handleMeasureSubject({ subject_content: 'modified', subject_metadata: { filename: 'f.py' } }, ctx));
    expect(m.drift_detected).toBe(true);
    // Revoke
    const r = parse(await handleRevokeArtifact({ sealed_hash: a.sealed_hash, reason: 'test' }, ctx));
    expect(r.success).toBe(true);
    expect(r.portal_state).toBe('TERMINATED');
  });

  it('chain contains all lifecycle events', async () => {
    const ctx = await createContext();
    await handleCreateArtifact({ subject_content: 'code', subject_metadata: { filename: 'f.py' } }, ctx);
    await handleMeasureSubject({ subject_content: 'code', subject_metadata: { filename: 'f.py' } }, ctx);
    const chain = parse(await handleGetChain({ verify: true }, ctx));
    expect(chain.count).toBeGreaterThanOrEqual(3); // genesis + policy_issuance + receipt
    expect(chain.chain_valid).toBe(true);
  });
});
