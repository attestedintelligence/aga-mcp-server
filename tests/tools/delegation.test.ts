/**
 * Delegation tool tests - 4 tests.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { createContext, type ServerContext } from '../../src/context.js';
import { handleCreateArtifact } from '../../src/tools/create-artifact.js';
import { handleDelegateSubagent } from '../../src/tools/delegate-subagent.js';

function parse(result: { content: Array<{ type: string; text: string }> }) {
  return JSON.parse(result.content[0].text);
}

describe('delegation tool - 4 tests', () => {
  let ctx: ServerContext;
  beforeEach(async () => {
    ctx = await createContext();
    await handleCreateArtifact({ subject_content: 'code', subject_metadata: { filename: 'f.py' } }, ctx);
  });

  it('derives constrained child artifact', async () => {
    const r = parse(await handleDelegateSubagent({
      enforcement_triggers: ['QUARANTINE'],
      measurement_types: ['FILE_SYSTEM_STATE'],
      requested_ttl_seconds: 1800,
      delegation_purpose: 'test delegation',
    }, ctx));
    expect(r.success).toBe(true);
    expect(r.child_artifact).toBeTruthy();
    expect(r.effective_ttl_seconds).toBeLessThanOrEqual(1800);
  });

  it('rejects scope expansion (invalid trigger)', async () => {
    const r = parse(await handleDelegateSubagent({
      enforcement_triggers: ['KEY_REVOKE'],
      measurement_types: ['FILE_SYSTEM_STATE'],
      requested_ttl_seconds: 100,
      delegation_purpose: 'test',
    }, ctx));
    expect(r.success).toBe(false);
    expect(r.error).toContain('Cannot expand scope');
  });

  it('clamps TTL to parent remaining', async () => {
    const r = parse(await handleDelegateSubagent({
      enforcement_triggers: ['QUARANTINE'],
      measurement_types: ['FILE_SYSTEM_STATE'],
      requested_ttl_seconds: 999999,
      delegation_purpose: 'test',
    }, ctx));
    expect(r.success).toBe(true);
    expect(r.effective_ttl_seconds).toBeLessThan(999999);
  });

  it('records delegation in chain', async () => {
    await handleDelegateSubagent({
      enforcement_triggers: ['QUARANTINE'],
      measurement_types: ['FILE_SYSTEM_STATE'],
      requested_ttl_seconds: 1800,
      delegation_purpose: 'test',
    }, ctx);
    const events = await ctx.storage.getAllEvents();
    const delegations = events.filter(e => e.event_type === 'DELEGATION');
    expect(delegations.length).toBeGreaterThan(0);
  });
});
