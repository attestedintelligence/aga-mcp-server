import { describe, it, expect } from 'vitest';
import { Portal } from '../../src/core/portal.js';
import { createGovernanceWrapper } from '../../src/middleware/governance.js';
import { initQuarantine } from '../../src/core/quarantine.js';

describe('governance middleware', () => {
  const j = (x: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(x) }] });
  const okHandler = async () => j({ success: true, data: 'allowed' });

  it('blocks governed tool when TERMINATED', async () => {
    const portal = new Portal();
    portal.state = 'TERMINATED';
    const wrap = createGovernanceWrapper(portal, { current: null }, 'measure_integrity');
    const result = await wrap(okHandler)({});
    const body = JSON.parse(result.content[0].text);
    expect(body.success).toBe(false);
    expect(body.error).toContain('GOVERNANCE_BLOCKED');
  });

  it('allows ungoverned tool when TERMINATED', async () => {
    const portal = new Portal();
    portal.state = 'TERMINATED';
    const wrap = createGovernanceWrapper(portal, { current: null }, 'get_server_info');
    const result = await wrap(okHandler)({});
    const body = JSON.parse(result.content[0].text);
    expect(body.success).toBe(true);
  });

  it('captures tool call as forensic input during QUARANTINE', async () => {
    const portal = new Portal();
    portal.state = 'PHANTOM_QUARANTINE';
    const q = initQuarantine();
    const wrap = createGovernanceWrapper(portal, { current: q }, 'measure_integrity');
    const result = await wrap(okHandler)({ some: 'args' });
    const body = JSON.parse(result.content[0].text);
    expect(body.success).toBe(false);
    expect(body.forensic_capture).toBe(true);
    expect(q.inputs_captured).toBe(1);
    expect(q.forensic_buffer[0].type).toBe('tool_call:measure_integrity');
  });

  it('blocks governed tool before attestation', async () => {
    const portal = new Portal(); // state = INITIALIZATION
    const wrap = createGovernanceWrapper(portal, { current: null }, 'create_checkpoint');
    const result = await wrap(okHandler)({});
    const body = JSON.parse(result.content[0].text);
    expect(body.error).toContain('GOVERNANCE_NOT_READY');
  });

  it('allows governed tool during ACTIVE_MONITORING', async () => {
    const portal = new Portal();
    portal.state = 'ACTIVE_MONITORING';
    const wrap = createGovernanceWrapper(portal, { current: null }, 'measure_integrity');
    const result = await wrap(okHandler)({});
    const body = JSON.parse(result.content[0].text);
    expect(body.success).toBe(true);
  });
});
