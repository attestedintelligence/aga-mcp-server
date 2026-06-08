/**
 * Phase 5 — governance partition tripwire (M-5/M-6).
 *
 * The full tool registry with its intended governance. Adding a tool? Update this map AND
 * register it correctly: governedTool(...) for a side-effecting agent action (emits a signed
 * PERMITTED/DENIED receipt), server.tool(...) otherwise. If UNGOVERNED_TOOLS drifts from this
 * map, the test fails — making any change to the governance boundary a conscious one.
 */
import { describe, it, expect } from 'vitest';
import { UNGOVERNED_TOOLS } from '../../src/middleware/governance.js';

const REGISTRY: Record<string, 'governed' | 'ungoverned'> = {
  // read-only
  get_server_info: 'ungoverned',
  get_portal_state: 'ungoverned',
  get_receipts: 'ungoverned',
  get_chain_events: 'ungoverned',
  list_claims: 'ungoverned',
  verify_chain: 'ungoverned',
  // bootstrap (establish the governance relationship; re-attest does not reset the ledger)
  init_chain: 'ungoverned',
  attest_subject: 'ungoverned',
  // evidence operations (must work even after TERMINATION)
  generate_evidence_bundle: 'ungoverned',
  verify_bundle_offline: 'ungoverned',
  // detective monitor (self-records its own findings/enforcement)
  measure_behavior: 'ungoverned',
  // governed: side-effecting agent actions
  measure_integrity: 'governed',
  revoke_artifact: 'governed',
  request_claim: 'governed',
  delegate_to_subagent: 'governed',
};

describe('governance partition', () => {
  it('UNGOVERNED_TOOLS exactly matches the ungoverned tools in the registry', () => {
    const expected = Object.entries(REGISTRY).filter(([, g]) => g === 'ungoverned').map(([n]) => n).sort();
    expect([...UNGOVERNED_TOOLS].sort()).toEqual(expected);
  });

  it('no governed (mutating) tool is in the ungoverned set', () => {
    const governed = Object.entries(REGISTRY).filter(([, g]) => g === 'governed').map(([n]) => n);
    expect(governed.sort()).toEqual(['delegate_to_subagent', 'measure_integrity', 'request_claim', 'revoke_artifact']);
    for (const g of governed) expect(UNGOVERNED_TOOLS.has(g)).toBe(false);
  });
});
