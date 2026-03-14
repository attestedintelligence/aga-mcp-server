/**
 * Tool handler tests - 12 tests.
 * Tests individual tool handlers via the ServerContext.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { createContext, type ServerContext } from '../../src/context.js';
import { handleServerInfo } from '../../src/tools/server-info.js';
import { handleInitChain } from '../../src/tools/init-chain.js';
import { handleCreateArtifact } from '../../src/tools/create-artifact.js';
import { handleMeasureSubject } from '../../src/tools/measure-subject.js';
import { handleGetPortalState } from '../../src/tools/get-portal-state.js';
import { handleGetChain } from '../../src/tools/get-chain.js';
import { handleQuarantineStatus } from '../../src/tools/quarantine-status.js';
import { handleSetVerificationTier } from '../../src/tools/set-verification-tier.js';
import { handleMeasureBehavior } from '../../src/tools/measure-behavior.js';
import { handleFullLifecycle } from '../../src/tools/full-lifecycle.js';

function parse(result: { content: Array<{ type: string; text: string }> }) {
  return JSON.parse(result.content[0].text);
}

describe('tool handlers - 12 tests', () => {
  let ctx: ServerContext;
  beforeEach(async () => { ctx = await createContext(); });

  it('aga_server_info returns version 2.0.0', async () => {
    const r = parse(await handleServerInfo({} as any, ctx));
    expect(r.version).toBe('2.0.0');
    expect(r.server).toBe('AGA MCP Server');
    expect(r.issuer_public_key).toMatch(/^[0-9a-f]{64}$/);
  });

  it('aga_init_chain initializes genesis', async () => {
    const r = parse(await handleInitChain({}, ctx));
    expect(r.success).toBe(true);
    expect(r.genesis_leaf_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('aga_init_chain rejects double init', async () => {
    await handleInitChain({}, ctx);
    const r = parse(await handleInitChain({}, ctx));
    expect(r.success).toBe(false);
  });

  it('aga_create_artifact creates and loads artifact', async () => {
    const r = parse(await handleCreateArtifact({
      subject_content: 'test-code',
      subject_metadata: { filename: 'test.py' },
    }, ctx));
    expect(r.success).toBe(true);
    expect(r.portal_state).toBe('ACTIVE_MONITORING');
    expect(r.sealed_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('aga_measure_subject detects match', async () => {
    await handleCreateArtifact({ subject_content: 'test-code', subject_metadata: { filename: 'test.py' } }, ctx);
    const r = parse(await handleMeasureSubject({ subject_content: 'test-code', subject_metadata: { filename: 'test.py' } }, ctx));
    expect(r.success).toBe(true);
    expect(r.match).toBe(true);
    expect(r.drift_detected).toBe(false);
  });

  it('aga_measure_subject detects drift', async () => {
    await handleCreateArtifact({ subject_content: 'test-code', subject_metadata: { filename: 'test.py' } }, ctx);
    const r = parse(await handleMeasureSubject({ subject_content: 'modified-code', subject_metadata: { filename: 'test.py' } }, ctx));
    expect(r.success).toBe(true);
    expect(r.match).toBe(false);
    expect(r.drift_detected).toBe(true);
    expect(r.enforcement_action).toBeTruthy();
  });

  it('aga_get_portal_state returns current state', async () => {
    const r = parse(await handleGetPortalState({} as any, ctx));
    expect(r.state).toBe('INITIALIZATION');
    expect(r.artifact_loaded).toBe(false);
  });

  it('aga_get_chain returns events', async () => {
    await handleCreateArtifact({ subject_content: 'code', subject_metadata: { filename: 'f.py' } }, ctx);
    const r = parse(await handleGetChain({}, ctx));
    expect(r.count).toBeGreaterThan(0);
  });

  it('aga_quarantine_status returns error when not quarantined', async () => {
    const r = parse(await handleQuarantineStatus({} as any, ctx));
    expect(r.success).toBe(false);
    expect(r.error).toContain('not in quarantine');
  });

  it('aga_set_verification_tier changes tier', async () => {
    const r = parse(await handleSetVerificationTier({ tier: 'GOLD' }, ctx));
    expect(r.success).toBe(true);
    expect(r.current_tier).toBe('GOLD');
    expect(r.previous_tier).toBe('BRONZE');
  });

  it('aga_measure_behavior returns no violations initially', async () => {
    const r = parse(await handleMeasureBehavior({} as any, ctx));
    expect(r.success).toBe(true);
    expect(r.drift_detected).toBe(false);
  });

  it('aga_demonstrate_lifecycle completes attestation through verification', async () => {
    const r = parse(await handleFullLifecycle({ subject_content: 'lifecycle-test-code' }, ctx));
    expect(r.success).toBe(true);
    expect(r.final_verdict).toBe('PASS');
    expect(r.phases.attestation.success).toBe(true);
    expect(r.phases.monitoring.match).toBe(true);
    expect(r.phases.evidence_bundle.verification.overall).toBe(true);
  });
});
