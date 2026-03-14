/**
 * Crucible Compatibility Test
 * Simulates key Crucible audit checks against tool handlers directly.
 * Catches issues before the actual MCP-connected Crucible runs.
 */
import { describe, test, expect, beforeAll } from 'vitest';
import { createContext, type ServerContext } from '../../src/context.js';
import { handleServerInfo } from '../../src/tools/server-info.js';
import { handleInitChain } from '../../src/tools/init-chain.js';
import { handleCreateArtifact } from '../../src/tools/create-artifact.js';
import { handleMeasureSubject } from '../../src/tools/measure-subject.js';
import { handleStartMonitoring } from '../../src/tools/start-monitoring.js';
import { handleTriggerMeasurement } from '../../src/tools/trigger-measurement.js';
import { handleMeasureBehavior } from '../../src/tools/measure-behavior.js';
import { handleRevokeArtifact } from '../../src/tools/revoke-artifact.js';
import { handleGetChain } from '../../src/tools/get-chain.js';
import { handleDelegateSubagent } from '../../src/tools/delegate-subagent.js';
import { handleDiscloseClaim } from '../../src/tools/disclose-claim.js';
import { handleExportBundle } from '../../src/tools/export-bundle.js';
import { handleVerifyBundle } from '../../src/tools/verify-bundle.js';
import { handleSetVerificationTier } from '../../src/tools/set-verification-tier.js';
import { handleQuarantineStatus } from '../../src/tools/quarantine-status.js';
import { handleRotateKeys } from '../../src/tools/rotate-keys.js';
import { handleGenerateReceipt } from '../../src/tools/generate-receipt.js';
import { handleFullLifecycle } from '../../src/tools/full-lifecycle.js';
import { generateSampleBundle } from '../../src/resources/sample-bundle.js';
import { verifyBundleOffline } from '../../src/core/bundle.js';

function parse(r: { content: Array<{ type: string; text: string }> }) {
  return JSON.parse(r.content[0].text);
}

describe('Crucible Compatibility', () => {
  let ctx: ServerContext;
  let sealedHash: string;

  beforeAll(async () => {
    ctx = await createContext();
  });

  // Phase 0
  test('Phase 0: server info returns version 2.0.0', async () => {
    const r = parse(await handleServerInfo({} as any, ctx));
    expect(r.version).toBe('2.0.0');
    expect(r.issuer_public_key).toMatch(/^[0-9a-f]{64}$/);
    expect(r.portal_public_key).toMatch(/^[0-9a-f]{64}$/);
    expect(r.chain_public_key).toMatch(/^[0-9a-f]{64}$/);
    expect(r.patent).toContain('19/433,835');
  });

  test('Phase 0: sample bundle passes aga_verify_bundle', () => {
    const { bundle, issuerPkHex } = generateSampleBundle();
    const parsed = JSON.parse(bundle);
    const result = verifyBundleOffline(parsed, issuerPkHex);
    expect(result.step1_artifact_sig).toBe(true);
    expect(result.step2_receipt_sigs).toBe(true);
    expect(result.step3_merkle_proofs).toBe(true);
    expect(result.overall).toBe(true);
  });

  // Phase 1
  test('Phase 1: init chain and reject duplicate', async () => {
    const r1 = parse(await handleInitChain({}, ctx));
    expect(r1.success).toBe(true);
    expect(r1.genesis_leaf_hash).toMatch(/^[0-9a-f]{64}$/);

    const r2 = parse(await handleInitChain({}, ctx));
    expect(r2.success).toBe(false);
  });

  test('Phase 1: set GOLD tier', async () => {
    const r = parse(await handleSetVerificationTier({ tier: 'GOLD' }, ctx));
    expect(r.success).toBe(true);
    expect(r.current_tier).toBe('GOLD');
    expect(r.description).toContain('blockchain-anchored');
  });

  test('Phase 1: create artifact with pre-computed hashes', async () => {
    const r = parse(await handleCreateArtifact({
      subject_bytes_hash: 'a4f8c2e1b3d7094f6e2a8b1c5d9f3e7a0b4c6d8e1f2a3b5c7d9e0f1a2b3c4d5',
      subject_metadata_hash: '7b2e9f1a3c5d8e0f4a6b8c1d3e5f7a9b0c2d4e6f8a1b3c5d7e9f0a2b4c6d8e1',
      measurement_cadence_ms: 100,
      enforcement_action: 'QUARANTINE',
      ttl_seconds: 300,
      measurement_types: ['EXECUTABLE_IMAGE', 'CONFIG_MANIFEST', 'MEMORY_REGIONS'],
      behavioral_baseline: {
        permitted_tools: ['survey', 'report', 'return_to_home'],
        forbidden_sequences: [['exfiltrate', 'transmit_external']],
        rate_limits: { survey: 20, report: 10 },
        window_ms: 60000,
      },
    }, ctx));
    expect(r.success).toBe(true);
    expect(r.sealed_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(r.portal_state).toBe('ACTIVE_MONITORING');
    expect(r.verification_tier).toBe('GOLD');
    expect(r.enforcement_parameters.ttl_seconds).toBe(300);
    expect(r.enforcement_parameters.enforcement_triggers).toContain('QUARANTINE');
    sealedHash = r.sealed_hash;
  });

  // Phase 2
  test('Phase 2: measure with SAME hash = MATCH', async () => {
    const r = parse(await handleMeasureSubject({
      subject_bytes_hash: 'a4f8c2e1b3d7094f6e2a8b1c5d9f3e7a0b4c6d8e1f2a3b5c7d9e0f1a2b3c4d5',
      subject_metadata_hash: '7b2e9f1a3c5d8e0f4a6b8c1d3e5f7a9b0c2d4e6f8a1b3c5d7e9f0a2b4c6d8e1',
    }, ctx));
    expect(r.success).toBe(true);
    expect(r.match).toBe(true);
    expect(r.drift_detected).toBe(false);
  });

  test('Phase 2: trigger measurement with types', async () => {
    const r = parse(await handleTriggerMeasurement({
      subject_bytes_hash: 'a4f8c2e1b3d7094f6e2a8b1c5d9f3e7a0b4c6d8e1f2a3b5c7d9e0f1a2b3c4d5',
      measurement_type: 'EXECUTABLE_IMAGE',
    }, ctx));
    expect(r.success).toBe(true);
    expect(r.match).toBe(true);
    expect(r.measurement_type).toBe('EXECUTABLE_IMAGE');
  });

  // Phase 3
  test('Phase 3: behavioral drift - permitted tool clean', async () => {
    const r = parse(await handleMeasureBehavior({ tool_name: 'survey', record_only: false }, ctx));
    expect(r.success).toBe(true);
    // 'survey' is in permitted_tools, so no UNAUTHORIZED_TOOL violation for it
  });

  test('Phase 3: behavioral drift - unauthorized tool detected', async () => {
    const r = parse(await handleMeasureBehavior({ tool_name: 'exfiltrate', record_only: false }, ctx));
    expect(r.success).toBe(true);
    expect(r.drift_detected).toBe(true);
    expect(r.violations.some((v: any) => v.type === 'UNAUTHORIZED_TOOL' && v.tool === 'exfiltrate')).toBe(true);
  });

  test('Phase 3: behavioral drift - forbidden sequence', async () => {
    const r = parse(await handleMeasureBehavior({ tool_name: 'transmit_external', record_only: false }, ctx));
    expect(r.success).toBe(true);
    expect(r.drift_detected).toBe(true);
    expect(r.violations.some((v: any) => v.type === 'FORBIDDEN_SEQUENCE')).toBe(true);
  });

  // Phase 4
  test('Phase 4: revocation transitions to SAFE_STATE', async () => {
    const r = parse(await handleRevokeArtifact({
      reason: 'Red Team Override: administrative authority termination',
      transition_to: 'SAFE_STATE',
    }, ctx));
    expect(r.success).toBe(true);
    expect(r.portal_state).toBe('SAFE_STATE');
  });

  test('Phase 4: post-revocation measurement rejected', async () => {
    const r = parse(await handleTriggerMeasurement({
      subject_bytes_hash: 'a4f8c2e1b3d7094f6e2a8b1c5d9f3e7a0b4c6d8e1f2a3b5c7d9e0f1a2b3c4d5',
    }, ctx));
    expect(r.success).toBe(false);
  });

  // Phase 5
  test('Phase 5: re-attestation after revocation', async () => {
    const r = parse(await handleCreateArtifact({
      subject_bytes_hash: 'a4f8c2e1b3d7094f6e2a8b1c5d9f3e7a0b4c6d8e1f2a3b5c7d9e0f1a2b3c4d5',
      subject_metadata_hash: '7b2e9f1a3c5d8e0f4a6b8c1d3e5f7a9b0c2d4e6f8a1b3c5d7e9f0a2b4c6d8e1',
      enforcement_action: 'ALERT_ONLY',
      ttl_seconds: 3600,
    }, ctx));
    expect(r.success).toBe(true);
    expect(r.is_re_attestation).toBe(true);
    expect(r.event_type).toBe('RE_ATTESTATION');
    expect(r.sealed_hash).not.toBe(sealedHash);
    expect(r.portal_state).toBe('ACTIVE_MONITORING');
  });

  test('Phase 5: ALERT_ONLY drift keeps ACTIVE_MONITORING', async () => {
    const r = parse(await handleTriggerMeasurement({
      subject_bytes_hash: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      measurement_type: 'EXECUTABLE_IMAGE',
    }, ctx));
    expect(r.success).toBe(true);
    expect(r.drift_detected).toBe(true);
    expect(r.enforcement_action).toBe('ALERT_ONLY');
    expect(r.portal_state).toBe('ACTIVE_MONITORING');
  });

  // Phase 6
  test('Phase 6: delegation succeeds with reduced scope', async () => {
    const r = parse(await handleDelegateSubagent({
      sub_agent_id: 'survey-drone-beta',
      permitted_tools: ['survey', 'report'],
      ttl_seconds: 600,
      delegation_reason: 'Delegated reconnaissance sub-task',
    }, ctx));
    expect(r.success).toBe(true);
    expect(r.scope_diminished).toBe(true);
  });

  test('Phase 6: delegation rejects scope expansion', async () => {
    const r = parse(await handleDelegateSubagent({
      sub_agent_id: 'rogue-agent',
      enforcement_triggers: ['KEY_REVOKE'],
      ttl_seconds: 600,
      delegation_reason: 'test',
    }, ctx));
    expect(r.success).toBe(false);
    expect(r.error).toContain('Cannot expand scope');
  });

  // Phase 7
  test('Phase 7: key rotation', async () => {
    const r = parse(await handleRotateKeys({
      keypair: 'portal',
      reason: 'scheduled quarterly rotation',
    }, ctx));
    expect(r.success).toBe(true);
    expect(r.new_public_key).not.toBe(r.old_public_key);
  });

  // Phase 8
  test('Phase 8: S4 claim DENIED at REVEAL_FULL, auto-substituted', async () => {
    const r = parse(await handleDiscloseClaim({
      claim_id: 'vehicle.exact_position',
      mode: 'REVEAL_FULL',
    }, ctx));
    expect(r.permitted).toBe(true); // substitution succeeded
    expect(r.was_substituted).toBe(true);
    expect(r.substitution_receipt).toBeTruthy();
  });

  test('Phase 8: S1 claim PERMITTED at REVEAL_FULL', async () => {
    const r = parse(await handleDiscloseClaim({
      claim_id: 'vehicle.operational_area',
      mode: 'REVEAL_FULL',
    }, ctx));
    expect(r.permitted).toBe(true);
    expect(r.was_substituted).toBe(false);
    expect(r.disclosed_value).toBe('National Capital Region');
  });

  test('Phase 8: PROOF_ONLY returns boolean', async () => {
    const r = parse(await handleDiscloseClaim({
      claim_id: 'plant.reactor_id',
      mode: 'PROOF_ONLY',
    }, ctx));
    expect(r.permitted).toBe(true);
    expect(r.disclosed_value).toBe(true);
  });

  // Phase 9
  test('Phase 9: chain contains expected event types', async () => {
    const r = parse(await handleGetChain({ filter_type: 'all', verify: true }, ctx));
    expect(r.chain_valid).toBe(true);
    const types = r.events.map((e: any) => e.event_type);
    expect(types).toContain('GENESIS');
    expect(types).toContain('POLICY_ISSUANCE');
    expect(types).toContain('INTERACTION_RECEIPT');
    expect(types).toContain('REVOCATION');
    expect(types).toContain('RE_ATTESTATION');
    expect(types).toContain('DELEGATION');
    expect(types).toContain('KEY_ROTATION');
  });

  test('Phase 9: behavioral filter works', async () => {
    const r = parse(await handleGetChain({ filter_type: 'behavioral' }, ctx));
    for (const e of r.events) {
      expect(e.event_type).toBe('BEHAVIORAL_DRIFT');
    }
  });

  test('Phase 9: delegation filter works', async () => {
    const r = parse(await handleGetChain({ filter_type: 'delegations' }, ctx));
    for (const e of r.events) {
      expect(e.event_type).toBe('DELEGATION');
    }
  });

  // Phase 10
  test('Phase 10: export + verify bundle', async () => {
    // Need checkpoint first - create one via export which auto-checkpoints
    // The export tool requires a checkpoint, so let's create the artifact fresh
    const ctx2 = await createContext();
    await handleInitChain({}, ctx2);
    await handleCreateArtifact({
      subject_content: 'bundle-test-code',
      subject_metadata: { filename: 'test.py' },
    }, ctx2);
    await handleMeasureSubject({
      subject_content: 'bundle-test-code',
      subject_metadata: { filename: 'test.py' },
    }, ctx2);

    // Create checkpoint
    const { createCheckpoint } = await import('../../src/core/checkpoint.js');
    const allEvents = await ctx2.storage.getAllEvents();
    const { checkpoint } = createCheckpoint(allEvents);
    await ctx2.storage.storeCheckpoint(checkpoint);

    const bundle = parse(await handleExportBundle({} as any, ctx2));
    expect(bundle.success).toBe(true);
    expect(bundle.bundle.artifact).toBeTruthy();
    expect(bundle.bundle.receipts.length).toBeGreaterThan(0);

    const verification = parse(await handleVerifyBundle({
      bundle: bundle.bundle,
      pinned_public_key: (await import('../../src/crypto/sign.js')).pkToHex(ctx2.issuerKP.publicKey),
    }, ctx2));
    expect(verification.verification.step1_artifact_sig).toBe(true);
    expect(verification.verification.step2_receipt_sigs).toBe(true);
    expect(verification.verification.overall).toBe(true);
  });

  // Phase 11
  test('Phase 11: tampered bundle fails verification', async () => {
    const { bundle, issuerPkHex } = generateSampleBundle();
    const parsed = JSON.parse(bundle);
    // Tamper artifact
    parsed.artifact.policy_version = 999;
    const result = verifyBundleOffline(parsed, issuerPkHex);
    expect(result.step1_artifact_sig).toBe(false);
    expect(result.overall).toBe(false);
  });

  // Phase 12
  test('Phase 12: quarantine status errors outside quarantine', async () => {
    const ctx3 = await createContext();
    const r = parse(await handleQuarantineStatus({} as any, ctx3));
    expect(r.success).toBe(false);
    expect(r.error).toContain('not in quarantine');
  });

  // Bonus
  test('Bonus: demonstrate_lifecycle completes', async () => {
    const ctx4 = await createContext();
    const r = parse(await handleFullLifecycle({
      scenario: 'drone',
      include_drift: true,
      include_revocation: true,
      include_behavioral: true,
    }, ctx4));
    expect(r.success).toBe(true);
    expect(r.final_verdict).toBe('PASS');
    expect(r.phases.attestation).toBeTruthy();
    expect(r.phases.monitoring).toBeTruthy();
    expect(r.phases.drift_detection).toBeTruthy();
    expect(r.phases.behavioral_drift).toBeTruthy();
    expect(r.phases.revocation).toBeTruthy();
    expect(r.phases.evidence_bundle).toBeTruthy();
  });
});
