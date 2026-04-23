/**
 * Integration Tests for all 3 deployment scenarios
 * Each scenario produces a valid evidence bundle that passes 4-step verification
 */
import { describe, it, expect } from 'vitest';
import { runScadaScenario } from '../../scenarios/scada-enforcement.js';
import { runAutonomousVehicleScenario } from '../../scenarios/autonomous-vehicle.js';
import { runAiAgentScenario } from '../../scenarios/ai-agent-governance.js';

describe('Integration - Deployment Scenarios', () => {
  it('SCADA: seal -> monitor -> drift -> quarantine -> forensic -> revoke -> bundle -> verify PASS', () => {
    const result = runScadaScenario();

    expect(result.verification.step1_artifact_sig).toBe(true);
    expect(result.verification.step2_receipt_sigs).toBe(true);
    expect(result.verification.step3_merkle_proofs).toBe(true);
    expect(result.verification.overall).toBe(true);

    // Verify chain has expected event types
    const types = result.chain.map(e => e.event_type);
    expect(types).toContain('GENESIS');
    expect(types).toContain('POLICY_ISSUANCE');
    expect(types).toContain('INTERACTION_RECEIPT');
    expect(types).toContain('REVOCATION');

    // Bundle is GOLD tier
    expect(result.bundle.verification_tier).toBe('GOLD');
    expect(result.bundle.merkle_proofs.length).toBeGreaterThan(0);
  });

  it('Drone: seal -> monitor -> disclose (substitution) -> drift -> SAFE_STATE -> bundle -> verify PASS', () => {
    const result = runAutonomousVehicleScenario();

    expect(result.verification.step1_artifact_sig).toBe(true);
    expect(result.verification.step2_receipt_sigs).toBe(true);
    expect(result.verification.step3_merkle_proofs).toBe(true);
    expect(result.verification.overall).toBe(true);

    // Verify chain has disclosure events
    const types = result.chain.map(e => e.event_type);
    expect(types).toContain('DISCLOSURE');
    expect(types).toContain('SUBSTITUTION');
  });

  it('AI Agent: seal -> monitor -> behavioral checks -> delegate -> behavioral drift -> bundle -> verify PASS', () => {
    const result = runAiAgentScenario();

    expect(result.verification.step1_artifact_sig).toBe(true);
    expect(result.verification.step2_receipt_sigs).toBe(true);
    expect(result.verification.step3_merkle_proofs).toBe(true);
    expect(result.verification.overall).toBe(true);

    // Verify chain has delegation and behavioral drift events
    const types = result.chain.map(e => e.event_type);
    expect(types).toContain('DELEGATION');
    expect(types).toContain('BEHAVIORAL_DRIFT');
    expect(types).toContain('DISCLOSURE');
    expect(types).toContain('SUBSTITUTION');
  });
});
