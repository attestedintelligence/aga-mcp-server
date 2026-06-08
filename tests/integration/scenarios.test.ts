/**
 * Integration tests for all 3 deployment scenarios.
 * Each scenario produces a canonical SEP evidence bundle that verifies offline (with provenance),
 * plus a continuity chain with the expected event types.
 */
import { describe, it, expect } from 'vitest';
import { runScadaScenario } from '../../scenarios/scada-enforcement.js';
import { runAutonomousVehicleScenario } from '../../scenarios/autonomous-vehicle.js';
import { runAiAgentScenario } from '../../scenarios/ai-agent-governance.js';
import { verifyEvidenceBundle } from '../../independent-verifier/verify.js';

const verifies = (b: { public_key: string }) => verifyEvidenceBundle(JSON.stringify(b), b.public_key);

describe('Integration - Deployment Scenarios', () => {
  it('SCADA: seal -> monitor -> drift -> quarantine -> forensic -> revoke -> SEP bundle verifies', () => {
    const result = runScadaScenario();
    const v = verifies(result.sepBundle);
    expect(v.verdict).toBe('VERIFIED');
    expect(v.issuerVerified).toBe(true);
    expect(result.sepBundle.merkle_proofs.length).toBeGreaterThan(0);

    const types = result.chain.map(e => e.event_type);
    expect(types).toContain('GENESIS');
    expect(types).toContain('POLICY_ISSUANCE');
    expect(types).toContain('INTERACTION_RECEIPT');
    expect(types).toContain('REVOCATION');
  });

  it('Drone: seal -> monitor -> disclose (substitution) -> drift -> SAFE_STATE -> SEP bundle verifies', () => {
    const result = runAutonomousVehicleScenario();
    expect(verifies(result.sepBundle).verdict).toBe('VERIFIED');
    const types = result.chain.map(e => e.event_type);
    expect(types).toContain('DISCLOSURE');
    expect(types).toContain('SUBSTITUTION');
  });

  it('AI Agent: seal -> monitor -> behavioral checks -> delegate -> behavioral drift -> SEP bundle verifies', () => {
    const result = runAiAgentScenario();
    expect(verifies(result.sepBundle).verdict).toBe('VERIFIED');
    const types = result.chain.map(e => e.event_type);
    expect(types).toContain('DELEGATION');
    expect(types).toContain('BEHAVIORAL_DRIFT');
    expect(types).toContain('DISCLOSURE');
    expect(types).toContain('SUBSTITUTION');
  });
});
