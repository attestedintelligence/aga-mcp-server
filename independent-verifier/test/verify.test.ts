/**
 * Independent Verifier Tests
 *
 * Verifies that the independent verifier (zero AGA imports) can
 * successfully verify evidence bundles from all 3 deployment scenarios.
 */
import { describe, it, expect } from 'vitest';
import { verifyEvidenceBundle } from '../verify.js';

// Import scenarios to generate bundles (these use AGA code, but the VERIFIER does not)
import { runScadaScenario } from '../../scenarios/scada-enforcement.js';
import { runAutonomousVehicleScenario } from '../../scenarios/autonomous-vehicle.js';
import { runAiAgentScenario } from '../../scenarios/ai-agent-governance.js';

describe('Independent Verifier - Zero AGA Imports', () => {
  it('verifies SCADA scenario bundle', () => {
    const { bundle } = runScadaScenario();
    const bundleJson = JSON.stringify(bundle);
    const result = verifyEvidenceBundle(bundleJson);

    expect(result.step1_artifact_sig).toBe(true);
    expect(result.step2_receipt_sigs).toBe(true);
    expect(result.step3_merkle_proofs).toBe(true);
    expect(result.step4_anchor).toBe('SKIPPED');
    expect(result.overall).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('verifies Autonomous Vehicle scenario bundle', () => {
    const { bundle } = runAutonomousVehicleScenario();
    const bundleJson = JSON.stringify(bundle);
    const result = verifyEvidenceBundle(bundleJson);

    expect(result.step1_artifact_sig).toBe(true);
    expect(result.step2_receipt_sigs).toBe(true);
    expect(result.step3_merkle_proofs).toBe(true);
    expect(result.overall).toBe(true);
  });

  it('verifies AI Agent scenario bundle', () => {
    const { bundle } = runAiAgentScenario();
    const bundleJson = JSON.stringify(bundle);
    const result = verifyEvidenceBundle(bundleJson);

    expect(result.step1_artifact_sig).toBe(true);
    expect(result.step2_receipt_sigs).toBe(true);
    expect(result.step3_merkle_proofs).toBe(true);
    expect(result.overall).toBe(true);
  });

  it('rejects tampered bundle', () => {
    const { bundle } = runScadaScenario();
    // Tamper with artifact signature
    const tampered = { ...bundle, artifact: { ...bundle.artifact, signature: 'AAAA' + bundle.artifact.signature.slice(4) } };
    const result = verifyEvidenceBundle(JSON.stringify(tampered));

    expect(result.step1_artifact_sig).toBe(false);
    expect(result.overall).toBe(false);
  });

  it('rejects invalid JSON', () => {
    const result = verifyEvidenceBundle('not valid json');
    expect(result.overall).toBe(false);
    expect(result.errors).toContain('Failed to parse bundle JSON');
  });
});
