/**
 * Independent Verifier Test
 * Verifier has zero AGA imports AND verifies all 3 scenario bundles
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifyEvidenceBundle } from '../../independent-verifier/verify.js';
import { runScadaScenario } from '../../scenarios/scada-enforcement.js';
import { runAutonomousVehicleScenario } from '../../scenarios/autonomous-vehicle.js';
import { runAiAgentScenario } from '../../scenarios/ai-agent-governance.js';

describe('Independent Verifier - Zero AGA Imports', () => {
  it('verifier has zero AGA imports and verifies all 3 scenario bundles', () => {
    // Verify zero AGA imports by reading the source
    const verifierSource = readFileSync(resolve(__dirname, '../../independent-verifier/verify.ts'), 'utf-8');
    expect(verifierSource).not.toContain("from '../src/");
    expect(verifierSource).not.toContain("from '../../src/");
    expect(verifierSource).not.toContain("require('../src/");
    expect(verifierSource).not.toContain("require('../../src/");

    // Verify all 3 scenario SEP bundles under the independent (zero-AGA-import) verifier
    const s1 = runScadaScenario();
    const r1 = verifyEvidenceBundle(JSON.stringify(s1.sepBundle), s1.sepBundle.public_key);
    expect(r1.verdict).toBe('VERIFIED');
    expect(r1.issuerVerified).toBe(true);

    const s2 = runAutonomousVehicleScenario();
    const r2 = verifyEvidenceBundle(JSON.stringify(s2.sepBundle), s2.sepBundle.public_key);
    expect(r2.verdict).toBe('VERIFIED');

    const s3 = runAiAgentScenario();
    const r3 = verifyEvidenceBundle(JSON.stringify(s3.sepBundle), s3.sepBundle.public_key);
    expect(r3.verdict).toBe('VERIFIED');
  });
});
