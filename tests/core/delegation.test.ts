import { describe, it, expect } from 'vitest';
import { generateKeyPair, pkToHex } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';
import { performAttestation } from '../../src/core/attestation.js';
import { generateArtifact, hashArtifact, verifyArtifactSignature } from '../../src/core/artifact.js';
import { deriveArtifact, validateDelegation } from '../../src/core/delegation.js';

function makeParentArtifact(issuerKP: ReturnType<typeof generateKeyPair>, ttl = 3600) {
  const subId = computeSubjectIdFromString('def agent(): pass', { filename: 'agent.py', version: '1.0' });
  const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('pol'), evidence_items: [] });
  return generateArtifact({
    subject_identifier: subId, policy_reference: sha256Str('pol'), policy_version: 1,
    sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
    enforcement_parameters: {
      measurement_cadence_ms: 100, ttl_seconds: ttl,
      enforcement_triggers: ['QUARANTINE', 'TERMINATE', 'SAFE_STATE'],
      re_attestation_required: true,
      measurement_types: ['EXECUTABLE_IMAGE', 'CONFIG_MANIFEST', 'FILE_SYSTEM_STATE'],
    },
    disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
    evidence_commitments: att.evidence_commitments, issuer_keypair: issuerKP,
  });
}

describe('constrained sub-agent delegation', () => {
  const issuerKP = generateKeyPair();

  it('derives artifact with reduced TTL and scope', () => {
    const parent = makeParentArtifact(issuerKP);
    const result = deriveArtifact(parent, {
      enforcement_triggers: ['QUARANTINE'],
      measurement_types: ['EXECUTABLE_IMAGE'],
      requested_ttl_seconds: 1800,
      delegation_purpose: 'Sub-agent monitoring',
    }, issuerKP);

    expect(result.success).toBe(true);
    expect(result.child_artifact).toBeDefined();
    expect(result.effective_ttl_seconds!).toBeLessThanOrEqual(1800);
    expect(result.child_artifact!.enforcement_parameters.enforcement_triggers).toEqual(['QUARANTINE']);
    expect(result.child_artifact!.enforcement_parameters.measurement_types).toEqual(['EXECUTABLE_IMAGE']);
  });

  it('clamps child TTL to parent remaining TTL', () => {
    const parent = makeParentArtifact(issuerKP, 600); // 10 min
    const result = deriveArtifact(parent, {
      enforcement_triggers: ['QUARANTINE'],
      measurement_types: ['EXECUTABLE_IMAGE'],
      requested_ttl_seconds: 7200, // asks for 2 hours
      delegation_purpose: 'Test',
    }, issuerKP);

    expect(result.success).toBe(true);
    expect(result.effective_ttl_seconds!).toBeLessThanOrEqual(600);
  });

  it('rejects scope expansion - invalid trigger', () => {
    const parent = makeParentArtifact(issuerKP);
    const result = deriveArtifact(parent, {
      enforcement_triggers: ['QUARANTINE', 'KEY_REVOKE'], // KEY_REVOKE not in parent
      measurement_types: ['EXECUTABLE_IMAGE'],
      requested_ttl_seconds: 1800,
      delegation_purpose: 'Test',
    }, issuerKP);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Cannot expand scope');
    expect(result.error).toContain('KEY_REVOKE');
  });

  it('rejects scope expansion - invalid measurement type', () => {
    const parent = makeParentArtifact(issuerKP);
    const result = deriveArtifact(parent, {
      enforcement_triggers: ['QUARANTINE'],
      measurement_types: ['EXECUTABLE_IMAGE', 'NETWORK_TRAFFIC'], // NETWORK_TRAFFIC not in parent
      requested_ttl_seconds: 1800,
      delegation_purpose: 'Test',
    }, issuerKP);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Cannot expand scope');
    expect(result.error).toContain('NETWORK_TRAFFIC');
  });

  it('child artifact has valid signature', () => {
    const parent = makeParentArtifact(issuerKP);
    const result = deriveArtifact(parent, {
      enforcement_triggers: ['QUARANTINE'],
      measurement_types: ['EXECUTABLE_IMAGE'],
      requested_ttl_seconds: 1800,
      delegation_purpose: 'Test',
    }, issuerKP);

    expect(result.success).toBe(true);
    expect(verifyArtifactSignature(result.child_artifact!, pkToHex(issuerKP.publicKey))).toBe(true);
  });

  it('validateDelegation passes for valid derivation', () => {
    const parent = makeParentArtifact(issuerKP);
    const result = deriveArtifact(parent, {
      enforcement_triggers: ['QUARANTINE'],
      measurement_types: ['EXECUTABLE_IMAGE'],
      requested_ttl_seconds: 1800,
      delegation_purpose: 'Test',
    }, issuerKP);

    const validation = validateDelegation(parent, result.child_artifact!);
    expect(validation.valid).toBe(true);
    expect(validation.errors).toHaveLength(0);
  });

  it('validateDelegation catches scope expansion', () => {
    const parent = makeParentArtifact(issuerKP);
    // Manually create a child with expanded scope (bypassing deriveArtifact)
    const subId = computeSubjectIdFromString('def agent(): pass', { filename: 'agent.py', version: '1.0' });
    const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('pol'), evidence_items: [] });
    const badChild = generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('pol'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: {
        measurement_cadence_ms: 100, ttl_seconds: 9999, // exceeds parent
        enforcement_triggers: ['QUARANTINE', 'KEY_REVOKE'], // KEY_REVOKE not in parent
        re_attestation_required: true,
        measurement_types: ['EXECUTABLE_IMAGE'],
      },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: att.evidence_commitments, issuer_keypair: issuerKP,
    });

    const validation = validateDelegation(parent, badChild);
    expect(validation.valid).toBe(false);
    expect(validation.errors.length).toBeGreaterThanOrEqual(2); // TTL + trigger
  });

  it('tracks scope reduction in result', () => {
    const parent = makeParentArtifact(issuerKP);
    const result = deriveArtifact(parent, {
      enforcement_triggers: ['QUARANTINE'], // removed TERMINATE, SAFE_STATE
      measurement_types: ['EXECUTABLE_IMAGE'], // removed CONFIG_MANIFEST, FILE_SYSTEM_STATE
      requested_ttl_seconds: 1800,
      delegation_purpose: 'Test',
    }, issuerKP);

    expect(result.scope_reduction!.triggers_removed).toContain('TERMINATE');
    expect(result.scope_reduction!.triggers_removed).toContain('SAFE_STATE');
    expect(result.scope_reduction!.measurement_types_removed).toContain('CONFIG_MANIFEST');
    expect(result.scope_reduction!.measurement_types_removed).toContain('FILE_SYSTEM_STATE');
  });
});
