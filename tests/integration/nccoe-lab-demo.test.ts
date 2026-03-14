/**
 * Full lifecycle integration test matching the NCCoE lab demo scenario
 * from our NIST filing (NCCoE_Attested_Intelligence.pdf, Section 7).
 *
 * Phase 1: Attestation and Identity Binding
 * Phase 2: Authorized Operation (clean measurements with receipts)
 * Phase 3: Simulated Prompt Injection → Drift → Quarantine
 * Phase 3b: Mid-Session Revocation
 * Phase 4: Offline Audit via Evidence Bundle
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPair, pkToHex } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';
import { performAttestation } from '../../src/core/attestation.js';
import { generateArtifact, hashArtifact, verifyArtifactSignature } from '../../src/core/artifact.js';
import { Portal } from '../../src/core/portal.js';
import { generateReceipt } from '../../src/core/receipt.js';
import { createGenesisEvent, appendEvent, verifyChainIntegrity } from '../../src/core/chain.js';
import { createCheckpoint, eventInclusionProof } from '../../src/core/checkpoint.js';
import { generateBundle, verifyBundleOffline } from '../../src/core/bundle.js';
import { initQuarantine, captureInput, releaseQuarantine } from '../../src/core/quarantine.js';

describe('NCCoE Lab Demo - Full AGA Lifecycle', () => {
  const issuerKP = generateKeyPair();
  const portalKP = generateKeyPair();
  const chainKP = generateKeyPair();
  const enc = new TextEncoder();

  const agentCode = 'def monitor(): return sensors.read_all()';
  const agentMeta = { filename: 'scada_agent.py', version: '2.1.0', author: 'engineering' };

  it('Phase 1: Attestation and Identity Binding', () => {
    const subId = computeSubjectIdFromString(agentCode, agentMeta);
    expect(subId.bytes_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(subId.metadata_hash).toMatch(/^[0-9a-f]{64}$/);

    const att = performAttestation({
      subject_identifier: subId,
      policy_reference: sha256Str('scada-policy-v2'),
      evidence_items: [{ label: 'code_review', content: 'Approved 2026-03-04' }],
    });
    expect(att.success).toBe(true);

    const artifact = generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('scada-policy-v2'), policy_version: 2,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: {
        measurement_cadence_ms: 100, ttl_seconds: 3600,
        enforcement_triggers: ['QUARANTINE', 'SAFE_STATE'],
        re_attestation_required: true,
        measurement_types: ['EXECUTABLE_IMAGE', 'CONFIG_MANIFEST'],
      },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: att.evidence_commitments, issuer_keypair: issuerKP,
    });
    expect(verifyArtifactSignature(artifact, pkToHex(issuerKP.publicKey))).toBe(true);
  });

  it('Phase 2-4: Full lifecycle with receipts on every measurement', () => {
    const subId = computeSubjectIdFromString(agentCode, agentMeta);
    const att = performAttestation({
      subject_identifier: subId, policy_reference: sha256Str('scada-policy-v2'),
      evidence_items: [{ label: 'review', content: 'ok' }],
    });
    const artifact = generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('scada-policy-v2'), policy_version: 2,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: {
        measurement_cadence_ms: 100, ttl_seconds: 3600,
        enforcement_triggers: ['QUARANTINE', 'SAFE_STATE'],
        re_attestation_required: true,
        measurement_types: ['EXECUTABLE_IMAGE'],
      },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: att.evidence_commitments, issuer_keypair: issuerKP,
    });

    // ── Phase 2: Authorized Operation ──────────────────────────
    const portal = new Portal();
    expect(portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey)).ok).toBe(true);

    const artRef = hashArtifact(artifact);

    // Clean measurement #1 → receipt generated (V3: receipts for ALL measurements)
    const m1 = portal.measure(enc.encode(agentCode), agentMeta);
    expect(m1.match).toBe(true);
    expect(m1.ttl_ok).toBe(true);
    const r1 = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: `${m1.currentBytesHash}||${m1.currentMetaHash}`,
      sealedHash: `${m1.expectedBytesHash}||${m1.expectedMetaHash}`,
      driftDetected: false, driftDescription: null, action: null,
      measurementType: 'EXECUTABLE_IMAGE', seq: 1, prevLeaf: null, portalKP,
    });
    expect(r1.drift_detected).toBe(false);
    expect(r1.measurement_type).toBe('EXECUTABLE_IMAGE');

    // Clean measurement #2
    const m2 = portal.measure(enc.encode(agentCode), agentMeta);
    expect(m2.match).toBe(true);
    const r2 = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: `${m2.currentBytesHash}||${m2.currentMetaHash}`,
      sealedHash: `${m2.expectedBytesHash}||${m2.expectedMetaHash}`,
      driftDetected: false, driftDescription: null, action: null,
      measurementType: 'EXECUTABLE_IMAGE', seq: 2, prevLeaf: null, portalKP,
    });

    // ── Phase 3: Simulated Attack ──────────────────────────────
    const injectedCode = 'def monitor(): return attacker.exfiltrate(sensors.read_all())';
    const m3 = portal.measure(enc.encode(injectedCode), agentMeta);
    expect(m3.match).toBe(false);
    expect(portal.state).toBe('DRIFT_DETECTED');

    portal.enforce('QUARANTINE');
    expect(portal.state).toBe('PHANTOM_QUARANTINE');

    // Phantom execution: capture attacker inputs
    const q = initQuarantine();
    captureInput(q, 'attacker_command', 'exfiltrate /etc/passwd');
    captureInput(q, 'attacker_command', 'modify sensor_calibration');
    expect(q.inputs_captured).toBe(2);
    expect(q.outputs_severed).toBe(true);

    const r3 = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: `${m3.currentBytesHash}||${m3.currentMetaHash}`,
      sealedHash: `${m3.expectedBytesHash}||${m3.expectedMetaHash}`,
      driftDetected: true, driftDescription: 'Agent binary modified - prompt injection',
      action: 'QUARANTINE', measurementType: 'EXECUTABLE_IMAGE',
      seq: 3, prevLeaf: null, portalKP,
    });
    expect(r3.drift_detected).toBe(true);
    expect(r3.enforcement_action).toBe('QUARANTINE');

    // ── Phase 3b: Mid-Session Revocation ───────────────────────
    const portal2 = new Portal();
    portal2.loadArtifact(artifact, pkToHex(issuerKP.publicKey));
    portal2.revoke(artifact.sealed_hash);
    expect(portal2.state).toBe('TERMINATED');
    expect(portal2.isRevoked(artifact.sealed_hash)).toBe(true);

    // ── Phase 4: Continuity Chain + Offline Verification ───────
    const genesis = createGenesisEvent(chainKP, sha256Str('AGA-Spec'));
    const e1 = appendEvent('POLICY_ISSUANCE', { artifact_hash: artRef }, genesis, chainKP);
    const e2 = appendEvent('INTERACTION_RECEIPT', r1, e1, chainKP);  // clean
    const e3 = appendEvent('INTERACTION_RECEIPT', r2, e2, chainKP);  // clean
    const e4 = appendEvent('INTERACTION_RECEIPT', r3, e3, chainKP);  // drift
    const e5 = appendEvent('REVOCATION', {
      artifact_sealed_hash: artifact.sealed_hash,
      reason: 'Compromise detected', revoked_by: pkToHex(issuerKP.publicKey),
    }, e4, chainKP);

    const chain = [genesis, e1, e2, e3, e4, e5];
    const integrity = verifyChainIntegrity(chain);
    expect(integrity.valid).toBe(true);

    // Checkpoint
    const { checkpoint } = createCheckpoint(chain);
    expect(checkpoint.merkle_root).toMatch(/^[0-9a-f]{64}$/);

    // Evidence bundle
    const proof = eventInclusionProof(chain, e4.sequence_number); // proof for drift receipt
    const bundle = generateBundle(artifact, [r1, r2, r3], [proof], checkpoint, portalKP);
    const verification = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));

    expect(verification.step1_artifact_sig).toBe(true);
    expect(verification.step2_receipt_sigs).toBe(true);
    expect(verification.step3_merkle_proofs).toBe(true);
    expect(verification.overall).toBe(true);
    expect(verification.step4_anchor).toBe('SKIPPED_OFFLINE');

    // Verify chain contains all expected event types
    const types = chain.map(e => e.event_type);
    expect(types).toContain('GENESIS');
    expect(types).toContain('POLICY_ISSUANCE');
    expect(types).toContain('INTERACTION_RECEIPT');
    expect(types).toContain('REVOCATION');

    // Release quarantine
    const qResult = releaseQuarantine(q);
    expect(qResult.total_captures).toBe(2);
  });
});
