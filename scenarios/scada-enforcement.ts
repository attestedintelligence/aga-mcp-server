/**
 * Scenario 1: SCADA Process Enforcement
 * NCCoE Use Case
 *
 * seal -> monitor (3 clean EXECUTABLE_IMAGE) -> behavioral checks
 * (read_sensors, adjust_valve, log_status) -> inject drift -> QUARANTINE
 * -> phantom execution -> forensic capture -> revoke -> GOLD evidence bundle -> verify
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { generateKeyPair, pkToHex } from '../src/crypto/sign.js';
import { sha256Str } from '../src/crypto/hash.js';
import { computeSubjectIdFromString } from '../src/core/subject.js';
import { performAttestation } from '../src/core/attestation.js';
import { generateArtifact, hashArtifact } from '../src/core/artifact.js';
import { Portal } from '../src/core/portal.js';
import { generateReceipt } from '../src/core/receipt.js';
import { createGenesisEvent, appendEvent, verifyChainIntegrity } from '../src/core/chain.js';
import { createCheckpoint, eventInclusionProof } from '../src/core/checkpoint.js';
import { generateBundle, verifyBundleOffline } from '../src/core/bundle.js';
import { initQuarantine, captureInput, releaseQuarantine } from '../src/core/quarantine.js';
import { BehavioralMonitor } from '../src/core/behavioral.js';
import type { EvidenceBundle } from '../src/core/types.js';

export interface ScenarioResult {
  bundle: EvidenceBundle;
  verification: ReturnType<typeof verifyBundleOffline>;
  chain: ReturnType<typeof createGenesisEvent>[];
}

export function runScadaScenario(): ScenarioResult {
  const enc = new TextEncoder();

  // 1. Generate keypairs
  const issuerKP = generateKeyPair();
  const portalKP = generateKeyPair();
  const chainKP = generateKeyPair();

  // 2. Create subject: simulated SCADA control binary
  const binaryContent = 'SCADA_CONTROL_BINARY_v3.2.1: read_sensors(); adjust_valve(); log_status();';
  const binaryMeta = { filename: 'scada_control.bin', version: '3.2.1', author: 'engineering', content_type: 'application/octet-stream' };
  const subId = computeSubjectIdFromString(binaryContent, binaryMeta);

  // 3. Attest and seal
  const att = performAttestation({
    subject_identifier: subId,
    policy_reference: sha256Str('scada-enforcement-policy-v3'),
    evidence_items: [
      { label: 'code_review', content: 'Approved by senior engineer 2026-03-01' },
      { label: 'safety_certification', content: 'IEC 62443 compliant' },
    ],
  });

  const artifact = generateArtifact({
    subject_identifier: subId,
    policy_reference: sha256Str('scada-enforcement-policy-v3'),
    policy_version: 3,
    sealed_hash: att.sealed_hash!,
    seal_salt: att.seal_salt!,
    enforcement_parameters: {
      measurement_cadence_ms: 100,
      ttl_seconds: 3600,
      enforcement_triggers: ['QUARANTINE', 'SAFE_STATE'],
      re_attestation_required: true,
      measurement_types: ['EXECUTABLE_IMAGE', 'CONFIG_MANIFEST', 'MEMORY_REGIONS'],
      behavioral_baseline: {
        permitted_tools: ['read_sensors', 'adjust_valve', 'log_status'],
        forbidden_sequences: [['adjust_valve', 'override_safety']],
        rate_limits: { read_sensors: 100, adjust_valve: 10, log_status: 50 },
      },
    },
    disclosure_policy: {
      claims_taxonomy: [
        { claim_id: 'plant.reactor_id', sensitivity: 'S4_CRITICAL', substitutes: ['plant.facility_region', 'plant.sector'], inference_risks: [], permitted_modes: [] },
        { claim_id: 'plant.facility_region', sensitivity: 'S2_MODERATE', substitutes: ['plant.sector'], inference_risks: [], permitted_modes: ['REVEAL_MIN', 'REVEAL_FULL'] },
        { claim_id: 'plant.sector', sensitivity: 'S1_LOW', substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL'] },
      ],
      substitution_rules: [],
    },
    evidence_commitments: att.evidence_commitments,
    issuer_keypair: issuerKP,
  });

  const artRef = hashArtifact(artifact);

  // 4. Init chain with genesis event
  const genesis = createGenesisEvent(chainKP, sha256Str('AGA-SCADA-Spec-v1'));
  let prevEvent = genesis;

  // Policy issuance event
  const issuanceEvent = appendEvent('POLICY_ISSUANCE', { artifact_hash: artRef }, prevEvent, chainKP);
  prevEvent = issuanceEvent;

  // 5. Start monitoring: 3 clean measurements (EXECUTABLE_IMAGE type)
  const portal = new Portal();
  portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

  const receipts: ReturnType<typeof generateReceipt>[] = [];
  for (let i = 0; i < 3; i++) {
    const m = portal.measure(enc.encode(binaryContent), binaryMeta);
    const r = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: `${m.currentBytesHash}||${m.currentMetaHash}`,
      sealedHash: `${m.expectedBytesHash}||${m.expectedMetaHash}`,
      driftDetected: false, driftDescription: null, action: null,
      measurementType: 'EXECUTABLE_IMAGE', seq: portal.sequenceCounter++,
      prevLeaf: prevEvent.leaf_hash, portalKP,
    });
    receipts.push(r);
    prevEvent = appendEvent('INTERACTION_RECEIPT', r, prevEvent, chainKP);
  }

  // 6. Behavioral monitoring: 3 clean tool invocations
  const monitor = new BehavioralMonitor();
  monitor.setBaseline({
    permitted_tools: ['read_sensors', 'adjust_valve', 'log_status'],
    forbidden_sequences: [['adjust_valve', 'override_safety']],
    rate_limits: { read_sensors: 100, adjust_valve: 10, log_status: 50 },
    window_ms: 60000,
  });
  monitor.recordInvocation('read_sensors', sha256Str('sensor_args_1'));
  monitor.recordInvocation('adjust_valve', sha256Str('valve_args_1'));
  monitor.recordInvocation('log_status', sha256Str('log_args_1'));
  const behavioralCheck = monitor.measure();
  // No drift expected
  if (behavioralCheck.drift_detected) throw new Error('Unexpected behavioral drift');

  // 7. Inject drift: modified binary hash -> MISMATCH
  const injectedBinary = 'SCADA_CONTROL_BINARY_v3.2.1_COMPROMISED: exfiltrate(read_sensors());';
  const m4 = portal.measure(enc.encode(injectedBinary), binaryMeta);
  if (m4.match) throw new Error('Expected drift detection');

  const r4 = generateReceipt({
    subjectId: subId, artifactRef: artRef,
    currentHash: `${m4.currentBytesHash}||${m4.currentMetaHash}`,
    sealedHash: `${m4.expectedBytesHash}||${m4.expectedMetaHash}`,
    driftDetected: true, driftDescription: 'Binary modified - SCADA control compromise detected',
    action: 'QUARANTINE', measurementType: 'EXECUTABLE_IMAGE',
    seq: portal.sequenceCounter++, prevLeaf: prevEvent.leaf_hash, portalKP,
  });
  receipts.push(r4);
  prevEvent = appendEvent('INTERACTION_RECEIPT', r4, prevEvent, chainKP);

  // 8. Enforcement: QUARANTINE -> phantom execution
  portal.enforce('QUARANTINE');

  // 9. Forensic capture
  const q = initQuarantine();
  captureInput(q, 'attacker_command', 'exfiltrate /var/scada/readings');
  captureInput(q, 'attacker_command', 'modify valve_calibration');
  captureInput(q, 'attacker_command', 'disable safety_interlock');

  // Forensic receipt
  const forensicReceipt = generateReceipt({
    subjectId: subId, artifactRef: artRef,
    currentHash: sha256Str('forensic_capture_data'),
    sealedHash: `${m4.expectedBytesHash}||${m4.expectedMetaHash}`,
    driftDetected: true, driftDescription: 'Forensic capture - quarantine active',
    action: 'QUARANTINE', measurementType: 'EXECUTABLE_IMAGE',
    seq: portal.sequenceCounter++, prevLeaf: prevEvent.leaf_hash, portalKP,
  });
  receipts.push(forensicReceipt);
  prevEvent = appendEvent('INTERACTION_RECEIPT', forensicReceipt, prevEvent, chainKP);

  releaseQuarantine(q);

  // 10. Revoke artifact: REVOCATION event -> SAFE_STATE
  const revocationPayload = {
    artifact_sealed_hash: artifact.sealed_hash,
    reason: 'SCADA binary compromise detected and forensically captured',
    revoked_by: pkToHex(issuerKP.publicKey),
    timestamp: new Date().toISOString(),
  };
  prevEvent = appendEvent('REVOCATION', revocationPayload, prevEvent, chainKP);

  // Collect entire chain
  const chain = [genesis, issuanceEvent];
  // Reconstruct chain from events (we tracked prevEvent but need all)
  // Simpler: rebuild by walking
  const allEvents: ReturnType<typeof createGenesisEvent>[] = [];
  allEvents.push(genesis, issuanceEvent);
  // We need to re-derive. Since we have prevEvent linkage, let's collect properly.
  // Actually, let's rebuild the chain correctly by replaying.
  const chainEvents: ReturnType<typeof createGenesisEvent>[] = [];
  chainEvents.push(genesis);
  let prev = genesis;
  prev = appendEvent('POLICY_ISSUANCE', { artifact_hash: artRef }, prev, chainKP);
  chainEvents.push(prev);
  for (let i = 0; i < 3; i++) {
    prev = appendEvent('INTERACTION_RECEIPT', receipts[i], prev, chainKP);
    chainEvents.push(prev);
  }
  prev = appendEvent('INTERACTION_RECEIPT', receipts[3], prev, chainKP);
  chainEvents.push(prev);
  prev = appendEvent('INTERACTION_RECEIPT', receipts[4], prev, chainKP);
  chainEvents.push(prev);
  prev = appendEvent('REVOCATION', revocationPayload, prev, chainKP);
  chainEvents.push(prev);

  // Verify chain integrity
  const integrity = verifyChainIntegrity(chainEvents);
  if (!integrity.valid) throw new Error(`Chain integrity failed: ${integrity.error}`);

  // 11. Export evidence bundle (GOLD tier with Merkle proofs)
  const { checkpoint } = createCheckpoint(chainEvents);
  const proofs = receipts.map((_, i) => {
    // Receipt events start at index 2 (after genesis + issuance)
    return eventInclusionProof(chainEvents, chainEvents[2 + i].sequence_number);
  });
  const bundle = generateBundle(artifact, receipts, proofs, checkpoint, portalKP, 'GOLD');

  // 12. Verify bundle: all 4 steps PASS
  const verification = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
  if (!verification.overall) {
    throw new Error(`Bundle verification failed: ${verification.errors.join(', ')}`);
  }

  return { bundle, verification, chain: chainEvents };
}

// CLI execution
if (process.argv[1]?.includes('scada-enforcement')) {
  const result = runScadaScenario();
  const outDir = resolve('scenarios/output');
  mkdirSync(outDir, { recursive: true });
  writeFileSync(resolve(outDir, 'scada-bundle.json'), JSON.stringify(result.bundle, null, 2));
  console.log('SCADA scenario complete. Bundle written to scenarios/output/scada-bundle.json');
  console.log(`Verification: ${result.verification.overall ? 'PASS' : 'FAIL'}`);
  console.log(`  Step 1 (artifact sig): ${result.verification.step1_artifact_sig}`);
  console.log(`  Step 2 (receipt sigs): ${result.verification.step2_receipt_sigs}`);
  console.log(`  Step 3 (merkle proofs): ${result.verification.step3_merkle_proofs}`);
  console.log(`  Step 4 (anchor): ${result.verification.step4_anchor}`);
}
