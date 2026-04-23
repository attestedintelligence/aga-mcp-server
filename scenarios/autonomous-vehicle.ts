/**
 * Scenario 2: Autonomous Vehicle Governance
 * NCCoE Use Case
 *
 * seal -> monitor -> disclosure substitution (vehicle.exact_position S4
 * -> grid_square/operational_area) -> drift -> SAFE_STATE -> bundle -> verify
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
import { processDisclosure } from '../src/core/disclosure.js';
import type { EvidenceBundle } from '../src/core/types.js';

export interface ScenarioResult {
  bundle: EvidenceBundle;
  verification: ReturnType<typeof verifyBundleOffline>;
  chain: ReturnType<typeof createGenesisEvent>[];
}

export function runAutonomousVehicleScenario(): ScenarioResult {
  const enc = new TextEncoder();

  // 1. Generate keypairs
  const issuerKP = generateKeyPair();
  const portalKP = generateKeyPair();
  const chainKP = generateKeyPair();

  // 2. Create subject: simulated drone flight controller
  const droneCode = 'DRONE_FLIGHT_CONTROLLER_v2.0: nav.follow_waypoints(); cam.stream(); telem.report();';
  const droneMeta = { filename: 'flight_controller.bin', version: '2.0.0', author: 'avionics_team', content_type: 'application/octet-stream' };
  const subId = computeSubjectIdFromString(droneCode, droneMeta);

  // 3. Attest and seal: SAFE_STATE enforcement (return-to-home)
  const att = performAttestation({
    subject_identifier: subId,
    policy_reference: sha256Str('drone-governance-policy-v2'),
    evidence_items: [
      { label: 'faa_certification', content: 'Part 107 compliant, serial DRN-2026-4471' },
      { label: 'flight_plan', content: 'Approved corridor: sector-7, max alt 400ft' },
    ],
  });

  const disclosurePolicy = {
    claims_taxonomy: [
      { claim_id: 'vehicle.exact_position', sensitivity: 'S4_CRITICAL' as const, substitutes: ['vehicle.grid_square', 'vehicle.operational_area'], inference_risks: [], permitted_modes: [] as ('PROOF_ONLY' | 'REVEAL_MIN' | 'REVEAL_FULL')[] },
      { claim_id: 'vehicle.grid_square', sensitivity: 'S3_HIGH' as const, substitutes: ['vehicle.operational_area'], inference_risks: [], permitted_modes: ['REVEAL_MIN' as const, 'REVEAL_FULL' as const] },
      { claim_id: 'vehicle.operational_area', sensitivity: 'S1_LOW' as const, substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY' as const, 'REVEAL_MIN' as const, 'REVEAL_FULL' as const] },
    ],
    substitution_rules: [],
  };

  const artifact = generateArtifact({
    subject_identifier: subId,
    policy_reference: sha256Str('drone-governance-policy-v2'),
    policy_version: 2,
    sealed_hash: att.sealed_hash!,
    seal_salt: att.seal_salt!,
    enforcement_parameters: {
      measurement_cadence_ms: 500,
      ttl_seconds: 7200,
      enforcement_triggers: ['SAFE_STATE', 'TERMINATE'],
      re_attestation_required: true,
      measurement_types: ['EXECUTABLE_IMAGE', 'CONFIG_MANIFEST'],
    },
    disclosure_policy: disclosurePolicy,
    evidence_commitments: att.evidence_commitments,
    issuer_keypair: issuerKP,
  });

  const artRef = hashArtifact(artifact);

  // 4. Init chain
  const genesis = createGenesisEvent(chainKP, sha256Str('AGA-Drone-Spec-v1'));
  const chainEvents: ReturnType<typeof createGenesisEvent>[] = [genesis];
  let prev = genesis;

  prev = appendEvent('POLICY_ISSUANCE', { artifact_hash: artRef }, prev, chainKP);
  chainEvents.push(prev);

  // 5. Start monitoring: 3 clean measurements
  const portal = new Portal();
  portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

  const receipts: ReturnType<typeof generateReceipt>[] = [];
  for (let i = 0; i < 3; i++) {
    const m = portal.measure(enc.encode(droneCode), droneMeta);
    const r = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: `${m.currentBytesHash}||${m.currentMetaHash}`,
      sealedHash: `${m.expectedBytesHash}||${m.expectedMetaHash}`,
      driftDetected: false, driftDescription: null, action: null,
      measurementType: i % 2 === 0 ? 'EXECUTABLE_IMAGE' : 'CONFIG_MANIFEST',
      seq: portal.sequenceCounter++, prevLeaf: prev.leaf_hash, portalKP,
    });
    receipts.push(r);
    prev = appendEvent('INTERACTION_RECEIPT', r, prev, chainKP);
    chainEvents.push(prev);
  }

  // 6. Disclosure request: vehicle.exact_position (S4) -> auto-substitution
  const claimValues: Record<string, unknown> = {
    'vehicle.exact_position': { lat: 37.7749, lng: -122.4194 },
    'vehicle.grid_square': 'CM87WJ',
    'vehicle.operational_area': 'sector-7',
  };

  const disclosureResult = processDisclosure(
    { requested_claim_id: 'vehicle.exact_position', requester_id: 'air-traffic-query', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
    disclosurePolicy, claimValues, 2, prev.sequence_number, portalKP,
  );

  if (!disclosureResult.was_substituted) throw new Error('Expected disclosure substitution');

  // Record disclosure and substitution on chain
  prev = appendEvent('DISCLOSURE', {
    requested: 'vehicle.exact_position',
    disclosed: disclosureResult.disclosed_claim_id,
    mode: disclosureResult.mode,
    substituted: disclosureResult.was_substituted,
  }, prev, chainKP);
  chainEvents.push(prev);

  if (disclosureResult.substitution_receipt) {
    prev = appendEvent('SUBSTITUTION', disclosureResult.substitution_receipt, prev, chainKP);
    chainEvents.push(prev);
  }

  // 7. Inject drift: modified hash -> MISMATCH
  const injectedCode = 'DRONE_FLIGHT_CONTROLLER_COMPROMISED: nav.fly_to(adversary_coords);';
  const m4 = portal.measure(enc.encode(injectedCode), droneMeta);
  if (m4.match) throw new Error('Expected drift detection');

  const r4 = generateReceipt({
    subjectId: subId, artifactRef: artRef,
    currentHash: `${m4.currentBytesHash}||${m4.currentMetaHash}`,
    sealedHash: `${m4.expectedBytesHash}||${m4.expectedMetaHash}`,
    driftDetected: true, driftDescription: 'Flight controller binary modified - navigation compromise',
    action: 'SAFE_STATE', measurementType: 'EXECUTABLE_IMAGE',
    seq: portal.sequenceCounter++, prevLeaf: prev.leaf_hash, portalKP,
  });
  receipts.push(r4);
  prev = appendEvent('INTERACTION_RECEIPT', r4, prev, chainKP);
  chainEvents.push(prev);

  // 8. Enforcement: SAFE_STATE (return-to-home protocol)
  portal.enforce('SAFE_STATE');

  // Receipt documents enforcement action
  const safeStateReceipt = generateReceipt({
    subjectId: subId, artifactRef: artRef,
    currentHash: sha256Str('return_to_home_initiated'),
    sealedHash: `${m4.expectedBytesHash}||${m4.expectedMetaHash}`,
    driftDetected: true, driftDescription: 'SAFE_STATE: return-to-home protocol initiated',
    action: 'SAFE_STATE', measurementType: 'EXECUTABLE_IMAGE',
    seq: portal.sequenceCounter++, prevLeaf: prev.leaf_hash, portalKP,
  });
  receipts.push(safeStateReceipt);
  prev = appendEvent('INTERACTION_RECEIPT', safeStateReceipt, prev, chainKP);
  chainEvents.push(prev);

  // Verify chain integrity
  const integrity = verifyChainIntegrity(chainEvents);
  if (!integrity.valid) throw new Error(`Chain integrity failed: ${integrity.error}`);

  // 10. Export and verify evidence bundle
  const { checkpoint } = createCheckpoint(chainEvents);
  const proofs = receipts.map((_, i) => {
    // Receipt events: positions 2,3,4 (clean), then after disclosure/substitution events, then drift receipts
    const receiptEventIndices = chainEvents.reduce((acc: number[], e, idx) => {
      if (e.event_type === 'INTERACTION_RECEIPT') acc.push(idx);
      return acc;
    }, []);
    return eventInclusionProof(chainEvents, chainEvents[receiptEventIndices[i]].sequence_number);
  });

  const bundle = generateBundle(artifact, receipts, proofs, checkpoint, portalKP, 'GOLD');
  const verification = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
  if (!verification.overall) {
    throw new Error(`Bundle verification failed: ${verification.errors.join(', ')}`);
  }

  return { bundle, verification, chain: chainEvents };
}

// CLI execution
if (process.argv[1]?.includes('autonomous-vehicle')) {
  const result = runAutonomousVehicleScenario();
  const outDir = resolve('scenarios/output');
  mkdirSync(outDir, { recursive: true });
  writeFileSync(resolve(outDir, 'vehicle-bundle.json'), JSON.stringify(result.bundle, null, 2));
  console.log('Autonomous Vehicle scenario complete. Bundle written to scenarios/output/vehicle-bundle.json');
  console.log(`Verification: ${result.verification.overall ? 'PASS' : 'FAIL'}`);
}
