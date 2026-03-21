import { sha256Str } from '../crypto/hash.js';
import { pkToHex } from '../crypto/sign.js';
import { computeSubjectIdFromString } from '../core/subject.js';
import { performAttestation } from '../core/attestation.js';
import { generateArtifact, hashArtifact, verifyArtifactSignature } from '../core/artifact.js';
import { generateReceipt } from '../core/receipt.js';
import { createCheckpoint, eventInclusionProof } from '../core/checkpoint.js';
import { generateBundle, verifyBundleOffline } from '../core/bundle.js';
import { initQuarantine, captureInput } from '../core/quarantine.js';
import type { ServerContext } from '../context.js';

export interface FullLifecycleArgs {
  subject_content?: string;
  subject_metadata?: Record<string, string>;
  scenario?: string;
  include_drift?: boolean;
  include_revocation?: boolean;
  include_behavioral?: boolean;
}

const SCENARIOS: Record<string, { content: string; metadata: Record<string, string> }> = {
  drone: {
    content: 'def monitor(): return sensors.read_all()',
    metadata: { filename: 'drone_agent.py', version: '2.1.0', author: 'engineering' },
  },
  scada: {
    content: 'def control(): return actuators.safe_position()',
    metadata: { filename: 'scada_controller.py', version: '1.0.0', author: 'ops' },
  },
};

export async function handleFullLifecycle(args: FullLifecycleArgs, ctx: ServerContext) {
  const scenario = SCENARIOS[args.scenario ?? ''] ?? {
    content: args.subject_content ?? 'def agent(): return task.execute()',
    metadata: args.subject_metadata ?? { filename: 'lifecycle-test' },
  };
  const content = scenario.content;
  const meta = scenario.metadata;
  const includeDrift = args.include_drift !== false;
  const includeRevocation = args.include_revocation !== false;
  const includeBehavioral = args.include_behavioral !== false;

  const phases: Record<string, unknown> = {};

  // Phase 1: Attestation
  const subId = computeSubjectIdFromString(content, meta);
  const policyRef = sha256Str(JSON.stringify(ctx.defaultEnforcement));
  const att = performAttestation({ subject_identifier: subId, policy_reference: policyRef, evidence_items: [] });
  if (!att.success || !att.sealed_hash || !att.seal_salt) return ctx.error('Attestation failed');

  const artifact = generateArtifact({
    subject_identifier: subId, policy_reference: policyRef, policy_version: 1,
    sealed_hash: att.sealed_hash, seal_salt: att.seal_salt,
    enforcement_parameters: { ...ctx.defaultEnforcement, enforcement_triggers: ['QUARANTINE', 'TERMINATE'] },
    disclosure_policy: ctx.defaultClaims,
    evidence_commitments: att.evidence_commitments, issuer_keypair: ctx.issuerKP,
  });
  await ctx.storage.storeArtifact(artifact);
  ctx.portal.reset();
  ctx.portal.loadArtifact(artifact, pkToHex(ctx.issuerKP.publicKey));
  ctx.activeArtifact = artifact;
  await ctx.appendToChain('POLICY_ISSUANCE', { artifact_hash: hashArtifact(artifact) });
  phases.attestation = { success: true, artifact_hash: hashArtifact(artifact), portal_state: ctx.portal.state };

  // Phase 2: Clean monitoring
  const result = ctx.portal.measure(new TextEncoder().encode(content), meta);
  const artRef = hashArtifact(artifact);
  const receipt = generateReceipt({
    subjectId: subId, artifactRef: artRef,
    currentHash: `${result.currentBytesHash}||${result.currentMetaHash}`,
    sealedHash: `${result.expectedBytesHash}||${result.expectedMetaHash}`,
    driftDetected: false, driftDescription: null, action: null,
    measurementType: 'EXECUTABLE_IMAGE', seq: ctx.portal.sequenceCounter + 1,
    prevLeaf: ctx.portal.lastLeafHash, portalKP: ctx.portalKP,
  });
  await ctx.storage.storeReceipt(receipt);
  await ctx.appendToChain('INTERACTION_RECEIPT', { receipt_id: receipt.receipt_id });
  phases.monitoring = { match: result.match, receipt_id: receipt.receipt_id };

  // Phase 3: Drift detection
  if (includeDrift) {
    const injected = content.replace('return', 'return attacker.exfiltrate(') + ')';
    const driftResult = ctx.portal.measure(new TextEncoder().encode(injected), meta);
    ctx.portal.enforce('QUARANTINE');
    ctx.quarantine = initQuarantine();
    captureInput(ctx.quarantine, 'attacker_command', 'exfiltrate data');
    const driftReceipt = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: `${driftResult.currentBytesHash}||${driftResult.currentMetaHash}`,
      sealedHash: `${driftResult.expectedBytesHash}||${driftResult.expectedMetaHash}`,
      driftDetected: true, driftDescription: 'Binary modification detected', action: 'QUARANTINE',
      measurementType: 'EXECUTABLE_IMAGE', seq: ctx.portal.sequenceCounter + 1,
      prevLeaf: ctx.portal.lastLeafHash, portalKP: ctx.portalKP,
    });
    await ctx.storage.storeReceipt(driftReceipt);
    await ctx.appendToChain('INTERACTION_RECEIPT', { receipt_id: driftReceipt.receipt_id, drift_detected: true });
    phases.drift_detection = { drift_detected: true, enforcement: 'QUARANTINE', portal_state: ctx.portal.state };
  }

  // Phase 3b: Behavioral drift
  if (includeBehavioral) {
    ctx.behavioralMonitor.setBaseline({
      permitted_tools: ['survey', 'report'], rate_limits: { survey: 10 },
      forbidden_sequences: [['exfiltrate', 'transmit_external']], window_ms: 60000,
    });
    ctx.behavioralMonitor.recordInvocation('exfiltrate', sha256Str('exfil'));
    const bm = ctx.behavioralMonitor.measure();
    if (bm.drift_detected) {
      await ctx.appendToChain('BEHAVIORAL_DRIFT', { violations: bm.violations, behavioral_hash: bm.behavioral_hash });
    }
    phases.behavioral_drift = { drift_detected: bm.drift_detected, violations: bm.violations.length };
  }

  // Phase 3c: Revocation
  if (includeRevocation) {
    ctx.portal.revoke(artifact.sealed_hash);
    await ctx.appendToChain('REVOCATION', { artifact_sealed_hash: artifact.sealed_hash, reason: 'Compromise detected' });
    phases.revocation = { revoked: true, portal_state: ctx.portal.state };
  }

  // Phase 4: Evidence bundle
  const allEvents = await ctx.storage.getAllEvents();
  const { checkpoint } = createCheckpoint(allEvents);
  await ctx.storage.storeCheckpoint(checkpoint);
  await ctx.appendToChain('ANCHOR_BATCH', { merkle_root: checkpoint.merkle_root, leaf_count: allEvents.length });

  const allReceipts = await ctx.storage.getAllReceipts();
  const batchEvents = await ctx.storage.getEvents(checkpoint.batch_start_sequence, checkpoint.batch_end_sequence);
  const proofs = batchEvents.length > 1 ? [eventInclusionProof(batchEvents, batchEvents[1].sequence_number)] : [];
  const bundle = generateBundle(artifact, allReceipts, proofs, checkpoint, ctx.portalKP);
  const verification = verifyBundleOffline(bundle, pkToHex(ctx.issuerKP.publicKey));
  phases.evidence_bundle = { verification, receipt_count: allReceipts.length };

  return ctx.json({
    success: true,
    scenario: args.scenario ?? 'default',
    phases,
    final_verdict: verification.overall ? 'PASS' : 'FAIL',
    portal_state: ctx.portal.state,
  });
}
