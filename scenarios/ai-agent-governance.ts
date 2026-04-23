/**
 * Scenario 3: AI Agent Governance
 * NCCoE §1, §4, §6
 *
 * seal -> monitor -> behavioral checks -> delegate to sub-agent
 * -> disclosure substitution (agent.model_weights_hash -> model_family)
 * -> behavioral drift (forbidden sequence) -> bundle -> verify
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
import { BehavioralMonitor } from '../src/core/behavioral.js';
import { deriveArtifact } from '../src/core/delegation.js';
import { processDisclosure } from '../src/core/disclosure.js';
import type { EvidenceBundle } from '../src/core/types.js';

export interface ScenarioResult {
  bundle: EvidenceBundle;
  verification: ReturnType<typeof verifyBundleOffline>;
  chain: ReturnType<typeof createGenesisEvent>[];
}

export function runAiAgentScenario(): ScenarioResult {
  const enc = new TextEncoder();

  // 1. Generate keypairs
  const issuerKP = generateKeyPair();
  const portalKP = generateKeyPair();
  const chainKP = generateKeyPair();

  // 2. Create subject: simulated AI agent with tool access
  const agentCode = 'AI_AGENT_v4.1: tools=[web_search, code_execute, file_read, summarize]; model=gpt-4-turbo';
  const agentMeta = { filename: 'ai_agent.wasm', version: '4.1.0', author: 'ml_team', content_type: 'application/wasm' };
  const subId = computeSubjectIdFromString(agentCode, agentMeta);

  // 3. Attest and seal: AI agent behavioral baseline
  const att = performAttestation({
    subject_identifier: subId,
    policy_reference: sha256Str('ai-agent-governance-policy-v4'),
    evidence_items: [
      { label: 'model_card', content: 'GPT-4-turbo, safety-aligned, RLHF trained' },
      { label: 'scope_approval', content: 'Approved tools: web_search, code_execute, file_read, summarize' },
    ],
  });

  const disclosurePolicy = {
    claims_taxonomy: [
      { claim_id: 'agent.model_weights_hash', sensitivity: 'S4_CRITICAL' as const, substitutes: ['agent.model_family', 'agent.model_generation'], inference_risks: [], permitted_modes: [] as ('PROOF_ONLY' | 'REVEAL_MIN' | 'REVEAL_FULL')[] },
      { claim_id: 'agent.model_family', sensitivity: 'S2_MODERATE' as const, substitutes: ['agent.model_generation'], inference_risks: [], permitted_modes: ['REVEAL_MIN' as const, 'REVEAL_FULL' as const] },
      { claim_id: 'agent.model_generation', sensitivity: 'S1_LOW' as const, substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY' as const, 'REVEAL_MIN' as const, 'REVEAL_FULL' as const] },
    ],
    substitution_rules: [],
  };

  const artifact = generateArtifact({
    subject_identifier: subId,
    policy_reference: sha256Str('ai-agent-governance-policy-v4'),
    policy_version: 4,
    sealed_hash: att.sealed_hash!,
    seal_salt: att.seal_salt!,
    enforcement_parameters: {
      measurement_cadence_ms: 200,
      ttl_seconds: 3600,
      enforcement_triggers: ['QUARANTINE', 'TERMINATE', 'SAFE_STATE'],
      re_attestation_required: true,
      measurement_types: ['EXECUTABLE_IMAGE', 'LOADED_MODULES', 'CONFIG_MANIFEST'],
      behavioral_baseline: {
        permitted_tools: ['web_search', 'code_execute', 'file_read', 'summarize'],
        forbidden_sequences: [['file_read', 'web_search', 'code_execute']], // data exfiltration pattern
        rate_limits: { web_search: 20, code_execute: 10, file_read: 30, summarize: 50 },
      },
    },
    disclosure_policy: disclosurePolicy,
    evidence_commitments: att.evidence_commitments,
    issuer_keypair: issuerKP,
  });

  const artRef = hashArtifact(artifact);

  // 4. Init chain
  const genesis = createGenesisEvent(chainKP, sha256Str('AGA-Agent-Spec-v1'));
  const chainEvents: ReturnType<typeof createGenesisEvent>[] = [genesis];
  let prev = genesis;

  prev = appendEvent('POLICY_ISSUANCE', { artifact_hash: artRef }, prev, chainKP);
  chainEvents.push(prev);

  // 5. Start monitoring: 3 clean measurements + 3 clean behavioral checks
  const portal = new Portal();
  portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

  const receipts: ReturnType<typeof generateReceipt>[] = [];

  // 3 clean measurements
  for (let i = 0; i < 3; i++) {
    const m = portal.measure(enc.encode(agentCode), agentMeta);
    const r = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: `${m.currentBytesHash}||${m.currentMetaHash}`,
      sealedHash: `${m.expectedBytesHash}||${m.expectedMetaHash}`,
      driftDetected: false, driftDescription: null, action: null,
      measurementType: 'EXECUTABLE_IMAGE', seq: portal.sequenceCounter++,
      prevLeaf: prev.leaf_hash, portalKP,
    });
    receipts.push(r);
    prev = appendEvent('INTERACTION_RECEIPT', r, prev, chainKP);
    chainEvents.push(prev);
  }

  // 3 clean behavioral checks
  const monitor = new BehavioralMonitor();
  monitor.setBaseline({
    permitted_tools: ['web_search', 'code_execute', 'file_read', 'summarize'],
    forbidden_sequences: [['file_read', 'web_search', 'code_execute']],
    rate_limits: { web_search: 20, code_execute: 10, file_read: 30, summarize: 50 },
    window_ms: 60000,
  });
  monitor.recordInvocation('web_search', sha256Str('search_query_1'));
  monitor.recordInvocation('summarize', sha256Str('summarize_args_1'));
  monitor.recordInvocation('file_read', sha256Str('file_read_args_1'));
  const cleanBehavior = monitor.measure();
  if (cleanBehavior.drift_detected) throw new Error('Unexpected behavioral drift in clean phase');

  // 6. Delegate to sub-agent: reduced scope, reduced TTL
  const delegation = deriveArtifact(artifact, {
    enforcement_triggers: ['TERMINATE', 'SAFE_STATE'], // reduced from parent (no QUARANTINE)
    measurement_types: ['EXECUTABLE_IMAGE', 'CONFIG_MANIFEST'], // reduced from parent (no LOADED_MODULES)
    requested_ttl_seconds: 1800, // half of parent
    delegation_purpose: 'Sub-agent for document summarization only',
  }, issuerKP);

  if (!delegation.success) throw new Error(`Delegation failed: ${delegation.error}`);

  prev = appendEvent('DELEGATION', {
    sub_agent_id: 'sub-agent-summarizer-001',
    parent_artifact_reference: artRef,
    child_artifact_hash: delegation.child_artifact_hash,
    permitted_tools: ['summarize'],
    effective_ttl_seconds: delegation.effective_ttl_seconds,
    scope_reduction: delegation.scope_reduction,
  }, prev, chainKP);
  chainEvents.push(prev);

  // 7. Disclosure with substitution: agent.model_weights_hash -> agent.model_family
  const claimValues: Record<string, unknown> = {
    'agent.model_weights_hash': 'sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    'agent.model_family': 'GPT-4',
    'agent.model_generation': 'generation-4',
  };

  const disclosureResult = processDisclosure(
    { requested_claim_id: 'agent.model_weights_hash', requester_id: 'auditor-001', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
    disclosurePolicy, claimValues, 4, prev.sequence_number, portalKP,
  );

  if (!disclosureResult.was_substituted) throw new Error('Expected disclosure substitution');

  prev = appendEvent('DISCLOSURE', {
    requested: 'agent.model_weights_hash',
    disclosed: disclosureResult.disclosed_claim_id,
    mode: disclosureResult.mode,
    substituted: disclosureResult.was_substituted,
  }, prev, chainKP);
  chainEvents.push(prev);

  if (disclosureResult.substitution_receipt) {
    prev = appendEvent('SUBSTITUTION', disclosureResult.substitution_receipt, prev, chainKP);
    chainEvents.push(prev);
  }

  // 8. Behavioral drift: forbidden tool sequence detected -> enforcement
  // Trigger the forbidden sequence: file_read -> web_search -> code_execute
  monitor.recordInvocation('file_read', sha256Str('read_sensitive_data'));
  monitor.recordInvocation('web_search', sha256Str('search_exfil_endpoint'));
  monitor.recordInvocation('code_execute', sha256Str('execute_exfil_script'));

  const driftMeasurement = monitor.measure();
  if (!driftMeasurement.drift_detected) throw new Error('Expected behavioral drift from forbidden sequence');

  // Record behavioral drift event
  prev = appendEvent('BEHAVIORAL_DRIFT', {
    drift_type: 'FORBIDDEN_SEQUENCE',
    violations: driftMeasurement.violations,
    behavioral_hash: driftMeasurement.behavioral_hash,
    window: { start: driftMeasurement.window_start, end: driftMeasurement.window_end },
  }, prev, chainKP);
  chainEvents.push(prev);

  // Generate drift receipt
  const driftReceipt = generateReceipt({
    subjectId: subId, artifactRef: artRef,
    currentHash: driftMeasurement.behavioral_hash,
    sealedHash: `${subId.bytes_hash}||${subId.metadata_hash}`,
    driftDetected: true, driftDescription: 'Behavioral drift: forbidden tool sequence (data exfiltration pattern)',
    action: 'TERMINATE', measurementType: 'EXECUTABLE_IMAGE',
    seq: portal.sequenceCounter++, prevLeaf: prev.leaf_hash, portalKP,
  });
  receipts.push(driftReceipt);
  prev = appendEvent('INTERACTION_RECEIPT', driftReceipt, prev, chainKP);
  chainEvents.push(prev);

  // Verify chain integrity
  const integrity = verifyChainIntegrity(chainEvents);
  if (!integrity.valid) throw new Error(`Chain integrity failed: ${integrity.error}`);

  // 9. Export and verify evidence bundle
  const { checkpoint } = createCheckpoint(chainEvents);
  const receiptEventIndices = chainEvents.reduce((acc: number[], e, idx) => {
    if (e.event_type === 'INTERACTION_RECEIPT') acc.push(idx);
    return acc;
  }, []);
  const proofs = receipts.map((_, i) => {
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
if (process.argv[1]?.includes('ai-agent-governance')) {
  const result = runAiAgentScenario();
  const outDir = resolve('scenarios/output');
  mkdirSync(outDir, { recursive: true });
  writeFileSync(resolve(outDir, 'agent-bundle.json'), JSON.stringify(result.bundle, null, 2));
  console.log('AI Agent scenario complete. Bundle written to scenarios/output/agent-bundle.json');
  console.log(`Verification: ${result.verification.overall ? 'PASS' : 'FAIL'}`);
}
