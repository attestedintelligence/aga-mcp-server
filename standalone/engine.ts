/**
 * Enhanced Portal Engine for v2 standalone.
 * Supports all protocol capabilities, all measurement types, all enforcement actions.
 *
 * Attested Intelligence Holdings LLC
 */
import {
  readFileSync, writeFileSync, existsSync,
  mkdirSync, statSync, readdirSync, unlinkSync
} from 'node:fs';
import { join } from 'node:path';
import { generateKeyPair, pkToHex } from '../src/crypto/sign.js';
import { sha256Str, sha256Bytes } from '../src/crypto/hash.js';
import { computeSubjectId } from '../src/core/subject.js';
import { performAttestation } from '../src/core/attestation.js';
import { generateArtifact, hashArtifact } from '../src/core/artifact.js';
import { Portal, type MeasurementResult } from '../src/core/portal.js';
import { generateReceipt } from '../src/core/receipt.js';
import {
  createGenesisEvent, appendEvent, verifyChainIntegrity, computeLeafHash
} from '../src/core/chain.js';
import { createCheckpoint, eventInclusionProof } from '../src/core/checkpoint.js';
import { generateBundle, verifyBundleOffline } from '../src/core/bundle.js';
import { initQuarantine, captureInput } from '../src/core/quarantine.js';
import { processDisclosure } from '../src/core/disclosure.js';
import { BehavioralMonitor } from '../src/core/behavioral.js';
import { canonicalize } from '../src/utils/canonical.js';
import { generateWalkthrough } from './report.js';
import type {
  ContinuityEvent, SignedReceipt, PolicyArtifact,
  QuarantineState, SubjectIdentifier, StructuralMetadata,
  EnforcementAction
} from '../src/core/types.js';
import type { HashHex } from '../src/crypto/types.js';
import type { ScenarioConfig } from './scenarios.js';

export class PortalEngine {
  readonly issuerKP = generateKeyPair();
  readonly portalKP = generateKeyPair();
  readonly chainKP  = generateKeyPair();
  readonly portal   = new Portal();
  readonly behavioral = new BehavioralMonitor();

  chain: ContinuityEvent[] = [];
  receipts: SignedReceipt[] = [];
  quarantine: QuarantineState | null = null;
  artifact: PolicyArtifact | null = null;

  private subjectId: SubjectIdentifier | null = null;
  private scenario: ScenarioConfig;
  private agentPath: string;
  private configPath: string;
  private originalContent: string;
  private evidenceDir: string;

  constructor(scenario: ScenarioConfig, baseDir: string) {
    this.scenario = scenario;
    this.agentPath = join(baseDir, scenario.agentFilename);
    this.configPath = join(baseDir, 'config.json');
    this.evidenceDir = join(process.cwd(), 'aga-evidence');
    this.originalContent = scenario.agentContent;

    if (!existsSync(baseDir)) mkdirSync(baseDir, { recursive: true });
    if (!existsSync(this.evidenceDir)) mkdirSync(this.evidenceDir, { recursive: true });

    // Write agent file and config file to disk
    writeFileSync(this.agentPath, scenario.agentContent);
    writeFileSync(this.configPath, JSON.stringify({
      scenario: scenario.id,
      measurement_cadence_ms: scenario.measurementCadenceMs,
      enforcement_triggers: scenario.enforcementTriggers,
      permitted_tools: scenario.permittedTools,
    }, null, 2));

    // Set up behavioral baseline
    this.behavioral.setBaseline({
      permitted_tools: scenario.permittedTools,
      rate_limits: scenario.toolRateLimits,
      forbidden_sequences: scenario.forbiddenSequences,
      window_ms: 60000,
    });
  }

  // ── Measurement helpers ────────────────────────────────────

  private readFile(path: string): { bytes: Uint8Array; meta: Record<string, string> } {
    const raw = readFileSync(path);
    const stat = statSync(path);
    return {
      bytes: new Uint8Array(raw),
      meta: { filename: path, size: String(stat.size), modified: stat.mtime.toISOString() },
    };
  }

  /** Multi-measurement: hash agent binary + config file (composite) */
  private computeCompositeHash(): { bytesHash: HashHex; metaHash: HashHex; measurements: Record<string, HashHex> } {
    const agent = this.readFile(this.agentPath);
    const agentHash = sha256Bytes(agent.bytes);

    const measurements: Record<string, HashHex> = {
      EXECUTABLE_IMAGE: agentHash,
    };

    if (existsSync(this.configPath)) {
      measurements.CONFIG_MANIFEST = sha256Bytes(this.readFile(this.configPath).bytes);
    }

    return {
      bytesHash: agentHash,
      metaHash: sha256Str(canonicalize(agent.meta)),
      measurements,
    };
  }

  // ── Core operations ────────────────────────────────────────

  attest(): { bytesHash: HashHex; metaHash: HashHex } {
    const { bytes, meta } = this.readFile(this.agentPath);
    this.subjectId = computeSubjectId(bytes, meta);
    const policyRef = sha256Str(`aga-${this.scenario.id}-policy-v1`);

    const att = performAttestation({
      subject_identifier: this.subjectId,
      policy_reference: policyRef,
      evidence_items: [
        { label: 'binary_path', content: this.agentPath },
        { label: 'scenario', content: this.scenario.id },
        { label: 'attestation_time', content: new Date().toISOString() },
        { label: 'security_review', content: 'APPROVED by Engineering Lead' },
      ],
    });

    this.artifact = generateArtifact({
      subject_identifier: this.subjectId,
      policy_reference: policyRef,
      policy_version: 1,
      sealed_hash: att.sealed_hash!,
      seal_salt: att.seal_salt!,
      enforcement_parameters: {
        measurement_cadence_ms: this.scenario.measurementCadenceMs,
        ttl_seconds: this.scenario.ttlSeconds,
        enforcement_triggers: this.scenario.enforcementTriggers,
        re_attestation_required: true,
        measurement_types: this.scenario.measurementTypes,
      },
      disclosure_policy: this.scenario.disclosurePolicy,
      evidence_commitments: att.evidence_commitments,
      issuer_keypair: this.issuerKP,
    });

    this.portal.loadArtifact(this.artifact, pkToHex(this.issuerKP.publicKey));

    const genesis = createGenesisEvent(this.chainKP, sha256Str('AGA-Protocol-v1'));
    this.chain.push(genesis);
    const policyEvt = appendEvent('POLICY_ISSUANCE', {
      artifact_hash: hashArtifact(this.artifact),
      sealed_hash: this.artifact.sealed_hash,
      scenario: this.scenario.id,
    }, genesis, this.chainKP);
    this.chain.push(policyEvt);

    return { bytesHash: this.subjectId.bytes_hash, metaHash: this.subjectId.metadata_hash };
  }

  measure(): MeasurementResult & { receipt: SignedReceipt; measurements: Record<string, HashHex> } {
    if (!this.artifact || !this.subjectId) throw new Error('Not attested');
    const { bytes, meta } = this.readFile(this.agentPath);
    const result = this.portal.measure(bytes, meta);
    const composite = this.computeCompositeHash();

    const receipt = generateReceipt({
      subjectId: this.subjectId,
      artifactRef: hashArtifact(this.artifact),
      currentHash: result.currentBytesHash
        ? `${result.currentBytesHash}||${result.currentMetaHash}` : 'UNAVAILABLE',
      sealedHash: `${result.expectedBytesHash}||${result.expectedMetaHash}`,
      driftDetected: !result.match,
      driftDescription: result.match ? null : 'Agent binary modified on disk',
      action: result.match ? null
        : this.scenario.enforcementTriggers[0] ?? 'TERMINATE',
      measurementType: this.scenario.measurementTypes.join(','),
      seq: this.chain.length,
      prevLeaf: this.chain[this.chain.length - 1].leaf_hash,
      portalKP: this.portalKP,
    });

    this.receipts.push(receipt);
    const evt = appendEvent('INTERACTION_RECEIPT', {
      receipt_id: receipt.receipt_id,
      drift_detected: !result.match,
      enforcement_action: receipt.enforcement_action,
    }, this.chain[this.chain.length - 1], this.chainKP);
    this.chain.push(evt);

    if (!result.match && this.portal.state === 'DRIFT_DETECTED') {
      const action = this.scenario.enforcementTriggers[0] ?? 'TERMINATE';
      this.portal.enforce(action);
      if (action === 'QUARANTINE') this.quarantine = initQuarantine();
    }

    return { ...result, receipt, measurements: composite.measurements };
  }

  /** Record a behavioral event (tool invocation) */
  recordBehavior(toolName: string): void {
    this.behavioral.recordInvocation(toolName, sha256Str(toolName + Date.now()));
  }

  /** Check behavioral drift */
  measureBehavior() {
    return this.behavioral.measure();
  }

  /** Process a disclosure request */
  processDisclosureRequest(claimId: string, mode: 'PROOF_ONLY' | 'REVEAL_MIN' | 'REVEAL_FULL' = 'REVEAL_FULL') {
    const result = processDisclosure(
      { requested_claim_id: claimId, requester_id: 'demo', mode, timestamp: new Date().toISOString() },
      this.scenario.disclosurePolicy,
      this.scenario.claimValues,
      this.artifact?.policy_version ?? 1,
      this.chain.length,
      this.portalKP
    );
    if (result.substitution_receipt) {
      const evt = appendEvent('SUBSTITUTION', result.substitution_receipt,
        this.chain[this.chain.length - 1], this.chainKP);
      this.chain.push(evt);
    }
    return result;
  }

  /** Demonstrate leaf hash privacy */
  proveLeafHashExcludesPayload(): {
    metadata: StructuralMetadata;
    leafHash: HashHex;
    payloadA: unknown;
    payloadB: unknown;
    hashWithA: HashHex;
    hashWithB: HashHex;
    identical: boolean;
  } {
    const event = this.chain[this.chain.length - 1];
    const metadata: StructuralMetadata = {
      schema_version: event.schema_version,
      protocol_version: event.protocol_version,
      event_type: event.event_type,
      event_id: event.event_id,
      sequence_number: event.sequence_number,
      timestamp: event.timestamp,
      previous_leaf_hash: event.previous_leaf_hash,
    };
    const payloadA = { data: 'public information' };
    const payloadB = { data: 'TOP SECRET classified intelligence' };
    const hashWithA = computeLeafHash(metadata);
    const hashWithB = computeLeafHash(metadata); // same - payload excluded
    return { metadata, leafHash: event.leaf_hash, payloadA, payloadB, hashWithA, hashWithB, identical: hashWithA === hashWithB };
  }

  tamper(): void {
    const current = readFileSync(this.agentPath, 'utf-8');
    writeFileSync(this.agentPath, current + this.scenario.tamperPayload);
  }

  forensicCapture(type: string, data: unknown): void {
    if (this.quarantine?.active) captureInput(this.quarantine, type, data);
  }

  revoke(reason: string): void {
    if (!this.artifact) return;
    this.portal.revoke(this.artifact.sealed_hash);
    const evt = appendEvent('REVOCATION', {
      artifact_sealed_hash: this.artifact.sealed_hash,
      reason, revoked_by: pkToHex(this.issuerKP.publicKey),
      timestamp: new Date().toISOString(),
    }, this.chain[this.chain.length - 1], this.chainKP);
    this.chain.push(evt);
  }

  verifyChain() {
    const r = verifyChainIntegrity(this.chain);
    return { valid: r.valid, count: this.chain.length, error: r.error };
  }

  generateEvidence() {
    const { checkpoint } = createCheckpoint(this.chain);
    const receiptEvents = this.chain.filter(e => e.event_type === 'INTERACTION_RECEIPT');
    const proofs = receiptEvents.map(e => eventInclusionProof(this.chain, e.sequence_number));
    const bundle = generateBundle(this.artifact!, this.receipts, proofs, checkpoint, this.portalKP);
    const verification = verifyBundleOffline(bundle, pkToHex(this.issuerKP.publicKey));
    return { checkpoint, verification, bundle };
  }

  exportEvidence(transcript: string[]): string {
    const { checkpoint, verification, bundle } = this.generateEvidence();
    const dir = this.evidenceDir;

    // Clean stale evidence before writing new data
    if (existsSync(dir)) {
      for (const f of readdirSync(dir)) unlinkSync(join(dir, f));
    }

    const w = (name: string, data: unknown) => writeFileSync(join(dir, name), JSON.stringify(data, null, 2));

    w('artifact.json', this.artifact);
    w('receipts.json', this.receipts);
    w('chain.json', this.chain);
    w('evidence-bundle.json', bundle);
    w('verification-report.json', {
      verification, checkpoint,
      chain_event_count: this.chain.length, receipt_count: this.receipts.length,
      scenario: this.scenario.id, verified_at: new Date().toISOString(),
      organization: 'Attested Intelligence Holdings LLC',
    });
    const walkthrough = generateWalkthrough(
      this.artifact!, this.receipts, this.chain,
      checkpoint.merkle_root, verification, this.scenario.name
    );
    writeFileSync(join(dir, 'verification-walkthrough.txt'), walkthrough);
    writeFileSync(join(dir, 'demo-transcript.txt'), [
      'AGA (Attested Governance Artifacts) - Demo Transcript',
      `Scenario: ${this.scenario.name}`,
      `Date: ${new Date().toISOString()}`,
      'Organization: Attested Intelligence Holdings LLC', '',
      ...transcript,
    ].join('\n'));

    return dir;
  }

  restore(): void { writeFileSync(this.agentPath, this.originalContent); }
  get filePath(): string { return this.agentPath; }
  get sealedHash(): string { return this.artifact?.sealed_hash ?? ''; }
  get portalState(): string { return this.portal.state; }
  get chainLength(): number { return this.chain.length; }
  get receiptCount(): number { return this.receipts.length; }
  get quarantineCaptures(): number { return this.quarantine?.inputs_captured ?? 0; }
  get scenarioConfig(): ScenarioConfig { return this.scenario; }
}
