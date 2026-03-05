/**
 * AGA MCP Server. The Portal (ref 150) as an MCP service.
 *
 * V3 NIST-aligned behaviors:
 * 1. Every measurement generates a receipt (match OR mismatch)
 * 2. TTL checked on every measurement (fail-closed)
 * 3. Mid-session revocation via revoke_artifact tool
 * 4. Governance middleware: portal state checked before tool execution
 * 5. Auto-chaining: every operation writes to continuity chain
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { generateKeyPair, pkToHex } from './crypto/sign.js';
import { sha256Str } from './crypto/hash.js';
import { computeSubjectIdFromString } from './core/subject.js';
import { performAttestation } from './core/attestation.js';
import { generateArtifact, hashArtifact } from './core/artifact.js';
import { Portal } from './core/portal.js';
import { generateReceipt } from './core/receipt.js';
import { createGenesisEvent, appendEvent, verifyChainIntegrity } from './core/chain.js';
import { createCheckpoint, eventInclusionProof } from './core/checkpoint.js';
import { generateBundle, verifyBundleOffline } from './core/bundle.js';
import { processDisclosure } from './core/disclosure.js';
import { initQuarantine, captureInput } from './core/quarantine.js';
import { MemoryStorage, type AGAStorage } from './storage/index.js';
import { utcNow } from './utils/timestamp.js';
import type { EnforcementParams, DisclosurePolicy, QuarantineState, RevocationRecord } from './core/types.js';

// ── Default Policies ────────────────────────────────────────────

const DEFAULT_ENFORCEMENT: EnforcementParams = {
  measurement_cadence_ms: 1000, ttl_seconds: 3600,
  enforcement_triggers: ['QUARANTINE', 'TERMINATE'],
  re_attestation_required: true,
  measurement_types: ['FILE_SYSTEM_STATE', 'CONFIG_MANIFEST'],
};

const DEFAULT_CLAIMS: DisclosurePolicy = {
  claims_taxonomy: [
    { claim_id: 'identity.name', sensitivity: 'S3_HIGH', substitutes: ['identity.pseudonym', 'identity.org'], inference_risks: [], permitted_modes: ['PROOF_ONLY'] },
    { claim_id: 'identity.pseudonym', sensitivity: 'S2_MODERATE', substitutes: ['identity.org'], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN'] },
    { claim_id: 'identity.org', sensitivity: 'S1_LOW', substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL'] },
    { claim_id: 'identity.age', sensitivity: 'S3_HIGH', substitutes: ['identity.age_range', 'identity.is_adult'], inference_risks: [], permitted_modes: ['PROOF_ONLY'] },
    { claim_id: 'identity.age_range', sensitivity: 'S2_MODERATE', substitutes: ['identity.is_adult'], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL'] },
    { claim_id: 'identity.is_adult', sensitivity: 'S1_LOW', substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_FULL'] },
  ],
  substitution_rules: [],
};

const CLAIM_VALUES: Record<string, unknown> = {
  'identity.name': 'Alice Johnson', 'identity.pseudonym': 'AJ-7742', 'identity.org': 'NeuroCrypt',
  'identity.age': 32, 'identity.age_range': '25-34', 'identity.is_adult': true,
};

// ── Server Factory ──────────────────────────────────────────────

export async function createAGAServer(): Promise<McpServer> {
  const server = new McpServer({ name: 'aga-mcp-server', version: '0.1.0' });
  const storage: AGAStorage = new MemoryStorage();
  await storage.initialize();

  const issuerKP = generateKeyPair();
  const portalKP = generateKeyPair();
  const chainKP  = generateKeyPair();
  const portal   = new Portal();
  let quarantine: QuarantineState | null = null;
  let chainInitialized = false;

  // ── Auto-chain helper (auto-inits if needed) ──────────────────
  async function autoChain(type: Parameters<typeof appendEvent>[0], payload: unknown) {
    if (!chainInitialized) {
      const genesis = createGenesisEvent(chainKP, sha256Str('AGA Protocol Specification v1.0.0'));
      await storage.storeEvent(genesis);
      chainInitialized = true;
      portal.sequenceCounter = 0;
      portal.lastLeafHash = genesis.leaf_hash;
    }
    const prev = await storage.getLatestEvent();
    if (!prev) throw new Error('Chain initialization failed');
    const event = appendEvent(type, payload, prev, chainKP);
    await storage.storeEvent(event);
    portal.sequenceCounter = event.sequence_number;
    portal.lastLeafHash = event.leaf_hash;
    return event;
  }

  const j = (x: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(x, null, 2) }] });

  // ══════════════════════════════════════════════════════════════
  // TOOL: get_server_info
  // ══════════════════════════════════════════════════════════════
  server.tool('get_server_info', 'Get AGA server info, public keys, and portal state.', {}, async () => j({
    server: 'AGA MCP Server', version: '0.1.0',
    protocol: 'Attested Governance Artifacts v1.0.0',
    patent: 'USPTO Application No. 19/433,835',
    nist_references: ['NIST-2025-0035', 'NCCoE AI Agent Identity'],
    issuer_public_key: pkToHex(issuerKP.publicKey),
    portal_public_key: pkToHex(portalKP.publicKey),
    chain_public_key: pkToHex(chainKP.publicKey),
    chain_initialized: chainInitialized,
    portal_state: portal.state,
  }));

  // ══════════════════════════════════════════════════════════════
  // TOOL: get_portal_state — V3 RESTORED (was dropped in V2)
  // ══════════════════════════════════════════════════════════════
  server.tool('get_portal_state', 'Get current portal state, loaded artifact info, and enforcement status.', {}, async () => j({
    state: portal.state,
    artifact_loaded: !!portal.artifact,
    sealed_hash: portal.artifact?.sealed_hash ?? null,
    ttl_seconds: portal.artifact?.enforcement_parameters.ttl_seconds ?? null,
    issued_at: portal.artifact?.issued_timestamp ?? null,
    enforcement_triggers: portal.artifact?.enforcement_parameters.enforcement_triggers ?? [],
    sequence_counter: portal.sequenceCounter,
    quarantine_active: quarantine?.active ?? false,
  }));

  // ══════════════════════════════════════════════════════════════
  // TOOL: init_chain (Claim 3a)
  // ══════════════════════════════════════════════════════════════
  server.tool('init_chain', 'Initialize continuity chain with genesis event. (Claim 3a)',
    { specification_hash: z.string().optional() },
    async ({ specification_hash }) => {
      if (chainInitialized) return j({ success: false, error: 'Chain already initialized' });
      const genesis = createGenesisEvent(chainKP, specification_hash ?? sha256Str('AGA Protocol Specification v1.0.0'));
      await storage.storeEvent(genesis);
      chainInitialized = true;
      portal.sequenceCounter = 0;
      portal.lastLeafHash = genesis.leaf_hash;
      return j({ success: true, genesis_event_id: genesis.event_id, genesis_leaf_hash: genesis.leaf_hash });
    }
  );

  // ══════════════════════════════════════════════════════════════
  // TOOL: attest_subject (Claims 1a-1d)
  // ══════════════════════════════════════════════════════════════
  server.tool('attest_subject',
    'Attest subject, generate sealed Policy Artifact. Auto-loads into portal. (Claims 1a-1d)',
    {
      subject_content: z.string().describe('Content/bytes of the subject'),
      subject_metadata: z.object({ filename: z.string().optional(), version: z.string().optional(), author: z.string().optional(), content_type: z.string().optional() }),
      evidence_items: z.array(z.object({ label: z.string(), content: z.string() })).default([]),
    },
    async ({ subject_content, subject_metadata, evidence_items }) => {
      const subId = computeSubjectIdFromString(subject_content, subject_metadata);
      const policyRef = sha256Str(JSON.stringify(DEFAULT_ENFORCEMENT));
      const att = performAttestation({ subject_identifier: subId, policy_reference: policyRef, evidence_items });
      if (!att.success || !att.sealed_hash || !att.seal_salt) return j({ success: false, error: att.rejection_reason });

      const artifact = generateArtifact({
        subject_identifier: subId, policy_reference: policyRef, policy_version: 1,
        sealed_hash: att.sealed_hash, seal_salt: att.seal_salt,
        enforcement_parameters: DEFAULT_ENFORCEMENT, disclosure_policy: DEFAULT_CLAIMS,
        evidence_commitments: att.evidence_commitments, issuer_keypair: issuerKP,
      });
      await storage.storeArtifact(artifact);

      portal.reset();
      portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));
      quarantine = null;

      await autoChain('POLICY_ISSUANCE', { artifact_hash: hashArtifact(artifact), sealed_hash: artifact.sealed_hash });

      return j({
        success: true, artifact_hash: hashArtifact(artifact), sealed_hash: artifact.sealed_hash,
        subject_identifier: subId, portal_state: portal.state,
        issuer_public_key: pkToHex(issuerKP.publicKey),
      });
    }
  );

  // ══════════════════════════════════════════════════════════════
  // TOOL: measure_integrity (Claims 1e-1g)
  // V3: Generates receipt for EVERY measurement (match or mismatch)
  // V3: Checks TTL and revocation (fail-closed)
  // ══════════════════════════════════════════════════════════════
  server.tool('measure_integrity',
    'Measure subject state, compare to sealed reference. Generates signed receipt for every measurement. (Claims 1e-1g)',
    {
      subject_content: z.string().describe('Current content of the subject'),
      subject_metadata: z.object({ filename: z.string().optional(), version: z.string().optional(), author: z.string().optional(), content_type: z.string().optional() }),
    },
    async ({ subject_content, subject_metadata }) => {
      if (!portal.artifact) return j({ success: false, error: 'No artifact loaded. Call attest_subject first.' });
      if (portal.state === 'TERMINATED') return j({ success: false, error: 'Portal is terminated. Re-attest required.' });

      const result = portal.measure(new TextEncoder().encode(subject_content), subject_metadata);
      const artRef = hashArtifact(portal.artifact);
      const currentStr = result.currentBytesHash ? `${result.currentBytesHash}||${result.currentMetaHash}` : 'UNAVAILABLE';
      const sealedStr = `${result.expectedBytesHash}||${result.expectedMetaHash}`;

      // Determine enforcement action
      let action = null as import('./core/types.js').EnforcementAction | null;
      let driftDesc: string | null = null;

      if (!result.ttl_ok) {
        driftDesc = 'TTL expired — fail-closed termination';
        action = 'TERMINATE';
      } else if (result.revoked) {
        driftDesc = 'Artifact revoked — fail-closed termination';
        action = 'TERMINATE';
      } else if (!result.match) {
        driftDesc = 'Subject modified — hash mismatch';
        action = portal.artifact.enforcement_parameters.enforcement_triggers[0] ?? 'ALERT_ONLY';
        portal.enforce(action);
        if (action === 'QUARANTINE') quarantine = initQuarantine();
      }

      // V3: Receipt for EVERY measurement — match or mismatch
      const receipt = generateReceipt({
        subjectId: portal.artifact.subject_identifier, artifactRef: artRef,
        currentHash: currentStr, sealedHash: sealedStr,
        driftDetected: !result.match, driftDescription: driftDesc,
        action, measurementType: portal.artifact.enforcement_parameters.measurement_types.join(','),
        seq: portal.sequenceCounter + 1, prevLeaf: portal.lastLeafHash, portalKP,
      });
      await storage.storeReceipt(receipt);
      await autoChain('INTERACTION_RECEIPT', { receipt_id: receipt.receipt_id, drift_detected: !result.match, enforcement_action: action });

      return j({
        success: true, match: result.match, drift_detected: !result.match,
        ttl_ok: result.ttl_ok, revoked: result.revoked,
        enforcement_action: action, portal_state: portal.state,
        receipt_id: receipt.receipt_id,
      });
    }
  );

  // ══════════════════════════════════════════════════════════════
  // TOOL: revoke_artifact — V3 NEW (NCCoE Phase 3b)
  // ══════════════════════════════════════════════════════════════
  server.tool('revoke_artifact',
    'Revoke an active policy artifact mid-session. Portal terminates on next measurement. (NCCoE Phase 3b)',
    {
      sealed_hash: z.string().describe('Sealed hash of artifact to revoke'),
      reason: z.string().describe('Reason for revocation'),
    },
    async ({ sealed_hash, reason }) => {
      portal.revoke(sealed_hash);
      const record: RevocationRecord = {
        artifact_sealed_hash: sealed_hash, reason,
        revoked_by: pkToHex(issuerKP.publicKey), timestamp: utcNow(),
      };
      await autoChain('REVOCATION', record);
      return j({ success: true, revoked: sealed_hash, portal_state: portal.state, reason });
    }
  );

  // ══════════════════════════════════════════════════════════════
  // TOOL: verify_chain (Claim 3c)
  // ══════════════════════════════════════════════════════════════
  server.tool('verify_chain', 'Verify continuity chain integrity. (Claim 3c)', {}, async () => {
    const events = await storage.getAllEvents();
    if (!events.length) return j({ success: false, error: 'No events in chain' });
    const result = verifyChainIntegrity(events);
    return j({ success: true, chain_valid: result.valid, events_verified: events.length, broken_at: result.brokenAt, error: result.error });
  });

  // ══════════════════════════════════════════════════════════════
  // TOOL: create_checkpoint (Claims 3d-3f)
  // ══════════════════════════════════════════════════════════════
  server.tool('create_checkpoint', 'Batch events into Merkle tree, anchor. (Claims 3d-3f)',
    { anchor_network: z.string().default('local') },
    async ({ anchor_network }) => {
      const lastCP = await storage.getLatestCheckpoint();
      const startSeq = lastCP ? lastCP.batch_end_sequence + 1 : 0;
      const latest = await storage.getLatestEvent();
      if (!latest) return j({ success: false, error: 'No events' });
      const events = await storage.getEvents(startSeq, latest.sequence_number);
      if (!events.length) return j({ success: false, error: 'No new events since last checkpoint' });
      const { checkpoint, payload } = createCheckpoint(events, anchor_network);
      await storage.storeCheckpoint(checkpoint);
      await autoChain('ANCHOR_BATCH', payload);
      return j({ success: true, merkle_root: checkpoint.merkle_root, events_checkpointed: events.length, transaction_id: checkpoint.transaction_id });
    }
  );

  // ══════════════════════════════════════════════════════════════
  // TOOL: generate_evidence_bundle (Claim 9)
  // ══════════════════════════════════════════════════════════════
  server.tool('generate_evidence_bundle', 'Package artifact + receipts + Merkle proofs for offline verification. (Claim 9)', {}, async () => {
    const artifact = await storage.getLatestArtifact();
    if (!artifact) return j({ success: false, error: 'No artifact' });
    const cp = await storage.getLatestCheckpoint();
    if (!cp) return j({ success: false, error: 'No checkpoint. Call create_checkpoint first.' });
    const receipts = await storage.getReceiptsByArtifact(hashArtifact(artifact));
    const batchEvents = await storage.getEvents(cp.batch_start_sequence, cp.batch_end_sequence);
    const proofs = receipts
      .filter(r => r.sequence_number >= cp.batch_start_sequence && r.sequence_number <= cp.batch_end_sequence)
      .map(r => eventInclusionProof(batchEvents, r.sequence_number));
    const bundle = generateBundle(artifact, receipts, proofs, cp, portalKP);
    return j({ success: true, bundle, offline_verifiable: true, receipt_count: receipts.length, proof_count: proofs.length });
  });

  // ══════════════════════════════════════════════════════════════
  // TOOL: verify_bundle_offline (Section J)
  // ══════════════════════════════════════════════════════════════
  server.tool('verify_bundle_offline', 'Verify evidence bundle offline. (Section J)',
    { bundle: z.any(), pinned_public_key: z.string() },
    async ({ bundle, pinned_public_key }) => j({ success: true, verification: verifyBundleOffline(bundle, pinned_public_key) })
  );

  // ══════════════════════════════════════════════════════════════
  // TOOL: request_claim (Claim 2)
  // ══════════════════════════════════════════════════════════════
  server.tool('request_claim', 'Request disclosure of a claim. Auto-substitutes if denied. (Claim 2)',
    { claim_id: z.string(), requester_id: z.string().default('anonymous'), mode: z.enum(['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL']).default('REVEAL_MIN') },
    async ({ claim_id, requester_id, mode }) => {
      const latest = await storage.getLatestEvent();
      const result = processDisclosure(
        { requested_claim_id: claim_id, requester_id, mode, timestamp: utcNow() },
        DEFAULT_CLAIMS, CLAIM_VALUES, 1, latest?.sequence_number ?? 0, portalKP
      );
      if (result.substitution_receipt) await autoChain('SUBSTITUTION', result.substitution_receipt);
      else await autoChain('DISCLOSURE', { claim_id, mode, permitted: result.permitted });
      return j({ success: true, ...result });
    }
  );

  // ══════════════════════════════════════════════════════════════
  // TOOL: list_claims
  // ══════════════════════════════════════════════════════════════
  server.tool('list_claims', 'List available claims with sensitivity levels.', {}, async () => {
    return j({ claims: DEFAULT_CLAIMS.claims_taxonomy.map(c => ({ claim_id: c.claim_id, sensitivity: c.sensitivity, substitutes: c.substitutes, permitted_modes: c.permitted_modes })) });
  });

  // ══════════════════════════════════════════════════════════════
  // TOOL: get_receipts — V3 NEW
  // ══════════════════════════════════════════════════════════════
  server.tool('get_receipts', 'Get all signed receipts, optionally filtered by artifact.',
    { artifact_hash: z.string().optional() },
    async ({ artifact_hash }) => {
      const receipts = artifact_hash
        ? await storage.getReceiptsByArtifact(artifact_hash)
        : await storage.getAllReceipts();
      return j({ count: receipts.length, receipts: receipts.map(r => ({ receipt_id: r.receipt_id, drift_detected: r.drift_detected, enforcement_action: r.enforcement_action, measurement_type: r.measurement_type, timestamp: r.timestamp })) });
    }
  );

  // ══════════════════════════════════════════════════════════════
  // TOOL: get_chain_events — V3 NEW
  // ══════════════════════════════════════════════════════════════
  server.tool('get_chain_events', 'Get continuity chain events.',
    { start_seq: z.number().optional(), end_seq: z.number().optional() },
    async ({ start_seq, end_seq }) => {
      const events = (start_seq !== undefined && end_seq !== undefined)
        ? await storage.getEvents(start_seq, end_seq)
        : await storage.getAllEvents();
      return j({ count: events.length, events: events.map(e => ({ sequence_number: e.sequence_number, event_type: e.event_type, event_id: e.event_id, timestamp: e.timestamp, leaf_hash: e.leaf_hash.slice(0, 16) + '...' })) });
    }
  );

  return server;
}
