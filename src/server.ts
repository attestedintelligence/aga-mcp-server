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
// NOTE: the legacy continuity EVIDENCE path (src/core/bundle.ts, src/core/checkpoint.ts,
// src/crypto/merkle.ts) has been physically removed (P4). The canonical evidence path is src/sep.
import { processDisclosure } from './core/disclosure.js';
import { initQuarantine, captureInput } from './core/quarantine.js';
import { MemoryStorage, type AGAStorage } from './storage/index.js';
import { utcNow } from './utils/timestamp.js';
import { deriveArtifact } from './core/delegation.js';
import { createGovernanceWrapper, type ToolHandler } from './middleware/governance.js';
import { BehavioralMonitor } from './core/behavioral.js';
import type { EnforcementParams, DisclosurePolicy, QuarantineState, RevocationRecord } from './core/types.js';
import { readFileSync } from 'node:fs';
import { SepGateway, signerFromSeed, seedFromHex, verifySepBundle } from './sep/index.js';

// Single-source the reported version from package.json — no more hardcoded version drift.
// Resolves to the package root from both src/ (tsx dev) and dist/ (published bin).
const PKG = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
const SERVER_VERSION: string = PKG.version;

/**
 * Resolve the gateway signing seed (the key that signs evidence bundles).
 * Optional persistence so provenance survives restarts and a verifier can PIN the key:
 *   - AGA_GATEWAY_KEY       — a 64-hex (32-byte) Ed25519 seed, OR
 *   - AGA_GATEWAY_KEY_FILE  — path to a file containing that hex seed.
 * If neither is set (or the value is invalid), fall back to an EPHEMERAL key and warn on stderr.
 * See DEPLOYMENT.md. stderr only — never stdout (would corrupt the JSON-RPC stream).
 */
function resolveGatewaySeed(fallback: Uint8Array): Uint8Array {
  const envKey = process.env.AGA_GATEWAY_KEY;
  const keyFile = process.env.AGA_GATEWAY_KEY_FILE;
  try {
    if (envKey) return seedFromHex(envKey);
    if (keyFile) return seedFromHex(readFileSync(keyFile, 'utf8'));
  } catch (e) {
    console.error(`[aga] gateway key from ${envKey ? 'AGA_GATEWAY_KEY' : 'AGA_GATEWAY_KEY_FILE'} is invalid (${String(e)}); falling back to an ephemeral key.`);
  }
  console.error('[aga] Using an EPHEMERAL gateway signing key — it rotates on restart, so evidence-bundle provenance cannot be pinned across restarts. Set AGA_GATEWAY_KEY (64-hex 32-byte seed) or AGA_GATEWAY_KEY_FILE to persist it. See DEPLOYMENT.md.');
  return fallback;
}

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
  'identity.name': 'Alice Johnson', 'identity.pseudonym': 'AJ-7742', 'identity.org': 'Attested Intelligence',
  'identity.age': 32, 'identity.age_range': '25-34', 'identity.is_adult': true,
};

// ── Server Factory ──────────────────────────────────────────────

export async function createAGAServer(): Promise<McpServer> {
  const server = new McpServer({ name: 'aga-mcp-server', version: SERVER_VERSION });
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

  // ── Governance middleware (NCCoE Section 4: Portal as PEP) ────
  const quarantineRef = { get current() { return quarantine; } };
  const behavioralMonitor = new BehavioralMonitor();

  // Canonical SEP evidence ledger — single source of truth for the public bundle.
  // Gateway signing key: persisted (AGA_GATEWAY_KEY / _FILE) so provenance is pinnable across
  // restarts, else an ephemeral key (warned on stderr). This key signs every receipt + checkpoint.
  const sep = new SepGateway({ gatewayId: 'aga-mcp-server', signer: signerFromSeed(resolveGatewaySeed(portalKP.secretKey)) });

  // Registration convention (single partition, enforced by tests/core/governance-partition.test.ts):
  //   governedTool(...) → side-effecting agent action → emits a signed PERMITTED/DENIED SEP receipt.
  //   server.tool(...)  → read / bootstrap / evidence / detective-monitor → ungoverned (in UNGOVERNED_TOOLS).
  // createGovernanceWrapper double-checks UNGOVERNED_TOOLS, so a tool can never be both.
  function governedTool(
    name: string, description: string, schema: any,
    handler: ToolHandler
  ) {
    const wrap = createGovernanceWrapper(portal, quarantineRef, name, behavioralMonitor,
      (d) => { sep.record({ tool_name: d.tool, decision: d.decision, reason: d.reason, argumentsHash: d.argsHash }); });
    server.tool(name, description, schema, wrap(handler));
  }

  // ══════════════════════════════════════════════════════════════
  // TOOL: get_server_info
  // ══════════════════════════════════════════════════════════════
  server.tool('get_server_info', 'Get AGA server info, public keys, and portal state.', {}, async () => j({
    server: 'AGA MCP Server', version: SERVER_VERSION,
    protocol: 'Attested Governance Artifacts',
    bundle_format: 'Ed25519-SHA256-JCS (canonical SEP evidence bundle)',
    nist_references: ['NIST-2025-0035', 'NCCoE AI Agent Identity'],
    issuer_public_key: pkToHex(issuerKP.publicKey),
    portal_public_key: pkToHex(portalKP.publicKey),
    chain_public_key: pkToHex(chainKP.publicKey),
    gateway_public_key: sep.publicKeyHex,   // pin THIS to prove provenance of evidence bundles
    sep_receipt_count: sep.count,
    chain_initialized: chainInitialized,
    portal_state: portal.state,
  }));

  // ══════════════════════════════════════════════════════════════
  // TOOL: get_portal_state - V3 RESTORED (was dropped in V2)
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
  // TOOL: init_chain
  // ══════════════════════════════════════════════════════════════
  server.tool('init_chain', 'Initialize continuity chain with genesis event.',
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
  // TOOL: attest_subject
  // ══════════════════════════════════════════════════════════════
  server.tool('attest_subject',
    'Attest subject, generate sealed Policy Artifact. Auto-loads into portal.',
    {
      subject_content: z.string().describe('Content/bytes of the subject'),
      subject_metadata: z.object({ filename: z.string().optional(), version: z.string().optional(), author: z.string().optional(), content_type: z.string().optional() }),
      evidence_items: z.array(z.object({ label: z.string(), content: z.string() })).default([]),
      behavioral_baseline: z.object({
        permitted_tools: z.array(z.string()),
        rate_limits: z.record(z.number()),
        forbidden_sequences: z.array(z.array(z.string())),
        window_ms: z.number(),
      }).optional(),
    },
    async ({ subject_content, subject_metadata, evidence_items, behavioral_baseline }) => {
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
      behavioralMonitor.reset();
      // NOTE: the SEP ledger (`sep`) is intentionally NOT reset on re-attestation. The
      // tamper-evident record of prior decisions (including DENIED) MUST survive, so an agent
      // cannot "cover up" a denied permissions-workaround by re-attesting (the provable-denial
      // property; regression-tested in tests/integration/provable-denial.test.ts).
      if (behavioral_baseline) behavioralMonitor.setBaseline(behavioral_baseline);

      await autoChain('POLICY_ISSUANCE', { artifact_hash: hashArtifact(artifact), sealed_hash: artifact.sealed_hash });

      return j({
        success: true, artifact_hash: hashArtifact(artifact), sealed_hash: artifact.sealed_hash,
        subject_identifier: subId, portal_state: portal.state,
        issuer_public_key: pkToHex(issuerKP.publicKey),
      });
    }
  );

  // ══════════════════════════════════════════════════════════════
  // TOOL: measure_integrity
  // V3: Generates receipt for EVERY measurement (match or mismatch)
  // V3: Checks TTL and revocation (fail-closed)
  // ══════════════════════════════════════════════════════════════
  governedTool('measure_integrity',
    'Measure subject state, compare to sealed reference. Generates signed receipt for every measurement.',
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
        // HONESTY FIX: this branch previously sealed `action = 'TERMINATE'` and described itself as
        // "fail-closed termination". No termination occurs. portal.measure() degrades the portal to
        // SAFE_STATE on TTL expiry (see core/portal.ts, "Graceful degradation") and keeps accepting
        // measurements; portal.enforce() is NOT called here and CANNOT be — it throws unless state
        // is DRIFT_DETECTED. The entry guard above rejects only TERMINATED, so post-expiry calls
        // keep succeeding and would keep minting fresh receipts each asserting a termination that
        // never happened. A signed receipt asserting an enforcement that did not occur is the exact
        // failure this product exists to prevent, so the receipt now records what actually happened.
        //
        // NOTE: the sibling `revoked` branch below is honest — portal.measure() genuinely sets
        // TERMINATED there, so sealing 'TERMINATE' is accurate. TTL was uniquely hollow.
        //
        // OPEN PRODUCT DECISION (founder/architecture, deliberately NOT made here): whether TTL
        // expiry SHOULD hard-terminate and require re-attestation. Several public pages describe
        // that behavior. Until it is ruled, the record must not claim a behavior the code lacks.
        driftDesc = 'TTL expired - portal degraded to SAFE_STATE; no enforcement performed, measurement logging continues';
        action = null;
      } else if (result.revoked) {
        driftDesc = 'Artifact revoked - fail-closed termination';
        action = 'TERMINATE';
      } else if (!result.match) {
        driftDesc = 'Subject modified - hash mismatch';
        action = portal.artifact.enforcement_parameters.enforcement_triggers[0] ?? 'ALERT_ONLY';
        portal.enforce(action);
        if (action === 'QUARANTINE') quarantine = initQuarantine();
      }

      // V3: Receipt for EVERY measurement - match or mismatch
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
  // TOOL: revoke_artifact - V3 NEW (NCCoE Phase 3b)
  // ══════════════════════════════════════════════════════════════
  governedTool('revoke_artifact',
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
  // TOOL: verify_chain
  // ══════════════════════════════════════════════════════════════
  server.tool('verify_chain', 'Verify continuity chain integrity.', {}, async () => {
    const events = await storage.getAllEvents();
    if (!events.length) return j({ success: false, error: 'No events in chain' });
    const result = verifyChainIntegrity(events);
    return j({ success: true, chain_valid: result.valid, events_verified: events.length, broken_at: result.brokenAt, error: result.error });
  });

  // (create_checkpoint REMOVED in P4 — it was the legacy continuity-chain checkpoint over the
  //  non-conformant Merkle. The canonical signed checkpoint is emitted automatically inside the
  //  SEP bundle by generate_evidence_bundle.)

  // ══════════════════════════════════════════════════════════════
  // TOOL: generate_evidence_bundle
  // ══════════════════════════════════════════════════════════════
  server.tool('generate_evidence_bundle', 'Export the canonical SEP evidence bundle: signed PERMITTED/DENIED tool-call receipts + Merkle proofs + a mandatory signed checkpoint, for offline third-party verification (verify_bundle_offline, aga-verify, or aga-receipt-spec/verify/verify-sep.mjs). Pin gateway_public_key to prove provenance.', {}, async () => {
    if (sep.count === 0) return j({ success: false, error: 'No governed tool-call receipts yet. Exercise a governed tool (e.g. measure_integrity) first.' });
    return j(sep.exportBundle());
  });

  // ══════════════════════════════════════════════════════════════
  // TOOL: verify_bundle_offline (Section J)
  // ══════════════════════════════════════════════════════════════
  server.tool('verify_bundle_offline', 'Verify a canonical SEP evidence bundle offline (full §6 algorithm: structural floor, receipt signatures, chain+ordering, leaf-recompute + Merkle bijection, signed checkpoint). Pass pinned_public_key to also prove provenance.',
    { bundle: z.any(), pinned_public_key: z.string().optional() },
    async ({ bundle, pinned_public_key }) => {
      try { return j(verifySepBundle(bundle, pinned_public_key)); }
      catch (e) { return j({ verdict: 'FAILED', summary: 'FAILED — could not parse or verify the bundle', error: String(e) }); }
    }
  );

  // ══════════════════════════════════════════════════════════════
  // TOOL: request_claim
  // ══════════════════════════════════════════════════════════════
  governedTool('request_claim', 'Request disclosure of a claim. Auto-substitutes if denied.',
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
  // TOOL: delegate_to_subagent (NCCoE: constrained sub-mandates)
  // ══════════════════════════════════════════════════════════════
  governedTool('delegate_to_subagent',
    'Derive a constrained policy artifact for a sub-agent. Scope can only diminish, never expand. (NCCoE constrained delegation)',
    {
      enforcement_triggers: z.array(z.string()).describe('Subset of parent enforcement triggers'),
      measurement_types: z.array(z.string()).describe('Subset of parent measurement types'),
      requested_ttl_seconds: z.number().describe('Requested TTL (will be clamped to parent remaining)'),
      delegation_purpose: z.string().describe('Purpose of the delegation'),
    },
    async ({ enforcement_triggers, measurement_types, requested_ttl_seconds, delegation_purpose }) => {
      if (!portal.artifact) return j({ success: false, error: 'No artifact loaded. Call attest_subject first.' });

      const result = deriveArtifact(portal.artifact, {
        enforcement_triggers: enforcement_triggers as import('./core/types.js').EnforcementAction[],
        measurement_types: measurement_types as import('./core/types.js').MeasurementType[],
        requested_ttl_seconds,
        delegation_purpose,
      }, issuerKP);

      if (result.success) {
        await autoChain('ATTESTATION', {
          type: 'DELEGATION',
          parent_artifact_hash: result.parent_artifact_hash,
          child_artifact_hash: result.child_artifact_hash,
          effective_ttl: result.effective_ttl_seconds,
          scope_reduction: result.scope_reduction,
          purpose: delegation_purpose,
        });
      }

      return j(result);
    }
  );

  // ══════════════════════════════════════════════════════════════
  // TOOL: measure_behavior (NIST-2025-0035)
  // ══════════════════════════════════════════════════════════════
  server.tool('measure_behavior',
    'Measure behavioral patterns (unauthorized tools, rate violations, forbidden sequences). DETECTIVE-ONLY by default: it records and PROVES drift but does not block. Pass enforce=true to also trip the portal into phantom quarantine on drift (opt-in; off by default). (NIST-2025-0035)',
    { enforce: z.boolean().default(false) },
    async ({ enforce }) => {
      const measurement = behavioralMonitor.measure();
      let enforced = false;
      if (measurement.drift_detected) {
        const summary = measurement.violations.map(v => v.type).join(',');
        // Opt-in enforcement (off by default): trip phantom quarantine so subsequent governed calls are denied.
        if (enforce && portal.state !== 'TERMINATED') {
          portal.state = 'PHANTOM_QUARANTINE';
          quarantine = initQuarantine();
          enforced = true;
        }
        // Provable detection: a signed SEP receipt records the drift finding and whether it was enforced.
        sep.record({
          tool_name: 'measure_behavior',
          decision: enforced ? 'DENIED' : 'PERMITTED',
          reason: `BEHAVIORAL_DRIFT_DETECTED [${enforced ? 'ENFORCED->QUARANTINE' : 'detective-only, not enforced'}]: ${summary}`,
          arguments: { violations: measurement.violations, behavioral_hash: measurement.behavioral_hash },
        });
        await autoChain('INTERACTION_RECEIPT', {
          type: 'BEHAVIORAL_DRIFT',
          violations: measurement.violations,
          behavioral_hash: measurement.behavioral_hash,
          enforced,
        });
      }
      return j({
        success: true,
        mode: enforce ? 'enforcement' : 'detective-only',
        enforced,
        ...measurement,
        violation_count: measurement.violations.length,
      });
    }
  );

  // ══════════════════════════════════════════════════════════════
  // TOOL: get_receipts - V3 NEW
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
  // TOOL: get_chain_events - V3 NEW
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
