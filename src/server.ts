/**
 * AGA MCP Server V2.0.0 - The Portal (ref 150) as an MCP service.
 *
 * 20 tools, 4 resources, 3 prompts.
 * USPTO Application No. 19/433,835
 * NIST-2025-0035, NCCoE AI Agent Identity and Authorization
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { createContext } from './context.js';
import { createGovernanceWrapper, type ToolHandler } from './middleware/governance.js';

// ── Tool handlers ────────────────────────────────────────────────
import { handleServerInfo } from './tools/server-info.js';
import { handleInitChain } from './tools/init-chain.js';
import { handleCreateArtifact } from './tools/create-artifact.js';
import { handleMeasureSubject } from './tools/measure-subject.js';
import { handleVerifyArtifact } from './tools/verify-artifact.js';
import { handleStartMonitoring } from './tools/start-monitoring.js';
import { handleGetPortalState } from './tools/get-portal-state.js';
import { handleTriggerMeasurement } from './tools/trigger-measurement.js';
import { handleGenerateReceipt } from './tools/generate-receipt.js';
import { handleExportBundle } from './tools/export-bundle.js';
import { handleVerifyBundle } from './tools/verify-bundle.js';
import { handleDiscloseClaim } from './tools/disclose-claim.js';
import { handleGetChain } from './tools/get-chain.js';
import { handleQuarantineStatus } from './tools/quarantine-status.js';
import { handleRevokeArtifact } from './tools/revoke-artifact.js';
import { handleSetVerificationTier } from './tools/set-verification-tier.js';
import { handleFullLifecycle } from './tools/full-lifecycle.js';
import { handleMeasureBehavior } from './tools/measure-behavior.js';
import { handleDelegateSubagent } from './tools/delegate-subagent.js';
import { handleRotateKeys } from './tools/rotate-keys.js';

// ── Resources ────────────────────────────────────────────────────
import { PROTOCOL_SPECIFICATION, SPECIFICATION_URI } from './resources/specification.js';
import { generateSampleBundle, SAMPLE_BUNDLE_URI } from './resources/sample-bundle.js';
import { CRYPTO_PRIMITIVES_DOC, CRYPTO_PRIMITIVES_URI } from './resources/crypto-primitives.js';
import { PATENT_CLAIMS_DOC, PATENT_CLAIMS_URI } from './resources/patent-claims.js';

// ── Prompts ──────────────────────────────────────────────────────
import { NCCOE_DEMO_PROMPT } from './prompts/nccoe-demo.js';
import { GOVERNANCE_REPORT_PROMPT } from './prompts/governance-report.js';
import { DRIFT_ANALYSIS_PROMPT } from './prompts/drift-analysis.js';

// ── Server Factory ──────────────────────────────────────────────

export async function createAGAServer(): Promise<McpServer> {
  const server = new McpServer({ name: 'aga-mcp-server', version: '2.0.0' });
  const ctx = await createContext();

  const quarantineRef = { get current() { return ctx.quarantine; } };

  function governedTool(
    name: string, description: string, schema: any,
    handler: ToolHandler
  ) {
    const wrap = createGovernanceWrapper(ctx.portal, quarantineRef, name, ctx.behavioralMonitor);
    server.tool(name, description, schema, wrap(handler));
  }

  // ══════════════════════════════════════════════════════════════
  // 20 TOOLS
  // ══════════════════════════════════════════════════════════════

  // 1. aga_server_info (ungoverned)
  server.tool('aga_server_info',
    'Get AGA server info, public keys, portal state, and framework alignment.',
    {},
    async () => handleServerInfo({} as any, ctx),
  );

  // Also register as get_server_info for backward compat
  server.tool('get_server_info',
    'Get AGA server info (alias for aga_server_info).',
    {},
    async () => handleServerInfo({} as any, ctx),
  );

  // 2. aga_init_chain (ungoverned)
  server.tool('aga_init_chain',
    'Initialize continuity chain with genesis event. (Claim 3a)',
    { specification_hash: z.string().optional() },
    async (args) => handleInitChain(args, ctx),
  );

  // Also register as init_chain for backward compat
  server.tool('init_chain',
    'Initialize continuity chain (alias for aga_init_chain). (Claim 3a)',
    { specification_hash: z.string().optional() },
    async (args) => handleInitChain(args, ctx),
  );

  // 3. aga_create_artifact (ungoverned)
  server.tool('aga_create_artifact',
    'Attest subject, generate sealed Policy Artifact, load into portal. Accepts content or pre-computed hashes. (Claims 1a-1d)',
    {
      subject_content: z.string().optional().describe('Content/bytes of the subject'),
      subject_bytes_hash: z.string().optional().describe('Pre-computed SHA-256 bytes hash'),
      subject_metadata_hash: z.string().optional().describe('Pre-computed SHA-256 metadata hash'),
      subject_metadata: z.object({
        filename: z.string().optional(),
        version: z.string().optional(),
        author: z.string().optional(),
        content_type: z.string().optional(),
      }).optional(),
      measurement_cadence_ms: z.number().optional(),
      enforcement_action: z.string().optional(),
      ttl_seconds: z.number().optional(),
      measurement_types: z.array(z.string()).optional(),
      evidence_items: z.array(z.object({ label: z.string(), content: z.string() })).default([]),
      behavioral_baseline: z.object({
        permitted_tools: z.array(z.string()),
        rate_limits: z.record(z.number()),
        forbidden_sequences: z.array(z.array(z.string())),
        window_ms: z.number(),
      }).optional(),
    },
    async (args) => handleCreateArtifact(args, ctx),
  );

  // 4. aga_measure_subject (governed)
  governedTool('aga_measure_subject',
    'Measure subject state, compare to sealed reference. Generates signed receipt. (Claims 1e-1g)',
    {
      subject_content: z.string().optional().describe('Raw content to measure'),
      subject_bytes_hash: z.string().optional().describe('Pre-computed SHA-256 bytes hash (64 hex)'),
      subject_metadata_hash: z.string().optional().describe('Pre-computed SHA-256 metadata hash (64 hex)'),
      subject_metadata: z.object({
        filename: z.string().optional(),
        version: z.string().optional(),
        author: z.string().optional(),
        content_type: z.string().optional(),
      }).optional(),
    },
    async (args) => handleMeasureSubject({ ...args, subject_metadata: args.subject_metadata ?? {} }, ctx),
  );

  // 5. aga_verify_artifact (ungoverned)
  server.tool('aga_verify_artifact',
    'Verify an artifact signature against an issuer public key.',
    {
      artifact: z.any().describe('The policy artifact to verify'),
      issuer_public_key: z.string().optional().describe('Issuer public key (hex)'),
    },
    async (args) => {
      const pk = args.issuer_public_key ?? (await import('./crypto/sign.js')).pkToHex(ctx.issuerKP.publicKey);
      return handleVerifyArtifact({ artifact: args.artifact ?? ctx.activeArtifact, issuer_public_key: pk }, ctx);
    },
  );

  // 6. aga_start_monitoring (governed)
  governedTool('aga_start_monitoring',
    'Start or restart behavioral monitoring with a new baseline.',
    {
      behavioral_baseline: z.object({
        permitted_tools: z.array(z.string()),
        rate_limits: z.record(z.number()),
        forbidden_sequences: z.array(z.array(z.string())),
        window_ms: z.number(),
      }).optional(),
    },
    async (args) => handleStartMonitoring(args, ctx),
  );

  // 7. aga_get_portal_state (ungoverned)
  server.tool('aga_get_portal_state',
    'Get current portal state, loaded artifact info, and enforcement status.',
    {},
    async () => handleGetPortalState({} as any, ctx),
  );

  // 8. aga_trigger_measurement (governed)
  governedTool('aga_trigger_measurement',
    'Trigger a measurement of subject content and generate a receipt.',
    {
      subject_content: z.string().optional().describe('Raw content to measure'),
      subject_bytes_hash: z.string().optional().describe('Pre-computed SHA-256 bytes hash (64 hex)'),
      subject_metadata_hash: z.string().optional().describe('Pre-computed SHA-256 metadata hash (64 hex)'),
      measurement_type: z.string().optional(),
      subject_metadata: z.record(z.string()).optional(),
    },
    async (args) => handleTriggerMeasurement(args, ctx),
  );

  // 9. aga_generate_receipt (governed)
  governedTool('aga_generate_receipt',
    'Generate a signed measurement receipt manually.',
    {
      subject_content: z.string().optional(),
      drift_detected: z.boolean().optional(),
      drift_description: z.string().optional(),
      measurement_type: z.string().optional(),
      action_type: z.string().optional(),
      action_detail: z.string().optional(),
    },
    async (args) => handleGenerateReceipt(args, ctx),
  );

  // 10. aga_export_bundle (governed)
  governedTool('aga_export_bundle',
    'Package artifact + receipts + Merkle proofs for offline verification. (Claim 9)',
    {},
    async () => handleExportBundle({} as any, ctx),
  );

  // 11. aga_verify_bundle (ungoverned - verification is always allowed)
  server.tool('aga_verify_bundle',
    'Verify evidence bundle offline - 4-step verification. (Section J)',
    {
      bundle: z.any(),
      pinned_public_key: z.string().optional(),
    },
    async (args) => {
      const pk = args.pinned_public_key ?? (await import('./crypto/sign.js')).pkToHex(ctx.issuerKP.publicKey);
      return handleVerifyBundle({ bundle: args.bundle, pinned_public_key: pk }, ctx);
    },
  );

  // 12. aga_disclose_claim (governed)
  governedTool('aga_disclose_claim',
    'Request disclosure of a claim. Auto-substitutes if sensitivity denied. (Claim 2)',
    {
      claim_id: z.string(),
      requester_id: z.string().default('anonymous'),
      mode: z.enum(['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL']).default('REVEAL_MIN'),
      disclosure_mode: z.enum(['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL']).optional(),
    },
    async (args) => handleDiscloseClaim({
      claim_id: args.claim_id,
      requester_id: args.requester_id,
      mode: args.disclosure_mode ?? args.mode,
    }, ctx),
  );

  // 13. aga_get_chain (ungoverned)
  server.tool('aga_get_chain',
    'Get continuity chain events with optional verification and filtering. (Claim 3c)',
    {
      start_seq: z.number().optional(),
      end_seq: z.number().optional(),
      verify: z.boolean().optional(),
      filter_type: z.string().optional().describe('Filter: all, behavioral, delegations, receipts, revocations, attestations, disclosure, keys'),
    },
    async (args) => handleGetChain(args, ctx),
  );

  // 14. aga_quarantine_status (ungoverned)
  server.tool('aga_quarantine_status',
    'Get quarantine state and forensic capture status. (Claim 5)',
    {},
    async () => handleQuarantineStatus({} as any, ctx),
  );

  // 15. aga_revoke_artifact (governed)
  governedTool('aga_revoke_artifact',
    'Revoke an active policy artifact mid-session. Supports TERMINATED or SAFE_STATE transition. (NCCoE Phase 3b)',
    {
      sealed_hash: z.string().optional().describe('Sealed hash of artifact to revoke'),
      reason: z.string().describe('Reason for revocation'),
      transition_to: z.enum(['TERMINATED', 'SAFE_STATE']).optional(),
    },
    async (args) => handleRevokeArtifact(args, ctx),
  );

  // 16. aga_set_verification_tier (ungoverned)
  server.tool('aga_set_verification_tier',
    'Set the verification tier (BRONZE, SILVER, GOLD).',
    {
      tier: z.enum(['BRONZE', 'SILVER', 'GOLD']),
    },
    async (args) => handleSetVerificationTier(args, ctx),
  );

  // 17. aga_demonstrate_lifecycle (ungoverned)
  server.tool('aga_demonstrate_lifecycle',
    'Execute full AGA lifecycle demo: attest → measure → drift → revoke → bundle → verify.',
    {
      subject_content: z.string().optional(),
      subject_metadata: z.record(z.string()).optional(),
      scenario: z.string().optional().describe('Scenario: drone, scada, or custom'),
      include_drift: z.boolean().optional(),
      include_revocation: z.boolean().optional(),
      include_behavioral: z.boolean().optional(),
    },
    async (args) => handleFullLifecycle(args, ctx),
  );

  // 18. aga_measure_behavior (ungoverned)
  server.tool('aga_measure_behavior',
    'Measure behavioral patterns or record tool invocation. (NIST-2025-0035)',
    {
      tool_name: z.string().optional().describe('Tool name to record/test'),
      record_only: z.boolean().optional().describe('If true, just record without measuring'),
    },
    async (args) => handleMeasureBehavior(args, ctx),
  );

  // 19. aga_delegate_to_subagent (governed)
  governedTool('aga_delegate_to_subagent',
    'Derive constrained policy artifact for sub-agent. Scope only diminishes. (NCCoE)',
    {
      sub_agent_id: z.string().optional(),
      permitted_tools: z.array(z.string()).optional(),
      enforcement_triggers: z.array(z.string()).optional(),
      measurement_types: z.array(z.string()).optional(),
      ttl_seconds: z.number().optional(),
      requested_ttl_seconds: z.number().optional(),
      delegation_purpose: z.string().optional(),
      delegation_reason: z.string().optional(),
    },
    async (args) => handleDelegateSubagent(args, ctx),
  );

  // 20. aga_rotate_keys (governed)
  governedTool('aga_rotate_keys',
    'Rotate a keypair (issuer, portal, or chain). Old key should be revoked.',
    {
      key_type: z.enum(['issuer', 'portal', 'chain']).optional(),
      keypair: z.enum(['issuer', 'portal', 'chain']).optional(),
      reason: z.string().optional(),
    },
    async (args) => handleRotateKeys(args, ctx),
  );

  // ══════════════════════════════════════════════════════════════
  // 4 RESOURCES
  // ══════════════════════════════════════════════════════════════

  server.resource(
    'protocol-specification',
    SPECIFICATION_URI,
    { mimeType: 'text/markdown', description: 'AGA Protocol Specification v2.0.0 with SPIFFE integration and framework alignment' },
    async () => ({ contents: [{ uri: SPECIFICATION_URI, mimeType: 'text/markdown', text: PROTOCOL_SPECIFICATION }] }),
  );

  server.resource(
    'sample-bundle',
    SAMPLE_BUNDLE_URI,
    { mimeType: 'application/json', description: 'Pre-generated cryptographically signed evidence bundle' },
    async () => {
      const { bundle, issuerPkHex } = generateSampleBundle();
      const text = JSON.stringify({ issuer_public_key: issuerPkHex, bundle: JSON.parse(bundle) }, null, 2);
      return { contents: [{ uri: SAMPLE_BUNDLE_URI, mimeType: 'application/json', text }] };
    },
  );

  server.resource(
    'crypto-primitives',
    CRYPTO_PRIMITIVES_URI,
    { mimeType: 'text/markdown', description: 'AGA cryptographic primitives documentation' },
    async () => ({ contents: [{ uri: CRYPTO_PRIMITIVES_URI, mimeType: 'text/markdown', text: CRYPTO_PRIMITIVES_DOC }] }),
  );

  server.resource(
    'patent-claims',
    PATENT_CLAIMS_URI,
    { mimeType: 'text/markdown', description: 'USPTO 19/433,835 patent claims mapped to 20 tools' },
    async () => ({ contents: [{ uri: PATENT_CLAIMS_URI, mimeType: 'text/markdown', text: PATENT_CLAIMS_DOC }] }),
  );

  // ══════════════════════════════════════════════════════════════
  // 3 PROMPTS
  // ══════════════════════════════════════════════════════════════

  server.prompt(
    NCCOE_DEMO_PROMPT.name,
    NCCOE_DEMO_PROMPT.description,
    {
      agent_code: z.string().optional().describe('The agent source code to attest'),
      include_behavioral: z.string().optional().describe('Include behavioral drift detection phase'),
    },
    async (args) => ({
      messages: [{
        role: 'user' as const,
        content: { type: 'text' as const, text: NCCOE_DEMO_PROMPT.template(args) },
      }],
    }),
  );

  server.prompt(
    GOVERNANCE_REPORT_PROMPT.name,
    GOVERNANCE_REPORT_PROMPT.description,
    {},
    async () => ({
      messages: [{
        role: 'user' as const,
        content: { type: 'text' as const, text: GOVERNANCE_REPORT_PROMPT.template() },
      }],
    }),
  );

  server.prompt(
    DRIFT_ANALYSIS_PROMPT.name,
    DRIFT_ANALYSIS_PROMPT.description,
    {
      drift_type: z.string().optional().describe('Type of drift: binary, behavioral, or both'),
    },
    async (args) => ({
      messages: [{
        role: 'user' as const,
        content: { type: 'text' as const, text: DRIFT_ANALYSIS_PROMPT.template(args) },
      }],
    }),
  );

  return server;
}
