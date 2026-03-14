/**
 * AGA Protocol V2.0.0 - Unified Type Definitions
 * USPTO Application No. 19/433,835
 * NIST-2025-0035, NCCoE AI Agent Identity and Authorization
 *
 * All enums/interfaces aligned to directive specification.
 */

// ── Crypto Primitives ────────────────────────────────────────────

export type PublicKey = Uint8Array;
export type SecretKey = Uint8Array;
export interface KeyPair { publicKey: PublicKey; secretKey: SecretKey; }
export type Signature = Uint8Array;
export type HashHex = string;
export type SignatureBase64 = string;
export type SaltHex = string;

export interface SaltedCommitment {
  commitment: HashHex;
  salt: SaltHex;
}

export interface MerkleInclusionProof {
  leafHash: HashHex;
  leafIndex: number;
  siblings: Array<{ hash: HashHex; position: 'left' | 'right' }>;
  root: HashHex;
}

// ── Event Types (11) ─────────────────────────────────────────────

export type EventType =
  | 'GENESIS'
  | 'POLICY_ISSUANCE'
  | 'INTERACTION_RECEIPT'
  | 'REVOCATION'
  | 'ATTESTATION'
  | 'ANCHOR_BATCH'
  | 'DISCLOSURE'
  | 'SUBSTITUTION'
  | 'KEY_ROTATION'
  | 'BEHAVIORAL_DRIFT'
  | 'DELEGATION'
  | 'RE_ATTESTATION';

// ── Enforcement Actions (7) ──────────────────────────────────────

export type EnforcementAction =
  | 'TERMINATE'
  | 'QUARANTINE'
  | 'NETWORK_ISOLATE'
  | 'SAFE_STATE'
  | 'KEY_REVOKE'
  | 'TOKEN_INVALIDATE'
  | 'ACTUATOR_DISCONNECT'
  | 'ALERT_ONLY';

// ── Measurement Types (10) ───────────────────────────────────────

export type MeasurementType =
  | 'EXECUTABLE_IMAGE'
  | 'LOADED_MODULES'
  | 'CONTAINER_IMAGE'
  | 'CONFIG_MANIFEST'
  | 'SBOM'
  | 'TEE_QUOTE'
  | 'MEMORY_REGIONS'
  | 'CONTROL_FLOW'
  | 'FILE_SYSTEM_STATE'
  | 'NETWORK_CONFIG';

// ── Portal States (6) ────────────────────────────────────────────

export type PortalState =
  | 'INITIALIZATION'
  | 'ARTIFACT_VERIFICATION'
  | 'ACTIVE_MONITORING'
  | 'DRIFT_DETECTED'
  | 'PHANTOM_QUARANTINE'
  | 'SAFE_STATE'
  | 'TERMINATED';

// ── Verification Tiers (3) ───────────────────────────────────────

export type VerificationTier = 'BRONZE' | 'SILVER' | 'GOLD';

// ── Disclosure Modes (3) ─────────────────────────────────────────

export type DisclosureMode = 'PROOF_ONLY' | 'REVEAL_MIN' | 'REVEAL_FULL';

// ── Sensitivity Levels (4) ───────────────────────────────────────

export type Sensitivity = 'S1_LOW' | 'S2_MODERATE' | 'S3_HIGH' | 'S4_CRITICAL';

// ── Subject ──────────────────────────────────────────────────────

export interface SubjectIdentifier {
  bytes_hash: HashHex;
  metadata_hash: HashHex;
}

export interface SubjectMetadata {
  filename?: string;
  creation_timestamp?: string;
  author?: string;
  version?: string;
  content_type?: string;
  [key: string]: unknown;
}

// ── Enforcement ──────────────────────────────────────────────────

export interface EnforcementParams {
  measurement_cadence_ms: number;
  ttl_seconds: number;
  enforcement_triggers: EnforcementAction[];
  re_attestation_required: boolean;
  measurement_types: MeasurementType[];
}

// ── Disclosure & Claims ──────────────────────────────────────────

export interface ClaimRecord {
  claim_id: string;
  sensitivity: Sensitivity;
  substitutes: string[];
  inference_risks: string[];
  permitted_modes: DisclosureMode[];
}

export interface ClaimsTaxonomy {
  claims: ClaimRecord[];
  version: string;
}

export interface SubstitutionRule {
  original_claim_id: string;
  substitute_claim_id: string;
  conditions: Record<string, unknown>;
}

export interface DisclosurePolicy {
  claims_taxonomy: ClaimRecord[];
  substitution_rules: SubstitutionRule[];
}

export interface DisclosureRequest {
  requested_claim_id: string;
  requester_id: string;
  mode: DisclosureMode;
  timestamp: string;
}

export interface SubstitutionReceipt {
  receipt_id: string;
  original_claim_id: string;
  substitute_claim_id: string | null;
  policy_version: number;
  reason_code: string;
  timestamp: string;
  chain_sequence_ref: number;
  signature: SignatureBase64;
}

// ── Evidence ─────────────────────────────────────────────────────

export interface EvidenceCommitmentRecord {
  commitment: HashHex;
  salt: SaltHex;
  label: string;
}

export interface EvidenceBundle {
  artifact: PolicyArtifact;
  receipts: SignedReceipt[];
  merkle_proofs: MerkleInclusionProof[];
  checkpoint_reference: CheckpointReference;
  public_key: string;
  bundle_signature: SignatureBase64;
}

// ── Policy Artifact ──────────────────────────────────────────────

export interface PolicyArtifact {
  schema_version: string;
  protocol_version: string;
  subject_identifier: SubjectIdentifier;
  policy_reference: HashHex;
  policy_version: number;
  sealed_hash: HashHex;
  seal_salt: SaltHex;
  issued_timestamp: string;
  effective_timestamp: string;
  expiration_timestamp: string | null;
  issuer_identifier: string;
  enforcement_parameters: EnforcementParams;
  disclosure_policy: DisclosurePolicy;
  evidence_commitments: EvidenceCommitmentRecord[];
  signature: SignatureBase64;
}

// ── Signed Receipt ───────────────────────────────────────────────

export interface SignedReceipt {
  receipt_id: string;
  subject_identifier: SubjectIdentifier;
  artifact_reference: HashHex;
  current_hash: string;
  sealed_hash: string;
  drift_detected: boolean;
  drift_description: string | null;
  enforcement_action: EnforcementAction | null;
  measurement_type: string;
  timestamp: string;
  sequence_number: number;
  previous_leaf_hash: HashHex | null;
  portal_signature: SignatureBase64;
}

// ── Continuity Chain ─────────────────────────────────────────────

export interface GenesisPayload {
  protocol_version: string;
  taxonomy_version: string;
  root_fingerprint: string;
  specification_hash: HashHex;
  marker: 'GENESIS';
}

export interface StructuralMetadata {
  schema_version: string;
  protocol_version: string;
  event_type: EventType;
  event_id: string;
  sequence_number: number;
  timestamp: string;
  previous_leaf_hash: HashHex | null;
}

export interface ContinuityEvent {
  schema_version: string;
  protocol_version: string;
  event_type: EventType;
  event_id: string;
  sequence_number: number;
  timestamp: string;
  previous_leaf_hash: HashHex | null;
  leaf_hash: HashHex;
  payload: unknown;
  payload_hash: HashHex;
  event_signature: SignatureBase64;
}

// ── Checkpoints ──────────────────────────────────────────────────

export interface CheckpointReference {
  merkle_root: HashHex;
  batch_start_sequence: number;
  batch_end_sequence: number;
  anchor_network: string;
  transaction_id: string;
  timestamp: string;
}

export interface AnchorBatchPayload {
  checkpoint_reference: CheckpointReference;
  leaf_count: number;
}

// ── Quarantine ───────────────────────────────────────────────────

export interface QuarantineState {
  active: boolean;
  started_at: string | null;
  inputs_captured: number;
  outputs_severed: boolean;
  forensic_buffer: Array<{ timestamp: string; type: string; data: unknown }>;
}

// ── Revocation ───────────────────────────────────────────────────

export interface RevocationRecord {
  artifact_sealed_hash: HashHex;
  reason: string;
  revoked_by: string;
  timestamp: string;
}

// ── Behavioral ───────────────────────────────────────────────────

export interface BehavioralBaseline {
  permitted_tools: string[];
  rate_limits: Record<string, number>;
  forbidden_sequences: string[][];
  window_ms: number;
}

export interface ToolInvocation {
  tool_name: string;
  timestamp: string;
  args_hash: HashHex;
}

export type BehavioralViolation =
  | { type: 'UNAUTHORIZED_TOOL'; tool: string }
  | { type: 'RATE_EXCEEDED'; tool: string; count: number; limit: number }
  | { type: 'FORBIDDEN_SEQUENCE'; sequence: string[] };

export interface BehavioralMeasurement {
  window_start: string;
  window_end: string;
  invocations: ToolInvocation[];
  violations: BehavioralViolation[];
  behavioral_hash: HashHex;
  drift_detected: boolean;
}

export interface BehavioralMonitor {
  setBaseline(baseline: BehavioralBaseline): void;
  recordInvocation(toolName: string, argsHash: HashHex): void;
  measure(): BehavioralMeasurement;
  reset(): void;
}

// ── Delegation ───────────────────────────────────────────────────

export interface DelegationRecord {
  parent_artifact_hash: HashHex;
  child_artifact_hash: HashHex;
  effective_ttl_seconds: number;
  scope_reduction: {
    triggers_removed: string[];
    measurement_types_removed: string[];
  };
  purpose: string;
  timestamp: string;
}

export interface DelegationRequest {
  enforcement_triggers: EnforcementAction[];
  measurement_types: MeasurementType[];
  requested_ttl_seconds: number;
  delegation_purpose: string;
}

export interface DelegationResult {
  success: boolean;
  child_artifact?: PolicyArtifact;
  child_artifact_hash?: string;
  parent_artifact_hash: string;
  effective_ttl_seconds?: number;
  scope_reduction?: {
    triggers_removed: string[];
    measurement_types_removed: string[];
  };
  error?: string;
}
