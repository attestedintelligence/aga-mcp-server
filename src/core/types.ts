/**
 * V3: Aligned with NIST-2025-0035 and NCCoE AI Agent Identity filings.
*/
import type { HashHex, SignatureBase64, SaltHex, MerkleInclusionProof } from '../crypto/types.js';

// ── Subject (100, 102, 104, 106, 126) ──────────────────────────

export interface SubjectIdentifier {          // Ref 126
  bytes_hash: HashHex;                        // Ref 104
  metadata_hash: HashHex;                     // Ref 106
}

export interface SubjectMetadata {
  filename?: string;
  creation_timestamp?: string;
  author?: string;
  version?: string;
  content_type?: string;
  [key: string]: unknown;
}

// ── Enforcement (130–136, 162–168) ──────────────────────────────

export type EnforcementAction =
  | 'TERMINATE'           // Ref 162: immediate kill
  | 'QUARANTINE'          // Ref 164: phantom execution
  | 'NETWORK_ISOLATE'     // Ref 166: sever network, continue local
  | 'SAFE_STATE'          // Ref 168: return-to-home / controlled shutdown
  | 'KEY_REVOKE'          // invalidate crypto keys
  | 'TOKEN_INVALIDATE'    // revoke access tokens
  | 'ACTUATOR_DISCONNECT' // sever physical actuator connections
  | 'ALERT_ONLY';         // log without enforcement (gradual deployment)

export type MeasurementType =
  | 'EXECUTABLE_IMAGE' | 'LOADED_MODULES' | 'CONTAINER_IMAGE'
  | 'CONFIG_MANIFEST'  | 'SBOM'           | 'TEE_QUOTE'
  | 'MEMORY_REGIONS'   | 'CONTROL_FLOW'   | 'FILE_SYSTEM_STATE'
  | 'NETWORK_CONFIG';

export interface EnforcementParams {           // Ref 130
  measurement_cadence_ms: number;              // Ref 132
  ttl_seconds: number;                         // Ref 134
  enforcement_triggers: EnforcementAction[];   // Ref 136
  re_attestation_required: boolean;
  measurement_types: MeasurementType[];
  behavioral_baseline?: BehavioralBaselineRef; // NCCoE §6: optional behavioral baseline reference
}

/** Inline behavioral baseline reference for EnforcementParams (NCCoE §6, CAISI §1a) */
export interface BehavioralBaselineRef {
  permitted_tools: string[];
  forbidden_sequences: string[][];
  rate_limits: Record<string, number>;
}

// ── Policy & Disclosure (112, 138–142) ──────────────────────────

export type Sensitivity = 'S1_LOW' | 'S2_MODERATE' | 'S3_HIGH' | 'S4_CRITICAL';
export type DisclosureMode = 'PROOF_ONLY' | 'REVEAL_MIN' | 'REVEAL_FULL';

export interface ClaimRecord {                 // Ref 140
  claim_id: string;
  sensitivity: Sensitivity;
  substitutes: string[];
  inference_risks: string[];
  permitted_modes: DisclosureMode[];
}

export interface SubstitutionRule {             // Ref 142
  original_claim_id: string;
  substitute_claim_id: string;
  conditions: Record<string, unknown>;
}

export interface DisclosurePolicy {            // Ref 138
  claims_taxonomy: ClaimRecord[];
  substitution_rules: SubstitutionRule[];
}

// ── Evidence Commitment (114) ───────────────────────────────────

export interface EvidenceCommitmentRecord {
  commitment: HashHex;
  salt: SaltHex;
  label: string;
}

// ── Policy Artifact (120, 122, 124, 144) ────────────────────────

export interface PolicyArtifact {              // Ref 122 (Weave Piece)
  schema_version: string;
  protocol_version: string;
  subject_identifier: SubjectIdentifier;
  policy_reference: HashHex;                   // Ref 128
  policy_version: number;
  sealed_hash: HashHex;                        // Ref 124
  seal_salt: SaltHex;                          // stored for audit
  issued_timestamp: string;
  effective_timestamp: string;
  expiration_timestamp: string | null;
  issuer_identifier: string;
  enforcement_parameters: EnforcementParams;
  disclosure_policy: DisclosurePolicy;
  evidence_commitments: EvidenceCommitmentRecord[];
  signature: SignatureBase64;                  // Ref 144
}

// ── Receipts (170, 172) ─────────────────────────────────────────
// V3: Generated for EVERY measurement, not just drift. Per NIST filing:
// "each measurement generates a signed receipt - match or mismatch"

export interface SignedReceipt {                // Ref 172
  receipt_id: string;
  subject_identifier: SubjectIdentifier;
  artifact_reference: HashHex;
  current_hash: string;
  sealed_hash: string;
  drift_detected: boolean;
  drift_description: string | null;
  enforcement_action: EnforcementAction | null;
  measurement_type: string;                    // V3: which measurement was performed
  timestamp: string;
  sequence_number: number;
  previous_leaf_hash: HashHex | null;
  portal_signature: SignatureBase64;
}

// ── Continuity Chain (180–196) ──────────────────────────────────

export type EventType =
  | 'GENESIS'
  | 'POLICY_ISSUANCE'
  | 'INTERACTION_RECEIPT'
  | 'REVOCATION'              // V3: mid-session revocation
  | 'ATTESTATION'
  | 'ANCHOR_BATCH'
  | 'DISCLOSURE'
  | 'SUBSTITUTION'
  | 'KEY_ROTATION'            // V3: key lifecycle event
  | 'BEHAVIORAL_DRIFT'        // NCCoE §6: behavioral pattern deviation
  | 'DELEGATION'              // NCCoE §4: sub-agent delegation
  | 'DEGRADATION'             // CAISI §4a: graceful degradation event
  | 'RE_ATTESTATION';         // TTL re-attestation

export interface GenesisPayload {
  protocol_version: string;
  taxonomy_version: string;
  root_fingerprint: string;
  specification_hash: HashHex;
  marker: 'GENESIS';
}

export interface ContinuityEvent {             // Ref 184
  schema_version: string;
  protocol_version: string;
  event_type: EventType;
  event_id: string;
  sequence_number: number;
  timestamp: string;
  previous_leaf_hash: HashHex | null;
  leaf_hash: HashHex;                          // Ref 186
  payload: unknown;                            // Ref 192
  payload_hash: HashHex;                       // Ref 194
  event_signature: SignatureBase64;            // Ref 196
}

export interface StructuralMetadata {          // Ref 190
  schema_version: string;
  protocol_version: string;
  event_type: EventType;
  event_id: string;
  sequence_number: number;
  timestamp: string;
  previous_leaf_hash: HashHex | null;
}

// ── Checkpoints (200–214) ───────────────────────────────────────

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

// ── Evidence Bundle (240–246) ───────────────────────────────────

export interface EvidenceBundle {
  artifact: PolicyArtifact;
  receipts: SignedReceipt[];
  merkle_proofs: MerkleInclusionProof[];
  checkpoint_reference: CheckpointReference;
  public_key: string;
  bundle_signature: SignatureBase64;
  verification_tier?: VerificationTier;         // CAISI §3b: Bronze/Silver/Gold tiering
}

// ── Disclosure (250–256) ────────────────────────────────────────

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

// ── Portal State Machine (150, 270–280) ─────────────────────────

export type PortalState =
  | 'INITIALIZATION'         // Ref 270
  | 'ARTIFACT_VERIFICATION'  // Ref 272
  | 'ACTIVE_MONITORING'      // Ref 274
  | 'DRIFT_DETECTED'         // Ref 276
  | 'PHANTOM_QUARANTINE'     // Ref 278
  | 'SAFE_STATE'             // Graceful degradation (TTL expiry)
  | 'TERMINATED';            // Ref 280

export type VerificationTier = 'BRONZE' | 'SILVER' | 'GOLD';

// ── Revocation (V3) ────────────────────────────────────────────
// Per NCCoE filing Phase 3b: "An administrator pushes a REVOCATION event
// to the continuity chain, invalidating the agent's active policy artifact."

export interface RevocationRecord {
  artifact_sealed_hash: HashHex;
  reason: string;
  revoked_by: string;                         // issuer pk hex
  timestamp: string;
}

// ── Quarantine (220–230) ────────────────────────────────────────

export interface QuarantineState {
  active: boolean;
  started_at: string | null;
  inputs_captured: number;
  outputs_severed: boolean;
  forensic_buffer: Array<{ timestamp: string; type: string; data: unknown }>;
  forensic_receipts?: string[];  // Receipt IDs from forensic capture
}

// ── Delegation (NCCoE §4) ──────────────────────────────────────

export interface DelegationRecord {
  sub_agent_id: string;
  parent_artifact_reference: HashHex;
  child_artifact: PolicyArtifact;
  permitted_tools: string[];
  ttl_seconds: number;
  delegation_timestamp: string;
  chain_sequence: number;
}

// ── Key Lifecycle ──────────────────────────────────────────────

export interface KeyRotationRecord {
  keypair_type: string;            // e.g. 'issuer', 'portal', 'chain'
  old_public_key: string;
  new_public_key: string;
  reason: string;
  rotation_timestamp: string;
  chain_sequence: number;
}

// ── Sensitivity Level Aliases ────────────────────────────────────
// Existing Sensitivity type uses S1_LOW etc. These aliases map to the short forms.
export type SensitivityLevel = 'S1' | 'S2' | 'S3' | 'S4';
