/**
 * Constrained Sub-Agent Delegation.
 * NCCoE filing: "Scope can only diminish through delegation, never expand."
 *
 * Primary agent's portal issues a derived artifact to secondary agent:
 * - TTL <= parent's remaining TTL
 * - Scope can only diminish, never expand
 * - Secondary's genesis links to parent's chain
 */
import { generateArtifact, hashArtifact } from './artifact.js';
import { isExpired } from '../utils/timestamp.js';
import type { PolicyArtifact, EnforcementAction, MeasurementType } from './types.js';
import type { KeyPair } from '../crypto/types.js';

export interface DelegationRequest {
  /** Subset of parent's enforcement triggers */
  enforcement_triggers: EnforcementAction[];
  /** Subset of parent's measurement types */
  measurement_types: MeasurementType[];
  /** Requested TTL in seconds (will be clamped to parent remaining) */
  requested_ttl_seconds: number;
  /** Description of the delegation purpose */
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

/**
 * Derive a constrained artifact from a parent artifact.
 * Key rule: scope can only diminish, never expand.
 */
export function deriveArtifact(
  parentArtifact: PolicyArtifact,
  request: DelegationRequest,
  issuerKP: KeyPair
): DelegationResult {
  const parentHash = hashArtifact(parentArtifact);

  // Validate parent is not expired
  if (isExpired(parentArtifact.issued_timestamp, parentArtifact.enforcement_parameters.ttl_seconds)) {
    return { success: false, parent_artifact_hash: parentHash, error: 'Parent artifact TTL has expired' };
  }

  // Calculate parent remaining TTL
  const parentIssuedMs = Date.parse(parentArtifact.issued_timestamp);
  const parentExpiresMs = parentIssuedMs + (parentArtifact.enforcement_parameters.ttl_seconds * 1000);
  const remainingMs = parentExpiresMs - Date.now();
  const remainingSeconds = Math.max(0, Math.floor(remainingMs / 1000));

  // Clamp child TTL to parent remaining
  const effectiveTTL = Math.min(request.requested_ttl_seconds, remainingSeconds);
  if (effectiveTTL <= 0) {
    return { success: false, parent_artifact_hash: parentHash, error: 'No remaining TTL to delegate' };
  }

  // Validate triggers are subset of parent
  const parentTriggers = new Set(parentArtifact.enforcement_parameters.enforcement_triggers);
  const invalidTriggers = request.enforcement_triggers.filter(t => !parentTriggers.has(t));
  if (invalidTriggers.length > 0) {
    return { success: false, parent_artifact_hash: parentHash, error: `Cannot expand scope: triggers [${invalidTriggers.join(', ')}] not in parent` };
  }

  // Validate measurement types are subset of parent
  const parentTypes = new Set<string>(parentArtifact.enforcement_parameters.measurement_types);
  const invalidTypes = request.measurement_types.filter(t => !parentTypes.has(t));
  if (invalidTypes.length > 0) {
    return { success: false, parent_artifact_hash: parentHash, error: `Cannot expand scope: measurement types [${invalidTypes.join(', ')}] not in parent` };
  }

  // Build constrained child artifact
  const childArtifact = generateArtifact({
    subject_identifier: parentArtifact.subject_identifier,
    policy_reference: parentArtifact.policy_reference,
    policy_version: parentArtifact.policy_version,
    sealed_hash: parentArtifact.sealed_hash,
    seal_salt: parentArtifact.seal_salt,
    enforcement_parameters: {
      measurement_cadence_ms: parentArtifact.enforcement_parameters.measurement_cadence_ms,
      ttl_seconds: effectiveTTL,
      enforcement_triggers: request.enforcement_triggers,
      re_attestation_required: parentArtifact.enforcement_parameters.re_attestation_required,
      measurement_types: request.measurement_types,
    },
    disclosure_policy: parentArtifact.disclosure_policy,  // cannot expand
    evidence_commitments: parentArtifact.evidence_commitments,
    issuer_keypair: issuerKP,
  });

  // Track scope reduction
  const triggersRemoved = [...parentTriggers].filter(t => !request.enforcement_triggers.includes(t as EnforcementAction));
  const typesRemoved = [...parentTypes].filter(t => !request.measurement_types.includes(t as MeasurementType));

  return {
    success: true,
    child_artifact: childArtifact,
    child_artifact_hash: hashArtifact(childArtifact),
    parent_artifact_hash: parentHash,
    effective_ttl_seconds: effectiveTTL,
    scope_reduction: {
      triggers_removed: triggersRemoved,
      measurement_types_removed: typesRemoved,
    },
  };
}

/**
 * Validate that a child artifact is a valid delegation of a parent.
 */
export function validateDelegation(parent: PolicyArtifact, child: PolicyArtifact): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // TTL must be <= parent TTL
  if (child.enforcement_parameters.ttl_seconds > parent.enforcement_parameters.ttl_seconds) {
    errors.push(`Child TTL (${child.enforcement_parameters.ttl_seconds}s) exceeds parent (${parent.enforcement_parameters.ttl_seconds}s)`);
  }

  // Triggers must be subset
  const pTriggers = new Set<string>(parent.enforcement_parameters.enforcement_triggers);
  for (const t of child.enforcement_parameters.enforcement_triggers) {
    if (!pTriggers.has(t)) errors.push(`Child trigger '${t}' not in parent scope`);
  }

  // Measurement types must be subset
  const pTypes = new Set<string>(parent.enforcement_parameters.measurement_types);
  for (const t of child.enforcement_parameters.measurement_types) {
    if (!pTypes.has(t)) errors.push(`Child measurement type '${t}' not in parent scope`);
  }

  // Subject must match
  if (child.subject_identifier.bytes_hash !== parent.subject_identifier.bytes_hash) {
    errors.push('Child subject bytes_hash does not match parent');
  }

  return { valid: errors.length === 0, errors };
}
