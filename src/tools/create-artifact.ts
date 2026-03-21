import { sha256Str } from '../crypto/hash.js';
import { pkToHex } from '../crypto/sign.js';
import { computeSubjectIdFromString } from '../core/subject.js';
import { performAttestation } from '../core/attestation.js';
import { generateArtifact, hashArtifact } from '../core/artifact.js';
import type { ServerContext } from '../context.js';
import type { SubjectMetadata, EnforcementAction, MeasurementType } from '../core/types.js';
import type { BehavioralBaseline } from '../types.js';

export interface CreateArtifactArgs {
  // Content-based (V1 pattern)
  subject_content?: string;
  subject_metadata?: SubjectMetadata;
  // Hash-based (V2 pattern - pre-computed hashes)
  subject_bytes_hash?: string;
  subject_metadata_hash?: string;
  // Custom enforcement parameters
  measurement_cadence_ms?: number;
  enforcement_action?: string;
  ttl_seconds?: number;
  measurement_types?: string[];
  // Evidence and behavioral
  evidence_items?: Array<{ label: string; content: string }>;
  behavioral_baseline?: BehavioralBaseline;
}

export async function handleCreateArtifact(args: CreateArtifactArgs, ctx: ServerContext) {
  // Determine subject identifier - support both content and hash inputs
  let subId: { bytes_hash: string; metadata_hash: string };
  if (args.subject_bytes_hash && args.subject_metadata_hash) {
    subId = { bytes_hash: args.subject_bytes_hash, metadata_hash: args.subject_metadata_hash };
  } else if (args.subject_content) {
    subId = computeSubjectIdFromString(args.subject_content, args.subject_metadata ?? {});
  } else {
    return ctx.error('Provide either subject_content or subject_bytes_hash + subject_metadata_hash');
  }

  // Build enforcement parameters - merge custom with defaults
  const enforcement = {
    measurement_cadence_ms: args.measurement_cadence_ms ?? ctx.defaultEnforcement.measurement_cadence_ms,
    ttl_seconds: args.ttl_seconds ?? ctx.defaultEnforcement.ttl_seconds,
    enforcement_triggers: args.enforcement_action
      ? [args.enforcement_action as EnforcementAction]
      : ctx.defaultEnforcement.enforcement_triggers,
    re_attestation_required: ctx.defaultEnforcement.re_attestation_required,
    measurement_types: (args.measurement_types ?? ctx.defaultEnforcement.measurement_types.map(String)) as MeasurementType[],
  };

  const policyRef = sha256Str(JSON.stringify(enforcement));
  const att = performAttestation({
    subject_identifier: subId,
    policy_reference: policyRef,
    evidence_items: args.evidence_items ?? [],
  });
  if (!att.success || !att.sealed_hash || !att.seal_salt) {
    return ctx.error(att.rejection_reason ?? 'Attestation failed');
  }

  // Track whether this is a re-attestation (after revocation)
  const previousArtifact = ctx.activeArtifact;
  const isReAttestation = previousArtifact !== null && (
    ctx.portal.state === 'TERMINATED' || ctx.portal.state === 'SAFE_STATE' ||
    ctx.portal.isRevoked(previousArtifact.sealed_hash)
  );

  const artifact = generateArtifact({
    subject_identifier: subId,
    policy_reference: policyRef,
    policy_version: isReAttestation ? (previousArtifact!.policy_version + 1) : 1,
    sealed_hash: att.sealed_hash,
    seal_salt: att.seal_salt,
    enforcement_parameters: enforcement,
    disclosure_policy: ctx.defaultClaims,
    evidence_commitments: att.evidence_commitments,
    issuer_keypair: ctx.issuerKP,
  });
  await ctx.storage.storeArtifact(artifact);

  ctx.portal.reset();
  ctx.portal.loadArtifact(artifact, pkToHex(ctx.issuerKP.publicKey));
  ctx.activeArtifact = artifact;
  ctx.quarantine = null;
  ctx.measurementCount = 0;
  ctx.behavioralMonitor.reset();
  if (args.behavioral_baseline) ctx.behavioralMonitor.setBaseline(args.behavioral_baseline);

  const eventType = isReAttestation ? 'RE_ATTESTATION' : 'POLICY_ISSUANCE';
  const eventPayload: Record<string, unknown> = {
    artifact_hash: hashArtifact(artifact),
    sealed_hash: artifact.sealed_hash,
  };
  if (isReAttestation && previousArtifact) {
    eventPayload.predecessor_sealed_hash = previousArtifact.sealed_hash;
    eventPayload.predecessor_artifact_hash = hashArtifact(previousArtifact);
  }
  await ctx.appendToChain(eventType as any, eventPayload);

  return ctx.json({
    success: true,
    artifact_hash: hashArtifact(artifact),
    sealed_hash: artifact.sealed_hash,
    subject_identifier: subId,
    portal_state: ctx.portal.state,
    issuer_public_key: pkToHex(ctx.issuerKP.publicKey),
    verification_tier: ctx.verificationTier,
    event_type: eventType,
    enforcement_parameters: enforcement,
    evidence_commitments: att.evidence_commitments,
    is_re_attestation: isReAttestation,
  });
}
