import { hashArtifact } from '../core/artifact.js';
import { generateReceipt } from '../core/receipt.js';
import { initQuarantine } from '../core/quarantine.js';
import type { ServerContext } from '../context.js';
import type { EnforcementAction } from '../core/types.js';

export interface TriggerMeasurementArgs {
  subject_content?: string;
  subject_bytes_hash?: string;
  subject_metadata_hash?: string;
  measurement_type?: string;
  subject_metadata?: Record<string, string>;
}

export async function handleTriggerMeasurement(args: TriggerMeasurementArgs, ctx: ServerContext) {
  if (!ctx.portal.artifact) return ctx.error('No artifact loaded.');
  if (ctx.portal.state === 'TERMINATED' || ctx.portal.state === 'SAFE_STATE') {
    return ctx.error(`Portal is ${ctx.portal.state}. Artifact revoked or expired.`);
  }

  let match: boolean;
  let action: EnforcementAction | null = null;
  let driftDesc: string | null = null;
  let currentHash = 'UNAVAILABLE';

  if (args.subject_bytes_hash) {
    // Pre-computed hash mode
    const bMatch = args.subject_bytes_hash === ctx.portal.artifact.subject_identifier.bytes_hash;
    const mMatch = !args.subject_metadata_hash || args.subject_metadata_hash === ctx.portal.artifact.subject_identifier.metadata_hash;
    match = bMatch && mMatch;
    currentHash = args.subject_bytes_hash;
    if (!match && ctx.portal.state === 'ACTIVE_MONITORING') {
      (ctx.portal as any).state = 'DRIFT_DETECTED';
    }
  } else if (args.subject_content) {
    const meta = args.subject_metadata ?? {};
    const result = ctx.portal.measure(new TextEncoder().encode(args.subject_content), meta);
    match = result.match;
    currentHash = result.currentBytesHash || 'UNAVAILABLE';
    if (!result.ttl_ok) { driftDesc = 'TTL expired'; action = 'TERMINATE'; match = false; }
    else if (result.revoked) { driftDesc = 'Artifact revoked'; action = 'TERMINATE'; match = false; }
  } else {
    return ctx.error('Provide either subject_content or subject_bytes_hash');
  }

  if (!match && !action) {
    driftDesc = 'Subject modified - hash mismatch';
    action = ctx.portal.artifact.enforcement_parameters.enforcement_triggers[0] ?? 'ALERT_ONLY';
    if (ctx.portal.state === 'DRIFT_DETECTED') {
      ctx.portal.enforce(action);
    }
    if (action === 'QUARANTINE') ctx.quarantine = initQuarantine();
  }

  ctx.measurementCount++;
  const artRef = hashArtifact(ctx.portal.artifact);
  const mType = args.measurement_type ?? ctx.portal.artifact.enforcement_parameters.measurement_types[0] ?? 'FILE_SYSTEM_STATE';

  const receipt = generateReceipt({
    subjectId: ctx.portal.artifact.subject_identifier,
    artifactRef: artRef,
    currentHash,
    sealedHash: ctx.portal.artifact.subject_identifier.bytes_hash,
    driftDetected: !match,
    driftDescription: driftDesc,
    action,
    measurementType: mType,
    seq: ctx.portal.sequenceCounter + 1,
    prevLeaf: ctx.portal.lastLeafHash,
    portalKP: ctx.portalKP,
  });
  await ctx.storage.storeReceipt(receipt);
  await ctx.appendToChain('INTERACTION_RECEIPT', {
    receipt_id: receipt.receipt_id,
    drift_detected: !match,
    enforcement_action: action,
    measurement_type: mType,
  });

  return ctx.json({
    success: true,
    match,
    drift_detected: !match,
    enforcement_action: action,
    portal_state: ctx.portal.state,
    receipt_id: receipt.receipt_id,
    measurement_type: mType,
    measurement_count: ctx.measurementCount,
  });
}
