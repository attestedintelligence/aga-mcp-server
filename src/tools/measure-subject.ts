import { sha256Bytes, sha256Str } from '../crypto/hash.js';
import { hashArtifact } from '../core/artifact.js';
import { generateReceipt } from '../core/receipt.js';
import { initQuarantine } from '../core/quarantine.js';
import { canonicalize } from '../utils/canonical.js';
import type { ServerContext } from '../context.js';
import type { SubjectMetadata, EnforcementAction } from '../core/types.js';

export interface MeasureSubjectArgs {
  subject_content?: string;
  subject_bytes_hash?: string;
  subject_metadata_hash?: string;
  subject_metadata?: SubjectMetadata;
}

export async function handleMeasureSubject(args: MeasureSubjectArgs, ctx: ServerContext) {
  if (!ctx.portal.artifact) return ctx.error('No artifact loaded. Call aga_create_artifact first.');
  if (ctx.portal.state === 'TERMINATED') return ctx.error('Portal is terminated. Re-attest required.');
  if (ctx.portal.state === 'SAFE_STATE') return ctx.error('Portal is in safe state. Re-attest required.');

  let currentBytesHash: string;
  let currentMetaHash: string;
  let match: boolean;

  if (args.subject_bytes_hash) {
    // Pre-computed hash mode
    currentBytesHash = args.subject_bytes_hash;
    currentMetaHash = args.subject_metadata_hash ?? ctx.portal.artifact.subject_identifier.metadata_hash;
    match = currentBytesHash === ctx.portal.artifact.subject_identifier.bytes_hash &&
            currentMetaHash === ctx.portal.artifact.subject_identifier.metadata_hash;
    if (!match && ctx.portal.state === 'ACTIVE_MONITORING') {
      (ctx.portal as any).state = 'DRIFT_DETECTED';
    }
  } else if (args.subject_content) {
    // Content mode - use portal.measure()
    const result = ctx.portal.measure(
      new TextEncoder().encode(args.subject_content),
      args.subject_metadata ?? {},
    );
    currentBytesHash = result.currentBytesHash;
    currentMetaHash = result.currentMetaHash;
    match = result.match;
    if (!result.ttl_ok) {
      ctx.measurementCount++;
      const receipt = generateReceipt({
        subjectId: ctx.portal.artifact.subject_identifier, artifactRef: hashArtifact(ctx.portal.artifact),
        currentHash: 'UNAVAILABLE', sealedHash: `${result.expectedBytesHash}||${result.expectedMetaHash}`,
        driftDetected: true, driftDescription: 'TTL expired - fail-closed termination', action: 'TERMINATE',
        measurementType: ctx.portal.artifact.enforcement_parameters.measurement_types.join(','),
        seq: ctx.portal.sequenceCounter + 1, prevLeaf: ctx.portal.lastLeafHash, portalKP: ctx.portalKP,
      });
      await ctx.storage.storeReceipt(receipt);
      await ctx.appendToChain('INTERACTION_RECEIPT', { receipt_id: receipt.receipt_id, drift_detected: true, enforcement_action: 'TERMINATE' });
      return ctx.json({ success: true, match: false, drift_detected: true, ttl_ok: false, revoked: false, enforcement_action: 'TERMINATE', portal_state: ctx.portal.state, receipt_id: receipt.receipt_id, measurement_count: ctx.measurementCount });
    }
    if (result.revoked) {
      ctx.measurementCount++;
      const receipt = generateReceipt({
        subjectId: ctx.portal.artifact.subject_identifier, artifactRef: hashArtifact(ctx.portal.artifact),
        currentHash: 'UNAVAILABLE', sealedHash: `${result.expectedBytesHash}||${result.expectedMetaHash}`,
        driftDetected: true, driftDescription: 'Artifact revoked - fail-closed termination', action: 'TERMINATE',
        measurementType: ctx.portal.artifact.enforcement_parameters.measurement_types.join(','),
        seq: ctx.portal.sequenceCounter + 1, prevLeaf: ctx.portal.lastLeafHash, portalKP: ctx.portalKP,
      });
      await ctx.storage.storeReceipt(receipt);
      await ctx.appendToChain('INTERACTION_RECEIPT', { receipt_id: receipt.receipt_id, drift_detected: true, enforcement_action: 'TERMINATE' });
      return ctx.json({ success: true, match: false, drift_detected: true, ttl_ok: true, revoked: true, enforcement_action: 'TERMINATE', portal_state: ctx.portal.state, receipt_id: receipt.receipt_id, measurement_count: ctx.measurementCount });
    }
  } else {
    return ctx.error('Provide either subject_content or subject_bytes_hash');
  }

  const artRef = hashArtifact(ctx.portal.artifact);
  const currentStr = `${currentBytesHash}||${currentMetaHash}`;
  const sealedStr = `${ctx.portal.artifact.subject_identifier.bytes_hash}||${ctx.portal.artifact.subject_identifier.metadata_hash}`;

  let action: EnforcementAction | null = null;
  let driftDesc: string | null = null;

  if (!match) {
    driftDesc = 'Subject modified - hash mismatch';
    action = ctx.portal.artifact.enforcement_parameters.enforcement_triggers[0] ?? 'ALERT_ONLY';
    if (ctx.portal.state === 'DRIFT_DETECTED') {
      ctx.portal.enforce(action);
    }
    if (action === 'QUARANTINE') ctx.quarantine = initQuarantine();
  }

  ctx.measurementCount++;

  const receipt = generateReceipt({
    subjectId: ctx.portal.artifact.subject_identifier,
    artifactRef: artRef,
    currentHash: currentStr,
    sealedHash: sealedStr,
    driftDetected: !match,
    driftDescription: driftDesc,
    action,
    measurementType: ctx.portal.artifact.enforcement_parameters.measurement_types.join(','),
    seq: ctx.portal.sequenceCounter + 1,
    prevLeaf: ctx.portal.lastLeafHash,
    portalKP: ctx.portalKP,
  });
  await ctx.storage.storeReceipt(receipt);
  await ctx.appendToChain('INTERACTION_RECEIPT', {
    receipt_id: receipt.receipt_id,
    drift_detected: !match,
    enforcement_action: action,
  });

  return ctx.json({
    success: true,
    match,
    drift_detected: !match,
    ttl_ok: true,
    revoked: false,
    enforcement_action: action,
    portal_state: ctx.portal.state,
    receipt_id: receipt.receipt_id,
    measurement_count: ctx.measurementCount,
  });
}
