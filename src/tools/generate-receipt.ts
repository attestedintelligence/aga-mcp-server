import { hashArtifact } from '../core/artifact.js';
import { generateReceipt } from '../core/receipt.js';
import type { ServerContext } from '../context.js';

export interface GenerateReceiptArgs {
  subject_content?: string;
  drift_detected?: boolean;
  drift_description?: string;
  measurement_type?: string;
  action_type?: string;
  action_detail?: string;
}

export async function handleGenerateReceipt(args: GenerateReceiptArgs, ctx: ServerContext) {
  if (!ctx.portal.artifact) return ctx.error('No artifact loaded.');

  const artRef = hashArtifact(ctx.portal.artifact);
  const mType = args.action_type ?? args.measurement_type ?? 'FILE_SYSTEM_STATE';
  const driftDesc = args.action_detail ?? args.drift_description ?? null;

  const receipt = generateReceipt({
    subjectId: ctx.portal.artifact.subject_identifier,
    artifactRef: artRef,
    currentHash: args.subject_content ?? artRef,
    sealedHash: ctx.portal.artifact.sealed_hash,
    driftDetected: args.drift_detected ?? false,
    driftDescription: driftDesc,
    action: null,
    measurementType: mType,
    seq: ctx.portal.sequenceCounter + 1,
    prevLeaf: ctx.portal.lastLeafHash,
    portalKP: ctx.portalKP,
  });
  await ctx.storage.storeReceipt(receipt);
  await ctx.appendToChain('INTERACTION_RECEIPT', {
    receipt_id: receipt.receipt_id,
    drift_detected: args.drift_detected ?? false,
    action_type: args.action_type,
    action_detail: args.action_detail,
  });

  return ctx.json({ success: true, receipt_id: receipt.receipt_id, receipt });
}
