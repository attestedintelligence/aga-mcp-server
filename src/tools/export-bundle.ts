import { hashArtifact } from '../core/artifact.js';
import { eventInclusionProof } from '../core/checkpoint.js';
import { generateBundle } from '../core/bundle.js';
import type { ServerContext } from '../context.js';

export async function handleExportBundle(_args: Record<string, never>, ctx: ServerContext) {
  const artifact = await ctx.storage.getLatestArtifact();
  if (!artifact) return ctx.error('No artifact');
  const cp = await ctx.storage.getLatestCheckpoint();
  if (!cp) return ctx.error('No checkpoint. Call aga_create_checkpoint first.');
  const receipts = await ctx.storage.getReceiptsByArtifact(hashArtifact(artifact));
  const batchEvents = await ctx.storage.getEvents(cp.batch_start_sequence, cp.batch_end_sequence);
  const proofs = receipts
    .filter(r => r.sequence_number >= cp.batch_start_sequence && r.sequence_number <= cp.batch_end_sequence)
    .map(r => eventInclusionProof(batchEvents, r.sequence_number));
  const bundle = generateBundle(artifact, receipts, proofs, cp, ctx.portalKP);
  return ctx.json({
    success: true,
    bundle,
    offline_verifiable: true,
    receipt_count: receipts.length,
    proof_count: proofs.length,
  });
}
