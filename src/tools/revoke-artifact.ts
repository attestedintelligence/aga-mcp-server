import { pkToHex } from '../crypto/sign.js';
import { utcNow } from '../utils/timestamp.js';
import type { ServerContext } from '../context.js';
import type { RevocationRecord } from '../core/types.js';

export interface RevokeArtifactArgs {
  sealed_hash?: string;
  reason: string;
  transition_to?: 'TERMINATED' | 'SAFE_STATE';
}

export async function handleRevokeArtifact(args: RevokeArtifactArgs, ctx: ServerContext) {
  const sealedHash = args.sealed_hash ?? ctx.activeArtifact?.sealed_hash;
  if (!sealedHash) return ctx.error('No sealed_hash provided and no active artifact.');

  const transition = args.transition_to ?? 'TERMINATED';
  ctx.portal.revoke(sealedHash, transition);

  const record: RevocationRecord = {
    artifact_sealed_hash: sealedHash,
    reason: args.reason,
    revoked_by: pkToHex(ctx.issuerKP.publicKey),
    timestamp: utcNow(),
  };
  await ctx.appendToChain('REVOCATION', { ...record, transition_to: transition });

  return ctx.json({
    success: true,
    revoked: sealedHash,
    portal_state: ctx.portal.state,
    reason: args.reason,
    transition_to: transition,
  });
}
