import { processDisclosure } from '../core/disclosure.js';
import { utcNow } from '../utils/timestamp.js';
import type { ServerContext } from '../context.js';
import type { DisclosureMode } from '../core/types.js';

export interface DiscloseClaimArgs {
  claim_id: string;
  requester_id?: string;
  mode?: DisclosureMode;
}

export async function handleDiscloseClaim(args: DiscloseClaimArgs, ctx: ServerContext) {
  const latest = await ctx.storage.getLatestEvent();
  const result = processDisclosure(
    {
      requested_claim_id: args.claim_id,
      requester_id: args.requester_id ?? 'anonymous',
      mode: args.mode ?? 'REVEAL_MIN',
      timestamp: utcNow(),
    },
    ctx.defaultClaims,
    ctx.claimValues,
    1,
    latest?.sequence_number ?? 0,
    ctx.portalKP,
  );
  if (result.substitution_receipt) {
    await ctx.appendToChain('SUBSTITUTION', result.substitution_receipt);
  } else {
    await ctx.appendToChain('DISCLOSURE', {
      claim_id: args.claim_id,
      mode: args.mode ?? 'REVEAL_MIN',
      permitted: result.permitted,
    });
  }
  return ctx.json({ success: true, ...result });
}
