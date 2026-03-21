import { sha256Str } from '../crypto/hash.js';
import { createGenesisEvent } from '../core/chain.js';
import type { ServerContext } from '../context.js';

export async function handleInitChain(args: { specification_hash?: string }, ctx: ServerContext) {
  if (ctx.chainInitialized) return ctx.error('Chain already initialized');
  const genesis = createGenesisEvent(ctx.chainKP, args.specification_hash ?? sha256Str('AGA Protocol Specification v2.0.0'));
  await ctx.storage.storeEvent(genesis);
  ctx.chainInitialized = true;
  ctx.portal.sequenceCounter = 0;
  ctx.portal.lastLeafHash = genesis.leaf_hash;
  return ctx.json({ success: true, genesis_event_id: genesis.event_id, genesis_leaf_hash: genesis.leaf_hash });
}
