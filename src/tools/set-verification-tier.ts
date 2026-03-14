import type { ServerContext } from '../context.js';

export interface SetVerificationTierArgs {
  tier: 'BRONZE' | 'SILVER' | 'GOLD';
}

const TIER_DESCRIPTIONS: Record<string, { description: string; trust_assumption: string }> = {
  BRONZE: {
    description: 'Cryptographic signatures only - artifact and receipt verification via Ed25519',
    trust_assumption: 'Trust that signing keys are not compromised',
  },
  SILVER: {
    description: 'Signatures plus continuity chain verification - tamper-evident event linkage',
    trust_assumption: 'Trust the chain operator plus key integrity',
  },
  GOLD: {
    description: 'Full verification with blockchain-anchored Merkle proofs - offline-verifiable evidence bundles',
    trust_assumption: 'Minimal trust - cryptographic proof anchored to immutable external ledger',
  },
};

export async function handleSetVerificationTier(args: SetVerificationTierArgs, ctx: ServerContext) {
  const validTiers = ['BRONZE', 'SILVER', 'GOLD'] as const;
  if (!validTiers.includes(args.tier as any)) {
    return ctx.error(`Invalid tier: ${args.tier}. Must be BRONZE, SILVER, or GOLD.`);
  }
  const previousTier = ctx.verificationTier;
  ctx.verificationTier = args.tier;
  const info = TIER_DESCRIPTIONS[args.tier];
  return ctx.json({
    success: true,
    previous_tier: previousTier,
    current_tier: ctx.verificationTier,
    description: info.description,
    trust_assumption: info.trust_assumption,
  });
}
