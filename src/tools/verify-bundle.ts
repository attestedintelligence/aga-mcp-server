import { verifyBundleOffline } from '../core/bundle.js';
import type { ServerContext } from '../context.js';
import type { EvidenceBundle } from '../core/types.js';

export interface VerifyBundleArgs {
  bundle: EvidenceBundle;
  pinned_public_key: string;
}

export async function handleVerifyBundle(args: VerifyBundleArgs, ctx: ServerContext) {
  const verification = verifyBundleOffline(args.bundle, args.pinned_public_key);
  return ctx.json({ success: true, verification });
}
