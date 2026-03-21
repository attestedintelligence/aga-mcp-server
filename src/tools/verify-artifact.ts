import { verifyArtifactSignature } from '../core/artifact.js';
import type { ServerContext } from '../context.js';
import type { PolicyArtifact } from '../core/types.js';

export interface VerifyArtifactArgs {
  artifact: PolicyArtifact;
  issuer_public_key: string;
}

export async function handleVerifyArtifact(args: VerifyArtifactArgs, ctx: ServerContext) {
  const valid = verifyArtifactSignature(args.artifact, args.issuer_public_key);
  return ctx.json({ success: true, signature_valid: valid });
}
