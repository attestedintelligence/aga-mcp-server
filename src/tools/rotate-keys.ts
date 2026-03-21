import { pkToHex } from '../crypto/sign.js';
import { rotateKeys } from '../core/identity.js';
import type { ServerContext } from '../context.js';

export interface RotateKeysArgs {
  key_type?: 'issuer' | 'portal' | 'chain';
  keypair?: 'issuer' | 'portal' | 'chain';
  reason?: string;
}

export async function handleRotateKeys(args: RotateKeysArgs, ctx: ServerContext) {
  const keyType = args.key_type ?? args.keypair;
  if (!keyType) return ctx.error('Provide key_type or keypair parameter.');

  let result;
  switch (keyType) {
    case 'issuer':
      result = rotateKeys(ctx.issuerKP);
      (ctx as any).issuerKP = result.newKeyPair;
      break;
    case 'portal':
      result = rotateKeys(ctx.portalKP);
      (ctx as any).portalKP = result.newKeyPair;
      break;
    case 'chain':
      result = rotateKeys(ctx.chainKP);
      (ctx as any).chainKP = result.newKeyPair;
      break;
    default:
      return ctx.error(`Invalid key_type: ${keyType}. Must be issuer, portal, or chain.`);
  }

  await ctx.appendToChain('KEY_ROTATION', {
    key_type: keyType,
    old_public_key: result.oldPublicKeyHex,
    new_public_key: result.newPublicKeyHex,
    rotated_at: result.rotatedAt,
    reason: args.reason ?? 'Key rotation',
  });

  return ctx.json({
    success: true,
    key_type: keyType,
    old_public_key: result.oldPublicKeyHex,
    new_public_key: result.newPublicKeyHex,
    rotated_at: result.rotatedAt,
    reason: args.reason,
  });
}
