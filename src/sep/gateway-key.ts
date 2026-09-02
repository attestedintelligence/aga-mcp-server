// Gateway signing-key resolution — the ONE place both binaries read the operator's key contract.
//
// This package ships two bins (`aga-mcp-server` and `aga-proxy`). Until now only the MCP server
// honoured AGA_GATEWAY_KEY / AGA_GATEWAY_KEY_FILE; `aga-proxy` called generateSigner() unconditionally,
// so an operator who correctly set the variable and started the proxy was **silently ignored** — no
// effect and no warning, and their evidence bundles were unpinnable without them ever being told.
// That is worse than unsupported: silence defeats a correct configuration.
//
// Both binaries now call resolveGatewaySigner(). One contract, one implementation, one set of
// warnings. Do NOT introduce a second variable name for the proxy: one installable must not have two
// key contracts.
import { readFileSync } from 'node:fs';
import { generateSigner, seedFromHex, signerFromSeed, type SepSigner } from './crypto.js';

/** How the active signing key was obtained. `ephemeral` means provenance cannot be pinned. */
export type GatewayKeySource =
  | 'AGA_GATEWAY_KEY'
  | 'AGA_GATEWAY_KEY_FILE'
  | 'ephemeral'
  | 'ephemeral-requested'
  | 'ephemeral-after-error';

export interface ResolvedGatewayKey {
  signer: SepSigner;
  /** Present only when the key was generated here; callers may persist it. Never logged. */
  seed?: Uint8Array;
  source: GatewayKeySource;
  /** True when the key rotates on restart, so a pinned verifier will fail after one. */
  ephemeral: boolean;
}

export interface ResolveGatewayKeyOptions {
  /** Caller explicitly asked for a throwaway key: skip the environment, warn once, no error. */
  forceEphemeral?: boolean;
  /** Label used in log lines, e.g. 'aga' or 'aga-proxy'. */
  logPrefix?: string;
  /**
   * Seed to use when falling back to ephemeral. The MCP server passes its portal keypair's secret so
   * the unconfigured case keeps the exact behaviour it has always had; the proxy passes nothing and
   * gets a fresh random key. Extracting the resolver must not silently change either binary — only
   * where the code lives.
   */
  fallbackSeed?: Uint8Array;
  /**
   * Where warnings go. MUST default to stderr: the MCP server speaks JSON-RPC on stdout and any
   * stray byte there corrupts the stream.
   */
  warn?: (message: string) => void;
}

const EPHEMERAL_NOTE =
  'it rotates on restart, so evidence-bundle provenance cannot be pinned across restarts. ' +
  'Set AGA_GATEWAY_KEY (64-hex 32-byte seed) or AGA_GATEWAY_KEY_FILE to persist it. See DEPLOYMENT.md.';

/**
 * Resolve the gateway signing key from the operator's environment.
 *
 * Order: AGA_GATEWAY_KEY, then AGA_GATEWAY_KEY_FILE, then a fresh ephemeral key.
 *
 * An invalid or unreadable key **warns and falls back** rather than exiting. That is deliberate and
 * matches the behaviour the MCP server has always had: this process is usually a long-lived sidecar,
 * and refusing to start would take a governed boundary offline over a key that only affects whether
 * provenance is *pinnable*. Integrity, chaining, and the deny path are unaffected by which key signs.
 * If that trade is ever revisited, change it for BOTH binaries in one commit — divergence here is the
 * defect this module exists to remove.
 *
 * Never logs key material: only the variable name that was tried, and the derived PUBLIC key.
 */
export function resolveGatewaySigner(options: ResolveGatewayKeyOptions = {}): ResolvedGatewayKey {
  const prefix = options.logPrefix ?? 'aga';
  const warn = options.warn ?? ((m: string) => console.error(m));

  // One ephemeral path, so fallbackSeed is honoured identically wherever we land here.
  const makeEphemeral = (source: GatewayKeySource): ResolvedGatewayKey => {
    if (options.fallbackSeed) {
      return { signer: signerFromSeed(options.fallbackSeed), source, ephemeral: true };
    }
    const { signer, seed } = generateSigner();
    return { signer, seed, source, ephemeral: true };
  };

  if (options.forceEphemeral) {
    warn(`[${prefix}] Using an EPHEMERAL gateway signing key by request (--ephemeral) — ${EPHEMERAL_NOTE}`);
    return makeEphemeral('ephemeral-requested');
  }

  const envKey = process.env.AGA_GATEWAY_KEY;
  const keyFile = process.env.AGA_GATEWAY_KEY_FILE;

  try {
    if (envKey) {
      return { signer: signerFromSeed(seedFromHex(envKey)), source: 'AGA_GATEWAY_KEY', ephemeral: false };
    }
    if (keyFile) {
      return {
        signer: signerFromSeed(seedFromHex(readFileSync(keyFile, 'utf8'))),
        source: 'AGA_GATEWAY_KEY_FILE',
        ephemeral: false,
      };
    }
  } catch (e) {
    const which = envKey ? 'AGA_GATEWAY_KEY' : 'AGA_GATEWAY_KEY_FILE';
    warn(`[${prefix}] gateway key from ${which} is invalid (${String(e)}); falling back to an ephemeral key.`);
    warn(`[${prefix}] Using an EPHEMERAL gateway signing key — ${EPHEMERAL_NOTE}`);
    return makeEphemeral('ephemeral-after-error');
  }

  warn(`[${prefix}] Using an EPHEMERAL gateway signing key — ${EPHEMERAL_NOTE}`);
  return makeEphemeral('ephemeral');
}

/**
 * One line naming the active identity, for a startup banner.
 *
 * An operator needs the public key to pin it out of band, and a verifier that reads the key out of
 * the bundle it is checking proves nothing about issuance — so printing it here, before any bundle
 * exists, is what makes honest pinning possible.
 */
export function describeGatewayKey(resolved: ResolvedGatewayKey): string {
  const origin = resolved.ephemeral ? 'ephemeral, rotates on restart' : `persisted via ${resolved.source}`;
  return `gateway key ${resolved.signer.publicKeyHex} (${origin})`;
}
