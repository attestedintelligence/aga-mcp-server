import { pkToHex } from '../crypto/sign.js';
import type { ServerContext } from '../context.js';

export async function handleServerInfo(_args: Record<string, never>, ctx: ServerContext) {
  return ctx.json({
    server: 'AGA MCP Server',
    version: '2.0.0',
    protocol: 'Attested Governance Artifacts v2.0.0',
    patent: 'USPTO Application No. 19/433,835',
    nist_references: ['NIST-2025-0035', 'NCCoE AI Agent Identity'],
    framework_alignment: {
      spiffe: 'SPIFFE provides workload identity (SVID); AGA binds governance to workload intent',
      nist_sp_800_57: 'Key management aligned with SP 800-57 recommendations',
      nist_ai_rmf: 'AI Risk Management Framework: Govern, Map, Measure, Manage',
    },
    issuer_public_key: pkToHex(ctx.issuerKP.publicKey),
    portal_public_key: pkToHex(ctx.portalKP.publicKey),
    chain_public_key: pkToHex(ctx.chainKP.publicKey),
    chain_initialized: ctx.chainInitialized,
    portal_state: ctx.portal.state,
    verification_tier: ctx.verificationTier,
    measurement_count: ctx.measurementCount,
    uptime_ms: Date.now() - Date.parse(ctx.startTime),
  });
}
