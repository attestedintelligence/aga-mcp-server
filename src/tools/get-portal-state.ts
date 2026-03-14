import type { ServerContext } from '../context.js';

export async function handleGetPortalState(_args: Record<string, never>, ctx: ServerContext) {
  return ctx.json({
    state: ctx.portal.state,
    artifact_loaded: !!ctx.portal.artifact,
    sealed_hash: ctx.portal.artifact?.sealed_hash ?? null,
    ttl_seconds: ctx.portal.artifact?.enforcement_parameters.ttl_seconds ?? null,
    issued_at: ctx.portal.artifact?.issued_timestamp ?? null,
    enforcement_triggers: ctx.portal.artifact?.enforcement_parameters.enforcement_triggers ?? [],
    sequence_counter: ctx.portal.sequenceCounter,
    quarantine_active: ctx.quarantine?.active ?? false,
    verification_tier: ctx.verificationTier,
    measurement_count: ctx.measurementCount,
  });
}
