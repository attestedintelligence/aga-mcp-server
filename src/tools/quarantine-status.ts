import type { ServerContext } from '../context.js';

export async function handleQuarantineStatus(_args: Record<string, never>, ctx: ServerContext) {
  if (ctx.portal.state !== 'PHANTOM_QUARANTINE' && !ctx.quarantine?.active) {
    return ctx.error('Quarantine status unavailable - portal is not in quarantine state', {
      portal_state: ctx.portal.state,
    });
  }

  return ctx.json({
    quarantine_active: ctx.quarantine?.active ?? false,
    started_at: ctx.quarantine?.started_at ?? null,
    inputs_captured: ctx.quarantine?.inputs_captured ?? 0,
    outputs_severed: ctx.quarantine?.outputs_severed ?? false,
    forensic_buffer_size: ctx.quarantine?.forensic_buffer.length ?? 0,
    portal_state: ctx.portal.state,
  });
}
