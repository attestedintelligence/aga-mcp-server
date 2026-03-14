import type { ServerContext } from '../context.js';
import type { BehavioralBaseline } from '../core/behavioral.js';

export interface StartMonitoringArgs {
  behavioral_baseline?: BehavioralBaseline;
}

export async function handleStartMonitoring(args: StartMonitoringArgs, ctx: ServerContext) {
  if (!ctx.portal.artifact) return ctx.error('No artifact loaded. Call aga_create_artifact first.');
  if (ctx.portal.state !== 'ACTIVE_MONITORING') return ctx.error(`Cannot start monitoring in state ${ctx.portal.state}`);

  ctx.behavioralMonitor.reset();
  if (args.behavioral_baseline) {
    ctx.behavioralMonitor.setBaseline(args.behavioral_baseline);
  }

  return ctx.json({
    success: true,
    portal_state: ctx.portal.state,
    monitoring_active: true,
    baseline_set: !!args.behavioral_baseline,
  });
}
