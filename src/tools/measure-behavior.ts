import { sha256Str } from '../crypto/hash.js';
import type { ServerContext } from '../context.js';

export interface MeasureBehaviorArgs {
  tool_name?: string;
  record_only?: boolean;
}

export async function handleMeasureBehavior(args: MeasureBehaviorArgs, ctx: ServerContext) {
  // If a tool_name is provided, record the invocation first
  if (args.tool_name) {
    ctx.behavioralMonitor.recordInvocation(args.tool_name, sha256Str(args.tool_name));
  }

  // If record_only, just acknowledge the recording
  if (args.record_only) {
    return ctx.json({
      success: true,
      recorded: args.tool_name,
      record_only: true,
    });
  }

  // Measure behavioral patterns
  const measurement = ctx.behavioralMonitor.measure();
  if (measurement.drift_detected) {
    await ctx.appendToChain('BEHAVIORAL_DRIFT', {
      violations: measurement.violations,
      behavioral_hash: measurement.behavioral_hash,
    });
  }
  return ctx.json({
    success: true,
    ...measurement,
    violation_count: measurement.violations.length,
  });
}
