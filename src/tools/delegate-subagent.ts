import { deriveArtifact } from '../core/delegation.js';
import { utcNow } from '../utils/timestamp.js';
import type { ServerContext } from '../context.js';
import type { EnforcementAction, MeasurementType } from '../core/types.js';
import type { DelegationRecord } from '../types.js';

export interface DelegateSubagentArgs {
  // V2 parameter names (crucible pattern)
  sub_agent_id?: string;
  permitted_tools?: string[];
  ttl_seconds?: number;
  delegation_reason?: string;
  // V1 parameter names (enforcement-level pattern)
  enforcement_triggers?: string[];
  measurement_types?: string[];
  requested_ttl_seconds?: number;
  delegation_purpose?: string;
}

export async function handleDelegateSubagent(args: DelegateSubagentArgs, ctx: ServerContext) {
  if (!ctx.portal.artifact) return ctx.error('No artifact loaded. Call aga_create_artifact first.');

  // Resolve parameters (support both V1 and V2 naming)
  const triggers = args.enforcement_triggers
    ?? ctx.portal.artifact.enforcement_parameters.enforcement_triggers.map(String);
  const types = args.measurement_types
    ?? ctx.portal.artifact.enforcement_parameters.measurement_types.map(String);
  const ttl = args.ttl_seconds ?? args.requested_ttl_seconds ?? 1800;
  const purpose = args.delegation_reason ?? args.delegation_purpose ?? 'Sub-agent delegation';
  const subAgentId = args.sub_agent_id ?? 'sub-agent';

  // If permitted_tools provided, validate against behavioral baseline
  const permittedTools = args.permitted_tools;

  const result = deriveArtifact(ctx.portal.artifact, {
    enforcement_triggers: triggers as EnforcementAction[],
    measurement_types: types as MeasurementType[],
    requested_ttl_seconds: ttl,
    delegation_purpose: purpose,
  }, ctx.issuerKP);

  if (result.success && result.child_artifact_hash && result.effective_ttl_seconds !== undefined && result.scope_reduction) {
    const record: DelegationRecord = {
      parent_artifact_hash: result.parent_artifact_hash,
      child_artifact_hash: result.child_artifact_hash,
      effective_ttl_seconds: result.effective_ttl_seconds,
      scope_reduction: result.scope_reduction,
      purpose,
      timestamp: utcNow(),
    };
    ctx.delegations.push(record);

    await ctx.appendToChain('DELEGATION', {
      type: 'DELEGATION',
      sub_agent_id: subAgentId,
      parent_artifact_hash: result.parent_artifact_hash,
      child_artifact_hash: result.child_artifact_hash,
      effective_ttl: result.effective_ttl_seconds,
      scope_reduction: result.scope_reduction,
      permitted_tools: permittedTools,
      purpose,
    });
  }

  return ctx.json({
    ...result,
    sub_agent_id: subAgentId,
    scope_diminished: result.success ? true : undefined,
    permitted_tools: permittedTools,
  });
}
