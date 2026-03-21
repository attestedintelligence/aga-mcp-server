/**
 * Governance Middleware: wraps every MCP tool handler.
 *
 * NCCoE filing Section 4: "The portal operates as a Policy Enforcement Point (PEP)...
 * Every tool invocation, API call, actuator command, and data access passes through
 * the portal, which evaluates it against the sealed artifact's enforcement parameters."
 */
import type { Portal } from '../core/portal.js';
import type { QuarantineState } from '../core/types.js';
import { captureInput } from '../core/quarantine.js';
import type { BehavioralMonitor } from '../core/behavioral.js';
import { sha256Str } from '../crypto/hash.js';
import { canonicalize } from '../utils/canonical.js';

export type ToolResult = { content: Array<{ type: 'text'; text: string }> };
export type ToolHandler<T = any> = (args: T) => Promise<ToolResult>;

const UNGOVERNED_TOOLS = new Set([
  // V1 names (backward compat)
  'get_server_info', 'get_portal_state', 'get_receipts', 'get_chain_events',
  'list_claims', 'init_chain', 'attest_subject', 'verify_chain',
  // V2 names
  'aga_server_info', 'aga_get_portal_state', 'aga_init_chain', 'aga_create_artifact',
  'aga_verify_artifact', 'aga_verify_bundle', 'aga_get_chain', 'aga_quarantine_status',
  'aga_set_verification_tier', 'aga_demonstrate_lifecycle', 'aga_measure_behavior',
]);

export function createGovernanceWrapper(
  portal: Portal,
  quarantine: { current: QuarantineState | null },
  toolName: string,
  behavioralMonitor?: BehavioralMonitor
) {
  const isGoverned = !UNGOVERNED_TOOLS.has(toolName);

  return function wrapHandler<T>(handler: ToolHandler<T>): ToolHandler<T> {
    if (!isGoverned) return handler;

    return async (args: T): Promise<ToolResult> => {
      const j = (x: unknown): ToolResult => ({
        content: [{ type: 'text', text: JSON.stringify(x, null, 2) }]
      });

      if (portal.state === 'TERMINATED' || portal.state === 'SAFE_STATE') {
        return j({
          success: false,
          error: `GOVERNANCE_BLOCKED: Portal is ${portal.state.toLowerCase()}. Agent governance has been revoked. Re-attestation required.`,
          portal_state: portal.state,
          tool: toolName,
        });
      }

      if (portal.state === 'PHANTOM_QUARANTINE' && quarantine.current?.active) {
        captureInput(quarantine.current, `tool_call:${toolName}`, {
          tool: toolName, args, timestamp: new Date().toISOString(),
        });
        return j({
          success: false,
          error: 'GOVERNANCE_QUARANTINED: Agent is in phantom quarantine. All outputs are severed. Inputs are being captured for forensic analysis.',
          portal_state: portal.state,
          tool: toolName,
          forensic_capture: true,
        });
      }

      if (portal.state === 'INITIALIZATION' || portal.state === 'ARTIFACT_VERIFICATION') {
        return j({
          success: false,
          error: 'GOVERNANCE_NOT_READY: No active policy artifact. Call aga_create_artifact first.',
          portal_state: portal.state,
          tool: toolName,
        });
      }

      if (behavioralMonitor) {
        const argsHash = sha256Str(canonicalize(args));
        behavioralMonitor.recordInvocation(toolName, argsHash);
      }
      return handler(args);
    };
  };
}
