/**
 * Governance Middleware - wraps every MCP tool handler.
 *
 * NCCoE filing Section 4: "The portal operates as a Policy Enforcement Point (PEP)...
 * Every tool invocation, API call, actuator command, and data access passes through
 * the portal, which evaluates it against the sealed artifact's enforcement parameters."
 *
 * Behavior:
 * - TERMINATED state → reject all governed tools
 * - PHANTOM_QUARANTINE → capture tool call as forensic input, reject
 * - ACTIVE_MONITORING → allow, log to chain
 * - Ungoverned tools (get_server_info, get_portal_state, list_claims) → always allow
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
  'get_server_info',
  'get_portal_state',
  'get_receipts',
  'get_chain_events',
  'list_claims',
  'init_chain',        // must work before attestation
  'attest_subject',    // creates the governance relationship
  'verify_chain',      // read-only verification
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

      // TERMINATED → reject everything
      if (portal.state === 'TERMINATED') {
        return j({
          success: false,
          error: 'GOVERNANCE_BLOCKED: Portal is terminated. Agent governance has been revoked. Re-attestation required.',
          portal_state: portal.state,
          tool: toolName,
        });
      }

      // PHANTOM_QUARANTINE → capture as forensic input, reject
      if (portal.state === 'PHANTOM_QUARANTINE' && quarantine.current?.active) {
        captureInput(quarantine.current, `tool_call:${toolName}`, {
          tool: toolName,
          args,
          timestamp: new Date().toISOString(),
        });
        return j({
          success: false,
          error: 'GOVERNANCE_QUARANTINED: Agent is in phantom quarantine. All outputs are severed. Inputs are being captured for forensic analysis.',
          portal_state: portal.state,
          tool: toolName,
          forensic_capture: true,
        });
      }

      // INITIALIZATION or ARTIFACT_VERIFICATION → not yet governed
      if (portal.state === 'INITIALIZATION' || portal.state === 'ARTIFACT_VERIFICATION') {
        return j({
          success: false,
          error: 'GOVERNANCE_NOT_READY: No active policy artifact. Call attest_subject first.',
          portal_state: portal.state,
          tool: toolName,
        });
      }

      // ACTIVE_MONITORING or DRIFT_DETECTED → record + allow through
      if (behavioralMonitor) {
        const argsHash = sha256Str(canonicalize(args));
        behavioralMonitor.recordInvocation(toolName, argsHash);
      }
      return handler(args);
    };
  };
}
