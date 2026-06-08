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
 * - ACTIVE_MONITORING → allow, record a signed PERMITTED SEP receipt, then run
 * - Ungoverned tools (UNGOVERNED_TOOLS below: read/bootstrap/evidence/monitor) → run unwrapped
 *
 * Single source of truth for the governed/ungoverned partition is UNGOVERNED_TOOLS. A tool is
 * GOVERNED (emits a signed PERMITTED/DENIED receipt) iff it is NOT in that set. Any new tool that
 * performs a side-effecting agent action MUST be governed (i.e. absent from the set).
 */
import type { Portal } from '../core/portal.js';
import type { QuarantineState } from '../core/types.js';
import { captureInput } from '../core/quarantine.js';
import type { BehavioralMonitor } from '../core/behavioral.js';
import { safeArgumentsHash } from '../sep/index.js';

export type ToolResult = { content: Array<{ type: 'text'; text: string }> };
export type ToolHandler<T = any> = (args: T) => Promise<ToolResult>;

/**
 * The authoritative ungoverned set (read/bootstrap/evidence/monitor). A tool is GOVERNED iff it
 * is NOT here. Exported so a test can assert the partition and catch drift. Adding a side-effecting
 * agent action? Do NOT list it here.
 */
export const UNGOVERNED_TOOLS = new Set([
  'get_server_info',
  'get_portal_state',
  'get_receipts',
  'get_chain_events',
  'list_claims',
  'init_chain',        // must work before attestation
  'attest_subject',    // creates the governance relationship (re-attest does NOT reset the SEP ledger)
  'verify_chain',      // read-only verification
  // Evidence operations: must work even after TERMINATION (you need to export/verify
  // the evidence ESPECIALLY after governance is revoked). Not agent actions → not SEP-recorded.
  'generate_evidence_bundle',
  'verify_bundle_offline',
  // Detective behavioral monitor: it self-records a signed SEP receipt for any drift finding
  // (and for opt-in enforcement) inside its own handler, so it is not double-recorded here.
  'measure_behavior',
]);

/** A governance decision surfaced to the SEP ledger (one signed receipt per governed call).
 *  `argsHash` is the PRECOMPUTED safe arguments_hash — the recorder must use it directly and
 *  never re-canonicalize the raw args (which could be a depth-bomb). */
export type GovernanceDecision = { tool: string; decision: 'PERMITTED' | 'DENIED'; reason: string; argsHash: string };

export function createGovernanceWrapper(
  portal: Portal,
  quarantine: { current: QuarantineState | null },
  toolName: string,
  behavioralMonitor?: BehavioralMonitor,
  record?: (d: GovernanceDecision) => void,
) {
  const isGoverned = !UNGOVERNED_TOOLS.has(toolName);

  return function wrapHandler<T>(handler: ToolHandler<T>): ToolHandler<T> {
    if (!isGoverned) return handler;

    return async (args: T): Promise<ToolResult> => {
      const j = (x: unknown): ToolResult => ({
        content: [{ type: 'text', text: JSON.stringify(x, null, 2) }]
      });
      // Hash the arguments ONCE, safely (never throws). `ok=false` means they could not be
      // canonicalized (e.g. a depth-bomb) — we fail closed below. Computing it up front means
      // every recorded decision (allow OR deny) carries a valid hash and can never be silently
      // dropped by a canonicalize throw (anti-DoS / anti-silent-erasure).
      const { hash: argsHash, ok: argsOk } = safeArgumentsHash(args);
      const deny = (reason: string, extra: Record<string, unknown> = {}): ToolResult => {
        record?.({ tool: toolName, decision: 'DENIED', reason, argsHash });
        return j({ success: false, error: reason, portal_state: portal.state, tool: toolName, ...extra });
      };

      // TERMINATED → reject everything
      if (portal.state === 'TERMINATED') {
        return deny('GOVERNANCE_BLOCKED: Portal is terminated. Agent governance has been revoked. Re-attestation required.');
      }

      // PHANTOM_QUARANTINE → capture as forensic input, reject
      if (portal.state === 'PHANTOM_QUARANTINE' && quarantine.current?.active) {
        captureInput(quarantine.current, `tool_call:${toolName}`, {
          tool: toolName,
          args,
          timestamp: new Date().toISOString(),
        });
        return deny('GOVERNANCE_QUARANTINED: Agent is in phantom quarantine. All outputs are severed. Inputs are being captured for forensic analysis.', { forensic_capture: true });
      }

      // INITIALIZATION or ARTIFACT_VERIFICATION → not yet governed
      if (portal.state === 'INITIALIZATION' || portal.state === 'ARTIFACT_VERIFICATION') {
        return deny('GOVERNANCE_NOT_READY: No active policy artifact. Call attest_subject first.');
      }

      // Fail closed: arguments that cannot be canonicalized (depth-bomb / hostile payload) are
      // DENIED and recorded — the governed call is never silently executed or dropped.
      if (!argsOk) {
        return deny('GOVERNANCE_FAILCLOSED: tool arguments could not be canonicalized (too deeply nested or invalid); refusing the call.');
      }

      // ACTIVE_MONITORING or DRIFT_DETECTED → record PERMITTED + allow through
      if (behavioralMonitor) behavioralMonitor.recordInvocation(toolName, argsHash);
      record?.({ tool: toolName, decision: 'PERMITTED', reason: `policy allows (portal ${portal.state})`, argsHash });
      return handler(args);
    };
  };
}
