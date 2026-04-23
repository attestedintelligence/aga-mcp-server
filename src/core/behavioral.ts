/**
 * Behavioral Drift Detection.
 * NIST-2025-0035: "Governance mechanisms must measure behavioral outputs
 * and decision patterns in addition to static artifacts."
 *
 * Tracks tool invocation patterns and compares against a behavioral
 * baseline sealed in the policy artifact.
 */
import { sha256Str } from '../crypto/hash.js';
import type { HashHex } from '../crypto/types.js';

export interface ToolInvocation {
  tool_name: string;
  timestamp: string;
  args_hash: HashHex;  // hash of args, not args themselves (privacy)
}

export interface BehavioralBaseline {
  /** Allowed tools in this policy context */
  permitted_tools: string[];
  /** Maximum invocations per tool per measurement window */
  rate_limits: Record<string, number>;
  /** Forbidden tool sequences (e.g., read_secret then send_email) */
  forbidden_sequences: string[][];
  /** Measurement window in milliseconds */
  window_ms: number;
}

export interface BehavioralMeasurement {
  window_start: string;
  window_end: string;
  invocations: ToolInvocation[];
  violations: BehavioralViolation[];
  behavioral_hash: HashHex;  // hash of the behavioral pattern
  drift_detected: boolean;
}

export type BehavioralViolation =
  | { type: 'UNAUTHORIZED_TOOL'; tool: string }
  | { type: 'RATE_EXCEEDED'; tool: string; count: number; limit: number }
  | { type: 'FORBIDDEN_SEQUENCE'; sequence: string[] };

export class BehavioralMonitor {
  private invocations: ToolInvocation[] = [];
  private baseline: BehavioralBaseline | null = null;

  setBaseline(baseline: BehavioralBaseline): void {
    this.baseline = baseline;
  }

  recordInvocation(toolName: string, argsHash: HashHex): void {
    this.invocations.push({
      tool_name: toolName,
      timestamp: new Date().toISOString(),
      args_hash: argsHash,
    });
  }

  measure(): BehavioralMeasurement {
    if (!this.baseline) {
      return {
        window_start: '', window_end: '', invocations: [],
        violations: [], behavioral_hash: sha256Str('no-baseline'),
        drift_detected: false,
      };
    }

    const now = Date.now();
    const windowStart = now - this.baseline.window_ms;
    const windowInvocations = this.invocations.filter(
      i => Date.parse(i.timestamp) >= windowStart
    );

    const violations: BehavioralViolation[] = [];

    // Check unauthorized tools
    for (const inv of windowInvocations) {
      if (!this.baseline.permitted_tools.includes(inv.tool_name)) {
        violations.push({ type: 'UNAUTHORIZED_TOOL', tool: inv.tool_name });
      }
    }

    // Check rate limits
    const counts: Record<string, number> = {};
    for (const inv of windowInvocations) {
      counts[inv.tool_name] = (counts[inv.tool_name] ?? 0) + 1;
    }
    for (const [tool, count] of Object.entries(counts)) {
      const limit = this.baseline.rate_limits[tool];
      if (limit !== undefined && count > limit) {
        violations.push({ type: 'RATE_EXCEEDED', tool, count, limit });
      }
    }

    // Check forbidden sequences
    const toolSequence = windowInvocations.map(i => i.tool_name);
    for (const forbidden of this.baseline.forbidden_sequences) {
      if (containsSubsequence(toolSequence, forbidden)) {
        violations.push({ type: 'FORBIDDEN_SEQUENCE', sequence: forbidden });
      }
    }

    // Compute behavioral hash (pattern fingerprint)
    const pattern = windowInvocations.map(i => i.tool_name).join('|');
    const behavioral_hash = sha256Str(pattern);

    return {
      window_start: new Date(windowStart).toISOString(),
      window_end: new Date(now).toISOString(),
      invocations: windowInvocations,
      violations,
      behavioral_hash,
      drift_detected: violations.length > 0,
    };
  }

  reset(): void {
    this.invocations = [];
  }
}

function containsSubsequence(haystack: string[], needle: string[]): boolean {
  if (needle.length === 0) return true;
  let ni = 0;
  for (const h of haystack) {
    if (h === needle[ni]) {
      ni++;
      if (ni === needle.length) return true;
    }
  }
  return false;
}
