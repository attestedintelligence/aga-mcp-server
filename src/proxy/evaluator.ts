/**
 * AGA Governance Proxy - Tool Policy Evaluator
 * Ported from aga-mcp-gateway/src/governance/policy.ts with rate limiting.
 *
 * Patent: USPTO App. No. 19/433,835
 * Copyright (c) 2026 Attested Intelligence Holdings LLC
 * SPDX-License-Identifier: MIT
 */

import type { ToolPolicy, ToolCallDecision } from './types.js';

// ── Rate Limiter ────────────────────────────────────────────

interface RateWindow {
  timestamps: number[];
}

const rateLimits = new Map<string, RateWindow>();

function checkRateLimit(toolName: string, maxPerMinute: number): boolean {
  const now = Date.now();
  const cutoff = now - 60_000;

  let window = rateLimits.get(toolName);
  if (!window) {
    window = { timestamps: [] };
    rateLimits.set(toolName, window);
  }

  // Prune expired entries
  window.timestamps = window.timestamps.filter(t => t > cutoff);

  if (window.timestamps.length >= maxPerMinute) return false;

  window.timestamps.push(now);
  return true;
}

export function resetRateLimits(): void {
  rateLimits.clear();
}

// ── Path Utilities (from aga-mcp-gateway) ───────────────────

export function cleanPath(p: string): string {
  p = p.replace(/\\/g, '/');
  p = p.replace(/\/+/g, '/');

  const segments = p.split('/');
  const resolved: string[] = [];
  const absolute = segments[0] === '';

  for (const seg of segments) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (resolved.length > 0 && resolved[resolved.length - 1] !== '..') {
        resolved.pop();
      } else if (!absolute) {
        resolved.push('..');
      }
    } else {
      resolved.push(seg);
    }
  }

  let result = (absolute ? '/' : '') + resolved.join('/');
  if (result === '') result = '.';
  return result;
}

export function matchesPrefix(prefix: string, candidate: string): boolean {
  const cleanPrefix = cleanPath(prefix);
  const cleanCandidate = cleanPath(candidate);

  if (cleanCandidate === cleanPrefix) return true;
  const prefixWithSlash = cleanPrefix.endsWith('/') ? cleanPrefix : cleanPrefix + '/';
  return cleanCandidate.startsWith(prefixWithSlash);
}

function checkPathConstraints(
  constraint: { path_prefix?: string; path_keys?: string[] },
  args?: Record<string, unknown>,
): string | null {
  if (!constraint.path_prefix) return null;
  const keys = constraint.path_keys?.length ? constraint.path_keys : ['path'];
  if (!args) return null;

  for (const key of keys) {
    const val = args[key];
    if (typeof val === 'string') {
      if (!matchesPrefix(constraint.path_prefix, val)) {
        return `path "${val}" outside allowed prefix "${constraint.path_prefix}"`;
      }
    }
  }
  return null;
}

function checkDeniedPatterns(
  constraint: { denied_patterns?: string[] },
  args?: Record<string, unknown>,
): string | null {
  if (!constraint.denied_patterns?.length) return null;
  if (!args) return null;

  for (const [, val] of Object.entries(args)) {
    if (typeof val !== 'string') continue;
    for (const pattern of constraint.denied_patterns) {
      if (val.includes(pattern)) {
        return `argument value matches denied pattern "${pattern}"`;
      }
    }
  }
  return null;
}

// ── Main Evaluator ──────────────────────────────────────────

export function evaluate(
  policy: ToolPolicy,
  toolName: string,
  args?: Record<string, unknown>,
): ToolCallDecision {
  const base = { tool_name: toolName, policy_mode: policy.mode };

  // Audit-only mode: always permit
  if (policy.mode === 'audit_only') {
    return { ...base, allowed: true, reason: 'audit_only: all calls permitted' };
  }

  if (policy.mode !== 'allowlist' && policy.mode !== 'denylist') {
    return { ...base, allowed: false, reason: `unknown policy mode: ${policy.mode}` };
  }

  const constraint = policy.constraints[toolName];

  if (policy.mode === 'allowlist') {
    if (!constraint) {
      return { ...base, allowed: false, reason: 'tool not in allowlist' };
    }
    if (!constraint.allowed) {
      return { ...base, allowed: false, reason: 'tool explicitly disallowed' };
    }

    // Rate limit check
    if (constraint.max_calls_per_minute) {
      if (!checkRateLimit(toolName, constraint.max_calls_per_minute)) {
        return { ...base, allowed: false, reason: `rate limit exceeded: ${constraint.max_calls_per_minute}/min` };
      }
    }

    const pathResult = checkPathConstraints(constraint, args);
    if (pathResult !== null) {
      return { ...base, allowed: false, reason: pathResult };
    }
    const patternResult = checkDeniedPatterns(constraint, args);
    if (patternResult !== null) {
      return { ...base, allowed: false, reason: patternResult };
    }
    return { ...base, allowed: true, reason: 'tool permitted by allowlist' };
  }

  // Denylist mode
  if (constraint && !constraint.allowed) {
    return { ...base, allowed: false, reason: 'tool denied by denylist' };
  }

  // Rate limit check for denylist mode (tool not explicitly denied)
  if (constraint?.max_calls_per_minute) {
    if (!checkRateLimit(toolName, constraint.max_calls_per_minute)) {
      return { ...base, allowed: false, reason: `rate limit exceeded: ${constraint.max_calls_per_minute}/min` };
    }
  }

  return { ...base, allowed: true, reason: 'tool not denied' };
}
