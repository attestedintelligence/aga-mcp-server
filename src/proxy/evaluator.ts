/**
 * AGA Governance Proxy - Tool Policy Evaluator
 * Ported from the internal AGA governance gateway's policy engine, with rate limiting.
 *
 * Copyright (c) 2026 Attested Intelligence Holdings LLC
 * SPDX-License-Identifier: MIT
 */

import type { ToolPolicy, ToolCallDecision } from './types.js';
import { performance } from 'node:perf_hooks';

// ── Rate Limiter ────────────────────────────────────────────

interface RateWindow {
  timestamps: number[];
}

export type RateLimitState = Map<string, RateWindow>;
export const createRateLimitState = (): RateLimitState => new Map();
const rateLimits = createRateLimitState();

function checkRateLimit(toolName: string, maxPerMinute: number, state: RateLimitState): boolean {
  // Monotonic basis: a wall-clock adjustment (NTP step, DST, manual/container clock change) must not perturb
  // the rate-limit window. performance.now() is monotonic and immune to such skew, unlike Date.now().
  const now = performance.now();
  const cutoff = now - 60_000;

  let window = state.get(toolName);
  if (!window) {
    window = { timestamps: [] };
    state.set(toolName, window);
  }

  // Prune expired entries
  window.timestamps = window.timestamps.filter(t => t > cutoff);

  if (window.timestamps.length >= maxPerMinute) return false;

  window.timestamps.push(now);
  return true;
}

export function resetRateLimits(state: RateLimitState = rateLimits): void {
  state.clear();
}

// ── Path Utilities ────────────────────────────────

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
  if (!args) return 'required path arguments are missing';

  for (const key of keys) {
    const val = Object.hasOwn(args, key) ? args[key] : undefined;
    if (typeof val !== 'string' || !val) return `required path argument "${key}" must be a non-empty string`;
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
  state: RateLimitState = rateLimits,
): ToolCallDecision {
  const base = { tool_name: toolName, policy_mode: policy.mode };
  if (typeof toolName !== 'string' || !toolName || toolName.length > 256
    || (args !== undefined && (!args || typeof args !== 'object' || Array.isArray(args)))) {
    return { ...base, allowed: false, reason: 'invalid tool name or arguments' };
  }

  // Audit-only mode: always permit
  if (policy.mode === 'audit_only') {
    return { ...base, allowed: true, reason: 'audit_only: all calls permitted' };
  }

  if (policy.mode !== 'allowlist' && policy.mode !== 'denylist') {
    return { ...base, allowed: false, reason: `unknown policy mode: ${policy.mode}` };
  }

  const constraint = Object.hasOwn(policy.constraints, toolName) ? policy.constraints[toolName] : undefined;

  if (policy.mode === 'allowlist') {
    if (!constraint) {
      return { ...base, allowed: false, reason: 'tool not in allowlist' };
    }
    if (constraint.allowed !== true) {
      return { ...base, allowed: false, reason: 'tool explicitly disallowed' };
    }

    // Rate limit check
    if (constraint.max_calls_per_minute) {
      if (!checkRateLimit(toolName, constraint.max_calls_per_minute, state)) {
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
    if (!checkRateLimit(toolName, constraint.max_calls_per_minute, state)) {
      return { ...base, allowed: false, reason: `rate limit exceeded: ${constraint.max_calls_per_minute}/min` };
    }
  }

  if (constraint) {
    const reason = checkPathConstraints(constraint, args) ?? checkDeniedPatterns(constraint, args);
    if (reason !== null) return { ...base, allowed: false, reason };
  }
  return { ...base, allowed: true, reason: 'tool not denied' };
}
