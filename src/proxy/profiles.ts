/**
 * AGA Governance Proxy - Built-in Policy Profiles
 *
 * Copyright (c) 2026 Attested Intelligence Holdings LLC
 * SPDX-License-Identifier: MIT
 */

import type { ToolPolicy } from './types.js';

/** All tools permitted, no rate limits, logging only. */
export const PERMISSIVE: ToolPolicy = {
  mode: 'audit_only',
  constraints: {},
};

/** All common tools allowed with rate limits. Dangerous patterns denied. */
export const STANDARD: ToolPolicy = {
  mode: 'allowlist',
  constraints: {
    filesystem_read:   { name: 'filesystem_read',   allowed: true, max_calls_per_minute: 30 },
    filesystem_write:  { name: 'filesystem_write',  allowed: true, max_calls_per_minute: 30, denied_patterns: ['/etc/', '/sys/', '/proc/'] },
    shell_execute:     { name: 'shell_execute',     allowed: true, max_calls_per_minute: 10, denied_patterns: ['rm -rf', 'mkfs', 'dd if=', ':(){:|:&};:'] },
    web_search:        { name: 'web_search',        allowed: true, max_calls_per_minute: 20 },
    web_fetch:         { name: 'web_fetch',         allowed: true, max_calls_per_minute: 20 },
    send_message:      { name: 'send_message',      allowed: true, max_calls_per_minute: 5 },
    calendar_create:   { name: 'calendar_create',   allowed: true, max_calls_per_minute: 5 },
    memory_search:     { name: 'memory_search',     allowed: true, max_calls_per_minute: 30 },
    memory_store:      { name: 'memory_store',      allowed: true, max_calls_per_minute: 10 },
    code_execute:      { name: 'code_execute',      allowed: true, max_calls_per_minute: 10 },
  },
};

/** Explicit allowlist only. All unrecognized tools denied. Low rate limits. */
export const RESTRICTIVE: ToolPolicy = {
  mode: 'allowlist',
  constraints: {
    filesystem_read:  { name: 'filesystem_read',  allowed: true, max_calls_per_minute: 10, path_prefix: '/home' },
    web_search:       { name: 'web_search',       allowed: true, max_calls_per_minute: 5 },
    memory_search:    { name: 'memory_search',    allowed: true, max_calls_per_minute: 10 },
  },
};

export const PROFILES: Record<string, ToolPolicy> = {
  permissive: PERMISSIVE,
  standard: STANDARD,
  restrictive: RESTRICTIVE,
};

/**
 * REL-04: resolve a --profile name to its policy, or undefined for an
 * UNRECOGNIZED name. Own-property check so prototype-chain names (e.g.
 * 'constructor') can never resolve to garbage. The caller decides the
 * failure behavior — the CLI refuses to start rather than silently
 * falling back to 'permissive' (audit_only).
 */
export function resolveProfile(name: string): ToolPolicy | undefined {
  return Object.prototype.hasOwnProperty.call(PROFILES, name) ? PROFILES[name] : undefined;
}

/**
 * REL-04: the loud stderr banner printed when the proxy starts with an
 * audit_only policy. audit_only records and signs every decision but
 * denies nothing; denial happens only under an allowlist-mode policy
 * (--profile standard / restrictive, or a custom --policy file).
 * `source` names where the policy came from, e.g. "--profile permissive".
 */
export function auditOnlyWarningBanner(source: string): string {
  const bar = '!'.repeat(76);
  return [
    bar,
    '!!  AUDIT-ONLY MODE — THIS PROXY WILL NOT BLOCK ANY TOOL CALL',
    '!!',
    `!!  The active policy (${source}) has mode 'audit_only': every tool call`,
    '!!  is PERMITTED and recorded. No call is denied in this mode. Signed',
    '!!  receipts are still issued for every decision, so the evidence trail',
    '!!  remains verifiable offline.',
    '!!',
    '!!  To enforce an allowlist (calls outside it are DENIED at the proxy',
    '!!  boundary), start with --profile standard or --profile restrictive,',
    '!!  or pass --policy <file> with "mode": "allowlist".',
    bar,
  ].join('\n');
}
