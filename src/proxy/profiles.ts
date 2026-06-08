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
