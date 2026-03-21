/**
 * AGA Governance Proxy - Types
 * Adapted from aga-mcp-gateway/src/governance/types.ts
 *
 * Patent: USPTO App. No. 19/433,835
 * Copyright (c) 2026 Attested Intelligence Holdings LLC
 * SPDX-License-Identifier: MIT
 */

export interface ToolConstraint {
  name: string;
  allowed: boolean;
  max_calls_per_minute?: number;
  path_prefix?: string;
  path_keys?: string[];
  denied_patterns?: string[];
}

export interface ToolPolicy {
  mode: 'allowlist' | 'denylist' | 'audit_only';
  constraints: Record<string, ToolConstraint>;
}

export interface ToolCallDecision {
  allowed: boolean;
  reason: string;
  tool_name: string;
  policy_mode: string;
}

export interface ProxyConfig {
  port: number;
  upstream: string;
  upstreamType: 'stdio' | 'http';
  policy: ToolPolicy;
  dataDir: string;
}

export const DEFAULT_PROXY_PORT = 18800;
export const DEFAULT_DATA_DIR = '.aga-proxy';
