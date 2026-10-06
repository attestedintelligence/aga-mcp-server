/**
 * Legacy OpenClaw configuration reader.
 * Automatic mutation is retired because the assumed transport and recovery
 * behavior are not qualified. Existing configuration and backups are preserved.
 *
 * Copyright (c) 2026 Attested Intelligence Holdings LLC
 * SPDX-License-Identifier: MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// Legacy schema reader only. No supported OpenClaw integration is established.
// The historical path/schema guesses are retained for explicit read-only inspection.
// The reference listener is raw TCP, not an MCP HTTP endpoint.

export class UnsupportedAdapterOperationError extends Error {
  readonly code = 'AGA_UNSUPPORTED_ADAPTER';
  constructor(operation: 'patch' | 'restore') {
    super(`Automatic OpenClaw configuration ${operation} is disabled. This legacy adapter has no qualified transport or recovery contract. Preserve current configuration and backup files; see DEPLOYMENT.md section 7.`);
    this.name = 'UnsupportedAdapterOperationError';
  }
}

export interface McpServerConfig {
  name: string;
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
  [key: string]: unknown;
}

export interface AgentConfigAdapter {
  detect(configPath?: string): Promise<{ found: boolean; path: string; version?: string }>;
  readMcpServers(): Promise<McpServerConfig[]>;
  patchMcpServers(proxyPort: number, originals: McpServerConfig[]): Promise<void>;
  restore(): Promise<void>;
}

export class OpenClawAdapter implements AgentConfigAdapter {
  private configPath: string | null = null;

  private getDefaultPath(): string {
    return path.join(os.homedir(), '.openclaw', 'openclaw.json');
  }

  async detect(configPath?: string): Promise<{ found: boolean; path: string; version?: string }> {
    const p = configPath ?? this.getDefaultPath();
    this.configPath = p;

    if (!fs.existsSync(p)) {
      return { found: false, path: p };
    }

    try {
      const config = JSON.parse(fs.readFileSync(p, 'utf-8'));
      return {
        found: true,
        path: p,
        version: config.version ?? config.openclaw_version ?? undefined,
      };
    } catch {
      return { found: false, path: p };
    }
  }

  async readMcpServers(): Promise<McpServerConfig[]> {
    if (!this.configPath) throw new Error('Call detect() first');

    const config = JSON.parse(fs.readFileSync(this.configPath, 'utf-8'));
    const servers = config.mcpServers ?? {};
    return Object.entries(servers).map(([name, entry]) => ({
      name,
      ...(entry as Record<string, unknown>),
    }));
  }

  /** @deprecated No supported automatic integration. Refuses without filesystem access. */
  async patchMcpServers(_proxyPort: number, _originals: McpServerConfig[]): Promise<void> {
    throw new UnsupportedAdapterOperationError('patch');
  }

  /** @deprecated Recovery needs a reviewed comparison; never blindly replace or delete files. */
  async restore(): Promise<void> {
    throw new UnsupportedAdapterOperationError('restore');
  }
}
