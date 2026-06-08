/**
 * OpenClaw Config Adapter
 * Detects and patches openclaw.json to route MCP servers through the AGA governance proxy.
 *
 * All OpenClaw assumptions are documented inline. When a real OpenClaw instance
 * becomes available, validate each assumption.
 *
 * Copyright (c) 2026 Attested Intelligence Holdings LLC
 * SPDX-License-Identifier: MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// ── Assumptions ──────────────────────────────────────────────
// ASSUMPTION 1: OpenClaw stores its config at ~/.openclaw/openclaw.json
//   Source: OpenClaw documentation pattern (similar to Claude Desktop, Cursor)
//   Fallback: Accept explicit path via detect(configPath?)
//
// ASSUMPTION 2: Config has a "mcpServers" field with server entries
//   Source: MCP client config convention (matches Claude Desktop format)
//   Format: { "mcpServers": { "name": { "command": "...", "args": [...] } } }
//
// ASSUMPTION 3: Each server entry has "command" + "args" (stdio) or "url" (HTTP)
//   Source: MCP transport specification
//   Fallback: Skip entries that don't match either pattern

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
  private backupPath: string | null = null;

  private getDefaultPath(): string {
    return path.join(os.homedir(), '.openclaw', 'openclaw.json');
  }

  async detect(configPath?: string): Promise<{ found: boolean; path: string; version?: string }> {
    const p = configPath ?? this.getDefaultPath();
    this.configPath = p;
    this.backupPath = p + '.aga-backup';

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

  async patchMcpServers(proxyPort: number, originals: McpServerConfig[]): Promise<void> {
    if (!this.configPath || !this.backupPath) throw new Error('Call detect() first');

    // Backup original
    const originalContent = fs.readFileSync(this.configPath, 'utf-8');
    fs.writeFileSync(this.backupPath, originalContent);

    const config = JSON.parse(originalContent);

    // Rewrite each MCP server entry to point at the proxy
    // The proxy will forward to the original command/URL
    for (const server of originals) {
      if (config.mcpServers?.[server.name]) {
        const original = config.mcpServers[server.name];

        // Store original config for the proxy to use
        config.mcpServers[server.name] = {
          // Point at proxy instead
          url: `http://127.0.0.1:${proxyPort}`,
          // Preserve metadata
          _aga_original: original,
          _aga_governed: true,
        };
      }
    }

    fs.writeFileSync(this.configPath, JSON.stringify(config, null, 2));
  }

  async restore(): Promise<void> {
    if (!this.configPath || !this.backupPath) throw new Error('Call detect() first');

    if (fs.existsSync(this.backupPath)) {
      fs.copyFileSync(this.backupPath, this.configPath);
      fs.unlinkSync(this.backupPath);
    } else {
      throw new Error('No backup found - cannot restore');
    }
  }
}
