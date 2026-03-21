/**
 * Tests for the OpenClaw config adapter.
 * Uses a temp directory with a fixture openclaw.json.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { OpenClawAdapter } from '../../src/adapters/openclaw.js';

let tmpDir: string;
let configPath: string;

const FIXTURE_CONFIG = {
  version: '1.0.0',
  mcpServers: {
    filesystem: {
      command: 'node',
      args: ['filesystem-server.js'],
    },
    web: {
      url: 'http://localhost:3000/mcp',
    },
    memory: {
      command: 'python',
      args: ['-m', 'memory_server'],
      env: { MEMORY_DB: '/tmp/mem.db' },
    },
  },
};

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aga-openclaw-test-'));
  configPath = path.join(tmpDir, 'openclaw.json');
  fs.writeFileSync(configPath, JSON.stringify(FIXTURE_CONFIG, null, 2));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('OpenClaw Adapter', () => {
  it('detects existing config', async () => {
    const adapter = new OpenClawAdapter();
    const result = await adapter.detect(configPath);
    expect(result.found).toBe(true);
    expect(result.path).toBe(configPath);
    expect(result.version).toBe('1.0.0');
  });

  it('reports missing config', async () => {
    const adapter = new OpenClawAdapter();
    const result = await adapter.detect(path.join(tmpDir, 'nonexistent.json'));
    expect(result.found).toBe(false);
  });

  it('reads MCP server entries', async () => {
    const adapter = new OpenClawAdapter();
    await adapter.detect(configPath);
    const servers = await adapter.readMcpServers();
    expect(servers).toHaveLength(3);
    expect(servers.map(s => s.name)).toContain('filesystem');
    expect(servers.map(s => s.name)).toContain('web');
    expect(servers.map(s => s.name)).toContain('memory');
  });

  it('patches config to route through proxy', async () => {
    const adapter = new OpenClawAdapter();
    await adapter.detect(configPath);
    const servers = await adapter.readMcpServers();

    await adapter.patchMcpServers(18800, servers);

    // Read patched config
    const patched = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    for (const name of ['filesystem', 'web', 'memory']) {
      const entry = patched.mcpServers[name];
      expect(entry.url).toBe('http://127.0.0.1:18800');
      expect(entry._aga_governed).toBe(true);
      expect(entry._aga_original).toBeDefined();
    }

    // Backup should exist
    expect(fs.existsSync(configPath + '.aga-backup')).toBe(true);
  });

  it('restores original config', async () => {
    const adapter = new OpenClawAdapter();
    await adapter.detect(configPath);
    const servers = await adapter.readMcpServers();

    await adapter.patchMcpServers(18800, servers);
    await adapter.restore();

    // Config should match original
    const restored = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(restored).toEqual(FIXTURE_CONFIG);

    // Backup should be gone
    expect(fs.existsSync(configPath + '.aga-backup')).toBe(false);
  });

  it('restore fails without backup', async () => {
    const adapter = new OpenClawAdapter();
    await adapter.detect(configPath);
    await expect(adapter.restore()).rejects.toThrow('No backup found');
  });
});
