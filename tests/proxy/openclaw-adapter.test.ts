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
  const resolved = path.resolve(tmpDir);
  if (path.dirname(resolved) !== path.resolve(os.tmpdir()) || !path.basename(resolved).startsWith('aga-openclaw-test-')) throw new Error('Refusing unsafe test cleanup');
  fs.rmSync(resolved, { recursive: true, force: true });
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

  it('refuses automatic patching without changing configuration or creating a backup', async () => {
    const before = fs.readFileSync(configPath);
    const adapter = new OpenClawAdapter();
    await adapter.detect(configPath);
    await expect(adapter.patchMcpServers(18800, await adapter.readMcpServers())).rejects.toMatchObject({ code: 'AGA_UNSUPPORTED_ADAPTER' });
    expect(fs.readFileSync(configPath)).toEqual(before);
    expect(fs.readdirSync(tmpDir)).toEqual(['openclaw.json']);
  });

  it('preserves both current configuration and an existing backup across repeated patch attempts', async () => {
    const before = fs.readFileSync(configPath);
    const backup = 'synthetic retained original, different from the current configuration';
    fs.writeFileSync(configPath + '.aga-backup', backup);
    const adapter = new OpenClawAdapter();
    await adapter.detect(configPath);
    for (let attempt = 0; attempt < 2; attempt++) {
      await expect(adapter.patchMcpServers(18800, await adapter.readMcpServers())).rejects.toMatchObject({ code: 'AGA_UNSUPPORTED_ADAPTER' });
    }
    expect(fs.readFileSync(configPath)).toEqual(before);
    expect(fs.readFileSync(configPath + '.aga-backup', 'utf8')).toBe(backup);
    expect(fs.readdirSync(tmpDir).sort()).toEqual(['openclaw.json', 'openclaw.json.aga-backup']);
  });

  it('refuses blind restoration and preserves the backup for reviewed recovery', async () => {
    const before = fs.readFileSync(configPath);
    const backup = '{"retained":"synthetic backup"}';
    fs.writeFileSync(configPath + '.aga-backup', backup);
    const adapter = new OpenClawAdapter();
    await adapter.detect(configPath);
    await expect(adapter.restore()).rejects.toMatchObject({ code: 'AGA_UNSUPPORTED_ADAPTER' });
    expect(fs.readFileSync(configPath)).toEqual(before);
    expect(fs.readFileSync(configPath + '.aga-backup', 'utf8')).toBe(backup);
  });

  it('does not fabricate a backup or modify configuration when recovery material is missing', async () => {
    const before = fs.readFileSync(configPath);
    const adapter = new OpenClawAdapter();
    await adapter.detect(configPath);
    await expect(adapter.restore()).rejects.toMatchObject({ code: 'AGA_UNSUPPORTED_ADAPTER' });
    expect(fs.readFileSync(configPath)).toEqual(before);
    expect(fs.readdirSync(tmpDir)).toEqual(['openclaw.json']);
  });

  it('refuses mutation even without detection or access to a configuration path', async () => {
    const adapter = new OpenClawAdapter();
    await expect(adapter.patchMcpServers(18800, [])).rejects.toMatchObject({ code: 'AGA_UNSUPPORTED_ADAPTER' });
    await expect(adapter.restore()).rejects.toMatchObject({ code: 'AGA_UNSUPPORTED_ADAPTER' });
  });
});
