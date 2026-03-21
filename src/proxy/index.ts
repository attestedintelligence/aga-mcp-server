#!/usr/bin/env node
/**
 * AGA Governance Proxy - CLI Entry Point
 *
 * Usage:
 *   aga-proxy start --upstream "node server.js"     # stdio upstream
 *   aga-proxy start --upstream-url http://host:port  # HTTP upstream
 *   aga-proxy start --profile standard               # policy profile
 *   aga-proxy stop
 *   aga-proxy status
 *   aga-proxy export --output bundle.json
 *   aga-proxy verify bundle.json
 *
 * Patent: USPTO App. No. 19/433,835
 * Copyright (c) 2026 Attested Intelligence Holdings LLC
 * SPDX-License-Identifier: MIT
 */

import { Command } from 'commander';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { GovernanceProxy } from './server.js';
import { PROFILES } from './profiles.js';
import type { ToolPolicy } from './types.js';

const program = new Command();
let proxy: GovernanceProxy | null = null;

function getDataDir(): string {
  return path.join(os.homedir(), '.aga-proxy');
}

function getPidFile(): string {
  return path.join(getDataDir(), 'proxy.pid');
}

program
  .name('aga-proxy')
  .description('AGA Governance Proxy - cryptographic runtime governance for MCP tool calls')
  .version('0.1.0');

// ── start ────────────────────────────────────────────────────

program
  .command('start')
  .description('Start the governance proxy')
  .option('-p, --port <port>', 'Proxy port', '18800')
  .option('--upstream <command>', 'Downstream MCP server command (stdio)')
  .option('--upstream-url <url>', 'Downstream MCP server URL (HTTP)')
  .option('--profile <name>', 'Policy profile: permissive, standard, restrictive', 'permissive')
  .option('--policy <path>', 'Custom policy JSON file')
  .action(async (opts) => {
    const port = parseInt(opts.port, 10);
    let policy: ToolPolicy;

    if (opts.policy) {
      policy = JSON.parse(fs.readFileSync(opts.policy, 'utf-8'));
    } else {
      policy = PROFILES[opts.profile] ?? PROFILES.permissive;
    }

    const upstream = opts.upstream ? parseUpstreamCommand(opts.upstream) : undefined;

    proxy = new GovernanceProxy({
      port,
      policy,
      upstream,
      upstreamUrl: opts.upstreamUrl,
    });

    proxy.on('started', ({ port: p }: { port: number }) => {
      console.log(`AGA Governance Proxy started on port ${p}`);
      console.log(`Policy mode: ${policy.mode}`);
      if (opts.upstream) console.log(`Upstream (stdio): ${opts.upstream}`);
      if (opts.upstreamUrl) console.log(`Upstream (HTTP): ${opts.upstreamUrl}`);
    });

    proxy.on('error', (err: Error) => {
      console.error(`Proxy error: ${err.message}`);
    });

    // Ensure data dir exists
    const dataDir = getDataDir();
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

    await proxy.start();

    // Write PID file
    fs.writeFileSync(getPidFile(), String(process.pid));

    // Graceful shutdown
    const shutdown = async () => {
      console.log('\nShutting down...');
      if (proxy) {
        await proxy.stop();
        try { fs.unlinkSync(getPidFile()); } catch { /* ok */ }
      }
      process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  });

// ── run (foreground, alias for start) ────────────────────────

program
  .command('run')
  .description('Run proxy in foreground (same as start, Ctrl+C to stop)')
  .option('-p, --port <port>', 'Proxy port', '18800')
  .option('--upstream <command>', 'Downstream MCP server command (stdio)')
  .option('--upstream-url <url>', 'Downstream MCP server URL (HTTP)')
  .option('--profile <name>', 'Policy profile', 'permissive')
  .option('--policy <path>', 'Custom policy JSON file')
  .action(async (opts) => {
    // Delegate to start - identical behavior in Node.js
    await program.commands.find(c => c.name() === 'start')!.parseAsync(
      ['node', 'aga-proxy', 'start', ...process.argv.slice(3)],
    );
  });

// ── stop ─────────────────────────────────────────────────────

program
  .command('stop')
  .description('Stop the running proxy')
  .action(async () => {
    const pidFile = getPidFile();
    if (!fs.existsSync(pidFile)) {
      console.log('No running proxy found');
      return;
    }
    const pid = parseInt(fs.readFileSync(pidFile, 'utf-8').trim(), 10);
    try {
      process.kill(pid, 'SIGTERM');
      console.log(`Sent SIGTERM to proxy (PID ${pid})`);
      fs.unlinkSync(pidFile);
    } catch {
      console.log('Proxy process not found, cleaning up PID file');
      fs.unlinkSync(pidFile);
    }
  });

// ── status ───────────────────────────────────────────────────

program
  .command('status')
  .description('Show proxy status')
  .action(async () => {
    if (proxy) {
      console.log(JSON.stringify(proxy.getStatus(), null, 2));
    } else {
      const pidFile = getPidFile();
      if (fs.existsSync(pidFile)) {
        const pid = parseInt(fs.readFileSync(pidFile, 'utf-8').trim(), 10);
        try {
          process.kill(pid, 0); // Check if alive
          console.log(JSON.stringify({ running: true, pid }, null, 2));
        } catch {
          console.log(JSON.stringify({ running: false, stale_pid: pid }, null, 2));
        }
      } else {
        console.log(JSON.stringify({ running: false }, null, 2));
      }
    }
  });

// ── export ───────────────────────────────────────────────────

program
  .command('export')
  .description('Export evidence bundle')
  .option('-o, --output <path>', 'Output file', 'evidence-bundle.json')
  .action(async (opts) => {
    if (!proxy) {
      console.error('Proxy not running in this process. Start the proxy first.');
      process.exit(1);
    }
    const bundle = await proxy.exportBundle();
    fs.writeFileSync(opts.output, JSON.stringify(bundle, null, 2));
    console.log(`Evidence bundle exported to ${opts.output}`);
  });

// ── verify ───────────────────────────────────────────────────

program
  .command('verify <bundle>')
  .description('Verify an evidence bundle (Ed25519-SHA256-JCS format)')
  .action(async (bundlePath) => {
    const { verifyGatewayBundle } = await import('./verify.js');
    const bundleJson = fs.readFileSync(bundlePath, 'utf-8');
    const result = await verifyGatewayBundle(bundleJson);

    console.log(`Algorithm:        ${result.algorithm_valid ? 'PASS' : 'FAIL'}`);
    console.log(`Signatures:       ${result.receipt_signatures_valid ? 'PASS' : 'FAIL'} (${result.receipts_checked} receipts)`);
    console.log(`Chain integrity:  ${result.chain_integrity_valid ? 'PASS' : 'FAIL'}`);
    console.log(`Merkle proofs:    ${result.merkle_proofs_valid ? 'PASS' : 'FAIL'}`);
    console.log(`Consistency:      ${result.bundle_consistent ? 'PASS' : 'FAIL'}`);
    console.log(`\nOVERALL: ${result.overall_valid ? 'VERIFIED' : 'FAILED'}`);
    if (result.error) console.log(`Error: ${result.error}`);

    process.exit(result.overall_valid ? 0 : 1);
  });

// ── policy ───────────────────────────────────────────────────

const policyCmd = program.command('policy').description('Policy management');

policyCmd
  .command('show')
  .description('Show current policy')
  .action(() => {
    if (!proxy) {
      console.error('Proxy not running in this process.');
      process.exit(1);
    }
    console.log(JSON.stringify(proxy.getStatus(), null, 2));
  });

policyCmd
  .command('switch <profile>')
  .description('Switch policy profile')
  .action(async (profile) => {
    if (!proxy) {
      console.error('Proxy not running in this process.');
      process.exit(1);
    }
    const newPolicy = PROFILES[profile];
    if (!newPolicy) {
      console.error(`Unknown profile: ${profile}. Available: ${Object.keys(PROFILES).join(', ')}`);
      process.exit(1);
    }
    await proxy.switchPolicy(newPolicy);
    console.log(`Switched to ${profile} profile`);
  });

// ── helpers ──────────────────────────────────────────────────

function parseUpstreamCommand(cmd: string): { command: string; args: string[] } {
  const parts = cmd.split(/\s+/);
  return { command: parts[0], args: parts.slice(1) };
}

// ── main ─────────────────────────────────────────────────────

export { GovernanceProxy } from './server.js';
export { evaluate, resetRateLimits } from './evaluator.js';
export { PROFILES, PERMISSIVE, STANDARD, RESTRICTIVE } from './profiles.js';
export type { ToolPolicy, ToolConstraint, ToolCallDecision, ProxyConfig } from './types.js';

// Only parse CLI if run directly
const isDirectRun = process.argv[1]?.includes('proxy') || process.argv[1]?.includes('aga-proxy');
if (isDirectRun) {
  program.parseAsync().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
