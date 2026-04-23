#!/usr/bin/env node
/**
 * AGA - Attested Governance Artifacts
 * Standalone Application v2
 *
 * Attested Intelligence Holdings LLC
 * NIST-2025-0035 | NCCoE AI Agent Identity
 *
 * Usage:
 *   aga-demo.exe                              Interactive scenario selector
 *   aga-demo.exe --scenario=scada             Run specific scenario
 *   aga-demo.exe --scenario=all               Run all scenarios
 *   aga-demo.exe --non-interactive            No pauses
 *   aga-demo.exe --watch path/to/file.py      Real-time monitoring
 *   aga-demo.exe --role=portal [opts]         (internal: portal child process)
 *   aga-demo.exe --role=agent [opts]          (internal: agent child process)
 */
import { createInterface } from 'node:readline';

const args = process.argv.slice(2);
function hasArg(name: string): boolean { return args.some(a => a === `--${name}` || a.startsWith(`--${name}=`)); }
function getArg(name: string, def = ''): string {
  const a = args.find(a => a.startsWith(`--${name}=`));
  return a ? a.split('=').slice(1).join('=') : def;
}

async function main(): Promise<void> {
  const role = getArg('role');

  // ── Child process modes (internal) ────────────────────────
  if (role === 'portal') {
    await import('./portal-server.js');
    return;
  }
  if (role === 'agent') {
    await import('./agent-client.js');
    return;
  }

  // ── Watch mode ────────────────────────────────────────────
  const watchTarget = args.find(a => !a.startsWith('--'));
  if (hasArg('watch') || (watchTarget && !hasArg('scenario'))) {
    const file = getArg('watch') || watchTarget;
    if (!file) { console.error('Usage: aga-demo --watch <file>'); process.exit(1); }
    const { watchMode } = await import('./watch.js');
    await watchMode(file, getArg('scenario', 'drone'));
    return;
  }

  // ── Orchestrator mode (default) ───────────────────────────
  const { banner, scenarioMenu, summary } = await import('./display.js');
  const { runScenario, runAllScenarios } = await import('./orchestrator.js');
  const interactive = !hasArg('non-interactive');

  banner();

  let scenarioId = getArg('scenario');

  if (!scenarioId && interactive) {
    scenarioMenu();
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const choice = await new Promise<string>(resolve => {
      rl.question('  Enter choice (1/2/3/A): ', answer => { rl.close(); resolve(answer.trim()); });
    });

    const map: Record<string, string> = { '1': 'scada', '2': 'drone', '3': 'ai-agent', 'a': 'all', 'A': 'all' };
    scenarioId = map[choice] ?? 'drone';
  }

  if (!scenarioId) scenarioId = 'drone';

  if (scenarioId === 'all') {
    await runAllScenarios(interactive);
  } else {
    await runScenario({ scenario: scenarioId as any, interactive, port: 9400 });
  }

  summary();

  if (interactive) {
    console.log('\n  Press Enter to exit...');
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    await new Promise<void>(r => rl.once('line', () => { rl.close(); r(); }));
  }
}

main().catch(e => {
  console.error('\nFatal error:', e.message);
  console.error(e.stack);
  process.exit(1);
});
