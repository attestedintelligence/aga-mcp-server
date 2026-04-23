/**
 * Watch Mode - real-time continuous file monitoring.
 * aga-demo.exe --watch path/to/file.py
 *
 * Attested Intelligence Holdings LLC
 */
import { existsSync, watchFile, unwatchFile } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { PortalEngine } from './engine.js';
import { SCENARIOS } from './scenarios.js';
import * as ui from './display.js';

export async function watchMode(filePath: string, scenarioId = 'drone'): Promise<void> {
  const absPath = resolve(filePath);
  if (!existsSync(absPath)) {
    console.error(`File not found: ${absPath}`);
    process.exit(1);
  }

  const scenario = { ...SCENARIOS[scenarioId as keyof typeof SCENARIOS] ?? SCENARIOS.drone };
  // Override with the user's file
  const { readFileSync } = await import('node:fs');
  scenario.agentContent = readFileSync(absPath, 'utf-8');
  scenario.agentFilename = absPath.split(/[/\\]/).pop() ?? 'watched-file';

  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const baseDir = join(tmpdir(), 'aga-v2-watch');
  const engine = new PortalEngine(scenario, baseDir);

  // Copy the user's file to the temp dir for measurement
  const { writeFileSync, copyFileSync } = await import('node:fs');
  copyFileSync(absPath, engine.filePath);

  ui.banner();
  console.log(`  ${'\x1b[1m'}AGA Watch Mode${'\x1b[0m'}`);
  console.log(`  Monitoring: ${absPath}`);
  console.log(`  Cadence:    ${scenario.measurementCadenceMs}ms`);
  console.log('');

  // Attest
  const { bytesHash } = engine.attest();
  ui.ok(`Attested: ${bytesHash.slice(0, 32)}...`);
  ui.portalState('Portal', engine.portalState);
  console.log('');
  console.log('  Monitoring active. Modify the file in another terminal to trigger drift.');
  console.log('  Press Ctrl+C to stop.\n');

  let cycle = 0;
  let running = true;

  // Watch the original file for changes and sync to temp
  watchFile(absPath, { interval: 100 }, () => {
    try {
      copyFileSync(absPath, engine.filePath);
    } catch {}
  });

  // Measurement loop
  const interval = setInterval(() => {
    if (!running) return;
    cycle++;

    try {
      // Sync file
      copyFileSync(absPath, engine.filePath);
    } catch {}

    const m = engine.measure();

    if (m.match) {
      ui.watchStatus(engine.portalState, scenario.measurementCadenceMs,
        scenario.ttlSeconds, engine.chainLength, engine.receiptCount);
    } else {
      console.log(''); // newline after the \r status
      ui.fail(`DRIFT DETECTED at cycle ${cycle}`);
      ui.info(`Expected: ${m.expectedBytesHash.slice(0, 32)}...`);
      ui.info(`Actual:   ${m.currentBytesHash.slice(0, 32)}...`);
      const action = engine.scenarioConfig.enforcementTriggers[0] ?? 'QUARANTINE';
      ui.enforce(action, engine.scenarioConfig.enforcementLabels[action]);
      ui.portalState('Portal', engine.portalState);
      console.log('');

      // Export evidence
      const dir = engine.exportEvidence([`Watch mode drift at cycle ${cycle}`]);
      ui.ok(`Evidence exported to: ${dir}`);

      running = false;
      clearInterval(interval);
      unwatchFile(absPath);

      console.log('\n  Press Enter to exit...');
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      rl.once('line', () => { rl.close(); process.exit(0); });
    }
  }, scenario.measurementCadenceMs);

  // Handle Ctrl+C
  process.on('SIGINT', () => {
    running = false;
    clearInterval(interval);
    unwatchFile(absPath);
    console.log('\n');
    const dir = engine.exportEvidence([`Watch stopped at cycle ${cycle}`]);
    ui.ok(`Evidence exported to: ${dir}`);
    process.exit(0);
  });
}
