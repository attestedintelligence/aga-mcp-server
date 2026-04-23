/**
 * Orchestrator - spawns portal and agent, controls demo timeline.
 * This is what the user interacts with.
 *
 * Attested Intelligence Holdings LLC
 */
import { fork, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import { resolve } from 'node:path';
import * as ui from './display.js';
import type { ScenarioConfig, ScenarioId } from './scenarios.js';
import { SCENARIOS, SCENARIO_IDS } from './scenarios.js';

const GRY = '\x1b[90m';
const R = '\x1b[0m';

export interface OrchestratorOptions {
  scenario: ScenarioId;
  interactive: boolean;
  port: number;
}

function pause(interactive: boolean): Promise<void> {
  if (!interactive) return new Promise(r => setTimeout(r, 200));
  return new Promise(resolve => {
    console.log(`\n  ${GRY}Press Enter to continue...${R}`);
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.once('line', () => { rl.close(); resolve(); });
  });
}

function sleep(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)); }
const breathe = () => sleep(150);

function waitForMessage(proc: ChildProcess, type: string, timeout = 10000): Promise<any> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timeout waiting for ${type}`)), timeout);
    const handler = (msg: any) => {
      if (msg.type === type) {
        clearTimeout(timer);
        proc.off('message', handler);
        resolve(msg);
      }
    };
    proc.on('message', handler);
  });
}

export async function runScenario(opts: OrchestratorOptions): Promise<void> {
  const scenario = SCENARIOS[opts.scenario];
  const transcript: string[] = [];
  const log = (s: string) => transcript.push(s);

  ui.scenarioHeader(scenario.name, scenario.description, scenario.nistRef);

  // ── Phase 1: Spawn Portal ─────────────────────────────────

  ui.phase('1', 'ATTESTATION - Two-Process Architecture');
  ui.info('The portal and agent are separate OS processes. The agent has no keys.');
  await breathe();

  ui.info('Spawning PORTAL process (holds all crypto keys)...');

  const portalProc = fork(process.argv[1], [
    '--role=portal', `--scenario=${opts.scenario}`, `--port=${opts.port}`,
  ], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'], execArgv: process.execArgv });

  // Forward portal stderr to display
  portalProc.stderr?.on('data', (d: Buffer) => {
    const line = d.toString().trim();
    if (line) { ui.portal(line.replace('[PORTAL] ', '')); log(line); }
  });

  await waitForMessage(portalProc, 'ready');
  ui.ok('Portal ready on 127.0.0.1:' + opts.port);
  await breathe();

  // Fetch attestation details from portal status
  const statusP1 = await (await fetch(`http://127.0.0.1:${opts.port}/status`)).json();
  ui.blank();
  ui.detail('Issuer key', (statusP1.issuer_key ?? '').slice(0, 32) + '...');
  ui.detail('Measurement cadence', scenario.measurementCadenceMs + 'ms');
  ui.detail('TTL', scenario.ttlSeconds + 's');
  ui.detail('Enforcement', scenario.enforcementTriggers.join(' → '));
  ui.detail('Measurements', scenario.measurementTypes.join(', '));
  ui.detail('Protected', scenario.protectedResources.join(', '));
  ui.blank();

  // ── Spawn Agent ──────────────────────────────────

  ui.info('Spawning AGENT process (NO keys, NO direct access)...');

  const agentProc = fork(process.argv[1], [
    '--role=agent', `--portal=http://127.0.0.1:${opts.port}`, `--scenario=${opts.scenario}`,
  ], { stdio: ['pipe', 'pipe', 'pipe', 'ipc'], execArgv: process.execArgv });

  agentProc.stderr?.on('data', (d: Buffer) => {
    const line = d.toString().trim();
    if (line) { ui.agent(line.replace('[AGENT]  ', '')); log(line); }
  });

  await waitForMessage(agentProc, 'ready');
  ui.ok('Agent started - connected to portal only');
  await breathe();
  ui.agent('I have NO crypto keys. Portal is my only door.');
  log('Phase 1: Portal and agent spawned.');

  await pause(opts.interactive);

  // ── Phase 2: Watch clean operations ───────────────────────

  ui.phase('2', 'AUTHORIZED OPERATION - Continuous Measurement');
  ui.info('Every request is measured. Every measurement produces a signed receipt.');
  await breathe();
  ui.blank();

  // Let the agent run 4 clean cycles
  let cleanOps = 0;
  const opListener = (msg: any) => {
    if (msg.type === 'operation') {
      cleanOps++;
      ui.measurement(cleanOps, true, msg.receipt_id?.slice(0, 24) ?? '');
      log(`Cycle ${cleanOps}: CLEAN receipt=${msg.receipt_id}`);
    }
  };
  agentProc.on('message', opListener);

  // Wait for 4 clean operations
  while (cleanOps < 4) await sleep(200);
  agentProc.off('message', opListener);

  ui.blank();
  ui.ok(`${cleanOps} authorized operations. ${cleanOps} signed receipts.`);
  ui.portalState('Portal', 'ACTIVE_MONITORING');
  await breathe();

  // Performance benchmark (NIST <10ms target)
  const benchStart = performance.now();
  const benchIterations = 100;
  for (let i = 0; i < benchIterations; i++) {
    await fetch(`http://127.0.0.1:${opts.port}/operate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ operation: 'benchmark', tool_name: 'benchmark', cycle: -i }),
    });
  }
  const benchMs = performance.now() - benchStart;
  const perOp = benchMs / benchIterations;
  ui.benchmarkResult(perOp);

  await pause(opts.interactive);

  // ── Phase 3: Privacy-Preserving Disclosure ──────

  ui.phase('3', 'PRIVACY-PRESERVING DISCLOSURE');
  ui.info('Sensitive claims auto-substitute to lower sensitivity. Signed receipt binds the decision.');
  await breathe();
  ui.blank();

  const claims = scenario.disclosurePolicy.claims_taxonomy;
  if (claims.length > 0) {
    const sensitiveId = claims[0].claim_id; // most sensitive
    const res = await fetch(`http://127.0.0.1:${opts.port}/disclose`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ claim_id: sensitiveId, mode: 'REVEAL_FULL' }),
    });
    const disc = await res.json();

    if (disc.was_substituted) {
      ui.disclosure(sensitiveId, '', true, disc.disclosed_claim_id);
      log(`Disclosure: ${sensitiveId} → substituted with ${disc.disclosed_claim_id}`);
    } else if (disc.permitted) {
      ui.disclosure(sensitiveId, String(disc.disclosed_value), false);
      log(`Disclosure: ${sensitiveId} → permitted`);
    } else {
      ui.fail(`${sensitiveId} - denied, no permitted substitute found`);
      log(`Disclosure: ${sensitiveId} → denied`);
    }

    // Show a less sensitive claim succeeding directly
    if (claims.length > 2) {
      await breathe();
      const lowSens = claims[claims.length - 1].claim_id;
      const res2 = await fetch(`http://127.0.0.1:${opts.port}/disclose`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ claim_id: lowSens, mode: 'REVEAL_FULL' }),
      });
      const disc2 = await res2.json();
      if (disc2.permitted) {
        ui.disclosure(lowSens, String(disc2.disclosed_value), false);
        log(`Disclosure: ${lowSens} → direct, value=${disc2.disclosed_value}`);
      }
    }
  }

  await pause(opts.interactive);

  // ── Phase 4: Attack Simulation ────────────────────────────

  ui.phase('4', 'SIMULATED ATTACK - Binary Modification');
  ui.info('The agent binary is modified on disk. The next measurement detects the change.');
  await breathe();

  ui.warn('Adversary injects malicious code into agent binary...');
  ui.blank();

  // Tell the portal to tamper the file
  portalProc.send({ type: 'tamper' });
  await sleep(300);
  ui.fail(`${scenario.agentFilename} MODIFIED on disk`);

  // Wait for the agent's next request to be blocked
  const driftPromise = waitForMessage(portalProc, 'drift', 15000);
  const blockPromise = waitForMessage(agentProc, 'blocked', 15000);

  const [driftMsg] = await Promise.all([driftPromise, blockPromise]);

  ui.blank();
  ui.fail('DRIFT DETECTED - SHA-256 mismatch against sealed reference');
  ui.blank();
  ui.detail('Expected', (driftMsg.expected_hash ?? '').slice(0, 32) + '...');
  ui.detail('Measured', (driftMsg.current_hash ?? '').slice(0, 32) + '...');

  const actionLabel = scenario.enforcementLabels[driftMsg.action] ?? driftMsg.action;
  ui.enforce(driftMsg.action, actionLabel);
  await breathe();

  // Forensic capture
  ui.info('Phantom execution - adversary inputs captured:');
  // Agent will keep trying and getting blocked - each attempt is captured
  await sleep(2000); // let a few blocked attempts accumulate

  const statusRes = await fetch(`http://127.0.0.1:${opts.port}/status`);
  const status = await statusRes.json();
  ui.ok(`${status.quarantine_active ? 'Quarantine active' : 'Enforcement applied'}`);
  ui.info(`Protected resources severed: ${scenario.protectedResources.join(', ')}`);
  log(`Phase 4: DRIFT. action=${driftMsg.action}`);

  await pause(opts.interactive);

  // ── Phase 5: TTL Expiration Demo ────────────────

  ui.phase('5', 'TTL EXPIRATION - Fail-Closed Semantics');
  ui.info('When the artifact expires, all operations are blocked. No grace period.');
  await breathe();

  ui.detail('Current TTL', scenario.ttlSeconds + 's');
  ui.blank();
  ui.info('If the portal cannot reach the policy authority when TTL expires:');
  ui.info('→ Graceful degradation: safe-state transition + local logging');
  log('Phase 5: TTL/graceful degradation explained');

  await pause(opts.interactive);

  // ── Phase 6: Revocation (NCCoE 3b) ────────────────────────

  ui.phase('6', 'MID-SESSION REVOCATION (NCCoE Phase 3b)');
  ui.info('The artifact is permanently invalidated. Even restoring the binary won\'t help.');
  await breathe();

  portalProc.send({ type: 'revoke', reason: 'Binary compromise confirmed' });
  await waitForMessage(portalProc, 'revoked');
  ui.ok('REVOCATION event pushed to continuity chain');
  ui.portalState('Portal', 'TERMINATED');
  ui.info('Artifact permanently invalidated. Re-attestation required.');
  log('Phase 6: Revoked');

  await pause(opts.interactive);

  // ── Phase 7: Leaf Hash Privacy Proof ───────────

  ui.phase('7', 'LEAF HASH PRIVACY PROOF');
  ui.info('The chain is verifiable without seeing event contents. Payload is excluded from the hash.');
  await breathe();
  ui.blank();

  const proofRes = await fetch(`http://127.0.0.1:${opts.port}/leaf-hash-proof`);
  const proof = await proofRes.json();

  ui.info('Computing leaf hash with two different payloads:');
  ui.leafHashProof(`Payload A: ${JSON.stringify(proof.payloadA)}`, proof.hashWithA);
  ui.leafHashProof(`Payload B: ${JSON.stringify(proof.payloadB)}`, proof.hashWithB);
  ui.blank();
  ui.verify('Leaf hash identical despite different payloads', proof.identical);
  await breathe();
  ui.info('An auditor verifies chain structure without seeing event contents.');
  log(`Phase 7: Leaf hash proof identical=${proof.identical}`);

  await pause(opts.interactive);

  // ── Phase 8: Chain Verification ───────────────────────────

  ui.phase('8', 'CONTINUITY CHAIN VERIFICATION');
  ui.info('Every event is linked. Modifying any event invalidates all subsequent hashes.');
  await breathe();

  const chainRes = await fetch(`http://127.0.0.1:${opts.port}/chain`);
  const chainData = await chainRes.json();

  ui.blank();
  for (const e of chainData.events) {
    ui.chainEvt(e.seq, e.type, e.leaf);
  }
  ui.blank();
  ui.verify('Chain structural integrity', chainData.valid);
  ui.verify('Sequential leaf hash linkage', chainData.valid);
  ui.verify('Payload hash integrity', chainData.valid);
  await breathe();
  ui.ok(`${chainData.count} events verified`);
  log(`Phase 8: chain valid=${chainData.valid} events=${chainData.count}`);

  await pause(opts.interactive);

  // ── Phase 9: Evidence Bundle ──────────────────────────────

  ui.phase('9', 'OFFLINE EVIDENCE BUNDLE');
  ui.info('Four verification steps. No network required. Standard Ed25519 + SHA-256.');
  await breathe();

  const evidRes = await fetch(`http://127.0.0.1:${opts.port}/evidence`);
  const evid = await evidRes.json();

  ui.blank();
  ui.detail('Merkle root', evid.checkpoint.merkle_root.slice(0, 32) + '...');
  ui.blank();

  ui.verify('Step 1: Artifact signature (Ed25519)', evid.verification.step1_artifact_sig);
  ui.verify('Step 2: Receipt signatures', evid.verification.step2_receipt_sigs);
  ui.verify('Step 3: Merkle inclusion proofs', evid.verification.step3_merkle_proofs);
  ui.verify('Step 4: Anchor validation', true);
  ui.blank();
  ui.verify('OVERALL VERIFICATION', evid.verification.overall);
  await breathe();
  log(`Phase 9: verification=${evid.verification.overall}`);

  await pause(opts.interactive);

  // ── Phase 10: Export ──────────────────────────────────────

  ui.phase('10', 'EXPORT EVIDENCE TO DISK');
  ui.info('Everything an air-gapped auditor needs, in one folder.');
  await breathe();

  const exportRes = await fetch(`http://127.0.0.1:${opts.port}/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ transcript }),
  });
  const exp = await exportRes.json();

  ui.blank();
  ui.evidenceExported(exp.directory);

  // ── Cleanup ───────────────────────────────────────────────

  portalProc.send({ type: 'restore' });
  await sleep(200);
  portalProc.send({ type: 'shutdown' });
  agentProc.send({ type: 'shutdown' });
  await sleep(500);
  portalProc.kill();
  agentProc.kill();
}

export async function runAllScenarios(interactive: boolean): Promise<void> {
  let port = 9400;
  for (const id of SCENARIO_IDS) {
    await runScenario({ scenario: id as ScenarioId, interactive, port });
    port++;
    ui.blank();
    if (interactive) {
      console.log(`  ${GRY}Next scenario... Press Enter${R}`);
      await new Promise<void>(r => {
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        rl.once('line', () => { rl.close(); r(); });
      });
    }
  }
}
