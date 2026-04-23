/**
 * Portal Server - the mandatory enforcement boundary.
 * Runs as a child process. Agent can ONLY reach this.
 *
 * Attested Intelligence Holdings LLC
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { PortalEngine } from './engine.js';
import { SCENARIOS, type ScenarioId } from './scenarios.js';
import { pkToHex } from '../src/crypto/sign.js';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const args = process.argv.slice(2);
function arg(name: string, def = ''): string {
  const a = args.find(a => a.startsWith(`--${name}=`));
  return a ? a.split('=').slice(1).join('=') : def;
}

const PORT = parseInt(arg('port', '9400'));
const SCENARIO = arg('scenario', 'drone') as ScenarioId;
const scenario = SCENARIOS[SCENARIO];
if (!scenario) { console.error(`Unknown scenario: ${SCENARIO}`); process.exit(1); }

const baseDir = join(tmpdir(), 'aga-v2-demo', SCENARIO);
const engine = new PortalEngine(scenario, baseDir);

const log = (msg: string) => {
  const line = `[PORTAL] ${msg}`;
  console.error(line); // stderr for display
  if (process.send) process.send({ type: 'log', data: line }); // IPC to orchestrator
};

// ── Attest on startup ────────────────────────────────────────

const { bytesHash, metaHash } = engine.attest();
log(`Attested: ${scenario.agentFilename}`);
log(`bytes_hash: ${bytesHash.slice(0, 24)}...`);
log(`sealed_hash: ${engine.sealedHash.slice(0, 24)}...`);
log(`State: ${engine.portalState}`);

// ── HTTP helpers ─────────────────────────────────────────────

function parseBody(req: IncomingMessage): Promise<any> {
  return new Promise(resolve => {
    let body = '';
    req.on('data', (c: Buffer) => body += c.toString());
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
  });
}

function respond(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// ── HTTP Server ──────────────────────────────────────────────

const server = createServer(async (req, res) => {
  const url = req.url ?? '/';
  const body = req.method === 'POST' ? await parseBody(req) : {};

  // Always-allowed: status + verification endpoints
  if (url === '/status') {
    return respond(res, 200, {
      portal_state: engine.portalState,
      chain_length: engine.chainLength,
      receipt_count: engine.receiptCount,
      scenario: scenario.id,
      quarantine_active: !!engine.quarantine?.active,
      issuer_key: pkToHex(engine.issuerKP.publicKey),
      portal_key: pkToHex(engine.portalKP.publicKey),
    });
  }

  if (url === '/chain') {
    const result = engine.verifyChain();
    return respond(res, 200, {
      valid: result.valid, count: result.count,
      events: engine.chain.map(e => ({ seq: e.sequence_number, type: e.event_type, leaf: e.leaf_hash })),
    });
  }

  if (url === '/evidence') {
    const { checkpoint, verification, bundle } = engine.generateEvidence();
    return respond(res, 200, { checkpoint, verification, bundle });
  }

  if (url === '/export') {
    const dir = engine.exportEvidence(body.transcript ?? []);
    return respond(res, 200, { exported: true, directory: dir });
  }

  if (url === '/leaf-hash-proof') {
    return respond(res, 200, engine.proveLeafHashExcludesPayload());
  }

  if (url === '/disclose') {
    const result = engine.processDisclosureRequest(body.claim_id, body.mode ?? 'REVEAL_FULL');
    return respond(res, 200, result);
  }

  // ── Governance gate ────────────────────────────────────

  if (engine.portalState === 'TERMINATED') {
    log(`BLOCKED - portal TERMINATED. Request: ${url}`);
    return respond(res, 403, { error: 'GOVERNANCE_TERMINATED', portal_state: engine.portalState });
  }

  if (engine.portalState === 'PHANTOM_QUARANTINE') {
    engine.forensicCapture(`http:${req.method}:${url}`, body);
    log(`QUARANTINE CAPTURE - ${url} (input #${engine.quarantineCaptures})`);
    return respond(res, 403, { error: 'GOVERNANCE_QUARANTINED', forensic_capture: true, inputs_captured: engine.quarantineCaptures });
  }

  // ── MEASURE BEFORE EVERY GOVERNED REQUEST ──────────────

  const m = engine.measure();

  if (!m.match) {
    const action = engine.scenarioConfig.enforcementTriggers[0] ?? 'TERMINATE';
    const label = engine.scenarioConfig.enforcementLabels[action] ?? action;
    log(`*** DRIFT DETECTED *** Enforcement: ${action}`);
    log(`  ${label}`);
    if (process.send) process.send({ type: 'drift', action, receipt_id: m.receipt.receipt_id, expected_hash: m.expectedBytesHash, current_hash: m.currentBytesHash });
    return respond(res, 403, {
      error: 'GOVERNANCE_DRIFT', enforcement_action: action,
      receipt_id: m.receipt.receipt_id, portal_state: engine.portalState,
    });
  }

  // Record behavioral event
  if (body.tool_name) {
    engine.recordBehavior(body.tool_name);
  }

  // ── Governed operations (agent calls these) ────────────

  if (url === '/operate') {
    if (body.operation !== 'benchmark') {
      log(`AUTHORIZED - ${body.operation ?? 'operation'} (receipt: ${m.receipt.receipt_id.slice(0, 8)}...)`);
    }
    if (process.send) process.send({ type: 'authorized', receipt_id: m.receipt.receipt_id, operation: body.operation });
    return respond(res, 200, {
      success: true, authorized: true,
      receipt_id: m.receipt.receipt_id, portal_state: engine.portalState,
    });
  }

  if (url === '/measure-behavior') {
    const bm = engine.measureBehavior();
    if (bm.drift_detected && process.send) {
      process.send({ type: 'behavioral_drift', violations: bm.violations });
    }
    return respond(res, 200, bm);
  }

  respond(res, 404, { error: 'Unknown endpoint' });
});

// ── Control commands from orchestrator via IPC ───────────────

process.on('message', (msg: any) => {
  if (msg.type === 'tamper') {
    engine.tamper();
    log('*** AGENT BINARY TAMPERED (by orchestrator command) ***');
  }
  if (msg.type === 'revoke') {
    engine.revoke(msg.reason ?? 'Revoked by orchestrator');
    log(`REVOCATION pushed - portal state: ${engine.portalState}`);
    if (process.send) process.send({ type: 'revoked', portal_state: engine.portalState });
  }
  if (msg.type === 'restore') {
    engine.restore();
    log('Agent binary restored to original');
  }
  if (msg.type === 'shutdown') {
    server.close();
    process.exit(0);
  }
});

server.on('error', (err: any) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[PORTAL] Port ${PORT} already in use. Try --port=${PORT + 1}`);
    process.exit(1);
  }
  throw err;
});

server.listen(PORT, '127.0.0.1', () => {
  log(`Listening on http://127.0.0.1:${PORT}`);
  log(`Scenario: ${scenario.name}`);
  log(`Protected resources: ${scenario.protectedResources.join(', ')}`);
  if (process.send) process.send({ type: 'ready', port: PORT });
});
