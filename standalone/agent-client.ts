/**
 * Agent Client - has NO crypto keys, NO direct access.
 * Can ONLY reach the portal at localhost.
 *
 * Attested Intelligence Holdings LLC
 */

const args = process.argv.slice(2);
function arg(name: string, def = ''): string {
  const a = args.find(a => a.startsWith(`--${name}=`));
  return a ? a.split('=').slice(1).join('=') : def;
}

const PORTAL_URL = arg('portal', 'http://127.0.0.1:9400');
const SCENARIO = arg('scenario', 'drone');

// NOTE: This file does NOT import any crypto, any SDK, any keys.
// The agent has NOTHING except fetch() to localhost.

const log = (msg: string) => {
  const line = `[AGENT]  ${msg}`;
  console.error(line);
  if (process.send) process.send({ type: 'log', data: line });
};

async function portalRequest(path: string, body?: unknown): Promise<any> {
  try {
    const res = await fetch(`${PORTAL_URL}${path}`, {
      method: body ? 'POST' : 'GET',
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json();
    if (!res.ok) {
      log(`✗ ${path} → ${res.status}: ${data.error}`);
      if (process.send) process.send({ type: 'blocked', path, status: res.status, error: data.error });
      return null;
    }
    return data;
  } catch (e: any) {
    log(`✗ ${path} → Connection failed: ${e.message}`);
    return null;
  }
}

// Tool operations the agent performs (scenario-dependent)
const TOOL_SEQUENCES: Record<string, string[][]> = {
  scada: [
    ['read_sensors', 'Read reactor pressure, temperature, flow rate'],
    ['log_status', 'Log readings to process historian'],
    ['adjust_valve', 'Adjust cooling valve to 72%'],
    ['read_sensors', 'Verify valve adjustment took effect'],
    ['log_status', 'Log post-adjustment readings'],
  ],
  drone: [
    ['survey', 'Execute area survey at designated waypoint'],
    ['report', 'Transmit encrypted survey findings'],
    ['survey', 'Continue survey pattern - next sector'],
    ['report', 'Transmit sector 2 findings'],
    ['return_to_home', 'Survey complete - RTH initiated'],
  ],
  'ai-agent': [
    ['reason', 'Analyzing task requirements'],
    ['read_database', 'Query customer records for report'],
    ['reason', 'Synthesizing findings'],
    ['store_memory', 'Cache intermediate results'],
    ['send_email', 'Send summary report to stakeholder'],
  ],
};

async function run() {
  log('Starting autonomous agent');
  log(`Scenario: ${SCENARIO}`);
  log('I have NO crypto keys. I have NO direct access to protected resources.');
  log(`My only connection: ${PORTAL_URL}`);

  // Wait for portal to be ready
  let ready = false;
  for (let i = 0; i < 20; i++) {
    const status = await portalRequest('/status');
    if (status) { ready = true; break; }
    await new Promise(r => setTimeout(r, 200));
  }
  if (!ready) { log('Portal not reachable. Exiting.'); process.exit(1); }

  if (process.send) process.send({ type: 'ready' });

  const tools = TOOL_SEQUENCES[SCENARIO] ?? TOOL_SEQUENCES.drone;
  let cycle = 0;
  let blocked = false;

  while (!blocked) {
    for (const [toolName, description] of tools) {
      cycle++;
      log(`─── Cycle ${cycle} ─── ${toolName}: ${description}`);

      const result = await portalRequest('/operate', {
        operation: description,
        tool_name: toolName,
        cycle,
      });

      if (!result) {
        blocked = true;
        log('');
        log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        log('REQUEST DENIED - Portal has blocked all operations.');
        log('I have no crypto keys. I have no fallback path.');
        log('I have no credentials to reach any protected resource.');
        log('The portal is the only door, and it is closed.');
        log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        break;
      }

      log(`✓ Authorized (receipt: ${result.receipt_id?.slice(0, 8)}...)`);

      if (process.send) process.send({
        type: 'operation',
        cycle, toolName, description,
        receipt_id: result.receipt_id,
      });

      // Simulate work
      await new Promise(r => setTimeout(r, 800));
    }

    if (!blocked) {
      log('Cycle complete. Restarting operations...');
      await new Promise(r => setTimeout(r, 500));
    }
  }

  // Post-incident: try to get evidence (will be blocked if quarantined)
  log('─── Post-incident ───');
  const status = await portalRequest('/status');
  if (status) {
    log(`Portal state: ${status.portal_state}`);
    log(`Chain events: ${status.chain_length}`);
    log(`Receipts: ${status.receipt_count}`);
  }

  if (process.send) process.send({ type: 'done' });
}

// IPC from orchestrator
process.on('message', (msg: any) => {
  if (msg.type === 'shutdown') process.exit(0);
});

run().catch(e => { log(`Fatal: ${e.message}`); process.exit(1); });
