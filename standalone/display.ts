/**
 * Terminal Display - Production Visual Layer
 * Attested Intelligence Holdings LLC
 */

const R  = '\x1b[0m';
const B  = '\x1b[1m';
const D  = '\x1b[2m';
const I  = '\x1b[3m';
const RED = '\x1b[31m';
const GRN = '\x1b[32m';
const YLW = '\x1b[33m';
const BLU = '\x1b[34m';
const CYN = '\x1b[36m';
const WHT = '\x1b[37m';
const GRY = '\x1b[90m';
const BG_RED = '\x1b[41m';
const BG_GRN = '\x1b[42m';
const BG_YLW = '\x1b[43m';
const BG_BLU = '\x1b[44m';
const BG_CYN = '\x1b[46m';
const BG_WHT = '\x1b[47m';

const W = 72;
const RULE = '─'.repeat(W);
const DRULE = '═'.repeat(W);
const DOT = `${GRY}·${R}`;

function pad(s: string, w: number): string {
  // Strip ANSI for length calculation
  const visible = s.replace(/\x1b\[[0-9;]*m/g, '');
  const diff = w - visible.length;
  return diff > 0 ? s + ' '.repeat(diff) : s;
}

function box(lines: string[]): void {
  console.log(`  ${CYN}${B}╔${'═'.repeat(W - 2)}╗${R}`);
  for (const line of lines) {
    console.log(`  ${CYN}${B}║${R} ${pad(line, W - 4)} ${CYN}${B}║${R}`);
  }
  console.log(`  ${CYN}${B}╚${'═'.repeat(W - 2)}╝${R}`);
}

export function banner(): void {
  console.log('');
  console.log('');
  box([
    '',
    `${B}${WHT}  A T T E S T E D   I N T E L L I G E N C E${R}`,
    '',
    `${CYN}  Attested Governance Artifacts ${GRY}(AGA)${R}`,
    `${GRY}  Cryptographic Runtime Governance for Autonomous Systems${R}`,
    '',
    `${GRY}  ┌─────────────────────────────────────────────────────┐${R}`,
    `${GRY}  │${R} ${D}NIST-2025-0035 ${DOT} NCCoE AI Agent Identity${R}       ${GRY}│${R}`,
    `${GRY}  │${R} ${D}Attested Intelligence Holdings LLC${R}                 ${GRY}│${R}`,
    `${GRY}  └─────────────────────────────────────────────────────┘${R}`,
    '',
  ]);
  console.log('');
}

export function scenarioHeader(name: string, desc: string, nistRef: string): void {
  console.log(`  ${CYN}${B}┌${'─'.repeat(W - 2)}┐${R}`);
  console.log(`  ${CYN}${B}│${R} ${B}${WHT}SCENARIO${R}${GRY}: ${B}${name}${R}`);
  console.log(`  ${CYN}${B}│${R} ${GRY}${desc}${R}`);
  console.log(`  ${CYN}${B}│${R} ${GRY}${I}${nistRef}${R}`);
  console.log(`  ${CYN}${B}└${'─'.repeat(W - 2)}┘${R}`);
  console.log('');
}

export function phase(num: string, title: string): void {
  console.log('');
  console.log(`  ${GRY}${'━'.repeat(W)}${R}`);
  console.log(`  ${B}${CYN}PHASE ${num}${R}  ${B}${WHT}${title}${R}`);
  console.log(`  ${GRY}${'━'.repeat(W)}${R}`);
  console.log('');
}

export function portal(msg: string): void {
  console.log(`  ${BG_CYN}${WHT}${B} PORTAL ${R} ${msg}`);
}

export function agent(msg: string): void {
  console.log(`  ${BG_BLU}${WHT}${B} AGENT  ${R} ${msg}`);
}

export function ok(msg: string): void {
  console.log(`  ${GRN}✓${R} ${msg}`);
}

export function fail(msg: string): void {
  console.log(`  ${RED}✗${R} ${B}${msg}${R}`);
}

export function warn(msg: string): void {
  console.log(`  ${YLW}⚠${R} ${YLW}${msg}${R}`);
}

export function info(msg: string): void {
  console.log(`  ${GRY}${msg}${R}`);
}

export function detail(label: string, value: string): void {
  console.log(`  ${GRY}${label.padEnd(20)}${R}${D}${value}${R}`);
}

export function blank(): void {
  console.log('');
}

export function measurement(cycle: number, match: boolean, hash: string): void {
  const num = String(cycle).padStart(2);
  if (match) {
    console.log(`  ${GRY}${num}${R}  ${BG_GRN}${WHT}${B} CLEAN ${R}  ${GRY}sha256=${hash.slice(0, 24)}${D}...${R}`);
  } else {
    console.log(`  ${num}  ${BG_RED}${WHT}${B} DRIFT ${R}  ${WHT}sha256=${hash.slice(0, 24)}${D}...${R}`);
  }
}

export function portalState(label: string, value: string): void {
  let color = GRY;
  let icon = '○';
  if (value === 'ACTIVE_MONITORING') { color = GRN; icon = '●'; }
  else if (value === 'DRIFT_DETECTED') { color = YLW; icon = '◉'; }
  else if (value.includes('QUARANTINE')) { color = RED; icon = '◈'; }
  else if (value === 'TERMINATED') { color = RED; icon = '■'; }
  console.log(`  ${color}${icon}${R} ${label}: ${color}${B}${value}${R}`);
}

export function enforce(action: string, label?: string): void {
  console.log('');
  console.log(`  ${BG_RED}${WHT}${B} ▸ ENFORCEMENT: ${action} ${R}`);
  if (label) console.log(`  ${RED}${I}  ${label}${R}`);
  console.log('');
}

export function chainEvt(seq: number, type: string, leaf: string): void {
  const typeColor = type === 'GENESIS' ? CYN
    : type === 'POLICY_ISSUANCE' ? BLU
    : type === 'INTERACTION_RECEIPT' ? GRN
    : type === 'SUBSTITUTION' ? YLW
    : type === 'REVOCATION' ? RED : GRY;
  console.log(`  ${GRY}${String(seq).padStart(3)}${R} ${typeColor}${B}${type.padEnd(24)}${R} ${GRY}${leaf.slice(0, 16)}${D}...${R}`);
}

export function verify(step: string, pass: boolean): void {
  const icon = pass ? `${GRN}${B}PASS${R}` : `${RED}${B}FAIL${R}`;
  console.log(`  ${step.padEnd(44)} ${icon}`);
}

export function disclosure(requested: string, result: string, wasSubstituted: boolean, substitute?: string): void {
  if (wasSubstituted) {
    console.log(`  ${RED}●${R} ${B}${requested}${R} ${GRY}→${R} ${RED}DENIED${R} ${GRY}(sensitivity too high)${R}`);
    console.log(`  ${GRN}●${R} ${B}${substitute}${R} ${GRY}→${R} ${GRN}PERMITTED${R} ${GRY}(auto-substituted)${R}`);
    console.log(`  ${GRY}  Substitution receipt signed and appended to chain${R}`);
  } else {
    console.log(`  ${GRN}●${R} ${B}${requested}${R} ${GRY}→${R} ${GRN}PERMITTED${R} = ${B}${result}${R}`);
  }
}

export function leafHashProof(meta: string, hash: string): void {
  console.log(`  ${GRY}${meta}${R}`);
  console.log(`  ${CYN}${B}LeafHash${R}: ${hash.slice(0, 32)}${GRY}...${R}`);
}

export function delegationInfo(parent: string[], child: string[], ttlParent: number, ttlChild: number): void {
  console.log(`  ${GRY}Parent scope:${R}  [${parent.join(', ')}]`);
  console.log(`  ${GRN}Child scope:${R}   [${child.join(', ')}] ${GRN}${I}(reduced)${R}`);
  console.log(`  ${GRY}Parent TTL:${R}    ${ttlParent}s remaining`);
  console.log(`  ${GRN}Child TTL:${R}     ${ttlChild}s ${GRN}${I}(cannot exceed parent)${R}`);
}

export function behavioralAlert(type: string, detail: string): void {
  console.log(`  ${BG_YLW}${WHT}${B} BEHAVIORAL ${R} ${YLW}${type}${R}: ${detail}`);
}

export function benchmarkResult(msPerOp: number): void {
  const status = msPerOp < 10 ? `${GRN}${B}PASS${R}` : `${RED}${B}FAIL${R}`;
  console.log(`  ${CYN}◆${R} Benchmark: ${B}${msPerOp.toFixed(2)}ms${R} per measurement ${GRY}(NIST target: <10ms)${R} ${status}`);
}

export function watchStatus(state: string, cadence: number, ttl: number, chainLen: number, receiptCount: number): void {
  const stColor = state === 'ACTIVE_MONITORING' ? GRN : RED;
  process.stdout.write(`\r  ${stColor}●${R} ${B}${state}${R} ${GRY}│${R} ${cadence}ms ${GRY}│${R} TTL ${ttl}s ${GRY}│${R} Chain ${chainLen} ${GRY}│${R} Receipts ${receiptCount}   `);
}

export function scenarioMenu(): void {
  console.log(`  ${B}Select Demonstration Scenario:${R}`);
  console.log('');
  console.log(`  ${CYN}${B}[1]${R}  ${B}SCADA Process Enforcement${R}`);
  console.log(`       ${GRY}Chemical reactor controller ${DOT} 100ms cadence ${DOT} actuator disconnect${R}`);
  console.log('');
  console.log(`  ${CYN}${B}[2]${R}  ${B}Autonomous Vehicle Governance${R}`);
  console.log(`       ${GRY}Flight control software ${DOT} return-to-home enforcement${R}`);
  console.log('');
  console.log(`  ${CYN}${B}[3]${R}  ${B}AI Agent Tool Governance${R}`);
  console.log(`       ${GRY}MCP tool-use agent ${DOT} behavioral drift detection${R}`);
  console.log('');
  console.log(`  ${CYN}${B}[A]${R}  ${B}Run All Scenarios${R}`);
  console.log('');
}

export function summary(): void {
  console.log('');
  box([
    '',
    `${GRN}${B}  DEMONSTRATION COMPLETE${R}`,
    '',
    `${WHT}  Protocol Capabilities Demonstrated:${R}`,
    `  ${GRN}✓${R} ${GRY}Attestation + measurement + enforcement${R}`,
    `  ${GRN}✓${R} ${GRY}Privacy-preserving disclosure${R}`,
    `  ${GRN}✓${R} ${GRY}Continuity chain (payload excluded)${R}`,
    `  ${GRN}✓${R} ${GRY}Quarantine / phantom execution${R}`,
    `  ${GRN}✓${R} ${GRY}TTL-based fail-closed${R}`,
    `  ${GRN}✓${R} ${GRY}Composite multi-measurement hash${R}`,
    `  ${GRN}✓${R} ${GRY}Offline evidence bundle${R}`,
    `  ${GRN}✓${R} ${GRY}Graceful degradation${R}`,
    `  ${GRN}✓${R} ${GRY}Disclosure substitution + inference risk${R}`,
    `  ${GRN}✓${R} ${GRY}Mid-session revocation${R}`,
    '',
    `${GRY}  ┌─────────────────────────────────────────────────────┐${R}`,
    `${GRY}  │${R} ${B}The portal is mandatory.${R} The agent cannot bypass it.${GRY}│${R}`,
    `${GRY}  │${R} ${B}The evidence is self-verifying.${R} No network needed. ${GRY}│${R}`,
    `${GRY}  │${R} ${B}The receipts prove enforcement happened.${R}            ${GRY}│${R}`,
    `${GRY}  └─────────────────────────────────────────────────────┘${R}`,
    '',
  ]);
}

export function evidenceExported(dir: string): void {
  console.log(`  ${GRN}${B}Evidence exported:${R}`);
  console.log(`  ${GRY}${dir}/${R}`);
  console.log('');
  const files = [
    ['artifact.json',              'Sealed policy artifact'],
    ['receipts.json',              'Signed measurement receipts'],
    ['chain.json',                 'Tamper-evident continuity chain'],
    ['evidence-bundle.json',       'Self-verifying Merkle bundle'],
    ['verification-report.json',   'Machine-readable verification'],
    ['verification-walkthrough.txt','Human-readable audit guide'],
    ['demo-transcript.txt',        'Timestamped demonstration log'],
  ];
  for (const [name, desc] of files) {
    console.log(`    ${CYN}${name.padEnd(32)}${R}${GRY}${desc}${R}`);
  }
  console.log('');
  console.log(`  ${GRY}An air-gapped auditor can verify every signature and proof${R}`);
  console.log(`  ${GRY}using ${B}only${R}${GRY} these files. No network access required.${R}`);
}
