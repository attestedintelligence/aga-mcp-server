/**
 * Cross-stack conformance harness — proves EVERY conformant SEP verifier renders the
 * SAME verdict on the committed vectors. Runs the canonical corpus (valid bundle, the
 * adversarial set, and all 10 small-order key swaps) through FIVE verifiers:
 *   1. reference   aga-receipt-spec/verify/verify-sep.mjs   (JS, normative authority)
 *   2. engine      dist/sep/verify.js                        (JS, the MCP server's verifier)
 *   3. aga-verify  independent-verifier/dist/aga-verify.mjs  (JS, published verifier)
 *   4. Go          aga-receipt-spec/verify/verify.go         (stdlib crypto/ed25519)
 *   5. Python      aga-receipt-spec/verify/verify.py         (pure-stdlib RFC-8032 Ed25519)
 *
 * Requires: node, go, python on PATH, and `npm run build` (for dist/). Exit 0 = all stacks
 * agree with the expected verdict on every case; 1 = any disagreement.
 *
 *   node fixtures/cross-stack/run-all-stacks.mjs
 */
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');
// Pin-check the corpus first (tamper-evident; mirrors the v2 harness). A byte change to vectors.json
// MUST fail here, forcing a conscious regenerate (npx tsx generate.mjs rewrites vectors.sha256).
const vectorsRaw = readFileSync(join(HERE, 'vectors.json'));
const vectorsPin = readFileSync(join(HERE, 'vectors.sha256'), 'utf8').trim().split(/\s+/)[0];
const vectorsDigest = createHash('sha256').update(vectorsRaw).digest('hex');
if (vectorsDigest !== vectorsPin) {
  console.error(`CORPUS PIN MISMATCH: sha256(vectors.json)=${vectorsDigest} but vectors.sha256=${vectorsPin}`);
  console.error('Regenerate with: npx tsx fixtures/cross-stack/generate.mjs');
  process.exit(1);
}
console.log(`corpus pin OK: sha256(vectors.json) = ${vectorsDigest}`);
const vectors = JSON.parse(vectorsRaw.toString('utf8'));
const imp = (rel) => import(pathToFileURL(resolve(ROOT, rel)).href);

const refMod = await imp('aga-receipt-spec/verify/verify-sep.mjs');
const engineMod = await imp('dist/sep/verify.js');
const agaMod = await imp('independent-verifier/dist/aga-verify.mjs');

const verdict = (r) => (r && r.verdict === 'VERIFIED' ? 'VERIFIED' : 'FAILED');
const jsRef = (b, pin) => verdict(refMod.verifySepBundle(b, pin));
const jsEngine = (b, pin) => verdict(engineMod.verifySepBundle(b, pin));
const jsAga = (b, pin) =>
  verdict(agaMod.verifyEvidenceBundle ? agaMod.verifyEvidenceBundle(JSON.stringify(b), pin) : agaMod.verifySepBundle(b, pin));

const work = mkdtempSync(join(tmpdir(), 'aga-xstack-'));
// Build the Go verifier once (fast per-case exe vs `go run` recompiling each time).
const goExe = join(work, process.platform === 'win32' ? 'verifygo.exe' : 'verifygo');
execFileSync('go', ['build', '-o', goExe, resolve(ROOT, 'aga-receipt-spec/verify/verify.go')], { stdio: 'pipe' });
const pyFile = resolve(ROOT, 'aga-receipt-spec/verify/verify.py');

let caseNo = 0;
const subVerdict = (cmd, args, b, pin) => {
  const f = join(work, `b${caseNo++}.json`);
  writeFileSync(f, JSON.stringify(b));
  const a = pin ? [...args, f, '--pubkey', pin] : [...args, f];
  try { execFileSync(cmd, a, { stdio: 'pipe' }); return 'VERIFIED'; } // exit 0
  catch (e) { return e.status === 1 ? 'FAILED' : `ERROR(${e.status})`; }
};
const goV = (b, pin) => subVerdict(goExe, [], b, pin);
const pyV = (b, pin) => subVerdict('python', [pyFile], b, pin);                            // default: audited library
const pyStdV = (b, pin) => subVerdict('python', [pyFile, '--ed25519', 'stdlib'], b, pin);  // opt-in stdlib demonstrator

const STACKS = [['reference', jsRef], ['engine', jsEngine], ['aga-verify', jsAga], ['go', goV], ['python', pyV], ['python-stdlib', pyStdV]];

const cases = [];
const vb = vectors.valid_bundle;
cases.push({ name: 'valid (pinned)', bundle: vb.bundle, pin: vb.pinned_public_key, expect: 'VERIFIED' });
cases.push({ name: 'valid (unpinned)', bundle: vb.bundle, pin: undefined, expect: 'VERIFIED' });
for (const v of (vectors.valid_variants || [])) cases.push({ name: `valid-variant: ${v.desc}`, bundle: v.bundle, pin: v.pinned_public_key, expect: 'VERIFIED' });
for (const [i, a] of vectors.adversarial.entries()) cases.push({ name: `adversarial[${i}] ${a.desc}`, bundle: a.bundle, pin: undefined, expect: 'FAILED' });

let failures = 0;
for (const c of cases) {
  const got = STACKS.map(([name, fn]) => [name, fn(c.bundle, c.pin)]);
  const allAgree = got.every(([, v]) => v === c.expect);
  if (!allAgree) failures++;
  const detail = got.map(([n, v]) => `${n}=${v}`).join(' ');
  console.log(`${allAgree ? 'OK ' : 'XX '} ${c.expect.padEnd(8)} ${c.name}  [${detail}]`);
}

// ── raw-byte / file-parse cases (literal files) ────────────────────────────
// The object harness above re-stringifies every bundle through JSON.stringify, which ERASES
// raw-byte differences (trailing content after the document; sub-ULP numeric literals that round
// to the same float64). Those are exactly the file-parse-layer divergences a blind re-audit found
// in the Go stack, so we ALSO feed a few LITERAL files to the FILE-PARSING verifiers. The engine
// is library-only (it receives pre-parsed objects in-server, never raw file bytes), so the JS
// file-parse layer is represented here by the reference + aga-verify CLIs.
const refCli = resolve(ROOT, 'aga-receipt-spec/verify/verify-sep.mjs');
const agaCli = resolve(ROOT, 'independent-verifier/dist/aga-verify.mjs');
const cliVerdict = (cmd, a) => {
  try { execFileSync(cmd, a, { stdio: 'pipe' }); return 'VERIFIED'; }
  catch (e) { return e.status === 1 ? 'FAILED' : `ERROR(${e.status})`; }
};
const withPin = (pin, ...a) => (pin ? [...a, '--pubkey', pin] : a);
const RAW_STACKS = [
  ['reference', (f, pin) => cliVerdict('node', withPin(pin, refCli, f))],
  ['aga-verify', (f, pin) => cliVerdict('node', withPin(pin, agaCli, f))],
  ['go', (f, pin) => cliVerdict(goExe, withPin(pin, f))],
  ['python', (f, pin) => cliVerdict('python', withPin(pin, pyFile, f))],
  ['python-stdlib', (f, pin) => cliVerdict('python', withPin(pin, pyFile, '--ed25519', 'stdlib', f))],
];
const validRaw = JSON.stringify(vb.bundle);
const rawCases = [
  { name: 'raw: trailing junk after the bundle document', raw: validRaw + '\njunk', expect: 'FAILED' },
  { name: 'raw: a second JSON document appended', raw: validRaw + '\n' + validRaw, expect: 'FAILED' },
  { name: 'raw: trailing whitespace only (control — must stay VERIFIED)', raw: validRaw + '\n   \n', expect: 'VERIFIED' },
  { name: 'raw: sub-ULP integral leaf_count literal (JCS float64 collapse → VERIFIED)', raw: validRaw.replace(/("leaf_count":)(\d+)/, '$1$2.0000000000000001'), expect: 'VERIFIED' },
];
console.log('\n--- raw-byte / file-parse cases (literal files; engine excluded — library-only) ---');
for (const c of rawCases) {
  const f = join(work, `raw${caseNo++}.json`);
  writeFileSync(f, c.raw);
  const got = RAW_STACKS.map(([name, fn]) => [name, fn(f, vb.pinned_public_key)]);
  const allAgree = got.every(([, v]) => v === c.expect);
  if (!allAgree) failures++;
  console.log(`${allAgree ? 'OK ' : 'XX '} ${c.expect.padEnd(8)} ${c.name}  [${got.map(([n, v]) => `${n}=${v}`).join(' ')}]`);
}
const total = cases.length + rawCases.length;

rmSync(work, { recursive: true, force: true });

console.log(failures
  ? `\nCROSS-STACK CONFORMANCE FAILED (${failures}/${total} cases had a disagreement)`
  : `\nCROSS-STACK CONFORMANCE PASSED — ${STACKS.length} verifiers agree on all ${total} cases (incl. ${rawCases.length} raw-byte/file-parse cases)`);
process.exit(failures ? 1 : 0);
