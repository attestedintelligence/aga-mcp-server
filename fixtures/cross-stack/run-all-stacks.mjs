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

// ── PINNED-PATH NEGATIVE CONTROLS ─────────────────────────────────────────────
// Without these, the pinned half of "six verifiers agree" was never exercised. Every pinned case
// above expects VERIFIED, and this harness collapses each stack to VERIFIED/FAILED (verdict only —
// `issuerVerified` is never read, and the subprocess stacks decide on exit code alone). So a stack
// that SILENTLY DISCARDED the pin still returned VERIFIED and the gate stayed green: "provenance
// verified" and "pin ignored" were indistinguishable. That is precisely the blind spot the shipped
// aga-verify fell into (a malformed --pubkey downgraded to integrity-only and exited 0) and the one
// the reviewer download's verifier fell into from the other direction (it lowercased an uppercase
// pin and asserted a key match the canonical verifiers do not make).
//
// A WRONG-but-well-formed pin is the control that closes it: any verifier honoring the pin must
// FAIL, and any verifier discarding it returns VERIFIED — a disagreement this gate now goes red on.
// The pin must be a GENUINE Ed25519 curve point, not merely 64 hex chars. A 64-hex value that is
// not a valid point (e.g. 'f'*64, whose y >= 2^255-19) is MALFORMED, and the stacks legitimately
// disagree about what a malformed pin means — see the KNOWN DIVERGENCE note below. Using such a
// value here would test that disagreement instead of the thing we want: that a pin which IS
// honored, and does NOT match, fails everywhere. Derived deterministically from the fixed seed
// 0x2a*32 (no randomness — this harness must be reproducible). NOTE: seed 0x07*32 derives the
// CORPUS's own key, so the collision guard below is load-bearing, not decorative — it already
// caught exactly that.
const wrongPin = '197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61';
if (wrongPin === vb.pinned_public_key) throw new Error('negative-control pin collides with the corpus key');
cases.push({ name: 'NEGATIVE CONTROL: valid-but-wrong pin must FAIL on every stack', bundle: vb.bundle, pin: wrongPin, expect: 'FAILED' });

// ── KNOWN DIVERGENCE, recorded not hidden (surfaced by adding the control above) ───────────────
// On a pin that is 64 hex but NOT a valid curve point, the stacks split:
//   engine (src/sep/verify.ts:131) gates `pinned` on validPublicKeyForProfile -> wellFormedKey,
//     which rejects a non-canonical y, so the pin is DISCARDED and the bundle reads VERIFIED
//     (integrity-only);
//   reference / aga-verify / go / python gate `pinned` on a plain ^[0-9a-f]{64}$ hex test, so the
//     pin is HONORED, mismatches, and the bundle reads FAILED.
// Same input, opposite verdicts, 1-vs-5. Neither is unsound — they disagree on whether a malformed
// pin means "no pin" or "a pin that cannot match" — but "six verifiers agree" must not paper over
// it. Deliberately NOT added as a passing case here: that would freeze the divergence into the
// corpus as if it were intended. It needs a spec ruling on malformed-pin semantics first.
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
  // R3 safe-integer floor — the release tree's proof that the 3.4.0 headline change is load-bearing.
  // A signed field carrying a JSON integer with |value| > 2^53-1 (or a non-finite / non-integral
  // literal) is preserved verbatim by Go (json.Number) and Python (arbitrary-precision int); a
  // file-parsing verifier WITHOUT the floor would re-canonicalize the preserved literal and could
  // VERIFY, while JS rounds it — a cross-stack split. With the floor applied in all five file-parse
  // verifiers, every stack rejects these at the canon step. If the floor regressed, these three
  // would split (Go/Python VERIFIED vs JS FAILED) and this gate would go red — the coverage the
  // GATE-01 review found missing from this tree (the monorepo already carried them).
  { name: 'raw: request_id = 9007199254740993 (2^53+1) exact literal → FAILED on all stacks', raw: validRaw.replace(/"request_id":"r1"/, '"request_id":9007199254740993'), expect: 'FAILED' },
  { name: 'raw: request_id = -9007199254740993 exact literal → FAILED', raw: validRaw.replace(/"request_id":"r1"/, '"request_id":-9007199254740993'), expect: 'FAILED' },
  { name: 'raw: request_id = 1e400 (large-exponent → non-finite) → FAILED', raw: validRaw.replace(/"request_id":"r1"/, '"request_id":1e400'), expect: 'FAILED' },
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
