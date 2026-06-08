/**
 * Cross-stack v2 (ML-DSA-65+Ed25519 composite) conformance harness — proves the v2 profile is held
 * to the v1 hardening bar across TWO genuinely independent-language oracles, and that the trichotomy
 * is real across languages. Runs the pinned v2 corpus (vectors-v2.json) through:
 *
 *   v2 oracles (must AGREE byte-for-byte on every case):
 *     1. engine     dist/sep/verify.js               (JS / @noble — the agile in-server verifier)
 *     2. go-v2      aga-receipt-spec/verify/v2 (CIRCL ML-DSA-65 + crypto/ed25519 — agile Go oracle)
 *
 *   v1-only references (must return UNSUPPORTED_PROFILE / exit 3 on the valid v2 bundle):
 *     3. reference  aga-receipt-spec/verify/verify-sep.mjs   (JS, node:crypto)
 *     4. go-v1      aga-receipt-spec/verify/verify.go        (Go, pure-stdlib)
 *     5. python     aga-receipt-spec/verify/verify.py        (pure-stdlib RFC-8032 Ed25519)
 *
 * Also pins the corpus: recomputes sha256(vectors-v2.json) and checks it against vectors-v2.sha256.
 *
 * Requires: node, go (+ CIRCL in the module cache), python on PATH, and `npm run build` (for dist/).
 * Exit 0 = pin matches AND both v2 oracles agree with the expected verdict on every case AND the
 * three v1-only references emit UNSUPPORTED_PROFILE on v2; 1 = any disagreement.
 *
 *   node fixtures/cross-stack/run-v2-stacks.mjs
 */
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');
const imp = (rel) => import(pathToFileURL(resolve(ROOT, rel)).href);

// ── 1. load + PIN-CHECK the corpus ──────────────────────────────────────────
const corpusPath = join(HERE, 'vectors-v2.json');
const corpusText = readFileSync(corpusPath, 'utf8');
const vectors = JSON.parse(corpusText);
const pinFile = readFileSync(join(HERE, 'vectors-v2.sha256'), 'utf8').trim().split(/\s+/)[0];
const digest = createHash('sha256').update(Buffer.from(corpusText, 'utf8')).digest('hex');
if (digest !== pinFile) {
  console.error(`CORPUS PIN MISMATCH: sha256(vectors-v2.json)=${digest} but vectors-v2.sha256=${pinFile}`);
  console.error('Regenerate with: npx tsx fixtures/cross-stack/generate-v2.mjs');
  process.exit(1);
}
console.log(`corpus pin OK: sha256(vectors-v2.json) = ${digest}`);

// ── 2. JS engine (agile) + ALG_ED25519 (for the v1-only mode) ─────────────────
const engineMod = await imp('dist/sep/verify.js');
const profilesMod = await imp('dist/sep/profiles.js');
const ALG_ED25519 = profilesMod.ALG_ED25519;
const jsVerdict = (b, pin) => engineMod.verifySepBundle(b, pin).verdict;
const jsV1OnlyVerdict = (b) => engineMod.verifySepBundle(b, undefined, { supportedProfiles: [ALG_ED25519] }).verdict;

// ── 3. build the Go oracles ───────────────────────────────────────────────────
const work = mkdtempSync(join(tmpdir(), 'aga-xstack-v2-'));
// Inherit the ambient Go env so this runs both locally (module cache) and in CI (default proxy fetches
// CIRCL + GOSUMDB verifies it against the committed go.sum). -mod=mod lets a fresh checkout resolve.
const goEnv = { ...process.env, GOFLAGS: '-mod=mod' };
const goV2Exe = join(work, process.platform === 'win32' ? 'verify-v2.exe' : 'verify-v2');
execFileSync('go', ['build', '-o', goV2Exe, '.'], { cwd: resolve(ROOT, 'aga-receipt-spec/verify/v2'), env: goEnv, stdio: 'pipe' });
const goV1Exe = join(work, process.platform === 'win32' ? 'verifygo.exe' : 'verifygo');
execFileSync('go', ['build', '-o', goV1Exe, resolve(ROOT, 'aga-receipt-spec/verify/verify.go')], { stdio: 'pipe' });
const refCli = resolve(ROOT, 'aga-receipt-spec/verify/verify-sep.mjs');
const pyFile = resolve(ROOT, 'aga-receipt-spec/verify/verify.py');

let caseNo = 0;
const exitToVerdict = (e) => {
  if (e === 0) return 'VERIFIED';
  if (e === 1) return 'FAILED';
  if (e === 3) return 'UNSUPPORTED_PROFILE';
  return `ERROR(${e})`;
};
const runCli = (cmd, args, b, pin) => {
  const f = join(work, `b${caseNo++}.json`);
  writeFileSync(f, JSON.stringify(b));
  const a = pin ? [...args, f, '--pubkey', pin] : [...args, f];
  try { execFileSync(cmd, a, { stdio: 'pipe' }); return 0; }       // exit 0
  catch (e) { return typeof e.status === 'number' ? e.status : -1; }
};
const goV2 = (b, pin) => exitToVerdict(runCli(goV2Exe, [], b, pin));
const goV1 = (b, pin) => exitToVerdict(runCli(goV1Exe, [], b, pin));
const refV1 = (b, pin) => exitToVerdict(runCli('node', [refCli], b, pin));
const pyV1 = (b, pin) => exitToVerdict(runCli('python', [pyFile], b, pin));

// ── 4. the v2 verdict cases (both oracles must agree with expect) ─────────────
const cases = [];
const vb = vectors.valid_bundle;
cases.push({ name: 'valid (pinned)', bundle: vb.bundle, pin: vb.pinned_public_key, expect: 'VERIFIED' });
cases.push({ name: 'valid (unpinned)', bundle: vb.bundle, pin: undefined, expect: 'VERIFIED' });
for (const v of (vectors.valid_variants || [])) cases.push({ name: `valid-variant: ${v.desc}`, bundle: v.bundle, pin: v.pinned_public_key, expect: 'VERIFIED' });
for (const [i, a] of vectors.adversarial.entries()) cases.push({ name: `adversarial[${i}] ${a.desc}`, bundle: a.bundle, pin: undefined, expect: 'FAILED' });

let failures = 0;
console.log('\n--- v2 verdict cases (engine [JS/noble] vs go-v2 [CIRCL] — must agree) ---');
for (const c of cases) {
  const js = jsVerdict(c.bundle, c.pin);
  const go = goV2(c.bundle, c.pin);
  const ok = js === c.expect && go === c.expect;
  if (!ok) failures++;
  console.log(`${ok ? 'OK ' : 'XX '} ${c.expect.padEnd(8)} ${c.name.slice(0, 88)}  [engine=${js} go-v2=${go}]`);
}

// ── 5. the trichotomy: the valid v2 bundle on v1-only verifiers -> UNSUPPORTED_PROFILE (exit 3) ──
console.log('\n--- trichotomy: valid v2 bundle on v1-only verifiers (must be UNSUPPORTED_PROFILE) ---');
const triStacks = [
  ['engine(v1-only)', () => jsV1OnlyVerdict(vb.bundle)],
  ['reference', () => refV1(vb.bundle, undefined)],
  ['go-v1', () => goV1(vb.bundle, undefined)],
  ['python', () => pyV1(vb.bundle, undefined)],
];
for (const [name, fn] of triStacks) {
  const got = fn();
  const ok = got === 'UNSUPPORTED_PROFILE';
  if (!ok) failures++;
  console.log(`${ok ? 'OK ' : 'XX '} UNSUPPORTED_PROFILE  ${name}  [got=${got}]`);
}

const total = cases.length + triStacks.length;
rmSync(work, { recursive: true, force: true });

console.log(failures
  ? `\nV2 CROSS-STACK CONFORMANCE FAILED (${failures}/${total} cases had a disagreement)`
  : `\nV2 CROSS-STACK CONFORMANCE PASSED — 2 independent-language oracles agree on all ${cases.length} v2 cases; ${triStacks.length} v1-only verifiers emit UNSUPPORTED_PROFILE on v2 (corpus pin verified)`);
process.exit(failures ? 1 : 0);
