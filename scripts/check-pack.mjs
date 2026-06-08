/**
 * Pack-manifest guard — POSITIVE ALLOWLIST (release hygiene; F0 item 4b).
 *
 * Asserts the publishable tarball (`npm pack`) contains EXACTLY the enumerated set and nothing
 * else: everything under dist/, plus a small fixed list of consumer/skeptic-facing files. ANY
 * unexpected entry (an internal process doc, src/, test/, a secret, a stray file) FAILS the guard.
 * A hard denylist additionally rejects forgeable/stale evidence artifacts that could otherwise slip
 * in under dist/ (finding C-2: `tsc` does not delete stale outputs).
 *
 * Run AFTER `npm run build` (needs dist/ populated). Wired into `check` + prepublishOnly.
 */
import { execSync } from 'node:child_process';

// Top-level files allowed beyond everything under dist/. npm always includes package.json;
// README/LICENSE are conventional; the rest are consumer/skeptic-facing assurance docs.
const ALLOWED_TOPLEVEL = new Set([
  'package.json',
  'README.md',
  'LICENSE',
  'SECURITY.md',
  'THREAT_BOUNDARY.md',
  'DEPLOYMENT.md',
]);
const ALLOWED_DIR_PREFIX = 'dist/';

// Even under dist/, these must NEVER ship (forgeable/stale evidence code or secrets).
const FORBIDDEN = [
  /^dist\/core\/bundle\./,        // forgeable verifyBundleOffline (deleted P4)
  /^dist\/core\/checkpoint\./,    // legacy unsigned checkpoint (deleted P4)
  /^dist\/proxy\/verify\./,       // forgeable proxy verifier (deleted C-1)
  /^dist\/crypto\/merkle\./,      // legacy hex-concat Merkle (deleted P4)
  /(^|\/)_realkey/,               // stray test signing seed
  /\.key$/,                       // key material
];

// Must be present (entry points + the key assurance doc).
const REQUIRED = [
  'dist/index.js',
  'dist/proxy/index.js',
  'dist/sep/verify.js',
  'README.md',
  'LICENSE',
  'THREAT_BOUNDARY.md',
];

let raw;
try {
  raw = execSync('npm pack --dry-run --json', { encoding: 'utf8' });
} catch (e) {
  console.error('check-pack: `npm pack --dry-run --json` failed — did you run `npm run build` first?');
  console.error(String(e));
  process.exit(1);
}
let manifest;
try { manifest = JSON.parse(raw); }
catch { console.error('check-pack: could not parse `npm pack --json` output.'); process.exit(1); }

const files = (manifest[0]?.files ?? []).map((f) => String(f.path).replace(/\\/g, '/'));
if (files.length === 0) { console.error('check-pack: tarball reported zero files — build likely missing.'); process.exit(1); }

const isAllowed = (p) => p.startsWith(ALLOWED_DIR_PREFIX) || ALLOWED_TOPLEVEL.has(p);
const unexpected = files.filter((p) => !isAllowed(p));                 // positive-allowlist violations
const forbidden = files.filter((p) => FORBIDDEN.some((rx) => rx.test(p)));
const missing = REQUIRED.filter((r) => !files.includes(r));

let ok = true;
if (unexpected.length) {
  ok = false;
  console.error('UNEXPECTED files in tarball (not on the allowlist — internal docs / src / tests / strays):');
  for (const u of unexpected) console.error(`  - ${u}`);
}
if (forbidden.length) {
  ok = false;
  console.error('FORBIDDEN files in tarball (forgeable/stale/secret artifacts):');
  for (const f of forbidden) console.error(`  - ${f}`);
}
if (missing.length) {
  ok = false;
  console.error('MISSING required files in tarball:');
  for (const m of missing) console.error(`  - ${m}`);
}

if (ok) {
  const docs = files.filter((p) => !p.startsWith(ALLOWED_DIR_PREFIX));
  console.log(`check-pack OK: ${files.length} files — dist/ + exactly [${docs.join(', ')}]; no forbidden artifacts; all ${REQUIRED.length} required present.`);
  process.exit(0);
}
console.error('\ncheck-pack FAILED — do not publish this tarball.');
process.exit(1);
