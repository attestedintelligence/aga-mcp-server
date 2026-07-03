/**
 * Pack-manifest guard — POSITIVE ALLOWLIST + IP-RAIL CONTENT SCAN (release hygiene).
 *
 * Two independent gates over the publishable tarball (`npm pack`):
 *
 *  1) PATH allowlist (F0 item 4b): the tarball must contain EXACTLY everything under dist/ plus a
 *     small fixed set of consumer/skeptic-facing files — nothing else. Any unexpected entry (an
 *     internal process doc, src/, test/, a secret, a stray file) FAILS. A hard path-denylist also
 *     rejects forgeable/stale evidence artifacts that could slip in under dist/ (finding C-2: `tsc`
 *     does not delete stale outputs).
 *
 *  2) IP-RAIL content scan (Phase 0c): the CONTENTS of every shippable file AND every emitted dist/
 *     file (the to-be-published TypeScript output, walked directly off disk so a marker can't slip
 *     through even if the pack manifest ever changed) are scanned for the unambiguous "must never
 *     ship" markers — so a future package can't regress and leak IP. The
 *     scanned markers are deliberately the high-confidence ones (no false positives that would wedge
 *     CI): the bare patent number, claim-to-mechanism mapping phrasing, the blocked vendor name, the
 *     private post-quantum / k8s package names, internal codenames, the private PQC scheme name, and
 *     local operator paths/handles. The noisier classes (generic claim legalese,
 *     post-quantum-as-roadmap prose) are intentionally NOT hard-gated here — they are caught by the
 *     periodic IP-rail sweep + human review, because regexing them automatically would false-positive
 *     on legitimate copy. Add a marker below only if it can never legitimately appear in a shipped file.
 *
 * NOTE: the sensitive tokens are ASSEMBLED FROM FRAGMENTS via f()/rx() — never written verbatim — so
 * this guard file is not itself a grep-hit for the very strings it exists to keep off public surfaces.
 * Do not "simplify" these back into literal strings or literal /regex/ — that would re-leak them.
 *
 * Run AFTER `npm run build` (needs dist/ populated). Wired into `check` + prepublishOnly.
 * Self-test the content scan without touching the tree:  node scripts/check-pack.mjs --selftest
 */
import { execSync } from 'node:child_process';
import { readFileSync, statSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

// ---- Gate 1: PATH allowlist -------------------------------------------------
// Top-level files allowed beyond everything under dist/. npm always includes package.json;
// README/LICENSE are conventional; the rest are consumer/skeptic-facing assurance docs.
const ALLOWED_TOPLEVEL = new Set([
  'package.json',
  'README.md',
  'CHANGELOG.md',
  'LICENSE',
  'SECURITY.md',
  'THREAT_BOUNDARY.md',
  'DEPLOYMENT.md',
]);
const ALLOWED_DIR_PREFIX = 'dist/';

// Even under dist/, these must NEVER ship (forgeable/stale evidence code or secrets).
const FORBIDDEN_PATHS = [
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

// ---- Gate 2: IP-RAIL content markers ---------------------------------------
// Fragments joined at runtime so the literals never appear verbatim in this file (see NOTE above).
const f = (...parts) => parts.join('');
const rx = (...parts) => new RegExp(f(...parts), 'i');

// Each marker: { label, rx, dirty (a string the rx MUST match), clean (a string it must NOT) }.
// `clean` exercises the most likely false-positive so --selftest proves we don't over-match.
const CONTENT_FORBIDDEN = [
  {
    label: f('blocked vendor name (', 'And', 'uril', ')'),
    rx: rx('and', 'uril'),
    dirty: f('integration with the ', 'And', 'uril', ' platform'),
    clean: 'an durable record of the audit',
  },
  {
    label: 'bare patent number',
    rx: rx('19\\s*/?\\s*433[,.\\s]?835'),
    dirty: f('U.S. Patent Application No. 19', '/', '433', ',', '835'),
    clean: 'see RFC 6962 section 2.1.1 and port 8335',
  },
  {
    label: f('claim-to-', 'code mapping'),
    rx: rx('claim[- ]?to[- ]?code|claim\\s*\\d+\\s*(?:->|:|maps?\\b)|maps?\\s+to\\s+claim|(?:element|limitation)\\s+of\\s+claim|claim\\s+chart|claim\\s+mapping'),
    dirty: f('Claim 7 maps', ' to a step (claim', '-to-', 'code)'),
    clean: 'we make no claim about third-party endpoints',
  },
  {
    label: f('private PQC package (', 'aga', '-pqc', ')'),
    rx: rx('aga', '-pqc'),
    dirty: f('import x from "', 'aga', '-pqc', '"'),
    clean: 'this is the aga-mcp-server package',
  },
  {
    label: f('private k8s package (', 'aga', '-k8s', ')'),
    rx: rx('aga', '-k8s'),
    dirty: f('deploy the ', 'aga', '-k8s', ' controller'),
    clean: 'the aga gateway runs on any k8s cluster',
  },
  {
    label: f('retired integration package (', 'aga', '-lattice', ')'),
    rx: rx('aga', '-lattice'),
    dirty: f('bridge into ', 'aga', '-lattice', ' adapters'),
    clean: 'a lattice of aga verifier nodes',
  },
  {
    label: f('internal codename (', 'Myth', 'os', ')'),
    rx: rx('myth', 'os'),
    dirty: f('the ', 'Myth', 'os', ' initiative'),
    clean: 'dispel the myth of secure-by-default OS images',
  },
  {
    label: f('internal codename (', 'Glass', 'wing', ')'),
    rx: rx('glass', 'wing'),
    dirty: f('project ', 'Glass', 'wing', ' milestone'),
    clean: 'a glass pane beside the wing panel',
  },
  {
    label: f('private PQC scheme name (', 'FAL', 'CON', ')'),
    rx: rx('fal', 'con'),
    dirty: f('sign with ', 'FAL', 'CON', '-512'),
    clean: 'fallback config online',
  },
  {
    label: f('local windows user path (C:', '\\', 'Users', ')'),
    rx: rx('C:', '[\\\\/]+', 'Users'),
    dirty: f('logs at C:', '\\', 'Users', '\\', 'jack'),
    clean: 'C: Users should mount the drive first',
  },
  {
    label: f('operator handle (', 'neu', 'ro', ')'),   // also covers the Neu·roCrypt codename
    rx: rx('neu', 'ro'),
    dirty: f('built on ', 'neu', 'ro', "'s machine"),
    clean: 'neutral routing over the proxy',
  },
  {
    label: f('internal governance codename (', 'CA', 'ISI', ')'),
    rx: rx('ca', 'isi'),
    dirty: f('graceful degradation (', 'CA', 'ISI', ' §4a)'),
    clean: 'the caisson wall holds under load',
  },
];

// ---- shared scanners --------------------------------------------------------
// Scan one file's text; return [{ label, snippet }] for every marker that hits (≤1 per marker).
function scanText(text) {
  const hits = [];
  const lines = text.split(/\r?\n/);
  for (const m of CONTENT_FORBIDDEN) {
    for (let i = 0; i < lines.length; i++) {
      if (m.rx.test(lines[i])) {
        hits.push({ label: m.label, snippet: lines[i].trim().slice(0, 160) });
        break;                                                             // one hit per marker is enough
      }
    }
  }
  return hits;
}

// Recursively list every file under a directory (forward-slash paths for cross-platform dedupe).
function walk(dir) {
  const out = [];
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) out.push(...walk(p));
    else out.push(p.replace(/\\/g, '/'));
  }
  return out;
}

// ---- selftest mode ----------------------------------------------------------
if (process.argv.includes('--selftest')) {
  let pass = true;
  // (a) per-marker: each planted "dirty" sample must be caught, each benign "clean" sample ignored.
  for (const m of CONTENT_FORBIDDEN) {
    const dirtyOk = m.rx.test(m.dirty);
    const cleanOk = !m.rx.test(m.clean);
    console.log(`  [${dirtyOk && cleanOk ? 'PASS' : 'FAIL'}] ${m.label}: catches dirty=${dirtyOk}, ignores clean=${cleanOk}`);
    if (!dirtyOk || !cleanOk) pass = false;
  }
  // (b) end-to-end: run the whole file scanner over a planted-dirty blob (must fail) and a
  //     realistic benign blob (must pass) — proves the dist scan wiring rejects a re-leak.
  const dirtyBlob = [
    'export type EventType =',
    f("  | 'DEGRADATION'  // ", 'CA', 'ISI', ' §4a: graceful degradation event'),
    f('// bridge into ', 'aga', '-lattice'),
  ].join('\n');
  const benignBlob = [
    'export type EventType =',
    "  | 'DEGRADATION'  // graceful-degradation event",
    '// NCCoE §6: optional behavioral baseline reference',
  ].join('\n');
  const dirtyHits = scanText(dirtyBlob);
  const benignHits = scanText(benignBlob);
  const dirtyCaught = dirtyHits.length > 0;
  const benignClean = benignHits.length === 0;
  console.log(`  [${dirtyCaught ? 'PASS' : 'FAIL'}] end-to-end scan catches a planted dirty blob (${dirtyHits.map((h) => h.label).join('; ') || 'NONE'})`);
  console.log(`  [${benignClean ? 'PASS' : 'FAIL'}] end-to-end scan passes a benign blob${benignClean ? '' : ` (unexpected: ${benignHits.map((h) => h.label).join('; ')})`}`);
  if (!dirtyCaught || !benignClean) pass = false;

  if (pass) { console.log('check-pack --selftest OK: every IP-rail marker catches its planted sample and ignores its benign sample; end-to-end dirty/benign scan behaves.'); process.exit(0); }
  console.error('check-pack --selftest FAILED: a marker regex is mis-tuned or the end-to-end scan misbehaved.'); process.exit(1);
}

// ---- run: build the manifest -----------------------------------------------
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

const files = (manifest[0]?.files ?? []).map((f2) => String(f2.path).replace(/\\/g, '/'));
if (files.length === 0) { console.error('check-pack: tarball reported zero files — build likely missing.'); process.exit(1); }

// ---- Gate 1 checks ----------------------------------------------------------
const isAllowed = (p) => p.startsWith(ALLOWED_DIR_PREFIX) || ALLOWED_TOPLEVEL.has(p);
const unexpected = files.filter((p) => !isAllowed(p));                 // positive-allowlist violations
const forbiddenPath = files.filter((p) => FORBIDDEN_PATHS.some((r) => r.test(p)));
const missing = REQUIRED.filter((r) => !files.includes(r));

// ---- Gate 2 checks: scan the CONTENT of every shippable file + emitted dist/ -
// Union of the pack manifest and a direct walk of dist/ (deduped) so the to-be-published
// TypeScript output is scanned even if the pack manifest ever drifts from what's on disk.
const distFiles = existsSync('dist') ? walk('dist') : [];
const scanTargets = Array.from(new Set([...files, ...distFiles]));
const contentHits = [];   // { file, label, snippet }
for (const p of scanTargets) {
  let text;
  try {
    if (statSync(p).size > 8 * 1024 * 1024) continue;                  // skip oversized blobs
    const buf = readFileSync(p);
    if (buf.includes(0)) continue;                                     // skip binary (null byte)
    text = buf.toString('utf8');
  } catch { continue; }                                                // unreadable / not-on-disk → skip
  for (const h of scanText(text)) {
    contentHits.push({ file: p, label: h.label, snippet: h.snippet });
  }
}

// ---- verdict ----------------------------------------------------------------
let ok = true;
if (unexpected.length) {
  ok = false;
  console.error('UNEXPECTED files in tarball (not on the allowlist — internal docs / src / tests / strays):');
  for (const u of unexpected) console.error(`  - ${u}`);
}
if (forbiddenPath.length) {
  ok = false;
  console.error('FORBIDDEN files in tarball (forgeable/stale/secret artifacts):');
  for (const fp of forbiddenPath) console.error(`  - ${fp}`);
}
if (missing.length) {
  ok = false;
  console.error('MISSING required files in tarball:');
  for (const m of missing) console.error(`  - ${m}`);
}
if (contentHits.length) {
  ok = false;
  console.error('IP-RAIL CONTENT VIOLATION - a "must never ship" marker appears in a shippable file:');
  for (const h of contentHits) console.error(`  - [${h.label}] ${h.file}: ${h.snippet}`);
}

if (ok) {
  const docs = files.filter((p) => !p.startsWith(ALLOWED_DIR_PREFIX));
  console.log(`check-pack OK: ${files.length} files — dist/ + exactly [${docs.join(', ')}]; no forbidden artifacts; all ${REQUIRED.length} required present; IP-rail content scan clean (${CONTENT_FORBIDDEN.length} markers × ${scanTargets.length} files incl. emitted dist/).`);
  process.exit(0);
}
console.error('\ncheck-pack FAILED — do not publish this tarball.');
process.exit(1);
