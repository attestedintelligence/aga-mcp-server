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
 *  2) IP-RAIL content scan (Phase 0c): the CONTENTS of every shippable file are scanned for the
 *     unambiguous "must never ship" markers — so a future package can't regress and leak IP. The
 *     scanned markers are deliberately the high-confidence ones (no false positives that would wedge
 *     CI): the bare patent number, any patent-claim-to-code mapping phrasing, an `Anduril` reference,
 *     and the private `aga-pqc` package name. The noisier classes (generic patent-claim legalese,
 *     post-quantum-as-roadmap prose) are intentionally NOT hard-gated here — they are caught by the
 *     periodic IP-rail sweep + human review, because regexing them automatically would false-positive
 *     on legitimate copy. Add a marker below only if it can never legitimately appear in a shipped
 *     file.
 *
 * Run AFTER `npm run build` (needs dist/ populated). Wired into `check` + prepublishOnly.
 * Self-test the content scan without touching the tree:  node scripts/check-pack.mjs --selftest
 */
import { execSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';

// ---- Gate 1: PATH allowlist -------------------------------------------------
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
// Each marker: { label, rx, dirty (a string the rx MUST match), clean (a string it must NOT) }.
// `clean` exercises the most likely false-positive so --selftest proves we don't over-match.
const CONTENT_FORBIDDEN = [
  {
    label: 'Anduril reference',
    rx: /anduril/i,
    dirty: 'integration with the Anduril Lattice platform',
    clean: 'an durable record of the audit',
  },
  {
    label: 'bare patent number',
    rx: /19\s*\/?\s*433[,.\s]?835|\b433,835\b/i,
    dirty: 'U.S. Patent Application No. 19/433,835',
    clean: 'see RFC 6962 section 2.1.1 and port 8335',
  },
  {
    label: 'patent-claim-to-code mapping',
    rx: /claim[- ]?to[- ]?code|claim\s*\d+\s*(?:→|->|:|maps?\b)|maps?\s+to\s+claim|(?:element|limitation)\s+of\s+claim|claim\s+chart|claim\s+mapping/i,
    dirty: 'Claim 1 maps to src/sep/verify.ts (claim-to-code mapping)',
    clean: 'we make no claim about third-party endpoints',
  },
  {
    label: 'aga-pqc private package reference',
    rx: /aga-pqc/i,
    dirty: 'import { sign } from "aga-pqc"',
    clean: 'this is the aga-mcp-server package',
  },
];

// ---- selftest mode ----------------------------------------------------------
if (process.argv.includes('--selftest')) {
  let pass = true;
  for (const m of CONTENT_FORBIDDEN) {
    const dirtyOk = m.rx.test(m.dirty);
    const cleanOk = !m.rx.test(m.clean);
    console.log(`  [${dirtyOk && cleanOk ? 'PASS' : 'FAIL'}] ${m.label}: catches dirty=${dirtyOk}, ignores clean=${cleanOk}`);
    if (!dirtyOk || !cleanOk) pass = false;
  }
  if (pass) { console.log('check-pack --selftest OK: every IP-rail marker catches its planted sample and ignores its benign sample.'); process.exit(0); }
  console.error('check-pack --selftest FAILED: a marker regex is mis-tuned.'); process.exit(1);
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

const files = (manifest[0]?.files ?? []).map((f) => String(f.path).replace(/\\/g, '/'));
if (files.length === 0) { console.error('check-pack: tarball reported zero files — build likely missing.'); process.exit(1); }

// ---- Gate 1 checks ----------------------------------------------------------
const isAllowed = (p) => p.startsWith(ALLOWED_DIR_PREFIX) || ALLOWED_TOPLEVEL.has(p);
const unexpected = files.filter((p) => !isAllowed(p));                 // positive-allowlist violations
const forbiddenPath = files.filter((p) => FORBIDDEN_PATHS.some((rx) => rx.test(p)));
const missing = REQUIRED.filter((r) => !files.includes(r));

// ---- Gate 2 checks: scan the CONTENT of every shippable file ----------------
const contentHits = [];   // { file, label, snippet }
for (const p of files) {
  let text;
  try {
    if (statSync(p).size > 8 * 1024 * 1024) continue;                  // skip oversized blobs
    const buf = readFileSync(p);
    if (buf.includes(0)) continue;                                     // skip binary (null byte)
    text = buf.toString('utf8');
  } catch { continue; }                                                // unreadable / not-on-disk → skip
  const lines = text.split(/\r?\n/);
  for (const m of CONTENT_FORBIDDEN) {
    for (let i = 0; i < lines.length; i++) {
      if (m.rx.test(lines[i])) {
        contentHits.push({ file: p, label: m.label, snippet: lines[i].trim().slice(0, 160) });
        break;                                                         // one hit per (file, marker) is enough
      }
    }
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
  for (const f of forbiddenPath) console.error(`  - ${f}`);
}
if (missing.length) {
  ok = false;
  console.error('MISSING required files in tarball:');
  for (const m of missing) console.error(`  - ${m}`);
}
if (contentHits.length) {
  ok = false;
  console.error('IP-RAIL CONTENT VIOLATION — a "must never ship" marker appears in a shippable file:');
  for (const h of contentHits) console.error(`  - [${h.label}] ${h.file}: ${h.snippet}`);
}

if (ok) {
  const docs = files.filter((p) => !p.startsWith(ALLOWED_DIR_PREFIX));
  console.log(`check-pack OK: ${files.length} files — dist/ + exactly [${docs.join(', ')}]; no forbidden artifacts; all ${REQUIRED.length} required present; IP-rail content scan clean (${CONTENT_FORBIDDEN.length} markers × ${files.length} files).`);
  process.exit(0);
}
console.error('\ncheck-pack FAILED — do not publish this tarball.');
process.exit(1);
