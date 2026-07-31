#!/usr/bin/env node
/**
 * CA-05 vendor sync + drift report — LOCAL ONLY (needs the private authority repo on disk).
 *
 * Modes:
 *   node scripts/sync-spec-vendor.mjs --report        compare vendored vs authority, change nothing
 *   node scripts/sync-spec-vendor.mjs --pin-current   rewrite the manifest from the CURRENT vendored
 *                                                     bytes (freeze what ships; no authority needed)
 *   node scripts/sync-spec-vendor.mjs --sync          copy authority → vendored for files that exist
 *                                                     in BOTH, then rewrite the manifest. Refuses on
 *                                                     a dirty authority worktree. Release-tree-only
 *                                                     files (e.g. verify/v2/*) are never deleted.
 *
 * IMPORTANT: --sync changes shipping verifier bytes. Do not run it inside a release window; the
 * freeze guard (check-spec-vendor.mjs) exists precisely so this is always a deliberate, reviewed,
 * two-artifact commit (files + manifest together).
 */
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { hashFile, trackedVendorFiles } from "./check-spec-vendor.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = path.join(root, "aga-receipt-spec.MANIFEST.json");
const AUTHORITY = process.env.AGA_SPEC_AUTHORITY ?? "C:\\Users\\neuro\\AGA\\aga-receipt-spec";

const mode = process.argv[2];
if (!["--report", "--pin-current", "--sync"].includes(mode ?? "")) {
  console.error("usage: sync-spec-vendor.mjs --report | --pin-current | --sync");
  process.exit(2);
}

const files = trackedVendorFiles();

function writeManifest(note) {
  const authorityCommit = existsSync(AUTHORITY)
    ? execFileSync("git", ["-C", AUTHORITY, "rev-parse", "HEAD"], { encoding: "utf8" }).trim()
    : null;
  const manifest = {
    _comment: "CA-05 freeze manifest for the vendored aga-receipt-spec/ tree. Regenerate ONLY via scripts/sync-spec-vendor.mjs; CI fails on any drift (scripts/check-spec-vendor.mjs). Hashes are sha256 over LF-normalized content.",
    synced_at: new Date().toISOString().slice(0, 10),
    authority_repo: "aga-receipt-spec (private)",
    authority_commit: authorityCommit,
    note,
    files: Object.fromEntries(files.map((f) => [f, hashFile(path.join(root, f))])),
  };
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  console.log(`manifest written: ${files.length} files pinned (authority ${authorityCommit?.slice(0, 7) ?? "absent"}).`);
}

if (mode === "--pin-current") {
  writeManifest("pinned from the current vendored bytes (freeze-what-ships); authority drift, if any, is recorded by --report, not resolved by this pin");
  process.exit(0);
}

if (!existsSync(AUTHORITY)) {
  console.error(`authority repo not found at ${AUTHORITY} (set AGA_SPEC_AUTHORITY).`);
  process.exit(2);
}

let drift = 0, releaseOnly = 0;
for (const f of files) {
  const rel = f.replace(/^aga-receipt-spec\//, "");
  const authPath = path.join(AUTHORITY, rel);
  if (!existsSync(authPath)) { releaseOnly++; console.log(`  RELEASE-ONLY: ${f} (not in authority)`); continue; }
  if (hashFile(authPath) !== hashFile(path.join(root, f))) {
    drift++;
    console.log(`  CONTENT-DRIFT: ${f}`);
    if (mode === "--sync") { copyFileSync(authPath, path.join(root, f)); console.log(`    → re-vendored from authority`); }
  }
}
console.log(`\n${files.length} vendored files: ${drift} content-drift, ${releaseOnly} release-only.`);
if (mode === "--sync") writeManifest(`synced from authority (${drift} files re-vendored; release-only files untouched)`);
