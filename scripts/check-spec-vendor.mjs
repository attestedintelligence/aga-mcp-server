#!/usr/bin/env node
/**
 * CA-05 vendor-freeze guard — the vendored `aga-receipt-spec/` tree is release-frozen.
 *
 * The spec's authority repo is private; this public CI cannot see it. What CI CAN prove is that
 * nobody hand-edited the vendored copy: every tracked file under aga-receipt-spec/ must match the
 * sha256 pinned in aga-receipt-spec.MANIFEST.json, with no extra or missing files. Any legitimate
 * update must go through scripts/sync-spec-vendor.mjs (local, where the authority repo exists),
 * which rewrites the manifest in the same commit — a lone edit to either side fails here.
 *
 * Hashes are computed over LF-normalized text for text files (the two repos disagree on line
 * endings historically; the guard freezes CONTENT, and .gitattributes owns endings).
 *
 * Usage: node scripts/check-spec-vendor.mjs   (exit 0 = frozen state intact)
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = path.join(root, "aga-receipt-spec.MANIFEST.json");

const BINARY_EXT = new Set([".png", ".jpg", ".gif", ".ico", ".woff", ".woff2"]);

export function hashFile(p) {
  const buf = readFileSync(p);
  if (BINARY_EXT.has(path.extname(p).toLowerCase())) {
    return createHash("sha256").update(buf).digest("hex");
  }
  const lf = buf.toString("utf8").replaceAll("\r\n", "\n");
  return createHash("sha256").update(lf, "utf8").digest("hex");
}

export function trackedVendorFiles() {
  return execFileSync("git", ["-C", root, "ls-files", "aga-receipt-spec"], { encoding: "utf8" })
    .split("\n").map((s) => s.trim()).filter(Boolean);
}

function main() {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const pinned = manifest.files;
  const actual = trackedVendorFiles();
  const problems = [];

  for (const f of actual) {
    const h = hashFile(path.join(root, f));
    if (!(f in pinned)) problems.push(`UNTRACKED-BY-MANIFEST: ${f} (${h.slice(0, 12)}…)`);
    else if (pinned[f] !== h) problems.push(`DRIFT: ${f} (manifest ${pinned[f].slice(0, 12)}… != actual ${h.slice(0, 12)}…)`);
  }
  for (const f of Object.keys(pinned)) {
    if (!actual.includes(f)) problems.push(`MISSING: ${f} (pinned but not tracked)`);
  }

  if (problems.length) {
    console.error("SPEC-VENDOR FREEZE VIOLATION — aga-receipt-spec/ no longer matches its manifest:");
    for (const p of problems) console.error("  - " + p);
    console.error("\nIf this change is intentional, run scripts/sync-spec-vendor.mjs locally (it");
    console.error("re-vendors from the authority repo and rewrites the manifest) and commit both.");
    process.exit(1);
  }
  console.log(`spec-vendor freeze OK: ${actual.length} files match aga-receipt-spec.MANIFEST.json (synced from authority ${manifest.authority_commit ?? "UNRECORDED"} at ${manifest.synced_at ?? "?"}).`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
