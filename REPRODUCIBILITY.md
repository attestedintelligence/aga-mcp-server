# Reproducibility — regenerating `dist/` and the published tarball

Internal process doc (not shipped — the pack allowlist excludes it). It documents how to
regenerate the published artifact from tagged source and how to verify it.

## Toolchain

- Node `>=20`, npm (the lockfile pins every dependency, incl. `typescript`).
- No other toolchain is needed to build or pack. (Go + Python are only needed to *run*
  `npm run conformance:cross-stack`, not to build `dist/`.)
- The vendored `aga-receipt-spec/` directory (regular files, NOT a git submodule) is **not** needed to build or pack — the shipped `dist/`
  does not import it; it is only needed to run the SEP conformance gate (the reference verifier).

## Regenerate `dist/` from tagged source

```bash
git clone <repo-url> aga-mcp-server   # plain clone: aga-receipt-spec is VENDORED (regular files), not a submodule
cd aga-mcp-server
git checkout <tag>          # e.g. v3.0.1 (every published version is tagged; the source commit is also in the SLSA provenance)
npm ci                      # install exactly the locked deps
npm run build               # = rm -rf dist  &&  tsc   (clean build; no stale outputs)
```

## Produce the publishable tarball

```bash
npm pack                    # writes attested-intelligence-aga-mcp-server-<version>.tgz
# or, for a provenance-attested release, the CI workflow .github/workflows/release.yml
```

## Determinism (and the one unavoidable nondeterminism)

`dist/*.js`, `dist/*.d.ts`, and the source maps are a **deterministic** function of `src/` +
`tsconfig.json` + the pinned `typescript` version — two clean builds from the same source produce
**byte-identical** files.

The single nondeterminism is the **gzip wrapper of the `.tgz`**: `npm pack` stamps the archive
with a build timestamp, so the `.tgz` *bytes* (and therefore its `shasum`) differ run-to-run. The
**extracted contents** are byte-identical. Verify reproducibility by comparing per-file hashes of
the extracted tarball, not the `.tgz` shasum:

```bash
# In each build, extract and hash every packed file:
tar -xzf *.tgz && find package -type f -print0 | sort -z | xargs -0 sha256sum > MANIFEST.txt
# Two clean builds (or a fresh clone) must produce identical MANIFEST.txt.
```

## Demonstrated

A from-clean-clone build was compared against the working-tree build: the per-file SHA-256
manifest of the packed contents is identical (only the `.tgz` gzip timestamp differs). The exact
commands run and the diff result are recorded in the F0 report / commit for item 5.

## Determinism + trust-surface notes (for a skeptic reproducing this)

- **Line endings (cross-platform determinism).** A committed `.gitattributes` forces `eol=lf` and
  `tsconfig.json` pins `"newLine": "lf"`, so `dist/` is byte-identical whether built on Linux, macOS,
  or Windows. (Historically, a default Windows checkout — `core.autocrlf=true` — leaked CRLF from a
  source template literal into `dist/storage/sqlite.js`, breaking the per-file manifest match on
  Windows only. The published artifact was always the LF build; the `.gitattributes` makes every
  fresh checkout reproduce it.)
- **Dependency surface (counted from `package.json` and `package-lock.json`).** 6 *direct* production
  dependencies (`@modelcontextprotocol/sdk`, `@noble/ed25519`, `@noble/hashes`, `@noble/post-quantum`,
  `commander`, `zod`) plus the optional `better-sqlite3`; about 100 packages installed in total, about
  135 with the optional storage driver (the bulk pulled by `@modelcontextprotocol/sdk`, which carries an
  Express-5 HTTP stack used only by the optional HTTP transport). The crypto path is `@noble/hashes`,
  `@noble/ed25519`, `@noble/post-quantum` (the v2 composite profile only) and `node:crypto`. The offline
  reference verifier `aga-receipt-spec/verify/verify-sep.mjs` has **zero** dependencies (Node
  `node:crypto` only): that is the trust-minimized verification path.
- **`npm ci` advisory banner.** A fresh install reports dev-toolchain advisories (vitest/vite/esbuild);
  **none ship** — `npm audit --omit=dev` is clean, and the published package depends only on the 6 direct
  production dependencies above (and the optional `better-sqlite3`). The `canonicalize` package is a dev-dependency (RFC 8785 reference for the JCS conformance
  test) and likewise does not ship.
- **Provenance → commit.** `npm audit signatures` verifies the SLSA provenance; decode the attestation
  to read `subject` (the published tarball digest) and `resolvedDependencies[].digest.gitCommit` (the
  exact source commit) — then rebuild that commit and compare the per-file manifest. The full
  repo → commit → source → build → published-artifact loop closes independently.

