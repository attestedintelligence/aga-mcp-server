# Reproducibility — regenerating `dist/` and the published tarball

Internal process doc (not shipped — the pack allowlist excludes it). It documents how to
regenerate the published artifact from tagged source and how to verify it.

## Toolchain

- Node `>=20`, npm (the lockfile pins every dependency, incl. `typescript`).
- No other toolchain is needed to build or pack. (Go + Python are only needed to *run*
  `npm run conformance:cross-stack`, not to build `dist/`.)
- The `aga-receipt-spec` submodule is **not** needed to build or pack — the shipped `dist/`
  does not import it; it is only needed to run the SEP conformance gate (the reference verifier).

## Regenerate `dist/` from tagged source

```bash
git clone --recurse-submodules <repo-url> aga-mcp-server
cd aga-mcp-server
git checkout <tag>          # e.g. v3.0.0-rc.0
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
