# Changelog

All notable changes to `@attested-intelligence/aga-verify` are recorded here, newest first. This package follows [Semantic Versioning](https://semver.org). Any change that can flip a verification verdict is called out explicitly, first.

## 2.2.0 — 2026-07-31

- **Verification now fail-closed rejects integers outside ±2^53 in receipt/checkpoint numeric fields — bundles previously VERIFIED may now FAIL; this closes the cross-language verdict split.** JavaScript loses integer precision beyond `Number.MAX_SAFE_INTEGER`, so a bundle carrying e.g. `leaf_count > 2^53` could VERIFY here on bytes the Go and Python verifiers read as a different number. Every stack now rejects the same out-of-range bundles at the same floor.
- CLI entry guard: the CLI now runs only when this module itself is the executed entry script — resolved `process.argv[1]` must equal the module's own file path (realpath-resolved, so npm `.bin` symlinks still match; case-folded on Windows). The previous check ran the CLI whenever the entry script's path merely contained the substring `verify`, so importing the library from such a path hijacked stdout and called `process.exit()`. Regression-tested in both directions.
- Internal: `node:` builtin imports are now static, removing the module's only top-level awaits.

## 2.1.1 and earlier

See the tagged releases and `git log` for this directory (`independent-verifier/`) in the repository.
