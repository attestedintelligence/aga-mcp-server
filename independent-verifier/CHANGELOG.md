# Changelog

All notable changes to `@attested-intelligence/aga-verify` are recorded here, newest first. This package follows [Semantic Versioning](https://semver.org). Any change that can flip a verification verdict is called out explicitly, first.

## Unreleased — malformed-pin guard (2026-08-28)

- **A malformed `--pubkey` is now a hard usage error (exit 2), never a silent downgrade.** A key that
  is not exactly 64 lowercase hex previously fell through to `pinned = false`, skipping the
  `gateway_key_match` step entirely, so a truncated or mistyped key printed
  `VERIFIED (integrity only — no --pubkey given)` and exited 0 — telling an operator who *did* pass a
  key that they had not. The reference verifier (`aga-receipt-spec/verify/verify-sep.mjs`) has always
  refused this; the guard had never propagated here, the file that becomes this package.
  `REVIEWER_GUIDE.md`'s claim that "a malformed `--pubkey` is a hard error, not a silent downgrade"
  was false for the shipped tool and is now true. Regression-tested in both directions.

## 2.2.0 — UNRELEASED (work completed 2026-07-31; npm `latest` is still 2.1.1)

> **Not published.** This header previously read as a dated, shipped release. Consumers running
> `npx @attested-intelligence/aga-verify` still get 2.1.1, which contains none of the below.

- **Verification now fail-closed rejects integers outside ±2^53 in receipt/checkpoint numeric fields — bundles previously VERIFIED may now FAIL; this closes the cross-language verdict split.** JavaScript loses integer precision beyond `Number.MAX_SAFE_INTEGER`, so a bundle carrying e.g. `leaf_count > 2^53` could VERIFY here on bytes the Go and Python verifiers read as a different number. Every stack now rejects the same out-of-range bundles at the same floor.
- CLI entry guard: the CLI now runs only when this module itself is the executed entry script — resolved `process.argv[1]` must equal the module's own file path (realpath-resolved, so npm `.bin` symlinks still match; case-folded on Windows). The previous check ran the CLI whenever the entry script's path merely contained the substring `verify`, so importing the library from such a path hijacked stdout and called `process.exit()`. Regression-tested in both directions.
- Internal: `node:` builtin imports are now static, removing the module's only top-level awaits.

## 2.1.1 and earlier

See the tagged releases and `git log` for this directory (`independent-verifier/`) in the repository.
