# Changelog

All notable changes to `@attested-intelligence/aga-mcp-server` are recorded here, newest first. This package follows [Semantic Versioning](https://semver.org). The signed receipt and evidence-bundle wire format is the canonical SEP profile; any format-affecting change is called out explicitly.

## 3.4.0 — 2026-07-31

- **Verification now fail-closed rejects integers outside ±2^53 in receipt/checkpoint numeric fields — bundles previously VERIFIED may now FAIL; this closes the cross-language verdict split.** JavaScript loses integer precision beyond `Number.MAX_SAFE_INTEGER`, so a bundle carrying e.g. `leaf_count > 2^53` could VERIFY in the JS stack on bytes the Go and Python verifiers read as a different number. Every stack now rejects the same out-of-range bundles at the same floor.
- Security: cleared GHSA-frvp-7c67-39w9 (`@hono/node-server` < 2.0.5, Windows encoded-backslash path traversal in `serve-static`, moderate): `@modelcontextprotocol/sdk` bumped to `^1.30.0` (resolves `@hono/node-server` 2.0.12) and an `overrides` pin holds `@hono/node-server` at `>= 2.0.5`. Production dependencies (`npm audit --omit=dev`) are clean at all severities; `body-parser` (2.3.0) and `fast-uri` (3.1.4) transitives refreshed in the same pass.
- Verifier CLI entry guard (developed in this repo, shipping alongside in `@attested-intelligence/aga-verify` 2.2.0): the CLI now runs only when the verifier module itself is the executed entry script (resolved-path identity against `import.meta.url`), replacing a substring check that ran the CLI — hijacking stdout and calling `process.exit()` — whenever the entry script's path merely contained `verify`.
- Regression coverage for the safe-integer floor above (`tests/sep/safe-integer-floor.test.ts`): a consistently re-signed bundle carrying a numeric field isolates the floor from the signature and structural checks, so removing the floor flips the verdict and the suite goes red. The cross-stack corpus also gains the ±2^53 and non-finite raw-literal cases (all six verifiers agree FAILED).
- Proxy CLI hardening: an unrecognized `--profile` value now exits 2 listing the valid names (`permissive`, `standard`, `restrictive`) instead of silently falling back to `permissive`; starting with an `audit_only` policy prints a loud multi-line stderr banner stating that every call is permitted and recorded and no call is denied in that mode. The default profile is unchanged. `aga-proxy run` (a documented foreground alias of `start`) is fixed — it exited 1 on every invocation from 3.0.0 through 3.3.3 because of a stray-argument delegation bug, and now shares the `start` implementation directly; `policy switch` gained the same own-property profile guard as `start`.
- MCP registry: `package.json` gains `"mcpName": "io.github.attestedintelligence/aga-mcp-server"` for npm package-ownership validation by the official registry.

## 3.3.3 — 2026-07-03

- Internal source-comment cleanup only: **no runtime, verifier, or evidence-bundle change** (behavior is byte-identical to 3.3.2).
- CI: added a production-only dependency-CVE audit gate (`npm audit --omit=dev` plus an OSV scan) to both the build and pre-publish flows; dev-only advisories never ship and are excluded from the gate.
- CI: tightened workflow token permissions to least-privilege (`contents: read`).
- Release hygiene: the pack guard now scans the emitted `dist/` content directly, not just the pack manifest, so a stray marker cannot slip through even if the manifest drifts.
- Docs: README documentation links normalized to absolute URLs, and the Live Gateway URL corrected to `aga-mcp-gateway.attested-intelligence.workers.dev`.

## 3.3.2 — 2026-07-02

- Added out-of-process evidence export from a running proxy: `aga-proxy start` opens a loopback-only (`127.0.0.1`) read-only control channel, and a separate `aga-proxy export` invocation fetches the same signed bundle the live proxy would emit. The in-memory ledger still does not survive a proxy restart; the exported signed bundle remains the durable record.
- Hardened proxy export: a gateway-identity header, an evidence-bundle shape guard, and an honest banner and docs pass.
- CI: the verifier's zero-import guard is now actually enforced (previously a silent no-op).

## 3.3.1 — 2026-07-01

- Extended the release pack-guard content scan to ten high-confidence "must never ship" markers.
- Wired npm build-provenance and attestation verification into the release workflow (checkable by consumers with `npm audit signatures`).
- Brought the standalone `aga-verify` verifier into the same provenance flow.

## 3.3.0 — 2026-06-29

- Exposed the offline verifier as a library API through the `./verify` and `./sep` subpath exports (previously reachable only via the CLI).
- Honest-scoped the package description and keywords (removed a turnkey-enforcement overclaim).

## Earlier releases

- **3.2.0** introduced the algorithm-agile verifier and the v2 `ML-DSA-65+Ed25519-SHA256-JCS` composite profile (a NIST FIPS-204 ML-DSA-65 plus RFC-8032 Ed25519 signature, both of which must verify), selected per-bundle with a `VERIFIED / FAILED / UNSUPPORTED_PROFILE` trichotomy. The v1 `Ed25519-SHA256-JCS` profile remains the default the gateway emits.
- For the full pre-3.3.0 history, see the tagged releases and `git log` in the repository.
