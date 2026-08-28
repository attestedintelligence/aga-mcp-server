# Changelog

All notable changes to `@attested-intelligence/aga-mcp-server` are recorded here, newest first. This package follows [Semantic Versioning](https://semver.org). The signed receipt and evidence-bundle wire format is the canonical SEP profile; any format-affecting change is called out explicitly.

## Unreleased — honesty + safety fixes (2026-08-28)

- **Security: two HIGH-severity production advisories cleared, both newly in range.** `npm audit
  --omit=dev --audit-level=high` was **failing** on this branch:
  - `fast-uri` — GHSA-v2hh-gcrm-f6hx (host confusion via backslash authority delimiter, CVSS 7.5).
    **The 3.4.0 entry below is not wrong about what it did** — it refreshed `fast-uri` to 3.1.4, which
    was clean at the time. The advisory range has since **widened to `<3.1.5`**, so the pinned version
    became vulnerable without anything in this repo changing. Now overridden to `^3.1.5` (resolves 3.1.6).
  - `ip-address` — GHSA-mwp4-54f8-5fhr (Address4 decodes leading-zero octets as decimal while
    resolvers decode them as octal; SSRF / trust-boundary bypass). Overridden to `>=10.3.1`
    (resolves 10.5.0). Reached via `@modelcontextprotocol/sdk` → `express-rate-limit`.
  - `hono` — the existing `>=4.12.25` override no longer covered a moderate CORS ReDoS whose range
    extends to `<4.12.34`; bumped accordingly (resolves 4.13.5).

  Production dependencies are once again **clean at all severities** (`npm audit --omit=dev`:
  found 0 vulnerabilities), which is what the 3.4.0 entry claims — that claim had silently gone false.
  **This is a standing hazard worth naming: a dependency claim is only true as of the day it was
  measured.** Advisory ranges widen over unchanged code, so a "clean" statement in a changelog decays
  on its own. Re-run the audit immediately before publishing, not once at RC time.
  Verified after the change: suite 404/404, `npm run build` clean, cross-stack 61/61.

> Version number pending a founder decision: `3.4.0` is currently claimed by **two different trees**
> (this release line and the quarantined governance branch) that are ~93 commits apart. Publishing
> this line as 3.4.0 permanently burns that number for the other. These entries will move under
> whatever number is chosen.

- **TTL expiry no longer signs an enforcement that never happened.** `measure_integrity` sealed
  `enforcement_action: "TERMINATE"` into a signed receipt on TTL expiry and described the branch as
  "fail-closed termination". Nothing terminates: the portal degrades to `SAFE_STATE` and keeps
  accepting measurements, and `portal.enforce()` is never called on that path — nor *can* it be, since
  it throws unless the state is `DRIFT_DETECTED`. Post-expiry calls kept succeeding and kept minting
  fresh receipts, each asserting a termination that did not occur. The receipt now records what
  actually happened. The sibling revocation branch was already honest and is unchanged.
  **Not changed here:** whether TTL expiry *should* hard-terminate and force re-attestation. That is an
  open product decision; until it is ruled, the record must not claim a behavior the code lacks.
- **`aga-proxy export --output` no longer destroys an existing file.** Pointing `--output` at an
  existing path silently truncated it and exited 0 reporting success — an ordinary path, no symlink,
  no attacker, on the very artifact a verifier consumes. Export is now exclusive-create by default;
  replacing a file requires an explicit `--force`.
- **A malformed `--pubkey` is now a hard error (exit 2) instead of a silent downgrade.** A truncated or
  mistyped key previously produced `VERIFIED (integrity only)` at exit 0, so an operator who intended
  to pin provenance got a green result. The reference verifier has always guarded this; the guard had
  never propagated to the CLI that becomes the published package.
- **The cross-stack release gate now exercises the pinned path.** The corpus had no wrong-pin case, and
  the harness collapses each stack to VERIFIED/FAILED without reading `issuerVerified`, so a verifier
  that silently discarded the pin still read VERIFIED and the gate stayed green. A valid-but-wrong pin
  control was added; all six verifiers agree FAILED across 61 cases.
  Recorded, not fixed: on a 64-hex pin that is **not a valid curve point**, the stacks split 1-vs-5 on
  whether that means "no pin" or "a pin that cannot match". Needs a spec ruling on malformed-pin
  semantics before "six verifiers agree" is stated without qualification.

## 3.4.0 — UNRELEASED (work completed 2026-07-31; npm `latest` is still 3.3.3)

> **Not published.** This header previously read as a dated, shipped release. It is not on npm and has
> not been since the work was completed. Nothing below is available to a consumer running
> `npm install @attested-intelligence/aga-mcp-server`, which still resolves 3.3.3.

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
