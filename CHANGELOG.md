# Changelog

All notable changes to `@attested-intelligence/aga-mcp-server` are recorded here, newest first. This package follows [Semantic Versioning](https://semver.org). The signed receipt and evidence-bundle wire format is the canonical SEP profile; any format-affecting change is called out explicitly.

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
