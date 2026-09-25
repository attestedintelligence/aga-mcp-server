# Changelog

All notable changes to `@attested-intelligence/aga-mcp-server` are recorded here, newest first. This package follows [Semantic Versioning](https://semver.org). The signed receipt and evidence-bundle wire format is the canonical SEP profile; any format-affecting change is called out explicitly.

## 3.6.2 — 2026-09-25

Documentation and version only; the runtime is 3.6.0's, file for file (`dist/` is byte-identical to 3.6.0's and 3.6.1's). The shipped documents:

- no longer say `aga-governance` 0.3.1 is the current release (PyPI serves a later version). They say 0.3.1 fixed the
  depth-bomb crash and every later release carries the fix;
- say the proxy evaluates each call against the operator's loaded policy (a JSON file or a built-in profile) and signs the
  SHA-256 of its canonical JSON into every receipt, instead of calling it a sealed policy; the npm package description
  says the same;
- describe the proxy's upstream as a stdio child process or a plain JSON-RPC POST (`--upstream-url`), with no Streamable
  HTTP session or SSE handling;
- THREAT_BOUNDARY.md: `denyMethods` is a library option that the `aga-proxy` CLI cannot set;
- SECURITY.md: adds GitHub private vulnerability reporting, names `@attested-intelligence/aga-verify` and `aga-governance`
  in scope, and says an evidence bundle shows tampering, not non-omission;
- the known issues are listed for 3.6.0 to 3.6.2.

## 3.6.1 — 2026-09-23

README and version only; the runtime is 3.6.0's, file for file. The README:

- no longer says `aga-governance` 0.3.0 is the latest release and not yanked. 0.3.1 fixed the
  depth-bomb crash, and 0.3.0 was yanked for it (0.2.6 has the same crash and is not yet yanked);
- lists three known issues in the `aga-proxy` gateway, each reproduced on 3.6.0 on 2026-09-23, with
  the measured workaround where one exists: the agent port listens on every interface without
  authentication; two clients reusing a JSON-RPC id can receive each other's results; a gateway key
  supplied through the environment is inherited by the stdio upstream;
- says how a client reaches the proxy's raw-TCP agent port, instead of "any MCP client".

## 3.6.0 — 2026-09-18

### `aga-proxy` now honours `AGA_GATEWAY_KEY` / `AGA_GATEWAY_KEY_FILE`

This package ships two binaries and only one of them read the operator's key contract. `aga-mcp-server`
honoured both variables; `GovernanceProxy` called `generateSigner()` unconditionally in its
constructor, read neither variable, and printed no warning. An operator who set `AGA_GATEWAY_KEY`
correctly and started the proxy was **silently ignored**: no effect, no notice, and evidence bundles
whose issuing key rotated on every restart. That is worse than an unsupported feature — silence
defeats a correct configuration. It is checkable in the published 3.5.0 tarball, where `dist/proxy/`
contains zero references to either variable while `dist/server.js` contains seven.

**What changes for you:** if you already set `AGA_GATEWAY_KEY` or `AGA_GATEWAY_KEY_FILE` and ran
`aga-proxy`, that variable now actually takes effect, so the proxy's `gateway_public_key` stops
rotating and becomes the key your seed derives. Nothing breaks: a proxy with neither variable set
behaves exactly as before except that it now says so. If you *want* the old throwaway-key behaviour
with a variable set, pass the new `--ephemeral` flag.

- **One resolver, both binaries** (`src/sep/gateway-key.ts`). Order: `AGA_GATEWAY_KEY`, then
  `AGA_GATEWAY_KEY_FILE`, then an ephemeral key. An invalid or unreadable key **warns and falls
  back** rather than exiting — deliberately matching what `aga-mcp-server` has always done, because
  refusing to start would take a governed boundary offline over a key that only affects whether
  provenance is *pinnable*. Integrity, chaining and the deny path do not depend on which key signs.
  A second variable name for the proxy was rejected: one installable must not carry two key
  contracts.
- **The proxy prints its active PUBLIC key at startup**, with its source:
  `Signing gateway key <64-hex> (persisted via AGA_GATEWAY_KEY_FILE)`. This is the line that makes an
  honest pin possible. A verifier handed a key lifted out of the bundle it is checking will print
  `provenance verified` and has proved nothing about issuance — the check is circular. A key printed
  before any bundle exists is a key you can obtain **out of band**.
- **`--ephemeral`** turns the old silent default into a stated choice, on both `start` and `run`.
- **Never logs key material.** Only the variable name that was tried and the derived public key.
- `aga-mcp-server` is behaviourally unchanged. It passes its portal keypair's secret as the fallback
  seed, so its unconfigured case stays byte-identical to previous releases; extracting the resolver
  must not silently rotate either binary's key, and a test now holds that.

**Not a turnkey guarantee, stated plainly.** Persisting the key makes provenance *pinnable*; it does
not make it *pinned*. The default on both binaries is still an ephemeral key, an unconfigured
deployment carries the old risk in full, and nothing in the package detects a deployment that skipped
the configuration. `THREAT_BOUNDARY.md` item 4 now says exactly that.

### Two halves of the above that were written but never shipped

`describeKey()` and the `--ephemeral` option both existed in the 3.5.0 tree and **neither was reachable
from the entry point**: `dist/proxy/index.js` never called `describeKey()`, so the shipped binary
printed no key line at all, and `new GovernanceProxy({...})` never passed `ephemeral`, so the flag was
parsed and discarded. Both are now wired, and the integration test below drives the built artifact
rather than the source, which is what catches this class of defect. A declared flag the entry point
does not read is not a feature.

### Tests

- `tests/sep/gateway-key.test.ts` (17): env key, key file, precedence when both are set, an invalid
  value, an unreadable file, malformed file contents, the unconfigured case, `forceEphemeral`,
  `fallbackSeed` identity across all three ephemeral paths, the default warning sink being
  `console.error` and never `console.log`, the log prefix, and that no path emits key material.
- `tests/integration/proxy-gateway-key.test.ts` (7): drives the **built** `dist/proxy/index.js` as a
  real child process. One key file, two processes, identical public key on the banner and zero
  warnings; the env var and the key file agree; unconfigured rotates between runs and says so;
  `--ephemeral` overrides a configured key; an invalid key warns, falls back, and still announces what
  it signs with; the seed appears in neither stream; the key line is on stdout and the warning on
  stderr.
- Suite: **404 → 428** tests across 45 → 47 files. SEP conformance 6/6. `check:pack` clean.

### Documentation corrected in the same release

`DEPLOYMENT.md` §2 and `THREAT_BOUNDARY.md` item 4 ship inside this tarball and described the *old*
proxy behaviour in the same breath as the new. The §2 comparison table had been updated in one cell
while the two paragraphs under it still told operators the proxy ignores both variables; `README.md`
still said so outright. All three are now consistent and **version-scoped**, so a reader running 3.5.0
or earlier still gets the truth for the version they are running rather than a claim that only holds
after upgrading. README test counts updated to the recomputed figure.

## 3.5.0 — 2026-08-29

**Version ruled 2026-08-29.** `3.4.0` was claimed by two different trees ~93 commits apart, so
publishing either line under that number would permanently burn it for the other. This line ships as
**3.5.0** and `3.4.0` is abandoned unpublished. Everything below — the 2026-08-28 honesty and safety
work *and* the 3.4.0 work completed 2026-07-31 — releases together; npm `latest` has been 3.3.3 since
2026-07-03.

### BEHAVIOR CHANGE — TTL expiry now fails closed

**If you rely on measurement continuing after an artifact's TTL lapses, this release breaks that.**
Founder decision D1, ruled 2026-08-29.

Previously `Portal.measure()` treated TTL expiry as *graceful degradation*: it moved the portal to
`SAFE_STATE`, logged the reason, and **kept accepting measurements indefinitely**. An expired artifact
therefore went on being measured, and the receipt recorded no enforcement because none occurred.

Now TTL expiry sets `TERMINATED`, exactly as the sibling revocation branch always has — TTL was the
odd one out, not the new behavior. Concretely:

- The first post-expiry `measure()` returns `ttl_ok: false`, `degraded: true`, and the portal is
  `TERMINATED`.
- **Any subsequent `measure()` throws `Portal is terminated`.** Re-attestation is the only way back.
  Callers that looped on `measure()` past expiry must handle this.
- `measure_integrity` now seals `enforcement_action: 'TERMINATE'` on TTL expiry, and that is accurate:
  termination genuinely happens. The invariant across every version of this code is unchanged — the
  receipt says what actually happened. Only the underlying behavior moved.
- The `TTL_EXPIRED` degradation entry is still written. It is the forensic record of *why* the portal
  terminated, and dropping it would trade one honesty problem for another.

**Semver note, stated plainly:** this is a behavioral break and a strict reading argues for a major
version. It ships as a minor because the previous behavior contradicted the documented intent, and
because no released consumer depends on post-expiry measurement (npm `latest` has been 3.3.3 since
2026-07-03). If that reading is wrong for your deployment, pin `3.3.3`.

Found while implementing this: `tests/core/fail-closed.test.ts` contained a test named
**"fail-closed: expired TTL blocks execution"** that asserted `SAFE_STATE` — the state in which
measurement *continues*. A test whose name claimed the boundary blocked execution had been green while
proving it did not. It now asserts termination and that a second call throws. Six other assertions
across four files encoded the old behavior and were updated with it; all were seen to go red before
going green.

Checked and unchanged: no shipped document and no public page makes a TTL enforcement claim, so this
change corrects no external copy.

### Documentation: proxy key-persistence claims corrected

`DEPLOYMENT.md` and `THREAT_BOUNDARY.md` ship inside this tarball, and both described key persistence
that **`aga-proxy` does not implement**. DEPLOYMENT §1 is explicitly about the proxy; §2 then told
operators to set `AGA_GATEWAY_KEY` / `AGA_GATEWAY_KEY_FILE`, said the ephemeral fallback "warns on
stderr", and pointed at `get_server_info`. For the proxy none of that is true — an operator following
it pinned a key that rotates on the next restart.

- `GovernanceProxy` calls `generateSigner()` unconditionally in its constructor: no key CLI option, no
  environment variable, no signer through `ProxyServerOptions`. Two runs with an identical
  `AGA_GATEWAY_KEY` produce different gateway public keys (measured). `dist/server.js` carries the
  `EPHEMERAL gateway signing key` stderr warning; `dist/proxy/` has none.
- `THREAT_BOUNDARY.md` §3.4 previously read **"Key persistence — mitigated in 3.0"** while §3.1–3.3 are
  each prefixed "Proxy —" and §3.4 was not, so it scanned as covering the package. A residual-risk
  register must not record an unmitigated risk as mitigated. It now states the asymmetry.
- Both files gained an entry-point comparison table, and record that a verifier handed a key taken from
  the bundle under test will still print `provenance verified` — that check is **circular**, and only a
  key obtained beforehand proves issuance.

**KNOWN LIMITATION, unchanged in this release:** `aga-proxy` still has no way to persist its signing
key, so proxy-issued bundles are integrity-verifiable but **not provenance-pinnable across restarts**.
`aga-mcp-server` (the stdio server) is unaffected and persists normally. Closing the proxy gap is
runtime work that is deliberately out of scope here.

### Honesty + safety fixes (2026-08-28)

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

> Resolved 2026-08-29: this line ships as **3.5.0**; `3.4.0` is abandoned unpublished so the number
> stays free for the other tree. See the release heading above.

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

### Included from the abandoned 3.4.0 line (work completed 2026-07-31, never published)

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
