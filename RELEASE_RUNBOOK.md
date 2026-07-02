# Release Runbook — `@attested-intelligence/aga-mcp-server`

How a release is cut and published, with provenance, so any maintainer can repeat it. The npm publish
runs **only** through GitHub Actions OIDC trusted publishing (no stored token, no local `npm publish`)
— that is what produces the SLSA build provenance.

## Pre-publish gates (must be green)

- `npm run check` → build + lint + **384 tests** + SEP conformance (6/6) + **`check:pack`**
  (positive-allowlist + IP-rail content scan: exactly `dist/` + the 5 docs + `package.json`, no
  forbidden artifacts, none of the four IP-rail markers in any shippable file).
- `npm run conformance:cross-stack` → **6 verifiers agree on all 57 canonical cases**.
- The release workflow runs BOTH as required gates before it will publish.

## Cutting a release

1. Land the change on `main`; bump `package.json` `version` (patch for docs/fixes, minor/major per
   semver). Commit + push.
2. Run the **release** workflow at
   `https://github.com/attestedintelligence/aga-mcp-server/actions/workflows/release.yml`
   (or `gh workflow run release.yml -R attestedintelligence/aga-mcp-server -f ...`):
   - **dry run first:** `dist_tag=rc`, `provenance=true`, `dry_run=true` → confirms gates + pack, publishes nothing.
   - **soak on rc:** `dist_tag=rc`, `provenance=true`, `dry_run=false` → publishes under the `rc` tag.
   - **promote to latest** once vetted: `npm dist-tag add "@attested-intelligence/aga-mcp-server@<ver>" latest`
     (a tag move — NO republish, the published artifact + its provenance are unchanged). `latest`
     requires provenance (the workflow enforces it for a public repo).
3. Deprecate superseded lines if needed: `npm deprecate "@attested-intelligence/aga-mcp-server@<range>" "<reason>"`.
4. Verify: `npm view "@attested-intelligence/aga-mcp-server" version dist-tags` and `npm audit signatures`.

## Provenance hardening (recommended for the next release)

The workflow currently builds from the **checked-out branch ref** (`main`). The commit binding is
cryptographically solid, but a cleaner posture is to dispatch the release from an **immutable git
tag** (e.g. `v3.0.2`) so the published provenance subject binds to a tag that cannot move:

- Tag the release commit: `git tag -a v<ver> -m "<ver>" && git push origin v<ver>`.
- Run the workflow against that tag (workflow_dispatch `ref`), so the SLSA subject pins the tag.
- This repo now carries a permanent `v3.0.2` tag capturing the canonical SEP format (spec + golden
  vectors + the three reference verifiers) — the durable, vendor-independent reference point.

## Python companion (`aga-governance`, PyPI)

Separate package, founder-credentialed. Build + guard, then upload:
`python -m build && python scripts/check_pack.py` (must print OK) `&& python -m twine upload dist/*`.
The sdist is restricted to `src/aga` + README + LICENSE + pyproject (no tests/testdata/internal docs).
Rollback is **yank + fixed patch version**, never deletion-reliance (mirrors the npm posture).

## Never

- No local `npm publish` (loses provenance + fails the trusted-publisher config).
- No publish if `check:pack` or the cross-stack gate is red.
- No shipping any IP-rail-blocked marker in any package — the pack guards (`scripts/check-pack.mjs` /
  `aga-python/scripts/check_pack.py`) hard-fail on these; run `node scripts/check-pack.mjs --selftest`
  for the live marker list.
