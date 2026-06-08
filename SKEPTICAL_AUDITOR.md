# SKEPTICAL_AUDITOR — the 30-minute test

**One question:** what objective evidence, reproducible by a hostile outsider in
about thirty minutes with no privileged access and no trust in us, proves that
3.0.0-rc *materially* differs from the published 2.2.2 — rather than being a
version bump with new prose?

The auditor is assumed adversarial: they expect marketing, they will not take a
README's word, and they will try to make the claims fail. Below is the script
that survives that auditor, with the expected result and what a failure would mean.

---

## The protocol (each step is a command + an expected, falsifiable result)

### Step 1 — The shipped 2.2.2 verifier is forgeable (≈8 min)

Install the *published* 2.2.2, generate a bundle, then mint a forgery signed by a
key you generate yourself and run it through 2.2.2's own offline check.

```
npm i @attested-intelligence/aga-mcp-server@2.2.2
# generate a bundle via the tools, then re-sign every receipt + checkpoint
# with your OWN keypair and re-run verifyBundleOffline on the result.
```

**Expected:** the forgery *passes* 2.2.2's offline check, because that check
verifies receipts against the bundle's own embedded key. **If it passes, the
auditor has independently reproduced the keystone defect** — the 2.2.2 verifier
proves self-consistency, not authenticity. (Repro notes:
`_validation/CRITICAL_FINDINGS_REPRO.md`.)

### Step 2 — The same forgery fails the 3.0.0 verifier when the key is pinned (≈7 min)

Take the identical forged bundle and verify it against the 3.0.0 sound verifier
(`src/sep/verify.ts`, or the reference `verify-sep.mjs`) **pinning the real
gateway key**.

**Expected:** `FAILED` on `gateway_key_match`. The forgery that 2.2.2 accepted is
rejected. This is the single sharpest before/after: same artifact, opposite
verdict. **If it still passes, 3.0.0's soundness claim is false** and this release
must not ship.

### Step 3 — The conformance corpus separates valid from malformed (≈5 min)

```
git clone <repo>; cd aga-mcp-server; npm i
node fixtures/run-conformance.mjs
```

**Expected:**
```
OK  valid_minimal.json:   VERIFIED
OK  valid_denied.json:    VERIFIED
OK  tampered.json:        FAILED
OK  truncated.json:       FAILED
OK  wrong_key.json:       FAILED
OK  small_order_key.json: FAILED
CONFORMANCE PASSED (6/6)
```

**If any malformed fixture VERIFIES, the verifier is unsound.** The six fixtures
are fixed bytes; the auditor can open and mutate them. (This gate runs the
*reference* verifier, so it also proves the reference rejects the small-order key.)

### Step 4 — A denial cannot be erased by the agent (≈7 min)

```
npx vitest run tests/integration/provable-denial.test.ts
```

This test drives the real in-process server: it provokes a DENIED decision,
re-attests (the agent's "wipe history" move), exports the bundle, and verifies it
independently. **Expected:** the DENIED receipt is still present and the bundle
verifies — re-attestation did not reset the SEP ledger. **If the denial
disappears, claim C4 is false.** For the tamper / truncate / reorder variants, the
auditor can run the red-team scripts in `_validation/redteam/` (A1–A4).

### Step 5 — The forgeable code is actually gone (≈3 min)

```
git grep -n "verifyBundleOffline\|generateBundle\|buildMerkleTree" src/
ls src/core/bundle.ts src/core/checkpoint.ts src/crypto/merkle.ts
```

**Expected:** no executable references in `src/` (only removal-note comments); the
three files do not exist. **If the forgeable verifier is still present and
reachable, the deletion claim is false.** (`P4_DELETION_REPORT.md`.) Also confirm
the *tarball* is clean — `npm run build && node scripts/check-pack.mjs` must report
no `dist/core/bundle.*`, `dist/core/checkpoint.*`, or `dist/proxy/verify.*`.

### Step 6 — A denial cannot be erased by crashing the recorder (≈4 min)

Every governed decision must yield a receipt; an attacker who can only send tool
calls should not be able to make one *vanish*. Drive the real proxy with a
deeply-nested-arguments "depth bomb":

```
npx vitest run tests/proxy/dos-failclosed.test.ts
```

**Expected:** the call returns a DENIED error (not a timeout or silent drop), the
DENIED decision is present in the exported bundle, and the bundle still verifies.
**If the decision disappears or the process hangs, "every governed decision yields
a receipt" is false.** (This is exactly what the first re-audit caught; Phase 10
made the path fail-closed and depth-bounded.)

### Step 7 — A from-nothing forgery under a small-order key is rejected by EVERY verifier (≈5 min)

The sharpest forgery needs no private key: under the Ed25519 identity point a
signature is universally valid. Run it through all three JS verifiers at once:

```
npx vitest run tests/sep/cross-stack-smallorder.test.ts
```

**Expected:** a bundle keyed to a small-order point is `FAILED` by the engine
(`src/sep`), the reference (`verify-sep.mjs`), AND `aga-verify` — while a real
bundle VERIFIES on all three. **If any verifier accepts the small-order bundle, the
forgery defense is incomplete on that stack.** (This is what the *second* re-audit
caught — the fix had been applied only to the engine; Phase 12 closed it across all
verifiers.)

### Step 8 — Canonicalization is byte-identical to the reference (≈3 min)

```
npx vitest run tests/sep/reaudit-fixes.test.ts
```

**Expected:** `src/sep` canonicalization equals a verbatim copy of the reference
`canon` on every case — **including integer-like keys** (a port map `{"22":..,"3":..}`
must serialize lexicographically, not numerically). **If they diverge, two language
stacks disagree on the same bundle.** The committed cross-stack vectors
(`fixtures/cross-stack/vectors.json`) and the multi-language conformance harness
exercise the same property across stacks.

---

## What this protocol does *not* let the auditor conclude

A fair auditor will note these limits, and we state them so the test is not
oversold:

- It does **not** prove non-omission. It proves present receipts are authentic and
  complete-as-a-set; it cannot prove the gateway logged everything it did
  (`THREAT_BOUNDARY.md §1`).
- Step 2's "independent npm verifier" leg uses the **published** `@attested-intelligence/aga-verify@2.0.0`
  (the unsound `1.0.0` is deprecated), runnable straight from the registry:
  `npx @attested-intelligence/aga-verify@2.0.0 <bundle.json> --pubkey <key>`. The dependency-free
  in-repo reference (`node aga-receipt-spec/verify/verify-sep.mjs <bundle.json>`) is the zero-install
  path. No open condition remains on this leg.
- It does **not** exercise the proxy mandatory-mediation property, which is a
  deployment concern, not a code guarantee (`THREAT_BOUNDARY.md §3.1`).

---

## The honest bottom line

Steps 1 and 2 alone settle the original question. The same forged bundle that the
*published* product accepts is rejected by this candidate when the key is pinned.
That is a material, reproducible, trust-free difference — not a version bump. Steps
3–8 confirm the verifier is sound across a fixed corpus, that denials survive both
an *erase* attempt (re-attest) and a *crash* attempt (depth bomb), that a
no-private-key small-order forgery is rejected by every verifier, that
canonicalization is byte-identical to the reference, and that the forgeable code is
physically gone from both `src/` and the tarball.

Two independent adversarial re-audits were run on this candidate; both found real
issues (canon divergence, DoS silent-erasure, an incomplete small-order defense in
the sibling verifiers) and **all were fixed and are pinned by the tests above** —
Steps 6–8 are exactly those reproductions. The one thing the auditor cannot yet do
from the public registry is Step 2/7's published-`aga-verify` leg: `2.0.0` (now
carrying the small-order fix) is built and tested in-repo but not yet published —
that, and pushing the reference-verifier fix, are the release's open conditions
(`RELEASE_RECOMMENDATION.md`, `PUBLISH_PLAN.md`).
