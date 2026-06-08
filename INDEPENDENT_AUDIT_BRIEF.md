# Independent Audit Brief — `@attested-intelligence/aga-mcp-server` SEP evidence

For a context-fresh reviewer. This brief lists **only the published verification surface**, the
soundness claims, and the exact forgeries you should attempt — so you can reproduce the trust-free
verification and try to break every claim **blind**, without reading the development history. It
deliberately contains no fix reasoning; verify the behavior yourself.

---

## 1. Scope — what you are auditing

The verification surface, and the only thing you need to trust, is:

- **The in-server verifier** — the `verify_bundle_offline` MCP tool, backed by `src/sep` (ships in
  the npm package under `dist/sep/`).
- **The reference verifier** — `aga-receipt-spec/verify/verify-sep.mjs` (zero deps, Node built-in
  crypto). Designated normative ground truth.
- **The published independent verifier** — `@attested-intelligence/aga-verify` (`verify.ts` → `dist/`).
- **Two sibling reference verifiers** — `aga-receipt-spec/verify/verify.go` (stdlib `crypto/ed25519`)
  and `verify.py` (audited library by default; pure-stdlib RFC-8032 only via `--ed25519 stdlib`).

You do **not** need to trust the gateway, the server, or us: a bundle is self-contained; a verifier
recomputes everything from the bundle bytes and checks signatures against a key **you** pin.

## 2. Soundness claims (what a PASS means)

A bundle that VERIFIES proves: every receipt present is Ed25519-authentic, hash-chained in order,
Merkle-included under a gateway-signed checkpoint that binds the leaf count + chain head, and —
when you pass `--pubkey <key>` — issued by exactly that pinned key. Canonicalization is the JCS
profile (sorted-key, lexicographic, injective).

It does **NOT** claim: non-omission (that the gateway logged every action it took); prevention of
jailbreaks, key theft, or infrastructure compromise; or mandatory mediation (a deployment property).
Without `--pubkey` the result is **integrity-only** (`issuerVerified=false`) and proves authenticity
of the present set, not who issued it.

## 3. Trust-free reproduction (run this)

```bash
git clone --recurse-submodules <repo-url> aga && cd aga && npm ci
npm run build
# Generate a real bundle via the server tools (or use a committed one), get its gateway key from
# get_server_info, then verify it offline with each independent verifier — all must agree:
node aga-receipt-spec/verify/verify-sep.mjs <bundle>.json --pubkey <gateway-key>   # reference
npx @attested-intelligence/aga-verify <bundle>.json --pubkey <gateway-key>          # published
go run aga-receipt-spec/verify/verify.go <bundle>.json --pubkey <gateway-key>       # Go
python aga-receipt-spec/verify/verify.py <bundle>.json --pubkey <gateway-key>       # Python
```
Expected: `VERIFIED (provenance verified)`, exit 0, on every verifier. Tamper any byte and re-run:
every verifier must return `FAILED`, exit 1.

## 4. Forgeries to attempt (blind) — each must be REJECTED by every verifier

The committed corpus `fixtures/cross-stack/vectors.json` contains a self-consistent bundle plus a
named adversarial set; `npm run conformance:cross-stack` runs the whole corpus through all verifiers
and asserts they agree. Attempt each of these (the corpus has a fixture for each — or construct your
own); the expected verdict on **every** verifier is FAILED:

1. **From-nothing forgery under a small-order key.** Build a fully self-consistent bundle whose
   `public_key` is the Ed25519 identity point (`01` + 31×`00`) and sign every receipt + the
   checkpoint with `encode(identity)‖0` (which verifies under identity for any message). Chain,
   Merkle, and checkpoint all recompute consistently. Expected: FAILED (the key is rejected).
2. **Each small-order / non-canonical key.** Swap `public_key` to any of the 10 small-order
   encodings, or any non-canonical encoding with `y ≥ 2²⁵⁵−19`. Expected: FAILED.
3. **`__proto__` / extra / missing field on a receipt or checkpoint.** Expected: FAILED.
4. **Truncate** a receipt (drop it), **reorder** receipts, or **tamper the checkpoint** root/algorithm.
   Expected: FAILED.
5. **Re-sign under your own key**, then pin the real gateway key. Expected: FAILED (provenance).
6. **Integer-keyed / unicode / `__proto__` canonicalization inputs** must produce byte-identical
   canonical output across all stacks (`fixtures/cross-stack/vectors.json#canonical`). Any
   divergence is a finding.

Confirm the corpus is a real guard: edit any verifier to weaken a check (e.g. accept small-order
keys), re-run `npm run conformance:cross-stack`, and confirm a fixture flips to disagreement.

## 5. Cross-repo consistency checklist (all must agree on the same SEP/canon)

Before relying on a published version, confirm these line up:

- [ ] **Server** `@attested-intelligence/aga-mcp-server` version and its `dist/sep` verifier.
- [ ] **Published verifier** `@attested-intelligence/aga-verify` version — same canon + key checks.
- [ ] **Reference verifier** commit in the `aga-receipt-spec` submodule (and the parent's recorded
      submodule pointer) — `verify-sep.mjs` + `verify.go` + `verify.py` all current.
- [ ] **Spec** `aga-receipt-spec/CANONICAL_CONSTRUCTION_v2.md` matches the implemented algorithm.
- [ ] All six verifiers (reference, engine, aga-verify, Go, Python-audited, Python-stdlib) return identical verdicts on `fixtures/cross-stack/vectors.json` (55 cases)
      (`npm run conformance:cross-stack` → all agree).

If any are out of step (e.g. an older published `aga-verify` than the server, or an unbumped
submodule pointer), treat the offline-verification claim as unverified until reconciled.

## 6. Out of scope

Non-omission; jailbreak / weight-theft / credential / infrastructure prevention; mandatory mediation
(network isolation is a deployment property); HSM/KMS key custody. See `THREAT_BOUNDARY.md`.
