# Cross-stack SEP conformance vectors

`vectors.json` is the **portable contract** every conformant SEP verifier must satisfy *identically* —
the TypeScript engine (`src/sep`), the reference verifier (`aga-receipt-spec/verify/verify-sep.mjs`), the
published `aga-verify` (`independent-verifier/`), the Go verifier (`verify.go`), and the Python verifier in
**both** backends (audited `cryptography`/PyNaCl and pure-stdlib RFC-8032) — i.e. **six verifiers**. It
exists to close a real soundness/interoperability gap: if two stacks canonicalize or validate the same
bundle differently, they can render different verdicts on it. A conformant verifier must not.

## The contract

1. **Canonicalization is injective and byte-identical across stacks.** `canonical[*]` gives
   `input → canonical`; each stack must produce the byte-identical string. A `__proto__` key is an ordinary
   key and MUST appear (not be dropped by a prototype setter). Keys sort by Unicode code-unit (lexicographic,
   via string concatenation — never a rebuilt object, which reorders integer-like keys); array order is
   preserved; integral numbers serialize in shortest integer form per RFC 8785 / IEEE-754 double.
2. **Strict structure.** Receipts carry EXACTLY the 15 canonical fields and the checkpoint EXACTLY its 7
   (no extra / missing / renamed / `__proto__`-injected key); `algorithm` is bound; Merkle `directions` are
   `"left"`/`"right"` only and length-matched to `siblings`; the unsigned envelope `gateway_id`,
   `merkle_root`, and `generated_at` must equal the signed/recomputed values.
3. **Canonical timestamps.** Exactly the `YYYY-MM-DDTHH:MM:SS.sssZ` UTC form, validated by an ASCII `[0-9]`
   regex + pure integer-arithmetic calendar checks (no native date parser) and ordered lexicographically.
4. **Crypto floor.** Small-order / non-canonical (`y ≥ p`) / all-zero keys and signatures are rejected; an
   unpaired UTF-16 surrogate in any string is rejected (valid surrogate pairs / emoji pass).
5. **Robust + whole-document.** A malformed/hostile bundle (depth bomb, type confusion, trailing content
   after the JSON document) yields a clean FAILED (exit 1) on every stack — never a crash, hang, or non-1
   exit.
6. **Verdicts match.** `valid_bundle` + every `valid_variant` → VERIFIED (provenance when pinned); every
   `adversarial[]` → FAILED — **identical on all six verifiers**.

## Files

- `vectors.json` — the committed vectors (source of truth; consumed by `tests/sep/cross-stack-vectors.test.ts`).
- `generate.mjs` — deterministic regenerator (`node --import tsx fixtures/cross-stack/generate.mjs`);
  self-checks against the engine before writing. Regenerate only intentionally.
- `run-all-stacks.mjs` — the **6-verifier conformance harness** (`npm run conformance:cross-stack`): runs the
  full corpus through reference, `src/sep` engine, `aga-verify`, Go, Python-audited, and Python-stdlib and
  asserts identical verdicts. It also feeds a few **literal-byte files** to the file-parsing verifiers
  (trailing content, sub-ULP numeric literals) that the object path would otherwise mask. Requires `node`,
  `go`, and `python` (with `cryptography`) on PATH + `npm run build`.

## Status — all six verifiers conformant (last verified 2026-06-07)

`run-all-stacks.mjs` proves all six render **identical verdicts on all 55 cases** (7 canonical + valid +
valid-variants + adversarial + 4 raw-byte/file-parse). This was hardened across six rounds of independent
**blind** differential re-audit, which found and closed these cross-stack divergence classes (none were
forgery-accepts — all were verdict disagreements on malformed input):

- [x] **Strict structure** — schema allowlist, `envelope_consistency`, checkpoint-algorithm binding,
      per-proof `merkle_root`, Merkle direction-token strictness — ported to all six.
- [x] **Canonical timestamps** — one shared library-free rule replacing three divergent native date parsers
      (incl. the Python `$`-vs-`fullmatch` trailing-newline case).
- [x] **RFC-8785 numbers** — integral-number normalization (Go `big.Float`→float64; Python int-coercion).
- [x] **Unicode** — unpaired-surrogate rejection (JS); Go un-escapes `U+2028`/`U+2029` (an exhaustive
      0..0x10FFFF sweep proved these were the only divergent string characters).
- [x] **Robustness** — depth-bounded never-throw across all stacks.
- [x] **Whole-document parse** — Go now rejects trailing content after the bundle (it previously ignored it).

**Documented residual (unreachable by construction):** a *non-integer* number in a signed field would
canonicalize differently across language stdlibs — but the emit guard `assertSignedReceiptFieldsAreStrings`
forbids any number other than the integer `leaf_count` in a signed field, so no conformant gateway can emit
one (guarded by `tests/sep/emit-guard.test.ts`). See `THREAT_BOUNDARY.md` §3.8.

> Emit-side note (not a verifier divergence): `arguments_hash` is computed by the *gateway* as
> `sha256(canon(arguments))`; the verifier only ever canonicalizes the receipt (which stores the hash
> string), never the raw arguments. An astral-codepoint *key* inside tool `arguments` would sort by UTF-16
> code unit (JS gateway) vs Unicode code point (a hypothetical Python gateway) — relevant only to a
> non-JS *gateway* implementation, not to verifier conformance. Align in a versioned format step if a
> second gateway is built.
