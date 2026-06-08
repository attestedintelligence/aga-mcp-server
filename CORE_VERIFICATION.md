# Core Verification Procedure (durable, vendor-independent)

This is the **plain-language definition** of how to verify an AGA SEP evidence bundle, written so the
format outlives any one implementation (or the company). Everything below is re-implementable from
standard primitives — **Ed25519 (RFC 8032) + SHA-256 + RFC 8785 JSON Canonicalization (JCS)** — with
no AGA code. The normative source is [`aga-receipt-spec/CANONICAL_CONSTRUCTION_v2.md`](aga-receipt-spec/CANONICAL_CONSTRUCTION_v2.md) §6; three reference
implementations ship in [`aga-receipt-spec/verify/`](aga-receipt-spec/verify/) (`verify-sep.mjs`, `verify.go`, `verify.py`) and the published
`@attested-intelligence/aga-verify`. If this prose and the reference verifier ever disagree, the
reference verifier wins; if you re-implement from this prose alone, the golden vectors in
[`aga-receipt-spec/vectors/`](aga-receipt-spec/vectors/) are the conformance oracle.

## What a bundle is

A JSON object with: a set of signed **receipts** (each receipt is the canonical 15-field record of one
governance decision), a binary SHA-256 **Merkle tree** over the receipts (`merkle_root` +
`merkle_proofs`), and a single gateway-signed **checkpoint** binding the root, the receipt count, and
the chain head. Identity fields: `gateway_id`, `public_key`, `algorithm` (`Ed25519-SHA256-JCS`).

## Canonicalization (used everywhere below)

`canon(obj)` = RFC 8785 JCS: object property names sorted by **UTF-16 code unit** (RFC 8785 §3.2.3),
no insignificant whitespace, ECMAScript-`Number`-shortest number form (RFC 8785 §3.2.2.3). AGA
additionally **rejects** lone (unpaired) UTF-16 surrogates and bounds nesting depth, and never applies
Unicode NFC/NFD normalization (a string is signed and hashed exactly as its code points appear). Hash
inputs are the UTF-8 bytes of `canon(obj)`. This canon is **byte-identical to RFC 8785** for the
receipt/checkpoint schema (all-string fields plus the integer `leaf_count`) — proven by the shipped
`tests/sep/jcs-rfc8785-conformance.test.ts`, which checks it against the reference `canonicalize`
package, so the `…-JCS` algorithm id is a verified claim rather than an approximation.

**Leaf vs. receipt-signature — do not conflate (this is the most common re-implementer error):**
- A Merkle **leaf** is `SHA-256(canon(receipt))` over the **full receipt object INCLUDING its
  `signature` field**.
- The **receipt-signature** (step 2) is verified over `canon(receipt WITHOUT its signature field)`.

These are two different canonicalizations of the same receipt. *Worked example* (the `valid_minimal`
fixture): `SHA-256(canon(receipt-including-signature))` = `077a3683…51a7`, which is that receipt's
`leaf_hash` and — for the single-receipt tree — the bundle's `merkle_root` and `head_leaf_hash`.

**Domain separation (why there are no `0x00`/`0x01` prefixes):** RFC 6962 prefixes leaf vs. node
hashes to stop an internal-node value being re-presented as a leaf (a second-preimage attack). AGA
achieves the same property **structurally**, without prefixes: every leaf preimage is `canon()` of a
strict 15-field receipt object (begins `{`, always > 64 bytes, schema-validated and signature-verified),
while every internal-node preimage is exactly 64 raw bytes — the input domains are disjoint, so no leaf
can equal a node. A verifier also **recomputes** each leaf from the receipt content (it never trusts a
supplied `leaf_hash`), and the mandatory signed checkpoint binds `leaf_count` + `merkle_root` +
`head_leaf_hash`, so truncation, extension, and tree-reshaping are infeasible without the gateway key.
(The `attack/01_merkle.mjs` red-team script mounts exactly this second-preimage attack and shows every
verifier rejects it.)

## The six steps (all must pass)

1. **Structural floor.** `algorithm == "Ed25519-SHA256-JCS"`; `public_key` is a well-formed Ed25519
   key (reject all small-order encodings + non-canonical `y ≥ p`); each `signature` is exactly 128
   lowercase-hex and not all-zero; `receipts.length > 0`; the number of Merkle proofs equals the number
   of receipts; and each receipt carries **exactly** the 15 canonical fields (no extra/missing/renamed
   key, including a JSON `"__proto__"`). The small-order/non-canonical-key rejection is **load-bearing**:
   a generic Ed25519 library does NOT reject low-order points, and they are the only barrier to a
   from-nothing universal forgery (identity key `R=A, S=0`). The exact rejected encodings are enumerated
   normatively in `aga-receipt-spec/CANONICAL_CONSTRUCTION_v2.md` §6.1 — a re-implementer MUST include
   them or ships a forgeable verifier.
2. **Receipt signatures.** For each receipt, verify its Ed25519 `signature` over
   `canon(receipt-without-signature)` using `public_key`.
3. **Chain + ordering.** Each receipt's `previous_receipt_hash` equals the **leaf** (step 4) of the
   preceding receipt (the first is the empty string); timestamps are non-decreasing and each is the
   exact canonical UTC form `YYYY-MM-DDTHH:MM:SS.sssZ` (exactly three fractional digits — validated by
   ASCII regex + integer calendar arithmetic, never a native date parser, which diverges across stacks).
4. **Merkle proofs.** Recompute each leaf as `SHA-256(canon(receipt))`; walk each proof's
   siblings/`directions` (`"left"`/`"right"` only, length-matched) combining `SHA-256(left || right)`
   over raw bytes (odd nodes are **promoted**, not duplicated) up to a single root that equals
   `merkle_root`; the proof leaf indices must form the complete `0..N-1` bijection (no gaps/dupes).
5. **Signed checkpoint.** Verify the gateway's Ed25519 signature over `canon(checkpoint-without-
   signature)`, and that the checkpoint binds `merkle_root`, `leaf_count == receipts.length`, and the
   chain head. This is what makes the no-prefix construction **truncation-safe** (you cannot drop the
   last receipt without breaking the checkpoint).
6. **Provenance (when a key is pinned).** If the verifier was given an expected key, require
   `public_key == expected`. With a pinned key you have **provenance + integrity**; without one you
   have **integrity only** (`issuerVerified = false`) — a self-consistent bundle signed by an unknown
   key passes integrity but proves nothing about *who* issued it. Always pin for provenance.

## Scope (what a PASS means)

A PASS proves the **integrity of the receipts present** — each is authentic, correctly ordered,
Merkle-included, checkpoint-bound, and (when pinned) provenance-bound. It does **not** prove
non-omission (that every action was logged). See [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md) / [`THREAT_BOUNDARY.md`](THREAT_BOUNDARY.md).

## Conformance

An implementation conforms iff, for every vector in `aga-receipt-spec/vectors/`, it verifies a genuine
vector to VERIFIED with a byte-identical `merkle_root` and returns FAILED on each negative mutation
(tampered field, dropped trailing receipt, re-pointed proof, wrong pinned key, malformed key/signature,
non-canonical timestamp, uppercase Merkle-sibling hex). `npm run conformance:cross-stack` demonstrates
six independent verifiers (the JS reference, the in-server engine, `aga-verify`, Go, and two Python
implementations) return byte-identical verdicts on all **56** cross-stack cases.

**The SEP conformance oracle is `aga-receipt-spec/vectors/aga_evidence_bundle_vectors.json` plus
`fixtures/cross-stack/vectors.json`.** The legacy `aga-receipt-spec/vectors/aga_test_vectors.json` in
that same directory describes a *different* (length-prefixed continuity-chain) profile and is **NOT**
the SEP oracle — do not re-implement against it.
