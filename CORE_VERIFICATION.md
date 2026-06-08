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

`canon(obj)` = RFC 8785 JCS: object keys sorted by Unicode code point, no insignificant whitespace,
minimal number form. AGA additionally **rejects** lone (unpaired) UTF-16 surrogates and bounds nesting
depth. Hash inputs are the UTF-8 bytes of `canon(obj)`. There are **no domain-separation prefixes**
(no `0x00`/`0x01`): a leaf is `SHA-256(canon(receipt))` over the full receipt object minus its
`signature` field — see step 4.

## The six steps (all must pass)

1. **Structural floor.** `algorithm == "Ed25519-SHA256-JCS"`; `public_key` is a well-formed Ed25519
   key (reject all small-order encodings + non-canonical `y ≥ p`); `receipts.length > 0`; the number
   of Merkle proofs equals the number of receipts.
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
non-canonical timestamp). `npm run conformance:cross-stack` demonstrates six independent verifiers
agree on all 55 canonical cases.
