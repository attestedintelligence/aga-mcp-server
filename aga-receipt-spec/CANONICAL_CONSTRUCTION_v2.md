# AGA Evidence Bundle — Canonical Construction (v2 freeze)

Status: **Normative (frozen 2026-06-03)** · Supersedes the SEP-bundle hashing details scattered across implementations.
Companion to `spec.md` (which defines the legacy continuity-chain profile, §4–8). This document freezes the **SEP Evidence Bundle profile** — the public, demo, and gateway-facing bundle — as the single canonical construction that every implementation MUST round-trip byte-identically.

> This freeze resolves a verified drift: as of 2026-06-03 there were seven mutually non-interoperable evidence-bundle crypto constructions across the codebase. This document is the one normative source they all reconcile to.

---

## 0. Decision record

| Decision | Choice | Rationale |
|---|---|---|
| Hash domain separation | **No-prefix** (no RFC-6962 `0x00`/`0x01`) | Already used by the paper, `spec.md`, the cross-language vectors, the Go reference, Python, and the published npm verifier. The website verifier was the lone RFC-6962 outlier and is realigned TO this, not the reverse. |
| Node hash input | **Raw 32-byte concatenation**, not hex-string concatenation | `sha256(rawbytes(L) ‖ rawbytes(R))`. The published npm verifier's hex-string concat (`sha256(leftHex+rightHex)`) is non-conformant and is fixed in its 2.0.0 republish. |
| Security model | **Mandatory signed checkpoint + leaf-recompute + index-bijection** | Ported from the (otherwise-outlier) website verifier — the only implementation that closed truncation malleability. No-prefix WITHOUT these is truncation-malleable. |
| Claim scope | **Integrity-of-present-receipts** (NOT non-omission) | A PASS proves every present receipt is authentic, chained, included, and (when pinned) provenance-bound. It does NOT prove the signer logged every action. Stated explicitly in §6 and in all public copy. |
| Canonicalization | **One audited RFC 8785 JCS** per language | No `JSON.stringify(sorted)` shortcut; numeric fields that vary (e.g. `request_id`) are emitted as strings at compose time and that constraint is enforced, OR a conformant JCS is used. |

Profiles: the **SEP profile** (this document) is canonical for the public/demo/gateway Evidence Bundle. The **continuity-chain profile** (`spec.md` §4–8, structural length-prefixed leaf + `payload_hash`-signed receipts) remains the internal Go-engine format; reconciling the two into one wire format is tracked separately and is NOT required for this freeze.

---

## 1. Primitives (normative)

```
canon(x)        = RFC 8785 JCS of x, UTF-8 bytes
sha256(b)       = FIPS 180-4 SHA-256 over bytes b
hexToBytes(h)   = the 32 raw bytes of a 64-char hex string
sign(sk, b)     = Ed25519 (RFC 8032) signature over bytes b, lower-hex (128 chars)
verify(pk,b,s)  = Ed25519 verify; pk MUST be rejected if small-order/all-zero; s MUST be 128 hex, not all-zero
```

`algorithm` for this profile is the literal string `Ed25519-SHA256-JCS`.

**Cross-stack canon rules (normative — so every language stack produces byte-identical canonical bytes and verdicts):** object keys are sorted by Unicode code-unit (lexicographic) order, built by string concatenation (never a rebuilt object — V8 reorders integer-like keys numerically); a `"__proto__"` key is an ordinary data key. Integral numbers serialize in shortest integer form per RFC 8785 / IEEE-754 double (`2`, never `2.0` / `2e0`; verifiers parse numbers as float64, so a sub-ULP literal rounds identically everywhere). A string containing an **unpaired UTF-16 surrogate** is invalid Unicode that cannot be UTF-8-encoded — a verifier MUST reject such a bundle (valid surrogate *pairs* / astral characters are fine). Canonicalization is **depth-bounded** (reject input nested beyond 100 levels) and a verifier MUST **fail closed** (return FAILED) on any malformed input — never throw, crash, hang, or exit non-`0/1`.

## 2. Receipt object (canonical field set)

A SEP receipt is exactly these fields (all strings):

```
receipt_id, receipt_version, algorithm, timestamp, request_id, method,
tool_name, decision, reason, policy_reference, arguments_hash,
previous_receipt_hash, gateway_id, public_key, signature
```

- `decision` ∈ {`PERMITTED`, `DENIED`}.
- `request_id` is the upstream request identifier (string | number | null), preserved verbatim in canonical JSON. It is **informational** — NOT a sequence counter and NOT an ordering field. (Numeric ids are permitted; emitters MAY use string ids to avoid any JCS number-canonicalization ambiguity.)
- `timestamp` MUST be the canonical UTC form `YYYY-MM-DDTHH:MM:SS.sssZ` — exactly what `Date.prototype.toISOString()` emits (4-digit year; 2-digit month, day, hour, minute, second; exactly 3 fractional-second digits; literal `Z`). Verifiers validate it with an ASCII `[0-9]` regex (NOT `\d`, which matches Unicode digits in some runtimes) plus pure-integer-arithmetic calendar-range checks — **no native date library** (`Date.parse`/`time.Parse`/`fromisoformat` accept different grammars and diverge across stacks) — and order timestamps by **lexicographic string comparison** (sound because the form is fixed-width UTC). Any other form (timezone offset, missing/extra fractional digits, lowercase `z`, trailing bytes, non-calendar date) MUST be rejected identically by every verifier.
- `arguments_hash` = `sha256(canon(arguments))` (or `sha256(canon({}))` for empty; `""` if absent), hex.
- Field-name unification: this profile uses `previous_receipt_hash` (NOT `previous_leaf_hash`) and `signature` (NOT `portal_signature`). Implementations emitting the old names MUST migrate; a field rename changes the signed bytes and the leaf, so cross-verification is impossible until names match.

### 2.1 Receipt signature

```
body      = receipt with the "signature" field removed
signature = sign(sk, canon(body))
```

The signature commits to every field except itself, including `previous_receipt_hash` and `public_key`.

## 3. Leaf hash (no-prefix, full receipt)

```
leaf(receipt) = sha256(canon(receipt))     // receipt INCLUDING its signature; NO 0x00 prefix
```

The leaf commits to the full signed receipt. This equals the gateway/Python SEP leaf; it is the website leaf with the `0x00` prefix removed.

## 4. Chain linkage

```
receipts[0].previous_receipt_hash = ""               // genesis
receipts[i].previous_receipt_hash = leaf(receipts[i-1])   for i >= 1
```

A verifier recomputes `leaf(receipts[i-1])` and checks equality. **Order is enforced cryptographically by this linkage** — any reorder or insertion breaks it (the link is inside the signed body); trailing-drop is caught by the checkpoint (§5). Verifiers MUST additionally require non-decreasing `timestamp` as a defense-in-depth check. `request_id` is informational and MUST NOT be used for ordering (real receipts carry arbitrary upstream ids).

## 5. Merkle tree + MANDATORY signed checkpoint

Tree over the leaf hashes, raw-byte nodes, last node promoted (not duplicated) on odd levels:

```
node(L, R) = sha256(hexToBytes(L) ‖ hexToBytes(R))
```

Each receipt has one inclusion proof `{leaf_hash, leaf_index, siblings[], directions[], merkle_root}`. `directions[j]` is the side the SIBLING sits on (`"left"` ⇒ `node(sibling,current)`, `"right"` ⇒ `node(current,sibling)`).

The bundle MUST carry a checkpoint signed by the gateway key:

```
checkpoint_body = { algorithm, gateway_id, generated_at, head_leaf_hash, leaf_count, merkle_root }
checkpoint.signature = sign(sk, canon(checkpoint_body))
head_leaf_hash = leaf(receipts[N-1]);  leaf_count = N;  merkle_root = tree root
```

The checkpoint is what makes no-prefix truncation-safe: it binds the receipt count and the chain head to a signature.

## 6. Verification algorithm (and what a PASS proves)

A bundle is **VERIFIED** iff every step passes; **provenance** additionally requires a pinned key:

1. **Structural floor** — whole-document parse (reject any trailing content after the bundle JSON); `algorithm == "Ed25519-SHA256-JCS"`; `public_key` well-formed (reject small-order / non-canonical-`y` / all-zero); `receipts.length > 0`; `merkle_proofs.length == receipts.length`; **strict receipt schema** — every receipt carries EXACTLY the 15 canonical fields (reject extra / missing / renamed / `__proto__`-injected keys).
2. **Receipt signatures** — for every receipt, `verify(public_key, canon(body), signature)`.
3. **Chain + ordering** — genesis link empty; `previous_receipt_hash == leaf(prev)` (this cryptographically enforces order); every `timestamp` is the canonical `.sssZ` form (§2) and the sequence is non-decreasing by lexicographic compare. `request_id` is informational, not an ordering field.
4. **Merkle** — recompute every leaf from receipt content (`leaf_hash == leaf(receipt)`); each proof's `directions` is an array the same length as its `siblings` with every element exactly `"left"`/`"right"`; walk each proof to a single root AND require the proof's own `merkle_root` to equal it; the set of `leaf_index` is the complete contiguous bijection `0..N-1`.
5. **Signed checkpoint** — **strict checkpoint schema** (exactly the 7 fields) with `algorithm == "Ed25519-SHA256-JCS"`; `verify(public_key, canon(checkpoint_body), checkpoint.signature)`; `merkle_root == recomputed root`; `leaf_count == N`; `head_leaf_hash == leaf(receipts[N-1])`.
6. **Envelope consistency** — the UNSIGNED envelope must agree with the signed/recomputed values: every `receipts[i].public_key == public_key`; every `receipts[i].gateway_id == bundle.gateway_id`; `checkpoint.gateway_id == bundle.gateway_id`; `bundle.merkle_root == recomputed root`; `bundle.generated_at == checkpoint.generated_at`. (The unsigned metadata `bundle_id`, `schema_version`, `policy_reference`, `offline_capable` have no signed counterpart and are informational only — a relying party MUST trust only signed/verified values.)
7. **Provenance (only when a key is pinned)** — `public_key == expectedKey`. Without a pin, a PASS proves integrity + self-consistency under the bundle's own key, NOT provenance; verifiers MUST report which case applies (`issuerVerified`).

A verifier MUST treat ANY malformed or hostile input (depth bomb, type confusion, invalid Unicode, trailing content, etc.) as a clean **FAILED** verdict — never an uncaught exception, crash, hang, or non-`0/1` exit. All six conformant verifiers (engine `src/sep`, reference `verify-sep.mjs`, `aga-verify`, Go `verify.go`, Python audited + pure-stdlib) return byte-identical verdicts on the committed cross-stack corpus; run `npm run conformance:cross-stack`.

**What a PASS proves (normative scope):** every *present* receipt is authentic, correctly chained, Merkle-included, and (when pinned) issued by the pinned gateway; nothing present was added, reordered, or truncated. **A PASS does NOT prove non-omission** — it cannot establish that the signer recorded every action it took. Completeness is bounded by the tamper-evidence of the interception point, which is outside the bundle. Public copy MUST state this boundary.

## 7. Conformance

An implementation conforms iff, for every vector in `vectors/aga_evidence_bundle_vectors.json`, it (a) verifies a genuine vector to VERIFIED with a byte-identical `merkle_root`, and (b) flips to FAIL on each negative mutation (tampered field, dropped trailing receipt, re-pointed proof, wrong pinned key). Golden roots in the corpus MUST be corroborated by an independent second computation, never re-baselined from the implementation under change.
