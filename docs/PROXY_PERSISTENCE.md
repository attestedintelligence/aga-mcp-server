# Opt-in restart persistence for the SEP evidence ledger (prototype)

Status: **prototype**, off by default. Staged on top of `3.3.2` as a reviewable change; not versioned or published.

This is the design companion to `src/sep/persistence.ts` (which carries the same DESIGN block at the top of the file). It states the model, the crash-safety argument, and the replay-verification guarantee.

## The gap

`SepGateway` (`src/sep/bundle.ts`) holds its ledger — `receipts[]` plus the chain head (`lastLeaf`, `lastTimestamp`) — **in memory**. `record()` builds, signs, and appends a receipt in memory; `exportBundle()` assembles the Merkle tree and the signed checkpoint from `receipts[]` at call time. So a proxy restart or crash loses every receipt recorded since the last export. That is the pilot-blocking durability gap this prototype closes.

## Model

Persistence is a thin, opt-in mirror of the in-memory ledger. It is enabled by a single option — `SepGateway({ persistPath })`, wired to `aga-proxy start --persist <path>`. When unset, nothing is opened or written and behavior is byte-for-byte unchanged.

- **It only SAVES already-signed receipts and REPLAYS them.** It never re-signs, re-hashes, or mutates a receipt, and it never touches the evidence core (`receipt` / `canonical` / `merkle` / `checkpoint` / `crypto` / `hybrid` / the verifier). A replayed ledger produces a bundle that verifies identically — same verdict, same `merkle_root` — to one built without a restart, because the leaves are the exact bytes that were signed.
- **On-disk format is JSONL:** one signed SEP receipt as a compact JSON object per line, in record order. A receipt is flat scalars (`string | null`) only — no numbers, no nested objects — so `JSON.stringify` → `JSON.parse` is lossless and the parsed receipt canonicalizes to the identical bytes (identical leaf hash).
- **The signing key is never written.** The log carries only public material; each receipt already embeds its own `public_key`. Durable *provenance* across restart is a separate axis — a stable gateway key (see below).

## Crash-safety argument

`append()` writes one **newline-terminated** line with `writeSync`, then `fsyncSync`. A returned `append()` therefore means the receipt's bytes are durably on disk, subject to the filesystem/hardware honoring `fsync`.

The **durable unit is a newline-terminated line.** A crash mid-append can leave a trailing partial line that is *not* newline-terminated. On the next `replay()`:

- everything up to and including the last `\n` is **committed**; anything after it is an **unterminated remainder**;
- a non-empty remainder is treated as a crash artifact: it is **dropped** and the file is **truncated** back to the last complete line, so a crash costs at most the one in-flight receipt and never wedges the log for future appends.

`record()` persists **before** advancing in-memory state: it appends+fsyncs the signed receipt first, and only then pushes it and updates the chain head. If the disk write throws, the in-memory ledger is not advanced and the error propagates — the durable log and the in-memory ledger stay atomic.

Out of scope for the prototype: directory-entry `fsync` (a freshly-created log file's directory entry is not separately synced) and fsync-lying hardware.

## Replay-verification guarantee

`replay()` never silently trusts the file. Every **complete** (newline-terminated) line is re-verified with the **existing** primitives before it enters the ledger:

1. **Strict schema** — exactly the 15 canonical receipt fields (rejects extra / unknown / `__proto__`-injected / missing keys), a registered algorithm, and a profile-well-formed `public_key`.
2. **Signature** — Ed25519 (v1) / composite (v2) over `canon(receipt minus "signature")` under the receipt's own `public_key`, via `verifyForProfile` — the same primitive the verifier uses at §6.2.
3. **Chain linkage** — `previous_receipt_hash` equals the leaf of the prior replayed receipt (`''` for the first), so reordering or a foreign-chain splice is caught.
4. **Single-key-per-log** — every line shares the first line's `public_key` and `algorithm`. This mirrors the SEP bundle's one-key invariant and rejects a foreign receipt spliced in under a different key **even if** the attacker forges its chain link with that other key.

A complete line that fails **any** check is treated as tampering/corruption and **rejected loudly** (throws `ReceiptLogError`); the ledger is never partially or silently loaded. Only the single unterminated trailing remainder is tolerated (dropped as a crash artifact) — never a committed line.

## Provenance across restart (the key)

Replay validates each line under the key it was signed with, which may differ from the gateway's current signer. That is fine for the log's own integrity, but a SEP **bundle is single-key**: `exportBundle()` signs the checkpoint with the current key and sets `bundle.public_key` to it, and the verifier checks every receipt against that one key. So a bundle assembled after a restart **verifies across the restart only if the gateway resumes with the same signing key.**

Because the proxy signs with an **ephemeral** key by default, `--persist` resolves a **stable** key from `AGA_GATEWAY_KEY` / `AGA_GATEWAY_KEY_FILE` when one is set (the same env contract `src/server.ts` honors) so durable evidence is verifiable end-to-end; with no stable key it falls back to ephemeral and **warns** that the exported bundle will not verify across a restart. `SepGateway` also warns if a replayed log's key differs from the current signer. **Key rotation across a restart is an open item:** rotating the seed makes the pre-rotation receipts (old key) and the post-rotation receipts (new key) unable to form a single verifiable bundle — a mixed-key log is rejected on replay by design.

## Non-goals (prototype)

- No concurrent-writer coordination — **one writer per path** (two live proxies on one path corrupt the chain); the file is not locked.
- No log rotation / compaction — the file grows unbounded.
- No encryption at rest — receipts are not secret and the key is never written.
- No external head-pointer — a truncation of the log tail is indistinguishable from a crash-mid-append at replay (an omission/availability concern, not a forgery one; the exported bundle re-checkpoints over the surviving receipts).

## Tests

`tests/sep/persistence.test.ts` proves, among other cases: record N with persistence on → a new gateway from the same path exports a bundle that **VERIFIES** with the **same receipt count and the same `merkle_root`** as pre-restart (the explicit cross-restart proof); a receipt appended after restart chains and verifies; a tampered / extra-field / foreign-key committed line throws on replay; a truncated final line is dropped and the rest replays; and persistence **off** writes no file and yields a byte-identical bundle.
