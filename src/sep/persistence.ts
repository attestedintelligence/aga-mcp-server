/**
 * SEP evidence ledger — OPT-IN restart persistence (PROTOTYPE).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * DESIGN
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * MODEL. The proxy's SepGateway keeps its ledger (receipts[] + chain head) in memory, so a
 * restart/crash loses every receipt recorded since the last export. This module adds an OPT-IN,
 * append-only, on-disk mirror of that ledger so it survives a restart. It is deliberately narrow:
 *
 *   - It SAVES already-signed receipts and REPLAYS them. It NEVER re-signs, re-hashes, or mutates
 *     a receipt, and it never touches the signing/verification core (receipt/canonical/merkle/
 *     checkpoint/crypto/hybrid). A replayed ledger produces a bundle that verifies identically to
 *     one built without a restart — same verdict, same merkle_root — because the leaves are the
 *     exact bytes that were signed.
 *   - The on-disk format is JSONL: one signed SEP receipt as a compact JSON object per line, in
 *     record order. `JSON.stringify(receipt)` → `JSON.parse` is lossless here because a receipt is
 *     flat scalars (string | null) only — no numbers, no floats, no nested objects — so the parsed
 *     receipt canonicalizes to the identical bytes and yields the identical leaf hash.
 *   - The signing KEY is never written to the log. A log carries only public material (each receipt
 *     already embeds its own `public_key`). Durable *provenance* across restart is a separate axis
 *     (a stable gateway key, e.g. AGA_GATEWAY_KEY) — see the provenance note below and
 *     KNOWN_LIMITATIONS.md.
 *
 * CRASH-SAFETY. Each `append()` writes one newline-terminated line with `writeSync` followed by
 * `fsyncSync`, so a returned `append()` means the receipt's bytes are durably on disk (subject to
 * the filesystem honoring fsync). The durable unit is a NEWLINE-TERMINATED line. A crash mid-append
 * can leave a trailing partial line that is NOT newline-terminated; on the next `replay()` that
 * unterminated remainder is DROPPED and the file is truncated back to the last complete line, so a
 * crash costs at most the one in-flight receipt and never wedges the log. (Directory-entry fsync and
 * fsync-lying hardware are out of scope for this prototype — noted in KNOWN_LIMITATIONS.md.)
 *
 * REPLAY-VERIFICATION GUARANTEE. `replay()` never silently trusts the file. Every COMPLETE (newline-
 * terminated) line is re-verified with the EXISTING verify primitives before it enters the ledger:
 *   (1) STRICT SCHEMA — exactly the 15 canonical receipt fields (rejects extra / unknown / injected
 *       keys), and a registered algorithm + a profile-well-formed public_key.
 *   (2) SIGNATURE — Ed25519 (v1) / composite (v2) over canon(receipt minus "signature") under the
 *       receipt's OWN public_key, via `verifyForProfile` (the same primitive verify.ts §6.2 uses).
 *   (3) CHAIN LINKAGE — `previous_receipt_hash` equals the leaf of the prior replayed receipt (''
 *       for the first), so reordering or a foreign-chain splice is rejected.
 *   (4) SINGLE-KEY-PER-LOG — every line shares the first line's public_key + algorithm. This mirrors
 *       the SEP bundle invariant (one gateway key per bundle) and rejects a foreign receipt spliced
 *       in under a different key EVEN IF the attacker forges its chain link with their own key.
 * A COMPLETE line that fails ANY of these is treated as tampering/corruption and REJECTED LOUDLY
 * (throws {@link ReceiptLogError}) — the ledger is never partially/silently loaded. Only the single
 * unterminated trailing remainder is tolerated (dropped as a crash artifact), never a committed line.
 *
 * PROVENANCE NOTE (key across restart). Replay validates each line under the key it was signed with,
 * which may differ from the gateway's CURRENT signer. That is fine for the log's own integrity, but
 * a SEP bundle is single-key: `exportBundle()` signs the checkpoint with the current key and sets
 * `bundle.public_key` to it, and the verifier checks every receipt against that one key. So a bundle
 * assembled after a restart VERIFIES across the restart only if the gateway resumes with the SAME
 * signing key the log was written under (a persisted key). With an ephemeral key that rotates on
 * restart, the replayed receipts still load and self-verify, but the exported bundle will not verify
 * as a single artifact. `replay()` surfaces the log's head key so the caller can warn on mismatch.
 *
 * SCOPE / NON-GOALS (prototype). No concurrent-writer coordination (one writer per path — see below),
 * no log rotation / compaction (the file grows unbounded), no encryption at rest (receipts are not
 * secret; the key is never written), no external head-pointer — so a truncation of the tail is
 * indistinguishable from a crash-mid-append at replay time (an availability/omission concern, not a
 * forgery one; the exported bundle re-checkpoints over the surviving receipts). These are tracked as
 * open risks, not silently ignored.
 *
 * CONCURRENCY. A single `ReceiptLog` (one SepGateway) must own a path. Two live writers appending to
 * one path will interleave/duplicate lines and corrupt the chain; this prototype does NOT lock the
 * file. Point each proxy instance at its own path.
 *
 * Copyright (c) 2026 Attested Intelligence Holdings LLC
 * SPDX-License-Identifier: MIT
 */

import {
  openSync, writeSync, fsyncSync, closeSync, existsSync, readFileSync, truncateSync,
} from 'node:fs';
import { canonicalize } from './canonical.js';
import { leafHash, SEP_RECEIPT_FIELDS, type SepReceipt } from './receipt.js';
import { isRegisteredProfile, validPublicKeyForProfile, verifyForProfile } from './profiles.js';

/** Thrown when a COMPLETE (committed) on-disk line is not a valid, chained, well-signed receipt. */
export class ReceiptLogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReceiptLogError';
  }
}

/** Outcome of replaying an on-disk log. */
export interface ReplayResult {
  /** Receipts recovered, in order, each already re-verified (schema + signature + chain + single-key). */
  receipts: SepReceipt[];
  /** Leaf hash of the last recovered receipt (the chain head the next record() must link to); '' if none. */
  headLeaf: string;
  /** Timestamp of the last recovered receipt (restores the monotonic clock floor); '' if none. */
  headTimestamp: string;
  /** The public_key every recovered receipt was signed under; null if the log was empty. */
  headPublicKey: string | null;
  /** True iff a partial/unterminated final line (a crash mid-append) was detected and dropped. */
  droppedPartialFinalLine: boolean;
}

const strip = (o: Record<string, unknown>, f: string): Record<string, unknown> =>
  Object.fromEntries(Object.entries(o).filter(([k]) => k !== f));

/** Exactly the canonical fields — no extra, unknown, or "__proto__"-injected key (mirrors verify.ts). */
const hasExactKeys = (o: unknown, fields: readonly string[]): boolean => {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  const keys = Object.keys(o as Record<string, unknown>);
  return keys.length === fields.length && fields.every((k) => Object.prototype.hasOwnProperty.call(o, k));
};

/**
 * Re-verify one recovered receipt with the EXISTING primitives. Throws {@link ReceiptLogError} on any
 * failure (loud rejection — the ledger is never partially/silently loaded).
 * @param chainKey the public_key established by the first recovered receipt, or null for the first.
 * @param chainAlg the algorithm established by the first recovered receipt, or null for the first.
 */
function verifyRecoveredReceipt(
  parsed: unknown,
  priorLeaf: string,
  chainKey: string | null,
  chainAlg: string | null,
  lineNo: number,
): SepReceipt {
  if (!hasExactKeys(parsed, SEP_RECEIPT_FIELDS)) {
    throw new ReceiptLogError(`line ${lineNo}: not a canonical SEP receipt (must carry exactly the ${SEP_RECEIPT_FIELDS.length} signed fields — extra/unknown/missing key)`);
  }
  const r = parsed as SepReceipt;
  const alg = r.algorithm;
  const pub = r.public_key;
  if (!isRegisteredProfile(alg)) {
    throw new ReceiptLogError(`line ${lineNo}: unregistered algorithm '${String(alg)}'`);
  }
  if (!validPublicKeyForProfile(alg, pub)) {
    throw new ReceiptLogError(`line ${lineNo}: malformed public_key for profile '${alg}'`);
  }
  // Single-key-per-log: mirrors the SEP bundle's one-key invariant. Rejects a foreign receipt spliced
  // in under a different key even if its chain link is forged with that other key.
  if (chainKey !== null && (pub !== chainKey || alg !== chainAlg)) {
    throw new ReceiptLogError(`line ${lineNo}: key/algorithm differs from the rest of the log (foreign or mixed-key receipt)`);
  }
  // Signature over canon(receipt minus "signature"), under the receipt's OWN key — same primitive as
  // verify.ts §6.2. Any field mutation breaks this.
  if (!verifyForProfile(alg, pub, canonicalize(strip(r as unknown as Record<string, unknown>, 'signature')), r.signature)) {
    throw new ReceiptLogError(`line ${lineNo}: signature verification failed (tampered or foreign line)`);
  }
  // Chain linkage: must point at the leaf of the prior recovered receipt ('' for the first).
  if ((r.previous_receipt_hash || '') !== priorLeaf) {
    throw new ReceiptLogError(`line ${lineNo}: chain linkage broken (previous_receipt_hash does not match the prior leaf — reordered/spliced)`);
  }
  return r;
}

/**
 * Append-only JSONL receipt log with crash-safe (fsync) appends and replay-with-verification.
 * One instance owns one path; do not point two live writers at the same file (see DESIGN → CONCURRENCY).
 */
export class ReceiptLog {
  private readonly path: string;
  private fd: number | null = null;

  constructor(path: string) {
    this.path = path;
  }

  /**
   * Read + re-verify the existing log. Drops a single unterminated trailing line (crash mid-append)
   * and truncates the file back to the last complete line. Throws {@link ReceiptLogError} if any
   * COMPLETE line is not a valid, chained, well-signed, single-key receipt.
   */
  replay(): ReplayResult {
    const empty: ReplayResult = { receipts: [], headLeaf: '', headTimestamp: '', headPublicKey: null, droppedPartialFinalLine: false };
    if (!existsSync(this.path)) return empty;

    const content = readFileSync(this.path, 'utf8');
    if (content.length === 0) return empty;

    // The durable unit is a newline-terminated line. Everything up to and including the last '\n' is
    // "committed"; anything after it is an unterminated remainder from a crash mid-append → drop it.
    const lastNl = content.lastIndexOf('\n');
    const committed = lastNl === -1 ? '' : content.slice(0, lastNl + 1);
    const remainder = content.slice(lastNl + 1);
    const droppedPartialFinalLine = remainder.length > 0;
    if (droppedPartialFinalLine) {
      truncateSync(this.path, Buffer.byteLength(committed, 'utf8'));
    }

    const receipts: SepReceipt[] = [];
    let priorLeaf = '';
    let headTimestamp = '';
    let chainKey: string | null = null;
    let chainAlg: string | null = null;

    if (committed.length > 0) {
      const lines = committed.split('\n');
      lines.pop(); // trailing '' after the final '\n'
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // A committed (newline-terminated) line must be a valid receipt. A blank or unparseable
        // committed line is corruption/tampering, NOT a crash artifact → reject loudly.
        let parsed: unknown;
        try {
          parsed = JSON.parse(line);
        } catch {
          throw new ReceiptLogError(`line ${i + 1}: not valid JSON (a committed line is corrupt — tampered or truncated mid-log)`);
        }
        const r = verifyRecoveredReceipt(parsed, priorLeaf, chainKey, chainAlg, i + 1);
        receipts.push(r);
        priorLeaf = leafHash(r);
        headTimestamp = r.timestamp;
        if (chainKey === null) { chainKey = r.public_key; chainAlg = r.algorithm; }
      }
    }

    return { receipts, headLeaf: priorLeaf, headTimestamp, headPublicKey: chainKey, droppedPartialFinalLine };
  }

  /**
   * Append one already-signed receipt as a newline-terminated JSON line, then fsync. On return the
   * receipt is durably on disk. Throws on I/O failure (the caller must NOT advance in-memory state).
   */
  append(receipt: SepReceipt): void {
    if (this.fd === null) this.fd = openSync(this.path, 'a');
    writeSync(this.fd, JSON.stringify(receipt) + '\n');
    fsyncSync(this.fd);
  }

  /** Close the append handle (idempotent). Call on gateway shutdown / before reopening the same path. */
  close(): void {
    if (this.fd !== null) {
      closeSync(this.fd);
      this.fd = null;
    }
  }
}
