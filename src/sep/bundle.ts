/**
 * SEP Evidence Bundle + the stateful SepGateway that the MCP server tools and the proxy
 * both build on. Single source of truth for evidence construction (CANONICAL_CONSTRUCTION_v2.md).
 */
import type { SepSigner } from './crypto.js';
import { newId } from './crypto.js';
import {
  buildReceipt, leafHash,
  type SepReceipt, type Decision,
} from './receipt.js';
import { merkleRoot, merkleProof, type MerkleProof } from './merkle.js';
import { buildCheckpoint, type SignedCheckpoint } from './checkpoint.js';
import { ReceiptLog } from './persistence.js';

export interface SepBundle {
  schema_version: string;
  bundle_id: string;
  algorithm: string;
  generated_at: string;
  gateway_id: string;
  public_key: string;
  policy_reference: string;
  receipts: SepReceipt[];
  merkle_root: string;
  merkle_proofs: MerkleProof[];
  checkpoint: SignedCheckpoint;
  offline_capable: boolean;
}

export interface SepGatewayOptions {
  gatewayId: string;
  signer: SepSigner;
  policyReference?: string;
  /** Injectable for deterministic tests; defaults to wall clock / random UUID. */
  clock?: () => string;
  idGen?: () => string;
  /**
   * OPT-IN restart persistence (prototype), default UNSET. When provided, this is the path to an
   * append-only JSONL log: every recorded receipt is appended + fsync'd at record() time, and an
   * existing log is replayed (re-verified: schema + signature + chain + single-key) on construction
   * so the in-memory ledger survives a process restart. Unset = pure in-memory (behavior unchanged;
   * no file is opened or written). The signing key is NEVER written to the log. A bundle assembled
   * after a restart verifies across the restart only if the gateway resumes with the SAME signing
   * key the log was written under (see src/sep/persistence.ts DESIGN + KNOWN_LIMITATIONS.md).
   */
  persistPath?: string;
}

export interface RecordInput {
  tool_name: string;
  decision: Decision;
  reason: string;
  arguments?: unknown;
  argumentsHash?: string;
  request_id?: string | number | null;
  method?: string;
  policy_reference?: string;
}

export class SepGateway {
  private readonly gatewayId: string;
  private readonly signer: SepSigner;
  private policyReference: string;
  private readonly clock: () => string;
  private readonly idGen: () => string;
  private readonly receipts: SepReceipt[] = [];
  private lastLeaf = '';
  private lastTimestamp = '';
  /** Opt-in append-only durable log; null = pure in-memory (default, behavior unchanged). */
  private readonly log: ReceiptLog | null;

  constructor(opts: SepGatewayOptions) {
    this.gatewayId = opts.gatewayId;
    this.signer = opts.signer;
    this.policyReference = opts.policyReference ?? '';
    this.clock = opts.clock ?? (() => new Date().toISOString());
    this.idGen = opts.idGen ?? (() => newId('rcpt'));

    // OPT-IN persistence: replay + re-verify an existing log so the ledger survives a restart. This
    // only restores already-signed receipts; it never re-signs or mutates the evidence core. Replay
    // throws loudly on a tampered/foreign committed line (never silently trusts the file).
    this.log = opts.persistPath ? new ReceiptLog(opts.persistPath) : null;
    if (this.log) {
      const replayed = this.log.replay();
      for (const r of replayed.receipts) this.receipts.push(r);
      this.lastLeaf = replayed.headLeaf;
      this.lastTimestamp = replayed.headTimestamp;
      // Provenance across restart is a SEPARATE axis (a stable signing key). If the recovered log was
      // signed by a DIFFERENT key than this gateway's current signer, the receipts self-verify but the
      // exported bundle (single-key: checkpoint + bundle.public_key are the current key) will NOT
      // verify as one artifact. Warn — do not fail (see KNOWN_LIMITATIONS.md → key lifecycle).
      if (replayed.headPublicKey && replayed.headPublicKey !== this.signer.publicKeyHex) {
        process.stderr.write(
          `[aga] persistence: replayed ${replayed.receipts.length} receipt(s) signed under a DIFFERENT key than the current gateway signer; ` +
          `the exported bundle will NOT verify as a single bundle until the gateway resumes with the log's original key ` +
          `(set a stable AGA_GATEWAY_KEY). See KNOWN_LIMITATIONS.md.\n`,
        );
      }
    }
  }

  get publicKeyHex(): string { return this.signer.publicKeyHex; }
  get count(): number { return this.receipts.length; }
  setPolicyReference(ref: string): void { this.policyReference = ref; }
  getReceipts(): readonly SepReceipt[] { return [...this.receipts]; }

  /** Record a governed tool-call decision as a signed, chained SEP receipt. */
  record(input: RecordInput): SepReceipt {
    // Monotonic timestamp: if the wall clock steps backward (NTP correction, VM migration),
    // clamp to the previous receipt's timestamp so the exported bundle always satisfies the
    // verifier's non-decreasing-timestamp check — a legitimately-recorded decision must never
    // land in a permanently-unverifiable bundle. ISO-8601 UTC strings compare chronologically.
    const now = this.clock();
    const timestamp = now >= this.lastTimestamp ? now : this.lastTimestamp;
    const receipt = buildReceipt({
      receipt_id: this.idGen(),
      timestamp,
      request_id: input.request_id ?? null,
      method: input.method,
      tool_name: input.tool_name,
      decision: input.decision,
      reason: input.reason,
      policy_reference: input.policy_reference ?? this.policyReference,
      arguments: input.arguments,
      argumentsHash: input.argumentsHash,
      previous_receipt_hash: this.lastLeaf,
      gateway_id: this.gatewayId,
    }, this.signer);
    // Durability BEFORE the in-memory commit (when persistence is on): append + fsync the signed
    // receipt first, so a failed/partial disk write throws and we do NOT advance lastLeaf/receipts —
    // the durable log and the in-memory ledger stay atomic. When persistence is off this is a no-op
    // and behavior is byte-identical to the pure in-memory path.
    if (this.log) this.log.append(receipt);
    this.receipts.push(receipt);
    this.lastLeaf = leafHash(receipt);
    this.lastTimestamp = timestamp;
    return receipt;
  }

  /**
   * Release the durable log's file handle (idempotent; no-op when persistence is off). Call on
   * gateway/proxy shutdown, or before reopening the same path from a fresh gateway.
   */
  close(): void {
    this.log?.close();
  }

  /** Assemble the canonical SEP evidence bundle (receipts + merkle + mandatory signed checkpoint). */
  exportBundle(): SepBundle {
    if (this.receipts.length === 0) throw new Error('No receipts to export');
    const leaves = this.receipts.map(leafHash);
    const generated_at = this.clock();
    return {
      schema_version: '2.0',
      bundle_id: this.idGen(),
      algorithm: this.signer.algorithm,
      generated_at,
      gateway_id: this.gatewayId,
      public_key: this.signer.publicKeyHex,
      policy_reference: this.policyReference,
      receipts: [...this.receipts],
      merkle_root: merkleRoot(leaves),
      merkle_proofs: leaves.map((_, i) => merkleProof(leaves, i)),
      checkpoint: buildCheckpoint(this.receipts, this.gatewayId, generated_at, this.signer),
      offline_capable: true,
    };
  }
}
