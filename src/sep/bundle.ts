/**
 * SEP Evidence Bundle + the stateful SepGateway that the MCP server tools and the proxy
 * both build on. Single source of truth for evidence construction (CANONICAL_CONSTRUCTION_v2.md).
 */
import type { SepSigner } from './crypto.js';
import { newId } from './crypto.js';
import {
  SEP_ALGORITHM, buildReceipt, leafHash,
  type SepReceipt, type Decision,
} from './receipt.js';
import { merkleRoot, merkleProof, type MerkleProof } from './merkle.js';
import { buildCheckpoint, type SignedCheckpoint } from './checkpoint.js';

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

  constructor(opts: SepGatewayOptions) {
    this.gatewayId = opts.gatewayId;
    this.signer = opts.signer;
    this.policyReference = opts.policyReference ?? '';
    this.clock = opts.clock ?? (() => new Date().toISOString());
    this.idGen = opts.idGen ?? (() => newId('rcpt'));
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
    this.receipts.push(receipt);
    this.lastLeaf = leafHash(receipt);
    this.lastTimestamp = timestamp;
    return receipt;
  }

  /** Assemble the canonical SEP evidence bundle (receipts + merkle + mandatory signed checkpoint). */
  exportBundle(): SepBundle {
    if (this.receipts.length === 0) throw new Error('No receipts to export');
    const leaves = this.receipts.map(leafHash);
    const generated_at = this.clock();
    return {
      schema_version: '2.0',
      bundle_id: this.idGen(),
      algorithm: SEP_ALGORITHM,
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
