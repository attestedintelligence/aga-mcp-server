/**
 * Project a scenario's continuity-chain governance decisions into a canonical SEP evidence
 * bundle via src/sep — so the public demo artifacts conform to CANONICAL_CONSTRUCTION_v2.md
 * and verify under aga-verify / verify-sep.mjs. Faithful projection of the SAME decisions:
 * a clean measurement -> PERMITTED, a drift detection -> DENIED.
 */
import { SepGateway, signerFromSeed, type SepBundle } from '../src/sep/index.js';
import type { SignedReceipt } from '../src/core/types.js';

export function projectSepBundle(gatewayId: string, seed: Uint8Array, receipts: SignedReceipt[]): SepBundle {
  const gw = new SepGateway({ gatewayId, signer: signerFromSeed(seed) });
  for (const r of receipts) {
    gw.record({
      tool_name: r.measurement_type ?? 'measure_integrity',
      decision: r.drift_detected ? 'DENIED' : 'PERMITTED',
      reason: r.drift_description ?? 'clean measurement (no drift)',
      argumentsHash: r.current_hash ?? '',
      request_id: String(r.sequence_number),
    });
  }
  return gw.exportBundle();
}
