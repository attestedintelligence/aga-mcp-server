import { signStr, sigToB64 } from '../crypto/sign.js';
import { canonicalize } from '../utils/canonical.js';
import { utcNow } from '../utils/timestamp.js';
import { uuid } from '../utils/uuid.js';
import type { KeyPair } from '../crypto/types.js';
import type { DisclosureRequest, DisclosurePolicy, SubstitutionReceipt, DisclosureMode } from './types.js';

export interface DisclosureResult {
  permitted: boolean; disclosed_claim_id: string | null; disclosed_value: unknown;
  mode: DisclosureMode; was_substituted: boolean; substitution_receipt: SubstitutionReceipt | null;
}

export function processDisclosure(req: DisclosureRequest, policy: DisclosurePolicy, values: Record<string, unknown>, policyVersion: number, chainSeq: number, kp: KeyPair): DisclosureResult {
  const claim = policy.claims_taxonomy.find(c => c.claim_id === req.requested_claim_id);
  if (!claim) return { permitted: false, disclosed_claim_id: null, disclosed_value: null, mode: req.mode, was_substituted: false, substitution_receipt: null };
  if (claim.permitted_modes.includes(req.mode))
    return { permitted: true, disclosed_claim_id: claim.claim_id, disclosed_value: fv(values[claim.claim_id], req.mode), mode: req.mode, was_substituted: false, substitution_receipt: null };
  for (const subId of claim.substitutes) {
    const sub = policy.claims_taxonomy.find(c => c.claim_id === subId);
    if (sub?.permitted_modes.includes(req.mode) && !sub.inference_risks.includes(req.requested_claim_id))
      return { permitted: true, disclosed_claim_id: subId, disclosed_value: fv(values[subId], req.mode), mode: req.mode, was_substituted: true,
        substitution_receipt: sr(req.requested_claim_id, subId, policyVersion, 'SENSITIVITY_DENIED', chainSeq, kp) };
  }
  return { permitted: false, disclosed_claim_id: null, disclosed_value: null, mode: req.mode, was_substituted: false,
    substitution_receipt: sr(req.requested_claim_id, null, policyVersion, 'NO_PERMITTED_SUBSTITUTE', chainSeq, kp) };
}

function fv(v: unknown, m: DisclosureMode): unknown { return m === 'PROOF_ONLY' ? v != null : v; }
function sr(orig: string, sub: string | null, pv: number, reason: string, seq: number, kp: KeyPair): SubstitutionReceipt {
  const u = { receipt_id: uuid(), original_claim_id: orig, substitute_claim_id: sub, policy_version: pv, reason_code: reason, timestamp: utcNow(), chain_sequence_ref: seq };
  return { ...u, signature: sigToB64(signStr(canonicalize(u), kp.secretKey)) };
}
