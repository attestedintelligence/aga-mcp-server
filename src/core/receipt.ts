/** V3: measurement_type field. Receipts generated for EVERY measurement. */
import { signStr, sigToB64 } from '../crypto/sign.js';
import { canonicalize } from '../utils/canonical.js';
import { utcNow } from '../utils/timestamp.js';
import { uuid } from '../utils/uuid.js';
import type { KeyPair, HashHex } from '../crypto/types.js';
import type { SignedReceipt, SubjectIdentifier, EnforcementAction } from './types.js';

export interface ReceiptInput {
  subjectId: SubjectIdentifier;
  artifactRef: HashHex;
  currentHash: string;
  sealedHash: string;
  driftDetected: boolean;
  driftDescription: string | null;
  action: EnforcementAction | null;
  measurementType: string;
  seq: number;
  prevLeaf: HashHex | null;
  portalKP: KeyPair;
}

export function generateReceipt(input: ReceiptInput): SignedReceipt {
  const unsigned = {
    receipt_id: uuid(), subject_identifier: input.subjectId,
    artifact_reference: input.artifactRef, current_hash: input.currentHash,
    sealed_hash: input.sealedHash, drift_detected: input.driftDetected,
    drift_description: input.driftDescription, enforcement_action: input.action,
    measurement_type: input.measurementType, timestamp: utcNow(),
    sequence_number: input.seq, previous_leaf_hash: input.prevLeaf,
  };
  return { ...unsigned, portal_signature: sigToB64(signStr(canonicalize(unsigned), input.portalKP.secretKey)) };
}
