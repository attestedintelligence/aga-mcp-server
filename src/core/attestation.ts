import { saltedCommitment, generateSalt } from '../crypto/salt.js';
import { sha256HexCat } from '../crypto/hash.js';
import type { SubjectIdentifier, EvidenceCommitmentRecord } from './types.js';
import type { HashHex, SaltHex } from '../crypto/types.js';

export interface AttestationInput {
  subject_identifier: SubjectIdentifier;
  policy_reference: HashHex;
  evidence_items: Array<{ label: string; content: string }>;
}

export interface AttestationResult {
  success: boolean;
  sealed_hash: HashHex | null;
  seal_salt: SaltHex | null;
  evidence_commitments: EvidenceCommitmentRecord[];
  rejection_reason: string | null;
}

export function performAttestation(input: AttestationInput): AttestationResult {
  const evidence_commitments = input.evidence_items.map(item => {
    const { commitment, salt } = saltedCommitment(item.content);
    return { commitment, salt, label: item.label };
  });
  const seal_salt = generateSalt();
  const sealed_hash = sha256HexCat(
    input.subject_identifier.bytes_hash,
    input.subject_identifier.metadata_hash,
    input.policy_reference,
    seal_salt
  );
  return { success: true, sealed_hash, seal_salt, evidence_commitments, rejection_reason: null };
}
