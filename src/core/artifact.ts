import { signStr, sigToB64, b64ToSig, pkToHex, hexToPk, verifyStr } from '../crypto/sign.js';
import { sha256Str } from '../crypto/hash.js';
import { canonicalize } from '../utils/canonical.js';
import { utcNow } from '../utils/timestamp.js';
import { SCHEMA_VERSION, PROTOCOL_VERSION } from '../utils/constants.js';
import type { KeyPair, HashHex } from '../crypto/types.js';
import type { PolicyArtifact, SubjectIdentifier, EnforcementParams, DisclosurePolicy, EvidenceCommitmentRecord } from './types.js';

export interface ArtifactInput {
  subject_identifier: SubjectIdentifier;
  policy_reference: HashHex;
  policy_version: number;
  sealed_hash: HashHex;
  seal_salt: string;
  enforcement_parameters: EnforcementParams;
  disclosure_policy: DisclosurePolicy;
  evidence_commitments: EvidenceCommitmentRecord[];
  issuer_keypair: KeyPair;
  effective_timestamp?: string;
  expiration_timestamp?: string | null;
}

export function generateArtifact(input: ArtifactInput): PolicyArtifact {
  const now = utcNow();
  const unsigned: Omit<PolicyArtifact, 'signature'> = {
    schema_version: SCHEMA_VERSION, protocol_version: PROTOCOL_VERSION,
    subject_identifier: input.subject_identifier, policy_reference: input.policy_reference,
    policy_version: input.policy_version, sealed_hash: input.sealed_hash,
    seal_salt: input.seal_salt, issued_timestamp: now,
    effective_timestamp: input.effective_timestamp ?? now,
    expiration_timestamp: input.expiration_timestamp ?? null,
    issuer_identifier: pkToHex(input.issuer_keypair.publicKey),
    enforcement_parameters: input.enforcement_parameters,
    disclosure_policy: input.disclosure_policy,
    evidence_commitments: input.evidence_commitments,
  };
  return { ...unsigned, signature: sigToB64(signStr(canonicalize(unsigned), input.issuer_keypair.secretKey)) };
}

export function hashArtifact(a: PolicyArtifact): HashHex { return sha256Str(canonicalize(a)); }

export function verifyArtifactSignature(a: PolicyArtifact, issuerPkHex: string): boolean {
  const { signature, ...unsigned } = a;
  return verifyStr(b64ToSig(signature), canonicalize(unsigned), hexToPk(issuerPkHex));
}
