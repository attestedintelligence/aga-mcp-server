/**
 * Portal (Sentinel) - Runtime Enforcement Boundary. Ref 150, 270-280.
 * V3: TTL + revocation checked every measurement. Fail-closed semantics.
 * Aligned with NCCoE filing Sections 3-4 and NIST-2025-0035.
 */
import { sha256Bytes, sha256Str } from '../crypto/hash.js';
import { b64ToSig, hexToPk, verifyStr } from '../crypto/sign.js';
import { canonicalize } from '../utils/canonical.js';
import { isWithinPeriod, isExpired, utcNow } from '../utils/timestamp.js';
import type { PolicyArtifact, PortalState, EnforcementAction, SubjectMetadata } from './types.js';
import type { HashHex } from '../crypto/types.js';

export interface MeasurementResult {
  match: boolean;
  currentBytesHash: HashHex;
  currentMetaHash: HashHex;
  expectedBytesHash: HashHex;
  expectedMetaHash: HashHex;
  ttl_ok: boolean;
  revoked: boolean;
}

export class Portal {
  state: PortalState = 'INITIALIZATION';
  artifact: PolicyArtifact | null = null;
  sequenceCounter = 0;
  lastLeafHash: HashHex | null = null;
  revocations: Set<string> = new Set();

  loadArtifact(artifact: PolicyArtifact, pinnedPkHex: string): { ok: boolean; error?: string } {
    this.state = 'ARTIFACT_VERIFICATION';
    const { signature, ...unsigned } = artifact;
    if (!verifyStr(b64ToSig(signature), canonicalize(unsigned), hexToPk(pinnedPkHex))) {
      this.state = 'TERMINATED'; return { ok: false, error: 'Signature verification failed' };
    }
    if (!isWithinPeriod(utcNow(), artifact.effective_timestamp, artifact.expiration_timestamp)) {
      this.state = 'TERMINATED'; return { ok: false, error: 'Artifact outside effective period' };
    }
    if (this.revocations.has(artifact.sealed_hash)) {
      this.state = 'TERMINATED'; return { ok: false, error: 'Artifact has been revoked' };
    }
    this.artifact = artifact;
    this.state = 'ACTIVE_MONITORING';
    return { ok: true };
  }

  measure(subjectBytes: Uint8Array, meta: SubjectMetadata): MeasurementResult {
    if (!this.artifact) throw new Error('No artifact loaded');
    if (this.state === 'TERMINATED') throw new Error('Portal is terminated');
    if (this.state === 'SAFE_STATE') throw new Error('Portal is in safe state - artifact revoked');
    const empty = { currentBytesHash: '', currentMetaHash: '',
      expectedBytesHash: this.artifact.subject_identifier.bytes_hash,
      expectedMetaHash: this.artifact.subject_identifier.metadata_hash };

    // Fail-closed: TTL check
    const ttl_ok = !isExpired(this.artifact.issued_timestamp, this.artifact.enforcement_parameters.ttl_seconds);
    if (!ttl_ok) { this.state = 'TERMINATED'; return { match: false, ttl_ok: false, revoked: false, ...empty }; }

    // Fail-closed: revocation check
    if (this.revocations.has(this.artifact.sealed_hash)) {
      this.state = 'TERMINATED'; return { match: false, ttl_ok: true, revoked: true, ...empty };
    }

    const currentBytesHash = sha256Bytes(subjectBytes);
    const currentMetaHash = sha256Str(canonicalize(meta));
    const match = currentBytesHash === this.artifact.subject_identifier.bytes_hash &&
                  currentMetaHash === this.artifact.subject_identifier.metadata_hash;

    if (!match && this.state === 'ACTIVE_MONITORING') this.state = 'DRIFT_DETECTED';
    return { match, currentBytesHash, currentMetaHash,
      expectedBytesHash: this.artifact.subject_identifier.bytes_hash,
      expectedMetaHash: this.artifact.subject_identifier.metadata_hash,
      ttl_ok: true, revoked: false };
  }

  enforce(action: EnforcementAction): void {
    if (this.state !== 'DRIFT_DETECTED') throw new Error(`Cannot enforce in state ${this.state}`);
    switch (action) {
      case 'TERMINATE': this.state = 'TERMINATED'; break;
      case 'SAFE_STATE': this.state = 'SAFE_STATE'; break;
      case 'QUARANTINE': this.state = 'PHANTOM_QUARANTINE'; break;
      case 'ALERT_ONLY': this.state = 'ACTIVE_MONITORING'; break;
      default: break;
    }
  }

  revoke(sealedHash: string, transitionTo?: 'TERMINATED' | 'SAFE_STATE'): void {
    this.revocations.add(sealedHash);
    if (this.artifact?.sealed_hash === sealedHash) {
      this.state = transitionTo === 'SAFE_STATE' ? 'SAFE_STATE' : 'TERMINATED';
    }
  }

  isRevoked(sealedHash: string): boolean { return this.revocations.has(sealedHash); }

  reset(): void {
    this.state = 'INITIALIZATION'; this.artifact = null;
    this.sequenceCounter = 0; this.lastLeafHash = null;
  }
}
