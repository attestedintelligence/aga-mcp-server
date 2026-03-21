/**
 * Subject measurement: hash, compare, detect drift.
 * Consolidates subject.ts + attestation.ts measurement logic.
 */
import { sha256Bytes, sha256Str } from '../crypto/hash.js';
import { canonicalize } from '../utils/canonical.js';
import type { SubjectIdentifier, SubjectMetadata, HashHex } from '../types.js';

export interface MeasurementInput {
  subjectBytes: Uint8Array;
  metadata: SubjectMetadata;
}

export interface MeasurementOutput {
  bytesHash: HashHex;
  metadataHash: HashHex;
}

export function measureSubject(input: MeasurementInput): MeasurementOutput {
  return {
    bytesHash: sha256Bytes(input.subjectBytes),
    metadataHash: sha256Str(canonicalize(input.metadata)),
  };
}

export function compareState(
  current: MeasurementOutput,
  expected: SubjectIdentifier,
): { match: boolean; bytesMatch: boolean; metadataMatch: boolean } {
  const bytesMatch = current.bytesHash === expected.bytes_hash;
  const metadataMatch = current.metadataHash === expected.metadata_hash;
  return { match: bytesMatch && metadataMatch, bytesMatch, metadataMatch };
}
