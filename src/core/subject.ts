import { sha256Bytes, sha256Str } from '../crypto/hash.js';
import { canonicalize } from '../utils/canonical.js';
import type { SubjectIdentifier, SubjectMetadata } from './types.js';

export function computeSubjectId(bytes: Uint8Array, meta: SubjectMetadata): SubjectIdentifier {
  return { bytes_hash: sha256Bytes(bytes), metadata_hash: sha256Str(canonicalize(meta)) };
}

export function computeSubjectIdFromString(content: string, meta: SubjectMetadata): SubjectIdentifier {
  return computeSubjectId(new TextEncoder().encode(content), meta);
}
