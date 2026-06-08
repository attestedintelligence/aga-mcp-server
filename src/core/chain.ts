import { sha256Str } from '../crypto/hash.js';
import { signStr, sigToB64, pkToHex } from '../crypto/sign.js';
import { canonicalize } from '../utils/canonical.js';
import { utcNow } from '../utils/timestamp.js';
import { uuid } from '../utils/uuid.js';
import { SCHEMA_VERSION, PROTOCOL_VERSION, TAXONOMY_VERSION } from '../utils/constants.js';
import type { KeyPair, HashHex } from '../crypto/types.js';
import type { ContinuityEvent, GenesisPayload, StructuralMetadata, EventType } from './types.js';

/** Leaf hash from structural metadata ONLY. Payload EXCLUDED. Uses "||" delimiter. */
export function computeLeafHash(m: StructuralMetadata): HashHex {
  return sha256Str([
    m.schema_version, m.protocol_version, m.event_type, m.event_id,
    String(m.sequence_number), m.timestamp, m.previous_leaf_hash ?? 'NULL'
  ].join('||'));
}

export function computePayloadHash(payload: unknown): HashHex {
  return sha256Str(canonicalize(payload));
}

function buildEvent(type: EventType, payload: unknown, seq: number, prevLeaf: HashHex | null, kp: KeyPair): ContinuityEvent {
  const id = uuid(), ts = utcNow();
  const meta: StructuralMetadata = {
    schema_version: SCHEMA_VERSION, protocol_version: PROTOCOL_VERSION,
    event_type: type, event_id: id, sequence_number: seq,
    timestamp: ts, previous_leaf_hash: prevLeaf,
  };
  const leafHash = computeLeafHash(meta);
  const payloadHash = computePayloadHash(payload);
  const sig = signStr(canonicalize({ ...meta, leaf_hash: leafHash, payload, payload_hash: payloadHash }), kp.secretKey);
  return {
    schema_version: SCHEMA_VERSION, protocol_version: PROTOCOL_VERSION,
    event_type: type, event_id: id, sequence_number: seq,
    timestamp: ts, previous_leaf_hash: prevLeaf,
    leaf_hash: leafHash, payload, payload_hash: payloadHash,
    event_signature: sigToB64(sig),
  };
}

export function createGenesisEvent(kp: KeyPair, specHash: HashHex): ContinuityEvent {
  const payload: GenesisPayload = {
    protocol_version: PROTOCOL_VERSION, taxonomy_version: TAXONOMY_VERSION,
    root_fingerprint: pkToHex(kp.publicKey), specification_hash: specHash, marker: 'GENESIS',
  };
  return buildEvent('GENESIS', payload, 0, null, kp);
}

export function appendEvent(type: EventType, payload: unknown, prev: ContinuityEvent, kp: KeyPair): ContinuityEvent {
  return buildEvent(type, payload, prev.sequence_number + 1, prev.leaf_hash, kp);
}

export function verifyChainIntegrity(events: ContinuityEvent[]): {
  valid: boolean; brokenAt: number | null; error: string | null;
} {
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    const meta: StructuralMetadata = {
      schema_version: e.schema_version, protocol_version: e.protocol_version,
      event_type: e.event_type, event_id: e.event_id,
      sequence_number: e.sequence_number, timestamp: e.timestamp,
      previous_leaf_hash: e.previous_leaf_hash,
    };
    if (e.leaf_hash !== computeLeafHash(meta))
      return { valid: false, brokenAt: e.sequence_number, error: `Leaf hash mismatch at seq ${e.sequence_number}` };
    if (i > 0 && e.previous_leaf_hash !== events[i - 1].leaf_hash)
      return { valid: false, brokenAt: e.sequence_number, error: `Chain linkage broken at seq ${e.sequence_number}` };
    if (e.payload_hash !== computePayloadHash(e.payload))
      return { valid: false, brokenAt: e.sequence_number, error: `Payload hash mismatch at seq ${e.sequence_number}` };
  }
  return { valid: true, brokenAt: null, error: null };
}
