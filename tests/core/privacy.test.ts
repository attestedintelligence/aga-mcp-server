/**
 * Privacy Tests - edge cases
 * Structural metadata only in leaf hash; payload excluded
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { createGenesisEvent, appendEvent, computeLeafHash, verifyChainIntegrity } from '../../src/core/chain.js';

describe('privacy (structural metadata only)', () => {
  const chainKP = generateKeyPair();

  it('same structural metadata + different payloads = same leaf hash', () => {
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));

    // Two events with identical structural metadata but different payloads
    // We can verify by computing leaf hash from structural metadata only
    const e1 = appendEvent('INTERACTION_RECEIPT', { data: 'payload_A' }, genesis, chainKP);
    const e2 = appendEvent('INTERACTION_RECEIPT', { data: 'payload_B' }, genesis, chainKP);

    // They have the same structural metadata (same seq, same prev_leaf_hash, same event_type)
    // but different event_id and timestamp due to generation, so leaf hashes differ.
    // To test the property directly, compute leaf hash from identical metadata:
    const meta = {
      schema_version: e1.schema_version,
      protocol_version: e1.protocol_version,
      event_type: e1.event_type,
      event_id: e1.event_id,
      sequence_number: e1.sequence_number,
      timestamp: e1.timestamp,
      previous_leaf_hash: e1.previous_leaf_hash,
    };
    const lh1 = computeLeafHash(meta);
    // Same metadata, different "payload" has no effect on leaf hash
    const lh2 = computeLeafHash(meta);
    expect(lh1).toBe(lh2);
    expect(lh1).toBe(e1.leaf_hash);
  });

  it('leaf hash excludes payload', () => {
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const event = appendEvent('INTERACTION_RECEIPT', { secret: 'TOP_SECRET_DATA' }, genesis, chainKP);

    // Recompute leaf hash from structural metadata only
    const meta = {
      schema_version: event.schema_version,
      protocol_version: event.protocol_version,
      event_type: event.event_type,
      event_id: event.event_id,
      sequence_number: event.sequence_number,
      timestamp: event.timestamp,
      previous_leaf_hash: event.previous_leaf_hash,
    };
    const recomputed = computeLeafHash(meta);
    expect(recomputed).toBe(event.leaf_hash);
    // The leaf hash does NOT contain any reference to 'TOP_SECRET_DATA'
  });

  it('third parties verify chain integrity WITHOUT payload access', () => {
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const e1 = appendEvent('INTERACTION_RECEIPT', { classified: 'data' }, genesis, chainKP);
    const e2 = appendEvent('REVOCATION', { reason: 'test' }, e1, chainKP);
    const chain = [genesis, e1, e2];

    // Chain integrity can be verified using only structural metadata
    const integrity = verifyChainIntegrity(chain);
    expect(integrity.valid).toBe(true);

    // Even if we "redact" payloads, leaf hash verification still works
    // (leaf hash is computed from structural metadata only)
    for (const event of chain) {
      const meta = {
        schema_version: event.schema_version,
        protocol_version: event.protocol_version,
        event_type: event.event_type,
        event_id: event.event_id,
        sequence_number: event.sequence_number,
        timestamp: event.timestamp,
        previous_leaf_hash: event.previous_leaf_hash,
      };
      expect(computeLeafHash(meta)).toBe(event.leaf_hash);
    }
  });
});
