import { describe, it, expect } from 'vitest';
import { createGenesisEvent, appendEvent, verifyChainIntegrity, computeLeafHash } from '../../src/core/chain.js';
import { generateKeyPair } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';

describe('continuity chain', () => {
  const kp = generateKeyPair(), specHash = sha256Str('spec');
  it('genesis at seq 0', () => { const g = createGenesisEvent(kp, specHash); expect(g.sequence_number).toBe(0); expect(g.event_type).toBe('GENESIS'); });
  it('increments sequence', () => { const g = createGenesisEvent(kp, specHash); const e1 = appendEvent('POLICY_ISSUANCE', {}, g, kp); expect(e1.sequence_number).toBe(1); expect(e1.previous_leaf_hash).toBe(g.leaf_hash); });
  it('verifies intact chain', () => { const g = createGenesisEvent(kp, specHash); const e1 = appendEvent('ATTESTATION', {}, g, kp); expect(verifyChainIntegrity([g, e1]).valid).toBe(true); });
  it('detects tampered leaf', () => { const g = createGenesisEvent(kp, specHash); const e1 = appendEvent('ATTESTATION', {}, g, kp); expect(verifyChainIntegrity([g, { ...e1, leaf_hash: sha256Str('x') }]).valid).toBe(false); });
  it('detects tampered payload', () => { const g = createGenesisEvent(kp, specHash); const e1 = appendEvent('ATTESTATION', { a: 1 }, g, kp); expect(verifyChainIntegrity([g, { ...e1, payload: { a: 2 } }]).valid).toBe(false); });
  it('leaf hash excludes payload (Claim 3c)', () => {
    const g = createGenesisEvent(kp, specHash);
    const meta = { schema_version: g.schema_version, protocol_version: g.protocol_version, event_type: g.event_type, event_id: g.event_id, sequence_number: g.sequence_number, timestamp: g.timestamp, previous_leaf_hash: g.previous_leaf_hash };
    expect(computeLeafHash(meta)).toBe(g.leaf_hash);
  });
  it('supports REVOCATION event', () => { const g = createGenesisEvent(kp, specHash); const e1 = appendEvent('REVOCATION', { reason: 'test' }, g, kp); expect(e1.event_type).toBe('REVOCATION'); expect(verifyChainIntegrity([g, e1]).valid).toBe(true); });
});
