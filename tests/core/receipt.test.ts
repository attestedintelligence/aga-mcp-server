/**
 * Receipt Tests
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPair, pkToHex } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { generateReceipt } from '../../src/core/receipt.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';
import { createGenesisEvent, appendEvent } from '../../src/core/chain.js';

describe('receipt', () => {
  const portalKP = generateKeyPair();
  const chainKP = generateKeyPair();
  const subId = computeSubjectIdFromString('test binary', { filename: 'test.bin' });

  it('contains timestamp, sequence_number, previous_leaf_hash, artifact_reference', () => {
    const r = generateReceipt({
      subjectId: subId, artifactRef: sha256Str('artifact-ref'),
      currentHash: 'abc', sealedHash: 'abc',
      driftDetected: false, driftDescription: null, action: null,
      measurementType: 'EXECUTABLE_IMAGE', seq: 42, prevLeaf: sha256Str('prev'), portalKP,
    });

    expect(r.timestamp).toBeTruthy();
    expect(r.sequence_number).toBe(42);
    expect(r.previous_leaf_hash).toBe(sha256Str('prev'));
    expect(r.artifact_reference).toBe(sha256Str('artifact-ref'));
  });

  it('receipt signed by portal key', () => {
    const r = generateReceipt({
      subjectId: subId, artifactRef: sha256Str('ref'),
      currentHash: 'x', sealedHash: 'y',
      driftDetected: true, driftDescription: 'drift', action: 'QUARANTINE',
      measurementType: 'EXECUTABLE_IMAGE', seq: 1, prevLeaf: null, portalKP,
    });

    expect(r.portal_signature).toBeTruthy();
    expect(r.portal_signature).toMatch(/^[A-Za-z0-9+/]+=*$/); // base64
  });

  it('receipt appended to chain as INTERACTION_RECEIPT', () => {
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));

    const r = generateReceipt({
      subjectId: subId, artifactRef: sha256Str('ref'),
      currentHash: 'abc', sealedHash: 'abc',
      driftDetected: false, driftDescription: null, action: null,
      measurementType: 'EXECUTABLE_IMAGE', seq: 1, prevLeaf: genesis.leaf_hash, portalKP,
    });

    const event = appendEvent('INTERACTION_RECEIPT', r, genesis, chainKP);
    expect(event.event_type).toBe('INTERACTION_RECEIPT');
    expect(event.sequence_number).toBe(1);
    expect((event.payload as any).receipt_id).toBe(r.receipt_id);
  });
});
