/**
 * Quarantine Tests
 * Phantom execution with forensic capture
 */
import { describe, it, expect } from 'vitest';
import { initQuarantine, captureInput, releaseQuarantine } from '../../src/core/quarantine.js';
import { generateKeyPair } from '../../src/crypto/sign.js';
import { generateReceipt } from '../../src/core/receipt.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { createGenesisEvent, appendEvent } from '../../src/core/chain.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';

describe('quarantine', () => {
  it('quarantine severs outputs (protected resources disconnected)', () => {
    const q = initQuarantine();
    expect(q.active).toBe(true);
    expect(q.outputs_severed).toBe(true);
    expect(q.started_at).toBeTruthy();
  });

  it('quarantine continues inputs (forensic capture)', () => {
    const q = initQuarantine();
    captureInput(q, 'network_packet', { src: '10.0.0.1', payload: 'exfiltrate' });
    captureInput(q, 'command', 'rm -rf /');
    expect(q.inputs_captured).toBe(2);
    expect(q.forensic_buffer).toHaveLength(2);
  });

  it('forensic capture logs all activity', () => {
    const q = initQuarantine();
    captureInput(q, 'attacker_command', 'modify_config');
    captureInput(q, 'attacker_command', 'exfiltrate_data');
    captureInput(q, 'system_event', 'unauthorized_access');

    expect(q.forensic_buffer).toHaveLength(3);
    expect(q.forensic_buffer[0].type).toBe('attacker_command');
    expect(q.forensic_buffer[0].data).toBe('modify_config');
    expect(q.forensic_buffer[2].type).toBe('system_event');
    // Each entry has a timestamp
    for (const entry of q.forensic_buffer) {
      expect(entry.timestamp).toBeTruthy();
    }
  });

  it('quarantine exits on release - Section G', () => {
    const q = initQuarantine();
    captureInput(q, 'cmd', 'test');
    const result = releaseQuarantine(q);
    expect(q.active).toBe(false);
    expect(result.total_captures).toBe(1);
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('forensic receipts appended to chain - Section G', () => {
    const chainKP = generateKeyPair();
    const portalKP = generateKeyPair();
    const subId = computeSubjectIdFromString('test', { filename: 'test.bin' });

    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));

    // Create quarantine and capture forensic data
    const q = initQuarantine();
    captureInput(q, 'attacker', 'payload');

    // Generate forensic receipt
    const forensicReceipt = generateReceipt({
      subjectId: subId, artifactRef: sha256Str('artref'),
      currentHash: sha256Str('forensic_data'),
      sealedHash: sha256Str('sealed'),
      driftDetected: true, driftDescription: 'Forensic capture during quarantine',
      action: 'QUARANTINE', measurementType: 'EXECUTABLE_IMAGE',
      seq: 1, prevLeaf: genesis.leaf_hash, portalKP,
    });

    // Append to chain
    const e1 = appendEvent('INTERACTION_RECEIPT', forensicReceipt, genesis, chainKP);
    expect(e1.event_type).toBe('INTERACTION_RECEIPT');
    expect(e1.sequence_number).toBe(1);
    expect(e1.previous_leaf_hash).toBe(genesis.leaf_hash);
  });
});
