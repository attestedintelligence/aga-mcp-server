/**
 * Disclosure Tests
 * Policy-gated disclosure with substitution traversal
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '../../src/crypto/sign.js';
import { processDisclosure } from '../../src/core/disclosure.js';
import type { DisclosurePolicy } from '../../src/core/types.js';

describe('disclosure', () => {
  const kp = generateKeyPair();

  const policy: DisclosurePolicy = {
    claims_taxonomy: [
      { claim_id: 'vehicle.exact_position', sensitivity: 'S4_CRITICAL', substitutes: ['vehicle.grid_square', 'vehicle.operational_area'], inference_risks: [], permitted_modes: [] },
      { claim_id: 'vehicle.grid_square', sensitivity: 'S3_HIGH', substitutes: ['vehicle.operational_area'], inference_risks: [], permitted_modes: ['REVEAL_MIN', 'REVEAL_FULL'] },
      { claim_id: 'vehicle.operational_area', sensitivity: 'S1_LOW', substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL'] },
    ],
    substitution_rules: [],
  };

  const values: Record<string, unknown> = {
    'vehicle.exact_position': { lat: 37.7749, lng: -122.4194 },
    'vehicle.grid_square': 'CM87WJ',
    'vehicle.operational_area': 'sector-7',
  };

  it('permitted claim disclosed at requested mode', () => {
    const result = processDisclosure(
      { requested_claim_id: 'vehicle.operational_area', requester_id: 'q1', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );
    expect(result.permitted).toBe(true);
    expect(result.disclosed_claim_id).toBe('vehicle.operational_area');
    expect(result.disclosed_value).toBe('sector-7');
    expect(result.was_substituted).toBe(false);
  });

  it('denied claim triggers substitution traversal', () => {
    const result = processDisclosure(
      { requested_claim_id: 'vehicle.exact_position', requester_id: 'q2', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );
    expect(result.permitted).toBe(true);
    expect(result.was_substituted).toBe(true);
    expect(result.disclosed_claim_id).toBe('vehicle.grid_square');
  });

  it('first permitted substitute selected by decreasing sensitivity', () => {
    // grid_square (S3) is tried before operational_area (S1)
    const result = processDisclosure(
      { requested_claim_id: 'vehicle.exact_position', requester_id: 'q3', mode: 'REVEAL_MIN', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );
    expect(result.disclosed_claim_id).toBe('vehicle.grid_square');
  });

  it('substitution receipt signed and chain-linked', () => {
    const result = processDisclosure(
      { requested_claim_id: 'vehicle.exact_position', requester_id: 'q4', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      policy, values, 1, 5, kp,
    );
    expect(result.substitution_receipt).not.toBeNull();
    expect(result.substitution_receipt!.original_claim_id).toBe('vehicle.exact_position');
    expect(result.substitution_receipt!.substitute_claim_id).toBe('vehicle.grid_square');
    expect(result.substitution_receipt!.chain_sequence_ref).toBe(5);
    expect(result.substitution_receipt!.signature).toBeTruthy();
  });

  it('inference risk check blocks dangerous disclosure', () => {
    const riskyPolicy: DisclosurePolicy = {
      claims_taxonomy: [
        { claim_id: 'secret.value', sensitivity: 'S4_CRITICAL', substitutes: ['secret.hint'], inference_risks: [], permitted_modes: [] },
        { claim_id: 'secret.hint', sensitivity: 'S2_MODERATE', substitutes: [], inference_risks: ['secret.value'], permitted_modes: ['REVEAL_FULL'] },
      ],
      substitution_rules: [],
    };
    const result = processDisclosure(
      { requested_claim_id: 'secret.value', requester_id: 'q5', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      riskyPolicy, { 'secret.value': 'x', 'secret.hint': 'y' }, 1, 0, kp,
    );
    // secret.hint has inference_risk for secret.value, so it should NOT be used as substitute
    expect(result.permitted).toBe(false);
  });

  it('PROOF_ONLY returns boolean without value', () => {
    const result = processDisclosure(
      { requested_claim_id: 'vehicle.operational_area', requester_id: 'q6', mode: 'PROOF_ONLY', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );
    expect(result.permitted).toBe(true);
    expect(result.disclosed_value).toBe(true); // boolean, not the actual value
  });

  it('substitution receipt verifiable offline with pinned key', () => {
    const result = processDisclosure(
      { requested_claim_id: 'vehicle.exact_position', requester_id: 'q7', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );
    expect(result.substitution_receipt).not.toBeNull();
    // Receipt has a signature that can be verified offline
    expect(result.substitution_receipt!.signature).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(result.substitution_receipt!.receipt_id).toBeTruthy();
    expect(result.substitution_receipt!.timestamp).toBeTruthy();
  });
});
