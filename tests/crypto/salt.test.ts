import { describe, it, expect } from 'vitest';
import { generateSalt, saltedCommitment, verifySaltedCommitment } from '../../src/crypto/salt.js';

describe('salted commitments', () => {
  it('salt is 32 hex chars', () => { expect(generateSalt()).toMatch(/^[0-9a-f]{32}$/); });
  it('deterministic with same salt', () => {
    const s = generateSalt();
    expect(saltedCommitment('x', s).commitment).toBe(saltedCommitment('x', s).commitment);
  });
  it('different salt → different commitment', () => {
    expect(saltedCommitment('x').commitment).not.toBe(saltedCommitment('x').commitment);
  });
  it('verify roundtrip', () => {
    const { commitment, salt } = saltedCommitment('evidence');
    expect(verifySaltedCommitment('evidence', salt, commitment)).toBe(true);
    expect(verifySaltedCommitment('wrong', salt, commitment)).toBe(false);
  });
});
