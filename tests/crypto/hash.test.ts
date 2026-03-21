import { describe, it, expect } from 'vitest';
import { sha256Str, sha256Cat, sha256HexCat } from '../../src/crypto/hash.js';

describe('hash', () => {
  it('sha256 empty string matches known', () => {
    expect(sha256Str('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
  it('returns 64-char lowercase hex', () => { expect(sha256Str('hello')).toMatch(/^[0-9a-f]{64}$/); });
  it('sha256Cat is deterministic', () => { expect(sha256Cat('a', 'b')).toBe(sha256Cat('a', 'b')); });
  it('sha256Cat order matters', () => { expect(sha256Cat('a', 'b')).not.toBe(sha256Cat('b', 'a')); });
  it('sha256HexCat concatenates then hashes', () => {
    expect(sha256HexCat('abcd', 'ef01')).toBe(sha256Str('abcdef01'));
  });
});
