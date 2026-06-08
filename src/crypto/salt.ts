import { randomBytes } from 'node:crypto';
import { bytesToHex } from '@noble/hashes/utils';
import { sha256Cat } from './hash.js';
import type { SaltHex, SaltedCommitment, HashHex } from './types.js';

const enc = new TextEncoder();

export function generateSalt(): SaltHex { return bytesToHex(randomBytes(16)); }

export function saltedCommitment(content: Uint8Array | string, salt?: SaltHex): SaltedCommitment {
  const s = salt ?? generateSalt();
  const c = typeof content === 'string' ? enc.encode(content) : content;
  return { commitment: sha256Cat(c, s), salt: s };
}

export function verifySaltedCommitment(content: Uint8Array | string, salt: SaltHex, expected: HashHex): boolean {
  return saltedCommitment(content, salt).commitment === expected;
}
