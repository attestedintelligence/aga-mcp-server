export type PublicKey = Uint8Array;
export type SecretKey = Uint8Array;
export interface KeyPair { publicKey: PublicKey; secretKey: SecretKey; }
export type Signature = Uint8Array;
export type HashHex = string;
export type SignatureBase64 = string;
export type SaltHex = string;

export interface SaltedCommitment {
  commitment: HashHex;
  salt: SaltHex;
}

export interface MerkleInclusionProof {
  leafHash: HashHex;
  leafIndex: number;
  siblings: Array<{ hash: HashHex; position: 'left' | 'right' }>;
  root: HashHex;
}
