export const CRYPTO_PRIMITIVES_DOC = `# AGA Cryptographic Primitives

## Ed25519 Digital Signatures
- Library: @noble/ed25519 v2.1.0
- Key size: 256-bit (32 bytes)
- Signature size: 512-bit (64 bytes)
- Used for: Artifact signing, receipt signing, chain event signing

## SHA-256 Hashing
- Library: @noble/hashes v1.7.0
- Output: 256-bit (64 hex characters)
- Used for: Sealed hash, leaf hash, payload hash, subject identity

## Sealed Hash Construction
\`\`\`
sealed_hash = SHA-256(bytes_hash || metadata_hash || policy_reference || seal_salt)
\`\`\`
- No delimiters between fields (raw hex concatenation)
- No delimiters per protocol spec

## Leaf Hash Construction
\`\`\`
leaf_hash = SHA-256(
  schema_version || "||" || protocol_version || "||" ||
  event_type || "||" || event_id || "||" ||
  sequence_number || "||" || timestamp || "||" ||
  previous_leaf_hash
)
\`\`\`
- **Payload EXCLUDED** - privacy innovation
- Chain integrity verifiable without revealing event contents

## Salted Commitments
\`\`\`
commitment = SHA-256(content_bytes || salt_bytes)
\`\`\`
- Salt: 128-bit (16 bytes, 32 hex chars) CSPRNG
- Enables selective disclosure

## Merkle Trees
- Binary tree over leaf hashes
- Internal nodes: SHA-256(left || right)
- Odd leaf count: last leaf duplicated
- Inclusion proofs: array of {hash, direction} pairs

## Canonical Serialization
- RFC 8785 aligned
- Sorted keys, no whitespace
- Used before signing any object
`;

export const CRYPTO_PRIMITIVES_URI = 'aga://crypto-primitives';
