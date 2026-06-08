/**
 * src/sep — the single canonical source of truth for AGA SEP evidence construction
 * and verification. Consumed by the MCP server tools and the governance proxy.
 * Conforms to aga-receipt-spec/CANONICAL_CONSTRUCTION_v2.md; verdicts match
 * aga-receipt-spec/verify/verify-sep.mjs. See SPEC_PRECEDENCE.md for precedence rules.
 */
export { canonicalize, assertSignedReceiptFieldsAreStrings, MAX_CANON_DEPTH } from './canonical.js';
export { sha256Hex, isHex, wellFormedKey, verifyHex, signerFromSeed, generateSigner, seedFromHex, newId, type SepSigner } from './crypto.js';
export { nodeHash, merkleRoot, merkleProof, type MerkleProof } from './merkle.js';
export { SEP_ALGORITHM, SEP_RECEIPT_VERSION, SEP_RECEIPT_FIELDS, buildReceipt, leafHash, argumentsHash, safeArgumentsHash, UNCANONICALIZABLE_ARGS_HASH, type SepReceipt, type ReceiptInput, type Decision } from './receipt.js';
export { buildCheckpoint, type SignedCheckpoint } from './checkpoint.js';
export { SepGateway, type SepBundle, type SepGatewayOptions, type RecordInput } from './bundle.js';
export { verifySepBundle, type SepVerificationResult, type VerifyStep } from './verify.js';
