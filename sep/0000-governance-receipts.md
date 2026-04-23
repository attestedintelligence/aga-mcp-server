---
SEP: 0000
Title: Cryptographic Governance Receipts for MCP Gateways
Author: Jack Brennan <jack@attestedintelligence.com>, Attested Intelligence Holdings LLC
Status: Draft
Type: Extensions Track
Created: 2026-04-01
---

## Abstract

This proposal defines a cryptographic receipt mechanism for Model Context Protocol (MCP) gateways that produces a tamper-evident, append-only log of every tool-invocation governance decision. Each receipt is individually signed with Ed25519, hash-linked to its predecessor to form a receipt chain, and exportable as a self-contained evidence bundle with Merkle inclusion proofs. The extension enables offline verification of governance history without requiring access to the gateway that produced it.

## Motivation

The Model Context Protocol enables AI models to invoke external tools, but the protocol currently offers no standard mechanism for recording, auditing, or proving what governance decisions were applied to those invocations. As MCP adoption grows across enterprise and safety-critical environments, this gap creates several pressing problems:

**Audit and compliance.** Organizations subject to regulatory frameworks (SOC 2, ISO 27001, NIST AI RMF, EU AI Act) need demonstrable evidence that AI tool use was governed by policy. Today, operators must build bespoke logging solutions with no interoperability guarantees and no cryptographic integrity.

**Multi-party trust.** When an MCP client, gateway, and tool server are operated by different parties, there is no shared source of truth about which requests were permitted or denied, or why. Disputes about past behavior devolve into log comparison with no way to detect tampering.

**Offline and air-gapped verification.** Environments with restricted connectivity (classified networks, industrial control systems, edge deployments) cannot rely on online verification services. A self-contained, cryptographically verifiable artifact is required.

**Fail-closed governance.** Without a normative standard for how governance decisions are recorded, implementations may silently degrade: dropping receipts under load, accepting unsigned records, or skipping chain validation. A specification with MUST-level requirements and a defined algorithm identifier provides a clear contract that verifiers can enforce.

This extension aligns with the MCP roadmap priorities of security, auditability, and enterprise readiness. It is designed as a pure addition to the protocol, requiring no changes to existing MCP message formats or transport mechanisms.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### Extension Identifier

```
governance/receipts
```

A gateway that implements this extension MUST advertise `governance/receipts` in its capabilities during MCP session initialization.

### Receipt Data Model

A governance receipt is a JSON object containing exactly the following 15 fields. Implementations MUST NOT add, remove, or rename fields.

| Field | Type | Description |
|---|---|---|
| `receipt_id` | string | A unique identifier for this receipt. MUST be a UUID v4. |
| `receipt_version` | string | The version of the receipt schema. MUST be `"1.0"` for this specification. |
| `algorithm` | string | The cryptographic algorithm suite identifier. MUST be `"Ed25519-SHA256-JCS"` for this specification. Verifiers MUST reject receipts with unrecognized algorithm values (fail closed). |
| `timestamp` | string | The time the receipt was generated, as an ISO 8601 string with UTC timezone (e.g., `"2026-04-01T12:00:00.000Z"`). |
| `request_id` | string \| number \| null | The JSON-RPC `id` from the originating request. MUST be `null` for notifications. |
| `method` | string | The JSON-RPC method name from the originating request (e.g., `"tools/call"`). |
| `tool_name` | string | The name of the tool being invoked. If the tool name could not be extracted from the request, the gateway MUST use the value `"UNKNOWN"` and MUST set `decision` to `"DENIED"`. |
| `decision` | string | The governance outcome. MUST be one of `"PERMITTED"` or `"DENIED"`. |
| `reason` | string | A human-readable explanation of the decision (e.g., `"tool is on the allow list"`, `"tool name extraction failed, fail-closed"`). |
| `policy_reference` | string | An identifier for the policy that produced the decision. SHOULD be a content hash of the policy document to enable policy pinning. |
| `arguments_hash` | string | A hash of the tool invocation arguments. See the Arguments Hash section below for the tri-state computation rules. |
| `previous_receipt_hash` | string | The ChainDigest of the immediately preceding receipt in this gateway's receipt chain. MUST be the empty string `""` for the first receipt in a chain. |
| `gateway_id` | string | An identifier for the gateway instance that produced this receipt. |
| `signature` | string | The Ed25519 signature over the SigningDigest of this receipt, encoded as a lowercase hexadecimal string. |
| `public_key` | string | The Ed25519 public key corresponding to the signing key, encoded as a lowercase hexadecimal string. |

#### Arguments Hash

The `arguments_hash` field MUST be computed according to the following three cases:

1. **Arguments key absent.** If the `arguments` key is not present in the `tools/call` request parameters, `arguments_hash` MUST be the empty string `""`.

2. **Arguments is an empty object.** If the `arguments` key is present and its value is `{}`, `arguments_hash` MUST be the lowercase hex-encoded SHA-256 digest of the UTF-8 encoding of the string `"{}"`.

3. **Arguments has content.** If the `arguments` key is present and its value is a non-empty object, `arguments_hash` MUST be the lowercase hex-encoded SHA-256 digest of the UTF-8 encoding of the RFC 8785 canonical form of the arguments object.

This tri-state design preserves a distinction between "no arguments were provided" and "arguments were provided but empty," while ensuring that the full argument values are never stored in the receipt itself.

### Canonicalization

All JSON canonicalization in this specification MUST conform to RFC 8785 (JSON Canonicalization Scheme, JCS). Specifically:

- Object keys MUST be sorted by Unicode code point order.
- Numbers MUST be serialized using ECMAScript `Number.toString()` semantics. Negative zero MUST be serialized as `0`. Non-finite values (NaN, Infinity) MUST be rejected.
- No whitespace MUST appear outside of string values.
- String values MUST use the JSON string escaping rules defined in ECMA-262.

Implementations MUST NOT use custom JSON serializers that deviate from RFC 8785. The canonical output is a UTF-8 byte sequence; all hashing and signing operations operate on this byte sequence directly.

### Signing

The signing operation produces the `signature` field of a governance receipt. The input to the signing operation is named **SigningDigest** and is computed as follows:

1. Construct a copy of the receipt object with the `signature` field removed.
2. Canonicalize the resulting object per RFC 8785 to produce a UTF-8 byte sequence.
3. This byte sequence is the **SigningDigest**.

The gateway MUST sign the SigningDigest using Ed25519 as specified in RFC 8032, Section 5.1. The resulting 64-byte signature MUST be encoded as a 128-character lowercase hexadecimal string and stored in the `signature` field of the receipt.

Formally:

```
SigningDigest(receipt) = canonicalize(receipt WITHOUT "signature" field)
receipt.signature      = hex(Ed25519_Sign(private_key, SigningDigest(receipt)))
```

Verifiers MUST reconstruct the SigningDigest by removing the `signature` field and canonicalizing, then verify using Ed25519_Verify with the `public_key` from the receipt.

### Chain Linking

Each receipt is linked to its predecessor via the `previous_receipt_hash` field. The hash used for chain linking is named **ChainDigest** and is computed as follows:

1. Take the complete receipt object, including the `signature` field.
2. Canonicalize the complete object per RFC 8785 to produce a UTF-8 byte sequence.
3. Compute the SHA-256 digest of that byte sequence.
4. Encode the digest as a 64-character lowercase hexadecimal string.

This value is the **ChainDigest**.

Formally:

```
ChainDigest(receipt) = hex(SHA-256(canonicalize(receipt WITH "signature" field)))
```

The distinction between SigningDigest and ChainDigest is critical:

- **SigningDigest** excludes the `signature` field because the signature cannot be an input to its own computation.
- **ChainDigest** includes the `signature` field because the chain link must commit to the full receipt, including its cryptographic binding.

For chain construction:

- The first receipt in a chain MUST have `previous_receipt_hash` set to `""`.
- Every subsequent receipt MUST have `previous_receipt_hash` set to `ChainDigest(previous_receipt)`.
- Verifiers MUST check chain integrity by recomputing ChainDigest for each receipt and comparing it to the `previous_receipt_hash` of the next receipt in the chain.

### Receipt Delivery

Gateways MUST support two receipt delivery mechanisms:

#### Inline Delivery

When a `tools/call` request is denied, the gateway MUST include the governance receipt in the JSON-RPC error response under the key `x-aga-receipt`:

```json
{
  "jsonrpc": "2.0",
  "error": { "code": -32600, "message": "Tool denied: reason" },
  "id": 1,
  "x-aga-receipt": { ... }
}
```

For permitted requests, the gateway SHOULD attach the receipt via an HTTP response header or include it in an extension field of the response. The specific delivery mechanism for permitted-request receipts is left to the transport binding.

#### Batch Export Endpoint

Gateways SHOULD expose an endpoint for retrieving evidence bundles containing accumulated receipts. The endpoint path, authentication, and pagination mechanisms are implementation-defined. The response format MUST conform to the Evidence Bundle schema defined below.

### Evidence Bundle

An evidence bundle is a self-contained, offline-verifiable artifact that packages a sequence of governance receipts with their Merkle inclusion proofs.

#### Bundle Schema

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | The bundle schema version. MUST be `"1.0"`. |
| `bundle_id` | string | A unique identifier for this bundle. MUST be a UUID v4. |
| `algorithm` | string | MUST be `"Ed25519-SHA256-JCS"`. |
| `generated_at` | string | ISO 8601 timestamp of bundle generation. |
| `gateway_id` | string | The gateway that produced the receipts. |
| `public_key` | string | The Ed25519 public key (hex) used by the gateway. |
| `policy_reference` | string | Identifier for the policy in effect. |
| `receipts` | array | Ordered array of GovernanceReceipt objects. |
| `merkle_root` | string | The root hash of the binary Merkle tree over the receipts. |
| `merkle_proofs` | array | One MerkleProof per receipt, in the same order. |
| `offline_capable` | boolean | MUST be `true`. Indicates the bundle is self-contained. |

#### Merkle Tree Construction

The Merkle tree is a binary tree over the receipts in chain order:

1. The leaf hash for receipt `i` is `SHA-256(canonicalize(receipt[i]))`, where the receipt includes its `signature` field (this is identical to ChainDigest).
2. Internal nodes are computed as `SHA-256(left_child_bytes || right_child_bytes)`, where `||` denotes byte concatenation of the raw 32-byte hash values.
3. If a tree level has an odd number of nodes, the last node is promoted to the next level without duplication.

Each MerkleProof object contains:

| Field | Type | Description |
|---|---|---|
| `leaf_hash` | string | The leaf hash for this receipt. |
| `leaf_index` | number | The zero-based index of this receipt in the bundle. |
| `siblings` | array of string | The sibling hashes needed to walk from leaf to root. |
| `directions` | array of string | For each sibling, either `"left"` or `"right"`, indicating the sibling's position relative to the current node. |
| `merkle_root` | string | The expected root hash (MUST match `bundle.merkle_root`). |

#### Five-Step Verification

Verifiers MUST execute the following five steps in order. If any step fails, the bundle MUST be rejected. The algorithm field check MUST be performed first to ensure fail-closed behavior on unknown algorithm suites.

**Step 1: Algorithm validation.** Verify that `bundle.algorithm` is `"Ed25519-SHA256-JCS"`. Verify that every receipt in the bundle has `algorithm` set to `"Ed25519-SHA256-JCS"`. If any algorithm value is unrecognized, the verifier MUST reject the bundle. This is a fail-closed check: new algorithm identifiers require explicit verifier support.

**Step 2: Receipt signature verification.** For each receipt, compute SigningDigest(receipt) by removing the `signature` field and canonicalizing per RFC 8785. Verify the Ed25519 signature against the receipt's `public_key`. If any signature is invalid, reject the bundle.

**Step 3: Chain integrity verification.** Verify that `receipts[0].previous_receipt_hash` is `""`. For each subsequent receipt `receipts[i]` where `i > 0`, compute `ChainDigest(receipts[i-1])` and verify that it equals `receipts[i].previous_receipt_hash`. Use constant-time comparison for all hash comparisons.

**Step 4: Merkle proof verification.** For each MerkleProof, walk from the leaf hash to the root using the sibling hashes and direction indicators. Verify that the computed root matches `bundle.merkle_root` using constant-time comparison.

**Step 5: Bundle consistency verification.** Verify that the number of Merkle proofs equals the number of receipts. For each receipt at index `i`, verify that `merkle_proofs[i].leaf_hash` equals `SHA-256(canonicalize(receipts[i]))` and that `merkle_proofs[i].leaf_index` equals `i`.

## Rationale

### Why Ed25519?

Ed25519 (RFC 8032) provides 128-bit security with fast, constant-time signing and verification, compact 64-byte signatures, and deterministic signature generation (no per-signature randomness needed). These properties make it well suited to high-throughput gateway environments where every request generates a receipt.

### Why RFC 8785?

JSON Canonicalization Scheme (JCS) is the only IETF-track canonicalization scheme for JSON. It is simple to implement correctly (sorted keys, ECMAScript number formatting, no whitespace) and avoids the complexity and attack surface of XML-based canonicalization. Using a standard canonicalization scheme ensures that independent implementations produce identical byte sequences from identical logical data.

### Why not JWS/JWT?

JWS (RFC 7515) and JWT (RFC 7519) are designed for bearer tokens and claims transport, not for append-only hash-linked chains. Adopting JWS would require:

- Base64url encoding of payloads, adding overhead and a decode step for every verification.
- JOSE header negotiation, which adds complexity without benefit when the algorithm is fixed.
- Loss of the clean JSON-in/JSON-out property that makes receipts easy to inspect, store, and query.

The receipt format defined here achieves the same cryptographic properties (integrity, authenticity, non-repudiation) with less overhead and a simpler implementation surface.

### Related Work

- **Sigstore Rekor** provides a transparency log for software supply chain artifacts. Governance receipts solve a different problem (runtime policy decisions vs. build-time signing) but share the principle of append-only, cryptographically verifiable logs.
- **Certificate Transparency (RFC 6962)** uses Merkle trees for append-only logs of TLS certificates. The Merkle proof structure in this specification follows similar principles.
- **SCITT (Supply Chain Integrity, Transparency, and Trust)** defines transparent claims for supply chain artifacts. Governance receipts could be submitted to a SCITT ledger for additional transparency guarantees.

## Backwards Compatibility

This extension is purely additive. It does not modify any existing MCP message formats, transport bindings, or protocol sequences.

- MCP clients that do not understand governance receipts MAY ignore the `x-aga-receipt` field in responses.
- MCP servers require no modifications; the gateway operates as a transparent proxy for permitted requests.
- Gateways that do not implement this extension are unaffected.

A gateway implementing this extension MUST continue to conform to all existing MCP protocol requirements. The receipt generation and chain maintenance are gateway-internal operations that do not alter the messages exchanged between client and server.

## Security Considerations

### Key Management

The Ed25519 signing key is the root of trust for the receipt chain. Compromise of this key allows an attacker to forge receipts. Implementations SHOULD:

- Generate keys using a cryptographically secure random number generator.
- Store keys in hardware security modules (HSMs) or platform key stores where available.
- Support key rotation with a clear transition protocol (the new key's first receipt links to the last receipt signed by the old key).
- Never transmit private key material in receipts, logs, or API responses.

### Replay Attacks

Each receipt contains a unique `receipt_id` (UUID v4) and a `timestamp`. The hash chain provides ordering guarantees. Verifiers SHOULD reject bundles containing duplicate `receipt_id` values. The chain linkage ensures that replaying a receipt in a different position will break chain integrity verification.

### Argument Privacy

The `arguments_hash` field stores a SHA-256 hash of the arguments, not the arguments themselves. This design ensures that sensitive argument values (credentials, PII, confidential parameters) are never persisted in the receipt chain. However, if the argument space is small or predictable, an attacker with access to the receipts could perform a dictionary attack to recover argument values. Operators handling highly sensitive arguments SHOULD consider additional protections such as HMAC-based argument hashing with a secret key.

### Gateway Compromise

If a gateway is compromised, the attacker can generate valid receipts with arbitrary decisions. The receipt chain provides tamper evidence (post-hoc detection) but not tamper prevention. Organizations requiring stronger guarantees SHOULD:

- Deploy multiple independent gateways and cross-verify receipt chains.
- Submit receipts or evidence bundles to external transparency logs.
- Monitor for anomalous patterns in receipt chains (unexpected decisions, gaps in timestamps).

### Trust Boundary

The receipt chain attests to what the gateway decided, not what the tool server did. A receipt with `decision: "PERMITTED"` proves the gateway allowed the request; it does not prove the tool server executed it correctly or at all. Operators SHOULD correlate receipt chains with tool server logs for end-to-end auditability.

### Constant-Time Comparisons

All hash and signature comparisons during verification MUST use constant-time comparison functions to prevent timing side-channel attacks.

## Reference Implementation

A reference implementation is available in the `aga-mcp-gateway` repository:

- **TypeScript (Cloudflare Workers):** Full gateway implementation with receipt generation, chain management, evidence bundle composition, and five-step verification.
- **Independent verifier:** A standalone verification tool that validates evidence bundles without requiring gateway access, confirming offline verification capability.

The reference implementation includes shared test vectors to ensure cross-implementation compatibility. Both the gateway and the independent verifier produce identical results for all test vector categories.

## Test Vectors

Test vectors are maintained in the `aga-mcp-gateway` repository under the `test/` directory. The vectors cover the following categories:

- **Canonicalization:** Verifies RFC 8785 compliance for sorted keys, number serialization (including negative zero), Unicode escaping, and nested object handling.
- **Canonicalization edge cases:** Covers empty objects, empty arrays, null values, boolean values, and deeply nested structures.
- **Receipt signing and verification:** End-to-end generation and verification of individual receipts with known key pairs.
- **Chain integrity:** Multi-receipt chains with verified ChainDigest linkage, including genesis receipt validation.
- **Evidence bundle verification:** Full five-step verification of composed bundles, including Merkle proof construction and validation.
- **Cross-language verification:** Shared vectors verified across TypeScript, Python, and Go implementations to confirm interoperability.

Implementers SHOULD verify their implementation against these vectors before claiming conformance. A conformant implementation MUST pass all test vector categories.

## Copyright

This document is placed in the public domain.
