# AGA Receipt Specification

Version: 1.0
Date: 2026-03-19
Status: Normative

Copyright (c) 2026 Attested Intelligence Holdings LLC

## 1. Overview

The Attested Governance Architecture (AGA) receipt format defines a
cryptographically verifiable record of AI governance decisions. Receipts
form tamper-evident continuity chains that can be verified offline
without contacting any central authority.

This document specifies:

1. The receipt JSON structure
2. The leaf hash computation (SigningDigest)
3. The chain hash computation (ChainDigest)
4. The Merkle tree construction
5. The four-step verification algorithm

## 2. Receipt Format

A receipt is a JSON object with the following fields:

```json
{
  "receipt_id":     "string",
  "event_type":     "string",
  "tool_name":      "string",
  "decision":       "ALLOW | DENY",
  "request_id":     "string | number | null",
  "arguments_hash": "string",
  "result_hash":    "string (hex, 64 chars)",
  "signer_key_id":  "string",
  "timestamp":      "string (ISO 8601, UTC)",
  "signature":      "string (hex, 128 chars)"
}
```

### 2.1 Field Definitions

**receipt_id**: Unique identifier for this receipt. Typically a
deterministic hash-based ID.

**event_type**: One of the defined event types:
- `POLICY_ISSUANCE`
- `INTERACTION_RECEIPT`
- `TOOL_CALL_PERMITTED`
- `TOOL_CALL_DENIED`
- `SYSTEM_PROMPT_DRIFT`
- `MODEL_IDENTITY_CHANGE`
- `REVOCATION`
- `ATTESTATION`
- `ANCHOR_BATCH`
- `KEY_ROTATION`
- `GENESIS`

**tool_name**: The tool being governed. Present for `TOOL_CALL_PERMITTED`
and `TOOL_CALL_DENIED` events.

**decision**: The governance decision. `ALLOW` or `DENY`.

**request_id**: The upstream request identifier. MAY be a string, a
number, or null. The type is preserved exactly in canonical JSON.

**arguments_hash**: SHA-256 hash of the canonicalized tool arguments.
Has three cases:

1. **Empty string** (`""`): No arguments were provided, or arguments
   hashing was not applicable. The empty string is included literally
   in the canonical JSON.
2. **SHA-256 of empty object** (`"44136fa3..."`): The tool was called
   with an empty arguments object `{}`. The hash is SHA-256 of the
   canonical JSON string `"{}"`.
3. **SHA-256 of arguments** (any other 64-char hex string): The tool
   was called with non-empty arguments. The hash is SHA-256 of the
   RFC 8785 canonical JSON representation of the arguments object.

**result_hash**: SHA-256 hash of the tool execution result, hex-encoded.

**signer_key_id**: Identifier of the signing key used to produce the
signature.

**timestamp**: ISO 8601 timestamp in UTC. Normalized before use in
hash computation (see Section 3.2).

**signature**: Ed25519 signature over the SigningDigest, hex-encoded
(128 hex characters = 64 bytes).

### 2.2 Continuity Chain Event Fields

When a receipt participates in a continuity chain, it is wrapped in a
ContinuityEvent with additional structural fields:

```json
{
  "schema_version":     "string",
  "protocol_version":   "string",
  "event_type":         "string",
  "event_id":           "string",
  "sequence_number":    "integer (unsigned)",
  "timestamp":          "string (ISO 8601, UTC)",
  "previous_leaf_hash": "string (hex, 64 chars)",
  "payload":            "object (optional)",
  "payload_hash":       "string (hex, 64 chars)",
  "leaf_hash":          "string (hex, 64 chars)",
  "signatures":         ["bytes"]
}
```

## 3. SigningDigest (Canonical Hash for Signing)

The SigningDigest is the byte sequence over which the Ed25519 signature
is computed. It is produced by RFC 8785 JSON Canonicalization Scheme
(JCS) applied to all receipt fields except `signature`.

### 3.1 Canonicalization Rules (RFC 8785)

1. Object keys MUST be sorted by Unicode code point order.
2. No whitespace between tokens.
3. Numbers MUST use shortest representation: `1.0` becomes `1`,
   scientific notation is normalized.
4. Nested objects are sorted recursively.
5. Array element order is preserved (not sorted).

### 3.2 Timestamp Normalization

Before hashing, all timestamps MUST be normalized:

1. Parse the timestamp (RFC 3339 with optional fractional seconds).
2. Convert to UTC.
3. If fractional seconds are all zeros, omit them: `15:22:09.000Z`
   becomes `15:22:09Z`.
4. If fractional seconds are non-zero, strip trailing zeros:
   `15:22:09.120Z` becomes `15:22:09.12Z`.
5. Always use `Z` suffix (never `+00:00`).

### 3.3 Computing the SigningDigest

```
fields_without_signature = {all receipt fields except "signature"}
canonical_json = RFC8785_Canonicalize(fields_without_signature)
signing_digest = canonical_json  (raw bytes, NOT hashed again)
signature = Ed25519_Sign(private_key, signing_digest)
```

Note: For continuity chain receipts in the evidence bundle format,
the signing digest is the `payload_hash` (SHA-256 of the payload),
and the signature is over that hash directly.

## 4. Leaf Hash (Chain Linking)

The leaf hash links each event to its predecessor, forming the
continuity chain. It is computed over structural metadata only,
NOT over the payload.

### 4.1 Length-Prefixed Field Encoding

Each field is encoded as:

```
[4 bytes: big-endian uint32 length] [N bytes: field data]
```

This prevents field boundary ambiguity attacks where concatenation
of differently-split field values could produce the same hash.

### 4.2 LeafHash Computation

```
LeafHash = SHA-256(
    len32(SchemaVersion)       || SchemaVersion       ||
    len32(ProtocolVersion)     || ProtocolVersion     ||
    len32(EventType)           || EventType           ||
    len32(EventID)             || EventID             ||
    len32(SequenceNumberASCII) || SequenceNumberASCII ||
    len32(NormalizedTimestamp)  || NormalizedTimestamp  ||
    len32(PreviousLeafHashRaw) || PreviousLeafHashRaw
)
```

Field encoding notes:

- **SequenceNumber**: Converted to ASCII decimal string before encoding.
  Sequence number 42 becomes the string `"42"`.
- **PreviousLeafHash**: Hex-decoded to raw bytes (32 bytes) before
  length-prefixing. The length prefix is `0x00000020` (32).
- **Timestamp**: Normalized per Section 3.2 before encoding.
- **Genesis event**: The first event in a chain uses
  `0000...0000` (64 hex chars = 32 zero bytes) as PreviousLeafHash.

### 4.3 Chain Linking

Each event's PreviousLeafHash MUST equal the LeafHash of the
immediately preceding event in the chain. This creates a hash-linked
sequence:

```
Event 0: PreviousLeafHash = 0x00...00, LeafHash = H0
Event 1: PreviousLeafHash = H0,        LeafHash = H1
Event 2: PreviousLeafHash = H1,        LeafHash = H2
Event 3: PreviousLeafHash = H2,        LeafHash = H3
```

A verifier confirms chain integrity by recomputing each LeafHash and
checking that it matches the PreviousLeafHash of the next event.

## 5. ChainDigest (Receipt Chain Hash)

The ChainDigest is used for receipt-level chain verification in the
agent governance receipt format. It is computed as:

```
canonical_with_signature = RFC8785_Canonicalize(all_receipt_fields)
chain_hash = SHA-256(canonical_with_signature)
```

This includes the signature field in the canonical JSON before hashing,
ensuring that the chain hash commits to both the receipt content and
its cryptographic signature.

## 6. Merkle Tree

Evidence bundles include a binary SHA-256 Merkle tree over the leaf
hashes of all receipts in the bundle.

### 6.1 Tree Construction

1. Leaf nodes are the LeafHash values from each receipt (already
   SHA-256 hashes).
2. Internal nodes are computed as `SHA-256(left_child || right_child)`.
3. When a level has an odd number of nodes, the last node is promoted
   to the next level without hashing (NOT duplicated).

```
Level 0 (leaves):  H0    H1    H2    H3
                    \    /       \    /
Level 1:         SHA(H0||H1)  SHA(H2||H3)
                      \          /
Level 2 (root):    SHA(L1_0 || L1_1)
```

For odd counts:
```
Level 0 (leaves):  H0    H1    H2
                    \    /      |
Level 1:         SHA(H0||H1)  H2 (promoted)
                      \        /
Level 2 (root):    SHA(L1_0 || H2)
```

### 6.2 Inclusion Proof

An inclusion proof for a leaf consists of:

- **siblings**: Array of sibling hash values (hex) along the path
  from leaf to root.
- **directions**: Array of direction indicators (`"left"` or `"right"`)
  specifying which side the sibling is on.

Verification:

```
current = leaf_hash
for i in range(len(siblings)):
    sibling = hex_decode(siblings[i])
    if directions[i] == "right":
        current = SHA-256(current || sibling)
    else:  # "left"
        current = SHA-256(sibling || current)
assert current == merkle_root
```

## 7. Evidence Bundle

An evidence bundle packages all artifacts needed for offline
verification into a single JSON document.

```json
{
  "schema_version":  "1.0",
  "bundle_id":       "string",
  "generated_at":    "string (ISO 8601)",
  "artifact": {
    "artifact_id":      "string",
    "sealed_hash":      "string (hex)",
    "bytes_hash":       "string (hex)",
    "metadata_hash":    "string (hex)",
    "policy_reference": "string",
    "salt":             "string (hex)",
    "signature":        "string (hex)",
    "signer_key_id":    "string"
  },
  "receipts": [
    {
      "receipt_id":   "string",
      "event_type":   "string",
      "leaf_hash":    "string (hex)",
      "payload_hash": "string (hex)",
      "signature":    "string (hex)",
      "signer_key_id": "string",
      "timestamp":    "string (ISO 8601)"
    }
  ],
  "merkle_proofs": [
    {
      "leaf_hash":    "string (hex)",
      "leaf_index":   "integer",
      "siblings":     ["string (hex)"],
      "directions":   ["left | right"],
      "merkle_root":  "string (hex)"
    }
  ],
  "checkpoint":      "object (optional)",
  "public_key":      "string (hex, 64 chars = 32 bytes Ed25519)",
  "public_key_id":   "string",
  "chain_id":        "string",
  "offline_capable": true
}
```

### 7.1 Artifact Signature

The artifact signature covers the canonical JSON (RFC 8785) of all
artifact fields except `signature`:

```
sig_payload = {
    "artifact_id", "sealed_hash", "bytes_hash",
    "metadata_hash", "policy_reference", "salt", "signer_key_id"
}
canonical = RFC8785_Canonicalize(sig_payload)
signature = Ed25519_Sign(private_key, canonical)
```

### 7.2 Sealed Hash (Policy Artifact Seal)

The sealed hash binds the policy artifact to its content using
length-prefixed hashing:

```
SealedHash = SHA-256(
    len32(bytes_hash_raw)       || bytes_hash_raw       ||
    len32(metadata_hash_raw)    || metadata_hash_raw    ||
    len32(policy_reference_raw) || policy_reference_raw ||
    len32(salt_raw)             || salt_raw
)
```

All inputs are hex-decoded to raw bytes before length-prefixing.

## 8. Four-Step Verification Algorithm

A verifier performs these steps to validate an evidence bundle. Steps
1 through 3 are fully offline. Step 4 is optional and requires network
access.

### Step 1: Verify Artifact Signature

1. Decode the `public_key` from the bundle (hex to 32-byte Ed25519
   public key).
2. Build the signature payload from all artifact fields except
   `signature`.
3. Canonicalize the payload using RFC 8785.
4. Verify the Ed25519 signature over the canonical bytes.

### Step 2: Verify Receipt Signatures

For each receipt:

1. Decode the `payload_hash` from hex.
2. Decode the `signature` from hex.
3. Verify Ed25519: `Verify(public_key, payload_hash_bytes, signature_bytes)`.

### Step 3: Verify Merkle Inclusion Proofs

For each Merkle proof:

1. Start with the `leaf_hash`.
2. Walk the proof path using `siblings` and `directions`.
3. At each step, compute `SHA-256(left || right)` where the direction
   indicates which side the sibling is on.
4. Compare the computed root against `merkle_root`.
5. Use constant-time comparison to prevent timing side channels.

### Step 4: Verify Checkpoint (Optional)

If the bundle includes a `checkpoint` and an anchor provider is
available:

1. Submit the checkpoint reference to the anchor provider.
2. Confirm that the Merkle root in the checkpoint matches the root
   from Step 3.

If no anchor provider is available, this step is skipped and the
bundle is still considered valid for offline verification.

### Verification Result

```json
{
  "artifact_signature_valid": true,
  "receipts_valid":           true,
  "merkle_proofs_valid":      true,
  "checkpoint_valid":         true,
  "checkpoint_skipped":       false,
  "overall_valid":            true,
  "error":                    ""
}
```

`overall_valid` is true if and only if all four steps pass (with
checkpoint_valid defaulting to true when skipped).

## 9. Security Considerations

### 9.1 Length Prefix Encoding

The 4-byte big-endian length prefix on each field prevents field
boundary confusion. Without it, concatenating `("1.0a", "bc")` and
`("1.0", "abc")` would produce the same hash input. With length
prefixes, they produce distinct inputs.

### 9.2 Payload Exclusion from Leaf Hash

The leaf hash deliberately excludes the payload content. This allows
chain integrity verification without exposing sensitive governance
data. The payload hash is signed separately and can be verified
independently.

### 9.3 Constant-Time Comparison

Merkle root comparison MUST use constant-time byte comparison to
prevent timing side-channel attacks that could leak information
about the expected root value.

### 9.4 Genesis Event

The genesis event (sequence number 0) uses 32 zero bytes as its
previous leaf hash. This is the only event permitted to have a
zero previous hash. All subsequent events MUST reference a non-zero
previous leaf hash.

## 10. Normative References

- RFC 8785: JSON Canonicalization Scheme (JCS)
- RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519)
- FIPS 180-4: Secure Hash Standard (SHA-256)
- RFC 3339: Date and Time on the Internet (Timestamps)

## 12. Extended Event Types (v2.4.0+)

Starting with AGA v2.4.0, the following event types are added to the
normative set defined in Section 2.1. They MUST be accepted by any
conforming verifier. Unknown event types MUST be rejected unless the
verifier is operating in a forward-compatibility mode.

The `event_type` field values are string literals; the enumerated name
appears verbatim in the canonical JSON.

### 12.1 PASSTHROUGH_DENIED

**Purpose.** Records a passthrough request that was denied by policy at
the MCP gateway boundary. A passthrough request is any tool invocation
that traverses the governance plane without producing a per-call
governance decision of its own (for example, raw protocol frames routed
through the gateway).

**Emitter.** The AGA MCP gateway emits this event
when a passthrough rule matches a deny clause.

**Payload schema.**

```json
{
  "tool_name":    "string",
  "request_id":   "string | number | null",
  "reason":       "string",
  "policy_id":    "string",
  "upstream":     "string",
  "denied_at":    "string (ISO 8601, UTC)"
}
```

- `reason` is a short machine-readable reason code (for example
  `policy.passthrough.blocked`).
- `upstream` is the upstream identifier whose traffic was denied.

**When and why.** Emitted on every denied passthrough call, producing a
tamper-evident record even though no upstream tool was invoked. This
closes the audit gap where deny-at-edge decisions would otherwise not
appear in the continuity chain.

### 12.2 PASSTHROUGH_RECEIPT

**Purpose.** Records a passthrough request that was permitted by policy
and successfully delivered to its upstream. This is the permit-side
counterpart to `PASSTHROUGH_DENIED`.

**Emitter.** The AGA MCP gateway emits this event after a permitted
passthrough call returns a result.

**Payload schema.**

```json
{
  "tool_name":      "string",
  "request_id":     "string | number | null",
  "upstream":       "string",
  "arguments_hash": "string (hex, 64 chars)",
  "result_hash":    "string (hex, 64 chars)",
  "latency_ms":     "integer",
  "delivered_at":   "string (ISO 8601, UTC)"
}
```

- `arguments_hash` and `result_hash` follow the rules in Section 2.1.

**When and why.** Emitted on every permitted passthrough call. Together
with `PASSTHROUGH_DENIED`, it guarantees that every decision at the
passthrough boundary is reflected in the continuity chain.

### 12.3 SYSTEM_EGRESS

**Purpose.** Records a system-level egress event where the AGA runtime
itself initiates an outbound call (for example, anchor submission,
health reporting, or scheduled attestation). This event distinguishes
governance-plane egress from agent-tool egress.

**Emitter.** The AGA portal and supporting
system daemons emit this event.

**Payload schema.**

```json
{
  "component":      "string",
  "destination":    "string",
  "purpose":        "string",
  "bytes_sent":     "integer",
  "response_code":  "integer",
  "initiated_at":   "string (ISO 8601, UTC)"
}
```

- `component` names the AGA subsystem responsible for the egress
  (for example `portal.anchor-submitter`).
- `purpose` is a short machine-readable code (for example
  `anchor.submit` or `attestation.report`).

**When and why.** Emitted whenever the AGA runtime makes an outbound
network call on its own behalf. This provides clear separation between
governance-plane traffic and governed-agent traffic when auditing
network behavior.

### 12.4 Canonicalization

All three event types follow the canonicalization rules of Section 3.1
and the timestamp normalization rules of Section 3.2. Their leaf hash
is computed using the formula in Section 4.2; the payload is hashed
separately and referenced via `payload_hash` as with all other event
types.

### 12.5 Updated Event Type List

The normative event type set as of v2.4.0 is the union of the list in
Section 2.1 and the three events defined above, giving a total of
fourteen event types:

`POLICY_ISSUANCE`, `INTERACTION_RECEIPT`, `TOOL_CALL_PERMITTED`,
`TOOL_CALL_DENIED`, `SYSTEM_PROMPT_DRIFT`, `MODEL_IDENTITY_CHANGE`,
`REVOCATION`, `ATTESTATION`, `ANCHOR_BATCH`, `KEY_ROTATION`, `GENESIS`,
`PASSTHROUGH_DENIED`, `PASSTHROUGH_RECEIPT`, `SYSTEM_EGRESS`.

## 13. ForensicOnly Field (v2.4.0+)

Starting with v2.4.0, a continuity-chain event MAY carry a boolean
`forensic_only` field at the top level of the event object (peer of
`event_type`, `payload`, `payload_hash`, etc.).

### 13.1 Semantics

`forensic_only` signals that the event is intended for forensic and
post-incident analysis only, and MUST NOT be replayed, re-executed,
or used to drive live governance decisions by a downstream consumer.

Verifiers MUST still verify the event's signature, leaf hash, and
Merkle inclusion proof exactly as they would for any other event.
The flag affects consumption semantics, not verification semantics.

### 13.2 Default Value and Backward Compatibility

The default value of `forensic_only` is `false`.

Legacy events (v2.3.0 and earlier) that omit the field MUST be parsed
as if `forensic_only` is `false`. An implementation MUST NOT reject a
bundle solely because the field is absent. Conversely, a v2.4.0+
emitter MAY omit the field whenever its value would be `false`; this
is wire-equivalent to emitting `"forensic_only": false`.

### 13.3 Canonicalization

When present, `forensic_only` is included in the canonical JSON
per Section 3.1 and therefore contributes to the `payload_hash` and
any enclosing signature. Implementations MUST NOT inject a default
`false` value at canonicalization time when the field is absent on the
wire, because that would change the hash of legacy events.

### 13.4 Event Types That Set `forensic_only` True by Default

The following event types are emitted with `forensic_only: true` by
default in conforming AGA v2.4.0+ implementations, because their
semantics are inherently post-hoc:

- `QUARANTINE_ENTRY` — records that a subject has been placed in
  forensic quarantine for later human review.
- `PHANTOM_CAPTURE` — records a captured phantom (suspected
  adversarial) interaction for offline analysis.
- `FORENSIC_SUMMARY` — records a post-incident forensic summary.

Other event types MAY set `forensic_only: true` on a per-emission
basis (for example, when replaying a historical event into a
continuity chain for archival purposes). The flag is always advisory
to the consumer; verification is unchanged.

### 13.5 Interaction With Existing Event Types

Setting `forensic_only: true` on an event type whose default is
`false` (for example, `TOOL_CALL_PERMITTED`) is permitted and is
signalling only: the event is still part of the continuity chain, is
still signed, and is still included in the Merkle tree. Downstream
policy engines MUST treat such an event as non-actionable.
