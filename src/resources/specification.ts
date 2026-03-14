export const PROTOCOL_SPECIFICATION = `# Attested Governance Artifact (AGA) Protocol Specification v2.0.0

## Patent Reference
USPTO Application No. 19/433,835

## NIST References
- NIST-2025-0035: AI Agent Transparency and Accountability
- NCCoE AI Agent Identity and Authorization

## Protocol Overview
The AGA protocol provides cryptographic governance for autonomous AI systems through:
1. **Sealed Hash Attestation** - SHA-256(bytes_hash || metadata_hash || policy_ref || seal_salt)
2. **Continuity Chain** - Tamper-evident append-only event log with privacy-preserving leaf hashes
3. **Portal State Machine** - Zero-trust Policy Enforcement Point (7 states, fail-closed)
4. **Signed Receipts** - Ed25519-signed measurement receipt for EVERY measurement
5. **Evidence Bundles** - Offline-verifiable packages with Merkle inclusion proofs

## 10 Measurement Embodiments
1. EXECUTABLE_IMAGE - Runtime binary or script content
2. LOADED_MODULES - Dynamic libraries and plugins
3. CONTAINER_IMAGE - Container image manifest hash
4. CONFIG_MANIFEST - Configuration file integrity
5. SBOM - Software Bill of Materials verification
6. TEE_QUOTE - Trusted Execution Environment attestation
7. MEMORY_REGIONS - Runtime memory layout verification
8. CONTROL_FLOW - Execution path integrity
9. FILE_SYSTEM_STATE - Filesystem integrity monitoring
10. NETWORK_CONFIG - Network configuration baseline

## 6 Portal States
1. INITIALIZATION - Server started, no artifact loaded
2. ARTIFACT_VERIFICATION - Verifying artifact signature and validity
3. ACTIVE_MONITORING - Operational, measurements occurring
4. DRIFT_DETECTED - Hash mismatch detected, enforcement pending
5. PHANTOM_QUARANTINE - Forensic capture mode, outputs severed
6. TERMINATED - Fail-closed, no recovery without re-attestation

Plus SAFE_STATE for graceful degradation on revocation.

## 7 Enforcement Actions
1. QUARANTINE - Phantom execution with forensic capture
2. TERMINATE - Immediate kill, fail-closed
3. SAFE_STATE - Return-to-home / controlled shutdown
4. NETWORK_ISOLATE - Sever network, continue local
5. KEY_REVOKE - Invalidate cryptographic keys
6. TOKEN_INVALIDATE - Revoke access tokens
7. ALERT_ONLY - Log without enforcement (gradual deployment)

## 3 Verification Tiers
| Tier | Description | Trust Assumption |
|------|-------------|-----------------|
| Bronze | Cryptographic signatures only | Trust signing keys |
| Silver | Signatures + continuity chain | Trust chain operator + keys |
| Gold | Full verification with blockchain-anchored Merkle proofs | Minimal trust - external anchor |

## 3 Disclosure Modes
1. PROOF_ONLY - Returns boolean attestation without revealing the value
2. REVEAL_MIN - Returns minimal representation (e.g., range instead of exact value)
3. REVEAL_FULL - Returns the complete claim value

## Leaf Hash Formula (Claim 3c - Privacy Innovation)
\`\`\`
leaf_hash = SHA-256(
  schema_version || "||" || protocol_version || "||" ||
  event_type || "||" || event_id || "||" ||
  sequence_number || "||" || timestamp || "||" ||
  previous_leaf_hash
)
\`\`\`
**PAYLOAD IS EXCLUDED from the leaf hash.** This is the key patent innovation - chain integrity can be verified without revealing the contents of any event. Only the structural metadata participates in the hash. The payload is separately integrity-protected via event_signature.

## SPIFFE/SPIRE Integration Point
SPIRE handles node-to-workload identity (SVID); AGA handles workload-to-intent governance. SPIFFE provides transport-layer identity binding via SVIDs (SPIFFE Verifiable Identity Documents). AGA binds governance policy to the workload's operational intent, creating a complementary layer:
- SPIFFE: "This workload IS who it claims to be" (identity)
- AGA: "This workload IS DOING what it was attested to do" (governance)

## Framework Alignment
| Framework | AGA Alignment |
|-----------|--------------|
| NIST SP 800-53 | SI-7 (Software Integrity), AU-10 (Non-repudiation), SI-4 (Monitoring) |
| NIST AI RMF | Govern → Policy Artifacts; Map → Subject ID; Measure → Portal + Receipts; Manage → Enforcement |
| NIST SP 800-57 | Key management for Ed25519 signing keys |
| NIST SSDF (SP 800-218) | Software supply chain integrity via sealed hash attestation |
| NIST SP 800-207 (ZTA) | Zero Trust Architecture - portal as Policy Enforcement Point, never trust, always verify |
| ISO 42001 | AI management system - governance artifacts as compliance evidence |
| EU AI Act | High-risk AI system transparency via evidence bundles |

## Cryptographic Primitives
- **Hashing:** SHA-256 (primary), BLAKE2b-256 (secondary)
- **Signing:** Ed25519 via @noble/ed25519
- **Salts:** 128-bit CSPRNG via @noble/hashes/utils
- **Merkle Trees:** SHA-256 binary tree with inclusion proofs
- **Serialization:** RFC 8785 deterministic JSON (sorted keys)

## Event Types (12)
GENESIS, POLICY_ISSUANCE, INTERACTION_RECEIPT, REVOCATION, ATTESTATION,
ANCHOR_BATCH, DISCLOSURE, SUBSTITUTION, KEY_ROTATION, BEHAVIORAL_DRIFT,
DELEGATION, RE_ATTESTATION

## 4 Sensitivity Levels
- S1_LOW - Can be revealed fully
- S2_MODERATE - Can be revealed minimally or proved
- S3_HIGH - Proof only, auto-substitutes to lower sensitivity
- S4_CRITICAL - Maximum protection, proof only, cascading substitution
`;

export const SPECIFICATION_URI = 'aga://specification';
