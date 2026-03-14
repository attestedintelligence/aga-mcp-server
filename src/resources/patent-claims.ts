export const PATENT_CLAIMS_DOC = `# USPTO Application No. 19/433,835 - Patent Claims Mapped to Tools

## Claim 1: Subject Attestation and Measurement
| Sub-claim | Description | Tool |
|-----------|-------------|------|
| 1(a) | Receive subject for attestation | aga_create_artifact |
| 1(b) | Generate subject identifier (bytes_hash + metadata_hash) | aga_create_artifact |
| 1(c) | Perform attestation (sealed_hash generation) | aga_create_artifact |
| 1(d) | Generate policy artifact with signature | aga_create_artifact |
| 1(e) | Portal accepts artifact, begins monitoring | aga_measure_subject |
| 1(f) | Compare current state to sealed reference | aga_measure_subject |
| 1(g) | Enforce on drift, generate signed receipt | aga_measure_subject |

## Claim 2: Privacy-Preserving Disclosure
| Sub-claim | Description | Tool |
|-----------|-------------|------|
| 2 | Sensitivity-based claim disclosure | aga_disclose_claim |
| 2-sub | Auto-substitution when sensitivity denied | aga_disclose_claim |

## Claim 3: Continuity Chain
| Sub-claim | Description | Tool |
|-----------|-------------|------|
| 3(a) | Genesis event creation | aga_init_chain |
| 3(b) | Event appending (auto on every operation) | All tools |
| 3(c) | Leaf hash excludes payload (privacy innovation) | aga_get_chain |
| 3(d-f) | Merkle checkpoint anchoring | aga_export_bundle |

## Claim 5: Quarantine
| Sub-claim | Description | Tool |
|-----------|-------------|------|
| 5 | Phantom execution on drift | aga_quarantine_status |

## Claim 6: TTL Expiration
| Sub-claim | Description | Tool |
|-----------|-------------|------|
| 6 | Fail-closed on TTL expiry | aga_measure_subject |

## Claim 9: Evidence Bundle
| Sub-claim | Description | Tool |
|-----------|-------------|------|
| 9 | Offline-verifiable evidence bundle | aga_export_bundle |

## Claim 10: Pinned Key
| Sub-claim | Description | Tool |
|-----------|-------------|------|
| 10 | Portal pins issuer public key | aga_create_artifact |

## Claim 11: Phantom Execution
| Sub-claim | Description | Tool |
|-----------|-------------|------|
| 11 | Forensic input capture during quarantine | aga_quarantine_status |

## Claim 12: Graceful Degradation
| Sub-claim | Description | Tool |
|-----------|-------------|------|
| 12 | TTL + fail-closed termination | aga_measure_subject |

## Additional (NCCoE Filing)
| Feature | Description | Tool |
|---------|-------------|------|
| Mid-session revocation | NCCoE Phase 3b | aga_revoke_artifact |
| Behavioral drift | NIST-2025-0035 | aga_measure_behavior |
| Constrained delegation | NCCoE constrained sub-mandates | aga_delegate_subagent |
| Key rotation | Key lifecycle management | aga_rotate_keys |
`;

export const PATENT_CLAIMS_URI = 'aga://patent-claims';
