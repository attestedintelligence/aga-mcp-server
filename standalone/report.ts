/**
 * Human-readable evidence verification report.
 * Generates plain-text walkthrough alongside JSON evidence.
 *
 * Attested Intelligence Holdings LLC
 */
import type { PolicyArtifact, SignedReceipt, ContinuityEvent } from '../src/core/types.js';

export function generateWalkthrough(
  artifact: PolicyArtifact,
  receipts: SignedReceipt[],
  chain: ContinuityEvent[],
  merkleRoot: string,
  verificationResult: { step1_artifact_sig: boolean; step2_receipt_sigs: boolean; step3_merkle_proofs: boolean; overall: boolean },
  scenario: string,
): string {
  const cleanReceipts = receipts.filter(r => !r.drift_detected);
  const driftReceipts = receipts.filter(r => r.drift_detected);
  const revocationEvents = chain.filter(e => e.event_type === 'REVOCATION');

  return `════════════════════════════════════════════════════════════════
  ATTESTED GOVERNANCE ARTIFACTS
  VERIFICATION WALKTHROUGH
════════════════════════════════════════════════════════════════

  Organization:  Attested Intelligence Holdings LLC
  Scenario:      ${scenario}
  Generated:     ${new Date().toISOString()}

════════════════════════════════════════════════════════════════

────────────────────────────────────────────────────────────────
1. WHAT THIS BUNDLE CONTAINS
────────────────────────────────────────────────────────────────

This folder contains cryptographic evidence that an autonomous
agent was governed by a sealed policy artifact, continuously
measured against a known-good reference, and that enforcement
actions were executed when the agent was compromised.

Files:
  artifact.json           The sealed governance policy (immutable)
  receipts.json           Signed proof of each measurement (${receipts.length} total)
  chain.json              Tamper-evident event log (${chain.length} events)
  evidence-bundle.json    Self-verifying package with Merkle proofs
  verification-report.json Machine-readable verification results
  demo-transcript.txt     Human-readable demo log

────────────────────────────────────────────────────────────────
2. ARTIFACT DETAILS
────────────────────────────────────────────────────────────────

Schema:           ${artifact.schema_version}
Protocol:         ${artifact.protocol_version}
Sealed Hash:      ${artifact.sealed_hash}
Issued:           ${artifact.issued_timestamp}
Effective:        ${artifact.effective_timestamp}
Expiration:       ${artifact.expiration_timestamp ?? 'None (no expiration set)'}
TTL:              ${artifact.enforcement_parameters.ttl_seconds} seconds
Cadence:          ${artifact.enforcement_parameters.measurement_cadence_ms}ms
Triggers:         ${artifact.enforcement_parameters.enforcement_triggers.join(', ')}
Measurements:     ${artifact.enforcement_parameters.measurement_types.join(', ')}

Subject Binding:
  Bytes Hash:     ${artifact.subject_identifier.bytes_hash}
  Metadata Hash:  ${artifact.subject_identifier.metadata_hash}

Issuer:           ${artifact.issuer_identifier}
Evidence:         ${artifact.evidence_commitments.length} salted commitments

────────────────────────────────────────────────────────────────
3. MEASUREMENT HISTORY
────────────────────────────────────────────────────────────────

Total measurements: ${receipts.length}
Clean (no drift):   ${cleanReceipts.length}
Drift detected:     ${driftReceipts.length}

${receipts.map((r, i) => `  [${i + 1}] ${r.timestamp}  ${r.drift_detected ? 'DRIFT' : 'CLEAN'}  ${r.enforcement_action ?? 'none'}  ${r.receipt_id}`).join('\n')}

${driftReceipts.length > 0 ? `
Drift Detail:
${driftReceipts.map(r => `  Receipt:    ${r.receipt_id}
  Time:       ${r.timestamp}
  Expected:   ${r.sealed_hash}
  Actual:     ${r.current_hash}
  Action:     ${r.enforcement_action}
  Detail:     ${r.drift_description}`).join('\n\n')}
` : '  No drift events detected.'}

────────────────────────────────────────────────────────────────
4. CONTINUITY CHAIN
────────────────────────────────────────────────────────────────

Events: ${chain.length}
${chain.map(e => `  [${e.sequence_number}] ${e.event_type.padEnd(24)} ${e.leaf_hash}`).join('\n')}

${revocationEvents.length > 0 ? `
Revocation Events:
${revocationEvents.map(e => {
    const p = e.payload as any;
    return `  Sequence:   ${e.sequence_number}
  Time:       ${e.timestamp}
  Reason:     ${p?.reason ?? 'Not specified'}
  Revoked By: ${p?.revoked_by ?? 'Unknown'}`;
  }).join('\n\n')}
` : '  No revocation events.'}

Structural Integrity:
  The leaf hash for each event is computed from STRUCTURAL METADATA
  ONLY. The payload (event contents) is EXCLUDED from the leaf hash.
  This means a third-party auditor can verify the entire chain
  structure without accessing any event contents.

  Payload integrity is protected separately by:
  - Event signature (Ed25519 over complete event including payload)
  - Payload hash (SHA-256 of canonicalized payload)

────────────────────────────────────────────────────────────────
5. HOW TO VERIFY (no special tools required)
────────────────────────────────────────────────────────────────

STEP 1: Verify Artifact Signature
  Public key: ${artifact.issuer_identifier}
  Remove "signature" from artifact.json
  Canonicalize remaining JSON (sort keys, no whitespace)
  Verify Ed25519 signature against canonical bytes
  Result: ${verificationResult.step1_artifact_sig ? 'PASS ✓' : 'FAIL ✗'}

STEP 2: Verify Receipt Signatures
  For each receipt in receipts.json:
  Remove "portal_signature" field
  Canonicalize remaining JSON
  Verify Ed25519 signature against portal public key
  Result: ${verificationResult.step2_receipt_sigs ? `ALL ${receipts.length} PASS ✓` : 'SOME FAILED ✗'}

STEP 3: Verify Merkle Inclusion Proofs
  Merkle root: ${merkleRoot}
  For each proof in evidence-bundle.json:
  Recompute from leaf hash up through siblings
  Final hash must equal Merkle root
  Result: ${verificationResult.step3_merkle_proofs ? 'ALL PASS ✓' : 'SOME FAILED ✗'}

STEP 4: Anchor Validation (optional, requires network)
  Anchor network: local
  In production, this is a blockchain transaction ID
  (Arweave, Ethereum, etc.) verifiable on-chain

OVERALL: ${verificationResult.overall ? 'VERIFIED ✓' : 'VERIFICATION FAILED ✗'}

────────────────────────────────────────────────────────────────
6. WHAT THIS EVIDENCE PROVES
────────────────────────────────────────────────────────────────

This evidence bundle cryptographically proves that:

1. The agent was attested at ${artifact.issued_timestamp}
   with binary hash ${artifact.subject_identifier.bytes_hash}

2. ${cleanReceipts.length} measurements confirmed the agent was unmodified,
   each generating a signed receipt with the portal's signature

3. ${driftReceipts.length > 0 ? `Measurement ${driftReceipts[0]?.sequence_number} detected binary modification (drift)` : 'No drift was detected'}

4. ${driftReceipts.length > 0 ? `Enforcement action ${driftReceipts[0]?.enforcement_action} was executed automatically` : 'No enforcement was needed'}

5. ${revocationEvents.length > 0 ? 'The artifact was subsequently revoked' : 'The artifact was not revoked'}

6. All of the above is verifiable using ONLY the files in this
   folder. No network access to the original system is needed.

════════════════════════════════════════════════════════════════
Generated by AGA (Attested Governance Artifacts)
Attested Intelligence Holdings LLC
`;
}
