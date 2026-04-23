/**
 * Performance Test
 * Full lifecycle (seal + 5 measurements + drift + receipt + bundle + verify)
 * completes in < 1000ms
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPair, pkToHex } from '../../src/crypto/sign.js';
import { sha256Str } from '../../src/crypto/hash.js';
import { computeSubjectIdFromString } from '../../src/core/subject.js';
import { performAttestation } from '../../src/core/attestation.js';
import { generateArtifact, hashArtifact } from '../../src/core/artifact.js';
import { Portal } from '../../src/core/portal.js';
import { generateReceipt } from '../../src/core/receipt.js';
import { createGenesisEvent, appendEvent, verifyChainIntegrity } from '../../src/core/chain.js';
import { createCheckpoint, eventInclusionProof } from '../../src/core/checkpoint.js';
import { generateBundle, verifyBundleOffline } from '../../src/core/bundle.js';

describe('Performance', () => {
  it('full lifecycle completes in < 1000ms', () => {
    const start = performance.now();

    const issuerKP = generateKeyPair();
    const portalKP = generateKeyPair();
    const chainKP = generateKeyPair();
    const enc = new TextEncoder();

    const content = 'BINARY_CONTENT_FOR_PERF_TEST';
    const meta = { filename: 'perf.bin', version: '1.0' };
    const subId = computeSubjectIdFromString(content, meta);
    const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('pol'), evidence_items: [] });
    const artifact = generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('pol'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: { measurement_cadence_ms: 100, ttl_seconds: 3600, enforcement_triggers: ['QUARANTINE'], re_attestation_required: false, measurement_types: ['EXECUTABLE_IMAGE'] },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] }, evidence_commitments: [], issuer_keypair: issuerKP,
    });
    const artRef = hashArtifact(artifact);

    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    let prev = genesis;
    prev = appendEvent('POLICY_ISSUANCE', { artifact_hash: artRef }, prev, chainKP);
    const chainEvents = [genesis, prev];
    const receipts: ReturnType<typeof generateReceipt>[] = [];

    // 5 clean measurements
    for (let i = 0; i < 5; i++) {
      const m = portal.measure(enc.encode(content), meta);
      const r = generateReceipt({
        subjectId: subId, artifactRef: artRef,
        currentHash: `${m.currentBytesHash}||${m.currentMetaHash}`,
        sealedHash: `${m.expectedBytesHash}||${m.expectedMetaHash}`,
        driftDetected: false, driftDescription: null, action: null,
        measurementType: 'EXECUTABLE_IMAGE', seq: i + 1, prevLeaf: prev.leaf_hash, portalKP,
      });
      receipts.push(r);
      prev = appendEvent('INTERACTION_RECEIPT', r, prev, chainKP);
      chainEvents.push(prev);
    }

    // Drift measurement
    const mDrift = portal.measure(enc.encode('TAMPERED'), meta);
    const rDrift = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: `${mDrift.currentBytesHash}||${mDrift.currentMetaHash}`,
      sealedHash: `${mDrift.expectedBytesHash}||${mDrift.expectedMetaHash}`,
      driftDetected: true, driftDescription: 'drift', action: 'QUARANTINE',
      measurementType: 'EXECUTABLE_IMAGE', seq: 6, prevLeaf: prev.leaf_hash, portalKP,
    });
    receipts.push(rDrift);
    prev = appendEvent('INTERACTION_RECEIPT', rDrift, prev, chainKP);
    chainEvents.push(prev);

    // Chain integrity
    const integrity = verifyChainIntegrity(chainEvents);
    expect(integrity.valid).toBe(true);

    // Bundle
    const { checkpoint } = createCheckpoint(chainEvents);
    const proofs = receipts.map((_, i) => eventInclusionProof(chainEvents, chainEvents[2 + i].sequence_number));
    const bundle = generateBundle(artifact, receipts, proofs, checkpoint, portalKP, 'GOLD');
    const verification = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
    expect(verification.overall).toBe(true);

    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(1000);
  });
});
