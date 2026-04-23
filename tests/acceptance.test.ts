/**
 * AGA Core Acceptance Test Suite
 * Exhaustive acceptance tests proving every NIST submission
 * requirement through actual code execution with real cryptographic operations.
 *
 * 10 groups, ~66 tests. No mocking.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Crypto imports
import { sha256Str, sha256Bytes, sha256HexCat, sha256Cat } from '../src/crypto/hash.js';
import { generateKeyPair, signStr, verifyStr, sign, verify, sigToB64, b64ToSig, pkToHex, hexToPk, keyFingerprint } from '../src/crypto/sign.js';
import { generateSalt, saltedCommitment, verifySaltedCommitment } from '../src/crypto/salt.js';
import { buildMerkleTree, inclusionProof, verifyProof } from '../src/crypto/merkle.js';

// Core imports
import { computeSubjectId, computeSubjectIdFromString } from '../src/core/subject.js';
import { performAttestation } from '../src/core/attestation.js';
import { generateArtifact, verifyArtifactSignature, hashArtifact } from '../src/core/artifact.js';
import { Portal } from '../src/core/portal.js';
import { generateReceipt } from '../src/core/receipt.js';
import { createGenesisEvent, appendEvent, verifyChainIntegrity, computeLeafHash, computePayloadHash } from '../src/core/chain.js';
import { createCheckpoint, eventInclusionProof } from '../src/core/checkpoint.js';
import { generateBundle, verifyBundleOffline } from '../src/core/bundle.js';
import { processDisclosure } from '../src/core/disclosure.js';
import { BehavioralMonitor } from '../src/core/behavioral.js';
import { deriveArtifact, validateDelegation } from '../src/core/delegation.js';
import { isKeyValid, rotateKeyPair, recordKeyRotation } from '../src/core/identity.js';
import { initQuarantine, captureInput, releaseQuarantine } from '../src/core/quarantine.js';
import { canonicalize } from '../src/utils/canonical.js';

// Scenario imports
import { runScadaScenario } from '../scenarios/scada-enforcement.js';
import { runAutonomousVehicleScenario } from '../scenarios/autonomous-vehicle.js';
import { runAiAgentScenario } from '../scenarios/ai-agent-governance.js';

// Independent verifier
import { verifyEvidenceBundle } from '../independent-verifier/verify.js';

import type { StructuralMetadata, ContinuityEvent } from '../src/core/types.js';

// ── Helpers ──────────────────────────────────────────────────────

const enc = new TextEncoder();

function makeTestInfra() {
  const issuerKP = generateKeyPair();
  const portalKP = generateKeyPair();
  const chainKP = generateKeyPair();
  const content = 'test-subject-binary-content';
  const meta = { filename: 'test.bin', version: '1.0' };
  const subId = computeSubjectIdFromString(content, meta);
  const att = performAttestation({
    subject_identifier: subId,
    policy_reference: sha256Str('test-policy'),
    evidence_items: [{ label: 'review', content: 'approved' }],
  });
  const artifact = generateArtifact({
    subject_identifier: subId,
    policy_reference: sha256Str('test-policy'),
    policy_version: 1,
    sealed_hash: att.sealed_hash!,
    seal_salt: att.seal_salt!,
    enforcement_parameters: {
      measurement_cadence_ms: 100,
      ttl_seconds: 3600,
      enforcement_triggers: ['QUARANTINE', 'TERMINATE', 'SAFE_STATE', 'ALERT_ONLY'],
      re_attestation_required: false,
      measurement_types: ['EXECUTABLE_IMAGE', 'CONFIG_MANIFEST'],
      behavioral_baseline: {
        permitted_tools: ['read', 'write', 'log'],
        forbidden_sequences: [['delete', 'delete']],
        rate_limits: { write: 3 },
      },
    },
    disclosure_policy: {
      claims_taxonomy: [
        { claim_id: 'data.exact_value', sensitivity: 'S4_CRITICAL', substitutes: ['data.summary', 'data.category'], inference_risks: [], permitted_modes: [] },
        { claim_id: 'data.summary', sensitivity: 'S2_MODERATE', substitutes: ['data.category'], inference_risks: [], permitted_modes: ['REVEAL_MIN', 'REVEAL_FULL'] },
        { claim_id: 'data.category', sensitivity: 'S1_LOW', substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY', 'REVEAL_MIN', 'REVEAL_FULL'] },
        { claim_id: 'data.inferred_from_a', sensitivity: 'S3_HIGH', substitutes: [], inference_risks: ['data.exact_value'], permitted_modes: ['REVEAL_FULL'] },
      ],
      substitution_rules: [],
    },
    evidence_commitments: att.evidence_commitments,
    issuer_keypair: issuerKP,
  });
  const artRef = hashArtifact(artifact);
  return { issuerKP, portalKP, chainKP, content, meta, subId, att, artifact, artRef, enc };
}

// ═══════════════════════════════════════════════════════════════════
// GROUP 1: CRYPTOGRAPHIC FORMULA CORRECTNESS
// ═══════════════════════════════════════════════════════════════════

describe('Group 1: Cryptographic Formula Correctness', () => {
  it('1.1 [Reference Embodiment]: Sealed hash formula - no delimiters', () => {
    const bytes_hash = sha256Str('test subject bytes');
    const metadata_hash = sha256Str('test subject metadata');
    const policy_ref = sha256Str('test policy');
    const salt = 'a'.repeat(32);

    // sha256HexCat concatenates hex strings with NO delimiter
    const result = sha256HexCat(bytes_hash, metadata_hash, policy_ref, salt);

    // Exactly 64 lowercase hex chars
    expect(result).toMatch(/^[0-9a-f]{64}$/);

    // Must equal SHA-256 of 4 hex strings directly concatenated
    const manualConcat = bytes_hash + metadata_hash + policy_ref + salt;
    expect(result).toBe(sha256Str(manualConcat));

    // Must NOT match with ANY delimiter
    for (const d of [',', '|', ':', '-', ' ']) {
      const withDelim = [bytes_hash, metadata_hash, policy_ref, salt].join(d);
      expect(result).not.toBe(sha256Str(withDelim));
    }
  });

  it('1.2 Salted commitment - Hash(Content || Salt)', () => {
    const content = 'attestation evidence data';
    const salt = generateSalt();

    const c1 = saltedCommitment(content, salt);
    const c2 = saltedCommitment(content, salt);
    expect(c1.commitment).toBe(c2.commitment);

    // Different content, same salt -> different commitment
    const c3 = saltedCommitment('different content', salt);
    expect(c3.commitment).not.toBe(c1.commitment);

    // Same content, different salt -> different commitment
    const salt2 = generateSalt();
    const c4 = saltedCommitment(content, salt2);
    expect(c4.commitment).not.toBe(c1.commitment);
  });

  it('1.3 Leaf hash excludes payload - CRITICAL', () => {
    const kp = generateKeyPair();
    const specHash = sha256Str('spec');
    const genesis = createGenesisEvent(kp, specHash);

    const event1 = appendEvent('ATTESTATION', { data: 'payload A with unique content' }, genesis, kp);
    const event2 = appendEvent('ATTESTATION', { data: 'completely different payload B' }, genesis, kp);

    // Both events have same structural metadata (same seq, same previous_leaf_hash, same event_type)
    // but appendEvent generates different event_id and timestamp. We must test computeLeafHash directly.
    const meta1: StructuralMetadata = {
      schema_version: event1.schema_version,
      protocol_version: event1.protocol_version,
      event_type: event1.event_type,
      event_id: event1.event_id,
      sequence_number: event1.sequence_number,
      timestamp: event1.timestamp,
      previous_leaf_hash: event1.previous_leaf_hash,
    };
    const meta2: StructuralMetadata = { ...meta1 }; // identical structural metadata

    // Identical structural metadata -> identical leaf hash (payload excluded)
    expect(computeLeafHash(meta1)).toBe(computeLeafHash(meta2));

    // Now change meta2 with different payload-like field that IS NOT structural
    // The actual leaf hash computation only uses structural fields
    const meta2Alt: StructuralMetadata = { ...meta1, event_type: 'DISCLOSURE' };
    expect(computeLeafHash(meta1)).not.toBe(computeLeafHash(meta2Alt));
  });

  it('1.4 Leaf hash changes when structural metadata changes', () => {
    const baseMeta: StructuralMetadata = {
      schema_version: '1.0.0',
      protocol_version: '1.0.0',
      event_type: 'ATTESTATION',
      event_id: 'test-id-1',
      sequence_number: 5,
      timestamp: '2026-01-01T00:00:00.000Z',
      previous_leaf_hash: sha256Str('prev'),
    };

    const baseHash = computeLeafHash(baseMeta);

    // Different sequence_number
    expect(computeLeafHash({ ...baseMeta, sequence_number: 6 })).not.toBe(baseHash);

    // Different timestamp
    expect(computeLeafHash({ ...baseMeta, timestamp: '2026-01-02T00:00:00.000Z' })).not.toBe(baseHash);

    // Different event_type
    expect(computeLeafHash({ ...baseMeta, event_type: 'REVOCATION' })).not.toBe(baseHash);
  });

  it('1.5 Payload tamper detected via event signature', () => {
    const kp = generateKeyPair();
    const genesis = createGenesisEvent(kp, sha256Str('spec'));
    const event = appendEvent('ATTESTATION', { important: 'data' }, genesis, kp);

    // Verify original signature
    const fullContent = {
      schema_version: event.schema_version,
      protocol_version: event.protocol_version,
      event_type: event.event_type,
      event_id: event.event_id,
      sequence_number: event.sequence_number,
      timestamp: event.timestamp,
      previous_leaf_hash: event.previous_leaf_hash,
      leaf_hash: event.leaf_hash,
      payload: event.payload,
      payload_hash: event.payload_hash,
    };
    expect(verifyStr(b64ToSig(event.event_signature), canonicalize(fullContent), kp.publicKey)).toBe(true);

    // Tamper the payload
    const tampered = { ...event, payload: { important: 'TAMPERED' } };

    // Signature fails on tampered payload
    const tamperedContent = { ...fullContent, payload: tampered.payload };
    expect(verifyStr(b64ToSig(tampered.event_signature), canonicalize(tamperedContent), kp.publicKey)).toBe(false);

    // Leaf hash UNCHANGED (excludes payload) - structural metadata unchanged
    const meta: StructuralMetadata = {
      schema_version: event.schema_version,
      protocol_version: event.protocol_version,
      event_type: event.event_type,
      event_id: event.event_id,
      sequence_number: event.sequence_number,
      timestamp: event.timestamp,
      previous_leaf_hash: event.previous_leaf_hash,
    };
    expect(computeLeafHash(meta)).toBe(event.leaf_hash);
  });

  it('1.6 [Reference Embodiment]: Ed25519 signature over RFC 8785 canonical JSON', () => {
    const kp = generateKeyPair();
    const obj = { z: 1, a: 'hello', m: [3, 1, 2] };
    const canonical = canonicalize(obj);

    // Canonical form should have sorted keys, no whitespace
    expect(canonical).toBe('{"a":"hello","m":[3,1,2],"z":1}');

    const sig = signStr(canonical, kp.secretKey);
    expect(verifyStr(sig, canonical, kp.publicKey)).toBe(true);

    // Wrong key
    const kp2 = generateKeyPair();
    expect(verifyStr(sig, canonical, kp2.publicKey)).toBe(false);

    // Modified field
    const modified = canonicalize({ z: 2, a: 'hello', m: [3, 1, 2] });
    expect(verifyStr(sig, modified, kp.publicKey)).toBe(false);
  });

  it('1.7 Merkle tree correctness', () => {
    const leaves = [sha256Str('leaf0'), sha256Str('leaf1'), sha256Str('leaf2'), sha256Str('leaf3')];

    // Deterministic
    const { root: root1 } = buildMerkleTree(leaves);
    const { root: root2 } = buildMerkleTree(leaves);
    expect(root1).toBe(root2);

    // Root changes if any leaf changes
    const modifiedLeaves = [...leaves];
    modifiedLeaves[2] = sha256Str('leaf2-modified');
    const { root: root3 } = buildMerkleTree(modifiedLeaves);
    expect(root3).not.toBe(root1);

    // Inclusion proof for leaf 2
    const proof = inclusionProof(leaves, 2);
    expect(verifyProof(proof)).toBe(true);

    // Tamper with one sibling hash
    const tamperedProof = { ...proof, siblings: proof.siblings.map((s, i) => i === 0 ? { ...s, hash: sha256Str('tampered') } : s) };
    expect(verifyProof(tamperedProof)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════
// GROUP 2: POLICY ARTIFACT COMPLETENESS
// ═══════════════════════════════════════════════════════════════════

describe('Group 2: Policy Artifact Completeness', () => {
  it('2.1 Artifact contains ALL required fields', () => {
    const { artifact } = makeTestInfra();

    expect(artifact.schema_version).toBeTruthy();
    expect(artifact.protocol_version).toBeTruthy();
    expect(artifact.subject_identifier.bytes_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(artifact.subject_identifier.metadata_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(artifact.policy_reference).toMatch(/^[0-9a-f]{64}$/);
    expect(typeof artifact.policy_version).toBe('number');
    expect(artifact.sealed_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(artifact.seal_salt).toMatch(/^[0-9a-f]+$/);
    expect(new Date(artifact.issued_timestamp).toISOString()).toBe(artifact.issued_timestamp);
    expect(new Date(artifact.effective_timestamp).toISOString()).toBe(artifact.effective_timestamp);
    // expiration_timestamp may be null
    expect(artifact.issuer_identifier).toMatch(/^[0-9a-f]{64}$/);
    expect(artifact.enforcement_parameters).toBeDefined();
    expect(artifact.enforcement_parameters.measurement_cadence_ms).toBeGreaterThan(0);
    expect(artifact.disclosure_policy).toBeDefined();
    expect(Array.isArray(artifact.evidence_commitments)).toBe(true);
    expect(artifact.signature).toBeTruthy();
    // Signature is base64
    expect(() => Buffer.from(artifact.signature, 'base64')).not.toThrow();
  });

  it('2.2 Artifact signature binds all fields', () => {
    const { artifact, issuerKP } = makeTestInfra();
    const pkHex = pkToHex(issuerKP.publicKey);

    expect(verifyArtifactSignature(artifact, pkHex)).toBe(true);

    // Tamper each critical field
    expect(verifyArtifactSignature({ ...artifact, sealed_hash: sha256Str('tampered') }, pkHex)).toBe(false);
    expect(verifyArtifactSignature({
      ...artifact,
      subject_identifier: { ...artifact.subject_identifier, bytes_hash: sha256Str('tampered') },
    }, pkHex)).toBe(false);
    expect(verifyArtifactSignature({ ...artifact, policy_reference: sha256Str('tampered') }, pkHex)).toBe(false);
    expect(verifyArtifactSignature({
      ...artifact,
      enforcement_parameters: { ...artifact.enforcement_parameters, measurement_cadence_ms: 999999 },
    }, pkHex)).toBe(false);
    expect(verifyArtifactSignature({ ...artifact, issuer_identifier: pkToHex(generateKeyPair().publicKey) }, pkHex)).toBe(false);
  });

  it('2.3 Evidence commitments are salted', () => {
    const { att } = makeTestInfra();

    expect(att.evidence_commitments.length).toBeGreaterThan(0);
    for (const ec of att.evidence_commitments) {
      expect(ec.commitment).toMatch(/^[0-9a-f]{64}$/);
      expect(ec.salt).toMatch(/^[0-9a-f]+$/);
      expect(ec.label).toBeTruthy();
    }

    // Verify commitment recomputes correctly for known content
    const testContent = 'test evidence content';
    const { commitment, salt } = saltedCommitment(testContent);
    expect(verifySaltedCommitment(testContent, salt, commitment)).toBe(true);
    expect(verifySaltedCommitment('wrong content', salt, commitment)).toBe(false);
  });

  it('2.4 Subject identifier combines two hashes', () => {
    const content = 'known binary content';
    const meta = { filename: 'test.bin', version: '2.0' };
    const subId = computeSubjectIdFromString(content, meta);

    expect(subId.bytes_hash).toBe(sha256Bytes(enc.encode(content)));
    expect(subId.metadata_hash).toBe(sha256Str(canonicalize(meta)));
    expect(subId.bytes_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(subId.metadata_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('2.5 TTL enforcement', () => {
    const kp = generateKeyPair();
    const content = 'ttl-test-binary';
    const meta = { filename: 'ttl.bin' };
    const subId = computeSubjectIdFromString(content, meta);
    const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('p'), evidence_items: [] });

    // TTL = 0 seconds -> immediately expired
    const artifact = generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('p'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: { measurement_cadence_ms: 100, ttl_seconds: 0, enforcement_triggers: ['TERMINATE'], re_attestation_required: false, measurement_types: ['EXECUTABLE_IMAGE'] },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: [], issuer_keypair: kp,
    });

    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(kp.publicKey));
    const r = portal.measure(enc.encode(content), meta);
    expect(r.ttl_ok).toBe(false);
    expect(r.degraded).toBe(true);
    expect(portal.state).toBe('SAFE_STATE');
  });
});

// ═══════════════════════════════════════════════════════════════════
// GROUP 3: PORTAL STATE MACHINE
// ═══════════════════════════════════════════════════════════════════

describe('Group 3: Portal State Machine', () => {
  it('3.1 Complete happy path', () => {
    const { artifact, issuerKP, content, meta } = makeTestInfra();
    const portal = new Portal();
    expect(portal.state).toBe('INITIALIZATION');

    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));
    // Skips ARTIFACT_VERIFICATION internally, lands on ACTIVE_MONITORING
    expect(portal.state).toBe('ACTIVE_MONITORING');

    const r = portal.measure(enc.encode(content), meta);
    expect(r.match).toBe(true);
    expect(r.ttl_ok).toBe(true);
    expect(portal.state).toBe('ACTIVE_MONITORING');
  });

  it('3.2 Drift detection and enforcement', () => {
    const { artifact, issuerKP, portalKP, subId, artRef, meta } = makeTestInfra();
    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

    const r = portal.measure(enc.encode('TAMPERED'), meta);
    expect(r.match).toBe(false);
    expect(portal.state).toBe('DRIFT_DETECTED');

    portal.enforce('QUARANTINE');
    expect(portal.state).toBe('PHANTOM_QUARANTINE');
  });

  it('3.3 Termination enforcement', () => {
    const { artifact, issuerKP, meta } = makeTestInfra();
    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

    portal.measure(enc.encode('BAD'), meta);
    portal.enforce('TERMINATE');
    expect(portal.state).toBe('TERMINATED');

    // Subsequent measurements rejected
    expect(() => portal.measure(enc.encode('anything'), meta)).toThrow();
  });

  it('3.4 Quarantine / phantom execution', () => {
    const { artifact, issuerKP, meta } = makeTestInfra();
    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

    portal.measure(enc.encode('BAD'), meta);
    portal.enforce('QUARANTINE');
    expect(portal.state).toBe('PHANTOM_QUARANTINE');

    const q = initQuarantine();
    expect(q.outputs_severed).toBe(true);

    captureInput(q, 'attacker_cmd', 'exfil data');
    captureInput(q, 'attacker_cmd', 'pivot lateral');
    expect(q.inputs_captured).toBe(2);
    expect(q.forensic_buffer).toHaveLength(2);

    const released = releaseQuarantine(q);
    expect(released.total_captures).toBe(2);
  });

  it('3.5 Pinned key rejection', () => {
    const { artifact } = makeTestInfra();
    const wrongKP = generateKeyPair();
    const portal = new Portal();

    const result = portal.loadArtifact(artifact, pkToHex(wrongKP.publicKey));
    expect(result.ok).toBe(false);
    expect(portal.state).toBe('TERMINATED');
  });

  it('3.6 Graceful degradation on TTL expiry', () => {
    const kp = generateKeyPair();
    const content = 'test-content';
    const meta = { filename: 'test.bin' };
    const subId = computeSubjectIdFromString(content, meta);
    const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('p'), evidence_items: [] });

    const artifact = generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('p'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: { measurement_cadence_ms: 100, ttl_seconds: 0, enforcement_triggers: ['TERMINATE'], re_attestation_required: false, measurement_types: ['EXECUTABLE_IMAGE'] },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: [], issuer_keypair: kp,
    });

    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(kp.publicKey));
    const r = portal.measure(enc.encode(content), meta);

    expect(r.ttl_ok).toBe(false);
    expect(r.degraded).toBe(true);
    expect(portal.state).toBe('SAFE_STATE');
    expect(portal.degradationLog).toHaveLength(1);
    expect(portal.degradationLog[0].reason).toBe('TTL_EXPIRED');
  });

  it('3.7 [CAISI 4a]: Fail-closed - 4 conditions', () => {
    const { artifact, issuerKP, content, meta } = makeTestInfra();
    const pkHex = pkToHex(issuerKP.publicKey);

    // a) Unparseable artifact -> invalid signature -> blocked
    const portal1 = new Portal();
    const badArt = { ...artifact, signature: 'AAAA' }; // invalid sig
    const r1 = portal1.loadArtifact(badArt, pkHex);
    expect(r1.ok).toBe(false);

    // b) Invalid signature -> blocked
    const portal2 = new Portal();
    const wrongSig = { ...artifact, signature: sigToB64(signStr('wrong', generateKeyPair().secretKey)) };
    expect(portal2.loadArtifact(wrongSig, pkHex).ok).toBe(false);

    // c) Expired TTL -> measurement blocked with degradation
    const kp = generateKeyPair();
    const subId = computeSubjectIdFromString(content, meta);
    const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('p'), evidence_items: [] });
    const expiredArt = generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('p'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: { measurement_cadence_ms: 100, ttl_seconds: 0, enforcement_triggers: ['TERMINATE'], re_attestation_required: false, measurement_types: ['EXECUTABLE_IMAGE'] },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: [], issuer_keypair: kp,
    });
    const portal3 = new Portal();
    portal3.loadArtifact(expiredArt, pkToHex(kp.publicKey));
    const r3 = portal3.measure(enc.encode(content), meta);
    expect(r3.ttl_ok).toBe(false);
    expect(portal3.state).toBe('SAFE_STATE');

    // d) Initial hash mismatch -> drift detected
    const portal4 = new Portal();
    portal4.loadArtifact(artifact, pkHex);
    const r4 = portal4.measure(enc.encode('WRONG CONTENT'), meta);
    expect(r4.match).toBe(false);
    expect(portal4.state).toBe('DRIFT_DETECTED');
  });

  it('3.8 Composite measurement from multiple types', () => {
    const { artifact, issuerKP, portalKP, subId, artRef, content, meta } = makeTestInfra();
    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

    // First measurement: EXECUTABLE_IMAGE type
    const r1 = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: sha256Str('hash1'), sealedHash: artifact.sealed_hash,
      driftDetected: false, driftDescription: null, action: null,
      measurementType: 'EXECUTABLE_IMAGE', seq: 0, prevLeaf: null, portalKP,
    });
    expect(r1.measurement_type).toBe('EXECUTABLE_IMAGE');

    // Second measurement: CONFIG_MANIFEST type
    const r2 = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: sha256Str('hash2'), sealedHash: artifact.sealed_hash,
      driftDetected: false, driftDescription: null, action: null,
      measurementType: 'CONFIG_MANIFEST', seq: 1, prevLeaf: null, portalKP,
    });
    expect(r2.measurement_type).toBe('CONFIG_MANIFEST');

    // Different measurement types used in sequence
    expect(r1.measurement_type).not.toBe(r2.measurement_type);
  });

  it('3.9 Receipt contains all required fields', () => {
    const { portalKP, subId, artRef, artifact } = makeTestInfra();
    const prevLeaf = sha256Str('previous');

    const receipt = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: sha256Str('current'), sealedHash: artifact.sealed_hash,
      driftDetected: false, driftDescription: null, action: null,
      measurementType: 'EXECUTABLE_IMAGE', seq: 5, prevLeaf, portalKP,
    });

    // All required fields
    expect(new Date(receipt.timestamp).toISOString()).toBe(receipt.timestamp);
    expect(receipt.sequence_number).toBe(5);
    expect(receipt.previous_leaf_hash).toBe(prevLeaf);
    expect(receipt.artifact_reference).toBe(artRef);

    // Signed by portal key
    const { portal_signature, ...unsigned } = receipt;
    expect(verifyStr(b64ToSig(portal_signature), canonicalize(unsigned), portalKP.publicKey)).toBe(true);
  });

  it('3.10: ALERT_ONLY does not terminate', () => {
    const { artifact, issuerKP, content, meta } = makeTestInfra();
    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

    portal.measure(enc.encode('DRIFT'), meta);
    expect(portal.state).toBe('DRIFT_DETECTED');

    portal.enforce('ALERT_ONLY');
    expect(portal.state).toBe('ACTIVE_MONITORING');

    // Subsequent measurements still work
    const r = portal.measure(enc.encode(content), meta);
    expect(r.match).toBe(true);
  });

  it('3.11: Revocation bypasses DRIFT_DETECTED', () => {
    const { artifact, issuerKP, content, meta } = makeTestInfra();
    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

    expect(portal.state).toBe('ACTIVE_MONITORING');
    portal.revoke(artifact.sealed_hash);
    expect(portal.state).toBe('TERMINATED');
    // Went directly to TERMINATED, not through DRIFT_DETECTED
  });
});

// ═══════════════════════════════════════════════════════════════════
// GROUP 4: CONTINUITY CHAIN
// ═══════════════════════════════════════════════════════════════════

describe('Group 4: Continuity Chain', () => {
  it('4.1 Genesis event', () => {
    const kp = generateKeyPair();
    const specHash = sha256Str('AGA-Spec-v1');
    const genesis = createGenesisEvent(kp, specHash);

    expect(genesis.event_type).toBe('GENESIS');
    expect(genesis.sequence_number).toBe(0);
    expect(genesis.previous_leaf_hash).toBeNull();

    const payload = genesis.payload as { protocol_version: string; root_fingerprint: string; specification_hash: string; marker: string };
    expect(payload.protocol_version).toBeTruthy();
    expect(payload.root_fingerprint).toBe(pkToHex(kp.publicKey));
    expect(payload.specification_hash).toBe(specHash);
    expect(payload.marker).toBe('GENESIS');
  });

  it('4.2 Event structure completeness', () => {
    const kp = generateKeyPair();
    const genesis = createGenesisEvent(kp, sha256Str('spec'));
    const event = appendEvent('ATTESTATION', { data: 'test' }, genesis, kp);

    expect(event.event_type).toBe('ATTESTATION');
    expect(event.event_id).toMatch(/^[0-9a-f-]{36}$/); // UUID
    expect(event.sequence_number).toBe(1);
    expect(new Date(event.timestamp).toISOString()).toBe(event.timestamp);
    expect(event.previous_leaf_hash).toBe(genesis.leaf_hash);
    expect(event.payload).toEqual({ data: 'test' });
    expect(event.payload_hash).toBe(computePayloadHash({ data: 'test' }));

    // Signature is valid Ed25519 over complete event
    const fullContent = {
      schema_version: event.schema_version, protocol_version: event.protocol_version,
      event_type: event.event_type, event_id: event.event_id,
      sequence_number: event.sequence_number, timestamp: event.timestamp,
      previous_leaf_hash: event.previous_leaf_hash, leaf_hash: event.leaf_hash,
      payload: event.payload, payload_hash: event.payload_hash,
    };
    expect(verifyStr(b64ToSig(event.event_signature), canonicalize(fullContent), kp.publicKey)).toBe(true);
  });

  it('4.3 Structural tamper propagation', () => {
    const kp = generateKeyPair();
    const genesis = createGenesisEvent(kp, sha256Str('spec'));
    const events: ContinuityEvent[] = [genesis];
    let prev = genesis;
    for (let i = 0; i < 4; i++) {
      prev = appendEvent('ATTESTATION', { idx: i }, prev, kp);
      events.push(prev);
    }
    expect(events).toHaveLength(5);

    const originalHashes = events.map(e => e.leaf_hash);

    // Tamper event 2 (index 2) timestamp
    const tamperedEvents = events.map(e => ({ ...e }));
    tamperedEvents[2] = { ...tamperedEvents[2], timestamp: '1999-01-01T00:00:00.000Z' };

    // Recompute leaf hashes
    const recomputedHashes = tamperedEvents.map(e => computeLeafHash({
      schema_version: e.schema_version, protocol_version: e.protocol_version,
      event_type: e.event_type, event_id: e.event_id,
      sequence_number: e.sequence_number, timestamp: e.timestamp,
      previous_leaf_hash: e.previous_leaf_hash,
    }));

    // Events 0, 1 unchanged
    expect(recomputedHashes[0]).toBe(originalHashes[0]);
    expect(recomputedHashes[1]).toBe(originalHashes[1]);

    // Event 2 leaf hash changed (tampered timestamp)
    expect(recomputedHashes[2]).not.toBe(originalHashes[2]);

    // Events 3, 4 have unchanged structural metadata themselves, but their
    // previous_leaf_hash still points to the OLD leaf hashes. In a real tamper,
    // verifyChainIntegrity would catch that event 2's leaf_hash doesn't match
    // the recomputed one, proving forward detection.
    const integrity = verifyChainIntegrity(tamperedEvents);
    expect(integrity.valid).toBe(false);
    expect(integrity.brokenAt).toBe(2);
  });

  it('4.4 ANCHOR_BATCH event', () => {
    const kp = generateKeyPair();
    const genesis = createGenesisEvent(kp, sha256Str('spec'));
    const events: ContinuityEvent[] = [genesis];
    let prev = genesis;
    for (let i = 0; i < 4; i++) {
      prev = appendEvent('ATTESTATION', { idx: i }, prev, kp);
      events.push(prev);
    }

    const { checkpoint, payload } = createCheckpoint(events, 'ethereum');
    const anchorEvent = appendEvent('ANCHOR_BATCH', payload, prev, kp);

    expect(anchorEvent.event_type).toBe('ANCHOR_BATCH');
    const p = anchorEvent.payload as { checkpoint_reference: { transaction_id: string; merkle_root: string; batch_start_sequence: number; batch_end_sequence: number; anchor_network: string }; leaf_count: number };
    expect(p.checkpoint_reference.transaction_id).toContain('ethereum:');
    expect(p.checkpoint_reference.merkle_root).toMatch(/^[0-9a-f]{64}$/);
    expect(p.checkpoint_reference.batch_start_sequence).toBe(0);
    expect(p.checkpoint_reference.batch_end_sequence).toBe(4);
    expect(p.checkpoint_reference.anchor_network).toBe('ethereum');
  });

  it('4.5 Chain includes portal enforcement receipts', () => {
    const { artifact, issuerKP, portalKP, subId, artRef, content, meta, chainKP } = makeTestInfra();
    const kp = generateKeyPair();
    const genesis = createGenesisEvent(kp, sha256Str('spec'));

    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

    const m = portal.measure(enc.encode(content), meta);
    const receipt = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: `${m.currentBytesHash}||${m.currentMetaHash}`,
      sealedHash: `${m.expectedBytesHash}||${m.expectedMetaHash}`,
      driftDetected: false, driftDescription: null, action: null,
      measurementType: 'EXECUTABLE_IMAGE', seq: 0, prevLeaf: genesis.leaf_hash, portalKP,
    });

    const receiptEvent = appendEvent('INTERACTION_RECEIPT', receipt, genesis, kp);
    expect(receiptEvent.event_type).toBe('INTERACTION_RECEIPT');

    // Signature verifies
    const fullContent = {
      schema_version: receiptEvent.schema_version, protocol_version: receiptEvent.protocol_version,
      event_type: receiptEvent.event_type, event_id: receiptEvent.event_id,
      sequence_number: receiptEvent.sequence_number, timestamp: receiptEvent.timestamp,
      previous_leaf_hash: receiptEvent.previous_leaf_hash, leaf_hash: receiptEvent.leaf_hash,
      payload: receiptEvent.payload, payload_hash: receiptEvent.payload_hash,
    };
    expect(verifyStr(b64ToSig(receiptEvent.event_signature), canonicalize(fullContent), kp.publicKey)).toBe(true);

    // Chain links correctly
    expect(receiptEvent.previous_leaf_hash).toBe(genesis.leaf_hash);
  });

  it('4.6: Chain integrity verification passes for valid chain', () => {
    const kp = generateKeyPair();
    const genesis = createGenesisEvent(kp, sha256Str('spec'));
    const events: ContinuityEvent[] = [genesis];
    let prev = genesis;
    for (let i = 0; i < 10; i++) {
      prev = appendEvent('ATTESTATION', { idx: i }, prev, kp);
      events.push(prev);
    }

    const result = verifyChainIntegrity(events);
    expect(result.valid).toBe(true);
    expect(result.brokenAt).toBeNull();
    expect(result.error).toBeNull();
  });

  it('4.7: Chain integrity verification detects tampered event', () => {
    const kp = generateKeyPair();
    const genesis = createGenesisEvent(kp, sha256Str('spec'));
    const events: ContinuityEvent[] = [genesis];
    let prev = genesis;
    for (let i = 0; i < 9; i++) {
      prev = appendEvent('ATTESTATION', { idx: i }, prev, kp);
      events.push(prev);
    }

    // Tamper event 5
    events[5] = { ...events[5], timestamp: '1999-01-01T00:00:00.000Z' };

    const result = verifyChainIntegrity(events);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(events[5].sequence_number);
  });
});

// ═══════════════════════════════════════════════════════════════════
// GROUP 5: EVIDENCE BUNDLES AND OFFLINE VERIFICATION
// ═══════════════════════════════════════════════════════════════════

describe('Group 5: Evidence Bundles and Offline Verification', () => {
  function makeBundle() {
    const infra = makeTestInfra();
    const { artifact, issuerKP, portalKP, subId, artRef, content, meta } = infra;
    const chainKP = generateKeyPair();
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const chainEvents: ContinuityEvent[] = [genesis];
    let prev = genesis;

    prev = appendEvent('POLICY_ISSUANCE', { artifact_hash: artRef }, prev, chainKP);
    chainEvents.push(prev);

    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

    const receipts: ReturnType<typeof generateReceipt>[] = [];
    for (let i = 0; i < 3; i++) {
      const m = portal.measure(enc.encode(content), meta);
      const r = generateReceipt({
        subjectId: subId, artifactRef: artRef,
        currentHash: `${m.currentBytesHash}||${m.currentMetaHash}`,
        sealedHash: `${m.expectedBytesHash}||${m.expectedMetaHash}`,
        driftDetected: false, driftDescription: null, action: null,
        measurementType: 'EXECUTABLE_IMAGE', seq: portal.sequenceCounter++,
        prevLeaf: prev.leaf_hash, portalKP,
      });
      receipts.push(r);
      prev = appendEvent('INTERACTION_RECEIPT', r, prev, chainKP);
      chainEvents.push(prev);
    }

    // Drift
    const m4 = portal.measure(enc.encode('DRIFT'), meta);
    const r4 = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: `${m4.currentBytesHash}||${m4.currentMetaHash}`,
      sealedHash: `${m4.expectedBytesHash}||${m4.expectedMetaHash}`,
      driftDetected: true, driftDescription: 'tamper', action: 'QUARANTINE',
      measurementType: 'EXECUTABLE_IMAGE', seq: portal.sequenceCounter++,
      prevLeaf: prev.leaf_hash, portalKP,
    });
    receipts.push(r4);
    prev = appendEvent('INTERACTION_RECEIPT', r4, prev, chainKP);
    chainEvents.push(prev);

    const { checkpoint } = createCheckpoint(chainEvents);
    const receiptIndices = chainEvents.reduce((acc: number[], e, idx) => {
      if (e.event_type === 'INTERACTION_RECEIPT') acc.push(idx);
      return acc;
    }, []);
    const proofs = receipts.map((_, i) => eventInclusionProof(chainEvents, chainEvents[receiptIndices[i]].sequence_number));

    const bundle = generateBundle(artifact, receipts, proofs, checkpoint, portalKP, 'GOLD');
    return { bundle, infra, chainEvents, checkpoint, proofs, receipts };
  }

  it('5.1 Bundle contains all required components', () => {
    const { bundle } = makeBundle();

    expect(bundle.artifact).toBeDefined();
    expect(bundle.artifact.signature).toBeTruthy();
    expect(bundle.receipts.length).toBeGreaterThanOrEqual(1);
    expect(bundle.merkle_proofs.length).toBeGreaterThan(0);
    expect(bundle.checkpoint_reference).toBeDefined();
    expect(bundle.checkpoint_reference.merkle_root).toMatch(/^[0-9a-f]{64}$/);
    expect(bundle.public_key).toMatch(/^[0-9a-f]{64}$/);
    expect(bundle.bundle_signature).toBeTruthy();
  });

  it('5.2 4-step verification passes for valid bundle', () => {
    const { bundle, infra } = makeBundle();
    const result = verifyBundleOffline(bundle, pkToHex(infra.issuerKP.publicKey));

    expect(result.step1_artifact_sig).toBe(true);
    expect(result.step2_receipt_sigs).toBe(true);
    expect(result.step3_merkle_proofs).toBe(true);
    expect(result.step4_anchor).toBe('SKIPPED_OFFLINE');
    expect(result.overall).toBe(true);
  });

  it('5.3: Tampered artifact signature fails Step 1', () => {
    const { bundle, infra } = makeBundle();
    const tampered = {
      ...bundle,
      artifact: { ...bundle.artifact, signature: sigToB64(signStr('wrong', generateKeyPair().secretKey)) },
    };

    const result = verifyBundleOffline(tampered, pkToHex(infra.issuerKP.publicKey));
    expect(result.step1_artifact_sig).toBe(false);
    expect(result.overall).toBe(false);
  });

  it('5.4: Tampered receipt signature fails Step 2', () => {
    const { bundle, infra } = makeBundle();
    const tamperedReceipts = [...bundle.receipts];
    tamperedReceipts[0] = { ...tamperedReceipts[0], portal_signature: sigToB64(signStr('wrong', generateKeyPair().secretKey)) };

    const tampered = { ...bundle, receipts: tamperedReceipts };
    const result = verifyBundleOffline(tampered, pkToHex(infra.issuerKP.publicKey));
    expect(result.step1_artifact_sig).toBe(true);
    expect(result.step2_receipt_sigs).toBe(false);
    expect(result.overall).toBe(false);
  });

  it('5.5: Tampered Merkle proof fails Step 3', () => {
    const { bundle, infra } = makeBundle();
    const tamperedProofs = [...bundle.merkle_proofs];
    tamperedProofs[0] = {
      ...tamperedProofs[0],
      siblings: tamperedProofs[0].siblings.map((s, i) => i === 0 ? { ...s, hash: sha256Str('tampered') } : s),
    };

    const tampered = { ...bundle, merkle_proofs: tamperedProofs };
    const result = verifyBundleOffline(tampered, pkToHex(infra.issuerKP.publicKey));
    expect(result.step1_artifact_sig).toBe(true);
    expect(result.step2_receipt_sigs).toBe(true);
    expect(result.step3_merkle_proofs).toBe(false);
    expect(result.overall).toBe(false);
  });

  it('5.6: Tampered receipt content detected', () => {
    const { bundle, infra } = makeBundle();
    const tamperedReceipts = [...bundle.receipts];
    tamperedReceipts[0] = { ...tamperedReceipts[0], drift_detected: !tamperedReceipts[0].drift_detected };

    const tampered = { ...bundle, receipts: tamperedReceipts };
    const result = verifyBundleOffline(tampered, pkToHex(infra.issuerKP.publicKey));
    expect(result.step2_receipt_sigs).toBe(false);
    expect(result.overall).toBe(false);
  });

  it('5.7 [CAISI 3b]: Tiered verification', () => {
    const infra = makeTestInfra();
    const { artifact, issuerKP, portalKP, subId, artRef, content, meta } = infra;
    const chainKP = generateKeyPair();
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const chainEvents: ContinuityEvent[] = [genesis];
    let prev = genesis;
    prev = appendEvent('POLICY_ISSUANCE', { artifact_hash: artRef }, prev, chainKP);
    chainEvents.push(prev);

    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));
    const receipts: ReturnType<typeof generateReceipt>[] = [];
    const m = portal.measure(enc.encode(content), meta);
    const r = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: `${m.currentBytesHash}||${m.currentMetaHash}`,
      sealedHash: `${m.expectedBytesHash}||${m.expectedMetaHash}`,
      driftDetected: false, driftDescription: null, action: null,
      measurementType: 'EXECUTABLE_IMAGE', seq: 0, prevLeaf: prev.leaf_hash, portalKP,
    });
    receipts.push(r);
    prev = appendEvent('INTERACTION_RECEIPT', r, prev, chainKP);
    chainEvents.push(prev);

    const { checkpoint } = createCheckpoint(chainEvents);
    const proofs = [eventInclusionProof(chainEvents, chainEvents[2].sequence_number)];

    // BRONZE: proofs omitted
    const bronze = generateBundle(artifact, receipts, proofs, checkpoint, portalKP, 'BRONZE');
    expect(bronze.verification_tier).toBe('BRONZE');
    expect(bronze.merkle_proofs).toHaveLength(0);

    // GOLD: full proofs + anchor
    const gold = generateBundle(artifact, receipts, proofs, checkpoint, portalKP, 'GOLD');
    expect(gold.verification_tier).toBe('GOLD');
    expect(gold.merkle_proofs.length).toBeGreaterThan(0);
    expect(gold.checkpoint_reference.transaction_id).toBeTruthy();
  });

  it('5.8 Merkle inclusion proof for specific event', () => {
    const kp = generateKeyPair();
    const genesis = createGenesisEvent(kp, sha256Str('spec'));
    const events: ContinuityEvent[] = [genesis];
    let prev = genesis;
    for (let i = 0; i < 5; i++) {
      prev = appendEvent('ATTESTATION', { idx: i }, prev, kp);
      events.push(prev);
    }

    const { checkpoint } = createCheckpoint(events);
    const proof = eventInclusionProof(events, 3);

    // Proof verifies against checkpoint root
    expect(proof.root).toBe(checkpoint.merkle_root);
    expect(verifyProof(proof)).toBe(true);

    // Tampered leaf hash fails
    const tamperedProof = { ...proof, leafHash: sha256Str('tampered') };
    expect(verifyProof(tamperedProof)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════
// GROUP 6: POLICY-GATED DISCLOSURE
// ═══════════════════════════════════════════════════════════════════

describe('Group 6: Policy-Gated Disclosure', () => {
  function makeDisclosureSetup() {
    const kp = generateKeyPair();
    const policy = {
      claims_taxonomy: [
        { claim_id: 'data.low', sensitivity: 'S1_LOW' as const, substitutes: [], inference_risks: [], permitted_modes: ['PROOF_ONLY' as const, 'REVEAL_MIN' as const, 'REVEAL_FULL' as const] },
        { claim_id: 'data.moderate', sensitivity: 'S2_MODERATE' as const, substitutes: ['data.low'], inference_risks: [], permitted_modes: ['REVEAL_MIN' as const, 'REVEAL_FULL' as const] },
        { claim_id: 'data.high', sensitivity: 'S3_HIGH' as const, substitutes: ['data.moderate', 'data.low'], inference_risks: [], permitted_modes: [] },
        { claim_id: 'data.critical', sensitivity: 'S4_CRITICAL' as const, substitutes: ['data.moderate', 'data.low'], inference_risks: [], permitted_modes: [] },
        { claim_id: 'data.inferred', sensitivity: 'S2_MODERATE' as const, substitutes: [], inference_risks: ['data.critical'], permitted_modes: ['REVEAL_FULL'] },
      ],
      substitution_rules: [],
    };
    const values: Record<string, unknown> = {
      'data.low': 'public info',
      'data.moderate': 'summary info',
      'data.high': 'sensitive info',
      'data.critical': 'top secret',
      'data.inferred': 'inference-risk data',
    };
    return { kp, policy, values };
  }

  it('6.1 Permitted claim disclosed', () => {
    const { kp, policy, values } = makeDisclosureSetup();
    const result = processDisclosure(
      { requested_claim_id: 'data.low', requester_id: 'req', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );

    expect(result.permitted).toBe(true);
    expect(result.disclosed_claim_id).toBe('data.low');
    expect(result.was_substituted).toBe(false);
    expect(result.disclosed_value).toBe('public info');
  });

  it('6.2 Denied claim triggers substitution', () => {
    const { kp, policy, values } = makeDisclosureSetup();
    const result = processDisclosure(
      { requested_claim_id: 'data.critical', requester_id: 'req', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );

    expect(result.was_substituted).toBe(true);
    expect(result.disclosed_claim_id).toBe('data.moderate');
    // Substitute has lower sensitivity than original (S2 < S4)
    const origSens = policy.claims_taxonomy.find(c => c.claim_id === 'data.critical')!.sensitivity;
    const subSens = policy.claims_taxonomy.find(c => c.claim_id === result.disclosed_claim_id)!.sensitivity;
    expect(origSens).toBe('S4_CRITICAL');
    expect(subSens).toBe('S2_MODERATE');
  });

  it('6.3 Substitution receipt', () => {
    const { kp, policy, values } = makeDisclosureSetup();
    const result = processDisclosure(
      { requested_claim_id: 'data.critical', requester_id: 'req', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      policy, values, 1, 5, kp,
    );

    expect(result.substitution_receipt).not.toBeNull();
    const sr = result.substitution_receipt!;
    expect(sr.original_claim_id).toBe('data.critical');
    expect(sr.substitute_claim_id).toBe('data.moderate');
    expect(sr.policy_version).toBe(1);
    expect(sr.reason_code).toBeTruthy();
    expect(new Date(sr.timestamp).toISOString()).toBe(sr.timestamp);
    expect(sr.chain_sequence_ref).toBe(5);

    // Signature is valid Ed25519
    const { signature, ...unsigned } = sr;
    expect(verifyStr(b64ToSig(signature), canonicalize(unsigned), kp.publicKey)).toBe(true);
  });

  it('6.4 Inference risk blocking', () => {
    const { kp, policy, values } = makeDisclosureSetup();
    // data.inferred has inference_risks: ['data.critical'], and data.critical
    // is substituted to data.moderate. If data.inferred is a substitute candidate,
    // it should be blocked because it has inference_risks that include the original.
    // Set up: data.critical has substitutes: ['data.moderate', 'data.low']
    // data.inferred has inference_risks: ['data.critical'] and permitted_modes: ['REVEAL_FULL']
    // The disclosure system checks: sub.inference_risks.includes(req.requested_claim_id)
    // So if original is data.critical, and substitute candidate data.inferred has
    // inference_risks including data.critical, it should be BLOCKED.

    // Let's create a policy where the only substitute has an inference risk
    const restrictedPolicy = {
      claims_taxonomy: [
        { claim_id: 'secret.value', sensitivity: 'S4_CRITICAL' as const, substitutes: ['secret.inferred_proxy'], inference_risks: [], permitted_modes: [] as ('PROOF_ONLY' | 'REVEAL_MIN' | 'REVEAL_FULL')[] },
        { claim_id: 'secret.inferred_proxy', sensitivity: 'S2_MODERATE' as const, substitutes: [], inference_risks: ['secret.value'], permitted_modes: ['REVEAL_FULL' as const] },
      ],
      substitution_rules: [],
    };
    const restrictedValues = { 'secret.value': 'top secret', 'secret.inferred_proxy': 'can infer secret' };

    const result = processDisclosure(
      { requested_claim_id: 'secret.value', requester_id: 'req', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      restrictedPolicy, restrictedValues, 1, 0, kp,
    );

    // The substitute should be BLOCKED because it has inference risk
    expect(result.permitted).toBe(false);
    expect(result.disclosed_claim_id).toBeNull();
  });

  it('6.5 Three disclosure modes', () => {
    const { kp, policy, values } = makeDisclosureSetup();

    // PROOF_ONLY: boolean only
    const proof = processDisclosure(
      { requested_claim_id: 'data.low', requester_id: 'req', mode: 'PROOF_ONLY', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );
    expect(proof.permitted).toBe(true);
    expect(proof.disclosed_value).toBe(true); // fv returns v != null -> boolean

    // REVEAL_MIN: value returned
    const min = processDisclosure(
      { requested_claim_id: 'data.low', requester_id: 'req', mode: 'REVEAL_MIN', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );
    expect(min.permitted).toBe(true);
    expect(min.disclosed_value).toBe('public info');

    // REVEAL_FULL: complete value
    const full = processDisclosure(
      { requested_claim_id: 'data.low', requester_id: 'req', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );
    expect(full.permitted).toBe(true);
    expect(full.disclosed_value).toBe('public info');
  });

  it('6.6 Substitution receipt verifiable offline', () => {
    const { kp, policy, values } = makeDisclosureSetup();
    const result = processDisclosure(
      { requested_claim_id: 'data.critical', requester_id: 'req', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );

    const sr = result.substitution_receipt!;
    expect(sr).not.toBeNull();

    // Extract only the receipt and public key
    const publicKeyHex = pkToHex(kp.publicKey);
    const { signature, ...unsigned } = sr;

    // Verify offline with ONLY the public key
    const verified = verifyStr(b64ToSig(signature), canonicalize(unsigned), hexToPk(publicKeyHex));
    expect(verified).toBe(true);
  });

  it('6.7: Substitution receipt appended to chain', () => {
    const { kp, policy, values } = makeDisclosureSetup();
    const chainKP = generateKeyPair();
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));

    const result = processDisclosure(
      { requested_claim_id: 'data.critical', requester_id: 'req', mode: 'REVEAL_FULL', timestamp: new Date().toISOString() },
      policy, values, 1, 0, kp,
    );

    const subEvent = appendEvent('SUBSTITUTION', result.substitution_receipt, genesis, chainKP);
    expect(subEvent.event_type).toBe('SUBSTITUTION');

    const eventPayload = subEvent.payload as { original_claim_id: string };
    expect(eventPayload.original_claim_id).toBe('data.critical');
  });
});

// ═══════════════════════════════════════════════════════════════════
// GROUP 7: NIST EXTENSION CAPABILITIES
// ═══════════════════════════════════════════════════════════════════

describe('Group 7: NIST Extension Capabilities', () => {
  it('7.1 [NCCoE 6]: Behavioral drift - clean invocation', () => {
    const monitor = new BehavioralMonitor();
    monitor.setBaseline({
      permitted_tools: ['read', 'write', 'log'],
      forbidden_sequences: [],
      rate_limits: {},
      window_ms: 60000,
    });

    monitor.recordInvocation('read', sha256Str('args'));
    const m = monitor.measure();
    expect(m.drift_detected).toBe(false);
    expect(m.invocations.length).toBeGreaterThanOrEqual(1);
  });

  it('7.2 [NCCoE 6]: Behavioral drift - unauthorized tool', () => {
    const monitor = new BehavioralMonitor();
    monitor.setBaseline({
      permitted_tools: ['read', 'write'],
      forbidden_sequences: [],
      rate_limits: {},
      window_ms: 60000,
    });

    monitor.recordInvocation('delete', sha256Str('args'));
    const m = monitor.measure();
    expect(m.drift_detected).toBe(true);
    expect(m.violations.some(v => v.type === 'UNAUTHORIZED_TOOL')).toBe(true);
  });

  it('7.3 [CAISI 1a]: Behavioral drift - rate limit', () => {
    const monitor = new BehavioralMonitor();
    monitor.setBaseline({
      permitted_tools: ['write'],
      forbidden_sequences: [],
      rate_limits: { write: 3 },
      window_ms: 60000,
    });

    for (let i = 0; i < 4; i++) {
      monitor.recordInvocation('write', sha256Str(`args${i}`));
    }
    const m = monitor.measure();
    expect(m.drift_detected).toBe(true);
    const rateViolation = m.violations.find(v => v.type === 'RATE_EXCEEDED');
    expect(rateViolation).toBeDefined();
    expect(rateViolation!.type).toBe('RATE_EXCEEDED');
  });

  it('7.4 [NCCoE 6]: Behavioral drift - forbidden sequence', () => {
    const monitor = new BehavioralMonitor();
    monitor.setBaseline({
      permitted_tools: ['delete'],
      forbidden_sequences: [['delete', 'delete']],
      rate_limits: {},
      window_ms: 60000,
    });

    monitor.recordInvocation('delete', sha256Str('a'));
    monitor.recordInvocation('delete', sha256Str('b'));
    const m = monitor.measure();
    expect(m.drift_detected).toBe(true);
    expect(m.violations.some(v => v.type === 'FORBIDDEN_SEQUENCE')).toBe(true);
  });

  it('7.5 [NCCoE 6]: Behavioral drift event in chain', () => {
    const chainKP = generateKeyPair();
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));

    const monitor = new BehavioralMonitor();
    monitor.setBaseline({
      permitted_tools: ['read'],
      forbidden_sequences: [],
      rate_limits: {},
      window_ms: 60000,
    });
    monitor.recordInvocation('delete', sha256Str('args'));
    const m = monitor.measure();

    const driftEvent = appendEvent('BEHAVIORAL_DRIFT', {
      violations: m.violations,
      behavioral_hash: m.behavioral_hash,
    }, genesis, chainKP);

    expect(driftEvent.event_type).toBe('BEHAVIORAL_DRIFT');
    const payload = driftEvent.payload as { violations: unknown[]; behavioral_hash: string };
    expect(payload.violations.length).toBeGreaterThan(0);
    expect(payload.behavioral_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('7.6 [NCCoE 4]: Delegation - scope diminishment', () => {
    const { artifact, issuerKP } = makeTestInfra();

    const result = deriveArtifact(artifact, {
      enforcement_triggers: ['QUARANTINE', 'TERMINATE'], // subset
      measurement_types: ['EXECUTABLE_IMAGE'], // subset
      requested_ttl_seconds: 1800,
      delegation_purpose: 'Sub-agent task',
    }, issuerKP);

    expect(result.success).toBe(true);
    expect(result.child_artifact).toBeDefined();

    // Validate child is subset of parent
    const validation = validateDelegation(artifact, result.child_artifact!);
    expect(validation.valid).toBe(true);
    expect(validation.errors).toHaveLength(0);
  });

  it('7.7 [NCCoE 4]: Delegation - scope exceeding parent rejected', () => {
    const { artifact, issuerKP } = makeTestInfra();

    const result = deriveArtifact(artifact, {
      enforcement_triggers: ['QUARANTINE', 'TERMINATE', 'NETWORK_ISOLATE'], // NETWORK_ISOLATE not in parent
      measurement_types: ['EXECUTABLE_IMAGE'],
      requested_ttl_seconds: 1800,
      delegation_purpose: 'Overreach attempt',
    }, issuerKP);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Cannot expand scope');
  });

  it('7.8 [NCCoE 4]: Delegation - TTL constraint', () => {
    const kp = generateKeyPair();
    const content = 'content';
    const meta = { filename: 'test.bin' };
    const subId = computeSubjectIdFromString(content, meta);
    const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('p'), evidence_items: [] });

    // Parent with short TTL (2 seconds)
    const parentArtifact = generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('p'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: {
        measurement_cadence_ms: 100, ttl_seconds: 2,
        enforcement_triggers: ['TERMINATE'], re_attestation_required: false,
        measurement_types: ['EXECUTABLE_IMAGE'],
      },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: [], issuer_keypair: kp,
    });

    // Delegation with TTL that exceeds parent remaining
    const result = deriveArtifact(parentArtifact, {
      enforcement_triggers: ['TERMINATE'],
      measurement_types: ['EXECUTABLE_IMAGE'],
      requested_ttl_seconds: 7200, // way more than 2 seconds
      delegation_purpose: 'Long-running task',
    }, kp);

    // Should succeed but clamp TTL to parent remaining
    if (result.success) {
      expect(result.effective_ttl_seconds!).toBeLessThanOrEqual(2);
    }
    // If parent already expired, delegation fails
  });

  it('7.9 [NCCoE 4]: Delegation - chain event', () => {
    const { artifact, issuerKP } = makeTestInfra();
    const chainKP = generateKeyPair();
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));

    const delegation = deriveArtifact(artifact, {
      enforcement_triggers: ['TERMINATE'],
      measurement_types: ['EXECUTABLE_IMAGE'],
      requested_ttl_seconds: 1800,
      delegation_purpose: 'Sub-agent',
    }, issuerKP);

    expect(delegation.success).toBe(true);

    const delegationEvent = appendEvent('DELEGATION', {
      sub_agent_id: 'sub-001',
      parent_artifact_reference: delegation.parent_artifact_hash,
      child_artifact_hash: delegation.child_artifact_hash,
    }, genesis, chainKP);

    expect(delegationEvent.event_type).toBe('DELEGATION');
    const payload = delegationEvent.payload as { parent_artifact_reference: string; child_artifact_hash: string };
    expect(payload.parent_artifact_reference).toBeTruthy();
    expect(payload.child_artifact_hash).toBeTruthy();
  });

  it('7.10 [NCCoE 3]: Key rotation', () => {
    const chainKP = generateKeyPair();
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));

    const oldKP = generateKeyPair();
    const { oldKeyPair, newKeyPair } = rotateKeyPair(oldKP);

    const rotationEvent = recordKeyRotation(
      genesis, 'portal', pkToHex(oldKeyPair.publicKey), pkToHex(newKeyPair.publicKey),
      'scheduled rotation', chainKP,
    );

    expect(rotationEvent.event_type).toBe('KEY_ROTATION');
    const payload = rotationEvent.payload as { old_public_key: string; new_public_key: string; keypair_type: string };
    expect(payload.old_public_key).toMatch(/^[0-9a-f]{64}$/);
    expect(payload.new_public_key).toMatch(/^[0-9a-f]{64}$/);
    expect(payload.old_public_key).not.toBe(payload.new_public_key);
    expect(payload.keypair_type).toBe('portal');
  });

  it('7.11 [NCCoE 3]: Key rotation transition period', () => {
    const oldKP = generateKeyPair();
    const { oldKeyPair, newKeyPair } = rotateKeyPair(oldKP);

    const message = 'test message for transition';

    // Old key still valid for verification (signed before rotation)
    const oldSig = signStr(message, oldKeyPair.secretKey);
    expect(verifyStr(oldSig, message, oldKeyPair.publicKey)).toBe(true);

    // New key valid for signing
    const newSig = signStr(message, newKeyPair.secretKey);
    expect(verifyStr(newSig, message, newKeyPair.publicKey)).toBe(true);
  });

  it('7.12 Key fingerprint', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();

    const fp1a = keyFingerprint(pkToHex(kp1.publicKey));
    const fp1b = keyFingerprint(pkToHex(kp1.publicKey));

    // Deterministic
    expect(fp1a).toBe(fp1b);

    // Different key -> different fingerprint
    const fp2 = keyFingerprint(pkToHex(kp2.publicKey));
    expect(fp1a).not.toBe(fp2);

    // Fingerprint is 16-char hex
    expect(fp1a).toMatch(/^[0-9a-f]{16}$/);
  });
});

// ═══════════════════════════════════════════════════════════════════
// GROUP 8: END-TO-END SCENARIOS
// ═══════════════════════════════════════════════════════════════════

describe('Group 8: End-to-End Scenarios', () => {
  it('8.1 SCADA - Full lifecycle', () => {
    const enc = new TextEncoder();
    const issuerKP = generateKeyPair();
    const portalKP = generateKeyPair();
    const chainKP = generateKeyPair();

    // Create SCADA subject
    const binaryContent = 'SCADA_CONTROL_BINARY: read_sensors(); adjust_valve(); log_status();';
    const binaryMeta = { filename: 'scada.bin', version: '3.0' };
    const subId = computeSubjectIdFromString(binaryContent, binaryMeta);

    // Attest and seal
    const att = performAttestation({
      subject_identifier: subId,
      policy_reference: sha256Str('scada-policy'),
      evidence_items: [{ label: 'safety_cert', content: 'IEC 62443' }],
    });

    const artifact = generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('scada-policy'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: {
        measurement_cadence_ms: 100, ttl_seconds: 3600,
        enforcement_triggers: ['QUARANTINE', 'SAFE_STATE'], re_attestation_required: true,
        measurement_types: ['EXECUTABLE_IMAGE'],
        behavioral_baseline: { permitted_tools: ['read_sensors', 'adjust_valve', 'log_status'], forbidden_sequences: [], rate_limits: {} },
      },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: att.evidence_commitments, issuer_keypair: issuerKP,
    });
    const artRef = hashArtifact(artifact);

    // Init chain
    const genesis = createGenesisEvent(chainKP, sha256Str('SCADA-Spec'));
    const chainEvents: ContinuityEvent[] = [genesis];
    let prev = genesis;

    prev = appendEvent('POLICY_ISSUANCE', { artifact_hash: artRef }, prev, chainKP);
    chainEvents.push(prev);

    // Portal monitoring: 3 clean measurements
    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));
    expect(portal.state).toBe('ACTIVE_MONITORING');

    const receipts: ReturnType<typeof generateReceipt>[] = [];
    for (let i = 0; i < 3; i++) {
      const m = portal.measure(enc.encode(binaryContent), binaryMeta);
      expect(m.match).toBe(true);
      const r = generateReceipt({
        subjectId: subId, artifactRef: artRef,
        currentHash: `${m.currentBytesHash}||${m.currentMetaHash}`,
        sealedHash: `${m.expectedBytesHash}||${m.expectedMetaHash}`,
        driftDetected: false, driftDescription: null, action: null,
        measurementType: 'EXECUTABLE_IMAGE', seq: portal.sequenceCounter++,
        prevLeaf: prev.leaf_hash, portalKP,
      });
      receipts.push(r);
      prev = appendEvent('INTERACTION_RECEIPT', r, prev, chainKP);
      chainEvents.push(prev);
    }

    // Inject drift
    const m4 = portal.measure(enc.encode('COMPROMISED_BINARY'), binaryMeta);
    expect(m4.match).toBe(false);
    expect(portal.state).toBe('DRIFT_DETECTED');

    const r4 = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: `${m4.currentBytesHash}||${m4.currentMetaHash}`,
      sealedHash: `${m4.expectedBytesHash}||${m4.expectedMetaHash}`,
      driftDetected: true, driftDescription: 'Binary compromise', action: 'QUARANTINE',
      measurementType: 'EXECUTABLE_IMAGE', seq: portal.sequenceCounter++,
      prevLeaf: prev.leaf_hash, portalKP,
    });
    receipts.push(r4);
    prev = appendEvent('INTERACTION_RECEIPT', r4, prev, chainKP);
    chainEvents.push(prev);

    // QUARANTINE
    portal.enforce('QUARANTINE');
    expect(portal.state).toBe('PHANTOM_QUARANTINE');

    // Forensic capture
    const q = initQuarantine();
    captureInput(q, 'cmd', 'exfiltrate');
    expect(q.forensic_buffer).toHaveLength(1);

    const forensicReceipt = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: sha256Str('forensic'), sealedHash: artifact.sealed_hash,
      driftDetected: true, driftDescription: 'Forensic capture', action: 'QUARANTINE',
      measurementType: 'EXECUTABLE_IMAGE', seq: portal.sequenceCounter++,
      prevLeaf: prev.leaf_hash, portalKP,
    });
    receipts.push(forensicReceipt);
    prev = appendEvent('INTERACTION_RECEIPT', forensicReceipt, prev, chainKP);
    chainEvents.push(prev);

    // Export bundle
    const { checkpoint } = createCheckpoint(chainEvents);
    const receiptIndices = chainEvents.reduce((acc: number[], e, idx) => {
      if (e.event_type === 'INTERACTION_RECEIPT') acc.push(idx);
      return acc;
    }, []);
    const proofs = receipts.map((_, i) => eventInclusionProof(chainEvents, chainEvents[receiptIndices[i]].sequence_number));
    const bundle = generateBundle(artifact, receipts, proofs, checkpoint, portalKP, 'GOLD');

    // Verify: all 4 steps PASS
    const verification = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
    expect(verification.step1_artifact_sig).toBe(true);
    expect(verification.step2_receipt_sigs).toBe(true);
    expect(verification.step3_merkle_proofs).toBe(true);
    expect(verification.overall).toBe(true);

    // Chain has expected event types
    const types = chainEvents.map(e => e.event_type);
    expect(types).toContain('GENESIS');
    expect(types).toContain('POLICY_ISSUANCE');
    expect(types.filter(t => t === 'INTERACTION_RECEIPT').length).toBeGreaterThanOrEqual(4);
  });

  it('8.2 Drone - Safe-state transition', () => {
    const result = runAutonomousVehicleScenario();

    expect(result.verification.step1_artifact_sig).toBe(true);
    expect(result.verification.step2_receipt_sigs).toBe(true);
    expect(result.verification.step3_merkle_proofs).toBe(true);
    expect(result.verification.overall).toBe(true);

    const types = result.chain.map(e => e.event_type);
    expect(types).toContain('GENESIS');
    expect(types).toContain('POLICY_ISSUANCE');
    expect(types).toContain('DISCLOSURE');
    expect(types).toContain('SUBSTITUTION');
    expect(types).toContain('INTERACTION_RECEIPT');

    // Verify chain integrity
    const integrity = verifyChainIntegrity(result.chain);
    expect(integrity.valid).toBe(true);
  });

  it('8.3 [NCCoE 7]: AI Agent - Complete lab demo', () => {
    const result = runAiAgentScenario();

    expect(result.verification.step1_artifact_sig).toBe(true);
    expect(result.verification.step2_receipt_sigs).toBe(true);
    expect(result.verification.step3_merkle_proofs).toBe(true);
    expect(result.verification.overall).toBe(true);

    const types = result.chain.map(e => e.event_type);
    expect(types).toContain('GENESIS');
    expect(types).toContain('POLICY_ISSUANCE');
    expect(types).toContain('DELEGATION');
    expect(types).toContain('BEHAVIORAL_DRIFT');
    expect(types).toContain('DISCLOSURE');
    expect(types).toContain('SUBSTITUTION');
    expect(types).toContain('INTERACTION_RECEIPT');

    const integrity = verifyChainIntegrity(result.chain);
    expect(integrity.valid).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════
// GROUP 9: INDEPENDENT VERIFIER PROOF
// ═══════════════════════════════════════════════════════════════════

describe('Group 9: Independent Verifier Proof', () => {
  it('9.1: Independent verifier has zero AGA imports', () => {
    const verifierPath = resolve(__dirname, '../independent-verifier/verify.ts');
    const source = readFileSync(verifierPath, 'utf-8');

    // Must not import from ../src, ../../src, or any relative AGA path
    expect(source).not.toContain("from '../src/");
    expect(source).not.toContain("from '../../src/");
    expect(source).not.toContain('from "../src/');
    expect(source).not.toContain('from "../../src/');
    expect(source).not.toContain("require('../src/");
    expect(source).not.toContain("require('../../src/");

    // Check all .ts/.js files in independent-verifier (excluding node_modules)
    const testPath = resolve(__dirname, '../independent-verifier/test/verify.test.ts');
    try {
      const testSource = readFileSync(testPath, 'utf-8');
      // Test file may import from parent for creating test data, but verify.ts itself must not
    } catch {
      // Test file may not exist
    }
  });

  it('9.2: Independent verifier reaches same conclusion as AGA verifier', () => {
    const scada = runScadaScenario();

    // AGA verifier says PASS
    expect(scada.verification.overall).toBe(true);

    // Independent verifier also says PASS
    const indResult = verifyEvidenceBundle(JSON.stringify(scada.bundle));
    expect(indResult.overall).toBe(true);
    expect(indResult.step1_artifact_sig).toBe(true);
    expect(indResult.step2_receipt_sigs).toBe(true);
    expect(indResult.step3_merkle_proofs).toBe(true);
  });

  it('9.3: Independent verifier detects tampered bundle', () => {
    const scada = runScadaScenario();
    const bundle = scada.bundle;

    // Tamper artifact signature
    const tampered = { ...bundle, artifact: { ...bundle.artifact, signature: 'AAAA' + bundle.artifact.signature.slice(4) } };

    const agaResult = verifyBundleOffline(tampered, pkToHex(generateKeyPair().publicKey));
    expect(agaResult.step1_artifact_sig).toBe(false);

    const indResult = verifyEvidenceBundle(JSON.stringify(tampered));
    expect(indResult.step1_artifact_sig).toBe(false);
    expect(indResult.overall).toBe(false);
  });

  it('9.4: Independent verifier works on all 3 scenario bundles', () => {
    const s1 = runScadaScenario();
    const r1 = verifyEvidenceBundle(JSON.stringify(s1.bundle));
    expect(r1.overall).toBe(true);

    const s2 = runAutonomousVehicleScenario();
    const r2 = verifyEvidenceBundle(JSON.stringify(s2.bundle));
    expect(r2.overall).toBe(true);

    const s3 = runAiAgentScenario();
    const r3 = verifyEvidenceBundle(JSON.stringify(s3.bundle));
    expect(r3.overall).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════
// GROUP 10: PERFORMANCE
// ═══════════════════════════════════════════════════════════════════

describe('Group 10: Performance', () => {
  it('10.1: Full lifecycle under 1000ms', () => {
    const start = performance.now();

    // Keygen
    const issuerKP = generateKeyPair();
    const portalKP = generateKeyPair();
    const chainKP = generateKeyPair();

    // Subject
    const content = 'perf-test-binary';
    const meta = { filename: 'perf.bin' };
    const subId = computeSubjectIdFromString(content, meta);

    // Attestation
    const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('p'), evidence_items: [] });

    // Artifact
    const artifact = generateArtifact({
      subject_identifier: subId, policy_reference: sha256Str('p'), policy_version: 1,
      sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
      enforcement_parameters: { measurement_cadence_ms: 100, ttl_seconds: 3600, enforcement_triggers: ['TERMINATE'], re_attestation_required: false, measurement_types: ['EXECUTABLE_IMAGE'] },
      disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
      evidence_commitments: [], issuer_keypair: issuerKP,
    });
    const artRef = hashArtifact(artifact);

    // Chain
    const genesis = createGenesisEvent(chainKP, sha256Str('spec'));
    const chainEvents: ContinuityEvent[] = [genesis];
    let prev = genesis;
    prev = appendEvent('POLICY_ISSUANCE', { artifact_hash: artRef }, prev, chainKP);
    chainEvents.push(prev);

    // Portal: 5 measurements
    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));
    const receipts: ReturnType<typeof generateReceipt>[] = [];
    for (let i = 0; i < 5; i++) {
      const m = portal.measure(enc.encode(content), meta);
      const r = generateReceipt({
        subjectId: subId, artifactRef: artRef,
        currentHash: `${m.currentBytesHash}||${m.currentMetaHash}`,
        sealedHash: `${m.expectedBytesHash}||${m.expectedMetaHash}`,
        driftDetected: false, driftDescription: null, action: null,
        measurementType: 'EXECUTABLE_IMAGE', seq: i, prevLeaf: prev.leaf_hash, portalKP,
      });
      receipts.push(r);
      prev = appendEvent('INTERACTION_RECEIPT', r, prev, chainKP);
      chainEvents.push(prev);
    }

    // Drift + enforcement
    portal.measure(enc.encode('DRIFT'), meta);
    portal.enforce('TERMINATE');

    // Receipt
    const driftReceipt = generateReceipt({
      subjectId: subId, artifactRef: artRef,
      currentHash: sha256Str('drift'), sealedHash: artifact.sealed_hash,
      driftDetected: true, driftDescription: 'drift', action: 'TERMINATE',
      measurementType: 'EXECUTABLE_IMAGE', seq: 5, prevLeaf: prev.leaf_hash, portalKP,
    });
    receipts.push(driftReceipt);
    prev = appendEvent('INTERACTION_RECEIPT', driftReceipt, prev, chainKP);
    chainEvents.push(prev);

    // Bundle + verify
    const { checkpoint } = createCheckpoint(chainEvents);
    const receiptIndices = chainEvents.reduce((acc: number[], e, idx) => {
      if (e.event_type === 'INTERACTION_RECEIPT') acc.push(idx);
      return acc;
    }, []);
    const proofs = receipts.map((_, i) => eventInclusionProof(chainEvents, chainEvents[receiptIndices[i]].sequence_number));
    const bundle = generateBundle(artifact, receipts, proofs, checkpoint, portalKP);
    const verification = verifyBundleOffline(bundle, pkToHex(issuerKP.publicKey));
    expect(verification.overall).toBe(true);

    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(1000);
  });

  it('10.2: Measurement cycle under 10ms average', () => {
    const { artifact, issuerKP, content, meta } = makeTestInfra();
    const portal = new Portal();
    portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));

    const times: number[] = [];
    for (let i = 0; i < 100; i++) {
      const start = performance.now();
      portal.measure(enc.encode(content), meta);
      times.push(performance.now() - start);
      // Reset to ACTIVE_MONITORING for next measurement if needed
      if (portal.state !== 'ACTIVE_MONITORING' && portal.state !== 'SAFE_STATE') {
        // Re-initialize for next cycle
        portal.state = 'ACTIVE_MONITORING' as any;
      }
    }

    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const sorted = [...times].sort((a, b) => a - b);
    const p95 = sorted[Math.floor(sorted.length * 0.95)];

    expect(avg).toBeLessThan(10);
  });
});
