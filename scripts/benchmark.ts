import { generateKeyPair, pkToHex } from '../src/crypto/sign.js';
import { sha256Str } from '../src/crypto/hash.js';
import { computeSubjectIdFromString } from '../src/core/subject.js';
import { performAttestation } from '../src/core/attestation.js';
import { generateArtifact, hashArtifact } from '../src/core/artifact.js';
import { Portal } from '../src/core/portal.js';
import { generateReceipt } from '../src/core/receipt.js';

const ITERATIONS = 1000;
const issuerKP = generateKeyPair();
const portalKP = generateKeyPair();
const content = 'def monitor(): return sensors.read_all()';
const meta = { filename: 'agent.py', version: '1.0' };
const subId = computeSubjectIdFromString(content, meta);
const att = performAttestation({ subject_identifier: subId, policy_reference: sha256Str('pol'), evidence_items: [] });
const artifact = generateArtifact({
  subject_identifier: subId, policy_reference: sha256Str('pol'), policy_version: 1,
  sealed_hash: att.sealed_hash!, seal_salt: att.seal_salt!,
  enforcement_parameters: { measurement_cadence_ms: 100, ttl_seconds: 3600, enforcement_triggers: ['QUARANTINE'], re_attestation_required: false, measurement_types: ['FILE_SYSTEM_STATE'] },
  disclosure_policy: { claims_taxonomy: [], substitution_rules: [] },
  evidence_commitments: [], issuer_keypair: issuerKP,
});
const artRef = hashArtifact(artifact);
const enc = new TextEncoder();
const bytes = enc.encode(content);

// Warm up
const portal = new Portal();
portal.loadArtifact(artifact, pkToHex(issuerKP.publicKey));
portal.measure(bytes, meta);

// Benchmark: measure + receipt generation cycle
const start = performance.now();
for (let i = 0; i < ITERATIONS; i++) {
  const p = new Portal();
  p.loadArtifact(artifact, pkToHex(issuerKP.publicKey));
  const result = p.measure(bytes, meta);
  generateReceipt({
    subjectId: subId, artifactRef: artRef,
    currentHash: `${result.currentBytesHash}||${result.currentMetaHash}`,
    sealedHash: `${result.expectedBytesHash}||${result.expectedMetaHash}`,
    driftDetected: !result.match, driftDescription: null, action: null,
    measurementType: 'FILE_SYSTEM_STATE', seq: i, prevLeaf: null, portalKP,
  });
}
const elapsed = performance.now() - start;
const perOp = elapsed / ITERATIONS;

console.log(`\nAGA Measurement + Receipt Benchmark`);
console.log(`  Iterations:    ${ITERATIONS}`);
console.log(`  Total:         ${elapsed.toFixed(1)}ms`);
console.log(`  Per operation: ${perOp.toFixed(3)}ms`);
console.log(`  NIST target:   <10ms`);
console.log(`  Result:        ${perOp < 10 ? 'PASS' : 'FAIL'}`);
