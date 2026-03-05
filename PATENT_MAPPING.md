# Patent Claim → Code Mapping

| Claim | MCP Tool | Source | Function |
|---|---|---|---|
| 1(a) receive subject | `attest_subject` | core/subject.ts | `computeSubjectIdFromString()` |
| 1(b) generate identifier | `attest_subject` | core/subject.ts | `computeSubjectId()` |
| 1(c) perform attestation | `attest_subject` | core/attestation.ts | `performAttestation()` |
| 1(d) generate artifact | `attest_subject` | core/artifact.ts | `generateArtifact()` |
| 1(e) portal + measurement | `measure_integrity` | core/portal.ts | `Portal.measure()` |
| 1(f) compare to sealed | `measure_integrity` | core/portal.ts | `Portal.measure()` |
| 1(g) enforce + receipt | `measure_integrity` | core/receipt.ts | `generateReceipt()` |
| 2 disclosure | `request_claim` | core/disclosure.ts | `processDisclosure()` |
| 3(a) genesis | `init_chain` | core/chain.ts | `createGenesisEvent()` |
| 3(b) append events | auto (every tool) | core/chain.ts | `appendEvent()` |
| 3(c) leaf hash (no payload) | `verify_chain` | core/chain.ts | `computeLeafHash()` |
| 3(d-f) checkpoint | `create_checkpoint` | core/checkpoint.ts | `createCheckpoint()` |
| 5 quarantine | `measure_integrity` | core/quarantine.ts | `initQuarantine()` |
| 6 TTL expiration | `measure_integrity` | core/portal.ts | `Portal.measure()` |
| 9 evidence bundle | `generate_evidence_bundle` | core/bundle.ts | `generateBundle()` |
| 10 pinned key | portal load | core/portal.ts | `Portal.loadArtifact()` |
| 11 phantom execution | `measure_integrity` | core/quarantine.ts | `captureInput()` |
| 12 graceful degradation | `measure_integrity` | core/portal.ts | TTL + fail-closed |

## NIST Filing Alignment

| NIST Promise | Implementation |
|---|---|
| "each measurement generates a signed receipt" | `measure_integrity` generates receipt for match AND mismatch |
| "fail-closed semantics" | Portal checks TTL + revocation on every measurement |
| "mid-session revocation" (NCCoE 3b) | `revoke_artifact` tool + REVOCATION chain event |
| "phantom execution" | `QUARANTINE` enforcement → forensic capture buffer |
| "offline verification" | `generate_evidence_bundle` + `verify_bundle_offline` |
| "graduated enforcement" | TERMINATE / QUARANTINE / SAFE_STATE / ALERT_ONLY |
