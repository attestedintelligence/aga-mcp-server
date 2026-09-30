# Threat boundary and current limitations

Updated September 30, 2026. This is the current scope statement for the published reference implementation. Documentation-only releases 3.6.3 and 3.6.4 do not repair the behavioral limitations observed in 3.6.0 through 3.6.2. The README retains the thirteen detailed known issues and their observed version scope.

## 1. What verification establishes

A valid signature establishes that the signed bytes were produced by a holder of the corresponding private key. To establish an expected issuer, the reviewer must obtain and check the expected public key independently of the bundle. Cryptographic checks do not identify a person, authorize an action or prove the source claims are true.

For the presented receipt set, verification checks signatures, hash links, Merkle commitments and the signed checkpoint. Altering, adding, reordering or truncating signed receipts relative to that checkpoint fails the applicable checks. An earlier genuine export may still pass, and a key holder can sign another history. Completeness of the presented signed set is different from completeness of activity capture.

Each signed receipt's `policy_reference` is the policy value to inspect. `aga-proxy` records the SHA-256 of its canonical policy JSON; the separate `aga-mcp-server` path uses an empty value. Unsigned envelope fields, including `bundle_id`, `schema_version`, envelope `policy_reference` and `offline_capable`, are not authenticated policy or identity evidence.

The JavaScript CLI, Python SDK, library verifier and hybrid reference implementations have different supported profiles and edge-case behavior. The published `aga-verify` CLI checks the classical profile. Do not substitute one implementation for another without checking its profile, key-pin handling and result fields.

## 2. Maintenance requirements

Changes to signed fields, canonicalization, checkpoint rules, algorithms or verifier results need explicit format and cross-implementation review. A passing object-level unit test is not a raw-byte parser test. Preserve signed fixtures, test malformed inputs in an approved isolated environment and retain failures rather than relabeling them as unsupported tests.

For new governed tools, verify the actual request path, policy decision, receipt and upstream effect. The presence of a governance wrapper or a signed PERMITTED decision does not establish execution or complete capture. Keep production credentials out of tests.

## 3. Known residual risks

| Issue | Current limitation |
| --- | --- |
| 1 | The agent listener has no authentication, binds broadly and has shared-host exposure. |
| 2 | Clients reusing a JSON-RPC identifier can receive each other's results. |
| 3 | A stdio upstream inherits signing-related environment variables. |
| 4 | The HTTP upstream mode does not implement MCP Streamable HTTP. |
| 5 | Duplicate JSON field names are interpreted using the last value. Other readers may display a different value. |
| 6 | Duplicate HTTP method members can bypass policy evaluation and receipt creation. |
| 7 | Some malformed calls are refused without a receipt or response. |
| 8 | Non-ASCII bytes split across reads can be altered in transport. |
| 9 | Export can block calls and contribute to timeouts after an upstream effect. |
| 10 | Policy types, top-level path/pattern rules and shared rate limits have important constraints. |
| 11 | Large stdio output can be dropped after a PERMITTED receipt, with later timeout. |
| 12 | The loopback control channel lacks Host/Origin validation, leaving a DNS-rebinding risk where the browser permits it. |
| 13 | Large HTTP responses can interrupt the agent connection and lose in-flight replies on Linux. |

Read the [complete cases and measured workarounds](https://attestedintelligence.com/security#known-issues) before relying on a mitigation. A workaround is not a claim that a defect has been fixed.

Additional boundaries:

- A direct route to the upstream bypasses the proxy. A stdio child is not automatically isolated from the agent, host or signing environment.
- The default policy profile is permissive. Only covered `tools/call` traffic is policy-evaluated; other methods have passthrough or unrecorded paths. The CLI does not expose the library's `denyMethods` option.
- In MCP server mode, the governed client can re-attest its baseline and lift a lifecycle block without that call appearing in the exported bundle. Measurement and lifecycle events are not interchangeable with exported tool-call receipts.
- The live ledger is volatile. Retention, restart behavior, an independent witness, trusted time and freshness checks require separate arrangements.
- A malformed expected-key value can fall back to integrity-only behavior in some implementations. Check the exact verifier and the issuer-match result.
- The record does not prevent jailbreaks, infrastructure compromise, signing-key theft or actions outside the recorded boundary. It does not certify compliance or establish court, regulator or customer acceptance.

## 4. Historical test evidence

Earlier audit narratives and their corrections remain in [the September 30 pre-release source record](https://github.com/attestedintelligence/aga-mcp-server/blob/2475dd78d3439f1bd47c68115485bd24dba37add/THREAT_BOUNDARY.md). They are historical evidence, not current external certification. Later known issues narrow several earlier broad statements about capture, bypass and cross-stack agreement.

The retained classical corpus has 54 object-level cases across six verifier configurations and seven raw-byte cases across five file-parsing implementations. The library-only engine does not parse those seven files. The hybrid corpus is separate. Agreement is scoped to the actual corpus and harness; it is not universal parser equivalence. Actual release workflow results must be read for the exact source commit, and they do not qualify an unrelated deployment or private evaluation kit.

## 5. Public boundary statement

AGA supplies signed decision records that a reviewer can check outside the producing service. A verified record establishes the checks performed on the receipts present, with issuer assurance only against an independently obtained expected key. Capture completeness, policy quality, execution, containment, freshness and operational readiness require separate evidence.
