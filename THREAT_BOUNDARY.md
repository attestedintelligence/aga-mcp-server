# Threat boundary and current limitations

Updated October 3, 2026 for reference runtime 3.6.6. Documentation-only releases 3.6.3 and 3.6.4 retain the earlier runtime behavior. The README preserves thirteen historical cases; this table gives the current disposition, retaining the 3.6.5 security controls. Qualification of a reference implementation does not approve a deployment or establish independent certification.

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
| 1 | Default bind is loopback; explicit --host may expose it. No client authentication or shared-host privilege separation. |
| 2 | Stdio IDs are remapped and replies remain owned by the originating request. Duplicate in-flight IDs within one client are refused. This is not complete MCP session support. |
| 3 | No implicit signing-variable inheritance; explicit gateway-key variables are refused. Same-account filesystem and network access remain. |
| 4 | The HTTP upstream mode does not implement MCP Streamable HTTP. |
| 5 | Proxy transport and policy-file JSON reject repeated decoded member names. Other verifier parsers retain their own documented behavior; the library receives parsed objects. |
| 6 | Ambiguous request JSON is refused before HTTP or stdio forwarding. Refused syntax is not treated as an attributable tool decision. |
| 7 | Missing/invalid tool names and uncanonicalizable arguments have denied receipts and responses. Invalid syntax, oversized frames and connection/resource refusals need not yield a receipt; no complete request capture is claimed. |
| 8 | Framing preserves UTF-8 byte splits and refuses malformed UTF-8. This does not prove arbitrary downstream protocol compatibility. |
| 9 | Version 3.6.6 shares Merkle tree levels across proofs, removing the repeated whole-tree hashing. Export is still synchronous and can block calls or contribute to timeouts after an upstream effect. |
| 10 | Policies are validated immutable snapshots and rate state is per proxy. Required paths must be strings; lexical prefixes and top-level patterns are not filesystem containment. |
| 11 | Stdio output and pending work are bounded; malformed/oversized output rejects pending work. An upstream effect can precede failure; PERMITTED is not execution proof. |
| 12 | Control requests require the bound loopback Host and no Origin; cross-site browser metadata is refused. Any local process can still read the ledger; no local authorization is supplied. |
| 13 | HTTP work has a 30-second deadline, 8 MiB response bound, fatal UTF-8 and response-ID validation. Failed or oversized work can follow an upstream effect; do not infer non-execution or retry automatically. |

Read the [complete cases and measured workarounds](https://attestedintelligence.com/security#known-issues) before relying on a mitigation. A workaround is not a claim that a defect has been fixed.

Additional boundaries:

- A direct route to the upstream bypasses the proxy. A stdio child is not automatically isolated from the agent, host or signing environment.
- The default policy profile is permissive. Only covered `tools/call` traffic is policy-evaluated; other methods have passthrough or unrecorded paths. The CLI does not expose the library's `denyMethods` option.
- In MCP server mode, the governed client can re-attest its baseline and lift a lifecycle block without that call appearing in the exported bundle. Measurement and lifecycle events are not interchangeable with exported tool-call receipts.
- The live ledger is volatile. Retention, restart behavior, an independent witness, trusted time and freshness checks require separate arrangements.
- Standalone aga-verify 2.2.3 refuses malformed supplied API keys and missing, malformed, repeated or unknown CLI options. Runtime 3.6.5 independently fails malformed supplied expected keys. Omission remains integrity-only. Older versions and other implementations can downgrade some malformed inputs; check the exact verifier and issuer-match result. Signed format bytes and historical specifications remain unchanged.
- The record does not prevent jailbreaks, infrastructure compromise, signing-key theft or actions outside the recorded boundary. It does not certify compliance or establish court, regulator or customer acceptance.

## 4. Historical test evidence

Earlier audit narratives and their corrections remain in [the September 30 pre-release source record](https://github.com/attestedintelligence/aga-mcp-server/blob/2475dd78d3439f1bd47c68115485bd24dba37add/THREAT_BOUNDARY.md). They are historical evidence, not current external certification. Later known issues narrow several earlier broad statements about capture, bypass and cross-stack agreement.

The retained classical corpus has 54 object-level cases across six verifier configurations and seven raw-byte cases across five file-parsing implementations. The library-only engine does not parse those seven files. The hybrid corpus is separate. Agreement is scoped to the actual corpus and harness; it is not universal parser equivalence. Actual release workflow results must be read for the exact source commit, and they do not qualify an unrelated deployment or private evaluation kit.

## 5. Public boundary statement

AGA supplies signed decision records that a reviewer can check outside the producing service. A verified record establishes the checks performed on the receipts present, with issuer assurance only against an independently obtained expected key. Capture completeness, policy quality, execution, containment, freshness and operational readiness require separate evidence.
