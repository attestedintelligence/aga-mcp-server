# Deployment and evaluation boundary

Updated September 30, 2026. The published gateway is a reference implementation with known deployment risks. Publication and a successful static verification do not establish production readiness. Begin with the [static evaluation](https://attestedintelligence.com/evaluate). Do not start a gateway on a workstation containing production credentials, customer data or private files.

## 1. Choose and test the boundary

`aga-proxy` evaluates covered `tools/call` messages and records decisions. Its agent port uses newline-delimited JSON-RPC over raw TCP, listens on every interface and has no authentication. A stdio client needs a relay; SSE and Streamable HTTP require a bridge. Those adapters are not supplied by the package.

The default stdio upstream is a child process. That transport alone does not establish isolation: the child shares the proxy's account and inherits its environment, including signing-related variables. The listener, control channel, filesystem privileges and alternative routes to tools need separate controls.

With `--upstream-url`, the proxy sends plain JSON-RPC HTTP requests. It does not implement MCP Streamable HTTP sessions or SSE. Any direct route to the upstream bypasses the proxy. Duplicate `method` members can also bypass HTTP policy evaluation. Review all thirteen [known issues](https://attestedintelligence.com/security#known-issues) before selecting a topology.

Use a disposable environment with synthetic inputs and keys for the first runtime test. Before any run, verify actual listener exposure, account separation, child environment, resource limits, retained output and process cleanup. A configuration diagram is not proof that these controls work.

## 2. Select an explicit policy

The default `permissive` profile denies nothing on policy grounds. `standard` and `restrictive` contain generic example tool names; they are not policies for your actual upstream or sector. An allowlist file must name the upstream's real tools and intended constraints.

A policy for two named tools has this shape:

```json
{"mode":"allowlist","constraints":{"read_text_file":{"name":"read_text_file","allowed":true},"list_directory":{"name":"list_directory","allowed":true}}}
```

This illustrates policy syntax, not a recommended deployment or filesystem boundary. A missing or null `constraints` member can cause refusal without a receipt or response. Missing or unrecognized `mode` values deny tool calls. Unknown constraint keys are ignored; wrongly typed truthy values can allow a call. Path and pattern rules inspect top-level string arguments only and do not provide a filesystem sandbox. See known issues 7 and 10 for the exact cases.

Only `tools/call` is policy-evaluated. Protocol methods can pass without receipts; other methods may have passthrough receipts without policy evaluation. `denyMethods` is a library constructor option, not a CLI policy setting. A PERMITTED receipt does not establish successful tool execution.

## 3. Key custody and verification

Both binaries accept `AGA_GATEWAY_KEY` or `AGA_GATEWAY_KEY_FILE`; otherwise they use an ephemeral signing key. The proxy also has an explicit `--ephemeral` option. A restart with a new key changes the identity a reviewer must expect.

Use synthetic keys in a lab. A persistent production key requires an independently reviewed custody and access design. Supplying a seed to an agent process, or retaining a key file under the same untrusted account, does not create a protected signing boundary. The stdio child can inherit the signing-related environment. Do not put real seeds in source, shell history, screenshots or support messages.

A reviewer must obtain the expected public key through a separate trusted channel. A key read from the bundle under test establishes only internal consistency. Check both the verification result and issuer-key match. Some implementations treat malformed pins as absent; do not interpret exit zero alone as issuer verification. Read the README's exact verifier differences.

## 4. Export and retention

The live chain is in memory and a restart starts a new chain. Export before stopping and retain the bundle together with the expected key and any outside checkpoint used to establish freshness. Test restoration separately.

Export work grows with the receipt count and can block governed calls. A forwarded call can execute and later time out while export is running. Do not retry a potentially consequential call merely because the client received a timeout. Bound the lab workload and record actual upstream effects. See known issues 9, 11 and 13.

An earlier genuine export can still verify. A key holder can sign a different history. Retained signatures do not prove every action was captured, that the timestamp came from an independent time source or that the deployment prevented bypass.

## 5. Observable runtime acceptance

Before claiming a particular deployment is ready, retain evidence for its exact version, policy and topology:

- Listener and control-channel reachability, including denied unauthorized access.
- Child environment and signing-key separation without exposing key material.
- Allowed, denied, malformed and unevaluated requests, with actual upstream observations.
- Export, timeout, retry, restart and cleanup behavior under bounded resource pressure.
- Pinned-key success, wrong/malformed-key failure and signed-field tampering controls.
- An explicit disposition for every known issue and deployment-specific residual risk.

These are acceptance requirements, not completed results for your system. Current public package tests and old CI runs do not qualify a new kit/runtime combination or establish pilot approval.

## 6. What the record establishes

A passing verification checks the receipts present under the verified signing key, their order and the signed checkpoint. It does not establish complete capture, successful execution, effective access control, legal acceptance or compliance. See [THREAT_BOUNDARY.md](THREAT_BOUNDARY.md) and the [trust model](https://attestedintelligence.com/trust).
