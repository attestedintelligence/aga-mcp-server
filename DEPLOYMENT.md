# Deployment and evaluation boundary

Updated October 3, 2026. The published gateway is a reference implementation with known deployment risks. Publication and a successful static verification do not establish production readiness. Begin with the [static evaluation](https://attestedintelligence.com/evaluate). Do not start a gateway on a workstation containing production credentials, customer data or private files.

## 1. Choose and test the boundary

Reference runtime 3.6.6 evaluates covered `tools/call` requests and records decisions. Its agent port uses newline-delimited JSON-RPC over raw TCP and binds to 127.0.0.1 by default. `--host` explicitly changes that address. There is no client authentication: local access remains a trust boundary, and non-loopback exposure requires separate access controls. A stdio client needs a relay; SSE and Streamable HTTP require a bridge. Those adapters are not supplied by the package.

The default stdio upstream is a child process started without a shell. Version 3.6.5 uses a small environment allowlist and refuses explicitly supplied gateway-key variables. This removes implicit signing-environment inheritance, but the child still shares the proxy's account, filesystem and network privileges. The listener, control channel, filesystem privileges and alternative routes to tools need separate controls.

With `--upstream-url`, the proxy sends plain JSON-RPC HTTP requests. It does not implement MCP Streamable HTTP sessions or SSE. Any direct route to the upstream bypasses the proxy. Repeated JSON member names are now refused before forwarding, including escaped aliases. Read the thirteen historical cases and their current disposition in [THREAT_BOUNDARY.md](THREAT_BOUNDARY.md) before selecting a topology.

Use a disposable environment with synthetic inputs and keys for the first runtime test. Before any run, verify actual listener exposure, account separation, child environment, resource limits, retained output and process cleanup. A configuration diagram is not proof that these controls work.

## 2. Select an explicit policy

The default `permissive` profile denies nothing on policy grounds. `standard` and `restrictive` contain generic example tool names; they are not policies for your actual upstream or sector. An allowlist file must name the upstream's real tools and intended constraints.

A policy for two named tools has this shape:

```json
{"mode":"allowlist","constraints":{"read_text_file":{"name":"read_text_file","allowed":true},"list_directory":{"name":"list_directory","allowed":true}}}
```

This illustrates policy syntax, not a recommended deployment or filesystem boundary. Policies are validated, copied and frozen before startup or a policy switch. Missing, wrongly typed or unknown fields are refused. Configured path keys require nonempty string arguments; absent keys fail the call. Path-prefix checks remain lexical, and pattern rules inspect top-level strings. Neither provides filesystem containment or symlink protection. Rate limits are per proxy instance.

Only `tools/call` requests are policy-evaluated. Protocol methods can pass without receipts; other requests may have passthrough receipts without policy evaluation. Only initialization notifications are forwarded; unsupported notifications are refused and recorded without a JSON-RPC response. Complete server-initiated requests, sessions and cancellation relay are not implemented. `denyMethods` is a library constructor option, not a CLI policy setting. A PERMITTED receipt does not establish successful tool execution.

## 3. Key custody and verification

Both binaries accept `AGA_GATEWAY_KEY` or `AGA_GATEWAY_KEY_FILE`; otherwise they use an ephemeral signing key. The proxy also has an explicit `--ephemeral` option. A restart with a new key changes the identity a reviewer must expect.

Use synthetic keys in a lab. A persistent production key requires an independently reviewed custody and access design. Supplying a seed to an agent process, or retaining a key file under the same untrusted account, does not create a protected signing boundary. Environment filtering does not restrict a child's filesystem access to key files. Do not put real seeds in source, shell history, screenshots or support messages.

A reviewer must obtain the expected public key through a separate trusted channel. A key read from the bundle under test establishes only internal consistency. Check both the verification result and issuer-key match. Runtime 3.6.5 and standalone aga-verify 2.2.3 fail supplied malformed keys. Other implementations can treat them as absent; do not interpret exit zero alone as issuer verification. Read the README's version-scoped verifier differences.

## 4. Export and retention

The live chain is in memory and a restart starts a new chain. Export before stopping and retain the bundle together with the expected key and any outside checkpoint used to establish freshness. Test restoration separately.

Version 3.6.6 reuses tree levels when constructing Merkle proofs; it does not make export asynchronous. Proof material grows with receipt count and tree depth. Export work can still block governed calls. A forwarded call can execute and later time out while export is running. Do not retry a potentially consequential call merely because the client received a timeout. Bound the lab workload and record actual upstream effects. See known issues 9, 11 and 13.

The 3.6.7 candidate bounds a separate CLI control-channel download to 15 seconds and 32 MiB. It accepts only `127.0.0.1` or `localhost` locators, connects to the literal loopback address and refuses redirects. This is a client retrieval bound, not a ledger size cap or cancellation of synchronous server work. An oversized or incomplete response is refused before writing the destination. The control header and JSON shape check are routing safeguards, not authentication or signature verification. Verify the resulting artifact against an independently obtained expected key.

The 3.6.7 candidate also prepares each CLI export in a private staging directory beside the destination, flushes the complete file, then publishes it. Default publication uses an exclusive hard link and refuses an existing path. `--force` replaces the destination entry by rename, leaving other hard links and a destination symlink's referent unchanged. A write, flush or publication failure preserves the previous destination. The filesystem must support the required same-filesystem operation; unsupported operations fail rather than falling back to a direct overwrite. New files use mode 0600 on POSIX; Windows access remains subject to its ACLs. An abrupt process stop can leave a staging directory, and file flushing does not prove directory-entry persistence after power loss. Use a trusted output directory; this is not protection against an attacker who can rename its parents.

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
