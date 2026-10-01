# Reference runtime hardening candidate

This branch prepares reference runtime 3.6.5. Publication remains gated on qualification of the exact source, documentation, package bytes and registry readback. A build or branch push alone is not publication.

The candidate snapshots and freezes validated policies before binding their references, separates rate-limit state by proxy owner, defaults the TCP listener to loopback, validates request envelopes, refuses unsupported notifications without replying to them, bounds connections and in-flight work, cancels pending transport waits when their client disconnects, remaps stdio request IDs and preserves UTF-8 across byte splits. HTTP responses have a deadline, byte limit and response-ID check. Downstream children receive an explicit environment without implicit gateway credentials and start without a shell.

A supplied malformed expected issuer key now returns FAILED. Omission alone selects integrity-only verification. This tightens trust-input handling without modifying signed receipt bytes, algorithm identifiers, historical fixtures or the frozen vendored specification. It is an intentional API behavior change, not a claim that every historical malformed-input oracle has adopted it.

The proxy remains a raw TCP reference transport with no client authentication or complete MCP session/server-request/cancellation support. Unsupported notifications are refused and recorded. Path-prefix checks are lexical and do not contain symlinks or filesystem privileges. The child still shares the host account, filesystem and network privileges. Limiting environment inheritance does not establish a protected signing process. No production enforcement, key custody, independent audit or non-omission guarantee is claimed.

Qualification runs on disposable GitHub runners in credential-free containers with no external network, a read-only source and root filesystem, a non-root user, dropped capabilities, bounded writable temporary mounts and process/resource deadlines. Node 20 and 22 are tested separately. Logs and failed runs are preserved. No hostile runtime tests run on the workstation.
