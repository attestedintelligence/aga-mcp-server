# Runtime 3.6.6: shared-tree export proofs

Published October 3, 2026 local time. Source `fec28431ca1561bab80cd37114dd8b0d1c7be5c4`. The [machine-readable record](runtime-3.6.6.json) contains the two maintained-Node qualifications, archive hash, container image identities, installed-package checks and measured proof-construction timings.

## Change and compatibility

The earlier export called the single-proof constructor once per receipt. Each call rebuilt all internal Merkle nodes. Version 3.6.6 shares tree levels across all proofs. Constructing the proof set now hashes each internal node once. Materializing and serializing all proof paths still grows with receipt count and tree depth.

The signed format, root construction, odd-node promotion, proof order/directions, checkpoint and existing single-proof API remain unchanged. Twenty-seven added tests cover exact proof equivalence, frozen inputs, independent proof arrays, internal hash-operation count, empty-export refusal and complete serialized-bundle equality for deterministic classical and hybrid producers. The largest hash-count case checks 4,096 leaves and exactly 4,095 internal-node hashes. Existing verifier and protocol tests still apply.

## Qualification

Both Node 22 and Node 24 passed 488 tests in 49 files inside credential-free, network-disabled, non-root containers with a read-only filesystem, dropped capabilities and bounded CPU, memory, PIDs and time. Each fresh archive installation also matched the retained single-proof construction for an exported 257-receipt bundle, matched its signed checkpoint and verified it against the expected test key. The six reference controls and the classical and hybrid conformance workflows passed.

[Isolated source and archive qualification](https://github.com/attestedintelligence/aga-mcp-server/actions/runs/37172936072) and [publication](https://github.com/attestedintelligence/aga-mcp-server/actions/runs/37173182342) identify the tested source. Actions artifacts have finite retention. The source tests, qualification workflow and benchmark generator are committed for reproduction in disposable isolation.

## Measured proof construction

The bounded synthetic benchmark compared three repetitions at 128, 512 and 1,024 leaves. Every batch output exactly matched the retained single-proof implementation. At 1,024 leaves, median legacy construction was approximately 1.53 seconds on Node 22 and 1.48 seconds on Node 24; median batch construction was approximately 2.71 and 3.48 milliseconds, respectively. Full samples and machine context are in the JSON record.

These are proof-construction measurements on the retained runner, not an end-to-end export benchmark, universal speedup or service-level commitment. Receipt hashing, signing, output allocation, serialization, transport and contention remain separate work. Export is synchronous, the live ledger is still in memory, and a timeout can follow an upstream effect. No deployment containment, client authentication, independent security review or real-pilot acceptance follows from this optimization.

## Published bytes and provenance

The registry archive is 153,322 bytes. Its SHA-256 is `3cb8782e08fa9def5f3dcecbe0454a69c284995024d68a5995de2d6d2ffdb980` and matches both isolated builds. SHA-512 integrity and the SLSA subject match the downloaded bytes; provenance names the qualified source commit above.

A separate company-run consumer install with lifecycle scripts disabled passed npm 11.21.0 `audit signatures --json --include-attestations`. The report included this exact release's verified provenance, with no invalid or missing signatures. Its verified SLSA subject and source were matched to the archive and commit. This validates publishing evidence through npm's verification tooling; it is not independent assurance of the runtime.

Historical 3.6.5 and earlier records retain their own dates and scope. No standalone verifier, Python package, receipt specification or historical fixture was republished by this change.
