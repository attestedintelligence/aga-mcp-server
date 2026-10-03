# Published verifier file compatibility, October 3, 2026

This is a characterization of nine exact input files against downloaded npm `@attested-intelligence/aga-verify@2.2.3` and Python `aga-governance==0.3.2`, with the historical sample's expected signing key. It is not a new format, parser fix or universal conformance claim.

The retained [machine-readable report](published-verifier-bytes-20261003.json) records package archive hashes, each input's SHA-256, byte count, full CLI result and exit code. Qualification ran at source commit `02491c051bec49bf4c3f5256238acb710a740455` in [run 37129744702](https://github.com/attestedintelligence/aga-mcp-server/actions/runs/37129744702). The workflow artifact also contains the exact files and container boundary; Actions artifacts have finite retention.

| Exact input | npm exit | Python exit | Observed meaning |
| --- | ---: | ---: | --- |
| Original sample bytes | 0 | 0 | Verified with the expected key |
| Duplicate signed decision, genuine value last | 0 | 0 | Both use the last value |
| Duplicate signed decision, changed value last | 1 | 1 | Verification fails |
| Leaf index spelled `0.0` | 0 | 1 | File acceptance differs |
| Leaf index spelled `0e0` | 0 | 1 | File acceptance differs |
| Extra unsigned Unicode field | 0 | 0 | Extra field is not authenticated |
| Invalid UTF-8 byte in an extra unsigned field | 0 | 1 | npm decodes with replacement; Python rejects the input |
| UTF-8 byte-order mark | 1 | 1 | Input rejected |
| Changed signed decision | 1 | 1 | Verification fails |

All eighteen invocations completed without a process crash, timeout or stack trace. A successful qualification run means the required controls passed and the observational rows completed; it does not mean all implementations agreed or all files were accepted. The numeric-spelling, UTF-8 and byte-order-mark rows intentionally record behavior without imposing a new compatibility rule on published releases.

## Interpretation

A successful check authenticates the parsed signed receipt/checkpoint fields against the expected key. It does not authenticate every source-file byte, unknown envelope fields or the first occurrence of a duplicate member. Preserve original bytes when comparing parsers. A different decoder or first-member reader can interpret a file differently from the verifier.

The historical corpus separately checks 54 object-level cases in six configurations and seven file-parse cases in five configurations. Object reserialization can hide numeric-spelling differences. Neither corpus establishes agreement for every input or for all published packages. This new lane covers only the two named published CLIs. It makes no Go, browser, VerifyBundle, runtime containment or production signing claim. The sample is public and synthetic, not evidence of a real deployment.

## Reproduction and change policy

Dispatch `.github/workflows/published-verifiers.yml` on the desired source ref. `scripts/prepare-published-verifiers.mjs` downloads the bounded registry archives and records their hashes; `scripts/check-published-verifiers.mjs` constructs and preserves the raw files without parsing or reserializing them before CLI invocation. The test container is non-root, network-disabled, read-only except bounded temporary space and its evidence mount, with dropped capabilities and CPU, memory, PID and time limits. Do not run hostile fixtures on a workstation holding credentials or private files.

Review `raw-byte-report.json` alongside the original CLI controls in `report.json`. Recover an exact file from `raw-inputs/`, then compare its SHA-256 with the report before replaying it in isolation. The generator and public source sample remain versioned even after the run artifact expires.

No parser acceptance changed in this work. Rejecting duplicates or malformed UTF-8 in a future release requires an explicit compatibility decision, versioned release notes, updated vectors, and tests of every supported consumer. Do not silently normalize files and then claim their original bytes verified.
