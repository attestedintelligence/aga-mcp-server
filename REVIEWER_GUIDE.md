# Reviewer guide: static evidence and trust boundaries

Updated September 30, 2026. Start with static verification. This guide separates artifact integrity, expected-key matching, build provenance and deployment qualification. The gateway remains a reference implementation before its first external pilot.

Start with the [current reviewer case](https://attestedintelligence.com/evaluate#reviewer-case): explicit policy, two requests, expected decisions, a synthetic signed bundle, test public key and manifest. Download it into a new folder and follow its README. No model, running proxy or tool was used. The included verifier is byte-identical to the published standalone CLI 2.2.3.

Standalone verifier 2.2.3 was published manually, with a verified registry signature and no SLSA build attestation. Its source commit is `48ca8f4245e0147aea4a2586d3003ea2274b0792`. Its npm tarball SHA-256 is `f7174a66426f236e483383798db27d87dbb582e5d6b49d6e65c6d46f6973e642`, which identifies the npm package, not the separate reviewer-case ZIP.

## 0. A retained reference fixture

The reference verifier is a single dependency-free file (Node 18+, `node:crypto` only):

```bash
git clone https://github.com/attestedintelligence/aga-mcp-server && cd aga-mcp-server
node aga-receipt-spec/verify/verify-sep.mjs fixtures/valid_minimal.json   # OVERALL: VERIFIED (integrity of present receipts…)
node aga-receipt-spec/verify/verify-sep.mjs fixtures/tampered.json        # OVERALL: FAILED
```

After obtaining the source and fixtures, these commands need no package installation, network or running service. Changing an authenticated field value fails the applicable check. Insignificant JSON whitespace and the unsigned envelope fields listed in KNOWN_LIMITATIONS.md are outside that guarantee. Use a maintained Node release; Node 18 is an implementation minimum, not a recommendation to use an unsupported release.

## 1. Check provenance for the exact package version

```bash
npm view @attested-intelligence/aga-mcp-server version dist-tags

# 1. Registry signatures and attestations, checked on an installed copy:
mkdir aga-check && cd aga-check && npm init -y >/dev/null
npm install @attested-intelligence/aga-mcp-server@3.6.0
npm audit signatures                         # "verified registry signatures" + "verified attestations"

# 2. The SLSA provenance, checked against the published tarball. The attestation is stored by npm,
#    not in GitHub's attestation store, so fetch npm's bundle and pass it with --bundle (without it,
#    `gh attestation verify` finds nothing and exits 1):
npm pack @attested-intelligence/aga-mcp-server@3.6.0
curl -s https://registry.npmjs.org/-/npm/v1/attestations/@attested-intelligence%2faga-mcp-server@3.6.0 \
  | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{const a=JSON.parse(d).attestations.find(x=>x.predicateType==="https://slsa.dev/provenance/v1");process.stdout.write(JSON.stringify(a.bundle))})' \
  > slsa.bundle.json
gh attestation verify attested-intelligence-aga-mcp-server-3.6.0.tgz \
  --owner attestedintelligence --bundle slsa.bundle.json --digest-alg sha512
# The same two steps work for @attested-intelligence/aga-verify@2.2.0 with its own bundle.
# A tarball other than the one the bundle names fails verification.
```

The example above is for releases whose actual npm attestation contains a SLSA statement. Such a statement binds the named repository, release commit and artifact digest. Workflow configuration alone is not proof that a package has an attestation. Standalone verifier 2.2.3 has registry signatures and no SLSA attestation; the runtime package has a separate release record.

## 2. Reproduce the published tarball byte-for-byte

```bash
npm ci && npm run build            # deterministic: .gitattributes pins LF, tsconfig pins newLine:lf
npm pack                           # your tarball
# compare the per-file SHA-256 manifest of YOUR build's contents to the published one
# Whole-tarball equality also depends on the npm version and packing metadata; compare extracted file manifests as well.
```

A from-clean-clone build's `dist/` is byte-identical to the published `dist/` (see REPRODUCIBILITY.md for
the exact manifest procedure). Reproduce the exact version and commit under review. A measured rebuild of another version does not establish equality for the current release.

## 3. Conformance across verifier configurations

Run these harnesses in disposable isolation without production credentials or private files. They include hostile fixtures and synthetic runtime processes.

```bash
npm run conformance:cross-stack    # JS reference + in-server engine + aga-verify + Go + 2× Python
# => "6 verifier configurations agree on the 54 object-level cases; the 5 file-parsing verifiers
#     ... agree on the 7 raw-byte/file-parse cases ; 61 cases total"
#    The engine is library-only (it receives parsed objects in-server, never raw file bytes), so it
#    does not run the file-parse cases ; six configurations do NOT agree on all 61, and the tool no
#    longer claims they do. Includes the adversarial corpus (small-order keys,
#    truncation, reorder, surrogate, non-canonical timestamp, uppercase-Merkle-sibling, …)
```

These are six verifier configurations across three languages, not six independent cryptographic implementations. The result covers only the labeled corpus as the harness supplies it; object-level cases are reserialized and can normalize numeric spellings. Outside that corpus the implementations have documented differences.

## 4. Canonicalization checks

```bash
npx vitest run tests/sep/jcs-rfc8785-conformance.test.ts
# asserts the shipped canon is byte-identical to the reference RFC 8785 impl (`canonicalize`) on the
# real receipt + checkpoint and the classic RFC 8785 edge cases. Regenerate expected: `npx canonicalize`.
```

## 5. Inspect negative controls in isolation

The full verifier is `aga-receipt-spec/verify/verify-sep.mjs` (~245 lines) and `CORE_VERIFICATION.md` is
the plain-language, vendor-independent algorithm. The negative vectors in
`fixtures/cross-stack/vectors.json` are real mounted forgeries (tampered roots and checkpoints,
truncation/splice, re-sign, canon ambiguity, envelope lies, malformed proofs), each labeled with its intended control. Check the profile, parser and expected verdict of the exact implementation; the library engine does not consume raw file bytes. Mint your own
bundle with a key you choose (`signerFromSeed`) and attack it ; the construction is designed to be attacked.

## 6. What a PASS does and does not prove (read this before relying on it)

- **Proves:** every receipt *present* is authentic (Ed25519), correctly ordered (hash chain), Merkle-
  included, checkpoint-bound, and ; when you pin the gateway key (`--pubkey`) ; issued by that key.
- **Does NOT prove non-omission:** a *self-signed* checkpoint cannot stop a malicious or compromised
  issuer from suppressing a `DENIED` record before export. Defending against issuer equivocation needs
  an external transparency log/witness, which SEP deliberately does not include.
- Full scope + residuals: `THREAT_BOUNDARY.md`, `KNOWN_LIMITATIONS.md`. Relationship to CT / Sigstore /
  in-toto / RFC 3161 / C2PA / Veritas Acta: `sep/0000-governance-receipts.md` (Relationship to prior work).

## 7. Pin the key for provenance

Without `--pubkey`, a PASS is **integrity-only** (`issuerVerified=false`) ; a self-consistent bundle
signed by *any* key passes. Obtain and retain the expected public key through a separately trusted channel. A key returned by the same mutable service is not an independent identity witness. Standalone verifier 2.2.3 refuses malformed supplied keys and missing CLI values. Other implementations retain different semantics; check the exact version and issuer-match result. A key match does not establish truthful inputs, policy correctness, execution, complete capture, freshness or a secure deployment.
