# Reviewer's Guide — verify AGA without trusting us

For a skeptic (cryptographer, security researcher, acquirer's diligence team) who wants to *check the
claims*, not take them on faith. Every step below is a command you run; nothing here asks for trust.
Times are wall-clock on a laptop.

## 0. The 30-second, zero-install floor

The reference verifier is a single dependency-free file (Node 18+, `node:crypto` only):

```bash
git clone https://github.com/attestedintelligence/aga-mcp-server && cd aga-mcp-server
node aga-receipt-spec/verify/verify-sep.mjs fixtures/valid_minimal.json   # OVERALL: VERIFIED (integrity of present receipts…)
node aga-receipt-spec/verify/verify-sep.mjs fixtures/tampered.json        # OVERALL: FAILED
```

No `npm install`, no network, no service. A one-byte change to the bundle flips it to FAILED.

## 1. Provenance: the published package binds to this source

```bash
npm view @attested-intelligence/aga-mcp-server version dist-tags
npm audit signatures                         # "verified registry signatures" + "verified attestations"
# decode the SLSA attestation to read the published-tarball digest (subject) and the exact source commit:
npm view @attested-intelligence/aga-mcp-server dist.integrity
gh attestation verify --owner attestedintelligence \
  $(npm pack @attested-intelligence/aga-mcp-server >/dev/null 2>&1; ls *.tgz)   # or inspect via the npm provenance UI
```

The SLSA v1 provenance binds the GitHub repo + the exact release commit + the published artifact digest,
all produced by `.github/workflows/release.yml` via npm OIDC trusted publishing (no human-held token).

## 2. Reproduce the published tarball byte-for-byte

```bash
npm ci && npm run build            # deterministic: .gitattributes pins LF, tsconfig pins newLine:lf
npm pack                           # your tarball
# compare the per-file SHA-256 manifest of YOUR build's contents to the published one
# (the .tgz gzip timestamp is the only nondeterminism — compare extracted file hashes, not the .tgz shasum)
```

A from-clean-clone build's `dist/` is byte-identical to the published `dist/` (see REPRODUCIBILITY.md for
the exact manifest procedure). The repo → commit → source → build → published-artifact loop closes.

## 3. Six independent verifiers agree (the conformance authority)

```bash
npm run conformance:cross-stack    # JS reference + in-server engine + aga-verify + Go + 2× Python
# => "6 verifiers agree on all 57 cases" — including the adversarial corpus (small-order keys,
#    truncation, reorder, surrogate, non-canonical timestamp, uppercase-Merkle-sibling, …)
```

This is the real differentiator: not "trust our verifier," but six independent implementations across
three languages returning byte-identical verdicts on a labeled adversarial corpus.

## 4. The "JCS" claim is checked, not asserted

```bash
npx vitest run tests/sep/jcs-rfc8785-conformance.test.ts
# asserts the shipped canon is byte-identical to the reference RFC 8785 impl (`canonicalize`) on the
# real receipt + checkpoint and the classic RFC 8785 edge cases. Regenerate expected: `npx canonicalize`.
```

## 5. Try to break it yourself

The full verifier is `aga-receipt-spec/verify/verify-sep.mjs` (~245 lines) and `CORE_VERIFICATION.md` is
the plain-language, vendor-independent algorithm. The negative vectors in
`fixtures/cross-stack/vectors.json` are real mounted forgeries (tampered roots and checkpoints,
truncation/splice, re-sign, canon ambiguity, envelope lies, malformed proofs), each labeled with the
exact attack it defends — replay any against any of the six verifiers and watch it FAIL. Mint your own
bundle with a key you choose (`signerFromSeed`) and attack it — the construction is designed to be attacked.

## 6. What a PASS does and does not prove (read this before relying on it)

- **Proves:** every receipt *present* is authentic (Ed25519), correctly ordered (hash chain), Merkle-
  included, checkpoint-bound, and — when you pin the gateway key (`--pubkey`) — issued by that key.
- **Does NOT prove non-omission:** a *self-signed* checkpoint cannot stop a malicious or compromised
  issuer from suppressing a `DENIED` record before export. Defending against issuer equivocation needs
  an external transparency log/witness, which SEP deliberately does not include.
- Full scope + residuals: `THREAT_BOUNDARY.md`, `KNOWN_LIMITATIONS.md`. Relationship to CT / Sigstore /
  in-toto / RFC 3161 / C2PA / Veritas Acta: `sep/0000-governance-receipts.md` (Relationship to prior work).

## 7. Pin the key for provenance

Without `--pubkey`, a PASS is **integrity-only** (`issuerVerified=false`) — a self-consistent bundle
signed by *any* key passes. Pass the gateway's real key (from `get_server_info`, or persist it via
`AGA_GATEWAY_KEY`) to also prove *who* issued it. A malformed `--pubkey` is a hard error, not a silent
downgrade.
