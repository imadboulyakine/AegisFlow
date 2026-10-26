# AegisFlow — Verifying a build

How anyone (reviewers, the thesis jury) can check that an `aegisflow` binary was built from this
repository by its CI, unmodified. Requires the repository to be public (ADR-014) and at least one
successful `provenance.yml` run on `main`.

Last updated: 2026-10-26 (Phase 1b)

Every push to `main` builds `aegisflow` in `.github/workflows/provenance.yml`, attests SLSA build
provenance and a CycloneDX SBOM with GitHub artifact attestations, and signs the binary with
Sigstore keyless cosign. Signatures are bound to the identity
`https://github.com/imadboulyakine/AegisFlow/.github/workflows/provenance.yml@refs/heads/main`
(issuer `https://token.actions.githubusercontent.com`) and logged in the public Rekor log.
Tools: a recent `gh` (flags checked with 2.89.0), `cosign` v3 (CI uses v3.1.4), `sha256sum`. Verification itself needs **no
GitHub account**; downloading run artifacts does (GitHub requires sign-in for artifact downloads).

```bash
# 1. Pick a signed run on main and download its artifact (or: Actions → Provenance → run → Artifacts)
gh run list --repo imadboulyakine/AegisFlow --workflow provenance.yml --branch main \
  --status success --limit 5 --json databaseId,headSha,event
RUN_ID=<databaseId>; COMMIT=<headSha>
gh run download "$RUN_ID" --repo imadboulyakine/AegisFlow --name aegisflow-signed --dir aegisflow-signed
cd aegisflow-signed            # aegisflow, SHA256SUMS, aegisflow.cdx.json, *.sigstore.json

# 2. Integrity
sha256sum -c SHA256SUMS

# 3. SLSA build provenance (offline-capable: the bundle ships in the artifact)
gh attestation verify aegisflow --repo imadboulyakine/AegisFlow \
  --bundle aegisflow.provenance.sigstore.json \
  --signer-workflow imadboulyakine/AegisFlow/.github/workflows/provenance.yml \
  --source-ref refs/heads/main --source-digest "$COMMIT" --deny-self-hosted-runners
#    (omit --bundle … to fetch from GitHub's attestation store; needs `gh auth login`)
#    show what was attested: append  --format json --jq '.[0].verificationResult.statement.predicate'

# 4. SBOM attestation (same identity, CycloneDX predicate)
gh attestation verify aegisflow --repo imadboulyakine/AegisFlow \
  --bundle aegisflow.sbom.sigstore.json --predicate-type https://cyclonedx.org/bom \
  --signer-workflow imadboulyakine/AegisFlow/.github/workflows/provenance.yml \
  --source-ref refs/heads/main --source-digest "$COMMIT" --deny-self-hosted-runners

# 5. Sigstore keyless signature (independent of GitHub's tooling)
cosign verify-blob aegisflow --bundle aegisflow.sigstore.json \
  --certificate-identity https://github.com/imadboulyakine/AegisFlow/.github/workflows/provenance.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository imadboulyakine/AegisFlow \
  --certificate-github-workflow-sha "$COMMIT"

# 6. Negative control: any change to the bytes must fail steps 3-5
cp aegisflow /tmp/tampered && printf x >> /tmp/tampered
cosign verify-blob /tmp/tampered --bundle aegisflow.sigstore.json \
  --certificate-identity https://github.com/imadboulyakine/AegisFlow/.github/workflows/provenance.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com   # → error: invalid signature
```

Steps 2-5 in one command from a clone: `make verify-provenance PROVENANCE_DIR=/path/to/aegisflow-signed PROVENANCE_COMMIT=$COMMIT`
(`PROVENANCE_ATTESTATIONS=api` to use the attestation store instead of the bundles).

**Rebuild it yourself (strongest check; no trust in the CI runner):** the build is reproducible.
```bash
git clone https://github.com/imadboulyakine/AegisFlow && cd AegisFlow && git checkout --detach "$COMMIT"
make reproduce PROVENANCE_DIR=/path/to/aegisflow-signed PROVENANCE_COMMIT="$COMMIT"   # bit-identical → OK
gh attestation verify bin/aegisflow --repo imadboulyakine/AegisFlow \
  --bundle /path/to/aegisflow-signed/aegisflow.provenance.sigstore.json   # your own build is the attested one
```
Needs Go (any version with `GOTOOLCHAIN=auto`; go.mod pins go1.27.3), Bun exactly as in
`web/package.json` `packageManager` (1.4.4), `jq`, a clean checkout (keep the downloaded artifact
outside the checkout or in `bin/`). The binary targets linux/amd64; `chmod +x` a downloaded copy
before running it (artifact zips drop the executable bit).

**What a pass proves:** these exact bytes were produced by `provenance.yml` on `refs/heads/main` of
`imadboulyakine/AegisFlow` at commit `$COMMIT` on a GitHub-hosted runner, the signing event is in
the public Rekor log, and the SBOM was attested by the same workflow run. **What it does not
prove:** that the source or its dependencies are free of vulnerabilities (see the scan evidence),
or that the build steps were not subverted on the runner (SLSA Build L2: build and signing share
one workflow definition, although only the signing job can mint an OIDC token) — `make reproduce`
closes that gap for anyone willing to rebuild.

