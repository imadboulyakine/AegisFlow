# E3: tamper-detection scenario catalogue

**Hypothesis** (`docs/ROADMAP.md`): the Phase 3 gate (`POST /api/v1/gate`) rejects every tampered or
mis-provenanced artifact.

**Thresholds:**

- 100 % of tampered artifacts detected.
- 0 false rejections over at least 20 legitimate builds.
- Gate p95 latency under 5 s.

This file is the catalogue the Phase 3 harness will implement. **There is no code yet.** Read the
fixture recipes as plans, not as tested commands. Tool versions follow ADR-015 when they are
implemented: cosign `v3.x` (ARCHITECTURE.md lists v3.1.4), crane, and `registry:2` pinned by
digest.

## What the gate verifies (reference policy)

These are the checks of `internal/provenance` and `internal/policy` in ARCHITECTURE.md §3. A
scenario counts as *detected* when the gate returns `deny`, and the reason code names the failed
check. A correct verdict with the wrong reason counts as a detection, but it is reported separately
as an explanation error.

| Check | Expected value for a legitimate AegisFlow build |
|---|---|
| Subject | Artifact identified **by digest** (`sha256:…`). Tags are never trusted |
| Signature | Valid cosign signature over that digest. Keyless: a Fulcio certificate chained to the Sigstore trust root, plus a Rekor inclusion proof with an integrated time inside the cert validity. Key mode: a key in the trust policy that is not expired |
| Signer identity | Keyless: issuer `https://token.actions.githubusercontent.com`, SAN = `https://github.com/imadboulyakine/AegisFlow/.github/workflows/<release workflow>@refs/heads/main`. Key mode: key ID allow-list |
| Provenance | SLSA v1 provenance (in-toto statement, DSSE-signed). `subject[].digest` contains the artifact digest |
| Builder | `runDetails.builder.id` = the GitHub-hosted builder identity of the release workflow |
| Source | **Immutable repository ID** (not only the name), allowed ref (`refs/heads/main`, release tags), allowed workflow path, source commit = evidence `sha` |
| SBOM | SBOM attestation whose subject digest equals the artifact digest. Its content hash equals the SBOM evidence stored by AegisFlow |

Signing mode depends on ADR-014: keyless + `actions/attest` when public, key-based in-house in-toto
when private. Each scenario below lists the variant for both modes. Only the mode the project
adopts is required for the exit criteria.

## Tampered scenarios (expected verdict: `deny`)

| ID | Scenario | Attack it models | How the fixture is produced | Expected reason |
|---|---|---|---|---|
| T01 | Unsigned image | Push to the registry without going through CI | Build any image and push it to a local `registry:2` on loopback. Sign nothing | `signature.missing` |
| T02 | Wrong signer identity | Valid signature from another identity (fork, other repo, personal account) | Keyless: sign the digest from a workflow in a scratch repo, e.g. `aegisflow-tamper-fixtures`. Key mode: sign with a throwaway key generated at test time (never committed) | `signature.identity_mismatch` |
| T03 | Wrong OIDC issuer | A certificate from an issuer other than GitHub Actions | Keyless: offline, a test CA issues a cert with another issuer (unit-level). Key mode: N/A (covered by T12) | `signature.issuer_mismatch` |
| T04 | Re-tag to a different digest | Tag `:vX` moved to an image built elsewhere. The signature still exists for the old digest | `crane tag` (or `docker tag` + push) points the tag at another digest. The gate request names the tag | `subject.digest_mismatch` (the tag resolves to an unsigned or unattested digest) |
| T05 | Provenance from another repository | Build in an attacker repo, possibly one with the same name after a rename or deletion | Provenance whose source repository ID (and/or name) differs. Keyless: real provenance from the scratch repo. Key mode: an edited predicate, re-signed with the trusted test key | `provenance.source_repo_mismatch` |
| T06 | Provenance from another branch/ref | Release built from an unreviewed feature branch | Same build, `ref` = `refs/heads/feature/x` (keyless: run the workflow on that branch) | `provenance.ref_not_allowed` |
| T07 | Provenance from another workflow | A side workflow with weaker controls produces the artifact | `workflow.path` = `.github/workflows/unsafe.yml` (keyless: run from that file) | `provenance.workflow_mismatch` |
| T08 | Wrong builder | Self-hosted or unknown builder | `builder.id` changed in the predicate (key mode), or produced on a self-hosted runner (keyless, if available) | `provenance.builder_mismatch` |
| T09 | Layer modified after signing | Image altered in the registry or in transit after CI signed it | Pull the signed image, append a file to one layer (`crane mutate` / `crane append`) and push. The manifest digest changes. Sub-case: keep the old manifest but swap a blob in the local registry storage, so the content no longer matches its address | `signature.missing` for the new digest; `subject.digest_mismatch` (or a pull integrity error) for the swapped blob |
| T10 | SBOM digest mismatch | SBOM attestation belongs to another image, or the SBOM was edited | (a) Attach an SBOM attestation whose subject is another digest. (b) Change the stored SBOM after attestation, so the content hash differs | `sbom.subject_mismatch` / `sbom.content_digest_mismatch` |
| T11 | Expired key / certificate | Signature made outside the validity window, or with a retired key | Keyless: a cert whose validity does not contain the Rekor integrated time, or no inclusion proof (offline test vector). Key mode: a trust-policy key with `not_after` in the past | `signature.expired` |
| T12 | Unknown key | Signature by a key or root that is not in the trust policy | Sign with a fresh throwaway key that is absent from the trust policy | `signature.untrusted_key` |
| T13 | Tampered attestation payload | Predicate edited after signing (e.g. `ref` flipped to main) | Change one byte of the DSSE payload and keep the old signature | `attestation.signature_invalid` |

Each tampered scenario is run against at least 3 distinct base builds, giving ≥ 39 tampered
requests. Detection rate = denied / tampered.

## Legitimate controls (expected verdict: `allow`)

| ID | Control | Fixture |
|---|---|---|
| G01–G20 | 20 legitimate builds of `main` through the release workflow (different commits) | CI artifacts and evidence from real runs; digests listed in the run manifest |
| G21 | Re-run attempt (`run_attempt` = 2) of a legitimate build | Re-run one release job |
| G22 | Release tag build (if the policy allows `refs/tags/v*`) | Tag a commit and run the release workflow |
| G23 | Multi-arch index: verify the index digest and one platform digest | Build `linux/amd64,linux/arm64` |

False-rejection rate = denied / legitimate. **Any** `deny` on G01–G23 fails the experiment.
A `warn` is allowed but reported.

## Measurement

- **Detection rate**, **false-rejection rate**, and **gate latency** (p50/p95/max of the
  `/api/v1/gate` round-trip, client-measured, 3 repetitions per request, warm cache noted).
- **Explanation accuracy**: the reason code equals the expected reason in this table.
- Every request and response pair is stored with the decision's `input_sha256` (ARCHITECTURE §4), so
  the run can be replayed offline.
- Result layout follows `experiments/README.md`:
  `experiments/results/e3/<run>/{results.json,results.md}`, with tool versions and fixture digests.

## Fixture production plan

| Fixture class | Where | Why |
|---|---|---|
| Key-mode signatures, edited predicates (T02, T05–T08, T10–T13 in key mode) | Locally and in unit tests: keys generated at test time in a temp dir, local `registry:2` on loopback | Fully offline and deterministic. No Sigstore access is needed (Sigstore is blocked from the dev sandbox) |
| Keyless signatures and real provenance (T02, T05–T07 keyless, G01–G23) | GitHub Actions, in a `workflow_dispatch` fixture workflow, plus a scratch repository for foreign identities | Fulcio, Rekor and the GitHub OIDC token are reachable only on runners. The resulting Sigstore bundles are public data and can be committed as fixtures |
| Offline certificate vectors (T03, T11 keyless) | Unit tests with a test CA | The real Fulcio cannot issue these cases on purpose |

**Guardrails.** Never commit a private key, including throwaway ones: generate them at test time. Pin
the fixture registry image by digest and bind it to 127.0.0.1. Ask the owner before pushing images
to GHCR (ROADMAP Phase 1b).
