# AegisFlow experiments

This directory holds the reproducible harnesses for the PFE (final-year project) evaluation. The
hypotheses, metrics and success thresholds come from `docs/ROADMAP.md` ("Measurable PFE
experiments"). If the two disagree, the ROADMAP wins: update this file to match it.

| ID | Experiment | Harness | Status |
|---|---|---|---|
| E1 | Secret detection (gitleaks) | [`e1-secrets/`](e1-secrets) (Go) · `make e1` | Runs locally (first results below). Time-to-detect is measured in CI |
| E2 | Risk-based vs CVSS-only prioritisation | Phase 2 | Planned |
| E3 | Tamper detection by the provenance gate | [`e3-tamper/README.md`](e3-tamper/README.md) (scenario catalogue) | Catalogue only, code in Phase 3 |
| E4 | Pipeline overhead | [`e4-overhead/`](e4-overhead) (Go) · `make e4` | Collector ready. Needs a token and real runs |
| E5 | Canary rollback | Phase 4/5 | Planned (billable) |
| E6 | Explainable anomalies | Phase 5 | Planned |
| E7 | Azure cost | Phase 4–6 | Planned (billable) |
| E8 | VEX / reachability auto-triage | Phase 2 | Planned |

Harnesses are packages of the main Go module and use only the standard library. `go test ./...`,
`make lint` and the repository's own security gates (gitleaks, Semgrep) cover them.
`make experiments-test` runs just their tests.

## Reproducibility rules

1. **One command per experiment** (`make e1`, `make e4`, ...). Parameters are Make variables
   (`E1_SEED`, `E4_RUNS`, ...) and are recorded in the result files.
2. **Pinned tools.** Go programs build with the `go.mod` toolchain (go1.27.3). External tools follow
   ADR-015: `go run`/`go install module@vX.Y.Z` (checksums verified against sum.golang.org) or
   container images pinned by digest. Each result file records the version the run *actually
   executed*. For example, E1 reads the gitleaks binary's embedded Go build info and records its
   module version, its `h1:` module sum and the binary's SHA-256. E1 also refuses to run any binary
   that is not a gitleaks v8 build, or that does not match `-gitleaks-version`.
3. **Seeds.** All randomness comes from one seeded generator (ChaCha8, keyed by
   `SHA-256("aegisflow/e1-secrets/<seed>")`). Commit dates and identities in generated repositories
   are fixed, so the same seed and toolchain give byte-identical fixtures and the same git commit
   IDs.
4. **Dataset hashes in every result file.** E1 records the manifest SHA-256 (every planned file
   write), the ground-truth SHA-256 and the fixture HEAD commit. E4 records the SHA-256 of its raw
   `jobs.csv` and `pipelines.csv`. Equal hashes mean the same dataset.
5. **No real secrets, ever.** E1 builds every credential at runtime from a public format prefix plus
   seeded random characters. This source tree contains no credential-shaped literal, and a unit
   test enforces that (`TestSourceHasNoCredentialLiterals`). Fixture repositories live in the system
   temp directory and are deleted after the run unless you pass `-keep-repo`. Scanner reports are
   written with `--redact`. The ground truth stores only a SHA-256 fingerprint and a 4-character
   preview (the public prefix) of each value.
6. **Results.** Each run writes a timestamped folder under `experiments/results/<id>/`. That
   directory is gitignored, so raw runs are never committed by accident. For the thesis, copy the
   selected runs deliberately into a committed folder (proposal: `experiments/reports/<id>/`) and
   cite their hashes.
7. **Facts vs assumptions.** Result files separate measured values from configuration. Anything this
   harness cannot measure (for example CI time-to-detect) is marked as such, never estimated
   silently.

## E1: secret detection benchmark

**Hypothesis.** gitleaks in CI and pre-commit catches seeded secrets with few false alarms.
**Thresholds:** recall ≥ 0.90, precision ≥ 0.80, detection < 3 min (commit to failing check).

```sh
make e1                                  # 50 secrets + 50 decoys, seed 20261026, repo .gitleaks.toml
make e1 E1_SEED=7 E1_REPS=4              # another dataset, 200 + 200 items
go run ./experiments/e1-secrets -h       # all flags (-keep-repo, -generate-only, -modes, ...)
```

What one run does:

1. Generates the dataset from the seed. It has 10 secret types × 5 variants × `E1_REPS`
   (a balanced design), plus 10 decoy kinds × 5 × `E1_REPS`.
2. Writes a throwaway git repository: a skeleton commit, 12 feature commits that add the items
   inside realistic code and config files (one item per file), and removal commits for the
   history-only secrets.
3. Runs the pinned gitleaks binary (`GITLEAKS_VERSION` from `mk/code-security.mk`, the same pin and
   `.gitleaks.toml` as the CI gate, with `--ignore-gitleaks-allow`) in two modes:
   - `git`: every commit, like the nightly full-history scan. A PR scan is the same over the PR's
     commits. **This is the headline mode.**
   - `dir`: the working tree only. History-only secrets are expected misses here.
4. Matches findings to the ground truth and writes `results.json`, `results.md`,
   `ground-truth.json` and the redacted `findings-<mode>.json`.

| Secret types | Variants | Decoy kinds (must not be flagged) |
|---|---|---|
| AWS access key pair, GitHub classic PAT, GitHub fine-grained PAT, Azure Storage connection string, Entra ID client secret, Slack bot token, PEM private key (RSA/EC/OpenSSH), HS256 JWT, generic API key, PostgreSQL URI with password | `plain` (string literal in Go/Python/TS), `config` (.env, YAML, JSON, tfvars, key file), `base64` (Kubernetes Secret or opaque blob in code), `split` (concatenated across lines), `history` (committed, later removed) | vendor-documented examples (AWS docs, jwt.io), placeholders, secret-store references (`${{ secrets.X }}`, `os.Getenv`, `secretKeyRef`), truncated tokens, image digests, action SHA pins, Azure tenant/subscription/client IDs, SRI hashes and checksums, public keys and certificates, test vectors (digests, ETags, trace IDs) |

**Metric definitions.** A secret counts as *detected* when a finding has the same file, an
overlapping line range and (in `git` mode) the commit that introduced it. Every other finding is a
false alarm, counted once per distinct (commit, file, start line).

- Precision = TP / (TP + FP), where TP is detected secrets and FP is distinct false-alarm locations.
- Recall = TP / seeded secrets.
- The reports also give per-type and per-variant recall, a per-decoy-kind flag rate, findings per
  rule and the wall-clock time of each gitleaks run.

**Time-to-detect (CI only).** The harness cannot measure "commit to failing check" locally. Planned
procedure for Phase 1c:

1. Generate one fixture item with `-generate-only -keep-repo`.
2. Commit it on a throwaway branch and open a draft PR.
3. Read the `code-security.yml` secrets job: `completed_at` of the job minus `created_at` of the
   workflow run (the E4 collector exports both).
4. Close the PR and delete the branch.

Assumption to check first: GitHub push protection on the public repository may block the push. The
values are synthetic and have no valid checksum, but detection is provider-specific.

### First local results (2026-10-26, sandbox, 4 vCPU)

Tested facts, `make e1` defaults:

- gitleaks v8.30.1 (`h1:PmEvCfVI7ti9dV3s5aMZUY7sS2GxRvG3yzih7E+cS3w=`), config `.gitleaks.toml`.
- Seed 20261026. Manifest `sha256:9644e142…0689054`. Fixture HEAD `638e346…`.

| Mode | Recall | Precision | F1 | TP / FN / FP | Decoys flagged | Runtime |
|---|---|---|---|---|---|---|
| git (full history) | **0.74** | **0.974** | 0.841 | 37 / 13 / 1 | 1/50 | ~125 ms |
| dir (working tree) | 0.56 | 0.966 | 0.709 | 28 / 22 / 1 | 1/50 | ~160–230 ms |

- **Recall fails** the 0.90 threshold. **Precision passes.**
- Every miss comes from one of three gaps:
  - `split` values (9 of 10 missed).
  - `postgres-uri`: the default ruleset has no rule for database URIs with passwords (5 of 5).
  - One base64-wrapped generic key.
- The only false alarm is the public jwt.io example token in a Markdown doc (rules `jwt` and
  `curl-auth-header`). The AWS documentation example keys are allow-listed upstream.
- Seed sweep, seeds 1–5, git mode: recall 0.74–0.82, precision 0.974–0.976.
- `E1_REPS=4` (200 secrets, 200 decoys): recall 0.77, precision 0.963.
  - Per-variant recall: plain 0.90, config 0.90, base64 0.85, split 0.30, history 0.90.
  - `postgres-uri` recall: 1/20.

These numbers measure gitleaks with its upstream rules on this synthetic corpus. They do not
measure GitHub push protection.

## E4: pipeline overhead

**Hypothesis.** The full secure pipeline costs at most 2× the baseline wall-clock.
**Thresholds:** ≤ +6 min and ≤ +100 % wall-clock on the PR path, ≤ 20 billed minutes per PR.

```sh
GITHUB_TOKEN="$(gh auth token)" make e4                    # 20 newest PR head SHAs
GITHUB_TOKEN=... make e4 E4_RUNS=30 E4_EVENT=push E4_FLAGS="-branch main"
```

The collector reads only the GitHub REST API, and only with read access. A fine-grained token with
*Actions: read* and *Metadata: read* on the repository is enough. The token comes from
`GITHUB_TOKEN` and goes only to the configured API origin. It is never logged or written to a file.
The collector accepts no plain-HTTP API URL except loopback.

1. It takes the newest `E4_RUNS` distinct head SHAs of the baseline workflow (`ci.yml`, completed
   and successful).
2. For each SHA it adds the newest completed, non-cancelled run of every other full-pipeline
   workflow (`E4_WORKFLOWS`), plus every job of the latest attempt.

It writes three files:

- `jobs.csv`: the raw dataset, one row per job.
- `pipelines.csv`: one row per SHA, with baseline, full and overhead values.
- `summary.md`: median, p90 and mean for each metric, per-job tables, workflow coverage, threshold
  verdicts and the dataset hashes.

Definitions:

- **Wall-clock** runs from the earliest `run_started_at` to the last job's `completed_at` across the
  runs for one SHA. The workflows run in parallel, so this is how long the developer waits.
- **Billed minutes** are the sum over jobs of the duration rounded up to a whole minute, times the
  runner multiplier: Linux 1, Windows 2, macOS 10, self-hosted 0. Larger runners are not modelled.
  This is GitHub's documented per-job rounding rule. The collector computes it from job timestamps
  so it does not depend on the run-usage (`/timing`) endpoint. Assumption, not verified from the
  sandbox: GitHub's billing changes are phasing out that endpoint's billable fields.
- **Overhead** is full minus baseline, paired per SHA (seconds and %). The verdicts use the medians.
- **p90** uses linear interpolation between the closest ranks (the NumPy default).
- A workflow skipped by path filters, or not merged yet, counts as missing for that SHA, and
  `summary.md` reports it.

The sandbox cannot reach this repository's API, so `TestRunEndToEnd` checks the collector against
an `httptest` fake of the three endpoints it uses. The fake covers pagination, de-duplication,
cancelled runs, missing workflows, rate limits and leak checks on the token. Real numbers need
`make e4` on a machine with a token, or in a workflow with `actions: read`.
