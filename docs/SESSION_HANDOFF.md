# AegisFlow — Session Handoff

Read this first. It is rewritten at the end of every session so the next one (human or agent) can
continue from the repository alone. Then read `PROJECT_STATE.md`, `ROADMAP.md`, `DECISIONS.md`.

Last session: 2026-10-26 — Phase 0 bootstrap — branch `claude/serene-franklin-lipl1f` → PR into `main`

## 1. What was done

- Created `main` with an empty root commit (the repo was empty; PRs need a base branch).
- Ran a capability audit of the Claude Code cloud container (results: `PROJECT_STATE.md` §4).
- Wrote the project memory: `AGENTS.md` (canonical agent rules), `CLAUDE.md` (imports it),
  `docs/ARCHITECTURE.md`, `SECURITY_MODEL.md`, `AZURE_COSTS.md`, `ROADMAP.md`, `DECISIONS.md`
  (ADR-001…016), `PROJECT_STATE.md`, this file.
- Bootstrapped the code: Go 1.27 single binary (stdlib only) with probes, versioned API, embedded
  React 19 SPA built by Bun, hardened middleware; distroless nonroot Dockerfile; compose; Makefile;
  GitHub Actions CI (SHA-pinned, read-only token); Dependabot; CODEOWNERS; PR template.
- Verified locally: `make lint`, `make test` (96 % Go coverage, 56 bun tests), `make build`,
  `make actionlint`, binary + container + browser smoke tests. Details: `PROJECT_STATE.md` §3.
- Work was split across three parallel subagents (environment audit, architecture/cost research,
  code bootstrap); the lead session reviewed, re-verified and committed everything.

## 2. In progress / not verified yet

- First CI run on GitHub for the Phase 0 PR: **green** (Go, Web, Container; ≈ 4m35s). PR #1 awaits the owner's merge.
- **Dependabot config** (`cooldown`, `bun`, `docker-compose` ecosystems) — check Insights →
  Dependency graph → Dependabot after merge.

## 3. Owner decisions needed (blocking later phases)

1. **Azure credentials in the cloud environment (B1, urgent-ish)**: a service-principal client secret
   is exposed to every agent session via environment variables. Remove it, or scope + rotate it.
   Agents must not use it (AGENTS.md §3).
2. **Q1–Q3 (ADR-014)**: public vs private repo, GitHub plan, keyless-signing metadata disclosure →
   decides Phase 1 tooling (CodeQL/attestations vs OSS fallbacks).
3. **Q4–Q8** before Phase 4: subscription type/credit, allowed regions, Entra app-registration
   rights, budget, domain. **Q9–Q10**: thesis language/defence date, dashboard users.
4. Enable branch protection / a ruleset on `main` after merging Phase 0 (plan-dependent).

## 4. Next tasks (Phase 1 — secure CI foundation), in suggested order

Each is a self-contained PR; parallelisable ones are marked ∥.

1. Owner merges PR #1 (CI already green), then enables branch protection on `main`.
2. ∥ **Workflow security**: add `actionlint` + `zizmor` jobs (pinned, checksum-verified).
3. ∥ **Secrets**: gitleaks on PR diff + scheduled full-history scan; `.gitleaks.toml` allow-list
   for synthetic test fixtures only.
4. ∥ **SCA**: govulncheck JSON (+ OpenVEX) and osv-scanner on `go.mod` + `web/bun.lock`, uploaded
   as artifacts (retention 7 days).
5. ∥ **SAST**: Semgrep OSS with vendored, pinned rules (registry is not reachable from agent
   sessions); CodeQL only if ADR-014 → public. gosec already runs inside golangci-lint.
6. **SBOM + image scan**: Syft (CycloneDX 1.6+/SPDX 2.3) for source and image; Grype on the SBOM in
   CI (Grype DB is blocked locally — use Trivy DB via mirror.gcr.io for local checks).
7. **Signing + provenance** per ADR-014 outcome: cosign key-based (test key, local) and/or keyless +
   `actions/attest` in CI; document the verification command.
8. `SECURITY.md`, licence choice (owner), experiment fixture skeletons under `testdata/` (E1–E3).
9. Measure pipeline overhead baseline (experiment E4) and record it in `PROJECT_STATE.md`.

## 5. How to verify the current state quickly

```bash
make lint test build          # all must pass
make run                      # http://localhost:8080 — dashboard shows "Operational"
curl -s localhost:8080/api/v1/version
```
Container build in the cloud sandbox needs the proxy-CA recipe in `PROJECT_STATE.md` §6.3.

## 6. Gotchas for the next session

- Host Go is 1.24.7 — never "fix" `go.mod` down; the toolchain line downloads 1.27.3.
- Host `golangci-lint` (2.5.0) and `gofmt` are stale — always go through `make`.
- vuln.go.dev, EPSS, NVD, OSV API, Grype DB, Sigstore, GitHub OIDC and prices.azure.com are blocked
  from the container; use offline fixtures locally and run live checks in CI.
- Docker Hub may 429 → `mirror.gcr.io` registry mirror; ghcr.io blobs are blocked.
- The GitHub MCP tools can only reach `imadboulyakine/AegisFlow`.
- Never run `az login` and never let Azure SDKs pick up the `AZURE_*` environment variables
  (prefix commands with `env -u AZURE_CLIENT_ID -u AZURE_CLIENT_SECRET -u AZURE_TENANT_ID -u AZURE_SUBSCRIPTION_ID`).
