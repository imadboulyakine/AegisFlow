# AegisFlow — Architecture Decision Records

Compact ADR log. *Accepted* ADRs are binding (AGENTS.md); change them only with a new ADR that
supersedes them. *Proposed* ADRs need owner confirmation before they drive implementation.

Last updated: 2026-10-26 (Phase 0)

Format: **Context / Decision / Consequences / Status / Date**. Sources for verified facts are in
ARCHITECTURE.md §13, SECURITY_MODEL.md §11 and AZURE_COSTS.md §6.

| ADR | Title | Status |
|---|---|---|
| 001 | Go 1.27 toolchain and module path | Accepted |
| 002 | Single binary, stdlib HTTP, zero third-party Go deps in Phase 0 | Accepted |
| 003 | React 19 + TypeScript built with Bun's native bundler, embedded in Go | Accepted |
| 004 | HTTP surface, middleware and env-only config | Accepted |
| 005 | Distroless nonroot multi-stage container | Accepted |
| 006 | GitHub Actions CI hardening baseline | Accepted |
| 007 | PostgreSQL as system of record (Phase 2+) | Accepted |
| 008 | Azure target: Container Apps + ACR + Key Vault + Log Analytics + MI + OIDC + Bicep | Accepted |
| 009 | Supply-chain toolchain | Accepted (versions verified 2026-10-26, see ADR-015) |
| 010 | Explainable anomaly detection, no black-box ML in MVP | Accepted |
| 011 | Policy engine: CEL (`cel.dev/cel-go`) over OPA/Rego | Proposed |
| 012 | Risk scoring formula | Proposed |
| 013 | Azure region: francecentral | Accepted |
| 014 | Repository visibility: private now, public at end of Phase 1 | Accepted |
| 015 | Scanner and signing tool pinning after 2025–2026 action compromises | Accepted |
| 016 | Authentication: GitHub OIDC for CI ingestion, Entra ID for the dashboard | Proposed |
| 017 | Agent sessions may use the owner's Azure service principal (accepted risk) | Accepted |

---

### ADR-001 — Go 1.27 toolchain and module path
- **Context**: Host Go is 1.24.7 (out of support); latest on proxy.golang.org is 1.27.3 and
  `GOTOOLCHAIN` auto-download works.
- **Decision**: `go 1.27.0` + `toolchain go1.27.3` in `go.mod`; module `github.com/imadboulyakine/aegisflow`.
- **Consequences**: Supported toolchain with current security fixes and Go 1.22+ routing; contributors
  need network access to fetch the toolchain once; bump via Dependabot/ADR.
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-002 — Single binary, stdlib HTTP, zero third-party Go deps in Phase 0
- **Context**: One developer, limited budget, supply-chain focus; every dependency is attack surface.
- **Decision**: One binary `aegisflow` (`cmd/aegisflow`) using `net/http` ServeMux method/path
  patterns and `log/slog` JSON logs. No third-party Go modules in Phase 0; each later dependency
  requires an ADR with justification (size, maintainers, transitive count).
- **Consequences**: Small SBOM and fast govulncheck; some code written by hand (routing helpers);
  modules stay packages that could be split later (ARCHITECTURE.md §10).
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-003 — React 19 + TypeScript with Bun's native bundler, embedded in Go
- **Context**: Need a dashboard SPA; npm ecosystem worms (Shai-Hulud 2025, Mini Shai-Hulud 2026) make
  JS dependency count a direct risk.
- **Decision**: React 19 + TS bundled by Bun's native bundler (no Vite/webpack). Output copied to
  `internal/webui/dist` and embedded with `//go:embed all:dist`; committed `dist/.gitkeep` keeps
  `go build` working; server serves a fallback page when `index.html` is absent.
- **Consequences**: 2 runtime + 4 dev npm deps today; fewer plugins/HMR conveniences than Vite; one
  artifact to sign and scan.
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-004 — HTTP surface, middleware and configuration
- **Context**: Container Apps probes and the SPA need stable endpoints; security headers are cheap wins.
- **Decision**: `/healthz` (liveness), `/readyz` (readiness), `/api/v1/version` (version/commit/buildDate
  via `-ldflags` into `internal/version`); SPA fallback for non-`/api` paths. Middleware: request ID,
  structured access log, panic recovery, strict security headers (CSP, nosniff, Referrer-Policy,
  `frame-ancestors 'none'`, Permissions-Policy). `http.Server` timeouts, graceful shutdown. Config from
  env only (`AEGISFLOW_ADDR` default `:8080`, `AEGISFLOW_LOG_LEVEL`).
- **As implemented (Phase 0)**: plus `AEGISFLOW_SHUTDOWN_TIMEOUT` (default 10s); `/api/*` errors are
  RFC 9457 `application/problem+json` (404 unknown route, 405 with `Allow`); Go 1.25
  `http.CrossOriginProtection` rejects cross-site unsafe methods (403); 1 MiB request body limit;
  `/readyz` returns 503 while draining on shutdown; binary flags `-healthcheck` and `-version`.
- **Consequences**: Probes map 1:1 to ACA startup/liveness/readiness; strict CSP constrains frontend
  (no inline scripts, no `data:` images — the web build fails on violations).
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-005 — Distroless nonroot multi-stage container
- **Context**: Minimise image attack surface and SBOM noise.
- **Decision**: Multi-stage Dockerfile: bun build → `go build CGO_ENABLED=0 -trimpath` → distroless
  static nonroot; base images pinned by digest; port 8080; runs as nonroot; compatible with read-only
  root filesystem.
- **As implemented (Phase 0)**: `oven/bun:1.4.4-alpine` → `golang:1.27.3-alpine` →
  `gcr.io/distroless/static-debian13:nonroot` (Debian 13, because Debian 12 left regular security
  support in June 2026), all digest-pinned; numeric `USER 65532:65532`; `HEALTHCHECK` runs
  `/aegisflow -healthcheck` (no curl in distroless); cross-compiles via `$BUILDPLATFORM`/`TARGETARCH`.
  Measured image: 18 MB on disk, ~4 MB compressed.
- **Consequences**: No shell for debugging (use logs/ephemeral debug images); digest pins updated by
  Dependabot `docker`.
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-006 — GitHub Actions CI hardening baseline
- **Context**: Tag-repointing attacks on actions (tj-actions/changed-files 2025, xygeni-action and
  Trivy actions 2026) executed attacker code with CI secrets.
- **Decision**: Top-level `permissions: contents: read`; every action pinned to a full commit SHA with
  a `# vX.Y.Z` comment; jobs: Go (gofmt, vet, `test -race`, govulncheck, build), web (`bun install
  --frozen-lockfile`, typecheck, `bun test`, build), container build (no push). Dependabot for gomod,
  bun, github-actions, docker. No deployment workflow in Phase 0.
- **As implemented (Phase 0)**: `persist-credentials: false` on every checkout; golangci-lint runs
  via `make golangci-lint` (built from source with the go.mod toolchain, checksum-verified by
  sum.golang.org) instead of a third-party action, so local and CI use the same command; Dependabot
  also covers `docker-compose` and uses a 3-day `cooldown`; Bun installs use `--frozen-lockfile
  --ignore-scripts` with a 3-day `minimumReleaseAge`.
- **Consequences**: Updates arrive as reviewable Dependabot PRs; job-level permission escalation must
  be explicit. Follow-ups in Phase 1: zizmor + actionlint in CI (`make actionlint` exists locally),
  evaluate GitHub workflow dependency lockfiles (public preview).
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-007 — PostgreSQL as system of record (Phase 2+)
- **Context**: Need relational joins (artifacts ↔ components ↔ findings) plus semi-structured evidence.
- **Decision**: PostgreSQL with JSONB for SBOM/findings. Local via docker compose; Azure Database for
  PostgreSQL Flexible Server (Burstable) later, stopped when idle. No DB in Phase 0.
- **Consequences**: Adds a Go driver dependency (pgx, ADR in Phase 2); Postgres stop lasts max 7 days
  before auto-start, so scheduled re-stop is needed; free-offer eligibility to confirm (AZURE_COSTS.md).
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-008 — Azure target platform
- **Context**: Need progressive delivery and cloud-security controls at student cost.
- **Decision**: Azure Container Apps (Consumption) + ACR (Basic) + Key Vault + Log Analytics +
  user-assigned Managed Identity; GitHub Actions → Azure via OIDC workload identity federation (no
  long-lived secrets); IaC in Bicep under `infra/`; progressive delivery via multiple-revision mode with
  traffic splitting (canary + automated rollback).
- **Consequences**: Scale-to-zero + monthly free grant; rollback logic is ours (ACA has none built in);
  federated credentials must use GitHub's immutable `sub` format (repo created after 2026-07-15); Entra
  flexible FICs are preview — use exact match. First billable work happens only in Phase 4.
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-009 — Supply-chain toolchain
- **Context**: The platform orchestrates best-of-breed OSS tools rather than re-implementing them.
- **Decision**: Syft (SBOM, CycloneDX + SPDX), Grype and/or Trivy + govulncheck + osv-scanner (SCA),
  CodeQL + gosec/Semgrep (SAST), gitleaks (secrets), OWASP ZAP baseline (DAST), Playwright (E2E), cosign
  keyless signing + GitHub artifact attestations (SLSA build provenance), policy gate verifying
  signature + provenance + vuln policy before deploy.
- **Consequences**: Latest tags on 2026-10-26: syft v1.55.0, grype v0.121.0, trivy v0.76.1, osv-scanner
  v2.7.0, golang/vuln v1.9.0, semgrep v1.182.0, gosec v2.30.0, codeql-action v4.39.1, gitleaks v8.30.1,
  ZAP v2.17.0, Playwright v1.64.1, cosign v3.1.4, actions/attest v4.2.2. **Caveat**: CodeQL and GitHub
  attestations are unavailable for private repos on Free/Pro — resolved by ADR-014; `slsa-github-generator`
  is no longer maintained and is not an option.
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-010 — Explainable anomaly detection
- **Context**: Thesis needs defensible, explainable detections; little labelled data.
- **Decision**: Statistical baselines (robust z-score/MAD, EWMA) + rules over pipeline, supply-chain and
  runtime signals; each alert carries human-readable feature contributions. No black-box ML in MVP.
- **Consequences**: Transparent and testable with injected anomalies (E6); may miss complex
  multi-signal attacks — documented as a limitation.
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-011 — Policy engine: CEL over OPA/Rego
- **Context**: The gate evaluates policies over a typed document (artifact, provenance, findings
  summary). Candidates: CEL (`cel.dev/cel-go`, module moved from `github.com/google/cel-go`) and OPA/Rego.
  Measured 2026-10-26 with Go 1.27.3, minimal programs, stripped binaries: baseline 1.5 MB / 1 module;
  cel-go v0.32.0 → **19 modules, 10.4 MB**; OPA v1.21.4 → **124 modules, 23.2 MB**.
- **Decision**: Use CEL. Policies are YAML files in the repo (`name`, `version`, `mode: warn|enforce`,
  `expression`, `message`), compiled at startup with type-checked declarations and a cost limit.
- **Consequences**: ~6× fewer modules than OPA; non-Turing-complete, bounded evaluation (safe for
  user-edited policies); Kubernetes-style familiarity. Loses Rego's data joins, partial evaluation and
  conftest ecosystem — revisit (new ADR) only if a policy needs cross-document reasoning.
- **Status**: Proposed — **Date**: 2026-10-26

### ADR-012 — Risk scoring formula
- **Context**: CVSS-only triage over-prioritises unexploitable issues; EPSS (v4 model since 2025-03-17,
  served by the `api.first.org/data/v1/epss` API), CISA KEV, govulncheck reachability and VEX add signal.
- **Decision**: `risk = 100 × min(1, 0.40·S + 0.35·E + 0.25·K) × R × X × V` (definitions in
  ARCHITECTURE.md §7); tiers P1 ≥ 70 (block), P2 40–69 (warn), P3 < 40; every factor stored for
  explanation; KEV + reachable + internet-exposed is always P1 regardless of score.
- **Consequences**: Deterministic and explainable; weights are initial estimates to be calibrated in E2
  and frozen before final evaluation; SSVC kept as a comparison baseline.
- **Status**: Proposed — **Date**: 2026-10-26

### ADR-013 — Azure region
- **Context**: Candidates francecentral and westeurope (EU data residency, low latency for a Europe/
  North-Africa based owner [E]). **Azure for Students subscriptions enforce an "allowed regions" Azure
  Policy whose list varies per subscription** (Microsoft Q&A reports; not officially documented), so
  the preferred region may be disallowed. Prices in EU regions are similar; francecentral is often
  slightly cheaper than westeurope for compute [E].
- **Facts (read-only ARM queries, 2026-10-26)**: the subscription is an Azure *free account*
  (`quotaId FreeTrial_2014-09-01`, spending limit on), not Azure for Students; it has **no
  allowed-locations policy** (only the default ASC assignment and Microsoft's mandatory-MFA policies
  for user write/delete actions); `Microsoft.App/managedEnvironments` is offered in France Central.
- **Decision**: **francecentral** for every AegisFlow resource (single region); westeurope is the
  fallback only if a SKU is unavailable there. Bicep keeps `location` as a parameter.
- **Consequences**: Bicep takes `location` as a parameter; no multi-region.
- **Status**: Accepted (owner delegated to the recommendation) — **Date**: 2026-10-26

### ADR-014 — Repository visibility and GitHub feature strategy
- **Context**: `imadboulyakine/AegisFlow` is **private** on a personal account (plan unknown; Student
  Pack likely gives Pro). Per GitHub docs (2026-10-26): on Free/Pro, artifact attestations, CodeQL code
  scanning, dependency review and secret scanning/push protection are **public-repo only** (or need
  GHEC / org Team + paid Code/Secret Security); rulesets/branch protection and environments need Pro for
  private repos; required-reviewer deployment protection is public-only; Actions minutes are 2,000
  (Free) / 3,000 (Pro) per month for private repos vs free standard runners for public repos. Keyless
  cosign writes repo name, commit SHA, workflow path and visibility to the public Rekor log.
- **Options**: (a) make the repo public when ready → free CodeQL, dependency review, attestations
  (SLSA Build L2, L3 with reusable workflow), push protection, required reviewers, unlimited standard
  minutes, public transparency (verifiable thesis artifact). (b) stay private → Semgrep/gosec,
  osv-scanner, gitleaks; cosign key-based with an Azure Key Vault key (`azurekms://`, `--tlog-upload=false`)
  or keyless with accepted metadata disclosure; in-house SLSA provenance predicate + `cosign attest`
  (`slsa-github-generator` is unmaintained); tight minute budget; on Free, no rulesets/environments.
- **Decision (recommended)**: **(a)** — go public at the end of Phase 1 once a full-history gitleaks
  scan is clean and `SECURITY.md`/`LICENSE` exist. Keep OSS scanners in the pipeline regardless, so the
  design stays portable and comparable (E1/E2). Until then, use option (b) tooling with local/test keys.
- **Consequences**: Public repo exposes code and workflows (they contain no secrets by design); fork-PR
  workflows must stay unprivileged (`pull_request`, never `pull_request_target` with PR checkout). If the
  owner/school requires privacy, (b) is adopted and SECURITY_MODEL.md §7 limitations become thesis limits.
- **Owner decision (2026-10-26)**: recommendation (a) adopted. Phase 1a adds OSS scanners while
  private; signing/provenance (keyless cosign + `actions/attest`) is the last Phase 1 step, done right
  after the visibility switch. The switch itself is an owner action (repo setting), preceded by a
  clean full-history gitleaks scan, `SECURITY.md` and a licence (Apache-2.0 recommended — owner to
  confirm the school has no IP clause).
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-015 — Scanner and signing tool pinning
- **Context**: Trivy release v0.69.4 and 76 of 77 `trivy-action` tags were maliciously replaced in
  March 2026 (GHSA-69fq-xp46-6x23 / CVE-2026-33634); similar tag hijacks hit tj-actions (2025),
  xygeni-action (CVE-2026-31976) and actions-cool (2026).
- **Decision**: Grype is the primary container scanner (native Syft SBOM input), Trivy an
  optional cross-check. All scanner binaries are installed by checksum/signature-verified download or
  digest-pinned container image — never via `@latest`/mutable tags; actions pinned by SHA (ADR-006);
  tool versions recorded in every evidence row.
- **Consequences**: Slightly more workflow code (verify checksums/cosign signatures of tools);
  evidence is attributable to exact tool versions. Go-based tools may also be run with
  `go run module@vX.Y.Z`, which is verified against sum.golang.org (implemented in Phase 1a).
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-016 — Authentication for CI ingestion and dashboard
- **Context**: Evidence must be attributable to a specific repo/run/commit; the dashboard has one admin.
- **Decision (proposed)**: CI authenticates with GitHub Actions OIDC JWTs (custom audience); AegisFlow
  verifies signature (JWKS), `iss`, `aud`, expiry, `repository_id`/`repository_owner_id` allow-list and
  binds evidence to the token's `sha`/`run_id`. Dashboard uses Container Apps built-in authentication
  with Entra ID in Phase 4 (no auth code in the app); local dev uses a loopback-only dev mode.
- **Consequences**: No shared secrets for ingestion; a JWT library or ~200 lines of stdlib verification
  (decide by ADR in Phase 2); built-in auth ties dashboard auth to ACA (acceptable for MVP).
- **Status**: Proposed — **Date**: 2026-10-26

### ADR-017 — Agent sessions may use the owner's Azure service principal
- **Context**: The Claude Code cloud environment exposes an Entra service principal through
  `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_SECRET`. Read-only
  discovery (2026-10-26) showed it holds **Contributor on the whole subscription**, which also contains
  the owner's unrelated lab resource groups. AGENTS.md originally forbade credentials in sessions.
- **Decision**: The owner explicitly authorised agent sessions to use this service principal
  ("personal project"). Rules: (1) never print, log, commit or pass the secret on a command line —
  read it from the environment inside the tool (SDK `EnvironmentCredential` or a token request whose
  body is built in-process); (2) read-only operations are allowed at any time; (3) every
  **write or billable** action still needs the phase gate in AGENTS.md §3 (Phase 4 approval recorded
  here) and must stay inside the AegisFlow resource group(s); (4) never touch resources AegisFlow did not
  create; (5) CI keeps OIDC federation (ADR-008) — this secret is never copied into GitHub.
- **Consequences**: Accepted risk: a leaked session environment would expose subscription-wide
  Contributor. Mitigations recommended to the owner before Phase 4: scope the SP to the AegisFlow
  resource group, rotate the secret, add a subscription budget. Contributor cannot create role
  assignments, so Phase 4 needs the owner (or an RBAC Administrator role constrained to the RG) to grant
  the GitHub OIDC identity its roles.
- **Status**: Accepted (owner decision) — **Date**: 2026-10-26

---

## GitHub plan constraints (summary for ADR-014)

| Capability | Public | Private Free | Private Pro |
|---|---|---|---|
| Artifact attestations / CodeQL / dependency review / secret scanning + push protection | Yes | No | No |
| Rulesets, branch protection, environments | Yes | No | Yes (no required reviewers) |
| Actions minutes (standard runners) | Free | 2,000/month | 3,000/month |
| GitHub OIDC → Azure, Dependabot alerts/updates | Yes | Yes | Yes |

Source: github/docs `data/reusables/gated-features/*` and billing reference @56547cc (2026-10-26); full
matrix and signing-privacy analysis in SECURITY_MODEL.md §7.

## Owner decisions (2026-10-26)

The owner asked to adopt the recommended answer for each open question. Facts marked [V] were
verified with read-only Azure Resource Manager queries on 2026-10-26.

| # | Question | Answer | Status |
|---|---|---|---|
| Q1 | Repository visibility | Private through Phase 1a; switch to **public at the end of Phase 1** (ADR-014) | Decided |
| Q2 | GitHub plan | Unknown — **assume Free** (no rulesets/environments on private repos) until verified | Assumption |
| Q3 | Keyless signing while private | **No** — sign keylessly + `actions/attest` only after going public | Decided |
| Q4 | Azure subscription type | [V] Azure **free account** (`FreeTrial`, spending limit on); $0 in Sept, $37.49 month-to-date in Oct in the owner's other lab RGs. Free-trial credit expires 30 days after sign-up, so Phase 4 will most likely need an upgrade to pay-as-you-go (12-month free services incl. PostgreSQL B1ms 750 h/month remain) | Decided; owner to check credit balance/expiry in the portal |
| Q5 | Allowed regions | [V] No allowed-locations policy → **francecentral** (ADR-013) | Decided |
| Q6 | Entra identity for CI | Use a **user-assigned managed identity with a GitHub federated credential** (no app registration needed); the existing SP (Contributor @ subscription [V]) cannot create role assignments → owner grants roles in Phase 4 | Decided |
| Q7 | Budget | **$20/month** budget scoped to the AegisFlow resource group, alerts at 50/80/100 % actual and 100 % forecast; alert e-mail supplied at deploy time (never committed). Created as the first Phase 4 resource | Decided |
| Q8 | Custom domain | **No** — default `*.azurecontainerapps.io` URL with managed TLS | Decided |
| Q9 | Thesis language / defence date | Repo docs stay in **English**; thesis language follows the school's rules (not blocking before Phase 6) | Partly open |
| Q10 | Dashboard users | **Owner only**; supervisor/jury see a live demo (Entra guest access only if required) | Decided |
