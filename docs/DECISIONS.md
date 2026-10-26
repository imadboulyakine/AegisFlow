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
| 014 | Repository visibility: public now; Apache-2.0 | Accepted |
| 015 | Scanner and signing tool pinning after 2025–2026 action compromises | Accepted |
| 016 | Authentication: GitHub OIDC for CI ingestion, Entra ID for the dashboard | Accepted (CI part); dashboard part Proposed |
| 017 | Agent sessions may use the owner's Azure service principal (accepted risk) | Accepted |
| 018 | Phase 4 hosting: Azure for Students subscription, $50/month budget, UAMI + OIDC | Accepted |
| 019 | Phase 1 CI security gates and binary provenance design | Accepted |
| 020 | Stdlib JWS/JWKS verification for GitHub Actions OIDC (no JWT library) | Accepted |
| 021 | PostgreSQL store with pgx v5, embedded migrations, append-only triggers | Accepted |
| 022 | Evidence normalization rules (reachability, PURLs, VEX scope, limits) | Accepted |
| 023 | Risk engine edge cases: VEX vs KEV override, unknown exposure, fail-closed feeds | Accepted |

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
- **Amended in Phase 1a**: Dependabot `cooldown` raised to **7 days** (zizmor's default; Dependabot
  security updates are not delayed by cooldown) and a `pip` ecosystem added for the hash-pinned CI tool
  requirements; Bun's install-time `minimumReleaseAge` stays 3 days (raising it could break frozen
  installs of current pins). actionlint and zizmor now run in CI (`code-security.yml`).
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
- **Status**: Accepted (owner choice) — **Date**: 2026-10-26. **Caveat (ADR-018)**: Phase 4 runs on a
  new Azure for Students subscription, whose allowed-regions policy must be re-checked when it exists.

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
- **Owner decision (2026-10-26)**: **make the repository public now** (option a, earlier than the
  recommended "end of Phase 1"); licence **Apache-2.0**; signing = **keyless cosign + `actions/attest`
  once public** (no keyless signing while private). Pre-flight done before the switch: full-history
  gitleaks scan (only finding: a synthetic request-ID test fixture), no real GUIDs/e-mail in history,
  `SECURITY.md` and `LICENSE` added. The switch itself is an owner action (repo setting). OSS scanners
  stay in the pipeline; code-scanning SARIF uploads, CodeQL and dependency review run only when
  `github.event.repository.visibility == 'public'`. GitHub plan: **Pro** (owner, Student Pack).
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

### ADR-018 — Phase 4 hosting, budget and CI identity
- **Context**: The current subscription is a free trial (30-day credit) that holds the owner's other
  labs; Phase 4 is ~10 weeks away.
- **Decision (owner)**: Phase 4 deploys into a **new Azure for Students subscription**; resource-group
  budget **$50/month** with alerts at 50/80/100 % actual and 100 % forecast; GitHub Actions
  authenticates with a **user-assigned managed identity + GitHub OIDC federated credential**, scoped
  to the AegisFlow resource group; region francecentral (ADR-013) if the Students subscription allows it.
- **Consequences**: The service principal of ADR-017 lives on the trial subscription and will not
  reach the Students subscription — Phase 4 needs new owner-side setup (subscription, RG, role
  assignment for the UAMI). Students subscriptions may restrict regions/SKUs: verify before writing
  Bicep defaults. $50 leaves room for demo weeks; idle target stays ≈ $6–11/month.
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-019 — Phase 1 CI security gates and binary provenance design
- **Context**: Phase 1 makes AegisFlow's own pipeline produce the evidence the platform will ingest;
  gates must be strict enough to matter and quiet enough to stay green on a clean tree.
- **Decision**: Four workflows besides `ci.yml`:
  - `code-security.yml` — gitleaks v8.30.1 (`go run`, sum.golang.org-verified): PR range on PRs, full
    history otherwise, **any finding fails**, inline `gitleaks:allow` ignored, allow-list only for
    verified synthetic fixtures. Semgrep 1.182.0 (digest-pinned image): 10 repo rules with tests +
    registry packs in CI, **ERROR fails**, warnings summarised. zizmor 1.31.1 (PyPI, `--require-hashes`):
    **medium+ severity and confidence fails**. actionlint.
  - `supply-chain.yml` — govulncheck **fails on called vulnerable symbols**; osv-scanner v2.7.0 over
    `go.mod` (incl. Go stdlib version) and `web/bun.lock` **fails on any known vulnerability** unless
    excepted with reason + expiry (expect red when a Go point release fixes a stdlib CVE, until the
    toolchain is bumped); Syft v1.55.0 + Grype v0.121.0 (digest-pinned images, read-only, no caps):
    **high+ with a fix available fails**; JSON/OpenVEX/SBOM/SARIF artifacts with stable names for
    Phase 2 ingestion.
  - `github-security.yml` — CodeQL (`security-extended`; Go, JS/TS, Actions) and dependency review
    (high+), public-only.
  - `provenance.yml` — build job (no id-token, caches off) → sign job (main only, public only, runs no
    repo code, re-checks the sha256): `actions/attest` SLSA provenance + SBOM attestation and cosign
    keyless `sign-blob`; verify job with negative controls. Reproducible build (`make reproduce`).
  - SARIF uploads and every write-scoped token (`security-events`, `id-token`, `attestations`) live in
    separate, minimal jobs gated on `github.event.repository.visibility == 'public'`.
- **Consequences**: Honest claim **SLSA Build L2** (L3 needs a reusable build workflow — stretch).
  Scheduled runs may lack `github.event.repository`, so weekly SARIF/CodeQL uploads can be skipped
  (pushes and PRs still upload) — accepted. Tool versions/digests in `mk/*.mk` (Semgrep image, gitleaks,
  osv-scanner, Syft, Grype, cosign) are **not** bumped by Dependabot: manual, reviewed bumps. Estimated
  private-repo cost ≈ 10–15 billed minutes per PR run across workflows; free once public. Third-party
  verification steps: `docs/VERIFY.md`.
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-020 — Stdlib JWS/JWKS verification for GitHub Actions OIDC
- **Context**: ADR-016 left "JWT library vs stdlib" open. The ingestion API must verify GitHub Actions
  OIDC tokens; JWT libraries have a history of alg-confusion bugs and add dependencies.
- **Decision**: `internal/auth/ghoidc`, standard library only: RS256 allow-list (none/HS*/ES* rejected
  with typed errors), `kid` required, RSA ≥ 2048, JWKS cache with TTL, rate-limited refresh on unknown
  `kid`, last-good key set on fetch failure, no redirects; claims checked: `iss`, `aud` (GitHub's
  default and Azure's `api://AzureADTokenExchange` audiences refused), `exp/nbf/iat` with skew,
  `repository_id` + `repository_owner_id` allow-lists as `int64` (never names), optional ref/environment
  allow-lists; `Claims.CheckCommit` binds evidence to the token's `sha`; `sub` parsed for audit only
  (handles the immutable ID-based format). Middleware: 401 + `WWW-Authenticate`, 403, 503 + `Retry-After`.
- **Consequences**: ~530 lines of security-critical code (≈1,500 with config/middleware), 97.8 %
  coverage, 4 fuzz targets. No replay cache (tokens live minutes; ingestion is idempotent). Not yet
  exercised against a real GitHub token (blocked in the sandbox) — first real use is the CI upload job.
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-021 — PostgreSQL store with pgx v5
- **Context**: ADR-007 chose PostgreSQL; a driver is unavoidable.
- **Decision**: `github.com/jackc/pgx/v5` v5.11.0 (MIT; 6 modules linked into the binary, others
  test-only, MIT/BSD-3). Embedded SQL migrations with an in-house migrator (advisory lock, one
  transaction per migration, checksums verified, refuses a DB newer than the binary). `evidence` and
  `audit_log` are append-only via triggers (SQLSTATE AF001 → `ErrImmutable`). `IngestDocument` runs in
  one transaction, serialized per project, retried on deadlock; fixed-marking is scoped per tool; VEX
  scoped per project. **Deviation from ARCHITECTURE.md §4**: artifact digests are unique **per project**,
  not globally, so one project can never attach evidence to another's artifact.
- **Consequences**: Triggers do not stop a table owner/superuser: Phase 4 must run the app with a
  dedicated role holding only SELECT/INSERT on append-only tables (SECURITY_MODEL.md). CI runs the
  integration tests against a digest-pinned `postgres:18.4-alpine` service (CI-only placeholder password).
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-022 — Evidence normalization rules
- **Decision**: `internal/evidence/normalize` parses CycloneDX 1.4–1.7, SPDX 2.2/2.3, SARIF 2.1.0, Grype,
  govulncheck JSON and OpenVEX 0.2.0 (stdlib, pre-decode JSON guard: depth, duplicate/case-colliding
  keys, trailing data; 64 MiB / 100k items / depth 64 limits; output capped). **Reachability**: in a
  symbol-level govulncheck scan, package- and module-level findings are `imported` (0.3); `unknown`
  (0.7) only when the scan itself ran at package/module level — so a merely-required module never
  outranks an imported-but-uncalled package. PURLs are stored as tools wrote them and compared with
  `CanonicalPURL`. Artifact digests come from CI metadata (Syft's image SBOM has none). OpenVEX
  subcomponents are flattened into products; VEX must be scoped to the artifact it was ingested for.
- **Consequences**: govulncheck findings have no CVSS; severity arrives by merging with Grype through the
  shared fingerprint. Suggested model additions (VEX aliases/subcomponents, Finding.CWEs,
  Document.Warnings) deferred.
- **Status**: Accepted — **Date**: 2026-10-26

### ADR-023 — Risk engine edge cases
- **Decision (owner chose "trust the VEX", 2026-10-26)**: a valid VEX `not_affected`/`fixed` statement sets the
  score to 0 (P3) **even when the KEV + called + internet override would apply**; if it contradicts
  `called` reachability it is flagged `vex-conflict` for review. `not_affected` counts only with a
  justification or impact statement and must name the vulnerability ID or an alias. Unknown exposure
  scores as internet (1.0) but never triggers the override. Tier is computed on the score rounded to 2
  decimals. Feeds fail closed: an empty/inconsistent KEV catalogue or EPSS CSV is rejected and the
  previous snapshot kept.
- **Consequences**: ADR-012's "always P1" rule is read as "unless a justified VEX says not affected".
  Alternative if the owner prefers: keep P1 and only annotate the VEX (one-line change in the engine).
- **Status**: Accepted — **Date**: 2026-10-26

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

Asked one by one; the owner chose each answer. Facts marked [V] come from read-only Azure Resource
Manager queries on 2026-10-26.

| # | Question | Owner's answer | Notes |
|---|---|---|---|
| Q1 | Repository visibility | **Public now** | Owner flips the setting; pre-flight scan clean (ADR-014) |
| Q2 | GitHub plan | **Pro** (Student Developer Pack) | Rulesets/environments available |
| Q3 | Signing | **Keyless cosign + `actions/attest` after the repo is public** | Recommended option |
| Q4 | Funding for Phase 4 | **Azure for Students** subscription | [V] current sub is a free trial (spending limit on) — ADR-018 |
| Q5 | Region | **France Central** | [V] no region policy on the trial sub; re-check on the Students sub |
| Q6 | CI identity | **User-assigned managed identity + OIDC** | Recommended option |
| Q7 | Budget | **$50/month** on the AegisFlow resource group | Alerts 50/80/100 % actual, 100 % forecast |
| Q8 | Custom domain | **No** — default `*.azurecontainerapps.io` | Recommended option |
| Q9 | Thesis language / defence date | **English**; defence date **not fixed yet** | Revisit the schedule when the date is known |
| Q10 | Dashboard users | **Only the owner** | Supervisor/jury via live demo |
| — | Licence | **Apache-2.0** | `LICENSE` added |
| — | Azure credentials in sessions | **Use them** (ADR-017) | Owner's explicit instruction |
