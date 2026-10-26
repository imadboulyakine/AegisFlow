# AegisFlow — Project State

Authoritative record of what exists, what was verified (command + result) and what is blocked.
Update it in every PR that changes behaviour. Tested facts are marked **TESTED**; everything else
is an **ASSUMPTION** or **PLANNED**.

Last updated: 2026-10-26 — Phase 0 (bootstrap) — branch `claude/serene-franklin-lipl1f`

## 1. Phase status

| Phase | Status | Notes |
|---|---|---|
| 0 Bootstrap | **Done — CI green on GitHub**, PR #1 awaiting owner merge | See §3, §4 |
| 1 Secure CI foundation | Not started | Blocked on owner answers Q1–Q3 (DECISIONS.md) for signing mode |
| 2–6 | Not started | Phase 4 is the first billable phase (owner approval required) |

Nothing has been created in Azure. Read-only Azure discovery was run on 2026-10-26 with the
owner-authorised service principal (ADR-017; `scripts/azure/discover.py`). No secrets are committed.

## 2. Implementation status (Phase 0)

| Component | Status | Where |
|---|---|---|
| Go module, Go 1.27.3 toolchain pin, zero third-party deps | Done | `go.mod` (ADR-001/002) |
| Single binary: serve, `-healthcheck`, `-version`; graceful shutdown | Done | `cmd/aegisflow` |
| Env config `AEGISFLOW_ADDR`, `_LOG_LEVEL`, `_SHUTDOWN_TIMEOUT` (validated) | Done | `internal/config` |
| `/healthz`, `/readyz` (503 while draining), `/api/v1/version`, problem+json errors | Done | `internal/server` (ADR-004) |
| Middleware: request ID, access log, panic recovery, security headers/CSP, cross-origin protection, 1 MiB body limit | Done | `internal/server/middleware.go` |
| Embedded SPA with hashed-asset caching, ETags, deep-link fallback, "not built" fallback page | Done | `internal/server/spa.go`, `internal/webui` |
| React 19 + TS 7 dashboard shell (status card + 4 "Planned" module cards, tiny router) | Done | `web/src` (ADR-003) |
| Bun native build with CSP guard (fails on inline script/style, `data:` CSS) | Done | `web/scripts/build.ts` |
| Distroless Debian 13 nonroot image, digest-pinned bases, self-probing HEALTHCHECK | Done | `Dockerfile` (ADR-005) |
| Local stack (app hardened; Postgres behind `db` profile for Phase 2) | Done | `compose.yaml` |
| CI: go / web / container jobs, SHA-pinned actions, read-only token | Done, **green on GitHub** (run 40359255309) | `.github/workflows/ci.yml` (ADR-006) |
| Dependabot (gomod, bun, actions, docker, docker-compose; 3-day cooldown) | Done, **unverified on GitHub** | `.github/dependabot.yml` |
| CODEOWNERS, PR template | Done | `.github/` |
| Project memory docs | Done | `CLAUDE.md`, `AGENTS.md`, `docs/*` |
| Bicep / `infra/` | Not started (Phase 4) | — |

## 3. Checks executed in Phase 0 (2026-10-26, cloud container)

All run by the lead session after integrating subagent work, unless noted.

| Check | Command | Result |
|---|---|---|
| Lint | `make lint` | **TESTED PASS** — gofmt ok, go vet clean, golangci-lint v2.15.0 *0 issues*, `tsc --noEmit` clean |
| Tests | `make test` | **TESTED PASS** — bun: 56 pass / 0 fail; Go `-race`: all packages ok; coverage total **96.0 %** (server 97.2 %, config 97.8 %, version 100 %, cmd 90.0 %, webui 75.0 %) |
| Build | `make build` | **TESTED PASS** — JS bundle 214 KiB (React production build), `bin/aegisflow` 7.6 MB static, go1.27.3 |
| Workflow lint | `make actionlint` (v1.7.12) | **TESTED PASS** — 0 findings (bootstrap agent also ran it with shellcheck: 0) |
| Binary smoke test | run `bin/aegisflow`, curl routes | **TESTED PASS** — 200 JSON on probes/version; `/api/nope` 404 `application/problem+json`; `/vulnerabilities` → index.html; CSP/nosniff/Referrer-Policy/X-Request-ID present; cross-site POST → 403; SIGTERM → "shutdown complete" |
| Browser smoke test | Playwright (pre-installed Chromium) | **TESTED PASS** (bootstrap agent) — dashboard "Operational", 0 console errors, injected inline script blocked by CSP |
| Container | sandbox recipe (§6.3) build + `docker run --read-only --cap-drop ALL --security-opt no-new-privileges` | **TESTED PASS** — 18 MB image, user `65532:65532`, health `healthy`, `/api/v1/version` returns build args, `docker stop` exit 0 |
| Compose | `docker compose config` (with/without `--profile db`), `up` app | **TESTED PASS** (bootstrap agent) |
| govulncheck | `make vuln` | **BLOCKED here** (vuln.go.dev 403). Offline run against a DB built from the OSV export: *No vulnerabilities found* (bootstrap agent). Runs online in CI. |
| Go hygiene | `go mod tidy -diff`, `go fix -diff ./...` | **TESTED PASS** (bootstrap agent) |
| Secrets in diff | grep of staged diff for key/secret/token patterns | **TESTED PASS** — only synthetic test fixtures |
| CI on GitHub | PR #1, run 40359255309, head `75dc366` | **PASS** — Go 3m24s (incl. golangci-lint build, live govulncheck), Web 19s, Container build + smoke 1m07s; ≈ 4m35s wall-clock (first data point for E4) |

## 4. Environment capabilities (Claude Code cloud container, audited 2026-10-26)

Full audit with commands and evidence was produced in-session; key results:

| Capability | Status | Notes |
|---|---|---|
| Go 1.27.3 via `GOTOOLCHAIN` (host 1.24.7) | TESTED OK | build, `-race`, vet, arm64 cross-compile. Host `gofmt` is 1.24.7 — prefer `go fmt`/`make go-fmt-check` |
| golangci-lint | host 2.5.0 FAILS on Go 1.27; v2.15.0 via `make golangci-lint` OK | |
| Bun 1.4.4, React 19.3.1, TypeScript 7.0.2 | TESTED OK | text `bun.lock`; `bun build` needs production `NODE_ENV` (handled in `build.ts`) |
| Docker 29.9.2, buildx, compose | TESTED OK | daemon may need starting; Docker Hub anonymous pulls hit 429 → use `mirror.gcr.io`; ghcr.io blobs blocked |
| TLS inside containers | CONSTRAINT | egress proxy re-signs TLS; package installs inside `docker build` need the proxy CA (§6.3) |
| arm64 emulation (QEMU) | NOT AVAILABLE | multi-arch only via cross-compile or CI |
| Azure CLI | NOT INSTALLED, installable | `pip install azure-cli` (2.91.0) in a venv works; **no login by design** |
| Bicep | installable | 0.48.1 binary from GitHub releases builds/lints; `az bicep install` blocked |
| Azure authentication | **TESTED OK (read-only)** | owner-authorised SP (ADR-017); token + ARM GETs work; see §4.1 |
| GitHub | MCP tools work for `imadboulyakine/AegisFlow` only (admin); `gh` CLI unauthenticated; `git ls-remote`/release downloads of public repos OK | |
| Security tools | gitleaks, syft, trivy (DB via mirror.gcr.io), gosec, staticcheck, semgrep (local rules) OK; osv-scanner/govulncheck offline only; grype DB blocked; cosign key-based only (keyless/Sigstore blocked) | installable to scratch dirs, checksums verified |
| Playwright | TESTED OK with `@playwright/test@1.63.0` (matches `/opt/pw-browsers` Chromium) | 1.64.x cannot find a browser; `playwright install` blocked |
| Postgres 18 (Docker), Redis 7.0.15, `modernc.org/sqlite` fetch | TESTED OK | |
| OWASP ZAP baseline | TESTED OK via `mirror.gcr.io/zaproxy/zap-stable` | |
| Blocked egress (proxy 403) | — | vuln.go.dev, api.osv.dev, Grype DB, NVD, EPSS (api.first.org), cisa.gov (KEV available via `raw.githubusercontent.com/cisagov/kev-data`), prices.azure.com, Sigstore, `token.actions.githubusercontent.com`, semgrep.dev, Playwright CDN, go.dev, learn.microsoft.com, Debian/Alpine package mirrors |
| Resources | 4 vCPU, 15 GiB RAM, ~20–30 GB free disk (shared with Docker) | |

**Implication:** local sessions can build, test, lint, scan offline and run DAST/E2E; anything that
needs live vulnerability feeds, Sigstore keyless, GitHub OIDC or Azure runs **in CI only**. Design
feed clients and the provenance verifier with recorded fixtures so they are testable offline.

### 4.1 Azure subscription facts (read-only, 2026-10-26)

| Fact | Value |
|---|---|
| Offer | Azure free account (`quotaId FreeTrial_2014-09-01`), spending limit **on**, state Enabled |
| SP role | Contributor @ subscription (cannot create role assignments) |
| Policies | ASC Default + Microsoft mandatory-MFA policies for user write/delete; **no allowed-locations policy** |
| Region | francecentral offers `Microsoft.App/managedEnvironments` → ADR-013 Accepted |
| Providers | Microsoft.App, ContainerRegistry, KeyVault, OperationalInsights, Insights, ManagedIdentity, DBforPostgreSQL **NotRegistered** (register in Phase 4) |
| Existing resources | 6 RGs / 26 resources, none AegisFlow (owner's labs; VMs deallocated) |
| Spend | Sept 2026 $0.00; Oct 2026 MTD $37.49 (lab RGs) |
| Budgets | none; Defender: Foundational CSPM (free) + "Discovery" on Standard tier |

## 5. Blockers and risks

| ID | Blocker / risk | Impact | Owner action |
|---|---|---|---|
| B1 | Azure SP in the session environment has **Contributor on the whole subscription** | **Accepted risk** by the owner (ADR-017); sessions may use it read-only, writes only after Phase 4 approval and only in AegisFlow RGs | Recommended before Phase 4: scope SP to the AegisFlow RG, rotate the secret |
| B6 | Subscription is a **free trial** (credit valid 30 days from sign-up) and the owner's other labs bill ~$40+/month while idle (NAT gateway, Standard public IPs) | Phase 4 likely needs a pay-as-you-go upgrade | Owner: check credit/expiry in the portal; clean up idle lab networking |
| B2 | Repository is private: no artifact attestations, CodeQL, dependency review, push protection; Actions minutes capped | Phase 1 tooling choice | Answer Q1–Q3 (ADR-014) |
| B3 | Azure retail prices could not be pulled (prices.azure.com blocked) | AZURE_COSTS.md values are estimates | Re-verify before Phase 4 (queries listed in AZURE_COSTS.md §1) |
| B4 | Branch protection / rulesets not configured on `main` | Direct pushes possible | Owner: enable after Phase 0 merge (plan-dependent) |
| B5 | Dependabot config (`cooldown`, `bun`, `docker-compose`) not yet validated on GitHub | Update PRs may not appear | Check Insights → Dependency graph → Dependabot after merge |

## 6. How to work in the cloud container

### 6.1 Everyday commands
`make lint test build` (first golangci-lint run compiles it, ~1 min). `make run` serves on :8080.

### 6.2 Docker daemon
If `docker info` fails, start `dockerd` in the background. If Docker Hub returns 429, configure
`/etc/docker/daemon.json` with `{"registry-mirrors":["https://mirror.gcr.io"]}` and restart dockerd
(host-only change; nothing in the repo depends on it).

### 6.3 Container build behind the TLS-intercepting proxy (sandbox only)
The repo `Dockerfile` stays clean. In the cloud container, generate a throwaway variant that mounts
the proxy CA for `bun install`, and build with it:

```bash
S="$(mktemp -d)"
sed 's#^RUN bun install --frozen-lockfile --ignore-scripts$#RUN --mount=type=secret,id=sandboxca,target=/run/sandbox-ca.crt NODE_EXTRA_CA_CERTS=/run/sandbox-ca.crt bun install --frozen-lockfile --ignore-scripts#' \
  Dockerfile > "$S/Dockerfile.sandbox"
docker build --secret id=sandboxca,src=/root/.ccr/ca-bundle.crt -f "$S/Dockerfile.sandbox" -t aegisflow:dev .
```
When Go dependencies are added (Phase 2), `go mod download` inside the build will need the same CA
(`SSL_CERT_FILE`). In GitHub Actions the plain Dockerfile works.

### 6.4 govulncheck offline
`vuln.go.dev` is blocked here. Build a local DB from
`https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip` (reachable) and run
`go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -db file://<dir> ./...`. CI uses the live DB.

## 7. Known limitations / TODO (carried into Phase 1)

- No gzip/brotli precompression of embedded assets; no `require-trusted-types-for` in CSP yet.
- actionlint and zizmor are local-only (`make actionlint`); add to CI in Phase 1.
- Multi-arch image not built in CI (Dockerfile already cross-compiles).
- `bun test` will also pick up Playwright `*.spec.ts` once E2E is added — scope unit tests to `src`
  or set `[test] root` in `bunfig.toml` at that time; pin `@playwright/test@1.63.0` locally.
