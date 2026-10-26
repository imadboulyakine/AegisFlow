# AGENTS.md — shared instructions for coding agents

This file is the canonical, tool-agnostic instruction set for any coding agent (Claude Code, Codex,
Copilot, Cursor, …) working on AegisFlow. `CLAUDE.md` imports it. Keep it short, current and true.

## 1. What this project is

AegisFlow is a personal PFE (final-year engineering project): a cloud-native **DevSecOps and software
supply-chain security platform**. A single Go binary (API + embedded Bun-built React SPA) ingests CI
evidence (SBOMs, scan results, attestations, pipeline metadata), correlates and risk-scores
vulnerabilities, enforces policy, verifies provenance and flags explainable anomalies. CI/CD runs on
GitHub Actions; Azure infrastructure is declared in Bicep.

Priorities, in order: (1) secure delivery & supply-chain integrity, (2) risk-aware vulnerability
management, (3) explainable anomaly detection, (4) Azure cloud-security controls.

## 2. Session protocol (mandatory)

GitHub is the memory. Chat history is not. Every session must be resumable from the repo alone.

**At session start, read in this order:**
1. `docs/SESSION_HANDOFF.md` — what the last session did, what is next, open blockers.
2. `docs/PROJECT_STATE.md` — current phase, implementation status, verified checks.
3. `docs/ROADMAP.md` — the current phase's deliverables and exit criteria.
4. `docs/DECISIONS.md` — accepted ADRs (do not contradict an *Accepted* ADR without a new ADR).
5. `docs/ARCHITECTURE.md` / `docs/SECURITY_MODEL.md` / `docs/AZURE_COSTS.md` as relevant to the task.

**Before ending a session (or opening a PR), update:**
- `docs/PROJECT_STATE.md` — status tables, checks actually run (with result), known issues.
- `docs/SESSION_HANDOFF.md` — rewrite it: done / in progress / next tasks / blockers / how to verify.
- `docs/DECISIONS.md` — append an ADR for any significant choice (new dependency, new Azure resource,
  security trade-off, deviation from architecture).
- `docs/ROADMAP.md` — tick deliverables; move scope only with a recorded reason.

Distinguish **tested facts** from **assumptions** in every doc you touch.

## 3. Hard guardrails (never violate)

- **No billable cloud action without explicit owner approval** recorded in `docs/DECISIONS.md`.
  This includes `az deployment *`, `az group create`, creating any Azure resource, enabling Defender
  plans, buying anything. Phase 4 is the first billable phase.
- **No credentials in agent sessions.** Do not run `az login`, do not ask for or handle secrets,
  tokens, client secrets, connection strings or SAS tokens. CI authenticates to Azure via **OIDC
  workload identity federation only** (no long-lived secrets).
- **Never commit secrets** — not even "test" ones that look real. Local dev defaults must be
  obviously local (e.g. `aegisflow-local-dev-only`, loopback-bound, behind the compose `db` profile).
- **Least privilege everywhere**: workflow `permissions:` default `contents: read`, widened per job
  only when required; Azure RBAC scoped to resource group or resource, never subscription-wide
  `Owner`/`Contributor` for automation.
- **Pin every GitHub Action to a full 40-char commit SHA** with a `# vX.Y.Z` comment. Pin container
  base images by digest. Pin JS dependencies exactly and commit `web/bun.lock`.
- **Never skip, disable or weaken a test, linter or security check** to get CI green. Fix the cause.
- **No new third-party dependency without justification** (what it replaces, maintenance, licence,
  transitive weight). Record significant ones as an ADR. Prefer the Go standard library.
- **Never force-push `main` or rewrite shared history.** Work on a branch, open a PR.

## 4. Stack and layout

| Area | Choice |
| --- | --- |
| Backend | Go 1.27 (`go.mod`: `go 1.27.0`, `toolchain go1.27.3`), stdlib `net/http`, `log/slog` |
| Frontend | React 19 + TypeScript (strict), built with **Bun's native bundler** (no Vite) |
| Packaging | One binary `aegisflow`; SPA embedded via `//go:embed all:dist` in `internal/webui` |
| Container | Multi-stage Dockerfile → distroless static, nonroot, digest-pinned bases |
| CI/CD | GitHub Actions (`.github/workflows/`), Dependabot |
| IaC (later) | Bicep under `infra/`, deployed by CI via OIDC (Phase 4+, needs approval) |
| Data (later) | PostgreSQL (Phase 2+), local via `compose.yaml` profile `db` |

```
cmd/aegisflow/        entrypoint (serve + healthcheck mode)
internal/config/      env-only configuration (AEGISFLOW_*)
internal/server/      router, middleware, handlers, tests
internal/version/     build metadata (ldflags)
internal/webui/       go:embed of the built SPA (dist/ is generated; only .gitkeep committed)
web/                  Bun + React + TS app (src/, scripts/build.ts, bun.lock)
docs/                 permanent project memory (see §2)
.github/              CI workflow, Dependabot, CODEOWNERS, PR template
```

## 5. Commands

Run `make help` for the authoritative list. Core targets:

| Task | Command |
| --- | --- |
| Install frontend deps | `make web-install` |
| All tests (Go + web) | `make test` |
| Lint / format checks | `make lint` |
| Vulnerability scan (Go) | `make vuln` |
| Build SPA + binary → `bin/aegisflow` | `make build` |
| Run locally (http://localhost:8080) | `make run` |
| Container build / run | `make docker-build` / `make docker-run` |

The host may have an older Go; `go.mod`'s `toolchain` line makes `GOTOOLCHAIN=auto` download the
pinned toolchain from `proxy.golang.org`. Do not downgrade `go.mod` to match the host.

## 6. Engineering conventions

**Go**
- `gofmt`-clean, `go vet`-clean. Packages under `internal/` unless intentionally public.
- Wrap errors with context (`fmt.Errorf("load config: %w", err)`); no `panic` outside `main` init.
- Pass `context.Context` as the first parameter for I/O; respect cancellation.
- Structured logging with `log/slog` only; never log secrets, tokens or full request bodies.
- Config from environment variables (`AEGISFLOW_*`) validated at startup; fail fast.
- Table-driven tests with `httptest`; keep `go test -race ./...` green. New handlers need tests.
- HTTP: every server has timeouts; JSON errors under `/api/` use a consistent problem shape.

**TypeScript / React**
- `strict` TypeScript, no `any` without a comment explaining why. Function components + hooks.
- The app must run under the strict CSP set by the Go server: **no inline `<script>`, no
  `eval`, no CDN assets**. Styles live in CSS files.
- Talk to the backend only through the typed API client in `web/src/`; unit-test with `bun test`.

**Commits & PRs**
- Conventional Commits (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`, `refactor:`, `test:`, `sec:`).
- Small, reviewable PRs; fill in `.github/pull_request_template.md` (security impact + tests run).
- CI must be green. Docs updated in the same PR as the behaviour they describe.

## 7. Definition of done

A change is done when: code + tests are in, `make lint test build` pass locally (state which checks
you could not run and why), CI is green, security impact is described, and `docs/PROJECT_STATE.md`
and `docs/SESSION_HANDOFF.md` reflect the new state.
