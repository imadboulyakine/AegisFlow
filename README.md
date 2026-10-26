# AegisFlow

AegisFlow is a cloud-native DevSecOps and software supply-chain security platform, built as a
final-year engineering project (PFE). It is aiming for a secure CI/CD pipeline with SAST, SCA,
DAST and end-to-end testing, SBOMs, signed artifacts with build provenance, policy gates
before deployment, risk-aware vulnerability correlation, explainable anomaly detection, and
progressive delivery on Azure. The service is a single Go binary (standard library only) that
serves a JSON API and an embedded React dashboard bundled with Bun.

**Status: Phase 1 — secure CI foundation.** The hardened application skeleton is in place and
CI now scans every change (secrets, SAST, workflow security, Go and npm vulnerabilities, SBOMs,
image scan) and signs `main` builds with SLSA provenance. The platform features (evidence
ingestion, risk scoring, policy gate) arrive in Phase 2–3; see
[docs/ROADMAP.md](docs/ROADMAP.md) and [docs/PROJECT_STATE.md](docs/PROJECT_STATE.md).

## Quickstart

### Prerequisites

| Tool | Version | Notes |
| --- | --- | --- |
| Go | 1.27.3 | `go.mod` pins `toolchain go1.27.3`; an older local Go downloads it automatically (`GOTOOLCHAIN=auto`). |
| Bun | 1.4.4 | Frontend install, tests and bundling (`web/package.json` → `packageManager`). |
| Docker | recent, with BuildKit | Optional: container build and `compose.yaml`. |
| GNU Make | any | Task runner (`make help`). |

### Common tasks

```sh
make help          # list all targets
make build         # bundle the web UI, embed it, build bin/aegisflow
make run           # build and run on http://127.0.0.1:8080
make test          # bun test + go test -race with coverage
make lint          # gofmt check, go vet, golangci-lint, tsc --noEmit
make vuln          # govulncheck (pinned version)
make docker-build  # multi-stage image: aegisflow:dev
make docker-run    # run the image read-only, without capabilities, as non-root
make clean         # remove build outputs
```

Frontend development with hot reload, against a running Go server:

```sh
make run                 # terminal 1: API on :8080
cd web && bun run dev    # terminal 2: dashboard on http://127.0.0.1:3000, /api proxied to :8080
```

With Docker Compose (PostgreSQL is opt-in and only used from Phase 1):

```sh
docker compose up --build
docker compose --profile db up --build
```

### Configuration

All configuration comes from environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `AEGISFLOW_ADDR` | `:8080` | Listen address (`host:port` or `:port`). |
| `AEGISFLOW_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` (JSON logs on stdout). |
| `AEGISFLOW_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown budget after SIGINT/SIGTERM (max `5m`). |

The binary also accepts `-healthcheck`, which probes its own `/healthz` and is used by the image's
`HEALTHCHECK` because the distroless runtime has no shell or curl, and `-version`, which prints the
build metadata.

### HTTP endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Liveness: the process is serving HTTP. |
| `GET /readyz` | Readiness: `503` while starting or draining for shutdown. |
| `GET /api/v1/version` | Build metadata (`version`, `commit`, `buildDate`, `goVersion`). |
| `/api/...` (unknown) | RFC 9457 `application/problem+json` 404/405 responses. |
| everything else | Embedded single-page app; client routes fall back to `index.html`. |

Every response carries a strict Content-Security-Policy and related security headers, as well as an
`X-Request-ID`. HSTS is left to the TLS-terminating ingress.

## Repository layout

```text
cmd/aegisflow/        entry point: config, signals, graceful shutdown, -healthcheck
internal/config/      environment configuration and validation
internal/server/      routes, handlers, middleware, embedded SPA serving
internal/version/     build metadata (set with -ldflags, VCS fallback)
internal/webui/       go:embed of the built dashboard (dist/ is generated)
web/                  React 19 + TypeScript dashboard, Bun bundler, bun test
.github/              CI workflow, Dependabot, CODEOWNERS, PR template
docs/                 architecture, decisions, roadmap, security model, costs, handoff
Dockerfile            Bun, then Go, then a distroless static nonroot image (digest-pinned)
compose.yaml          local stack (app plus optional PostgreSQL profile)
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Project state](docs/PROJECT_STATE.md)
- [Roadmap](docs/ROADMAP.md)
- [Architecture decisions](docs/DECISIONS.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Azure cost plan](docs/AZURE_COSTS.md)
- [Session handoff](docs/SESSION_HANDOFF.md)
- [Verifying a build (signatures, provenance, reproducible build)](docs/VERIFY.md)
- [Security policy](SECURITY.md) · [Licence: Apache-2.0](LICENSE)
- Contributor and agent guidelines: [CLAUDE.md](CLAUDE.md), [AGENTS.md](AGENTS.md)
