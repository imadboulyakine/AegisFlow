# AegisFlow — Session Handoff

Read this first. It is rewritten at the end of every session so the next one (human or agent) can
continue from the repository alone. Then read `PROJECT_STATE.md`, `ROADMAP.md`, `DECISIONS.md`.

Last session: 2026-10-26 — Phase 1 implemented (PR #2), Phase 2 core packages in progress —
branch `claude/serene-franklin-lipl1f`

## 1. What was done

- **Phase 0 merged** (PR #1). Owner answered Q1–Q10 personally (DECISIONS.md "Owner decisions"):
  repo **public now**, GitHub **Pro**, keyless signing once public, **Apache-2.0**, France Central,
  **Azure for Students** subscription for Phase 4 with a **$50/month** budget, UAMI + OIDC, default
  ACA URL, owner-only dashboard, English thesis, defence date not fixed. Owner also authorised agent
  sessions to use the `AZURE_*` service principal (ADR-017); read-only discovery done
  (`scripts/azure/discover.py`, facts in PROJECT_STATE §4.1).
- **Phase 1** (subagents in parallel, lead verified and committed): `code-security.yml`,
  `supply-chain.yml`, `github-security.yml`, `provenance.yml`, `mk/*.mk` fragments, experiments E1/E4/E3,
  `SECURITY.md`, `LICENSE`, `docs/VERIFY.md`, ADR-018/019. All local gates green (PROJECT_STATE §3.1).
- **Phase 2 core packages** started in isolated git worktrees (`.claude/worktrees/agent-*`, local
  branches `worktree-agent-*`, not pushed), all sharing `internal/evidence/model.go` (identical bytes):
  - `internal/auth/ghoidc` — stdlib GitHub OIDC JWS/JWKS verifier + middleware — **done** (97.8 %).
  - `internal/intel` + `internal/risk` — KEV/EPSS feeds + ADR-012 engine — **done** (97 % / 99.5 %).
  - `internal/evidence/normalize` — CycloneDX/SPDX/SARIF/Grype/govulncheck/OpenVEX — in progress.
  - `internal/store` — PostgreSQL (pgx v5), migrations, append-only triggers — in progress.
  Reports: the subagent reports were in the session scratchpad; the essentials are below.

## 2. In progress / not verified yet

- PR #2 (Phase 1) CI run on GitHub; public-only jobs need the visibility switch.
- If the worktrees are gone (new container), Phase 2 packages must be rebuilt from the briefs —
  check `git branch -a` and `.claude/worktrees/` first.

## 3. Owner actions

1. **Make the repository public** (Settings → General → Change visibility), then enable private
   vulnerability reporting and secret scanning push protection (Settings → Security).
2. Merge PR #2 when green; then add a ruleset on `main` requiring the CI checks, blocking force-push.
3. Before Phase 4: create the Azure for Students subscription (the ADR-017 SP is on the trial sub).

## 4. Next tasks (in order)

1. Drive PR #2 to green and merged.
2. Restart the branch from `main`; merge the four `worktree-agent-*` branches; resolve go.mod (pgx);
   renumber the auth ADR (agent proposed "ADR-017", taken) → ADR-020 (stdlib JWS/JWKS), add ADR-021
   (pgx v5) and ADR-022 (risk engine decisions: **VEX not_affected/fixed beats the KEV override**,
   flagged `vex-conflict` when reachability says called; unknown exposure = 1.0 but never triggers the
   override; feeds fail closed).
3. Integrate: `AEGISFLOW_DATABASE_URL`/`AEGISFLOW_OIDC_*` config, `/api/v1/ingest` (OIDC middleware,
   `CheckCommit`, normalize → store → risk), `/api/v1/findings`, dashboard pages, CI upload job with a
   custom-audience OIDC token, Postgres service container in `ci.yml` for store integration tests.
4. E1 follow-up arm: custom gitleaks rules (DB URIs, split lines) measured as a separate arm.

## 5. How to verify the current state quickly

```bash
make lint test build     # all green
make code-security       # actionlint, zizmor, gitleaks, semgrep tests + scan (Docker needed for Semgrep)
make vuln GOVULNCHECK_FLAGS='-db file:///path/to/offline/govulndb'   # vuln.go.dev blocked in sandbox
make e1                  # secrets benchmark (seeded)
```

## 6. Gotchas

- Host Go is 1.24.7 — never downgrade `go.mod`; tools run with the go.mod toolchain via `make`.
- Blocked here: vuln.go.dev, OSV API, Grype DB, NVD, EPSS, cisa.gov, Sigstore, GitHub OIDC tokens,
  semgrep.dev, prices.azure.com. Use offline DBs/fixtures; live checks run in CI.
- Docker Hub may 429 → `mirror.gcr.io`; `dockerd` may need restarting after a container pause.
- Tool versions/digests in `mk/*.mk` are bumped manually (Dependabot cannot see them).
- Parallel agents running `make test` at once race on `coverage.out`.
- Azure: use the SP only per ADR-017 (never print the secret; writes only after Phase 4 approval).
