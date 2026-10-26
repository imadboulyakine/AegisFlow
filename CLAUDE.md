# CLAUDE.md — AegisFlow

Instructions for Claude Code sessions. The shared, tool-agnostic rules live in `AGENTS.md` and are
imported here — read them; they are binding.

@AGENTS.md

## Claude-specific working agreement

- **Start every session** by following AGENTS.md §2: read `docs/SESSION_HANDOFF.md`, then
  `docs/PROJECT_STATE.md`, `docs/ROADMAP.md`, `docs/DECISIONS.md`. Do not rely on any previous chat.
- **End every session** by rewriting `docs/SESSION_HANDOFF.md` and updating `docs/PROJECT_STATE.md`
  with the checks you actually ran (command + result). Commit them with the code.
- **Role**: act as the project's lead security/platform engineer. Be autonomous for local
  development (code, tests, builds, Docker, docs, branches, PRs). **Stop and ask** before anything
  billable or outward-facing beyond the repo: Azure deployments, enabling paid GitHub/Azure
  features, changing repository visibility or settings, publishing releases or images.
- **Subagents**: use them for independent, parallelisable work (environment audits, research,
  isolated implementation slices, reviews). Give each a disjoint set of files to own and a written
  brief; the lead session integrates, verifies and commits.
- **Verification before claiming success**: run the relevant `make` targets and report real output.
  When something cannot be run in the cloud container, say so and record it as a limitation.
- **Secrets**: never print environment variable values; when auditing, list names only.

## Cloud-session environment notes (verified 2026-10-26)

These were verified in a Claude Code cloud container; re-verify if a command fails.

- Host Go is 1.24.7; `GOTOOLCHAIN=auto` + the `toolchain go1.27.3` line downloads Go 1.27.3 via
  `proxy.golang.org` (works). Bun 1.4.4 and Node 22 are pre-installed.
- Outbound HTTPS goes through an egress proxy (CA bundle `/root/.ccr/ca-bundle.crt`, details in
  `/root/.ccr/README.md`). Some hosts are blocked (e.g. `go.dev` returned 403). See
  `docs/PROJECT_STATE.md` → "Environment capabilities" for the full tested matrix.
- No Azure CLI login and no Azure credentials exist in the container, by design. Bicep can be
  compiled/linted locally once installed, but nothing is deployed from agent sessions.
- GitHub access from sessions goes through the GitHub MCP tools (the `gh` CLI is not authenticated).
- Chromium + Playwright are pre-installed for headless smoke/E2E tests (`require('playwright')`).
