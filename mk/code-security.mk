## ---------- Code security: secrets, SAST, workflow security ----------
#
# Included by the top-level Makefile. .github/workflows/code-security.yml calls these targets, so
# local runs and CI use the same pinned tools, flags and gates (ADR-006, ADR-015). Each target
# writes machine-readable reports (SARIF, plus JSON where useful) and a Markdown summary to
# $(CS_REPORTS_DIR), inside the gitignored bin/ directory. Requires: go, docker, python3, jq.

CS_REPORTS_DIR ?= bin/reports/code-security

# gitleaks: built from source with the project toolchain (`go run`, checksums verified against
# sum.golang.org). Upstream moved to github.com/gitleaks/gitleaks; the Go module path is unchanged.
GITLEAKS_VERSION ?= v8.30.1
GITLEAKS_CONFIG  := .gitleaks.toml
# Limit the scan to a commit range, e.g. GITLEAKS_LOG_OPTS=origin/main..HEAD (CI sets base..head on
# pull requests). Empty = full history of every ref (`git log --all`).
GITLEAKS_LOG_OPTS ?=
export GITLEAKS_LOG_OPTS

# Semgrep OSS CLI: official multi-arch image, pinned by index digest (the tag is informational).
SEMGREP_IMAGE ?= semgrep/semgrep:1.182.0@sha256:4a34048c04fef049f71665047f074cffb00cc3d89482f965a5cd151d589237af
SEMGREP_RULES := .semgrep
# Registry packs are added only when SEMGREP_USE_REGISTRY=1 (CI). semgrep.dev is unreachable from
# the cloud dev container, so local runs use the repo rules only. Secrets are gitleaks' job (no
# p/secrets); gosec already runs inside golangci-lint (no p/gosec).
SEMGREP_REGISTRY_PACKS := p/golang p/typescript p/react p/dockerfile p/github-actions
SEMGREP_USE_REGISTRY ?= 0
# Rule test fixtures live in .semgrep/; .claude/worktrees holds local agent checkouts.
SEMGREP_EXCLUDES := .semgrep .claude/worktrees
# Findings at these severities fail `make sast` (legacy ERROR, new-style CRITICAL/HIGH);
# WARNING/MEDIUM and INFO/LOW findings are reported in the summary only.
SEMGREP_BLOCKING := ["ERROR","CRITICAL","HIGH"]

# zizmor: the version and the PyPI hashes of every wheel live in the requirements file (single
# source of truth, installed with --require-hashes into a private venv outside the repo).
ZIZMOR_REQUIREMENTS := .github/requirements/zizmor.txt
ZIZMOR_VERSION := $(shell sed -n 's/^zizmor==\([^ ]*\).*/\1/p' $(ZIZMOR_REQUIREMENTS))
ZIZMOR_CONFIG := .github/zizmor.yml
PYTHON ?= python3
ZIZMOR_VENV ?= $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/aegisflow/zizmor-$(ZIZMOR_VERSION)
ZIZMOR := $(ZIZMOR_VENV)/bin/zizmor
# Offline by default (no token in dev sessions). CI sets CS_ZIZMOR_OFFLINE=0 and GH_TOKEN so the
# online audits (impostor commits, ref/version mismatch, known-vulnerable actions) also run.
CS_ZIZMOR_OFFLINE ?= 1
# Gate: findings at or above BOTH thresholds fail; everything is still in the SARIF report.
ZIZMOR_MIN_SEVERITY   ?= medium
ZIZMOR_MIN_CONFIDENCE ?= medium
ZIZMOR_FLAGS = --config $(ZIZMOR_CONFIG) --no-progress $(if $(filter 1,$(CS_ZIZMOR_OFFLINE)),--offline)

# Hardened, throwaway Semgrep container: read-only root FS, no capabilities, caller's uid (so
# reports are not root-owned and git accepts the bind-mounted checkout), source mounted read-only.
SEMGREP_RUN = $(DOCKER) run --rm --read-only --tmpfs /tmp --cap-drop ALL \
	--security-opt no-new-privileges:true --user "$$(id -u):$$(id -g)" \
	--env HOME=/tmp --env SEMGREP_SEND_METRICS=off

.PHONY: code-security
code-security: actionlint zizmor secrets sast-test sast ## Run all code-security checks (actionlint, zizmor, gitleaks, semgrep)

.PHONY: secrets
secrets: ## Scan git history for secrets (gitleaks; GITLEAKS_LOG_OPTS=a..b limits the range)
	@mkdir -p $(CS_REPORTS_DIR) && rm -f $(CS_REPORTS_DIR)/gitleaks.sarif $(CS_REPORTS_DIR)/gitleaks-summary.md
	@scope="$${GITLEAKS_LOG_OPTS:-full history, all refs}"; echo "gitleaks $(GITLEAKS_VERSION): scanning $$scope"; \
	status=0; \
	$(GO_TOOL) run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION) git \
		--config $(GITLEAKS_CONFIG) --ignore-gitleaks-allow --redact --no-banner --exit-code 1 \
		--report-format sarif --report-path $(CS_REPORTS_DIR)/gitleaks.sarif \
		$${GITLEAKS_LOG_OPTS:+"--log-opts=$$GITLEAKS_LOG_OPTS"} . || status=$$?; \
	sarif=$(CS_REPORTS_DIR)/gitleaks.sarif; \
	if [[ -s "$$sarif" ]]; then n=$$(jq '[.runs[].results[]] | length' "$$sarif"); else n="n/a (no report)"; fi; \
	{ \
		echo "### Secrets — gitleaks $(GITLEAKS_VERSION)"; echo; \
		echo "- Scope: \`$$scope\`"; \
		echo "- Findings (redacted): **$$n** — gate: any finding fails"; \
		if [[ -s "$$sarif" ]] && [[ "$$n" != 0 ]]; then \
			echo; echo "| Rule | Location | Commit |"; echo "|---|---|---|"; \
			jq -r '.runs[].results[] | "| \(.ruleId) | \(.locations[0].physicalLocation.artifactLocation.uri):\(.locations[0].physicalLocation.region.startLine) | \((.partialFingerprints.commitSha // "")[0:12]) |"' "$$sarif" | head -n 50; \
		fi; \
	} > $(CS_REPORTS_DIR)/gitleaks-summary.md; \
	cat $(CS_REPORTS_DIR)/gitleaks-summary.md; \
	exit $$status

.PHONY: sast
sast: ## Static analysis with Semgrep OSS (repo rules; + registry packs when SEMGREP_USE_REGISTRY=1)
	@mkdir -p $(CS_REPORTS_DIR) && rm -f $(CS_REPORTS_DIR)/semgrep.json $(CS_REPORTS_DIR)/semgrep.sarif $(CS_REPORTS_DIR)/semgrep-summary.md
	@status=0; \
	$(SEMGREP_RUN) $(if $(filter 1,$(SEMGREP_USE_REGISTRY)),,--network none) \
		--volume "$(CURDIR):/src:ro" --volume "$(abspath $(CS_REPORTS_DIR)):/reports" --workdir /src \
		$(SEMGREP_IMAGE) semgrep scan --metrics=off --disable-version-check \
		--config $(SEMGREP_RULES) $(if $(filter 1,$(SEMGREP_USE_REGISTRY)),$(addprefix --config ,$(SEMGREP_REGISTRY_PACKS))) \
		$(addprefix --exclude ,$(SEMGREP_EXCLUDES)) \
		--json-output=/reports/semgrep.json --sarif-output=/reports/semgrep.sarif || status=$$?; \
	json=$(CS_REPORTS_DIR)/semgrep.json; \
	if [[ ! -s "$$json" ]]; then echo "semgrep produced no report (exit $$status)"; exit $$(( status ? status : 1 )); fi; \
	blocking=$$(jq '[.results[] | select(.extra.severity as $$s | $(SEMGREP_BLOCKING) | index($$s))] | length' "$$json"); \
	{ \
		echo "### SAST — Semgrep $$(jq -r '.version // "?"' "$$json")"; echo; \
		echo "- Rules: \`$(SEMGREP_RULES)/\`$(if $(filter 1,$(SEMGREP_USE_REGISTRY)), + $(SEMGREP_REGISTRY_PACKS), (registry packs off))"; \
		echo "- Findings by severity: $$(jq -r '[.results[].extra.severity] | group_by(.) | map("\(.[0]): \(length)") | join(", ") | if . == "" then "none" else . end' "$$json")"; \
		echo "- Blocking (ERROR/CRITICAL/HIGH): **$$blocking** — engine errors/warnings: $$(jq '.errors | length' "$$json")"; \
		if [[ "$$(jq '.results | length' "$$json")" != 0 ]]; then \
			echo; echo "| Severity | Rule | Location |"; echo "|---|---|---|"; \
			jq -r '.results | sort_by(.extra.severity | if IN("ERROR","CRITICAL","HIGH") then 0 elif IN("WARNING","MEDIUM") then 1 else 2 end) | .[] | "| \(.extra.severity) | \(.check_id | split(".") | last) | \(.path):\(.start.line) |"' "$$json" | head -n 50; \
		fi; \
	} > $(CS_REPORTS_DIR)/semgrep-summary.md; \
	cat $(CS_REPORTS_DIR)/semgrep-summary.md; \
	if [[ $$status -ne 0 ]]; then echo "semgrep failed (exit $$status)"; exit $$status; fi; \
	if [[ $$blocking -ne 0 ]]; then echo "SAST gate: $$blocking blocking finding(s)"; exit 1; fi

.PHONY: sast-test
sast-test: ## Unit-test the repo Semgrep rules against their fixtures (semgrep --test)
	$(SEMGREP_RUN) --network none --volume "$(CURDIR)/$(SEMGREP_RULES):/rules:ro" --workdir /rules \
		$(SEMGREP_IMAGE) semgrep scan --test --metrics=off --disable-version-check .

$(ZIZMOR): $(ZIZMOR_REQUIREMENTS)
	$(PYTHON) -m venv "$(ZIZMOR_VENV)"
	"$(ZIZMOR_VENV)/bin/pip" install --disable-pip-version-check --quiet \
		--require-hashes --only-binary=:all: --no-deps -r $(ZIZMOR_REQUIREMENTS)
	@touch "$@"

.PHONY: zizmor
zizmor: $(ZIZMOR) ## Audit GitHub Actions workflows and Dependabot config (zizmor; offline unless CS_ZIZMOR_OFFLINE=0)
	@mkdir -p $(CS_REPORTS_DIR) && rm -f $(CS_REPORTS_DIR)/zizmor.sarif $(CS_REPORTS_DIR)/zizmor-summary.md
	@"$(ZIZMOR)" --version
	@"$(ZIZMOR)" $(ZIZMOR_FLAGS) --persona regular --format sarif --no-exit-codes .github \
		> $(CS_REPORTS_DIR)/zizmor.sarif
	@sarif=$(CS_REPORTS_DIR)/zizmor.sarif; \
	{ \
		echo "### Workflow security — zizmor $(ZIZMOR_VERSION)$(if $(filter 1,$(CS_ZIZMOR_OFFLINE)), (offline audits only))"; echo; \
		echo "- Findings (regular persona): $$(jq -r '[.runs[].results[].level] | group_by(.) | map("\(.[0]): \(length)") | join(", ") | if . == "" then "none" else . end' "$$sarif")"; \
		echo "- Gate: severity >= $(ZIZMOR_MIN_SEVERITY) and confidence >= $(ZIZMOR_MIN_CONFIDENCE) fails (see job log)"; \
		if [[ "$$(jq '[.runs[].results[]] | length' "$$sarif")" != 0 ]]; then \
			echo; echo "| Level | Audit | Location |"; echo "|---|---|---|"; \
			jq -r '.runs[].results[] | "| \(.level) | \(.ruleId) | \(.locations[0].physicalLocation.artifactLocation.uri):\(.locations[0].physicalLocation.region.startLine) |"' "$$sarif" | head -n 50; \
		fi; \
	} > $(CS_REPORTS_DIR)/zizmor-summary.md; \
	cat $(CS_REPORTS_DIR)/zizmor-summary.md
	"$(ZIZMOR)" $(ZIZMOR_FLAGS) --min-severity $(ZIZMOR_MIN_SEVERITY) --min-confidence $(ZIZMOR_MIN_CONFIDENCE) .github
