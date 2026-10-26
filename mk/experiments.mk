## ---------- Experiments (PFE evaluation; see experiments/README.md) ----------
#
# Included by the top-level Makefile. One target per experiment. Each run writes into its own
# timestamped folder under $(EXPERIMENTS_RESULTS) (gitignored); every result file records the seed,
# the pinned tool versions and the dataset hashes needed to reproduce it.

EXPERIMENTS_RESULTS ?= experiments/results

# gitleaks pin: code-security.mk (included first, files are sorted) is the single source of truth;
# the fallback only applies if this fragment is used on its own. E1 execs the scanner directly, so
# it is installed (`go install module@version`: built from source with the project toolchain,
# checksums verified against sum.golang.org, ADR-015) into a per-version cache outside the repo.
GITLEAKS_VERSION ?= v8.30.1
EXPERIMENTS_TOOLS ?= $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/aegisflow/experiments/gitleaks-$(GITLEAKS_VERSION)

# E1 parameters (defaults reproduce the ROADMAP design: 50 secrets, 50 decoys).
E1_SEED            ?= 20261026
E1_REPS            ?= 1
E1_COMMITS         ?= 12
E1_MODES           ?= git,dir
E1_GITLEAKS_CONFIG ?= .gitleaks.toml
E1_FLAGS           ?=

# E4 parameters. GITHUB_TOKEN needs read access to Actions on E4_REPO and is never printed.
E4_REPO      ?= imadboulyakine/AegisFlow
E4_RUNS      ?= 20
E4_EVENT     ?= pull_request
E4_BASELINE  ?= ci.yml
E4_WORKFLOWS ?= ci.yml,code-security.yml,supply-chain.yml,github-security.yml
E4_FLAGS     ?=

.PHONY: experiments-test
experiments-test: ## Unit-test the experiment harnesses (race detector, no network)
	$(GO) test -race -count=1 ./experiments/...

$(EXPERIMENTS_TOOLS)/gitleaks:
	GOBIN="$(EXPERIMENTS_TOOLS)" $(GO_TOOL) install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)

.PHONY: e1
e1: $(EXPERIMENTS_TOOLS)/gitleaks ## E1: score gitleaks on seeded synthetic secrets + decoys (E1_SEED, E1_REPS)
	$(GO) run ./experiments/e1-secrets \
		-gitleaks "$(EXPERIMENTS_TOOLS)/gitleaks" -gitleaks-version $(GITLEAKS_VERSION) \
		$(if $(E1_GITLEAKS_CONFIG),-config $(E1_GITLEAKS_CONFIG)) \
		-seed $(E1_SEED) -reps $(E1_REPS) -commits $(E1_COMMITS) -modes $(E1_MODES) \
		-out-root $(EXPERIMENTS_RESULTS)/e1 $(E1_FLAGS)

.PHONY: e4
e4: ## E4: CI overhead, baseline vs full pipeline, from the GitHub API (needs GITHUB_TOKEN; E4_RUNS)
	@if [[ -z "$${GITHUB_TOKEN:-}" ]]; then \
		echo 'e4: GITHUB_TOKEN is not set (needs Actions: read on $(E4_REPO), e.g. GITHUB_TOKEN="$$(gh auth token)" make e4)'; \
		exit 2; \
	fi
	$(GO) run ./experiments/e4-overhead -repo $(E4_REPO) -runs $(E4_RUNS) -event "$(E4_EVENT)" \
		-baseline $(E4_BASELINE) -workflows "$(E4_WORKFLOWS)" -out-root $(EXPERIMENTS_RESULTS)/e4 $(E4_FLAGS)
