# Provenance, signing and third-party verification of bin/aegisflow (Phase 1b; ADR-009, ADR-014).
# Included by the main Makefile. CI counterpart: .github/workflows/provenance.yml.
#
# Produce (CI build job; locally a dry run: no signing, no network except the Syft image pull):
#   make provenance-dry-run   = provenance-build + checksums + provenance-sbom + provenance-check
# Verify a downloaded `aegisflow-signed` artifact (needs gh and cosign v3 on PATH; tested with gh 2.89.0, cosign 3.1.4):
#   make verify-provenance PROVENANCE_DIR=<artifact dir> [PROVENANCE_COMMIT=<sha>]
# Rebuild bit-for-bit from a clean checkout of the same commit and compare digests:
#   make reproduce PROVENANCE_DIR=<artifact dir>
#
# Deterministic build: VERSION=ci-<commit>, COMMIT=<commit>, BUILD_DATE=<commit time, UTC>, linux/amd64
# (GOAMD64=v1), -trimpath, toolchains pinned by go.mod (`toolchain`) and web/package.json
# (`packageManager`). Two builds of one clean commit are bit-identical (tested 2026-10-26: two
# clones, fresh GOCACHE, same sha256), so a verifier can rebuild instead of trusting the runner.

## ---------- Provenance & signing (mk/provenance.mk) ----------

# Canonical identity the signatures must carry. Deliberately not derived from the local git
# remote: a fork or a tampered clone must not be able to change what is verified.
PROVENANCE_REPO          ?= imadboulyakine/AegisFlow
PROVENANCE_WORKFLOW      ?= .github/workflows/provenance.yml
PROVENANCE_REF           ?= refs/heads/main
PROVENANCE_OIDC_ISSUER   ?= https://token.actions.githubusercontent.com
PROVENANCE_CERT_IDENTITY ?= https://github.com/$(PROVENANCE_REPO)/$(PROVENANCE_WORKFLOW)@$(PROVENANCE_REF)
# Optional: pin verification to one commit (gh --source-digest, cosign --certificate-github-workflow-sha).
PROVENANCE_COMMIT        ?=
# Directory holding the artifact to verify (aegisflow, SHA256SUMS, *.sigstore.json, aegisflow.cdx.json).
PROVENANCE_DIR           ?= $(BIN_DIR)
# Where gh reads the attestations: `bundle` = the *.sigstore.json files in PROVENANCE_DIR (no GitHub
# login needed); `api` = the repository's attestation store (needs `gh auth login` or GH_TOKEN).
PROVENANCE_ATTESTATIONS  ?= bundle

GH_CLI ?= gh
COSIGN ?= cosign

# Deterministic build metadata, derived from the checked-out commit (recursive: evaluated on use).
PROVENANCE_COMMIT_SHA = $(shell git rev-parse HEAD 2>/dev/null)
PROVENANCE_VERSION    = ci-$(PROVENANCE_COMMIT_SHA)
PROVENANCE_BUILD_DATE = $(shell TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ 2>/dev/null)

# Syft for the binary SBOM. Single source of truth: SYFT_IMAGE from mk/supply-chain.mk when that
# fragment is present (expanded lazily, so include order does not matter); otherwise the same
# release pinned by index digest (identical on Docker Hub and mirror.gcr.io, ADR-015).
PROVENANCE_SYFT_FALLBACK := docker.io/anchore/syft:v1.55.0@sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a
PROVENANCE_SYFT_IMAGE    ?= $(or $(SYFT_IMAGE),$(PROVENANCE_SYFT_FALLBACK))
PROVENANCE_SBOM_FORMAT   ?= cyclonedx-json@1.6
PROVENANCE_SBOM          := $(BIN_DIR)/aegisflow.cdx.json
PROVENANCE_SBOM_INPUT    := $(BIN_DIR)/provenance-sbom-input

# $(call prov_gh_source,<bundle file>): read the attestation from a bundle file unless mode is `api`.
prov_gh_source = $(if $(filter api,$(PROVENANCE_ATTESTATIONS)),,--bundle $(1))

.PHONY: provenance-build
provenance-build: ## Build bin/aegisflow reproducibly (VERSION=ci-<commit>, BUILD_DATE=commit time, linux/amd64)
	@[[ -z "$$(git status --porcelain)" ]] || echo "provenance-build: warning: dirty working tree (vcs.modified=true); the digest will not match CI" >&2
	GOOS=linux GOARCH=amd64 GOAMD64=v1 $(MAKE) --no-print-directory build \
		VERSION='$(PROVENANCE_VERSION)' COMMIT='$(PROVENANCE_COMMIT_SHA)' BUILD_DATE='$(PROVENANCE_BUILD_DATE)'

.PHONY: checksums
checksums: ## Write bin/SHA256SUMS for bin/aegisflow (sha256sum -c format)
	@test -f $(BINARY) || { echo "checksums: $(BINARY) not found: run 'make provenance-build' first" >&2; exit 1; }
	cd $(BIN_DIR) && sha256sum $(notdir $(BINARY)) > SHA256SUMS
	@cat $(BIN_DIR)/SHA256SUMS

# The SBOM subject is the binary, so Syft scans a staging directory holding exactly what ships in
# it: the binary (Go modules + stdlib from its build info) and web/bun.lock (Syft keeps only the
# runtime npm packages, i.e. what the embedded SPA bundles; devDependencies are excluded). Scanning
# the repository instead would pull in node_modules, tooling and test fixtures.
.PHONY: provenance-sbom
provenance-sbom: ## CycloneDX SBOM of bin/aegisflow (Go build info + bundled npm runtime deps; Syft, no network)
	@test -f $(BINARY) || { echo "provenance-sbom: $(BINARY) not found: run 'make provenance-build' first" >&2; exit 1; }
	rm -rf $(PROVENANCE_SBOM_INPUT) && mkdir -p $(PROVENANCE_SBOM_INPUT)/web
	cp $(BINARY) $(PROVENANCE_SBOM_INPUT)/
	cp web/package.json web/bun.lock $(PROVENANCE_SBOM_INPUT)/web/
	$(DOCKER) run --rm --user "$$(id -u):$$(id -g)" --read-only --tmpfs /tmp:rw,size=1g \
		--cap-drop ALL --security-opt no-new-privileges:true --network none \
		-e HOME=/tmp -e SYFT_CHECK_FOR_APP_UPDATE=false \
		-v "$(abspath $(PROVENANCE_SBOM_INPUT)):/artifact:ro" $(PROVENANCE_SYFT_IMAGE) \
		scan dir:/artifact --source-name aegisflow --source-version '$(PROVENANCE_VERSION)' \
		-q -o $(PROVENANCE_SBOM_FORMAT) > $(PROVENANCE_SBOM).tmp
	mv $(PROVENANCE_SBOM).tmp $(PROVENANCE_SBOM)
	rm -rf $(PROVENANCE_SBOM_INPUT)
	@jq -r '"\(.bomFormat) \(.specVersion): " + ([.components[] | select(.purl) | .purl] | join(", "))' $(PROVENANCE_SBOM)

.PHONY: provenance-check
provenance-check: ## Self-check build outputs: checksum, embedded commit, SBOM bound to the binary digest
	cd $(BIN_DIR) && sha256sum -c SHA256SUMS
	@got=$$(./$(BINARY) -version | jq -r .commit); want='$(PROVENANCE_COMMIT_SHA)'; \
	[[ "$$got" == "$$want" ]] || { echo "provenance-check: binary reports commit '$$got', expected '$$want'" >&2; exit 1; }; \
	echo "embedded commit: $$got"
	@jq -e --arg d "$$(sha256sum $(BINARY) | cut -d' ' -f1)" "$$PROVENANCE_JQ_SBOM_CHECK" $(PROVENANCE_SBOM) >/dev/null \
		|| { echo "provenance-check: $(PROVENANCE_SBOM) does not describe $(BINARY) (digest, Go stdlib, npm runtime deps)" >&2; exit 1; }
	@echo "provenance-check: OK"

# The SBOM must name the binary by digest and contain both halves of what ships in it.
define PROVENANCE_JQ_SBOM_CHECK
.bomFormat == "CycloneDX"
and any(.components[]; .type == "file" and any(.hashes[]?; .alg == "SHA-256" and .content == $$d))
and any(.components[]; (.purl // "") | startswith("pkg:golang/stdlib@"))
and any(.components[]; (.purl // "") | startswith("pkg:npm/"))
endef
export PROVENANCE_JQ_SBOM_CHECK

.PHONY: provenance-dry-run
provenance-dry-run: ## What the PR job runs: reproducible build + checksums + SBOM + self-checks (no signing)
	$(MAKE) --no-print-directory provenance-build
	$(MAKE) --no-print-directory checksums
	$(MAKE) --no-print-directory provenance-sbom
	$(MAKE) --no-print-directory provenance-check

.PHONY: verify-provenance
verify-provenance: ## Verify a downloaded build in PROVENANCE_DIR: SHA256SUMS, GitHub attestations, cosign signature
	@for tool in $(GH_CLI) $(COSIGN) sha256sum; do \
		command -v "$$tool" >/dev/null 2>&1 || { echo "verify-provenance: '$$tool' not found on PATH." \
			"Install gh (https://cli.github.com; tested 2.89.0) and cosign v3 (https://docs.sigstore.dev/cosign/system_config/installation/; tested 3.1.4)." >&2; exit 1; }; \
	done
	@cd '$(PROVENANCE_DIR)' && for f in aegisflow SHA256SUMS aegisflow.sigstore.json \
		$(if $(filter api,$(PROVENANCE_ATTESTATIONS)),,aegisflow.provenance.sigstore.json aegisflow.sbom.sigstore.json); do \
		test -f "$$f" || { echo "verify-provenance: $(PROVENANCE_DIR)/$$f missing (download the aegisflow-signed artifact)" >&2; exit 1; }; \
	done
	@echo "== 1/4 checksum"
	cd '$(PROVENANCE_DIR)' && sha256sum -c SHA256SUMS
	@echo "== 2/4 SLSA build provenance (GitHub artifact attestation)"
	cd '$(PROVENANCE_DIR)' && $(GH_CLI) attestation verify aegisflow --repo '$(PROVENANCE_REPO)' \
		$(call prov_gh_source,aegisflow.provenance.sigstore.json) \
		--signer-workflow '$(PROVENANCE_REPO)/$(PROVENANCE_WORKFLOW)' --source-ref '$(PROVENANCE_REF)' \
		$(if $(PROVENANCE_COMMIT),--source-digest '$(PROVENANCE_COMMIT)') --deny-self-hosted-runners
	@echo "== 3/4 SBOM attestation (CycloneDX)"
	cd '$(PROVENANCE_DIR)' && $(GH_CLI) attestation verify aegisflow --repo '$(PROVENANCE_REPO)' \
		$(call prov_gh_source,aegisflow.sbom.sigstore.json) --predicate-type https://cyclonedx.org/bom \
		--signer-workflow '$(PROVENANCE_REPO)/$(PROVENANCE_WORKFLOW)' --source-ref '$(PROVENANCE_REF)' \
		$(if $(PROVENANCE_COMMIT),--source-digest '$(PROVENANCE_COMMIT)') --deny-self-hosted-runners
	@echo "== 4/4 Sigstore keyless signature (cosign bundle)"
	cd '$(PROVENANCE_DIR)' && $(COSIGN) verify-blob aegisflow --bundle aegisflow.sigstore.json \
		--certificate-identity '$(PROVENANCE_CERT_IDENTITY)' --certificate-oidc-issuer '$(PROVENANCE_OIDC_ISSUER)' \
		--certificate-github-workflow-repository '$(PROVENANCE_REPO)' \
		$(if $(PROVENANCE_COMMIT),--certificate-github-workflow-sha '$(PROVENANCE_COMMIT)')
	@echo "verify-provenance: OK: $(PROVENANCE_DIR)/aegisflow was built and signed by $(PROVENANCE_CERT_IDENTITY)"

.PHONY: reproduce
reproduce: ## Rebuild this clean checkout and compare bin/aegisflow with PROVENANCE_DIR/SHA256SUMS
	@[[ -z "$$(git status --porcelain)" ]] || { echo "reproduce: the working tree must be clean (Go records" \
		"vcs.modified in the binary); keep the downloaded artifact outside the checkout or in bin/" >&2; exit 1; }
	@want_bun=$$(jq -r '.packageManager | ltrimstr("bun@")' web/package.json); got_bun=$$($(BUN) --version); \
	[[ "$$got_bun" == "$$want_bun" ]] || { echo "reproduce: bun $$want_bun required (web/package.json), found $$got_bun" >&2; exit 1; }
	@commit='$(PROVENANCE_COMMIT)'; [[ -z "$$commit" || "$$(git rev-parse HEAD)" == "$$commit" ]] \
		|| { echo "reproduce: check out $$commit first (git checkout --detach $$commit)" >&2; exit 1; }
	@want=$$(awk '$$2 == "aegisflow" { print $$1 }' '$(PROVENANCE_DIR)/SHA256SUMS'); \
	[[ -n "$$want" ]] || { echo "reproduce: no aegisflow entry in $(PROVENANCE_DIR)/SHA256SUMS" >&2; exit 1; }; \
	$(MAKE) --no-print-directory provenance-build; \
	got=$$(sha256sum $(BINARY) | cut -d' ' -f1); \
	if [[ "$$got" == "$$want" ]]; then echo "reproduce: OK, rebuilt $(BINARY) is bit-identical ($$got)"; \
	else echo "reproduce: MISMATCH, rebuilt $$got but $(PROVENANCE_DIR)/SHA256SUMS says $$want" >&2; exit 1; fi
