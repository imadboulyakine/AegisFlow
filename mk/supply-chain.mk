# Supply-chain evidence: SCA, SBOMs and image scan (Phase 1a). Included by the main Makefile.
#
# Every target writes into $(SC_OUT) (git-ignored, removed by `make clean`). The file names are
# stable because .github/workflows/supply-chain.yml uploads them as artifacts that Phase 2 ingests.
#
#   govulncheck.json, govulncheck.openvex.json    vuln-evidence  (gate: `make vuln`, main Makefile)
#   osv-scanner.json, osv-scanner.sarif            osv            (gate: any known vulnerability)
#   sbom-source.{cdx,spdx}.json                    sbom-source    (committed tree at HEAD)
#   sbom-image.{cdx,spdx,syft}.json                sbom-image     (container image $(IMAGE); .syft.json = Grype input)
#   grype-image.json, grype-image.sarif            grype          (gate: >= GRYPE_FAIL_ON with a fix)
#   *.summary.md                                   Markdown tables for $GITHUB_STEP_SUMMARY
#
# Tool pinning (ADR-015):
#   - osv-scanner: `go install module@version` (module checksums verified against
#     sum.golang.org), built with the project toolchain ($(GO_TOOL)); the binary is cached under
#     $(SC_TOOLS) with the version and toolchain in its file name.
#   - Syft and Grype: the official images pinned by index digest. The digests were checked to be
#     identical on Docker Hub and mirror.gcr.io, and `version` in each image reports the commit of
#     the upstream release tag. A cold `go run` build of Syft takes ~2.5 min versus ~4 s for the
#     pull. Containers run as the calling user with a read-only root filesystem, no capabilities
#     and no-new-privileges. Syft also runs without network.
#
# Sandbox (vuln.go.dev, api.osv.dev, the Grype DB and Docker Hub may be blocked); see
# docs/PROJECT_STATE.md §6:
#   make vuln-evidence GOVULNCHECK_FLAGS='-db file:///path/to/govulndb'
#   make osv OSV_SCANNER_FLAGS='--offline-vulnerabilities --download-offline-databases'
#   make sbom SC_TOOL_REGISTRY=mirror.gcr.io     # same digests as Docker Hub

## ---------- Supply chain (mk/supply-chain.mk) ----------

# Pinned versions. Bump deliberately: new version + new digest, verified as described above.
OSV_SCANNER_VERSION ?= v2.7.0
SYFT_VERSION        ?= v1.55.0
SYFT_DIGEST         ?= sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a
GRYPE_VERSION       ?= v0.121.0
GRYPE_DIGEST        ?= sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea
SC_TOOL_REGISTRY    ?= docker.io
SYFT_IMAGE          ?= $(SC_TOOL_REGISTRY)/anchore/syft:$(SYFT_VERSION)@$(SYFT_DIGEST)
GRYPE_IMAGE         ?= $(SC_TOOL_REGISTRY)/anchore/grype:$(GRYPE_VERSION)@$(GRYPE_DIGEST)

# Grype gate: fail when a match that is not ignored has severity >= this AND a known fix.
GRYPE_FAIL_ON ?= high

# Extra flags (sandbox/offline use, see above). Empty in CI.
GOVULNCHECK_FLAGS ?=
OSV_SCANNER_FLAGS ?=

# Lockfiles osv-scanner checks. Each one must yield at least one package (guards against a
# lockfile silently not being parsed).
OSV_LOCKFILES ?= go.mod web/bun.lock

# Evidence formats are pinned so that a Syft upgrade cannot silently change the schema.
SBOM_CDX_FORMAT  ?= cyclonedx-json@1.6
SBOM_SPDX_FORMAT ?= spdx-json@2.3
# Test fixtures (e.g. deliberately vulnerable lockfiles for experiments) are not part of the product.
SBOM_SOURCE_EXCLUDES ?= **/testdata/**

SC_OUT       ?= $(BIN_DIR)/supply-chain
SC_TOOLS     ?= $(BIN_DIR)/tools
GRYPE_DB_DIR ?= $(HOME)/.cache/aegisflow/grype-db

OSV_SCANNER := $(SC_TOOLS)/osv-scanner-$(OSV_SCANNER_VERSION)-$(GO_TOOLCHAIN)
GOVULNCHECK := $(GO_TOOL) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(GOVULNCHECK_FLAGS)
SC_OUT_ABS   = $(abspath $(SC_OUT))

# Hardened `docker run` for the scanner images.
SC_DOCKER_RUN = $(DOCKER) run --rm --user "$$(id -u):$$(id -g)" --read-only \
	--tmpfs /tmp:rw,size=2g,mode=1777 --cap-drop ALL --security-opt no-new-privileges:true -e HOME=/tmp

# $(call sc_syft,<extra docker run args>) — Syft never needs the network here.
sc_syft = $(SC_DOCKER_RUN) --network none -e SYFT_CHECK_FOR_APP_UPDATE=false $(1) \
	-v "$(SC_OUT_ABS):/out" $(SYFT_IMAGE)

# For the image, Syft also records which Go stdlib and golang.org/x functions are linked into the
# binary (pclntab). Only the Syft-native JSON carries them; Grype uses them to match Go advisories
# at function level instead of module level (fewer false positives, same DB).
SYFT_GO_SYMBOLS ?= extended-stdlib

# $(call sc_grype,<extra docker run args>,<grype args>)
sc_grype = $(SC_DOCKER_RUN) -e GRYPE_DB_CACHE_DIR=/grype-db $(1) \
	-v "$(abspath $(GRYPE_DB_DIR)):/grype-db" -v "$(CURDIR)/.grype.yaml:/config/grype.yaml:ro" \
	-v "$(SC_OUT_ABS):/out" $(GRYPE_IMAGE) --config /config/grype.yaml $(2)

.PHONY: vuln-evidence
vuln-evidence: ## govulncheck JSON + OpenVEX evidence (never fails on findings; `make vuln` is the gate)
	@mkdir -p $(SC_OUT)
	$(GOVULNCHECK) -format json ./... > $(SC_OUT)/govulncheck.json
	$(GOVULNCHECK) -format openvex ./... > $(SC_OUT)/govulncheck.openvex.json
	@jq -rs --arg v "$(GOVULNCHECK_VERSION)" "$$SC_JQ_GOVULNCHECK" $(SC_OUT)/govulncheck.json \
		| tee $(SC_OUT)/govulncheck.summary.md

.PHONY: osv-scanner-bin
osv-scanner-bin: $(OSV_SCANNER) ## Build the pinned osv-scanner into bin/tools (skipped when present)

$(OSV_SCANNER):
	@mkdir -p $(SC_TOOLS)/.gobin
	GOBIN="$(abspath $(SC_TOOLS))/.gobin" $(GO_TOOL) install \
		github.com/google/osv-scanner/v2/cmd/osv-scanner@$(OSV_SCANNER_VERSION)
	mv -f $(SC_TOOLS)/.gobin/osv-scanner $@
	@find $(SC_TOOLS) -maxdepth 1 -name 'osv-scanner-*' ! -name '$(@F)' -delete

# --all-vulns is part of the gate, not an option: without it osv-scanner exits 0 when every Go
# finding is "uncalled" by its built-in govulncheck call analysis (verified with v2.7.0: 14 known
# stdlib advisories → exit 0). Reachability is govulncheck's job (`make vuln`); this gate is
# "no known vulnerability at all". Call analysis still annotates the JSON (experimental_analysis).
OSV_SCAN = $(OSV_SCANNER) scan source --config osv-scanner.toml --all-vulns \
	$(addprefix -L ,$(OSV_LOCKFILES)) $(OSV_SCANNER_FLAGS)

.PHONY: osv
osv: $(OSV_SCANNER) ## osv-scanner on go.mod + web/bun.lock (fails on any known vuln not excepted in osv-scanner.toml)
	@mkdir -p $(SC_OUT)
	@awk "$$SC_AWK_OSV_POLICY" osv-scanner.toml
	@rc=0; \
	$(OSV_SCAN) --format json --all-packages --output-file $(SC_OUT)/osv-scanner.json || rc=$$?; \
	$(OSV_SCAN) --format sarif --output-file $(SC_OUT)/osv-scanner.sarif >/dev/null 2>&1 \
		|| [[ $$? -eq 1 ]] || { echo "osv-scanner: SARIF run failed" >&2; rc=127; }; \
	test -s $(SC_OUT)/osv-scanner.json || { echo "osv-scanner: no JSON report (exit $$rc)" >&2; exit 1; }; \
	jq -r --arg v "$(OSV_SCANNER_VERSION)" --arg root "$(CURDIR)/" "$$SC_JQ_OSV" $(SC_OUT)/osv-scanner.json \
		| tee $(SC_OUT)/osv-scanner.summary.md; \
	for lf in $(OSV_LOCKFILES); do \
		n=$$(jq --arg f "$(CURDIR)/$$lf" '[.results[] | select(.source.path == $$f) | .packages | length] | add // 0' \
			$(SC_OUT)/osv-scanner.json); \
		if [[ "$$n" -eq 0 ]]; then echo "osv-scanner: no packages parsed from $$lf" >&2; [[ $$rc -ne 0 ]] || rc=128; fi; \
	done; \
	case $$rc in \
		0) echo "osv-scanner: no known vulnerabilities" ;; \
		1) echo "osv-scanner: FAILED — known vulnerabilities (fix, or add a justified, expiring entry to osv-scanner.toml)" >&2 ;; \
		128) echo "osv-scanner: FAILED — a lockfile yielded no packages (not parsed?)" >&2 ;; \
		*) echo "osv-scanner: FAILED — scanner error (exit $$rc)" >&2 ;; \
	esac; \
	exit $$rc

.PHONY: sbom-source
sbom-source: ## SBOM of the committed source tree at HEAD (CycloneDX 1.6 + SPDX 2.3, Syft)
	@mkdir -p $(SC_OUT)
	rm -rf $(SC_OUT)/source-tree && mkdir -p $(SC_OUT)/source-tree
	git archive --format=tar HEAD | tar -x -C $(SC_OUT)/source-tree
	$(call sc_syft,) scan dir:/out/source-tree $(foreach e,$(SBOM_SOURCE_EXCLUDES),--exclude '$(e)') \
		--source-name aegisflow --source-version "$(COMMIT)" \
		-o $(SBOM_CDX_FORMAT)=/out/sbom-source.cdx.json -o $(SBOM_SPDX_FORMAT)=/out/sbom-source.spdx.json
	rm -rf $(SC_OUT)/source-tree
	@$(SC_SBOM_SUMMARY)

.PHONY: sbom-image
sbom-image: ## SBOM of the container image IMAGE (default aegisflow:dev; run docker-build first)
	@$(DOCKER) image inspect "$(IMAGE)" >/dev/null 2>&1 \
		|| { echo "image $(IMAGE) not found: run 'make docker-build' first" >&2; exit 1; }
	@mkdir -p $(SC_OUT)
	$(DOCKER) save "$(IMAGE)" -o $(SC_OUT)/image.tar
	$(call sc_syft,-e SYFT_GOLANG_CAPTURE_SYMBOLS=$(SYFT_GO_SYMBOLS)) scan docker-archive:/out/image.tar \
		--source-name aegisflow --source-version "$(COMMIT)" \
		-o $(SBOM_CDX_FORMAT)=/out/sbom-image.cdx.json -o $(SBOM_SPDX_FORMAT)=/out/sbom-image.spdx.json \
		-o syft-json=/out/sbom-image.syft.json
	rm -f $(SC_OUT)/image.tar
	@$(SC_SBOM_SUMMARY)

.PHONY: sbom
sbom: sbom-source sbom-image ## Source-tree and image SBOMs

.PHONY: grype
grype: ## Grype on the image SBOM (fails: severity >= GRYPE_FAIL_ON, default high, with a fix available)
	@test -s $(SC_OUT)/sbom-image.syft.json \
		|| { echo "missing $(SC_OUT)/sbom-image.syft.json: run 'make sbom-image' first" >&2; exit 1; }
	@mkdir -p "$(GRYPE_DB_DIR)"
	@# 1) Evidence: every match, no gate.
	$(call sc_grype,,sbom:/out/sbom-image.syft.json -o json=/out/grype-image.json -o sarif=/out/grype-image.sarif)
	@jq -r --arg v "$(GRYPE_VERSION)" --arg fail "$(GRYPE_FAIL_ON)" "$$SC_JQ_GRYPE" $(SC_OUT)/grype-image.json \
		| tee $(SC_OUT)/grype-image.summary.md
	@# 2) Gate on the same DB (no update between the two runs). Exit code 2 = threshold breached.
	$(call sc_grype,-e GRYPE_DB_AUTO_UPDATE=false,sbom:/out/sbom-image.syft.json --only-fixed --fail-on $(GRYPE_FAIL_ON) -o table)

.PHONY: supply-chain
supply-chain: vuln-evidence vuln osv sbom grype ## All supply-chain evidence and gates (needs the image: make docker-build)

# ---------- helpers (summaries and policy checks) ----------

# One table row per CycloneDX SBOM present in $(SC_OUT), rewritten after each SBOM target.
# (`\#`: a bare # would start a make comment inside this assignment.)
SC_SBOM_SUMMARY = { \
	echo "\#\#\# SBOMs — Syft $(SYFT_VERSION) ($(SBOM_CDX_FORMAT), $(SBOM_SPDX_FORMAT))"; echo; \
	echo "| SBOM | Components | By type (purl) | SPDX packages |"; echo "|---|---|---|---|"; \
	for s in source image; do \
		f=$(SC_OUT)/sbom-$$s.cdx.json; [[ -s $$f ]] || continue; \
		jq -r --arg spdx "$$(jq '.packages | length' $(SC_OUT)/sbom-$$s.spdx.json)" "$$SC_JQ_SBOM" $$f; \
	done; echo; \
	} | tee $(SC_OUT)/sbom.summary.md

define SC_JQ_GOVULNCHECK
(map(select(.config)) | first | .config) as $$c
| [ .[] | select(.finding) | .finding ] as $$f
| ([ $$f[] | select(.trace[0].function) | .osv ] | unique) as $$called
| (([ $$f[] | select(.trace[0].package) | .osv ] | unique) - $$called) as $$imported
| (([ $$f[] | .osv ] | unique) - $$called - $$imported) as $$required
| "### govulncheck \($$v) — gate: called (reachable) vulnerabilities\n",
  "Go `\($$c.go_version)` · DB `\($$c.db)` (modified \($$c.db_last_modified // "n/a"))\n",
  "| Level | Advisories | IDs |", "|---|---|---|",
  "| Called — **gate** (`make vuln`, exit 3) | \($$called | length) | \($$called | join(", ")) |",
  "| Imported, not called | \($$imported | length) | \($$imported | join(", ")) |",
  "| Required module only | \($$required | length) | \($$required | join(", ")) |", ""
endef
export SC_JQ_GOVULNCHECK

define SC_JQ_OSV
"### osv-scanner \($$v) — gate: any known vulnerability\n",
"| Lockfile | Packages | Vulnerable packages | Advisories |", "|---|---|---|---|",
(.results[] | "| `\(.source.path | ltrimstr($$root))` | \(.packages | length) | \([.packages[] | select((.groups // []) | length > 0)] | length) | \([.packages[] | (.groups // [])[]] | length) |"),
"",
(.results[].packages[] | select((.groups // []) | length > 0)
  | "- `\(.package.name)@\(.package.version)`: \([.groups[]
      | "\(.ids[0]) (severity \(if (.max_severity // "") == "" then "n/a" else .max_severity end)\(
          if (.experimental_analysis // {}) == {} then ""
          elif (.experimental_analysis | to_entries | any(.value.called)) then ", called"
          else ", not called" end))"] | join(", "))"),
""
endef
export SC_JQ_OSV

define SC_JQ_SBOM
def kind: if .purl then (.purl | capture("^pkg:(?<t>[^/]+)/").t) else .type end;
[ .components[]? | select(.type != "file") | kind ] as $$k
| "| `\(input_filename | split("/") | last)` | \($$k | length) | \($$k | group_by(.) | map("\(.[0]) \(length)") | join(", ")) | \($$spdx) |"
endef
export SC_JQ_SBOM

define SC_JQ_GRYPE
(.matches // []) as $$m
| def sevs: ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];
  def rank($$s): sevs | index($$s) // 5;
  def fixed: .vulnerability.fix.state == "fixed";
  ($$fail | ascii_downcase | (.[0:1] | ascii_upcase) + .[1:]) as $$threshold
| "### Grype \($$v) on `sbom-image.syft.json` — gate: severity ≥ \($$threshold) with a fix available\n",
  "DB built \(.descriptor.db.status.built // .descriptor.db.built // "n/a") · distro \(.distro.name // "?") \(.distro.version // "")\n",
  "| Severity | Matches | Fix available |", "|---|---|---|",
  (sevs[] as $$s | [ $$m[] | select(.vulnerability.severity == $$s) ] as $$x
    | "| \($$s) | \($$x | length) | \([ $$x[] | select(fixed) ] | length) |"),
  "| Ignored (`.grype.yaml`) | \(.ignoredMatches // [] | length) | |", "",
  ($$m[] | select(fixed and rank(.vulnerability.severity) <= rank($$threshold))
    | "- **gate**: \(.vulnerability.id) \(.vulnerability.severity) in `\(.artifact.name)@\(.artifact.version)` → fixed in \(.vulnerability.fix.versions | join(", "))"),
  ""
endef
export SC_JQ_GRYPE

# Every [[IgnoredVulns]] entry in osv-scanner.toml needs id, a non-empty reason and ignoreUntil.
define SC_AWK_OSV_POLICY
function check() {
	if (blk && !(has_id && has_reason && has_until)) {
		printf "osv-scanner.toml: [[IgnoredVulns]] entry starting at line %d needs id, reason and ignoreUntil\n", start > "/dev/stderr"; bad = 1
	}
}
/^[[:space:]]*\[/ { check(); blk = ($$0 ~ /^[[:space:]]*\[\[IgnoredVulns\]\]/); start = NR; has_id = has_reason = has_until = 0; next }
blk && /^[[:space:]]*id[[:space:]]*=[[:space:]]*"[^"]+"/ { has_id = 1 }
blk && /^[[:space:]]*reason[[:space:]]*=[[:space:]]*"[^"]+"/ { has_reason = 1 }
blk && /^[[:space:]]*ignoreUntil[[:space:]]*=/ { has_until = 1 }
END { check(); exit bad }
endef
export SC_AWK_OSV_POLICY
