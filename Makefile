# AegisFlow developer tasks. Run `make help` for the list.
#
# Go toolchain: go.mod pins `toolchain go1.27.3`; with the default GOTOOLCHAIN=auto an
# older local Go downloads and uses go1.27.3 automatically (verified with host Go 1.24).

SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

GO   ?= go
BUN  ?= bun
DOCKER ?= docker

BIN_DIR := bin
BINARY  := $(BIN_DIR)/aegisflow
PKG     := github.com/imadboulyakine/aegisflow
IMAGE   ?= aegisflow:dev

# Build metadata injected into internal/version (overridable: make build VERSION=v0.1.0).
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.BuildDate=$(BUILD_DATE)

# Pinned tool versions (bump deliberately; keep in sync with .github/workflows/ci.yml).
GOVULNCHECK_VERSION   ?= v1.9.0
GOLANGCI_LINT_VERSION ?= v2.15.0
ACTIONLINT_VERSION    ?= v1.7.12

# `go run tool@version` builds a tool with the toolchain from *the tool's* go.mod, which may
# be older than ours (golangci-lint v2.15.0 asks for go1.26 and then refuses to lint a
# go1.27 module). Force the project toolchain, read from go.mod, for all Go-based tools.
GO_TOOLCHAIN := $(shell sed -n 's/^toolchain //p' go.mod)
GO_TOOL := GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO)

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\nTargets:\n"} \
		/^[a-zA-Z0-9_-]+:.*##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

## ---------- Frontend (web/, Bun) ----------

.PHONY: web-install
web-install: ## Install frontend dependencies from bun.lock (frozen, no lifecycle scripts)
	cd web && $(BUN) install --frozen-lockfile --ignore-scripts

.PHONY: web-build
web-build: web-install ## Bundle the React app and copy it into internal/webui/dist
	cd web && $(BUN) run build

.PHONY: web-test
web-test: web-install ## Run frontend unit tests (bun test)
	cd web && $(BUN) test

.PHONY: web-typecheck
web-typecheck: web-install ## Type-check the frontend (tsc --noEmit, strict)
	cd web && $(BUN) run typecheck

.PHONY: web-dev
web-dev: web-install ## Run the Bun dev server with HMR on :3000 (proxies the API to :8080)
	cd web && $(BUN) run dev

## ---------- Backend (Go) ----------

.PHONY: go-test
go-test: ## Run Go tests with the race detector and coverage
	$(GO) test -race -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -n 1

.PHONY: go-vet
go-vet: ## Run go vet
	$(GO) vet ./...

.PHONY: go-fmt-check
go-fmt-check: ## Fail if any Go file is not gofmt-formatted
	@unformatted="$$(gofmt -l $$($(GO) list -f '{{.Dir}}' ./...))"; \
	if [[ -n "$$unformatted" ]]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi; \
	echo "gofmt: ok"

.PHONY: go-build
go-build: ## Build bin/aegisflow (static, trimmed, version metadata via -ldflags)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/aegisflow
	@ls -lh $(BINARY) | awk '{print "built " $$9 " (" $$5 ")"}'

.PHONY: golangci-lint
golangci-lint: ## Run golangci-lint (pinned; built with the project toolchain)
	$(GO_TOOL) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

.PHONY: vuln
vuln: ## Scan Go code and stdlib for known vulnerabilities (govulncheck)
	$(GO_TOOL) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

.PHONY: actionlint
actionlint: ## Lint GitHub Actions workflows (pinned actionlint)
	$(GO_TOOL) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

## ---------- Aggregates ----------

.PHONY: build
build: web-build go-build ## Build the frontend, embed it and build bin/aegisflow

.PHONY: test
test: web-test go-test ## Run all tests (frontend + Go)

.PHONY: lint
lint: go-fmt-check go-vet golangci-lint web-typecheck ## gofmt + go vet + golangci-lint + tsc

.PHONY: run
run: build ## Build everything and run the server on :8080
	AEGISFLOW_LOG_LEVEL=$${AEGISFLOW_LOG_LEVEL:-debug} ./$(BINARY)

## ---------- Container ----------

.PHONY: docker-build
docker-build: ## Build the container image (IMAGE, default aegisflow:dev)
	$(DOCKER) build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE) .

.PHONY: docker-run
docker-run: ## Run the image read-only, unprivileged, on :8080
	$(DOCKER) run --rm -it -p 8080:8080 --read-only --cap-drop ALL \
		--security-opt no-new-privileges:true $(IMAGE)

## ---------- Housekeeping ----------

.PHONY: clean
clean: ## Remove build outputs (keeps internal/webui/dist/.gitkeep)
	rm -rf $(BIN_DIR) coverage.out web/dist
	find internal/webui/dist -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf {} +
