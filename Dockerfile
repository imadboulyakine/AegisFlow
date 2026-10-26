# AegisFlow container image (ADR-005).
#
#   docker build --build-arg VERSION=v0.1.0 --build-arg COMMIT=$(git rev-parse HEAD) \
#     --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) -t aegisflow:dev .
#
# Stage 1 bundles the React app with Bun, stage 2 compiles a static Go binary that
# embeds it, stage 3 ships only that binary on distroless (no shell, no package manager).
# Base images are pinned by digest; Dependabot (docker ecosystem) proposes updates.
# Build stages run on the build host's platform and cross-compile, so multi-arch
# builds (--platform linux/amd64,linux/arm64) need no emulation.

# ---------- 1. Frontend ----------
FROM --platform=$BUILDPLATFORM oven/bun:1.4.4-alpine@sha256:4cf82f5686b196504fe119db3fcd9185b191f82ece82c40680e597228ec6070a AS web
WORKDIR /src/web
# Dependency layer first for caching; frozen lockfile, no lifecycle scripts.
COPY web/package.json web/bun.lock web/bunfig.toml ./
RUN bun install --frozen-lockfile --ignore-scripts
COPY web/ ./
# build.ts writes web/dist and copies it to ../internal/webui/dist.
RUN mkdir -p ../internal/webui/dist && bun run build

# ---------- 2. Go binary ----------
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /src
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=web /src/internal/webui/dist/ internal/webui/dist/
ARG TARGETOS TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
# -buildvcs=false: .git is not in the build context; version data comes from the ARGs.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w \
        -X github.com/imadboulyakine/aegisflow/internal/version.Version=${VERSION} \
        -X github.com/imadboulyakine/aegisflow/internal/version.Commit=${COMMIT} \
        -X github.com/imadboulyakine/aegisflow/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/aegisflow ./cmd/aegisflow

# ---------- 3. Runtime ----------
# Debian 13 variant: Debian 12 left regular security support in June 2026.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="aegisflow" \
      org.opencontainers.image.description="AegisFlow: DevSecOps and software supply-chain security platform" \
      org.opencontainers.image.source="https://github.com/imadboulyakine/AegisFlow" \
      org.opencontainers.image.url="https://github.com/imadboulyakine/AegisFlow" \
      org.opencontainers.image.vendor="imadboulyakine" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian13:nonroot"
COPY --from=build --chmod=0555 /out/aegisflow /aegisflow
# Numeric UID/GID so Kubernetes/Container Apps can verify runAsNonRoot.
USER 65532:65532
ENV AEGISFLOW_ADDR=:8080
EXPOSE 8080
# No curl in distroless: the binary probes its own /healthz.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/aegisflow", "-healthcheck"]
ENTRYPOINT ["/aegisflow"]
