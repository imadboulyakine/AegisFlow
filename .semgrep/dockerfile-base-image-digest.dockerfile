# Test cases for dockerfile-base-image-not-digest-pinned (run: make sast-test).

# ok: dockerfile-base-image-not-digest-pinned
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
RUN go version

# ruleid: dockerfile-base-image-not-digest-pinned
FROM alpine:3.22 AS tools
RUN true

# ruleid: dockerfile-base-image-not-digest-pinned
FROM --platform=linux/amd64 gcr.io/distroless/static-debian13:nonroot AS distroless

# ruleid: dockerfile-base-image-not-digest-pinned
FROM node:latest

# ok: dockerfile-base-image-not-digest-pinned
FROM build AS test
RUN go test ./...

# ok: dockerfile-base-image-not-digest-pinned
FROM scratch
COPY --from=build /out/app /app
