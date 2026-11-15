# SPDX-License-Identifier: Apache-2.0
#
# STATUS: not yet verified on a Docker host. This file was written on a
# machine without Docker. Build it and run the checks in
# docs/self-hosting.md before you rely on it.
#
# Build from the repository root:
#   docker build -f deploy/Dockerfile -t agentgov:local .
#
# Base images are pinned by tag. Release builds pin them by digest
# (image@sha256:...); the release process adds the digests. Confirm that the
# tags below exist before the first build.
#
# Assumptions to confirm with the CLI and dashboard owners:
#   - the dashboard builds with "npm ci && npm run build" into web/dist;
#   - the Go build embeds web/dist;
#   - the binary has the subcommands "serve" and "healthcheck --url <url>".

# ---- Stage 1: dashboard bundle -------------------------------------------
FROM node:22-alpine AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---- Stage 2: Go binary (static, no cgo) ----------------------------------
FROM golang:1.27-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
COPY --from=ui /src/web/dist ./web/dist
ARG VERSION=dev
RUN go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/agentgov ./cmd/agentgov
# An empty data directory to copy with the right owner. distroless has no
# shell, so the directory cannot be created in the final stage.
RUN mkdir -p /out/data

# ---- Stage 3: runtime ------------------------------------------------------
# distroless/static: no shell, no package manager, CA certificates included.
# The "nonroot" tag runs as UID and GID 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/agentgov /agentgov
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV AGENTGOV_DATA_DIR=/data \
    AGENTGOV_LISTEN=0.0.0.0:8080 \
    AGENTGOV_ALLOW_PUBLIC=true
# The process must listen on all interfaces INSIDE the container so that the
# published port can reach it. Exposure to other hosts is controlled by the
# port mapping in compose.yaml, which binds 127.0.0.1 only.
VOLUME ["/data"]
EXPOSE 8080
# A Dockerfile HEALTHCHECK needs a program in the image. distroless has no
# curl or wget, so the health check calls the binary itself. It is declared
# in compose.yaml:
#   /agentgov healthcheck --url http://127.0.0.1:8080/readyz
ENTRYPOINT ["/agentgov"]
CMD ["serve"]
