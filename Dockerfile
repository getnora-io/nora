# syntax=docker/dockerfile:1.4
#
# Multi-stage build for NORA artifact registry.
# Compiles inside Alpine — musl version always matches runtime.
#
# Usage:
#   docker build .                                             # Alpine (default)
#   docker build --target redos .                              # RED OS
#   docker build --target astra .                              # Astra Linux SE
#   docker buildx build --target binary --output type=local,dest=out .  # Binary only
#

# ── Build ──────────────────────────────────────────────────────────────────
FROM rust:1-alpine3.21 AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY nora-registry/ nora-registry/

# Exclude fuzz workspace member (requires C++ libfuzzer, not needed for binary)
RUN sed -i '/"fuzz"/d' Cargo.toml

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release -p nora-registry && \
    cp target/release/nora /nora && \
    strip /nora

# ── Binary export (for CI release artifacts) ───────────────────────────────
FROM scratch AS binary
COPY --from=builder /nora /nora

# ── RED OS (FSTEC-certified, RPM-based) ───────────────────────────────────
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4 AS redos

RUN microdnf install -y ca-certificates shadow-utils \
    && microdnf clean all \
    && groupadd -r nora && useradd -r -g nora -d /data -s /sbin/nologin nora \
    && mkdir -p /data && chown nora:nora /data

COPY --from=builder --chown=nora:nora /nora /usr/local/bin/nora

ENV RUST_LOG=info \
    NORA_HOST=0.0.0.0 \
    NORA_PORT=4000 \
    NORA_STORAGE_PATH=/data/storage \
    NORA_AUTH_TOKEN_STORAGE=/data/tokens

EXPOSE 4000
VOLUME ["/data"]
USER nora

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:4000/health || exit 1

ENTRYPOINT ["/usr/local/bin/nora"]
CMD ["serve"]

# ── Astra Linux SE (FSTEC-certified, Debian-based) ────────────────────────
FROM debian:bookworm-slim AS astra

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r nora && useradd -r -g nora -d /data -s /usr/sbin/nologin nora \
    && mkdir -p /data && chown nora:nora /data

COPY --from=builder --chown=nora:nora /nora /usr/local/bin/nora

ENV RUST_LOG=info \
    NORA_HOST=0.0.0.0 \
    NORA_PORT=4000 \
    NORA_STORAGE_PATH=/data/storage \
    NORA_AUTH_TOKEN_STORAGE=/data/tokens

EXPOSE 4000
VOLUME ["/data"]
USER nora

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:4000/health || exit 1

ENTRYPOINT ["/usr/local/bin/nora"]
CMD ["serve"]

# ── Alpine (default — must be last) ───────────────────────────────────────
FROM alpine:3.21

RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates \
    && addgroup -S nora && adduser -S -G nora nora \
    && mkdir -p /data && chown nora:nora /data

COPY --from=builder --chown=nora:nora /nora /usr/local/bin/nora

ENV RUST_LOG=info \
    NORA_HOST=0.0.0.0 \
    NORA_PORT=4000 \
    NORA_STORAGE_PATH=/data/storage \
    NORA_AUTH_TOKEN_STORAGE=/data/tokens

EXPOSE 4000
VOLUME ["/data"]
USER nora

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q --spider http://localhost:4000/health || exit 1

ENTRYPOINT ["/usr/local/bin/nora"]
CMD ["serve"]
