# syntax=docker/dockerfile:1.4
#
# Multi-stage build for NORA artifact registry.
# Compiles inside Alpine — musl version always matches runtime.
#
# Usage:
#   docker build .                                             # Alpine (default)
#   docker build --target redos .                              # RED OS
#   docker build --target astra .                              # Astra Linux SE
#   docker buildx build --target binary --output type=local,dest=out .      # amd64 binary
#   docker buildx build --target binary-arm64 --output type=local,dest=out .  # arm64 binary (cross-compiled)
#

# ── Build ──────────────────────────────────────────────────────────────────
FROM rust:1-alpine3.21 AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

# Pin the build toolchain: rustup reads rust-toolchain.toml and installs the
# exact channel, so the release binary is reproducible regardless of the base
# image's bundled rustc.
COPY rust-toolchain.toml ./
COPY Cargo.toml Cargo.lock ./
COPY nora-registry/ nora-registry/

# Exclude fuzz workspace member (requires C++ libfuzzer, not needed for binary)
RUN sed -i '/"fuzz"/d' Cargo.toml

ARG CARGO_FEATURES=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release -p nora-registry $CARGO_FEATURES && \
    cp target/release/nora /nora && \
    strip /nora

# ── Binary export (for CI release artifacts) ───────────────────────────────
FROM scratch AS binary
COPY --from=builder /nora /nora

# ── Cross-compile arm64 (runs natively on x86, no QEMU) ──────────────────
FROM rust:1-alpine3.21 AS cross-arm64

RUN apk add --no-cache musl-dev \
    && wget -qO- https://musl.cc/aarch64-linux-musl-cross.tgz | tar xz -C /opt

ENV PATH="/opt/aarch64-linux-musl-cross/bin:$PATH" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc

WORKDIR /build
# Pin the toolchain before adding the cross target so the target lands on the
# pinned channel (rust-toolchain.toml), keeping the arm64 build reproducible.
COPY rust-toolchain.toml ./
RUN rustup target add aarch64-unknown-linux-musl

COPY Cargo.toml Cargo.lock ./
COPY nora-registry/ nora-registry/
RUN sed -i '/"fuzz"/d' Cargo.toml

ARG CARGO_FEATURES=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --target aarch64-unknown-linux-musl -p nora-registry $CARGO_FEATURES && \
    cp target/aarch64-unknown-linux-musl/release/nora /nora && \
    aarch64-linux-musl-strip /nora

FROM scratch AS binary-arm64
COPY --from=cross-arm64 /nora /nora

# ── RED OS (FSTEC-certified, RPM-based) ───────────────────────────────────
FROM registry.red-soft.ru/ubi8/ubi-minimal AS redos

RUN microdnf install -y ca-certificates shadow-utils curl \
    && microdnf clean all \
    && groupadd -r nora && useradd -r -g nora -d /data -s /sbin/nologin nora \
    && mkdir -p /data && chown nora:nora /data

COPY --from=builder --chown=nora:nora /nora /usr/local/bin/nora

ENV RUST_LOG=info \
    NORA_HOST=:: \
    NORA_PORT=4000 \
    NORA_PUBLIC_URL=http://localhost:4000 \
    NORA_STORAGE_PATH=/data/storage \
    NORA_AUTH_TOKEN_STORAGE=/data/tokens

EXPOSE 4000
VOLUME ["/data"]
USER nora

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/nora", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/nora"]
CMD ["serve"]

# ── Astra Linux SE (FSTEC-certified, Debian-based) ────────────────────────
FROM registry.astralinux.ru/library/astra/ubi17:latest AS astra

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r nora && useradd -r -g nora -d /data -s /usr/sbin/nologin nora \
    && mkdir -p /data && chown nora:nora /data

COPY --from=builder --chown=nora:nora /nora /usr/local/bin/nora

ENV RUST_LOG=info \
    NORA_HOST=:: \
    NORA_PORT=4000 \
    NORA_PUBLIC_URL=http://localhost:4000 \
    NORA_STORAGE_PATH=/data/storage \
    NORA_AUTH_TOKEN_STORAGE=/data/tokens

EXPOSE 4000
VOLUME ["/data"]
USER nora

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/nora", "healthcheck"]

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
    NORA_HOST=:: \
    NORA_PORT=4000 \
    NORA_PUBLIC_URL=http://localhost:4000 \
    NORA_STORAGE_PATH=/data/storage \
    NORA_AUTH_TOKEN_STORAGE=/data/tokens

EXPOSE 4000
VOLUME ["/data"]
USER nora

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/nora", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/nora"]
CMD ["serve"]
