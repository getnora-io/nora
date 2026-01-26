# syntax=docker/dockerfile:1.4

# Build stage
FROM rust:1.83-alpine AS builder

RUN apk add --no-cache musl-dev curl

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY nora-registry/Cargo.toml nora-registry/
COPY nora-storage/Cargo.toml nora-storage/
COPY nora-cli/Cargo.toml nora-cli/

# Create dummy sources for dependency caching
RUN mkdir -p nora-registry/src nora-storage/src nora-cli/src && \
    echo "fn main() {}" > nora-registry/src/main.rs && \
    echo "fn main() {}" > nora-storage/src/main.rs && \
    echo "fn main() {}" > nora-cli/src/main.rs

# Build dependencies only (with cache)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --package nora-registry && \
    rm -rf nora-registry/src nora-storage/src nora-cli/src

# Copy real sources
COPY nora-registry/src nora-registry/src
COPY nora-storage/src nora-storage/src
COPY nora-cli/src nora-cli/src

# Build release binary (with cache)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    touch nora-registry/src/main.rs && \
    cargo build --release --package nora-registry && \
    cp /app/target/release/nora /usr/local/bin/nora

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy binary
COPY --from=builder /usr/local/bin/nora /usr/local/bin/nora

# Create data directory
RUN mkdir -p /data

# Default environment
ENV RUST_LOG=info
ENV NORA_HOST=0.0.0.0
ENV NORA_PORT=4000
ENV NORA_STORAGE_MODE=local
ENV NORA_STORAGE_PATH=/data/storage
ENV NORA_AUTH_TOKEN_STORAGE=/data/tokens

EXPOSE 4000

VOLUME ["/data"]

ENTRYPOINT ["nora"]
CMD ["serve"]
