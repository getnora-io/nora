# syntax=docker/dockerfile:1.4
# Binary is pre-built by CI (cargo build --release) and passed via context
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates \
    && addgroup -S nora && adduser -S -G nora nora \
    && mkdir -p /data && chown nora:nora /data

COPY --chown=nora:nora nora /usr/local/bin/nora

ENV RUST_LOG=info
ENV NORA_HOST=0.0.0.0
ENV NORA_PORT=4000
ENV NORA_STORAGE_PATH=/data/storage
ENV NORA_AUTH_TOKEN_STORAGE=/data/tokens

EXPOSE 4000

VOLUME ["/data"]

USER nora

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q --spider http://localhost:4000/health || exit 1

ENTRYPOINT ["/usr/local/bin/nora"]
CMD ["serve"]
