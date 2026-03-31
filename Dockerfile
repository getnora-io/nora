# syntax=docker/dockerfile:1.4
# Binary is pre-built by CI (cargo build --release) and passed via context
FROM alpine:3.20@sha256:a4f4213abb84c497377b8544c81b3564f313746700372ec4fe84653e4fb03805

RUN apk add --no-cache ca-certificates \
    && addgroup -S nora && adduser -S -G nora nora \
    && mkdir -p /data && chown nora:nora /data

COPY --chown=nora:nora nora /usr/local/bin/nora

ENV RUST_LOG=info
ENV NORA_HOST=0.0.0.0
ENV NORA_PORT=4000
ENV NORA_STORAGE_MODE=local
ENV NORA_STORAGE_PATH=/data/storage
ENV NORA_AUTH_TOKEN_STORAGE=/data/tokens

EXPOSE 4000

VOLUME ["/data"]

USER nora

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q --spider http://localhost:4000/health || exit 1

ENTRYPOINT ["/usr/local/bin/nora"]
CMD ["serve"]
