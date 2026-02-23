# syntax=docker/dockerfile:1.4
# Binary is pre-built by CI (cargo build --release) and passed via context
FROM alpine:3.20

RUN apk add --no-cache ca-certificates && mkdir -p /data

COPY nora /usr/local/bin/nora

ENV RUST_LOG=info
ENV NORA_HOST=0.0.0.0
ENV NORA_PORT=4000
ENV NORA_STORAGE_MODE=local
ENV NORA_STORAGE_PATH=/data/storage
ENV NORA_AUTH_TOKEN_STORAGE=/data/tokens

EXPOSE 4000

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/nora"]
CMD ["serve"]
