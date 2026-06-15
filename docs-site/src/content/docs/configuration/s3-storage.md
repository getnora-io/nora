---
title: S3 Storage
description: Configure NORA to use S3-compatible object storage (MinIO, RustFS, SeaweedFS, Garage, AWS S3)
---

By default NORA stores artifacts on the local filesystem. For production deployments you can switch to any S3-compatible backend — AWS S3, MinIO, RustFS, Ceph RGW, and others.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_STORAGE_MODE` | `local` | Set to `s3` to enable object storage |
| `NORA_STORAGE_S3_URL` | — | S3-compatible endpoint URL (e.g. `http://minio:9000`) |
| `NORA_STORAGE_BUCKET` | `registry` | Bucket name. Must exist before NORA starts |
| `NORA_STORAGE_S3_ACCESS_KEY` | — | Access key. If omitted, anonymous access is used |
| `NORA_STORAGE_S3_SECRET_KEY` | — | Secret key |
| `NORA_STORAGE_S3_REGION` | `us-east-1` | Region. Required by some S3 implementations |

:::caution
NORA **does not create buckets automatically**. The bucket must exist before NORA starts. Use an init container or pre-create it manually.
:::

:::danger[Silent fallback]
If S3 environment variable names are misspelled, NORA silently falls back to local storage. Double-check your variable names if artifacts appear in `data/storage/` instead of your bucket.
:::

## MinIO

MinIO is the most popular self-hosted S3-compatible storage. This example includes an init container that creates the bucket automatically.

### Docker Compose

```yaml
services:
  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: noraadmin
      MINIO_ROOT_PASSWORD: changeme-minio-secret
    ports:
      - 9000:9000   # S3 API
      - 9001:9001   # MinIO Console
    volumes:
      - minio-data:/data
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 5s
      timeout: 5s
      retries: 5

  createbucket:
    image: minio/mc:latest
    depends_on:
      minio:
        condition: service_healthy
    entrypoint: >
      /bin/sh -c "
      mc alias set myminio http://minio:9000 noraadmin changeme-minio-secret;
      mc mb --ignore-existing myminio/nora-storage;
      exit 0;
      "

  nora:
    image: ghcr.io/getnora-io/nora:latest
    depends_on:
      createbucket:
        condition: service_completed_successfully
    environment:
      NORA_HOST: "0.0.0.0"
      NORA_STORAGE_MODE: s3
      NORA_STORAGE_S3_URL: http://minio:9000
      NORA_STORAGE_BUCKET: nora-storage
      NORA_STORAGE_S3_ACCESS_KEY: noraadmin
      NORA_STORAGE_S3_SECRET_KEY: changeme-minio-secret
      NORA_STORAGE_S3_REGION: us-east-1
    ports:
      - 4000:4000
    restart: unless-stopped

volumes:
  minio-data:
```

### Verify

```bash
# Push a Docker image
docker tag alpine:latest localhost:4000/test/alpine:latest
docker push localhost:4000/test/alpine:latest

# Pull it back
docker rmi localhost:4000/test/alpine:latest
docker pull localhost:4000/test/alpine:latest

# Upload a raw file
curl -X PUT -d "hello s3" http://localhost:4000/raw/test/hello.txt
curl http://localhost:4000/raw/test/hello.txt
```

Check MinIO Console at `http://localhost:9001` — you should see objects in the `nora-storage` bucket.

## RustFS

[RustFS](https://github.com/rustfs/rustfs) is a lightweight S3-compatible storage written in Rust. Configuration is identical to MinIO with one difference: the health check endpoint is `/health` instead of `/minio/health/live`.

### Docker Compose

```yaml
services:
  rustfs:
    image: rustfs/rustfs:latest
    command: server /data --console-address ":9001"
    environment:
      RUSTFS_ROOT_USER: noraadmin
      RUSTFS_ROOT_PASSWORD: changeme-rustfs-secret
    ports:
      - 9000:9000   # S3 API
      - 9001:9001   # Console
    volumes:
      - rustfs-data:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/health"]
      interval: 5s
      timeout: 5s
      retries: 5

  createbucket:
    image: minio/mc:latest
    depends_on:
      rustfs:
        condition: service_healthy
    entrypoint: >
      /bin/sh -c "
      mc alias set myrustfs http://rustfs:9000 noraadmin changeme-rustfs-secret;
      mc mb --ignore-existing myrustfs/nora-storage;
      exit 0;
      "

  nora:
    image: ghcr.io/getnora-io/nora:latest
    depends_on:
      createbucket:
        condition: service_completed_successfully
    environment:
      NORA_HOST: "0.0.0.0"
      NORA_STORAGE_MODE: s3
      NORA_STORAGE_S3_URL: http://rustfs:9000
      NORA_STORAGE_BUCKET: nora-storage
      NORA_STORAGE_S3_ACCESS_KEY: noraadmin
      NORA_STORAGE_S3_SECRET_KEY: changeme-rustfs-secret
      NORA_STORAGE_S3_REGION: us-east-1
    ports:
      - 4000:4000
    restart: unless-stopped

volumes:
  rustfs-data:
```

:::tip
RustFS is API-compatible with MinIO — `minio/mc` works as the bucket management CLI.
:::

## AWS S3

For AWS S3, point `NORA_STORAGE_S3_URL` to the regional endpoint:

```yaml
environment:
  NORA_STORAGE_MODE: s3
  NORA_STORAGE_S3_URL: https://s3.eu-central-1.amazonaws.com
  NORA_STORAGE_BUCKET: my-nora-registry
  NORA_STORAGE_S3_ACCESS_KEY: AKIA...
  NORA_STORAGE_S3_SECRET_KEY: wJal...
  NORA_STORAGE_S3_REGION: eu-central-1
```

:::tip
Use IAM roles instead of static credentials when running on EC2/ECS/EKS. Omit `NORA_STORAGE_S3_ACCESS_KEY` and `NORA_STORAGE_S3_SECRET_KEY` — the AWS SDK will use instance metadata automatically.
:::

## SeaweedFS

[SeaweedFS](https://github.com/seaweedfs/seaweedfs) is a distributed storage system with an S3-compatible gateway. It supports anonymous access by default — no access key required for single-node setups.

:::caution[Keys containing `@`]
SeaweedFS returns HTTP 500 for S3 keys containing `@`. NORA automatically encodes `@` to `_at_` in storage keys when using any S3 backend, so scoped npm packages (`@babel/core`) and Docker images with `@sha256:` digests work correctly.
:::

### Docker Compose

```yaml
services:
  seaweedfs:
    image: chrislusf/seaweedfs:latest
    command: server -s3 -s3.port=8333 -master.volumeSizeLimitMB=100
    ports:
      - 8333:8333   # S3 API
      - 9333:9333   # Master
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://127.0.0.1:9333/cluster/status"]
      interval: 5s
      timeout: 5s
      retries: 10

  createbucket:
    image: minio/mc:latest
    depends_on:
      seaweedfs:
        condition: service_healthy
    entrypoint: >
      sh -c "
      mc alias set sw http://seaweedfs:8333 '' '' --api S3v4;
      mc mb --ignore-existing sw/nora-storage;
      exit 0;
      "

  nora:
    image: ghcr.io/getnora-io/nora:latest
    depends_on:
      createbucket:
        condition: service_completed_successfully
    environment:
      NORA_HOST: "0.0.0.0"
      NORA_STORAGE_MODE: s3
      NORA_STORAGE_S3_URL: http://seaweedfs:8333
      NORA_STORAGE_BUCKET: nora-storage
      NORA_STORAGE_S3_REGION: us-east-1
    ports:
      - 4000:4000
    restart: unless-stopped
```

:::tip
SeaweedFS allows anonymous S3 access by default. You can omit `NORA_STORAGE_S3_ACCESS_KEY` and `NORA_STORAGE_S3_SECRET_KEY` for single-node development setups. For production, configure SeaweedFS IAM and provide credentials.
:::

## Garage

[Garage](https://garagehq.deuxfleurs.fr/) is a lightweight, self-hosted S3-compatible storage designed for small-scale deployments. Unlike MinIO, Garage requires an initialization step to configure the cluster layout and create API keys via its admin API.

### Docker Compose

```yaml
services:
  garage:
    image: dxflrs/garage:v1.0.1
    environment:
      GARAGE_ALLOW_WORLD_READABLE_SECRETS: "true"
    ports:
      - 3900:3900   # S3 API
      - 3903:3903   # Admin API
    volumes:
      - garage-data:/var/lib/garage/data
      - garage-meta:/var/lib/garage/meta
      - ./garage.toml:/etc/garage.toml:ro
    healthcheck:
      test: ["CMD", "/garage", "stats", "-a"]
      interval: 5s
      timeout: 5s
      retries: 10
      start_period: 5s

  garage-init:
    image: alpine:latest
    depends_on:
      garage:
        condition: service_healthy
    volumes:
      - ./garage-init.sh:/garage-init.sh:ro
      - garage-creds:/creds
    entrypoint: ["/bin/sh", "/garage-init.sh"]

  nora:
    image: ghcr.io/getnora-io/nora:latest
    depends_on:
      garage-init:
        condition: service_completed_successfully
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        if [ -f /creds/env ]; then . /creds/env; fi
        exec /usr/local/bin/nora serve
    environment:
      NORA_HOST: "0.0.0.0"
      NORA_STORAGE_MODE: s3
      NORA_STORAGE_S3_URL: http://garage:3900
      NORA_STORAGE_BUCKET: nora-storage
      NORA_STORAGE_S3_REGION: garage
    volumes:
      - garage-creds:/creds:ro
    ports:
      - 4000:4000
    restart: unless-stopped

volumes:
  garage-data:
  garage-meta:
  garage-creds:
```

### garage.toml

```toml
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"

replication_factor = 1
rpc_bind_addr = "[::]:3901"
rpc_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[s3_api]
s3_region = "garage"
api_bind_addr = "[::]:3900"

[admin]
api_bind_addr = "[::]:3903"
admin_token = "changeme-admin-token"
```

### garage-init.sh

Garage generates API credentials dynamically via its admin API. This script creates a layout, an API key, a bucket, and exports the credentials to a shared volume so the NORA container can pick them up:

```bash
#!/bin/sh
set -e
apk add --no-cache curl jq >/dev/null 2>&1

ADMIN=http://garage:3903
AUTH="Authorization: Bearer changeme-admin-token"
CT="Content-Type: application/json"
sleep 2

# Assign node to layout
NODE_ID=$(curl -sf -H "$AUTH" "$ADMIN/v1/status" | jq -r '.node')
curl -sf -X POST -H "$AUTH" -H "$CT" "$ADMIN/v1/layout" \
  -d "[{\"id\":\"$NODE_ID\",\"zone\":\"dc1\",\"capacity\":1073741824,\"tags\":[]}]"
LAYOUT_VER=$(curl -sf -H "$AUTH" "$ADMIN/v1/layout" | jq '.version + 1')
curl -sf -X POST -H "$AUTH" -H "$CT" "$ADMIN/v1/layout/apply" \
  -d "{\"version\":$LAYOUT_VER}"

# Create API key
KEY_RESP=$(curl -sf -X POST -H "$AUTH" -H "$CT" "$ADMIN/v1/key" \
  -d '{"name":"nora-key"}')
KEY_ID=$(echo "$KEY_RESP" | jq -r '.accessKeyId')
KEY_SECRET=$(echo "$KEY_RESP" | jq -r '.secretAccessKey')

# Export credentials to shared volume
cat > /creds/env <<EOF
export NORA_STORAGE_S3_ACCESS_KEY="${KEY_ID}"
export NORA_STORAGE_S3_SECRET_KEY="${KEY_SECRET}"
EOF

# Create bucket and grant access
BUCKET_ID=$(curl -sf -X POST -H "$AUTH" -H "$CT" "$ADMIN/v1/bucket" \
  -d '{"globalAlias":"nora-storage"}' | jq -r '.id')
curl -sf -X POST -H "$AUTH" -H "$CT" "$ADMIN/v1/bucket/allow" \
  -d "{\"bucketId\":\"$BUCKET_ID\",\"accessKeyId\":\"$KEY_ID\",\"permissions\":{\"read\":true,\"write\":true,\"owner\":true}}"
```

:::note
Garage credentials are generated at init time, not pre-configured. The `garage-creds` shared volume passes them from the init container to NORA. The `entrypoint` override sources `/creds/env` before starting NORA.
:::

## config.toml

```toml
[storage]
mode = "s3"
s3_url = "http://minio:9000"
bucket = "nora-storage"
s3_access_key = "noraadmin"
s3_secret_key = "changeme"
s3_region = "us-east-1"
```

:::caution
Prefer environment variables over config.toml for credentials. NORA logs a warning if it detects plaintext secrets in the config file.
:::

## Troubleshooting

### NORA starts but artifacts go to local storage

Check `NORA_STORAGE_MODE` is set to exactly `s3` (lowercase). Any misspelling causes a silent fallback to local mode. Run:

```bash
docker exec nora env | grep NORA_STORAGE
```

You should see:

```
NORA_STORAGE_MODE=s3
NORA_STORAGE_S3_URL=http://minio:9000
NORA_STORAGE_BUCKET=nora-storage
...
```

### Connection refused to S3 endpoint

Ensure the S3 service is healthy before NORA starts. In Docker Compose, use `depends_on` with `condition: service_healthy`.

### Bucket does not exist

NORA does not create buckets. Pre-create with `mc mb` or an init container (see examples above).

### Proxied packages not visible in UI

Proxy-only downloads (Cargo, PyPI, Go, Maven, NuGet, Terraform, Conan, RubyGems, Pub) stream responses directly from upstream without storing them in S3. These packages will not appear in the web UI or in storage listings. Only published packages (via `npm publish`, `twine upload`, `cargo publish`, `docker push`, `curl -X PUT /raw/`) and cached tarballs (npm, Ansible) are persisted to storage.

## See Also

- [Settings](/configuration/settings/) — all configuration options
- [Production Guide](/deployment/production/) — deployment best practices
- [Docker Proxy](/configuration/docker-proxy/) — pull-through cache setup
