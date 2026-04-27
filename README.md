# NORA

**The artifact registry that grows with you.** Starts with `docker run`, scales to enterprise.

```bash
docker run -d -p 4000:4000 -v nora-data:/data ghcr.io/getnora-io/nora:latest
```

Open [http://localhost:4000/ui/](http://localhost:4000/ui/) — your registry is ready.

<p align="center">
  <img src=".github/assets/dashboard.png" alt="NORA Dashboard" width="960" />
</p>

## Why NORA

- **Zero-config** — single 32 MB binary, no database, no dependencies. `docker run` and it works.
- **Production-tested** — Docker (+ Helm OCI), Maven, npm, PyPI, Cargo, Go, Raw, RubyGems, Terraform, Ansible Galaxy, NuGet, Pub (Dart/Flutter), Conan (C/C++). Used in real CI/CD with ArgoCD, Buildx cache, and air-gapped environments.
- **Secure by default** — [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/getnora-io/nora), signed releases, SBOM, fuzz testing, 814 tests.

[![Release](https://img.shields.io/github/v/release/getnora-io/nora)](https://github.com/getnora-io/nora/releases)
[![Image Size](https://img.shields.io/badge/image-32%20MB-blue)](https://github.com/getnora-io/nora/pkgs/container/nora)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/nora)](https://artifacthub.io/packages/helm/nora/nora)

**32 MB** binary | **< 100 MB** RAM | **3s** startup | **13** registries

> Used in production at [DevIT Academy](https://github.com/devitway) since January 2026 for Docker images, Maven artifacts, and npm packages.

## Supported Registries

| Registry | Mount Point | Upstream Proxy | Auth |
|----------|------------|----------------|------|
| Docker Registry v2 | `/v2/` | Docker Hub, GHCR, any OCI, Helm OCI | ✓ |
| Maven | `/maven2/` | Maven Central, custom | ✓ |
| npm | `/npm/` | npmjs.org, custom | ✓ |
| Cargo | `/cargo/` | crates.io | ✓ |
| PyPI | `/simple/` | pypi.org, custom | ✓ |
| Go Modules | `/go/` | proxy.golang.org, custom | ✓ |
| Raw files | `/raw/` | — | ✓ |
| RubyGems | `/gems/` | rubygems.org | ✓ |
| Terraform | `/terraform/` | registry.terraform.io | ✓ |
| Ansible Galaxy | `/ansible/` | galaxy.ansible.com | ✓ |
| NuGet | `/nuget/` | api.nuget.org | ✓ |
| Pub (Dart/Flutter) | `/pub/` | pub.dev | ✓ |
| Conan (C/C++) | `/conan/` | ConanCenter | ✓ |

> **Helm charts** work via the Docker/OCI endpoint — `helm push`/`pull` with `--plain-http` or behind TLS reverse proxy.

## Quick Start

### Docker (Recommended)

```bash
docker run -d -p 4000:4000 -v nora-data:/data ghcr.io/getnora-io/nora:latest
```

### Binary

```bash
curl -fsSL https://github.com/getnora-io/nora/releases/latest/download/nora-linux-amd64 -o nora
chmod +x nora && ./nora
```

### Kubernetes (Helm)

```bash
helm repo add nora https://getnora-io.github.io/helm-charts
helm install nora nora/nora
```

See [chart documentation](https://github.com/getnora-io/helm-charts/tree/main/charts/nora) for configuration options.

### From Source

```bash
cargo install nora-registry
nora
```

## Usage

### Docker Images

```bash
docker tag myapp:latest localhost:4000/myapp:latest
docker push localhost:4000/myapp:latest
docker pull localhost:4000/myapp:latest
```

### Maven

```xml
<!-- settings.xml -->
<server>
  <id>nora</id>
  <url>http://localhost:4000/maven2/</url>
</server>
```

### npm

```bash
npm config set registry http://localhost:4000/npm/
npm publish
```

### Go Modules

```bash
GOPROXY=http://localhost:4000/go go get golang.org/x/text@latest
```

## Features

- **Web UI** — dashboard with search, browse, i18n (EN/RU)
- **Proxy & Cache** — transparent proxy to upstream registries with local cache
- **Mirror CLI** — offline sync for air-gapped environments (`nora mirror`)
- **Backup & Restore** — `nora backup` / `nora restore`
- **Migration** — `nora migrate --from local --to s3`
- **S3 Storage** — MinIO, AWS S3, any S3-compatible backend
- **Prometheus Metrics** — `/metrics` endpoint
- **Health Checks** — `/health`, `/ready` for Kubernetes probes
- **Swagger UI** — `/api-docs` for API exploration
- **Rate Limiting** — configurable per-endpoint rate limits
- **FSTEC Builds** — Astra Linux SE and RED OS images in every release

## Authentication

NORA supports Basic Auth (htpasswd) and revocable API tokens with RBAC.

```bash
# Create htpasswd file
htpasswd -cbB users.htpasswd admin yourpassword

# Start with auth enabled
docker run -d -p 4000:4000 \
  -v nora-data:/data \
  -v ./users.htpasswd:/data/users.htpasswd \
  -e NORA_AUTH_ENABLED=true \
  ghcr.io/getnora-io/nora:latest
```

| Role | Pull/Read | Push/Write | Delete/Admin |
|------|-----------|------------|--------------|
| `read` | Yes | No | No |
| `write` | Yes | Yes | No |
| `admin` | Yes | Yes | Yes |

See [Authentication guide](https://getnora.dev/configuration/authentication/) for token management, Docker login, and CI/CD integration.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_HOST` | 127.0.0.1 | Bind address |
| `NORA_PORT` | 4000 | Port |
| `NORA_STORAGE_MODE` | local | `local` or `s3` |
| `NORA_AUTH_ENABLED` | false | Enable authentication |
| `NORA_AUTH_ANONYMOUS_READ` | false | Allow unauthenticated read access |
| `NORA_DOCKER_PROXIES` | `https://registry-1.docker.io` | Docker upstreams for quick start (`url\|user:pass,...`). For production, use `config.toml` |
| `NORA_PUBLIC_URL` | — | Public URL for rewriting artifact links |
| `NORA_RATE_LIMIT_ENABLED` | true | Enable rate limiting |
| `NORA_RETENTION_ENABLED` | false | Enable background retention scheduler |
| `NORA_RETENTION_INTERVAL` | 86400 | Retention run interval in seconds |
| `NORA_CONFIG_PATH` | — | Path to config.toml (fatal if set but missing) |
| `NORA_STORAGE_PATH` | data/storage | Storage directory for local mode |
| `NORA_BODY_LIMIT_MB` | 512 | Max request body size in MB |
| `NORA_GC_ENABLED` | false | Enable background garbage collection |
| `NORA_GC_INTERVAL` | 86400 | GC run interval in seconds |
| `NORA_GC_DRY_RUN` | true | Log only, do not delete |
| `NORA_RETENTION_DRY_RUN` | true | Log only, do not delete |
| `NORA_STORAGE_S3_URL` | — | S3 endpoint URL (for `s3` storage mode) |
| `NORA_STORAGE_BUCKET` | nora | S3 bucket name |
| `NORA_RAW_ENABLED` | true | Enable raw file storage |
| `NORA_RAW_MAX_FILE_SIZE` | 104857600 | Max raw file size in bytes (100 MB) |

See [full configuration reference](https://getnora.dev/configuration/settings/) for all options.

### config.toml

```toml
[server]
host = "0.0.0.0"
port = 4000

[storage]
mode = "local"
path = "data/storage"

[auth]
enabled = false
htpasswd_file = "users.htpasswd"

[docker]
proxy_timeout = 60

[[docker.upstreams]]
url = "https://registry-1.docker.io"

[[docker.upstreams]]
url = "https://private.registry.io"
auth = "user:token"

[go]
proxy = "https://proxy.golang.org"

[gc]
enabled = true        # background GC scheduler
interval = 86400      # run every 24h
dry_run = false       # true = log only, no deletions

[retention]
enabled = true        # background retention scheduler
interval = 86400      # run every 24h
dry_run = false       # true = log only, no deletions

[[retention.rules]]
registry = "docker"
keep_last = 10

[[retention.rules]]
registry = "maven"
keep_last = 5
older_than_days = 90
```

## CLI Commands

```bash
nora serve                  # Start server
nora gc                     # Show orphaned blobs (dry-run)
nora gc --apply             # Delete orphaned blobs
nora retention-plan         # Show what retention would delete (dry-run)
nora retention-apply --yes  # Apply retention policies
nora backup -o backup.tar.gz
nora restore -i backup.tar.gz
nora migrate --from local --to s3
nora mirror npm --lockfile package-lock.json     # Mirror npm from lockfile
nora mirror npm --packages express,lodash        # Mirror specific npm packages
nora mirror pip --lockfile requirements.txt      # Mirror Python packages
nora mirror cargo --lockfile Cargo.lock          # Mirror Cargo crates
nora mirror maven --lockfile deps.txt            # Mirror Maven artifacts
nora mirror docker --images alpine:3.20,nginx    # Mirror Docker images
```

## Endpoints

| URL | Description |
|-----|-------------|
| `/ui/` | Web UI |
| `/api-docs` | Swagger UI |
| `/health` | Health check |
| `/ready` | Readiness probe |
| `/metrics` | Prometheus metrics |
| `/v2/` | Docker Registry |
| `/maven2/` | Maven |
| `/npm/` | npm |
| `/cargo/` | Cargo |
| `/simple/` | PyPI |
| `/go/` | Go Modules |
| `/raw/` | Raw files |
| `/gems/` | RubyGems |
| `/terraform/` | Terraform |
| `/ansible/` | Ansible Galaxy |
| `/nuget/` | NuGet |
| `/pub/` | Pub (Dart/Flutter) |
| `/conan/` | Conan (C/C++) |

## TLS / HTTPS

NORA serves plain HTTP. Use a reverse proxy for TLS:

```
registry.example.com {
    reverse_proxy localhost:4000
}
```

See [TLS / HTTPS guide](https://getnora.dev/configuration/tls/) for Nginx, Traefik, and custom CA setup.

## Performance

| Metric | NORA | Nexus | JFrog |
|--------|------|-------|-------|
| Startup | < 3s | 30-60s | 30-60s |
| Memory | < 100 MB | 2-4 GB | 2-4 GB |
| Image Size | 32 MB | 600+ MB | 1+ GB |

[See how NORA compares to other registries](https://getnora.dev)

## Roadmap

- ~~**Mirror CLI** — offline sync for air-gapped environments~~ ✅ v0.4.0
- ~~**Online Garbage Collection** — non-blocking cleanup without registry downtime~~ ✅ v0.6.0
- ~~**Retention Policies** — declarative rules: keep last N tags, delete older than X days~~ ✅ v0.6.0
- ~~**Helm Chart** — official chart for Kubernetes deployment~~ ✅ v0.6.1
- ~~**Signed releases** — cosign keyless signing and SLSA provenance~~ ✅ v0.6.4
- **Token management UI** — CRUD for API tokens in the web interface *(v0.7)*
- **SBOM** — CycloneDX generation in release pipeline *(v0.7)*

### Post-1.0

- **OIDC / Workload Identity** — zero-secret auth for GitHub Actions, GitLab CI
- **Image Signing Policy** — cosign verification and enforcement on upstream pulls
- **Curation** — package blocklist, minimum release age, scope protection

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Security & Trust

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/getnora-io/nora/badge)](https://scorecard.dev/viewer/?uri=github.com/getnora-io/nora)
[![CII Best Practices](https://www.bestpractices.dev/projects/12207/badge)](https://www.bestpractices.dev/projects/12207)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/devitway/0f0538f1ed16d5d9951e4f2d3f79b699/raw/nora-coverage.json)](https://github.com/getnora-io/nora/actions/workflows/ci.yml)
[![CI](https://img.shields.io/github/actions/workflow/status/getnora-io/nora/ci.yml?label=CI)](https://github.com/getnora-io/nora/actions)

- **Signed releases** — every release is signed with [cosign](https://github.com/sigstore/cosign)
- **SBOM** — SPDX + CycloneDX in every release
- **Fuzz testing** — cargo-fuzz + ClusterFuzzLite
- **Blob verification** — SHA256 digest validation on every upload
- **Non-root containers** — all images run as non-root
- **Security headers** — CSP, X-Frame-Options, nosniff

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Documentation

Full documentation: **https://getnora.dev**

> The `docs/` directory has been removed. All documentation lives on getnora.dev.
> Configuration reference: [getnora.dev/configuration/settings](https://getnora.dev/configuration/settings/)
> Source of truth for env vars: `nora-registry/src/config.rs` → `apply_env_overrides()`

## Author

Created and maintained by [Pavel Volkov](https://github.com/devitway)

[![GHCR](https://img.shields.io/badge/ghcr.io-nora-blue?logo=github)](https://github.com/getnora-io/nora/pkgs/container/nora)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Docs](https://img.shields.io/badge/docs-getnora.dev-green?logo=gitbook)](https://getnora.dev)
[![Telegram](https://img.shields.io/badge/Telegram-Community-blue?logo=telegram)](https://t.me/getnora)
[![GitHub Stars](https://img.shields.io/github/stars/getnora-io/nora?style=flat&logo=github)](https://github.com/getnora-io/nora/stargazers)

- Website: [getnora.dev](https://getnora.dev)
- Telegram: [@getnora](https://t.me/getnora)
- GitHub: [@devitway](https://github.com/devitway)

## Contributing

NORA welcomes contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE)

Copyright (c) 2026 The NORA Authors
