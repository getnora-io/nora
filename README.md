# NORA

**The artifact registry that grows with you.** Starts with `docker run`, scales to enterprise.

```bash
docker run -d -p 4000:4000 -v nora-data:/data getnora/nora:latest
```

Open [http://localhost:4000/ui/](http://localhost:4000/ui/) — your registry is ready.

<p align="center">
  <img src=".github/assets/dashboard.png" alt="NORA Dashboard" width="960" />
</p>

## Why NORA

- **Zero-config** — single binary, no database, no dependencies. `docker run` and it works.
- **13 registries** — Docker, Maven, npm, PyPI, Cargo, Go, Raw, RubyGems, Terraform, Ansible Galaxy, NuGet, Pub (Dart/Flutter), Conan (C/C++).
- **Secure by default** — [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/getnora-io/nora), signed releases, SBOM, fuzz testing, 900+ tests.

[![Release](https://img.shields.io/github/v/release/getnora-io/nora)](https://github.com/getnora-io/nora/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/nora)](https://artifacthub.io/packages/helm/nora/nora)
[![Docker Pulls](https://img.shields.io/docker/pulls/getnora/nora)](https://hub.docker.com/r/getnora/nora)

**< 23 MB** binary | **< 100 MB** RAM | **3s** startup | **13** registries

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
docker run -d -p 4000:4000 -v nora-data:/data getnora/nora:latest
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

### From Source

```bash
cargo install nora-registry
nora
```

## Usage

```bash
# Docker
docker tag myapp:latest localhost:4000/myapp:latest
docker push localhost:4000/myapp:latest

# npm
npm config set registry http://localhost:4000/npm/
npm publish

# Go
GOPROXY=http://localhost:4000/go go get golang.org/x/text@latest
```

See [full documentation](https://getnora.dev) for all registries.

## Features

- **Web UI** — dashboard with search, browse, i18n (EN/RU)
- **Proxy & Cache** — transparent proxy to upstream registries with local cache
- **Curation** — blocklist, allowlist, namespace isolation, integrity verification, min-release-age filter
- **Token RBAC** — read/write/admin roles, expiry tracking, deferred last_used flush
- **Mirror CLI** — offline sync for air-gapped environments (`nora mirror`)
- **Backup & Restore** — `nora backup` / `nora restore`
- **S3 Storage** — AWS S3, Ceph RGW, any S3-compatible backend
- **Prometheus Metrics** — `/metrics` endpoint
- **Rate Limiting** — configurable per-endpoint rate limits

## Configuration

NORA works out of the box. For advanced setup — auth, S3, retention, curation — see [getnora.dev/configuration](https://getnora.dev/configuration/settings/).

```bash
# Auth
docker run -d -p 4000:4000 \
  -v nora-data:/data \
  -v ./users.htpasswd:/data/users.htpasswd \
  -e NORA_AUTH_ENABLED=true \
  getnora/nora:latest
```

```bash
# Curation — block packages younger than 7 days
docker run -d -p 4000:4000 \
  -v nora-data:/data \
  -e NORA_CURATION_MODE=enforce \
  -e NORA_CURATION_MIN_RELEASE_AGE=7d \
  -e NORA_CURATION_ALLOWLIST_PATH=/data/allowlist.json \
  getnora/nora:latest
```

## Performance

| Metric | NORA | Nexus | JFrog |
|--------|------|-------|-------|
| Startup | < 3s | 30-60s | 30-60s |
| Memory | < 100 MB | 2-4 GB | 2-4 GB |
| Binary | < 23 MB | 600+ MB | 1+ GB |

## Roadmap

- ~~Mirror CLI~~ ✅ v0.4.0
- ~~Garbage Collection & Retention~~ ✅ v0.6.0
- ~~Helm Chart~~ ✅ v0.6.1
- ~~Signed releases & SBOM~~ ✅ v0.6.4
- ~~Curation layer~~ ✅ v0.7.0
- ~~13 registry formats~~ ✅ v0.7.0
- ~~Min Release Age~~ ✅ v0.7.1
- **OIDC / Workload Identity** — zero-secret auth for GitHub Actions, GitLab CI
- **Image Signing Policy** — cosign verification on upstream pulls

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Security & Trust

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/getnora-io/nora/badge)](https://scorecard.dev/viewer/?uri=github.com/getnora-io/nora)
[![CII Best Practices](https://www.bestpractices.dev/projects/12207/badge)](https://www.bestpractices.dev/projects/12207)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/devitway/0f0538f1ed16d5d9951e4f2d3f79b699/raw/nora-coverage.json)](https://github.com/getnora-io/nora/actions/workflows/ci.yml)
[![CI](https://img.shields.io/github/actions/workflow/status/getnora-io/nora/ci.yml?label=CI)](https://github.com/getnora-io/nora/actions)

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Documentation

Full documentation: **https://getnora.dev**

## Author

Created and maintained by [Pavel Volkov](https://github.com/devitway)

[![Docs](https://img.shields.io/badge/docs-getnora.dev-green?logo=gitbook)](https://getnora.dev)
[![Telegram](https://img.shields.io/badge/Telegram-Community-blue?logo=telegram)](https://t.me/getnora)
[![GitHub Stars](https://img.shields.io/github/stars/getnora-io/nora?style=flat&logo=github)](https://github.com/getnora-io/nora/stargazers)

## Contributing

NORA welcomes contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [LICENSE](LICENSE)

Copyright (c) 2026 The NORA Authors
