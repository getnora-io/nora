# NORA

**The artifact registry that grows with you.** Starts with `docker run`, scales with your needs.

```bash
docker run -d -p 4000:4000 -v nora-data:/data getnora/nora:latest
```

Open [http://localhost:4000/ui/](http://localhost:4000/ui/) — your registry is ready.

<p align="center">
  <img src=".github/assets/dashboard.png" alt="NORA Dashboard" width="960" />
</p>

## Why NORA

- **Zero-config** — single binary, no database, no dependencies. `docker run` and it works.
- **15 registries** — Docker, Maven, npm, PyPI, Cargo, Go, Raw, RubyGems, Terraform, Ansible Galaxy, NuGet, Pub (Dart/Flutter), Conan (C/C++), RPM (yum/dnf), Debian/APT.
- **Secure by default** — [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/getnora-io/nora), signed releases, SBOM, fuzz testing, 1200+ tests.

[![Release](https://img.shields.io/github/v/release/getnora-io/nora)](https://github.com/getnora-io/nora/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/nora)](https://artifacthub.io/packages/helm/nora/nora)
[![Docker Pulls](https://img.shields.io/docker/pulls/getnora/nora)](https://hub.docker.com/r/getnora/nora)

**< 30 MB** binary | **< 50 MB** RAM idle | **3s** startup | **15** registries

## Supported Registries

| Registry | Mount Point | Upstream Proxy | Pull (proxy/cache) | Push/Publish | Default Upstream | Cache Type | Auth | Notes |
|----------|------------|----------------|:---:|:---:|---|---|---|---|
| Docker Registry v2 | `/v2/` | Docker Hub, GHCR, any OCI, Helm OCI | ✅ | ✅ | `registry-1.docker.io` | immutable blobs + TTL manifest | ✓ | hosted + proxy; cache on when `docker.upstreams` non-empty (Docker Hub by default) |
| Maven | `/maven2/` | Maven Central, custom | ✅ | ✅ | `repo1.maven.org/maven2` | metadata (TTL) + artifacts (immutable) | ✓ | hosted + proxy |
| npm | `/npm/` | npmjs.org, custom | ✅ | ✅ | `registry.npmjs.org` | packuments (TTL) + tarball (immutable) | ✓ | hosted + proxy |
| Cargo | `/cargo/` | crates.io | ✅ | ✅ | `crates.io` (sparse index) | index (TTL) + `.crate` (immutable) | ✓ | hosted + proxy (sparse index) |
| PyPI | `/simple/` | pypi.org, custom | ✅ | ✅ | `pypi.org/simple/` | index (TTL) + files (immutable) | ✓ | hosted + proxy |
| Go Modules | `/go/` | proxy.golang.org, custom | ✅ | — | `proxy.golang.org` | `@v`/`@latest` (TTL) + `.info`/`.mod`/`.zip` (immutable) | ✓ | proxy only (modules immutable, push not in protocol) |
| Raw files | `/raw/` | — | ❌ | ✅ | — (no upstream) | — | ✓ | hosted only; conditional `PUT` (ETag/`If-Match` — local backend only; `If-None-Match: *` works on any backend) |
| RubyGems | `/gems/` | rubygems.org | ✅ | ❌ | `rubygems.org` | `specs`/`latest_specs`/`info` (TTL) + `gem`/`gemspec` (immutable) | ✓ | proxy only — `gem push` not implemented in NORA v1.1.0 |
| Terraform | `/terraform/` | registry.terraform.io | ✅ | — | `registry.terraform.io` | discovery (TTL) + providers (immutable) | ✓ | proxy only; requires `anonymous_read: true` (Terraform client sends no `Authorization`); geo-blocked for Yandex Cloud IPs → VLESS proxy needed |
| Ansible Galaxy | `/ansible/` | galaxy.ansible.com | ✅ | ❌ | `galaxy.ansible.com` | collection list/detail (TTL) + tarball (immutable) | ✓ | proxy only — `ansible-galaxy collection publish` not implemented |
| NuGet | `/nuget/` | api.nuget.org | ✅ | ❌ | `api.nuget.org` | registration/query (TTL) + `.nupkg`/`.nuspec` (immutable) | ✓ | proxy only — `dotnet nuget push` not implemented (no `PackagePublish/2.0.0` in service index) |
| Pub (Dart/Flutter) | `/pub/` | pub.dev | ✅ | ❌ | `pub.dev` | package metadata (TTL) + archive (immutable) | ✓ | proxy only — `dart pub publish` not implemented (no `/api/packages/versions/new` upload-URL endpoint) |
| Conan (C/C++) | `/conan/` | ConanCenter | ⚠️ | ❌ | `center2.conan.io` | revisions (TTL) + recipe/package files (immutable) | ✓ | v2 API works via curl (proxy/cache); Conan 2.x client does NOT work — v1 ping barrier (no `GET /conan/v1/ping`) |
| RPM (yum/dnf) | `/rpm/` | — (hosted, GPG-signed) | ⚠️ | ✅ | — (none by default) | packages (immutable) + repodata (regenerated) | ✓ | hosted; pull-through via `config.registries.rpm.proxies` (e.g. `fedora: https://download.fedoraproject.org/...`), off by default; auto-generates `repodata/` |
| Debian/APT | `/deb/` | — (hosted, GPG-signed) | ⚠️ | ✅ | — (none by default) | packages (immutable) + Packages/Release (regenerated) | ✓ | hosted; pull-through via `config.registries.deb.proxies` (e.g. `debian: https://deb.debian.org/debian`), off by default; flat & structured layouts; auto-generates `Packages`/`Release`/`InRelease` |

> **Helm charts** work via the Docker/OCI endpoint — `helm push`/`pull` with `--plain-http` or behind TLS reverse proxy.

> **Pull/Push legend:** ✅ supported · ⚠️ partial (pull-through available but off by default, or client compatibility issue) · ❌ not implemented in NORA v1.1.0 · — not applicable (protocol has no push). See [Usage](#usage) for per-format details.

## Quick Start

### Docker (Recommended)

```bash
docker run -d -p 4000:4000 -v nora-data:/data getnora/nora:latest
```

### Binary

```bash
# x86_64
curl -fsSL https://github.com/getnora-io/nora/releases/latest/download/nora-linux-amd64 -o nora

# ARM64 (Raspberry Pi, Graviton, Apple Silicon VMs)
curl -fsSL https://github.com/getnora-io/nora/releases/latest/download/nora-linux-arm64 -o nora

chmod +x nora && ./nora
```

`./nora` listens on `127.0.0.1:4000`. To expose it on a network, set the bind
address and the public URL clients should use for download links:

```bash
NORA_HOST=0.0.0.0 NORA_PUBLIC_URL=https://registry.example.com ./nora
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
- **Curation** — blocklist, allowlist, namespace isolation, integrity verification, min-release-age filter, digest quarantine
- **Token RBAC** — read/write/admin roles, expiry tracking, deferred last_used flush
- **Mirror CLI** — offline sync for air-gapped environments (`nora mirror`)
- **Backup & Restore** — `nora backup` / `nora restore`
- **S3 Storage** — AWS S3, Ceph RGW, any S3-compatible backend
- **Prometheus Metrics** — `/metrics` endpoint, [Grafana dashboard](MONITORING.md)
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
| Memory | < 50 MB idle | 2-4 GB | 2-4 GB |
| Binary | < 30 MB | 600+ MB | 1+ GB |

## Roadmap

- ~~Mirror CLI~~ ✅ v0.4.0
- ~~Garbage Collection & Retention~~ ✅ v0.6.0
- ~~Helm Chart~~ ✅ v0.6.1
- ~~Signed releases & SBOM~~ ✅ v0.6.4
- ~~Curation layer & 13 registry formats~~ ✅ v0.7.0
- ~~Min Release Age~~ ✅ v0.7.1
- ~~Hash Pin Store, auth rate limiting, Cache-Control~~ ✅ v0.8.0
- ~~Outbound proxy, structured audit log~~ ✅ v0.8.3
- ~~Circuit breaker, OIDC, hot reload, arm64, streaming uploads~~ ✅ v0.9.0
- ~~NuGet V3 stabilization, Cargo ETag, 1049 tests~~ ✅ v0.9.1
- ~~Prometheus metrics, Ansible Galaxy v3, security fixes, 1086 tests~~ ✅ v0.9.2
- ~~Security hardening, null byte protection, config refactor, 1204 tests~~ ✅ v0.9.3
- ~~Multi-upstream PyPI, conditional-request revalidation, single-flight coalescing, per-registry metrics~~ ✅ v0.9.4
- ~~Digest quarantine across all registries, trusted upstream dates, token access-control hardening~~ ✅ v0.9.5
- **Image Signing Policy** — cosign verification on upstream pulls
- **Semver contract** — stable API, configuration format, and storage layout

See [ROADMAP.md](ROADMAP.md) for the full roadmap and [CHANGELOG.md](CHANGELOG.md) for release history.

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
