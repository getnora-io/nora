[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/getnora-io/nora)](https://github.com/getnora-io/nora/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/getnora-io/nora/ci.yml?label=CI)](https://github.com/getnora-io/nora/actions)
[![GHCR](https://img.shields.io/badge/ghcr.io-nora-blue?logo=github)](https://github.com/getnora-io/nora/pkgs/container/nora)
[![GitHub Stars](https://img.shields.io/github/stars/getnora-io/nora?style=flat&logo=github)](https://github.com/getnora-io/nora/stargazers)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Docs](https://img.shields.io/badge/docs-getnora.dev-green?logo=gitbook)](https://getnora.dev)
[![Telegram](https://img.shields.io/badge/Telegram-Community-blue?logo=telegram)](https://t.me/getnora)

> **Multi-protocol artifact registry that doesn't suck.**
>
> One binary. All protocols. Stupidly fast.

**32 MB** binary | **< 100 MB** RAM | **3s** startup | **5** protocols

## Features

- **Multi-Protocol Support**
  - Docker Registry v2
  - Maven repository (+ proxy to Maven Central)
  - npm registry (+ proxy to npmjs.org)
  - Cargo registry
  - PyPI index

- **Storage Backends**
  - Local filesystem (zero-config default)
  - S3-compatible (MinIO, AWS S3)

- **Production Ready**
  - Web UI with search and browse
  - Swagger UI API documentation
  - Prometheus metrics (`/metrics`)
  - Health checks (`/health`, `/ready`)
  - JSON structured logging
  - Graceful shutdown

- **Security**
  - Basic Auth (htpasswd + bcrypt)
  - Revocable API tokens with RBAC
  - ENV-based configuration (12-Factor)
  - SBOM (SPDX + CycloneDX) in every release
  - See [SECURITY.md](SECURITY.md) for vulnerability reporting

## Quick Start

### Docker (Recommended)

```bash
docker run -d -p 4000:4000 -v nora-data:/data ghcr.io/getnora-io/nora:latest
```

### From Source

```bash
cargo install nora-registry
nora
```

Open http://localhost:4000/ui/

## Usage

### Docker Images

```bash
# Tag and push
docker tag myapp:latest localhost:4000/myapp:latest
docker push localhost:4000/myapp:latest

# Pull
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

## Authentication

NORA supports Basic Auth (htpasswd) and revocable API tokens with RBAC.

### Quick Setup

```bash
# 1. Create htpasswd file with bcrypt
htpasswd -cbB users.htpasswd admin yourpassword
# Add more users:
htpasswd -bB users.htpasswd ci-user ci-secret

# 2. Start NORA with auth enabled
docker run -d -p 4000:4000 \
  -v nora-data:/data \
  -v ./users.htpasswd:/data/users.htpasswd \
  -e NORA_AUTH_ENABLED=true \
  ghcr.io/getnora-io/nora:latest

# 3. Verify
curl -u admin:yourpassword http://localhost:4000/v2/_catalog
```

### API Tokens (RBAC)

| Role | Pull/Read | Push/Write | Delete/Admin |
|------|-----------|------------|--------------|
| `read` | Yes | No | No |
| `write` | Yes | Yes | No |
| `admin` | Yes | Yes | Yes |

See [Authentication guide](https://getnora.dev/configuration/authentication/) for token management, Docker login, and CI/CD integration.

## CLI Commands

```bash
nora              # Start server
nora serve        # Start server (explicit)
nora backup -o backup.tar.gz
nora restore -i backup.tar.gz
nora migrate --from local --to s3
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_HOST` | 127.0.0.1 | Bind address |
| `NORA_PORT` | 4000 | Port |
| `NORA_STORAGE_MODE` | local | `local` or `s3` |
| `NORA_AUTH_ENABLED` | false | Enable authentication |
| `NORA_DOCKER_UPSTREAMS` | `https://registry-1.docker.io` | Docker upstreams (`url\|user:pass,...`) |

See [full configuration reference](https://getnora.dev/configuration/settings/) for all environment variables including storage, rate limiting, proxy auth, and secrets.

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
```

See [full config reference](https://getnora.dev/configuration/settings/) for rate limiting, secrets, proxy auth, and all options.

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

## TLS / HTTPS

NORA serves plain HTTP. Use a reverse proxy for TLS:

```
registry.example.com {
    reverse_proxy localhost:4000
}
```

For internal networks without TLS, configure Docker:

```json
// /etc/docker/daemon.json
{
  "insecure-registries": ["192.168.1.100:4000"]
}
```

See [TLS / HTTPS guide](https://getnora.dev/configuration/tls/) for Nginx, Traefik, and custom CA setup.

## FSTEC-Certified OS Builds

Dedicated builds for Astra Linux SE and RED OS are published as `-astra` and `-redos` tagged images in every [GitHub Release](https://github.com/getnora-io/nora/releases). Both use `scratch` base with statically-linked binary.

## Performance

| Metric | NORA | Nexus | JFrog |
|--------|------|-------|-------|
| Startup | < 3s | 30-60s | 30-60s |
| Memory | < 100 MB | 2-4 GB | 2-4 GB |
| Image Size | 32 MB | 600+ MB | 1+ GB |

## Roadmap

- **OIDC / Workload Identity** — zero-secret auth for GitHub Actions, GitLab CI
- **Online Garbage Collection** — non-blocking cleanup without registry downtime
- **Retention Policies** — declarative rules: keep last N tags, delete older than X days
- **Image Signing** — cosign/notation verification and policy enforcement
- **Replication** — push/pull sync between NORA instances

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Author

**Created and maintained by [DevITWay](https://github.com/devitway)**

- Website: [getnora.dev](https://getnora.dev)
- Telegram: [@DevITWay](https://t.me/DevITWay)
- GitHub: [@devitway](https://github.com/devitway)
- Email: devitway@gmail.com

## Contributing

NORA welcomes contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE)

Copyright (c) 2026 DevITWay

---

**🐿️ N○RA** - Organized like a chipmunk's stash | Built with Rust by [DevITWay](https://t.me/DevITWay)
