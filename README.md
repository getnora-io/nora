[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/getnora-io/nora)](https://github.com/getnora-io/nora/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/getnora-io/nora/ci.yml?label=CI)](https://github.com/getnora-io/nora/actions)
[![GHCR](https://img.shields.io/badge/ghcr.io-nora-blue?logo=github)](https://github.com/getnora-io/nora/pkgs/container/nora)
[![GitHub Stars](https://img.shields.io/github/stars/getnora-io/nora?style=flat&logo=github)](https://github.com/getnora-io/nora/stargazers)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Docs](https://img.shields.io/badge/docs-getnora.dev-green?logo=gitbook)](https://getnora.dev)
[![Telegram](https://img.shields.io/badge/Telegram-Community-blue?logo=telegram)](https://t.me/getnora)

> **Your Cloud-Native Artifact Registry**

Fast. Organized. Feel at Home.

**10x faster** than Nexus | **< 100 MB RAM** | **32 MB Docker image**

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

```

See [full config reference](https://getnora.dev/configuration/settings/) for rate limiting, secrets, and proxy settings.

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

NORA serves plain HTTP by design. **TLS is intentionally not built into the binary** — this is a deliberate architectural decision:

- **Single responsibility**: NORA manages artifacts, not certificates. Embedding TLS means bundling Let's Encrypt clients, certificate renewal logic, ACME challenges, and custom CA support — all of which already exist in battle-tested tools.
- **Operational simplicity**: One place for certificates (reverse proxy), not scattered across every service. When a cert expires, you fix it in one config — not in NORA, Grafana, GitLab, and every other service separately.
- **Industry standard**: Docker Hub, GitHub Container Registry, AWS ECR, Harbor, Nexus — none of them terminate TLS in the registry process. A reverse proxy in front is the universal pattern.
- **Zero-config internal use**: On trusted networks (lab, CI/CD), NORA works out of the box without generating self-signed certs or managing keystores.

### Production (recommended): reverse proxy with auto-TLS

```
Client → Caddy/Nginx (HTTPS, port 443) → NORA (HTTP, port 4000)
```

Caddy example:

```
registry.example.com {
    reverse_proxy localhost:4000
}
```

Nginx example:

```nginx
server {
    listen 443 ssl;
    server_name registry.example.com;
    ssl_certificate     /etc/letsencrypt/live/registry.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/registry.example.com/privkey.pem;
    client_max_body_size 0;  # unlimited for large image pushes
    location / {
        proxy_pass http://127.0.0.1:4000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Internal / Lab: insecure registry

If you run NORA without TLS (e.g., on a private network), configure Docker to trust it:

```json
// /etc/docker/daemon.json
{
  "insecure-registries": ["192.168.1.100:4000"]
}
```

Then restart Docker:

```bash
sudo systemctl restart docker
```

> **Note:** `insecure-registries` disables TLS verification for that host. Use only on trusted networks.

## FSTEC-Certified OS Builds

NORA provides dedicated Dockerfiles for Russian FSTEC-certified operating systems:

- `Dockerfile.astra` — Astra Linux SE (for government and defense sector)
- `Dockerfile.redos` — RED OS (for enterprise and public sector)

Both use `scratch` base with statically-linked binary for minimal attack surface. Comments in each file show how to switch to official distro base images if required by your security policy.

These builds are published as `-astra` and `-redos` tagged images in GitHub Releases.

## Performance

| Metric | NORA | Nexus | JFrog |
|--------|------|-------|-------|
| Startup | < 3s | 30-60s | 30-60s |
| Memory | < 100 MB | 2-4 GB | 2-4 GB |
| Image Size | 32 MB | 600+ MB | 1+ GB |

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
