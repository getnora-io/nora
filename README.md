<img src="logo.jpg" alt="NORA" height="120" />


[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/getnora-io/nora)](https://github.com/getnora-io/nora/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/getnora-io/nora/ci.yml?label=CI)](https://github.com/getnora-io/nora/actions)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
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
  - Revocable API tokens
  - ENV-based configuration (12-Factor)

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

Tokens support three roles: `read`, `write`, `admin`.

```bash
# Create a write token (30 days TTL)
curl -s -X POST http://localhost:4000/api/tokens \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword","role":"write","ttl_days":90,"description":"CI/CD"}'

# Use token with Docker
docker login localhost:4000 -u token -p nra_<token>

# Use token with curl
curl -H "Authorization: Bearer nra_<token>" http://localhost:4000/v2/_catalog

# List tokens
curl -s -X POST http://localhost:4000/api/tokens/list \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}'

# Revoke token by hash prefix
curl -s -X POST http://localhost:4000/api/tokens/revoke \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword","hash_prefix":"<first 16 chars>"}'
```

| Role | Pull/Read | Push/Write | Delete/Admin |
|------|-----------|------------|--------------|
| `read` | Yes | No | No |
| `write` | Yes | Yes | No |
| `admin` | Yes | Yes | Yes |

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
| `NORA_STORAGE_PATH` | data/storage | Local storage path |
| `NORA_STORAGE_S3_URL` | - | S3 endpoint URL |
| `NORA_STORAGE_BUCKET` | registry | S3 bucket name |
| `NORA_AUTH_ENABLED` | false | Enable authentication |
| `NORA_RATE_LIMIT_AUTH_RPS` | 1 | Auth requests per second |
| `NORA_RATE_LIMIT_AUTH_BURST` | 5 | Auth burst size |
| `NORA_RATE_LIMIT_UPLOAD_RPS` | 200 | Upload requests per second |
| `NORA_RATE_LIMIT_UPLOAD_BURST` | 500 | Upload burst size |
| `NORA_RATE_LIMIT_GENERAL_RPS` | 100 | General requests per second |
| `NORA_RATE_LIMIT_GENERAL_BURST` | 200 | General burst size |
| `NORA_SECRETS_PROVIDER` | env | Secrets provider (`env`) |
| `NORA_SECRETS_CLEAR_ENV` | false | Clear env vars after reading |

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

[rate_limit]
# Strict limits for authentication (brute-force protection)
auth_rps = 1
auth_burst = 5
# High limits for CI/CD upload workloads
upload_rps = 200
upload_burst = 500
# Balanced limits for general API endpoints
general_rps = 100
general_burst = 200

[secrets]
# Provider: env (default), aws-secrets, vault, k8s (coming soon)
provider = "env"
# Clear environment variables after reading (security hardening)
clear_env = false
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

- Website: [getnora.io](https://getnora.io)
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
