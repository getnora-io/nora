# NORA

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Telegram](https://img.shields.io/badge/Telegram-DevITWay-blue?logo=telegram)](https://t.me/DevITWay)

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

## Performance

| Metric | NORA | Nexus | JFrog |
|--------|------|-------|-------|
| Startup | < 3s | 30-60s | 30-60s |
| Memory | < 100 MB | 2-4 GB | 2-4 GB |
| Image Size | 32 MB | 600+ MB | 1+ GB |

## Author

**Created and maintained by [DevITWay](https://github.com/devitway)**

- Website: [devopsway.ru](https://devopsway.ru)
- Telegram: [@DevITWay](https://t.me/DevITWay)
- GitHub: [@devitway](https://github.com/devitway)
- Email: devitway@gmail.com

## Contributing

NORA welcomes contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE)

Copyright (c) 2026 DevITWay

---

**NORA** - Organized like a chipmunk's stash | Built with Rust by [DevITWay](https://t.me/DevITWay)
