---
title: Configuration Reference
description: Complete reference for all NORA configuration options
---


NORA uses a layered configuration model with three levels of priority:

1. **Environment variables** (highest priority)
2. **config.toml** file
3. **Built-in defaults** (lowest priority)

Config file resolution order:
- `NORA_CONFIG_PATH` env var (fatal error if set but file not found)
- `config.toml` in the current working directory (optional)
- Built-in defaults if no file is found

---

## Environment Variables

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_HOST` | `127.0.0.1` | Bind address |
| `NORA_PORT` | `4000` | Listen port |
| `NORA_PUBLIC_URL` | *(none)* | Public URL for generated download links (e.g., `https://registry.example.com`). **Required** when `NORA_HOST` is `0.0.0.0` or when behind a reverse proxy, otherwise clients receive unreachable URLs in Cargo, PyPI, npm, NuGet, and Terraform responses. |
| `NORA_BODY_LIMIT_MB` | `2048` | Maximum request body size in MB |
| `NORA_CONFIG_PATH` | *(none)* | Path to config.toml file |

### Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_STORAGE_MODE` | `local` | Storage backend: `local` or `s3` |
| `NORA_STORAGE_PATH` | `data/storage` | Local storage directory |
| `NORA_STORAGE_S3_URL` | `http://127.0.0.1:9000` | S3-compatible endpoint URL |
| `NORA_STORAGE_BUCKET` | `registry` | S3 bucket name |
| `NORA_STORAGE_S3_ACCESS_KEY` | *(none)* | S3 access key |
| `NORA_STORAGE_S3_SECRET_KEY` | *(none)* | S3 secret key |
| `NORA_STORAGE_S3_REGION` | `us-east-1` | S3 region |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_AUTH_ENABLED` | `false` | Enable authentication |
| `NORA_AUTH_ANONYMOUS_READ` | `false` | Allow unauthenticated read (pull) access |
| `NORA_AUTH_HTPASSWD_FILE` | `users.htpasswd` | Path to htpasswd file |
| `NORA_AUTH_TOKEN_STORAGE` | `data/tokens` | Directory for API token storage |

### Registry Enable/Disable

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_DOCKER_ENABLED` | `true` | Enable Docker (OCI) registry |
| `NORA_MAVEN_ENABLED` | `true` | Enable Maven registry |
| `NORA_NPM_ENABLED` | `true` | Enable npm registry |
| `NORA_CARGO_ENABLED` | `true` | Enable Cargo (Rust) registry |
| `NORA_PYPI_ENABLED` | `true` | Enable PyPI (Python) registry |
| `NORA_GO_ENABLED` | `true` | Enable Go module proxy |
| `NORA_RAW_ENABLED` | `true` | Enable raw file storage |
| `NORA_GEMS_ENABLED` | `false` | Enable RubyGems registry |
| `NORA_TERRAFORM_ENABLED` | `false` | Enable Terraform provider registry |
| `NORA_ANSIBLE_ENABLED` | `false` | Enable Ansible Galaxy registry |
| `NORA_NUGET_ENABLED` | `false` | Enable NuGet registry |
| `NORA_PUB_ENABLED` | `false` | Enable Dart/Flutter pub registry |
| `NORA_CONAN_ENABLED` | `false` | Enable Conan (C/C++) registry |

### Maven

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_MAVEN_PROXIES` | `https://repo1.maven.org/maven2` | Upstream proxies. Format: `url1,url2` or `url1\|auth1,url2\|auth2` |
| `NORA_MAVEN_PROXY_TIMEOUT` | `30` | Proxy timeout in seconds |
| `NORA_MAVEN_CHECKSUM_VERIFY` | `true` | Verify uploaded checksums against server-computed values |
| `NORA_MAVEN_IMMUTABLE_RELEASES` | `true` | Prevent overwriting released (non-SNAPSHOT) artifacts |

### npm

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_NPM_PROXY` | `https://registry.npmjs.org` | Upstream npm registry |
| `NORA_NPM_PROXY_AUTH` | *(none)* | Upstream auth (`user:pass`) |
| `NORA_NPM_PROXY_TIMEOUT` | `30` | Proxy timeout in seconds |
| `NORA_NPM_METADATA_TTL` | `300` | Metadata cache TTL in seconds (0 = cache forever) |

### PyPI

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_PYPI_PROXY` | `https://pypi.org/simple/` | Upstream PyPI registry |
| `NORA_PYPI_PROXY_AUTH` | *(none)* | Upstream auth (`user:pass`) |
| `NORA_PYPI_PROXY_TIMEOUT` | `30` | Proxy timeout in seconds |

### Docker

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_DOCKER_PROXIES` | `https://registry-1.docker.io` | Upstream registries. Format: `url1,url2` or `url1\|auth1,url2\|auth2` |
| `NORA_DOCKER_PROXY_TIMEOUT` | `60` | Proxy timeout in seconds |

### Go

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_GO_PROXY` | `https://proxy.golang.org` | Upstream Go module proxy |
| `NORA_GO_PROXY_AUTH` | *(none)* | Upstream auth (`user:pass`) |
| `NORA_GO_PROXY_TIMEOUT` | `30` | Proxy timeout in seconds |
| `NORA_GO_PROXY_TIMEOUT_ZIP` | `120` | Timeout for .zip downloads in seconds |
| `NORA_GO_MAX_ZIP_SIZE` | `104857600` | Maximum module zip size in bytes (default 100MB) |

### Cargo

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_CARGO_PROXY` | `https://crates.io` | Upstream Cargo registry |
| `NORA_CARGO_PROXY_AUTH` | *(none)* | Upstream auth (`user:pass`) |
| `NORA_CARGO_PROXY_TIMEOUT` | `30` | Proxy timeout in seconds |

### Raw

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_RAW_MAX_FILE_SIZE` | `104857600` | Maximum file size in bytes (default 100MB) |
| `NORA_RAW_CACHE_CONTROL` | `no-cache` | `Cache-Control` header for GET/HEAD responses |

### RubyGems

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_GEMS_PROXY` | `https://rubygems.org` | Upstream RubyGems registry |
| `NORA_GEMS_PROXY_AUTH` | *(none)* | Upstream auth (`user:pass`) |
| `NORA_GEMS_PROXY_TIMEOUT` | `30` | Proxy timeout in seconds |
| `NORA_GEMS_INDEX_TTL` | `300` | Index cache TTL in seconds |

### Terraform

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_TERRAFORM_PROXY` | `https://registry.terraform.io` | Upstream Terraform registry |
| `NORA_TERRAFORM_PROXY_AUTH` | *(none)* | Upstream auth (`user:pass`) |
| `NORA_TERRAFORM_PROXY_TIMEOUT` | `30` | Proxy timeout in seconds |
| `NORA_TERRAFORM_PROXY_TIMEOUT_DOWNLOAD` | `120` | Timeout for binary downloads in seconds |

### Ansible Galaxy

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_ANSIBLE_PROXY` | `https://galaxy.ansible.com` | Upstream Galaxy server |
| `NORA_ANSIBLE_PROXY_AUTH` | *(none)* | Upstream auth (`user:pass`) |
| `NORA_ANSIBLE_PROXY_TIMEOUT` | `30` | Proxy timeout in seconds |

### NuGet

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_NUGET_PROXY` | `https://api.nuget.org` | Upstream NuGet API |
| `NORA_NUGET_PROXY_AUTH` | *(none)* | Upstream auth (`user:pass`) |
| `NORA_NUGET_PROXY_TIMEOUT` | `30` | Proxy timeout in seconds |
| `NORA_NUGET_METADATA_TTL` | `300` | Metadata cache TTL in seconds |

### Pub (Dart/Flutter)

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_PUB_PROXY` | `https://pub.dev` | Upstream pub registry |
| `NORA_PUB_PROXY_AUTH` | *(none)* | Upstream auth (`user:pass`) |
| `NORA_PUB_PROXY_TIMEOUT` | `30` | Proxy timeout in seconds |

### Conan (C/C++)

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_CONAN_PROXY` | `https://center2.conan.io` | Upstream Conan registry |
| `NORA_CONAN_PROXY_AUTH` | *(none)* | Upstream auth (`user:pass`) |
| `NORA_CONAN_PROXY_TIMEOUT` | `30` | Proxy timeout in seconds |
| `NORA_CONAN_PROXY_TIMEOUT_DOWNLOAD` | `120` | Timeout for binary downloads in seconds |
| `NORA_CONAN_METADATA_TTL` | `300` | Metadata cache TTL in seconds |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `NORA_RATE_LIMIT_AUTH_RPS` | `1` | Auth endpoint requests per second |
| `NORA_RATE_LIMIT_AUTH_BURST` | `5` | Auth endpoint burst size |
| `NORA_RATE_LIMIT_UPLOAD_RPS` | `200` | Upload requests per second |
| `NORA_RATE_LIMIT_UPLOAD_BURST` | `500` | Upload burst size |
| `NORA_RATE_LIMIT_GENERAL_RPS` | `100` | General requests per second |
| `NORA_RATE_LIMIT_GENERAL_BURST` | `200` | General burst size |

### Garbage Collection

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_GC_ENABLED` | `false` | Enable background GC |
| `NORA_GC_INTERVAL` | `86400` | Interval in seconds between GC runs (default 24h) |
| `NORA_GC_DRY_RUN` | `false` | Only report orphans without deleting |

### Retention

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_RETENTION_ENABLED` | `false` | Enable background retention |
| `NORA_RETENTION_INTERVAL` | `86400` | Interval in seconds between runs (default 24h) |
| `NORA_RETENTION_DRY_RUN` | `false` | Only report what would be deleted |

### Curation

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_CURATION_MODE` | `off` | Curation mode: `off`, `audit`, `enforce` |
| `NORA_CURATION_ON_FAILURE` | `closed` | Behavior on filter error: `closed` (block) or `open` (allow) |
| `NORA_CURATION_ALLOWLIST_PATH` | *(none)* | Path to allowlist JSON file |
| `NORA_CURATION_BLOCKLIST_PATH` | *(none)* | Path to blocklist JSON file |
| `NORA_CURATION_BYPASS_TOKEN` | *(none)* | Token to bypass curation checks |
| `NORA_CURATION_REQUIRE_INTEGRITY` | `false` | Require integrity metadata in allowlist entries |
| `NORA_CURATION_INTERNAL_NAMESPACES` | *(none)* | Comma-separated glob patterns for internal namespaces |
| `NORA_CURATION_MIN_RELEASE_AGE` | *(none)* | Global min release age (`7d`, `12h`, `2w`) |
| `NORA_CURATION_NPM_MIN_RELEASE_AGE` | *(none)* | npm-specific min release age override |
| `NORA_CURATION_PYPI_MIN_RELEASE_AGE` | *(none)* | PyPI-specific min release age override |
| `NORA_CURATION_CARGO_MIN_RELEASE_AGE` | *(none)* | Cargo-specific min release age override |
| `NORA_CURATION_GO_MIN_RELEASE_AGE` | *(none)* | Go-specific min release age override |
| `NORA_CURATION_DOCKER_MIN_RELEASE_AGE` | *(none)* | Docker-specific min release age override |

### Secrets

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_SECRETS_PROVIDER` | `env` | Secrets provider: `env`, `aws-secrets`, `vault`, `k8s` |
| `NORA_SECRETS_CLEAR_ENV` | `false` | Clear env vars after reading (env provider) |

---

## config.toml Reference

Below is a complete `config.toml` with all sections and their default values.

```toml
# =============================================================================
# Server
# =============================================================================
[server]
host = "127.0.0.1"
port = 4000
# public_url = "https://registry.example.com"  # Required when host = 0.0.0.0 or behind reverse proxy
body_limit_mb = 2048

# =============================================================================
# Storage
# =============================================================================
[storage]
mode = "local"          # "local" or "s3"
path = "data/storage"

# S3 settings (used when mode = "s3")
s3_url = "http://127.0.0.1:9000"
bucket = "registry"
# s3_access_key = ""
# s3_secret_key = ""
s3_region = "us-east-1"

# =============================================================================
# Authentication
# =============================================================================
[auth]
enabled = false
anonymous_read = false
htpasswd_file = "users.htpasswd"
token_storage = "data/tokens"

# =============================================================================
# Secrets
# =============================================================================
[secrets]
provider = "env"        # "env", "aws-secrets", "vault", "k8s"
clear_env = false

# =============================================================================
# Rate Limiting
# =============================================================================
[rate_limit]
enabled = true
auth_rps = 1
auth_burst = 5
upload_rps = 200
upload_burst = 500
general_rps = 100
general_burst = 200

# =============================================================================
# Docker (OCI) Registry
# =============================================================================
[docker]
enabled = true
proxy_timeout = 60

[[docker.upstreams]]
url = "https://registry-1.docker.io"
# auth = "user:pass"

# =============================================================================
# Maven Registry
# =============================================================================
[maven]
enabled = true
proxy_timeout = 30
checksum_verify = true
immutable_releases = true
proxies = ["https://repo1.maven.org/maven2"]

# Authenticated upstream example:
# [[maven.proxies]]
# url = "https://private.repo.com/maven2"
# auth = "user:pass"

# =============================================================================
# npm Registry
# =============================================================================
[npm]
enabled = true
proxy = "https://registry.npmjs.org"
# proxy_auth = "user:pass"
proxy_timeout = 30
metadata_ttl = 300

# =============================================================================
# Cargo (Rust) Registry
# =============================================================================
[cargo]
enabled = true
proxy = "https://crates.io"
# proxy_auth = "user:pass"
proxy_timeout = 30

# =============================================================================
# PyPI (Python) Registry
# =============================================================================
[pypi]
enabled = true
proxy = "https://pypi.org/simple/"
# proxy_auth = "user:pass"
proxy_timeout = 30

# =============================================================================
# Go Module Proxy
# =============================================================================
[go]
enabled = true
proxy = "https://proxy.golang.org"
# proxy_auth = "user:pass"
proxy_timeout = 30
proxy_timeout_zip = 120
max_zip_size = 104857600    # 100MB

# =============================================================================
# Raw File Storage
# =============================================================================
[raw]
enabled = true
max_file_size = 104857600   # 100MB
cache_control = "no-cache"

# =============================================================================
# RubyGems Registry
# =============================================================================
[gems]
enabled = false
proxy = "https://rubygems.org"
# proxy_auth = "user:pass"
proxy_timeout = 30
index_ttl = 300

# =============================================================================
# Terraform Provider Registry
# =============================================================================
[terraform]
enabled = false
proxy = "https://registry.terraform.io"
# proxy_auth = "user:pass"
proxy_timeout = 30
proxy_timeout_download = 120

# =============================================================================
# Ansible Galaxy Registry
# =============================================================================
[ansible]
enabled = false
proxy = "https://galaxy.ansible.com"
# proxy_auth = "user:pass"
proxy_timeout = 30

# =============================================================================
# NuGet Registry
# =============================================================================
[nuget]
enabled = false
proxy = "https://api.nuget.org"
# proxy_auth = "user:pass"
proxy_timeout = 30
metadata_ttl = 300

# =============================================================================
# Dart/Flutter Pub Registry
# =============================================================================
[pub_dart]
enabled = false
proxy = "https://pub.dev"
# proxy_auth = "user:pass"
proxy_timeout = 30

# =============================================================================
# Conan (C/C++) Registry
# =============================================================================
[conan]
enabled = false
proxy = "https://center2.conan.io"
# proxy_auth = "user:pass"
proxy_timeout = 30
proxy_timeout_download = 120
metadata_ttl = 300

# =============================================================================
# Garbage Collection
# =============================================================================
[gc]
enabled = false
interval = 86400        # 24 hours
dry_run = false

# =============================================================================
# Retention Policies
# =============================================================================
[retention]
enabled = false
interval = 86400        # 24 hours
dry_run = false

# Retention rules: registry = "*" applies to all formats
# [[retention.rules]]
# registry = "docker"
# keep_last = 10
# older_than_days = 90
# exclude_tags = ["latest", "v*"]

# [[retention.rules]]
# registry = "*"
# older_than_days = 180

# =============================================================================
# Curation (Package Access Control)
# =============================================================================
[curation]
mode = "off"                # "off", "audit", "enforce"
on_failure = "closed"       # "closed" (fail-safe) or "open" (fail-open)
# allowlist_path = "/etc/nora/allowlist.json"
# blocklist_path = "/etc/nora/blocklist.json"
# bypass_token = ""         # prefer NORA_CURATION_BYPASS_TOKEN env var
require_integrity = false
internal_namespaces = []    # e.g., ["@mycompany/**", "com.mycompany.**"]
```

---

## Configuration Priority

When the same setting is specified in multiple places, the highest-priority source wins:

```
ENV variable  >  config.toml  >  built-in default
```

For example, if `config.toml` sets `port = 8080` but `NORA_PORT=4000` is also set, NORA will listen on port 4000.

---

## Credential Security

NORA warns at startup if credentials (proxy auth, S3 keys) are found in `config.toml` in plaintext. Best practice is to pass credentials via environment variables or a secrets provider:

```bash
# Use env vars for credentials
export NORA_STORAGE_S3_ACCESS_KEY="your-key"
export NORA_STORAGE_S3_SECRET_KEY="your-secret"
export NORA_DOCKER_PROXIES="https://registry-1.docker.io|user:pass"
```

In Kubernetes, mount credentials from a Secret into the container environment instead of storing them in `config.toml`.

---

## See Also

- [Authentication](/configuration/authentication/) -- user management and API tokens
- [Curation](/configuration/curation/) -- package access control
- [Rate Limits](/configuration/rate-limits/) -- rate limiting tuning
- [Production Deployment](/deployment/production/) -- production deployment guide
