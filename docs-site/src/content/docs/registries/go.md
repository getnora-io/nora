---
title: Go Modules
description: Go module proxy (GOPROXY protocol).
---

The Go Modules registry provides a transparent caching proxy for Go modules using the [GOPROXY protocol](https://go.dev/ref/mod#module-proxy). Module metadata and zip archives are fetched from an upstream proxy on first request and served from local storage on subsequent requests.

## Client Configuration

Point `GOPROXY` at NORA before the fallback:

```bash
export GOPROXY=http://nora.example.com:4000/go/,direct
go get github.com/your/module@v1.2.3
```

To make the setting permanent, add it to your shell profile or `~/.config/go/env`:

```bash
go env -w GOPROXY=http://nora.example.com:4000/go/,direct
```

In a CI environment (e.g. GitLab CI):

```yaml
variables:
  GOPROXY: "http://nora.example.com:4000/go/,direct"
```

## Upstream Proxy

By default, NORA proxies to the public Go module proxy (`https://proxy.golang.org`). To use a private or alternative proxy:

```bash
export NORA_GO_PROXY=https://goproxy.internal.example.com
export NORA_GO_PROXY_AUTH=user:password
```

Module path escaping follows the GOPROXY spec: capital letters in import paths are encoded as `!x` (lowercase), for example `github.com/Azure/azure-sdk-go` is stored under `github.com/!azure/azure-sdk-go`.

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Version list | Full | `/@v/list` |
| Version metadata | Full | `/@v/{ver}.info` |
| go.mod fetch | Full | `/@v/{ver}.mod` |
| Module zip download | Full | Immutable cache |
| Latest version query | Full | `/@latest` |
| Module upload | -- | Proxy-only (read) |
| Sum database | -- | Client-side (`GONOSUMDB`) |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_GO_ENABLED` | Enable Go Modules registry | `true` |
| `NORA_GO_PROXY` | Upstream Go proxy URL | `https://proxy.golang.org` |
| `NORA_GO_PROXY_AUTH` | Upstream auth (`user:pass`) | *(none)* |
| `NORA_GO_PROXY_TIMEOUT` | Proxy timeout in seconds | `30` |
| `NORA_GO_PROXY_TIMEOUT_ZIP` | Timeout for zip downloads in seconds | `120` |
| `NORA_GO_METADATA_TTL` | TTL in seconds for `@v/list` and `@latest` | `300` |
| `NORA_GO_MAX_ZIP_SIZE` | Maximum module zip size in bytes | `104857600` |

**config.toml:**

```toml
[go]
enabled = true
proxy = "https://proxy.golang.org"
# proxy_auth = "user:pass"
proxy_timeout = 30
proxy_timeout_zip = 120
metadata_ttl = 300
max_zip_size = 104857600
```

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/go/{module}/@v/list` | GET | List known versions for module |
| `/go/{module}/@v/{ver}.info` | GET | Version metadata (JSON) |
| `/go/{module}/@v/{ver}.mod` | GET | `go.mod` file for version |
| `/go/{module}/@v/{ver}.zip` | GET | Module zip archive |
| `/go/{module}/@latest` | GET | Latest version metadata (JSON) |

Module paths use GOPROXY capital-letter escaping: a capital letter `X` in the import path is encoded as `!x` in the URL path segment.

## Caching Behavior

- **Immutable** (`.info`, `.mod`, `.zip`): written once on first fetch and served from local storage on all subsequent requests. The upstream is never contacted again for the same version.
- **Mutable** (`@v/list`, `@latest`): cached with a TTL controlled by `NORA_GO_METADATA_TTL` (default 300 seconds). After the TTL expires the upstream is queried again.

## Known Limitations

- Proxy-only: `go mod upload` or any write operation is not supported.
- `GONOSUMDB` and `GONOSUMCHECK` are client-side settings; NORA does not interact with the Go checksum database.
- Module zips larger than `NORA_GO_MAX_ZIP_SIZE` are not cached and are streamed directly from upstream.
