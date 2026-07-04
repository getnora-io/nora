---
title: Conan
description: Caching proxy for the Conan v2 API (C/C++).
---

The Conan registry provides a transparent caching proxy for [center2.conan.io](https://center2.conan.io). Recipe and package revision metadata is TTL-cached, and recipe/package file downloads are immutably cached on first fetch.

## Client Configuration

Register NORA as a Conan remote:

```bash
conan remote add nora http://nora.example.com:4000/conan
```

Install a package through the NORA remote:

```bash
conan install boost/1.86.0@ -r nora
```

To make NORA the default remote for all installs, place it first in the remote list:

```bash
conan remote add nora http://nora.example.com:4000/conan --index 0
```

## Upstream Proxy

By default, NORA proxies to ConanCenter (`https://center2.conan.io`). To use a private Conan server (Artifactory, conan_server):

```bash
export NORA_CONAN_PROXY=https://conan.internal.example.com
export NORA_CONAN_PROXY_AUTH=user:password
```

NORA does not rewrite URLs embedded in recipe files; clients communicate directly with NORA for all revision, file list, and download endpoints.

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Server capabilities ping | Full | Returns `revisions` capability |
| Recipe search | Full | Proxied from upstream |
| Recipe revision listing | Full | TTL-cached |
| Recipe file listing | Full | TTL-cached |
| Recipe file download | Full | Immutable cache on first download |
| Package revision listing | Full | TTL-cached |
| Package file listing | Full | TTL-cached |
| Package file download | Full | Immutable cache on first download |
| Recipe/package upload | -- | Proxy-only (read) |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_CONAN_ENABLED` | Enable Conan registry | `false` |
| `NORA_CONAN_PROXY` | Upstream Conan server URL | `https://center2.conan.io` |
| `NORA_CONAN_PROXY_AUTH` | Upstream auth (`user:pass`) | *(none)* |
| `NORA_CONAN_PROXY_TIMEOUT` | Proxy timeout in seconds (metadata) | `30` |
| `NORA_CONAN_PROXY_TIMEOUT_DL` | Proxy timeout in seconds (file download) | `120` |
| `NORA_CONAN_METADATA_TTL` | Metadata cache TTL in seconds | `300` |
| `NORA_CONAN_REVALIDATE` | Revalidate stale metadata in the background | `true` |
| `NORA_CONAN_SERVE_STALE` | Serve cached metadata when upstream is unreachable | `true` |

**config.toml:**

```toml
[conan]
enabled = true
proxy = "https://center2.conan.io"
# proxy_auth = "user:pass"
proxy_timeout = 30
proxy_timeout_dl = 120
metadata_ttl = 300
revalidate = true
serve_stale = true
```

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/conan/v2/ping` | GET | Server health; returns `X-Conan-Server-Capabilities: revisions` |
| `/conan/v2/conans/search` | GET | Search recipes by name pattern |
| `/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/latest` | GET | Latest recipe revision (TTL-cached) |
| `/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions` | GET | All recipe revisions (TTL-cached) |
| `/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rev}/files` | GET | Recipe file list (TTL-cached) |
| `/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rev}/files/{*file}` | GET | Recipe file download (immutable cache) |
| `/conan/v2/conans/{name}/{ver}/{user}/{chan}/packages/{pkg}/revisions/latest` | GET | Latest package revision (TTL-cached) |
| `/conan/v2/conans/{name}/{ver}/{user}/{chan}/packages/{pkg}/revisions` | GET | All package revisions (TTL-cached) |
| `/conan/v2/conans/{name}/{ver}/{user}/{chan}/packages/{pkg}/revisions/{rev}/files` | GET | Package file list (TTL-cached) |
| `/conan/v2/conans/{name}/{ver}/{user}/{chan}/packages/{pkg}/revisions/{rev}/files/{*file}` | GET | Package file download (immutable cache) |

## Caching Behavior

- **Metadata** (revision lists, latest revision, file lists): TTL-cached for `NORA_CONAN_METADATA_TTL` seconds (default 300) with background revalidation when `NORA_CONAN_REVALIDATE=true`. Stale entries are served when upstream is unreachable and `NORA_CONAN_SERVE_STALE=true`.
- **Recipe and package files**: cached on first download with `Cache-Control: public, max-age=31536000, immutable`. Subsequent requests are served from local storage without contacting upstream.

## Known Limitations

- Proxy-only: recipe and package upload is not supported. Use `conan upload` directly against ConanCenter or a private Conan server.
- Anonymous read only: Conan v2 authentication (token-based login via `conan remote login`) is not implemented. Upstreams that require authentication are not supported.
