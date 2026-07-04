---
title: Docker
description: OCI Distribution Spec registry — proxy and host.
---

The Docker registry implements [OCI Distribution Spec 1.1](https://github.com/opencontainers/distribution-spec) as a proxy and host, mounted at `/v2/`.

## Client Configuration

Pull a public image through NORA without authentication:

```bash
docker pull nora.example.com:4000/library/nginx:latest
```

To push or pull private images, authenticate first:

```bash
docker login nora.example.com:4000
docker pull nora.example.com:4000/myorg/image:tag
docker push nora.example.com:4000/myorg/image:tag
```

## Upstream Proxy

By default, NORA proxies pull requests to Docker Hub (`https://registry-1.docker.io`). Additional upstreams can be added in `config.toml`; NORA tries each in declaration order and returns the first successful response.

```bash
export NORA_DOCKER_UPSTREAMS=https://registry-1.docker.io
```

Upstream authentication is configured per-upstream in `config.toml` via the `auth` field.

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| API version check (`/v2/`) | Full | |
| Repository listing (`/v2/_catalog`) | Full | |
| Image pull (proxy) | Full | Multi-upstream fallback |
| Image push (host) | Full | |
| Manifest get / put / delete | Full | By tag or digest |
| Blob (layer) pull / delete | Full | Content-addressable |
| Blob upload session | Full | POST → PATCH → PUT |
| Content-addressable dedup | Full | Same digest stored once across all images |
| OCI 1.1 Referrers API | -- | Not implemented |
| Cross-repo blob mount | -- | Not implemented |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_DOCKER_ENABLED` | Enable Docker registry | `true` |
| `NORA_DOCKER_UPSTREAMS` | Comma-separated upstream URLs (TOML: `[[docker.upstreams]]`) | `https://registry-1.docker.io` |
| `NORA_DOCKER_PROXY_TIMEOUT` | Upstream proxy timeout in seconds | `300` |
| `NORA_DOCKER_READ_TIMEOUT` | Upstream read timeout in seconds | `60` |
| `NORA_DOCKER_METADATA_TTL` | Manifest cache TTL in seconds (`-1` = cache forever) | `-1` |
| `NORA_DOCKER_SERVE_STALE` | Serve cached manifests when upstream is unreachable | `true` |
| `NORA_DOCKER_DEFAULT_ACTION` | Action when no upstream prefix matches (`allow`\|`deny`) | `allow` |
| `NORA_AUTH_DOCKER_ANON_PULL` | Allow anonymous pulls (separate from `anonymous_read`; set in `[auth]`) | `false` |

**config.toml:**

```toml
[docker]
enabled = true
proxy_timeout = 300
read_timeout = 60
metadata_ttl = -1
serve_stale = true
default_action = "allow"

[[docker.upstreams]]
url = "https://registry-1.docker.io"
# auth = "user:password"
# prefix = "library"
# namespace = "library"
```

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/v2/` | GET | API version check |
| `/v2/_catalog` | GET | List repositories |
| `/v2/{name}/tags/list` | GET | List tags for image |
| `/v2/{name}/manifests/{ref}` | GET, HEAD | Pull manifest by tag or digest |
| `/v2/{name}/manifests/{ref}` | PUT | Push manifest |
| `/v2/{name}/manifests/{ref}` | DELETE | Delete manifest |
| `/v2/{name}/blobs/{digest}` | GET, HEAD | Pull blob (layer) |
| `/v2/{name}/blobs/{digest}` | DELETE | Delete blob |
| `/v2/{name}/blobs/uploads/` | POST | Start blob upload session |
| `/v2/{name}/blobs/uploads/{uuid}` | PATCH | Append chunk to upload |
| `/v2/{name}/blobs/uploads/{uuid}` | PUT | Complete blob upload |

## Caching Behavior

- **Manifests**: cached by reference (tag or digest) with TTL set by `metadata_ttl`. The default `-1` means manifests are cached indefinitely. When `serve_stale = true`, a cached manifest is returned even if the upstream is unreachable.
- **Blobs (layers)**: stored permanently by content digest (`sha256:…`). Once a blob is cached it is never re-fetched from upstream. The same blob shared across multiple images is stored only once.

## Known Limitations

- Image names are limited to two path segments (`org/image`). Three or more segments (e.g., `org/sub/path/image`) are not routed and return 404.
- Cross-repository blob mounting (`POST /v2/{name}/blobs/uploads/?mount={digest}&from={source}`) is not supported; the Docker client falls back to a standard upload session automatically.
- The OCI Distribution Spec 1.1 Referrers API (`GET /v2/{name}/referrers/{digest}`) is not implemented.
- Docker daemon mirror-auth bug ([moby/moby#30880](https://github.com/moby/moby/issues/30880), [#42022](https://github.com/moby/moby/issues/42022)): an authenticated mirror pull can fail because Docker sends wrong credentials to the mirror. Workaround: set `docker_anon_pull = true` under `[auth]` in `config.toml` to allow unauthenticated mirror pulls.
