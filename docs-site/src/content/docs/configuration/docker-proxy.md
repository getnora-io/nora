---
title: Docker Proxy
description: Configure upstream Docker/OCI registry proxying with namespace isolation, metadata caching, and stale-while-error
---


NORA can proxy Docker (OCI) images from multiple upstream registries simultaneously. Each upstream is isolated by namespace and supports independent authentication, timeouts, and path-based routing.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_DOCKER_PROXIES` | `https://registry-1.docker.io` | Upstream registries. Format: `url1,url2` or `url1\|auth1,url2\|auth2` |
| `NORA_DOCKER_PROXY_TIMEOUT` | `300` | Connection timeout in seconds |
| `NORA_DOCKER_READ_TIMEOUT` | `60` | Per-chunk read timeout for streaming blob downloads |
| `NORA_DOCKER_METADATA_TTL` | `-1` | Metadata cache TTL in seconds (-1 = forever, 0 = always refetch) |
| `NORA_DOCKER_SERVE_STALE` | `true` | Serve stale cached manifests when upstream is unreachable |

---

## Multiple Upstreams

Configure multiple upstream registries using `[[docker.upstreams]]` in config.toml. Each upstream gets its own URL, auth, and namespace:

```toml
[docker]
enabled = true
proxy_timeout = 300
read_timeout = 60
metadata_ttl = -1
serve_stale = true

# Docker Hub
[[docker.upstreams]]
url = "https://registry-1.docker.io"
# auth = "user:pass"

# GitHub Container Registry
[[docker.upstreams]]
url = "https://ghcr.io"
# auth = "user:ghp_token"

# Private registry
[[docker.upstreams]]
url = "https://registry.internal.example.com"
namespace = "internal"
```

With environment variables, separate multiple upstreams with commas:

```bash
export NORA_DOCKER_PROXIES="https://registry-1.docker.io,https://ghcr.io|user:ghp_token"
```

---

## Namespace Isolation

Each upstream is assigned a **namespace** that isolates its cached images from other upstreams. This prevents name collisions (e.g., `library/nginx` on Docker Hub vs `library/nginx` on a private registry).

The namespace is resolved in this order:

1. Explicit `namespace` field in the upstream config
2. Derived from the upstream URL host (e.g., `https://registry-1.docker.io` becomes `docker.io`)

```toml
[[docker.upstreams]]
url = "https://registry-1.docker.io"
# namespace = "docker.io"  (derived automatically)

[[docker.upstreams]]
url = "https://registry.internal.example.com"
namespace = "internal"  # explicit override
```

### Path-Based Routing

Upstreams can be exposed at a URL prefix. Requests to `/v2/<prefix>/...` route to the upstream with the prefix stripped:

```toml
[[docker.upstreams]]
url = "https://registry-1.docker.io"
prefix = "docker-hub"

[[docker.upstreams]]
url = "https://ghcr.io"
prefix = "ghcr"
```

With this config:
- `docker pull nora:4000/docker-hub/library/nginx:latest` pulls from Docker Hub
- `docker pull nora:4000/ghcr/owner/image:tag` pulls from GHCR

---

## Metadata TTL

The `metadata_ttl` setting controls how long cached manifests and tag lists are considered fresh:

| Value | Behavior |
|-------|----------|
| `-1` | Cache forever (default) -- manifests never expire, best for airgapped or bandwidth-constrained environments |
| `0` | Always refetch -- every request checks upstream, highest consistency but most bandwidth |
| `> 0` | Cache for N seconds -- balance between freshness and performance |

```toml
[docker]
metadata_ttl = 300  # 5 minutes
```

:::tip
For mutable tags like `latest`, consider a shorter TTL (e.g., 60-300 seconds). For immutable tags like `v1.2.3`, the default of `-1` (forever) is optimal.
:::

---

## Stale-While-Error

When `serve_stale` is enabled (the default), NORA serves cached manifests from local storage when the upstream registry is unreachable. This prevents upstream outages from breaking builds that use already-pulled images.

```toml
[docker]
serve_stale = true   # default
```

:::caution
Stale-while-error only works for images that have been previously pulled and cached. It does not help with images that have never been fetched.
:::

---

## See Also

- [Settings](/configuration/settings/) -- complete environment variable reference
- [Circuit Breaker](/configuration/circuit-breaker/) -- automatic upstream failure detection
- [TLS / HTTPS](/configuration/tls/) -- custom CA certificates for private registries
- [Outbound Proxy](/configuration/http-proxy/) -- HTTP/SOCKS5 proxy for upstream connections
