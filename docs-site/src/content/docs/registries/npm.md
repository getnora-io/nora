---
title: npm
description: npm registry — proxy, host, and npm audit.
---

The npm registry provides a transparent proxy and private host for npm packages. Metadata and tarballs are cached on first download; package versions are immutable once published.

## Client Configuration

Point the npm client at NORA globally:

```bash
npm config set registry http://nora.example.com:4000/npm/
```

Or per-project via `.npmrc`:

```ini
registry=http://nora.example.com:4000/npm/
```

For scoped packages:

```ini
@myorg:registry=http://nora.example.com:4000/npm/
```

## Upstream Proxy

By default, NORA proxies to the public npm registry (`https://registry.npmjs.org`). To use a private or self-hosted registry:

```bash
export NORA_NPM_PROXY=https://npm.internal.example.com
export NORA_NPM_PROXY_AUTH=user:password
```

NORA rewrites `dist.tarball` URLs in metadata responses to point through itself, so tarballs are always fetched through the proxy.

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Metadata proxy | Full | `GET /npm/{*path}` |
| Tarball proxy | Full | Immutable cache, served on first download |
| Package publish | Full | `PUT /npm/{*path}` (`npm publish`); versions are immutable |
| npm audit (npm7) | Full | `POST /-/npm/v1/security/advisories/bulk` forwarded upstream |
| npm audit (npm6) | Full | `POST /-/npm/v1/security/audits/quick` forwarded upstream |
| Other POSTs | -- | 405 Method Not Allowed |
| Search | -- | `/-/v1/search` not supported |
| Unpublish | -- | Immutable; use quarantine/blocklist to disable a version |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_NPM_ENABLED` | Enable npm registry | `true` |
| `NORA_NPM_PROXY` | Upstream registry URL | `https://registry.npmjs.org` |
| `NORA_NPM_PROXY_AUTH` | Upstream auth (`user:pass`) | *(none)* |
| `NORA_NPM_PROXY_TIMEOUT` | Proxy timeout in seconds | `30` |
| `NORA_NPM_METADATA_TTL` | Metadata cache TTL in seconds | `300` |
| `NORA_NPM_REVALIDATE` | Revalidate cached metadata on TTL expiry | `true` |
| `NORA_NPM_SERVE_STALE` | Serve stale metadata if upstream is unreachable | `true` |

**config.toml:**

```toml
[npm]
enabled = true
proxy = "https://registry.npmjs.org"
# proxy_auth = "user:pass"
proxy_timeout = 30
metadata_ttl = 300
revalidate = true
serve_stale = true
```

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/npm/{*path}` | GET | Package metadata and tarball download |
| `/npm/{*path}` | PUT | Publish a package (`npm publish`) |
| `/npm/-/npm/v1/security/advisories/bulk` | POST | npm7 audit (forwarded to upstream) |
| `/npm/-/npm/v1/security/audits/quick` | POST | npm6 audit (forwarded to upstream) |
| `/npm/{*path}` (other POST) | POST | 405 Method Not Allowed |

## Caching Behavior

- **Metadata** (package manifests): cached for `NORA_NPM_METADATA_TTL` seconds (default 300). On expiry, NORA revalidates with the upstream using `If-None-Match` / `ETag`. If upstream is unreachable and `NORA_NPM_SERVE_STALE=true`, the last known metadata is returned.
- **Tarballs**: cached on first download with `Cache-Control: public, max-age=31536000, immutable`. Subsequent requests are served from local storage without contacting upstream.

## Known Limitations

- `npm unpublish` is not supported; published versions are immutable. To disable a version, add it to the quarantine or blocklist.
- Dist-tag management (`npm dist-tag add/rm/ls`) is not supported.
- Search (`/-/v1/search`) is not implemented; queries return 404.
- npm audit is proxied to the upstream advisory database; there is no local advisory DB. Audit results are only available for packages reachable via the upstream registry.
