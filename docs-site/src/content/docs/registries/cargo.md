---
title: Cargo
description: Cargo registry — sparse index (RFC 2789) proxy and host.
---

The Cargo registry implements the sparse index protocol (RFC 2789) as both a transparent proxy for crates.io and a private host for internal crates. Index entries and `.crate` tarballs are cached on first access.

## Client Configuration

Add NORA as a named registry in `.cargo/config.toml`:

```toml
[registries.nora]
index = "sparse+http://nora.example.com:4000/cargo/index/"
```

To replace crates.io transparently:

```toml
[source.crates-io]
replace-with = "nora"

[source.nora]
registry = "sparse+http://nora.example.com:4000/cargo/index/"
```

Publish to NORA with credentials in `~/.cargo/credentials.toml`:

```toml
[registries.nora]
token = "your-api-token"
```

Then:

```bash
cargo publish --registry nora
```

## Upstream Proxy

By default, NORA proxies to crates.io (`https://crates.io`). To use an alternate upstream:

```bash
export NORA_CARGO_PROXY=https://crates-mirror.internal.example.com
export NORA_CARGO_PROXY_AUTH=user:password
```

NORA rewrites the `dl` field in the sparse index config (`/cargo/index/config.json`) to point all `.crate` downloads through itself.

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Sparse index proxy | Full | RFC 2789; prefix layout `1/` `2/` `3/ab/` `ab/cd/` |
| Index config | Full | `config.json` with rewritten `dl` URL |
| Crate download | Full | Immutable cache |
| Crate metadata | Full | `/api/v1/crates/{name}` |
| Cargo publish | Full | `PUT /cargo/api/v1/crates/new` |
| Yank / unyank | -- | Not supported |
| Owner management | -- | Not supported |
| Search | -- | Categories and keywords stored but not searchable via API |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_CARGO_ENABLED` | Enable Cargo registry | `true` |
| `NORA_CARGO_PROXY` | Upstream registry URL | `https://crates.io` |
| `NORA_CARGO_PROXY_AUTH` | Upstream auth (`user:pass`) | *(none)* |
| `NORA_CARGO_PROXY_TIMEOUT` | Proxy timeout in seconds | `30` |
| `NORA_CARGO_METADATA_TTL` | Index entry cache TTL in seconds | `300` |

**config.toml:**

```toml
[cargo]
enabled = true
proxy = "https://crates.io"
# proxy_auth = "user:pass"
proxy_timeout = 30
metadata_ttl = 300
```

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/cargo/index/config.json` | GET | Sparse index config (rewritten `dl` URL) |
| `/cargo/index/{*path}` | GET | Index entry (prefix layout: `1/`, `2/`, `3/ab/`, `ab/cd/`) |
| `/cargo/api/v1/crates/{name}` | GET | Crate metadata |
| `/cargo/api/v1/crates/{name}/{ver}/download` | GET | Download `.crate` tarball |
| `/cargo/api/v1/crates/new` | PUT | Publish a crate (`cargo publish`) |

## Caching Behavior

- **Index entries**: cached for `NORA_CARGO_METADATA_TTL` seconds (default 300). On expiry, NORA revalidates with the upstream using `If-None-Match` / `ETag` per the sparse index protocol.
- **`.crate` tarballs**: cached on first download with `Cache-Control: public, max-age=31536000, immutable`. Subsequent requests are served from local storage without contacting upstream.

## Known Limitations

- Yank and unyank are not supported; published crate versions are immutable in NORA's storage.
- Owner management (`cargo owner`) is not implemented.
- Categories and keywords are stored in crate metadata but are not exposed via a search API.
