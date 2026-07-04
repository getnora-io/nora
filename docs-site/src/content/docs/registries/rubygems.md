---
title: RubyGems
description: Caching proxy for rubygems.org.
---

The RubyGems registry provides a transparent caching proxy for [rubygems.org](https://rubygems.org). Index files are cached with a configurable TTL; gem archives and gemspecs are immutably cached on first download.

## Client Configuration

Configure Bundler to mirror rubygems.org through NORA:

```bash
bundle config mirror.https://rubygems.org http://nora.example.com:4000/gems/
```

Or set the source directly in your `Gemfile`:

```ruby
source "http://nora.example.com:4000/gems/"
```

For `gem` CLI usage without Bundler:

```bash
gem install rails --source http://nora.example.com:4000/gems/
```

## Upstream Proxy

By default, NORA proxies to the public RubyGems index (`https://rubygems.org`). To use a private or mirror source:

```bash
export NORA_GEMS_PROXY=https://gems.internal.example.com
export NORA_GEMS_PROXY_AUTH=user:password
```

NORA serves all RubyGems Bundler v2 compact index endpoints as well as the legacy Marshal index, allowing both modern and older clients to resolve dependencies through the same mount point.

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Full index | Full | `specs.4.8.gz`, TTL-cached |
| Latest index | Full | `latest_specs.4.8.gz`, TTL-cached |
| Prerelease index | Full | `prerelease_specs.4.8.gz`, TTL-cached |
| Compact index | Full | `/info/{name}`, TTL-cached |
| Gem download | Full | Immutable cache |
| Gemspec fetch | Full | Immutable cache |
| Gem push / publish | -- | Proxy-only (read) |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_GEMS_ENABLED` | Enable RubyGems registry | `false` |
| `NORA_GEMS_PROXY` | Upstream RubyGems server URL | `https://rubygems.org` |
| `NORA_GEMS_PROXY_AUTH` | Upstream auth (`user:pass`) | *(none)* |
| `NORA_GEMS_PROXY_TIMEOUT` | Proxy timeout in seconds | `30` |
| `NORA_GEMS_METADATA_TTL` | TTL in seconds for index and compact index responses | `300` |
| `NORA_GEMS_REVALIDATE` | Revalidate stale metadata against upstream | `true` |
| `NORA_GEMS_SERVE_STALE` | Serve stale cached metadata when upstream is unreachable | `true` |

**config.toml:**

```toml
[gems]
enabled = false
proxy = "https://rubygems.org"
# proxy_auth = "user:pass"
proxy_timeout = 30
metadata_ttl = 300
revalidate = true
serve_stale = true
```

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/gems/specs.4.8.gz` | GET | Full gem index (Marshal, gzipped), TTL-cached |
| `/gems/latest_specs.4.8.gz` | GET | Latest-version index (Marshal, gzipped), TTL-cached |
| `/gems/prerelease_specs.4.8.gz` | GET | Prerelease index (Marshal, gzipped), TTL-cached |
| `/gems/info/{name}` | GET | Compact index for gem (Bundler v2), TTL-cached |
| `/gems/gems/{filename}` | GET | Gem archive download (`.gem`), immutable |
| `/gems/quick/Marshal.4.8/{filename}` | GET | Gemspec fetch (Marshal), immutable |

## Caching Behavior

- **Immutable** (gem archives under `/gems/gems/`, gemspecs under `/gems/quick/`): written once on first download and served from local storage on all subsequent requests.
- **TTL-cached** (index files and compact index): refreshed after `NORA_GEMS_METADATA_TTL` seconds (default 300). When `NORA_GEMS_REVALIDATE` is `true`, NORA contacts upstream after TTL expiry. When upstream is unreachable and `NORA_GEMS_SERVE_STALE` is `true`, the cached response is served rather than returning an error.

## Known Limitations

- Proxy-only: `gem push` is not supported. Publish gems directly to rubygems.org or your private gem server.
- No offline/air-gap mode for index files: if the upstream is unreachable and no cached copy exists, requests return 502.
