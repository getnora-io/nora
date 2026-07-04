---
title: Pub (Dart/Flutter)
description: Caching proxy for pub.dev (hosted repository spec v2).
---

The Pub registry provides a transparent caching proxy for [pub.dev](https://pub.dev) using the [hosted repository spec v2](https://github.com/dart-lang/pub/blob/master/doc/repository-spec-v2.md). Package metadata is TTL-cached; package archives are immutably cached on first download with SHA-256 integrity verification.

## Client Configuration

Set `PUB_HOSTED_URL` before running Dart or Flutter package commands:

```bash
export PUB_HOSTED_URL=http://nora.example.com:4000/pub
dart pub get
```

```bash
export PUB_HOSTED_URL=http://nora.example.com:4000/pub
flutter pub get
```

To make the setting permanent, add it to your shell profile or CI environment variables. For Flutter projects, you can also set it in `pubspec.yaml` if using a workspace configuration that supports environment variable substitution.

## Upstream Proxy

By default, NORA proxies to the public Dart package repository (`https://pub.dev`). To use a private or self-hosted Pub server:

```bash
export NORA_PUB_PROXY=https://pub.internal.example.com
export NORA_PUB_PROXY_AUTH=user:password
```

NORA implements the hosted repository spec v2 API, so all standard `dart pub` and `flutter pub` commands work without client-side changes beyond setting `PUB_HOSTED_URL`.

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Package search | Full | `?q=` and `?page=` |
| Package metadata | Full | All versions, TTL-cached |
| Version detail | Full | TTL-cached |
| Security advisories | Full | TTL-cached |
| Archive download | Full | Immutable cache, SHA-256 verified |
| Package publish | -- | Proxy-only (read) |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_PUB_ENABLED` | Enable Pub registry | `false` |
| `NORA_PUB_PROXY` | Upstream Pub server URL | `https://pub.dev` |
| `NORA_PUB_PROXY_AUTH` | Upstream auth (`user:pass`) | *(none)* |
| `NORA_PUB_PROXY_TIMEOUT` | Proxy timeout in seconds | `30` |
| `NORA_PUB_METADATA_TTL` | TTL in seconds for metadata responses | `300` |
| `NORA_PUB_REVALIDATE` | Revalidate stale metadata against upstream | `true` |
| `NORA_PUB_SERVE_STALE` | Serve stale cached metadata when upstream is unreachable | `true` |

**config.toml:**

```toml
[pub]
enabled = false
proxy = "https://pub.dev"
# proxy_auth = "user:pass"
proxy_timeout = 30
metadata_ttl = 300
revalidate = true
serve_stale = true
```

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/pub/api/packages` | GET | Search packages (`?q=`, `?page=`) |
| `/pub/api/packages/{package}` | GET | Package metadata and version list, TTL-cached |
| `/pub/api/packages/{package}/versions/{version}` | GET | Single version detail, TTL-cached |
| `/pub/api/packages/{package}/advisories` | GET | Security advisories for package, TTL-cached |
| `/pub/packages/{package}/versions/{archive}` | GET | Package archive (`.tar.gz`), immutable, SHA-256 verified |

## Caching Behavior

- **Immutable** (package archives under `/pub/packages/`): written once on first download with SHA-256 integrity verification and served from local storage on all subsequent requests.
- **TTL-cached** (all `/pub/api/` endpoints): refreshed after `NORA_PUB_METADATA_TTL` seconds (default 300). When `NORA_PUB_REVALIDATE` is `true`, NORA contacts upstream after TTL expiry. When upstream is unreachable and `NORA_PUB_SERVE_STALE` is `true`, the cached response is served rather than returning an error.

## Known Limitations

- Proxy-only: `dart pub publish` is not supported. Publish packages directly to pub.dev or your private Pub server.
- No offline/air-gap mode for metadata: if the upstream is unreachable and no cached copy exists, requests return 502.
