---
title: PyPI
description: PyPI registry — PEP 503/691 proxy and host.
---

The PyPI registry implements the Simple Repository API (PEP 503 HTML and PEP 691 JSON) as both a transparent proxy for pypi.org and a private host for internal packages. Wheels and source distributions are cached on first download.

## Client Configuration

Pass the NORA URL as `--index-url` to pip:

```bash
pip install --index-url http://nora.example.com:4000/simple/ requests
```

Or set it globally in `pip.conf` (Linux: `~/.config/pip/pip.conf`; macOS: `~/Library/Application Support/pip/pip.conf`):

```ini
[global]
index-url = http://nora.example.com:4000/simple/
```

Upload packages with twine:

```bash
twine upload --repository-url http://nora.example.com:4000/simple/ dist/*
```

## Upstream Proxy

By default, NORA proxies to the public PyPI simple index (`https://pypi.org/simple/`). To use a private index or mirror:

```bash
export NORA_PYPI_PROXY=https://pypi.internal.example.com/simple/
export NORA_PYPI_PROXY_AUTH=user:password
```

To proxy multiple upstreams, use `NORA_PYPI_PROXIES` (takes precedence over `NORA_PYPI_PROXY`). Each entry is `url` or `url|user:pass`, separated by commas; NORA queries them in order and returns the first successful response:

```bash
export NORA_PYPI_PROXIES="https://pypi.org/simple/,https://mirror.internal.example.com/simple/|user:pass"
```

NORA rewrites download URLs in index responses to point through itself.

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Simple index (HTML, PEP 503) | Full | `GET /simple/` and `GET /simple/{name}/` |
| Simple index (JSON, PEP 691) | Full | `Accept: application/vnd.pypi.simple.v1+json` |
| File download | Full | Wheel, sdist, egg; immutable cache |
| Package upload | Full | `POST /simple/` (twine multipart) |
| Multi-upstream proxy | Full | `NORA_PYPI_PROXIES` comma-separated list |
| Yank | -- | Not supported |
| PGP upload signatures | -- | Not supported |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_PYPI_ENABLED` | Enable PyPI registry | `true` |
| `NORA_PYPI_PROXY` | Upstream simple index URL | `https://pypi.org/simple/` |
| `NORA_PYPI_PROXY_AUTH` | Upstream auth (`user:pass`) | *(none)* |
| `NORA_PYPI_PROXY_TIMEOUT` | Proxy timeout in seconds | `30` |
| `NORA_PYPI_PROXIES` | Multi-upstream list (`url\|auth`, comma-separated); takes precedence over `NORA_PYPI_PROXY` | *(none)* |

**config.toml:**

```toml
[pypi]
enabled = true
proxy = "https://pypi.org/simple/"
# proxy_auth = "user:pass"
proxy_timeout = 30
# proxies = "https://pypi.org/simple/,https://mirror.example.com/simple/|user:pass"
```

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/simple/` | GET | Root index (HTML PEP 503 or JSON PEP 691 via `Accept`) |
| `/simple/` | POST | Upload a package (`twine upload`, multipart) |
| `/simple/{name}/` | GET | Package versions page |
| `/simple/{name}/{filename}` | GET | Download wheel, sdist, or egg |

## Caching Behavior

- **Index pages** (`/simple/` and `/simple/{name}/`): proxied on every request; index responses are not stored locally, so freshness is always fetched from upstream.
- **Distribution files** (wheels, sdists, eggs): cached on first download with `Cache-Control: public, max-age=31536000, immutable`. Subsequent requests are served from local storage without contacting upstream.

## Known Limitations

- Yanking packages or individual files is not supported.
- PGP upload signatures are not accepted or stored.
- With `NORA_PYPI_PROXIES`, NORA returns the first successful upstream response; results are not merged across upstreams.
