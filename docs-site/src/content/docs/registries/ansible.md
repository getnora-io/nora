---
title: Ansible Galaxy
description: Caching proxy for Ansible Galaxy collections (API v3).
---

The Ansible Galaxy registry provides a transparent caching proxy for [galaxy.ansible.com](https://galaxy.ansible.com). Collection metadata is proxied with URL rewriting, and collection tarballs are immutably cached on first download.

## Client Configuration

Install a collection through NORA:

```bash
ansible-galaxy collection install community.general \
  --server http://nora.example.com:4000/ansible/
```

Install a specific version:

```bash
ansible-galaxy collection install community.general:==12.2.0 \
  --server http://nora.example.com:4000/ansible/
```

In `ansible.cfg`:

```ini
[galaxy]
server_list = nora

[galaxy_server.nora]
url = http://nora.example.com:4000/ansible/
```

For AWX / Ansible Automation Platform, set the Galaxy Server URL to `http://nora.example.com:4000/ansible/` in the organization or project settings.

## Upstream Proxy

By default, NORA proxies to the public Ansible Galaxy (`https://galaxy.ansible.com`). To use a private Galaxy server (Automation Hub, Pulp):

```bash
export NORA_ANSIBLE_PROXY=https://hub.internal.example.com
export NORA_ANSIBLE_PROXY_AUTH=user:password
```

NORA rewrites all upstream URLs in metadata responses to point through itself, so clients always download through the proxy.

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| API discovery | Full | `/ansible/` and `/ansible/api/` |
| Collection listing | Full | Short v3 and Pulp-style paths |
| Collection detail | Full | URL rewriting |
| Version listing | Full | Paginated |
| Version detail | Full | Curation checks |
| Tarball download | Full | Immutable cache, both `/download/` and `/artifacts/` paths |
| Tarball curation | Full | Blocklist/allowlist with integrity verification |
| Collection publish | -- | Proxy-only (read) |

**Environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NORA_ANSIBLE_ENABLED` | Enable Ansible Galaxy registry | `false` |
| `NORA_ANSIBLE_PROXY` | Upstream Galaxy server URL | `https://galaxy.ansible.com` |
| `NORA_ANSIBLE_PROXY_AUTH` | Upstream auth (`user:pass`) | *(none)* |
| `NORA_ANSIBLE_PROXY_TIMEOUT` | Proxy timeout in seconds | `30` |

**config.toml:**

```toml
[ansible]
enabled = true
proxy = "https://galaxy.ansible.com"
# proxy_auth = "user:pass"
proxy_timeout = 30
```

## Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/ansible/` | GET | API discovery (`available_versions`) |
| `/ansible/v3/collections/` | GET | List collections |
| `/ansible/v3/collections/{ns}/{name}/` | GET | Collection detail |
| `/ansible/v3/collections/{ns}/{name}/versions/` | GET | Version list (paginated) |
| `/ansible/v3/collections/{ns}/{name}/versions/{ver}/` | GET | Version detail with `download_url` |
| `/ansible/download/{ns}-{name}-{ver}.tar.gz` | GET | Download collection tarball |

Full Pulp-style paths (`/ansible/api/v3/plugin/ansible/content/published/collections/index/...`) are also supported as aliases.

## Caching Behavior

- **Metadata** (collection list, detail, versions): proxied on every request with `Cache-Control: public, max-age=60, must-revalidate`.
- **Tarballs**: cached on first download with `Cache-Control: public, max-age=31536000, immutable`. Subsequent requests are served from local storage without contacting upstream.

## Naming Constraints

Ansible Galaxy namespace and collection names follow the pattern `[a-z0-9_]+` -- alphanumeric characters and underscores only. Hyphens are not allowed in namespace or collection names (they are used as separators in tarball filenames).

The tarball filename format is `{namespace}-{name}-{version}.tar.gz`, for example `community-general-12.2.0.tar.gz`.

## Known Limitations

- Proxy-only: publishing collections through NORA is not supported. Use `ansible-galaxy collection publish` directly against Galaxy or Automation Hub.
- No offline/air-gap mode for metadata: if the upstream is unreachable and the metadata is not cached, requests return 502.
- Tarballs are cached indefinitely once downloaded. To force re-fetch, delete the file from storage (`ansible/download/{filename}`).
