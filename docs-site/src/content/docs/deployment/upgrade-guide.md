---
title: Upgrade Guide
description: Upgrading NORA between versions — migration notes and rollback procedures
---

## v0.8 to v0.9

v0.9 is backward-compatible for all features and storage. The only action required is updating renamed environment variables if you use any of the [renamed names](#renamed-environment-variables) listed below.

### What changed

| Feature | Impact | Action required |
|---------|--------|-----------------|
| Docker namespace isolation | Storage layout adds namespace prefix | None — lazy migration is automatic |
| Circuit breaker | New feature, disabled by default | None |
| Docker metadata TTL + stale-while-error | New feature, opt-in | None |
| Streaming read_timeout | New feature, opt-in | None |
| SIGHUP hot reload for curation | New capability | None |
| linux/arm64 binary | New platform | None |

### Docker namespace migration

v0.9 introduces per-upstream namespace prefixes for Docker storage keys to isolate data from different upstream registries.

**Old layout (v0.8):**
```
docker/{name}/blobs/{digest}
docker/{name}/manifests/{ref}.json
```

**New layout (v0.9):**
```
docker/{namespace}/{name}/blobs/{digest}
docker/{namespace}/{name}/manifests/{ref}.json
```

The namespace is derived from the upstream URL (e.g., `registry-1.docker.io` becomes `docker.io`) or set explicitly via the `namespace` field in `[[docker.upstreams]]`.

**Migration is automatic and lazy:**
- When NORA serves a request, it first checks the namespaced path.
- If not found, it falls back to the legacy flat path.
- No background migration runs at startup.
- Existing cached data continues to be served without interruption.

:::note
Locally pushed images (not proxied from an upstream) are unaffected — they have no namespace prefix.
:::

### Upgrade steps

1. Stop the running NORA instance.
2. Replace the binary or update the container image to v0.9.
3. Start NORA with your existing configuration.

```bash
# Binary upgrade
curl -fsSL https://github.com/getnora-io/nora/releases/latest/download/nora-linux-amd64 -o nora
chmod +x nora
./nora
```

No data migration scripts are needed.

### Rollback

To roll back from v0.9 to v0.8:

1. Stop the v0.9 instance.
2. Replace the binary or image with v0.8.
3. Start NORA.

:::caution
Any Docker images cached **after** upgrading to v0.9 are stored under the new namespaced layout. v0.8 will not find these entries — they appear as cache misses and are re-fetched from upstream on next access. Locally pushed artifacts are unaffected.
:::

### New environment variables

v0.9 adds these optional variables (all disabled or inactive by default):

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_CB_ENABLED` | `false` | Enable circuit breaker |
| `NORA_CB_THRESHOLD` | `5` | Failures before opening |
| `NORA_CB_RESET_TIMEOUT` | `30` | Seconds before probing |
| `NORA_DOCKER_READ_TIMEOUT` | `60` | Per-chunk read timeout (seconds) |
| `NORA_DOCKER_METADATA_TTL` | `-1` | Metadata cache TTL in seconds |
| `NORA_DOCKER_SERVE_STALE` | `true` | Serve cached manifests when upstream is down |

See [Settings](/configuration/settings/) for the full reference.

### Renamed environment variables

v0.9 shortens several variable names to follow the `NORA_{SECTION}_{FIELD}` convention (under 30 characters):

| Old name | New name |
|----------|----------|
| `NORA_TERRAFORM_ENABLED` | `NORA_TF_ENABLED` |
| `NORA_TERRAFORM_PROXY` | `NORA_TF_PROXY` |
| `NORA_TERRAFORM_PROXY_TIMEOUT` | `NORA_TF_PROXY_TIMEOUT` |
| `NORA_TERRAFORM_METADATA_TTL` | `NORA_TF_METADATA_TTL` |
| `NORA_TERRAFORM_PROXY_TIMEOUT_DOWNLOAD` | `NORA_TF_PROXY_TIMEOUT_DL` |
| `NORA_CONAN_PROXY_TIMEOUT_DOWNLOAD` | `NORA_CONAN_PROXY_TIMEOUT_DL` |
| `NORA_CURATION_INTERNAL_NAMESPACES` | `NORA_CURATION_INTERNAL_NS` |

The old names are no longer recognized. Update your configuration if you use any of these.

## See Also

- [Settings](/configuration/settings/) — full environment variable reference
- [Circuit Breaker](/configuration/circuit-breaker/) — new in v0.9
- [Docker Proxy](/configuration/docker-proxy/) — namespace isolation details
