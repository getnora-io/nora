---
title: Outbound Proxy
description: Configure NORA to route upstream requests through an HTTP or SOCKS5 proxy
---

When NORA proxies packages from upstream registries (npmjs.org, pypi.org, registry.docker.io, etc.), it makes outbound HTTP/HTTPS requests. In corporate environments these requests often need to go through a forward proxy.

NORA respects the standard proxy environment variables used by most HTTP clients.

## Environment Variables

| Variable | Example | Description |
|----------|---------|-------------|
| `HTTP_PROXY` | `http://proxy.corp:3128` | Proxy for HTTP requests |
| `HTTPS_PROXY` | `http://proxy.corp:3128` | Proxy for HTTPS requests |
| `ALL_PROXY` | `socks5://proxy.corp:1080` | Proxy for all protocols (lowest priority) |
| `NO_PROXY` | `localhost,127.0.0.1,.internal` | Comma-separated list of hosts/domains to bypass |

Both uppercase and lowercase variants are supported (`HTTP_PROXY` and `http_proxy`). Uppercase takes precedence.

:::tip
`ALL_PROXY` supports SOCKS5 proxies: `socks5://proxy.corp:1080` or `socks5h://proxy.corp:1080` (DNS resolution on proxy side).
:::

## Docker Compose Example

```yaml
services:
  nora:
    image: ghcr.io/getnora-io/nora:latest
    environment:
      NORA_HOST: "0.0.0.0"
      HTTPS_PROXY: http://proxy.corp.example.com:3128
      NO_PROXY: localhost,127.0.0.1,10.0.0.0/8,.corp.example.com
    ports:
      - 4000:4000
```

## systemd Example

```ini
[Service]
Environment="HTTPS_PROXY=http://proxy.corp.example.com:3128"
Environment="NO_PROXY=localhost,127.0.0.1,10.0.0.0/8"
ExecStart=/usr/local/bin/nora serve
```

## NO_PROXY Format

The `NO_PROXY` variable accepts:

- Exact hostnames: `registry.internal`
- Domain suffixes with dot: `.corp.example.com` (matches `anything.corp.example.com`)
- IP addresses: `127.0.0.1`, `10.0.0.1`
- CIDR ranges: `10.0.0.0/8`, `172.16.0.0/12`
- Wildcard: `*` (disable proxy for all requests)

:::caution
If NORA uses S3 storage on a local network (e.g., MinIO at `minio:9000`), add the S3 host to `NO_PROXY` to avoid routing S3 traffic through the proxy:

```yaml
NO_PROXY: localhost,127.0.0.1,minio
```
:::

## Verification

NORA logs the detected proxy configuration at startup:

```
INFO Outbound proxy detected from environment var=HTTPS_PROXY proxy=http://proxy.corp:3128
INFO NO_PROXY exclusions configured no_proxy=localhost,127.0.0.1,.internal
```

If you don't see these lines, the environment variables are not reaching the NORA process. Check your Docker Compose or systemd configuration.

## See Also

- [Settings](/configuration/settings/) — all configuration options
- [Docker Proxy](/configuration/docker-proxy/) — pull-through cache for Docker images
- [TLS / HTTPS](/configuration/tls/) — custom CA certificates for upstream registries
