---
title: Circuit Breaker
description: Configure the upstream circuit breaker to fail fast when registries are unreachable
---


NORA includes a per-registry circuit breaker that tracks upstream failures and short-circuits requests when a registry is known to be down. This avoids slow timeouts cascading into your build pipelines.

The circuit breaker is **disabled by default** and must be explicitly enabled.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NORA_CB_ENABLED` | `false` | Enable upstream circuit breaker |
| `NORA_CB_THRESHOLD` | `5` | Consecutive failures before opening the circuit |
| `NORA_CB_RESET_TIMEOUT` | `30` | Seconds to wait before probing a failed upstream |

---

## How It Works

The circuit breaker operates as a state machine with three states per upstream registry:

```
          success
  ┌─────────────────────┐
  │                     │
  ▼     N failures      │
Closed ──────────► Open ──(reset_timeout)──► HalfOpen
  ▲                  │                          │
  │                  │  reject (503 +           │ probe
  │                  │  Retry-After)            │ succeeds
  │                  ▼                          │
  │              caller gets 503               │
  └────────────────────────────────────────────┘
           probe fails → back to Open
```

**Closed** -- Normal operation. All requests pass through to the upstream. Each failure increments a counter.

**Open** -- The upstream has failed `failure_threshold` consecutive times. All proxy requests immediately receive `503 Service Unavailable` with a `Retry-After` header. No upstream connections are attempted.

**HalfOpen** -- After `reset_timeout` seconds, a single probe request is allowed through. If it succeeds, the breaker closes. If it fails, the breaker re-opens.

:::note
Local reads are never affected by an open circuit breaker. Only upstream proxy requests are short-circuited -- packages already in local storage continue to serve normally.
:::

---

## config.toml

```toml
[circuit_breaker]
enabled = true
failure_threshold = 5
reset_timeout = 30
```

### Per-Registry Overrides

Override the threshold or timeout for specific registries. The key format is `"registry:url"`:

```toml
[circuit_breaker]
enabled = true
failure_threshold = 5
reset_timeout = 30

[circuit_breaker.overrides."docker:https://registry-1.docker.io"]
failure_threshold = 10
reset_timeout = 120

[circuit_breaker.overrides."npm:https://registry.npmjs.org"]
failure_threshold = 3
reset_timeout = 60
```

This lets you be more tolerant of occasional Docker Hub failures while cutting off flaky npm upstreams faster.

---

## Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_circuit_breaker_state` | Gauge | `registry` | Current state: 0 = Closed, 1 = Open, 2 = HalfOpen |
| `nora_circuit_breaker_rejections_total` | Counter | `registry` | Total requests rejected by an open breaker |

Example alert (Prometheus):

```yaml
- alert: NoraCircuitBreakerOpen
  expr: nora_circuit_breaker_state == 1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "NORA circuit breaker open for {{ $labels.registry }}"
```

---

## Example: Docker Compose

```yaml
services:
  nora:
    image: getnora/nora:latest
    environment:
      NORA_CB_ENABLED: "true"
      NORA_CB_THRESHOLD: "5"
      NORA_CB_RESET_TIMEOUT: "30"
    ports:
      - "4000:4000"
```

---

## See Also

- [Settings](/configuration/settings/) -- complete environment variable reference
- [Docker Proxy](/configuration/docker-proxy/) -- upstream proxy configuration
- [Production Deployment](/deployment/production/) -- production deployment guide
