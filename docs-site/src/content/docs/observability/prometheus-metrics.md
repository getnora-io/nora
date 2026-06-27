---
title: Prometheus Metrics
description: Complete reference of all NORA Prometheus metrics available at /metrics
---

NORA exposes Prometheus-compatible metrics at the `/metrics` endpoint. No authentication is required.

```bash
curl http://localhost:4000/metrics
```

## HTTP metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_http_requests_total` | Counter | `registry`, `method`, `status` | Total HTTP requests processed |
| `nora_http_request_duration_seconds` | Histogram | `registry`, `method` | Request latency (buckets: 1ms to 10s) |

The `registry` label is derived from the request path:

| Path prefix | Label |
|-------------|-------|
| `/v2*` | `docker` |
| `/npm*` | `npm` |
| `/simple*`, `/packages*` | `pypi` |
| `/maven2*` | `maven` |
| `/cargo*` | `cargo` |
| `/go/*` | `go` |
| `/raw/*` | `raw` |
| `/gems/*` | `gems` |
| `/terraform/*` | `terraform` |
| `/ansible/*` | `ansible` |
| `/nuget/*` | `nuget` |
| `/pub/*` | `pub` |
| `/conan/*` | `conan` |
| `/ui*` | `ui` |
| *(other paths)* | `other` |

## Cache metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_cache_requests_total` | Counter | `registry`, `result` | Cache lookups (`hit` or `miss`) |

## Storage metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_storage_operations_total` | Counter | `operation`, `status` | Storage operations (`get`, `put`, `delete`, `list`) with `ok` or `error` status |
| `nora_artifacts_total` | Gauge | `registry` | Artifacts currently stored per registry (rises and falls with GC) |

## Circuit breaker metrics

Available when `NORA_CB_ENABLED=true`.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_circuit_breaker_state` | Gauge | `registry` | Current state: `0` = closed, `1` = open, `2` = half-open |
| `nora_circuit_breaker_rejections_total` | Counter | `registry` | Requests rejected by an open breaker |

## Garbage collection metrics

| Metric | Type | Description |
|--------|------|-------------|
| `nora_gc_blobs_removed_total` | Counter | Orphaned blobs removed by GC |
| `nora_gc_bytes_freed_total` | Counter | Bytes freed by GC |
| `nora_gc_duration_seconds` | Histogram | Duration of GC runs (buckets: 0.1s to 300s) |
| `nora_gc_last_run_timestamp` | Gauge | Unix timestamp of last GC run |
| `nora_gc_metadata_phantoms_total` | Counter | Phantom version entries cleaned from metadata |

## Retention metrics

| Metric | Type | Description |
|--------|------|-------------|
| `nora_retention_versions_deleted_total` | Counter | Versions removed by retention policies |
| `nora_retention_bytes_freed_total` | Counter | Bytes freed by retention |
| `nora_retention_duration_seconds` | Histogram | Duration of retention runs (buckets: 0.1s to 300s) |
| `nora_retention_last_run_timestamp` | Gauge | Unix timestamp of last retention run |

## Grafana example

```promql
# Request rate by registry (5m window)
sum by (registry) (rate(nora_http_requests_total[5m]))

# Cache hit ratio
sum(rate(nora_cache_requests_total{result="hit"}[5m]))
/
sum(rate(nora_cache_requests_total[5m]))

# p99 latency per registry
histogram_quantile(0.99, sum by (le, registry) (rate(nora_http_request_duration_seconds_bucket[5m])))

# Circuit breaker alerts (open state)
nora_circuit_breaker_state == 1

# GC bytes freed per hour
increase(nora_gc_bytes_freed_total[1h])
```

## Scrape configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: nora
    scrape_interval: 15s
    static_configs:
      - targets: ['nora:4000']
    metrics_path: /metrics
```

## See Also

- [Settings](/configuration/settings/) — server configuration reference (the `/metrics` endpoint is always enabled)
- [Circuit Breaker](/configuration/circuit-breaker/) — breaker metrics details
- [Upgrade Guide](/deployment/upgrade-guide/) — new metrics in v0.9
