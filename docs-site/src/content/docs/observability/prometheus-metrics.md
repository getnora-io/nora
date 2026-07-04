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

The `registry` label is derived from the request path by literal prefix
match (the first matching prefix wins, top to bottom). The trailing slash is
significant where shown — e.g. `/go/` matches but `/goblin` does not:

| Path prefix (`starts_with`) | Label |
|-----------------------------|-------|
| `/v2` | `docker` |
| `/npm` | `npm` |
| `/simple`, `/packages` | `pypi` |
| `/maven2` | `maven` |
| `/cargo` | `cargo` |
| `/go/` | `go` |
| `/raw/` | `raw` |
| `/gems/` | `gems` |
| `/terraform/` | `terraform` |
| `/ansible/` | `ansible` |
| `/nuget/` | `nuget` |
| `/pub/` | `pub` |
| `/conan/` | `conan` |
| `/ui` | `ui` |
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

## Additional metrics

Every metric below is exposed at `/metrics`. Metrics carrying a `registry` label use the same path-prefix → registry mapping described above.

### Curation & quarantine

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_curation_decisions_total` | counter | `decision` | Curation decisions by outcome (`allow`, `block`, `audit`, `skip`) |
| `nora_quarantine_holds_total` | counter | `registry`, `outcome` | Proxy artifacts held by the digest quarantine (`outcome`: `blocked`, `observed`) |

### Proxy — revalidation & coalescing

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_proxy_upstream_304_total` | counter | `registry` | Upstream `304 Not Modified` on revalidation (cached body reused) |
| `nora_proxy_revalidation_bytes_saved_total` | counter | `registry` | Body bytes not re-downloaded thanks to a 304 |
| `nora_proxy_revalidation_errors_total` | counter | `registry` | Revalidations that fell back to a full fetch (nonzero = degrading) |
| `nora_proxy_coalesced_total` | counter | `registry` | Followers served from the single-flight leader without an upstream fetch |
| `nora_proxy_inflight` | gauge | `registry` | Distinct keys currently fetched under single-flight (monotonic climb = guard leak) |
| `nora_proxy_coalesce_fallthrough_total` | counter | `registry`, `reason` | Followers that fetched on their own (`reason`: `leader`, `budget`) |
| `nora_proxy_active_downloads` | gauge | — | Docker blob proxy downloads currently in progress |
| `nora_proxy_download_bytes_total` | counter | — | Total bytes downloaded from upstream Docker registries (use `rate()` for bandwidth) |
| `nora_upstream_request_duration_seconds` | histogram | `registry`, `status` | Upstream proxy request latency (buckets 1ms–30s) |

### Storage & integrity

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_storage_bytes` | gauge | `registry` | Stored bytes per registry; the special value `registry="total"` is the full footprint incl. metadata |
| `nora_storage_verify_duration_seconds` | histogram | `registry` | SHA-256 integrity-verify wall-clock per buffered get (incl. blocking-pool queue) |
| `nora_storage_get_bytes` | histogram | `registry` | Body size of buffered `Storage::get()` reads (buckets 1KB–512MB) |
| `nora_cache_write_errors_total` | counter | `registry`, `operation` | Cache write failures in background cache tasks |
| `nora_metadata_corrupt_total` | counter | `registry` | Corrupt metadata detected during publish (parse failure on existing data) |
| `nora_gc_stat_failures_total` | counter | — | Orphans GC could not stat (kept, age unknown) — **alert on nonzero** |

### Downloads, uploads & process

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_downloads_total` | counter | `registry` | Total artifact downloads |
| `nora_uploads_total` | counter | `registry` | Total artifact uploads |
| `nora_uptime_seconds` | gauge | — | Process uptime in seconds |

### Auth & security

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_auth_namespace_scope_total` | counter | `provider`, `decision` | OIDC `namespace_scope` enforcement (`decision`: `allow`, `deny`, `would_deny`) |
| `nora_response_upstream_url_leak_total` | counter | `registry` | Upstream hostname detected in an outgoing response body (detection only, never blocks) |
| `nora_leak_detection_skipped_total` | counter | `reason` | Leak scans skipped (`reason`: `own_surface`, `too_large`, `unknown_size`, `body_read_error`, `gzip_truncated`) |

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
- [Upgrade Guide](/deployment/upgrade-guide/) — metric changes across releases
