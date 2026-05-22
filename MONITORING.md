# Monitoring

NORA exposes Prometheus metrics at `/metrics`. This page documents all available metrics and provides a ready-to-import Grafana dashboard.

## Quick Start

```yaml
# prometheus.yml
scrape_configs:
  - job_name: nora
    static_configs:
      - targets: ['nora:4000']
    scrape_interval: 15s
```

Import `dist/grafana-dashboard.json` into Grafana (Dashboards > Import > Upload JSON file).

## Metrics Reference

### HTTP (RED signals)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_http_requests_total` | counter | registry, method, status | Total HTTP requests |
| `nora_http_request_duration_seconds` | histogram | registry, method | Request latency (buckets: 1ms–10s) |

### Cache

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_cache_requests_total` | counter | registry, result | Cache lookups (`result`: hit / miss) |

### Upstream Proxy

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_upstream_request_duration_seconds` | histogram | registry, status | Upstream proxy latency (buckets: 1ms–30s) |

### Artifacts & Traffic

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_artifacts_total` | counter | registry | Total artifacts stored |
| `nora_downloads_total` | counter | registry | Total artifact downloads |
| `nora_uploads_total` | counter | registry | Total artifact uploads |

### Storage

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_storage_bytes` | gauge | registry | Storage size in bytes per registry |
| `nora_storage_operations_total` | counter | operation, status | Storage operations (put, get, delete) |

### Circuit Breaker

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_circuit_breaker_state` | gauge | registry | 0 = closed, 1 = open, 2 = half_open |
| `nora_circuit_breaker_rejections_total` | counter | registry | Requests rejected by open circuit breaker |

### Security

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_response_upstream_url_leak_total` | counter | registry | Upstream hostname detected in outgoing response body |

### Retention

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_retention_versions_deleted_total` | counter | — | Versions removed by retention policy |
| `nora_retention_bytes_freed_total` | counter | — | Bytes freed by retention |
| `nora_retention_duration_seconds` | histogram | — | Retention sweep duration |
| `nora_retention_last_run_timestamp` | gauge | — | Unix timestamp of last retention run |

### Garbage Collection

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_gc_blobs_removed_total` | counter | — | Orphan blobs removed by GC |
| `nora_gc_bytes_freed_total` | counter | — | Bytes freed by GC |
| `nora_gc_duration_seconds` | histogram | — | GC sweep duration |
| `nora_gc_last_run_timestamp` | gauge | — | Unix timestamp of last GC run |
| `nora_gc_metadata_phantoms_total` | counter | — | Metadata entries without corresponding blobs |

## Grafana Dashboard

The included dashboard (`dist/grafana-dashboard.json`) provides:

- **Row 1** — Key stats: request rate, error rate, p50/p99 latency, cache hit rate, storage used
- **Row 2** — Request rate by registry, HTTP latency percentiles (p50/p95/p99)
- **Row 3** — Error rate by registry, upstream proxy latency by registry
- **Row 4** — Cache hit/miss rate, downloads/uploads by registry
- **Row 5** — Storage by registry, circuit breaker state table, security alerts (URL leaks, CB rejections)
- **Row 6** — Retention & GC bytes freed, last run timestamps, storage operations

The dashboard includes a `registry` template variable to filter by specific protocol.

## Alerting Recommendations

```yaml
# alertmanager rules (example)
groups:
  - name: nora
    rules:
      - alert: NoraHighErrorRate
        expr: >
          sum(rate(nora_http_requests_total{status=~"5.."}[5m]))
          / sum(rate(nora_http_requests_total[5m])) > 0.05
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "NORA error rate above 5%"

      - alert: NoraHighLatency
        expr: >
          histogram_quantile(0.99, sum(rate(nora_http_request_duration_seconds_bucket[5m])) by (le)) > 5
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "NORA p99 latency above 5s"

      - alert: NoraCircuitBreakerOpen
        expr: nora_circuit_breaker_state == 1
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "NORA circuit breaker OPEN for {{ $labels.registry }}"

      - alert: NoraCacheLowHitRate
        expr: >
          sum(rate(nora_cache_requests_total{result="hit"}[15m]))
          / sum(rate(nora_cache_requests_total[15m])) < 0.5
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "NORA cache hit rate below 50%"

      - alert: NoraUpstreamUrlLeak
        expr: sum(rate(nora_response_upstream_url_leak_total[5m])) > 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Upstream URL leak detected in NORA responses"
```
