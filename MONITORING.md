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
| `nora_storage_operations_total` | counter | operation, status | Storage operations (put, get, delete). `status="integrity_fail"`/`"verify_error"` on `operation="get"` mean a stored artifact failed hash-pin verification and was refused (fail-closed, #582) — see [Integrity recovery](#integrity-recovery). |

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

      - alert: NoraIntegrityFailure
        expr: increase(nora_storage_operations_total{operation="get",status=~"integrity_fail|verify_error"}[5m]) > 0
        for: 0m
        labels: { severity: critical }
        annotations:
          summary: "NORA refusing to serve an artifact (hash-pin integrity failure)"
```

A ready-to-load version of these rules ships at [`deploy/prometheus-rules.yml`](deploy/prometheus-rules.yml); point Prometheus at it via `rule_files:`.

## Integrity recovery

When `nora_storage_operations_total{operation="get",status="integrity_fail"}`
fires, a stored artifact's bytes no longer match its hash pin (bit rot or
tampering) and `Storage::get()` returns 5xx on every read (fail-closed, #582).
The offending key is in the `integrity violation` error log line.

- **Cache/proxy artifacts** self-heal: the next request treats the failure as a
  cache miss, re-fetches from upstream, and re-pins.
- **Locally-authored artifacts** (e.g. uploaded `raw` blobs) have no upstream.
  Verify the on-disk bytes against a hash you trust, then:

  ```sh
  # Dry run — shows old → new pin without writing:
  nora re-pin raw/myorg/app-1.0.0.bin --expected <sha256>
  # Apply once you've confirmed:
  nora re-pin raw/myorg/app-1.0.0.bin --expected <sha256> --yes
  ```

  `--expected` is **mandatory**: re-pin updates the pin only if the on-disk
  bytes already hash to it. If they do not, the disk is genuinely corrupt — the
  command refuses (re-pin cannot heal corruption); restore from backup first.
