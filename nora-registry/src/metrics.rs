// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use memchr::memmem;
use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge,
    register_int_gauge_vec, Encoder, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, TextEncoder,
};
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use crate::AppState;

/// Total HTTP requests counter
pub static HTTP_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_http_requests_total",
        "Total number of HTTP requests",
        &["registry", "method", "status"]
    )
    .expect("failed to create HTTP_REQUESTS_TOTAL metric at startup")
});

/// Curation engine decisions, by effective outcome. Makes allow/deny visible in
/// telemetry — previously curation only kept internal counters, so an operator
/// could not see from Prometheus how often curation allowed vs blocked.
/// Labels: `decision` ∈ {allow, block, audit (would-block, allowed in audit
/// mode), skip}.
pub static CURATION_DECISIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_curation_decisions_total",
        "Curation engine decisions by effective outcome",
        &["decision"]
    )
    .expect("failed to create CURATION_DECISIONS_TOTAL metric at startup")
});

/// Internal-namespace requests refused by namespace isolation — the
/// dependency-confusion defense firing: an internal name that was neither served
/// from local storage nor proxied upstream (blocked / 404'd). Previously the guard
/// was invisible in Prometheus (only a client 403/404 and a test-internal counter
/// existed), so an operator could neither alert on nor graph it. By registry.
pub static NAMESPACE_ISOLATION_REFUSED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_namespace_isolation_refused_total",
        "Internal-namespace requests refused by namespace isolation (never served locally, never proxied upstream), by registry",
        &["registry"]
    )
    .expect("failed to create NAMESPACE_ISOLATION_REFUSED_TOTAL metric at startup")
});

/// Record one namespace-isolation refusal for `registry` (dependency-confusion
/// defense). `registry` must be a [`crate::registry_type::RegistryType::as_str`] value.
pub fn record_namespace_isolation_refused(registry: &str) {
    NAMESPACE_ISOLATION_REFUSED_TOTAL
        .with_label_values(&[registry])
        .inc();
}

/// Proxy artifacts held by the digest quarantine, by registry and outcome
/// (`blocked` = enforce returned 403; `observed` = observe served but recorded).
/// Gives the operator an alertable/graphable signal — the quarantine was
/// previously visible only in WARN logs.
pub static QUARANTINE_HOLDS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_quarantine_holds_total",
        "Proxy artifacts held by the digest quarantine, by registry and outcome",
        &["registry", "outcome"]
    )
    .expect("failed to create QUARANTINE_HOLDS_TOTAL metric at startup")
});

/// Conditional revalidations where upstream answered 304 Not Modified — the
/// cached body was reused and no body bytes were downloaded (#596).
pub static PROXY_UPSTREAM_304_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_proxy_upstream_304_total",
        "Upstream 304 Not Modified responses on revalidation",
        &["registry"]
    )
    .expect("failed to create PROXY_UPSTREAM_304_TOTAL metric at startup")
});

/// Body bytes saved by revalidation (size of the cached body that did NOT have
/// to be re-downloaded because upstream returned 304) (#596).
pub static PROXY_REVALIDATION_BYTES_SAVED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_proxy_revalidation_bytes_saved_total",
        "Body bytes not re-downloaded thanks to a 304 revalidation",
        &["registry"]
    )
    .expect("failed to create PROXY_REVALIDATION_BYTES_SAVED_TOTAL metric at startup")
});

/// Revalidation attempts that failed (conditional request error, corrupt
/// validator sidecar, missing cached body) and fell back to a full fetch.
/// Nonzero signals the feature is silently degrading (#596).
pub static PROXY_REVALIDATION_ERRORS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_proxy_revalidation_errors_total",
        "Revalidation attempts that fell back to a full fetch",
        &["registry"]
    )
    .expect("failed to create PROXY_REVALIDATION_ERRORS_TOTAL metric at startup")
});

/// Concurrent upstream fetches collapsed into one by the single-flight
/// coalescer: a follower served the leader's in-memory result without making
/// its own upstream round-trip (#595).
pub static PROXY_COALESCED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_proxy_coalesced_total",
        "Follower requests served from the single-flight leader without an upstream fetch",
        &["registry"]
    )
    .expect("failed to create PROXY_COALESCED_TOTAL metric at startup")
});

/// Current number of in-flight single-flight leaders (distinct keys being
/// fetched right now). A flat zero under load means coalescing is not engaging;
/// a monotonic climb signals a guard leak (#595).
pub static PROXY_INFLIGHT: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "nora_proxy_inflight",
        "Distinct keys currently being fetched under single-flight coalescing",
        &["registry"]
    )
    .expect("failed to create PROXY_INFLIGHT metric at startup")
});

/// Followers that did NOT get the leader's result and fell through to their own
/// upstream fetch — because the leader failed/cancelled (`leader`) or the wait
/// budget elapsed while the leader was still fetching (`budget`). A `budget`
/// rate rivalling `PROXY_COALESCED_TOTAL` means a slow upstream is re-stampeding
/// past the coalescer; without this it degrades silently (#595).
pub static PROXY_COALESCE_FALLTHROUGH_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_proxy_coalesce_fallthrough_total",
        "Followers that fell through to their own fetch instead of coalescing",
        &["registry", "reason"]
    )
    .expect("failed to create PROXY_COALESCE_FALLTHROUGH_TOTAL metric at startup")
});

/// HTTP request duration histogram
pub static HTTP_REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "nora_http_request_duration_seconds",
        "HTTP request latency in seconds",
        &["registry", "method"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("failed to create HTTP_REQUEST_DURATION metric at startup")
});

/// Cache requests counter (hit/miss)
pub static CACHE_REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_cache_requests_total",
        "Total cache requests",
        &["registry", "result"]
    )
    .expect("failed to create CACHE_REQUESTS metric at startup")
});

/// Storage operations counter
pub static STORAGE_OPERATIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_storage_operations_total",
        "Total storage operations",
        &["operation", "status"]
    )
    .expect("failed to create STORAGE_OPERATIONS metric at startup")
});

/// OIDC namespace_scope enforcement decisions, by provider and decision.
/// `decision` is one of: allow | deny | would_deny (audit mode). Lets operators
/// watch a staged rollout before switching a provider from audit to enforce (#583).
pub static NAMESPACE_SCOPE_DECISIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_auth_namespace_scope_total",
        "OIDC namespace_scope enforcement decisions",
        &["provider", "decision"]
    )
    .expect("failed to create NAMESPACE_SCOPE_DECISIONS metric at startup")
});

/// Current number of artifacts by registry (gauge — rises and falls with GC)
pub static ARTIFACTS_TOTAL: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "nora_artifacts_total",
        "Current number of artifacts by registry",
        &["registry"]
    )
    .expect("failed to create ARTIFACTS_TOTAL metric at startup")
});

/// Circuit breaker state per registry (0=closed, 1=open, 2=half_open)
pub static CIRCUIT_BREAKER_STATE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "nora_circuit_breaker_state",
        "Circuit breaker state (0=closed, 1=open, 2=half_open)",
        &["registry"]
    )
    .expect("failed to create CIRCUIT_BREAKER_STATE metric at startup")
});

/// Total requests rejected by circuit breaker
pub static CIRCUIT_BREAKER_REJECTIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_circuit_breaker_rejections_total",
        "Total requests rejected by circuit breaker",
        &["registry"]
    )
    .expect("failed to create CIRCUIT_BREAKER_REJECTIONS metric at startup")
});

/// Upstream URL leak detections in responses (#386)
pub static UPSTREAM_URL_LEAK_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_response_upstream_url_leak_total",
        "Upstream hostname detected in outgoing response body",
        &["registry"]
    )
    .expect("failed to create UPSTREAM_URL_LEAK_TOTAL metric at startup")
});

/// Upstream proxy request latency (#431)
pub static UPSTREAM_REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "nora_upstream_request_duration_seconds",
        "Upstream proxy request latency in seconds",
        &["registry", "status"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
    )
    .expect("failed to create UPSTREAM_REQUEST_DURATION metric at startup")
});

/// Wall-clock time of the integrity-verify step on a buffered `Storage::get()`
/// — the `spawn_blocking(pins.verify(..))` call. Includes blocking-pool queue
/// time, so a rising p99 under read load signals pool saturation, not just hash
/// cost. Recorded whenever a pin store is configured (Local backend); a key
/// with no pin returns early inside `verify()` and contributes a near-zero
/// sample. Quantifies the #602 perf question before any change is made (#602).
pub static STORAGE_VERIFY_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "nora_storage_verify_duration_seconds",
        "Integrity-verify (SHA-256) wall-clock per buffered get, including blocking-pool queue",
        &["registry"],
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
    )
    .expect("failed to create STORAGE_VERIFY_DURATION_SECONDS metric at startup")
});

/// Size in bytes of bodies served through the buffered `Storage::get()` path.
/// Shows how much read traffic is large enough for inline hashing to matter —
/// the data needed to decide whether a size threshold is worthwhile (#602).
pub static STORAGE_GET_BYTES: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "nora_storage_get_bytes",
        "Body size of buffered Storage::get() reads",
        &["registry"],
        vec![
            1024.0,
            16_384.0,
            262_144.0,
            1_048_576.0,
            8_388_608.0,
            67_108_864.0,
            536_870_912.0
        ]
    )
    .expect("failed to create STORAGE_GET_BYTES metric at startup")
});

/// Total artifact downloads by registry (#431)
pub static DOWNLOADS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_downloads_total",
        "Total artifact downloads",
        &["registry"]
    )
    .expect("failed to create DOWNLOADS_TOTAL metric at startup")
});

/// Total artifact uploads by registry (#431)
pub static UPLOADS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_uploads_total",
        "Total artifact uploads",
        &["registry"]
    )
    .expect("failed to create UPLOADS_TOTAL metric at startup")
});

/// Storage size in bytes by registry (#431)
pub static STORAGE_BYTES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "nora_storage_bytes",
        "Stored artifact bytes per registry (label \"total\" = full storage footprint incl. metadata)",
        &["registry"]
    )
    .expect("failed to create STORAGE_BYTES metric at startup")
});

/// Process uptime in seconds (gauge)
pub static UPTIME_SECONDS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!("nora_uptime_seconds", "Process uptime in seconds")
        .expect("failed to create UPTIME_SECONDS metric at startup")
});

/// Cache write errors by registry and operation (#500)
pub static CACHE_WRITE_ERRORS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_cache_write_errors_total",
        "Cache write failures in background cache tasks",
        &["registry", "operation"]
    )
    .expect("failed to create CACHE_WRITE_ERRORS metric at startup")
});

/// Corrupt metadata detected during publish (#533)
pub static METADATA_CORRUPT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_metadata_corrupt_total",
        "Corrupt metadata detected during publish (parse failure on existing data)",
        &["registry"]
    )
    .expect("failed to create METADATA_CORRUPT_TOTAL metric at startup")
});

/// Leak detection scans skipped (#517)
static LEAK_DETECTION_SKIPPED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_leak_detection_skipped_total",
        "Leak detection scans skipped (body too large or unknown size)",
        &["reason"]
    )
    .expect("failed to create LEAK_DETECTION_SKIPPED metric at startup")
});

/// Active streaming proxy downloads in progress (#580).
///
/// Incremented when `fetch_blob_from_upstream` starts streaming, decremented
/// on completion or error. Used to detect concurrent download pressure.
pub static PROXY_ACTIVE_DOWNLOADS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "nora_proxy_active_downloads",
        "Number of Docker blob proxy downloads currently in progress"
    )
    .expect("failed to create PROXY_ACTIVE_DOWNLOADS metric at startup")
});

/// Total bytes successfully downloaded from upstream via proxy (#580).
///
/// Only incremented after a complete, verified download (not on failures).
/// Use with `rate()` in Prometheus to track upstream bandwidth consumption.
pub static PROXY_DOWNLOAD_BYTES: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "nora_proxy_download_bytes_total",
        "Total bytes successfully downloaded from upstream Docker registries"
    )
    .expect("failed to create PROXY_DOWNLOAD_BYTES metric at startup")
});

/// Maximum response body size to scan for upstream URL leaks (2 MB).
const LEAK_SCAN_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Pre-compiled substring searchers for upstream hostname leak detection.
///
/// Built once at startup from `Config::upstream_hostnames()` and stored in `AppState`.
#[derive(Clone)]
pub struct LeakFinders {
    entries: Arc<Vec<LeakFinderEntry>>,
}

#[derive(Clone)]
struct LeakFinderEntry {
    registry: String,
    hostname: String,
    finder: memmem::Finder<'static>,
}

impl LeakFinders {
    /// Build leak finders from (registry, hostname) pairs.
    pub fn new(hostnames: Vec<(String, String)>) -> Self {
        let entries = hostnames
            .into_iter()
            .map(|(registry, hostname)| {
                let finder = memmem::Finder::new(hostname.as_bytes()).into_owned();
                LeakFinderEntry {
                    registry,
                    hostname,
                    finder,
                }
            })
            .collect();
        Self {
            entries: Arc::new(entries),
        }
    }

    /// Scan bytes for any upstream hostname. Returns first match.
    fn scan(&self, haystack: &[u8]) -> Option<(&str, &str)> {
        for entry in self.entries.iter() {
            if entry.finder.find(haystack).is_some() {
                return Some((&entry.registry, &entry.hostname));
            }
        }
        None
    }

    /// Returns true if no finders are configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Routes for metrics endpoint
pub fn routes() -> Router<AppState> {
    Router::new().route("/metrics", get(metrics_handler))
}

/// Handler for /metrics endpoint
async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();

    encoder
        .encode(&metric_families, &mut buffer)
        .unwrap_or_default();

    ([("content-type", "text/plain; charset=utf-8")], buffer)
}

/// Middleware to record request metrics
pub async fn metrics_middleware(
    matched_path: Option<MatchedPath>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = request.method().to_string();
    let path = matched_path
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    // Determine registry from path
    let registry = detect_registry(&path);

    // Process request
    let response = next.run(request).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    // Record metrics
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[&registry, &method, &status])
        .inc();

    HTTP_REQUEST_DURATION
        .with_label_values(&[&registry, &method])
        .observe(duration);

    response
}

/// Middleware to detect upstream URL leaks in JSON response bodies (#386).
///
/// Scans outgoing JSON responses for configured upstream hostnames.
/// Detection only — never blocks responses. Increments counter and logs WARN.
pub async fn leak_detection_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let response = next.run(request).await;

    // Fast path: skip if no finders configured
    if state.leak_finders.is_empty() {
        return response;
    }

    // Only scan JSON responses
    let is_json = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("json"));
    if !is_json {
        return response;
    }

    // Skip NORA's own admin/UI/observability surface (#624). These endpoints
    // (the dashboard, stats, OpenAPI spec, health) legitimately echo the
    // configured upstream URLs in their JSON — that is expected output, not a
    // failed rewrite. Proxying only ever happens inside registry handlers on
    // registry-protocol paths (ADR-4), so a configured upstream hostname here is
    // never a leak. Scanning them poisons UPSTREAM_URL_LEAK_TOTAL with false
    // positives and drowns the signal for genuine proxy-response leaks.
    //
    // Denylist (skip own-surface), not allowlist (scan only known registry
    // paths): a security detector must fail toward over-scanning. An allowlist
    // would silently blind the detector on any newly added registry path whose
    // prefix nobody remembered to register — a missed leak is far worse than a
    // stray scan. The skip is counted so it never goes silent.
    if is_own_surface(&path) {
        LEAK_DETECTION_SKIPPED
            .with_label_values(&["own_surface"])
            .inc();
        return response;
    }

    // Determine body size BEFORE consuming it (#517).
    // Primary: body.size_hint().exact() — works for handler-built responses (Full<Bytes>).
    // Fallback: Content-Length header — works for proxy responses where upstream set it.
    // If both are None (streaming/chunked without CL), skip scan to avoid body loss.
    use axum::body::HttpBody as _;
    let size_hint_exact = response.body().size_hint().exact().map(|s| s as usize);
    let content_length = response
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    let known_size = size_hint_exact.or(content_length);

    match known_size {
        Some(size) if size > LEAK_SCAN_MAX_BYTES => {
            LEAK_DETECTION_SKIPPED
                .with_label_values(&["too_large"])
                .inc();
            return response;
        }
        None => {
            // Unknown body size — cannot safely consume (body is one-shot stream).
            LEAK_DETECTION_SKIPPED
                .with_label_values(&["unknown_size"])
                .inc();
            return response;
        }
        Some(_) => {} // Size known and within limit — proceed to scan
    }

    let is_gzip = response
        .headers()
        .get(axum::http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ce| ce.contains("gzip"));

    // CANCEL-SAFETY: to_bytes consumes the body stream (one-shot). If this future is
    // dropped, the body is partially consumed and cannot be restored. The size pre-check
    // above ensures we only reach here for known-size bodies within the limit, so
    // cancellation would only occur from external timeout, not from exceeding the limit.
    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, LEAK_SCAN_MAX_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            // Defense-in-depth: should be unreachable with correct size pre-check.
            // Body is already consumed — cannot restore. Return 502 so clients
            // know the response is broken, not 200-with-empty-body (#540).
            LEAK_DETECTION_SKIPPED
                .with_label_values(&["body_read_error"])
                .inc();
            tracing::error!(
                path = path.as_str(),
                size_hint = ?size_hint_exact,
                content_length = ?content_length,
                "leak_detection: body read failed after size pre-check passed — response body lost"
            );
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                "upstream response error",
            )
                .into_response();
        }
    };

    // Skip tiny bodies
    if body_bytes.len() < 20 {
        return Response::from_parts(parts, Body::from(body_bytes));
    }

    // Decompress gzip if needed, scan decompressed bytes
    let scan_bytes: Vec<u8>;
    let haystack = if is_gzip {
        match decompress_gzip(&body_bytes) {
            Some(decompressed) => {
                scan_bytes = decompressed;
                &scan_bytes
            }
            None => &body_bytes[..],
        }
    } else {
        &body_bytes[..]
    };

    if let Some((registry, hostname)) = state.leak_finders.scan(haystack) {
        UPSTREAM_URL_LEAK_TOTAL.with_label_values(&[registry]).inc();
        tracing::warn!(
            registry = registry,
            upstream = hostname,
            path = path.as_str(),
            body_len = haystack.len(),
            "upstream URL leak detected in response"
        );
    }

    // Return original (possibly gzip-compressed) body unchanged
    Response::from_parts(parts, Body::from(body_bytes))
}

/// Decompress gzip bytes; returns None on failure or if decompressed size exceeds limit.
///
/// Capped at `LEAK_SCAN_MAX_BYTES` to prevent gzip bomb attacks (#517).
fn decompress_gzip(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let decoder = GzDecoder::new(data);
    // Cap decompression to prevent gzip bombs (e.g. 42KB compressed → 4.5GB decompressed).
    let mut limited = decoder.take(LEAK_SCAN_MAX_BYTES as u64);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf).ok()?;
    // Check if data was truncated (more bytes available beyond cap)
    let mut probe = [0u8; 1];
    if limited.into_inner().read(&mut probe).unwrap_or(0) > 0 {
        LEAK_DETECTION_SKIPPED
            .with_label_values(&["gzip_truncated"])
            .inc();
        tracing::debug!(
            compressed_len = data.len(),
            decompressed_cap = LEAK_SCAN_MAX_BYTES,
            "leak_detection: gzip decompression truncated at scan limit"
        );
    }
    debug_assert!(buf.len() <= LEAK_SCAN_MAX_BYTES);
    Some(buf)
}

/// Returns true for NORA's own admin / UI / observability endpoints.
///
/// These surfaces may legitimately include configured upstream URLs in their
/// responses (e.g. the dashboard listing which upstreams a registry proxies),
/// so an upstream hostname appearing here is expected output, not a rewrite
/// leak. Proxying happens exclusively inside registry handlers on
/// registry-protocol paths (ADR-4); none of those paths share these prefixes,
/// so excluding the own surface cannot blind leak detection on a proxy path —
/// the `every_registry_prefix_stays_scannable` test guards that invariant.
///
/// Prefixes are matched with a boundary (`/api/`, not bare `/api`) so a
/// hypothetical registry path like `/apiv2foo` is not skipped by accident.
///
/// INVARIANT (deliberate fail-open by prefix): the `/api/` prefix excludes every
/// current and future endpoint under it. Any future `/api/*` route that serves
/// *proxied upstream* content (not NORA's own config/data) MUST therefore be
/// kept off the own surface — either route it under a registry prefix or exclude
/// it from this function explicitly — or its upstream-URL leaks will go unscanned.
fn is_own_surface(path: &str) -> bool {
    path.starts_with("/api/")          // HTMX JSON backend: dashboard, stats, list, detail, search, tokens
        || path.starts_with("/api-docs") // Swagger UI + /api-docs/openapi.json spec
        || path == "/ui"
        || path.starts_with("/ui/")    // UI pages (HTML, scanned defensively)
        || path == "/health"
        || path == "/ready"
        || path == "/metrics"
}

/// Detect registry type from path
fn detect_registry(path: &str) -> String {
    if path.starts_with("/v2") {
        "docker".to_string()
    } else if path.starts_with("/maven2") {
        "maven".to_string()
    } else if path.starts_with("/npm") {
        "npm".to_string()
    } else if path.starts_with("/cargo") {
        "cargo".to_string()
    } else if path.starts_with("/simple") || path.starts_with("/packages") {
        "pypi".to_string()
    } else if path.starts_with("/go/") {
        "go".to_string()
    } else if path.starts_with("/raw/") {
        "raw".to_string()
    } else if path.starts_with("/gems/") {
        "gems".to_string()
    } else if path.starts_with("/terraform/") {
        "terraform".to_string()
    } else if path.starts_with("/ansible/") {
        "ansible".to_string()
    } else if path.starts_with("/nuget/") {
        "nuget".to_string()
    } else if path.starts_with("/pub/") {
        "pub".to_string()
    } else if path.starts_with("/conan/") {
        "conan".to_string()
    } else if path.starts_with("/ui") {
        "ui".to_string()
    } else {
        "other".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_registry_docker() {
        assert_eq!(detect_registry("/v2/nginx/manifests/latest"), "docker");
        assert_eq!(detect_registry("/v2/"), "docker");
        assert_eq!(
            detect_registry("/v2/library/alpine/blobs/sha256:abc"),
            "docker"
        );
    }

    #[test]
    fn test_detect_registry_maven() {
        assert_eq!(detect_registry("/maven2/com/example/artifact"), "maven");
    }

    #[test]
    fn test_detect_registry_npm() {
        assert_eq!(detect_registry("/npm/lodash"), "npm");
        assert_eq!(detect_registry("/npm/@scope/package"), "npm");
    }

    #[test]
    fn test_detect_registry_cargo_path() {
        assert_eq!(detect_registry("/cargo/api/v1/crates"), "cargo");
    }

    #[test]
    fn test_detect_registry_pypi() {
        assert_eq!(detect_registry("/simple/requests/"), "pypi");
        assert_eq!(
            detect_registry("/packages/requests/1.0/requests-1.0.tar.gz"),
            "pypi"
        );
    }

    #[test]
    fn test_detect_registry_ui() {
        assert_eq!(detect_registry("/ui/dashboard"), "ui");
        assert_eq!(detect_registry("/ui"), "ui");
    }

    #[test]
    fn test_detect_registry_other() {
        assert_eq!(detect_registry("/health"), "other");
        assert_eq!(detect_registry("/ready"), "other");
        assert_eq!(detect_registry("/unknown/path"), "other");
    }

    #[test]
    fn test_detect_registry_go_path() {
        assert_eq!(
            detect_registry("/go/github.com/user/repo/@v/v1.0.0.info"),
            "go"
        );
        assert_eq!(detect_registry("/go/github.com/user/repo/@latest"), "go");
        // Bare prefix without trailing slash should not match
        assert_eq!(detect_registry("/goblin/something"), "other");
    }

    #[test]
    fn test_detect_registry_raw_path() {
        assert_eq!(detect_registry("/raw/my-project/artifact.tar.gz"), "raw");
        assert_eq!(detect_registry("/raw/data/file.bin"), "raw");
        // Bare prefix without trailing slash should not match
        assert_eq!(detect_registry("/rawdata/file"), "other");
    }

    #[test]
    fn test_leak_finders_detects_upstream_hostname() {
        let finders = LeakFinders::new(vec![
            ("nuget".to_string(), "api.nuget.org".to_string()),
            ("npm".to_string(), "registry.npmjs.org".to_string()),
        ]);
        let body = br#"{"@id":"https://api.nuget.org/v3/registration/newtonsoft.json"}"#;
        let result = finders.scan(body);
        assert!(result.is_some());
        let (registry, hostname) = result.unwrap();
        assert_eq!(registry, "nuget");
        assert_eq!(hostname, "api.nuget.org");
    }

    #[test]
    fn test_leak_finders_no_match_returns_none() {
        let finders = LeakFinders::new(vec![("nuget".to_string(), "api.nuget.org".to_string())]);
        let body = br#"{"@id":"http://localhost:4000/nuget/v3/registration/newtonsoft.json"}"#;
        assert!(finders.scan(body).is_none());
    }

    #[test]
    fn test_leak_finders_empty_has_no_match() {
        let finders = LeakFinders::new(vec![]);
        assert!(finders.is_empty());
        assert!(finders.scan(b"anything").is_none());
    }

    #[test]
    fn test_decompress_gzip_roundtrip() {
        use flate2::write::GzEncoder;
        use std::io::Write;
        let original = b"hello upstream api.nuget.org world";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_gzip(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_leak_finders_detects_in_decompressed_gzip() {
        use flate2::write::GzEncoder;
        use std::io::Write;
        let finders = LeakFinders::new(vec![("nuget".to_string(), "api.nuget.org".to_string())]);
        let body = br#"{"packageContent":"https://api.nuget.org/v3-flatcontainer/pkg/1.0.0/pkg.1.0.0.nupkg"}"#;
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(body).unwrap();
        let compressed = encoder.finish().unwrap();

        // Compressed bytes should NOT match (gzip obfuscates)
        assert!(finders.scan(&compressed).is_none());

        // Decompressed bytes should match
        let decompressed = decompress_gzip(&compressed).unwrap();
        let result = finders.scan(&decompressed);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "nuget");
    }

    #[test]
    fn test_decompress_gzip_capped_at_limit() {
        use flate2::write::GzEncoder;
        use std::io::Write;
        // Create data larger than LEAK_SCAN_MAX_BYTES
        let large_data = vec![b'A'; LEAK_SCAN_MAX_BYTES + 1024];
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&large_data).expect("gzip encode");
        let compressed = encoder.finish().expect("gzip finish");

        // decompress_gzip must cap output at LEAK_SCAN_MAX_BYTES
        let result = decompress_gzip(&compressed).expect("decompress");
        assert!(result.len() <= LEAK_SCAN_MAX_BYTES);
    }

    #[test]
    fn test_decompress_gzip_invalid_data_returns_none() {
        // Random bytes are not valid gzip
        assert!(decompress_gzip(b"not gzip data at all").is_none());
        assert!(decompress_gzip(b"").is_none());
    }

    #[test]
    fn test_decompress_gzip_normal_data_unchanged() {
        use flate2::write::GzEncoder;
        use std::io::Write;
        // Data well under the limit should decompress fully
        let original = b"small payload for leak scanning test";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(original).expect("gzip encode");
        let compressed = encoder.finish().expect("gzip finish");

        let result = decompress_gzip(&compressed).expect("decompress");
        assert_eq!(result, original);
    }

    // --- #624: own-surface exclusion from upstream-URL leak detection ---

    #[test]
    fn is_own_surface_covers_admin_ui_and_observability() {
        // Exact strings as produced by axum `Uri::path()` (query stripped).
        assert!(is_own_surface("/api/ui/dashboard"));
        assert!(is_own_surface("/api/ui/stats"));
        assert!(is_own_surface("/api/ui/cargo/list"));
        assert!(is_own_surface("/api-docs/openapi.json"));
        assert!(is_own_surface("/ui"));
        assert!(is_own_surface("/ui/"));
        assert!(is_own_surface("/ui/cargo"));
        assert!(is_own_surface("/health"));
        assert!(is_own_surface("/ready"));
        assert!(is_own_surface("/metrics"));
    }

    #[test]
    fn is_own_surface_does_not_over_match_at_prefix_boundary() {
        // Boundary-aware: must not skip paths that merely start with the letters.
        assert!(!is_own_surface("/apiv2foo")); // not "/api/"
        assert!(!is_own_surface("/uikit/widget")); // not "/ui" or "/ui/"
        assert!(!is_own_surface("/metrics-export"));
        assert!(!is_own_surface("/healthcheck-proxy"));
    }

    #[test]
    fn every_registry_prefix_stays_scannable() {
        // Guard: the own-surface denylist must never swallow a registry-protocol
        // path, or the leak detector would go silently blind on that format.
        // These are the prefixes registry handlers actually route on.
        for p in [
            "/v2/library/alpine/manifests/latest",
            "/maven2/com/example/artifact/1.0/artifact-1.0.jar",
            "/npm/lodash",
            "/cargo/api/v1/crates/serde",
            "/simple/requests/",
            "/packages/requests/1.0/requests-1.0.tar.gz",
            "/go/github.com/user/repo/@v/v1.0.0.info",
            "/raw/my-project/artifact.tar.gz",
            "/gems/rails-7.0.0.gem",
            "/terraform/example/aws/1.0.0",
            "/ansible/community/general/1.0.0",
            "/nuget/v3/index.json",
            "/pub/api/packages/http",
            "/conan/v2/conans/zlib",
        ] {
            assert!(
                !is_own_surface(p),
                "registry path must remain scannable: {p}"
            );
        }
    }

    /// Build a minimal router that drives the REAL `leak_detection_middleware`
    /// over a single handler-built JSON response (PM-4: test the call-path, not
    /// the helper in isolation). A unique canary hostname per test keeps the
    /// global counter assertions free of cross-test races.
    fn leak_test_app(
        route: &'static str,
        registry_label: &'static str,
        canary_host: &'static str,
        body: &'static str,
    ) -> (axum::Router, AppState) {
        use axum::routing::get;
        let mut ctx = crate::test_helpers::create_test_context();
        ctx.state.leak_finders =
            LeakFinders::new(vec![(registry_label.to_string(), canary_host.to_string())]);
        let state = ctx.state.clone();
        // The leak middleware only inspects the response body — it never touches
        // storage — so the context's tempdir may drop at the end of this helper
        // without affecting the test.
        let app = axum::Router::new()
            .route(
                route,
                get(move || async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                leak_detection_middleware,
            ))
            .with_state(state.clone());
        (app, state)
    }

    #[tokio::test]
    async fn own_surface_dashboard_json_is_not_flagged_as_leak() {
        use tower::ServiceExt;
        let (app, _state) = leak_test_app(
            "/api/ui/dashboard",
            "canary624a",
            "leak-canary-624a.invalid",
            r#"{"registries":[{"name":"cargo","upstream":"leak-canary-624a.invalid"}]}"#,
        );
        let leak_before = UPSTREAM_URL_LEAK_TOTAL
            .with_label_values(&["canary624a"])
            .get();
        let skip_before = LEAK_DETECTION_SKIPPED
            .with_label_values(&["own_surface"])
            .get();

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/ui/dashboard?lang=en")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let leak_after = UPSTREAM_URL_LEAK_TOTAL
            .with_label_values(&["canary624a"])
            .get();
        let skip_after = LEAK_DETECTION_SKIPPED
            .with_label_values(&["own_surface"])
            .get();
        assert_eq!(
            leak_before, leak_after,
            "dashboard echoing an upstream URL must NOT be counted as a leak"
        );
        assert!(
            skip_after > skip_before,
            "own-surface skip must be observable via LEAK_DETECTION_SKIPPED"
        );
    }

    #[tokio::test]
    async fn registry_proxy_json_with_upstream_url_is_still_flagged() {
        use tower::ServiceExt;
        let (app, _state) = leak_test_app(
            "/npm/leftpad",
            "canary624b",
            "leak-canary-624b.invalid",
            r#"{"dist":{"tarball":"https://leak-canary-624b.invalid/leftpad-1.0.0.tgz"}}"#,
        );
        let leak_before = UPSTREAM_URL_LEAK_TOTAL
            .with_label_values(&["canary624b"])
            .get();

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/npm/leftpad")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let leak_after = UPSTREAM_URL_LEAK_TOTAL
            .with_label_values(&["canary624b"])
            .get();
        assert_eq!(
            leak_after,
            leak_before + 1,
            "a registry proxy response leaking an upstream URL must be flagged"
        );
    }
}
