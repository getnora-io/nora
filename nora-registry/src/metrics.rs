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
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec, Encoder,
    HistogramVec, IntCounterVec, IntGaugeVec, TextEncoder,
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

/// Artifacts count by registry
#[allow(dead_code)]
pub static ARTIFACTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_artifacts_total",
        "Total artifacts stored",
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
        "Storage size in bytes by registry",
        &["registry"]
    )
    .expect("failed to create STORAGE_BYTES metric at startup")
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

    // Skip if Content-Length exceeds scan limit (avoid consuming body we can't restore)
    let content_length = response
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    if content_length.is_some_and(|len| len > LEAK_SCAN_MAX_BYTES) {
        return response;
    }

    let is_gzip = response
        .headers()
        .get(axum::http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ce| ce.contains("gzip"));

    // Collect response body
    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, LEAK_SCAN_MAX_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            // Body exceeded limit or read failed — can't restore original, return empty.
            // In practice unreachable: Content-Length pre-check above catches oversized bodies.
            tracing::debug!("leak_detection: body read exceeded limit, skipping scan");
            return Response::from_parts(parts, Body::empty());
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

/// Decompress gzip bytes; returns None on failure (non-fatal).
fn decompress_gzip(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(data);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf).ok()?;
    Some(buf)
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
}
