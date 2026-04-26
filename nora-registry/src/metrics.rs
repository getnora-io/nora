// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use axum::{
    body::Body,
    extract::MatchedPath,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use lazy_static::lazy_static;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, Encoder, HistogramVec, IntCounterVec,
    TextEncoder,
};
use std::sync::Arc;
use std::time::Instant;

use crate::AppState;

lazy_static! {
    /// Total HTTP requests counter
    pub static ref HTTP_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "nora_http_requests_total",
        "Total number of HTTP requests",
        &["registry", "method", "status"]
    ).expect("failed to create HTTP_REQUESTS_TOTAL metric at startup");

    /// HTTP request duration histogram
    pub static ref HTTP_REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "nora_http_request_duration_seconds",
        "HTTP request latency in seconds",
        &["registry", "method"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    ).expect("failed to create HTTP_REQUEST_DURATION metric at startup");

    /// Cache requests counter (hit/miss)
    pub static ref CACHE_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "nora_cache_requests_total",
        "Total cache requests",
        &["registry", "result"]
    ).expect("failed to create CACHE_REQUESTS metric at startup");

    /// Storage operations counter
    pub static ref STORAGE_OPERATIONS: IntCounterVec = register_int_counter_vec!(
        "nora_storage_operations_total",
        "Total storage operations",
        &["operation", "status"]
    ).expect("failed to create STORAGE_OPERATIONS metric at startup");

    /// Artifacts count by registry
    pub static ref ARTIFACTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "nora_artifacts_total",
        "Total artifacts stored",
        &["registry"]
    ).expect("failed to create ARTIFACTS_TOTAL metric at startup");
}

/// Routes for metrics endpoint
pub fn routes() -> Router<Arc<AppState>> {
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
    } else if path.starts_with("/api/packages")
        || (path.starts_with("/packages/") && path.contains("/versions/"))
    {
        "pub".to_string()
    } else if path.starts_with("/simple") || path.starts_with("/packages") {
        "pypi".to_string()
    } else if path.starts_with("/go/") {
        "go".to_string()
    } else if path.starts_with("/raw/") {
        "raw".to_string()
    } else if path.starts_with("/ui") {
        "ui".to_string()
    } else {
        "other".to_string()
    }
}

/// Record cache hit
#[allow(dead_code)]
pub fn record_cache_hit(registry: &str) {
    CACHE_REQUESTS.with_label_values(&[registry, "hit"]).inc();
}

/// Record cache miss
#[allow(dead_code)]
pub fn record_cache_miss(registry: &str) {
    CACHE_REQUESTS.with_label_values(&[registry, "miss"]).inc();
}

/// Record storage operation
#[allow(dead_code)]
pub fn record_storage_op(operation: &str, success: bool) {
    let status = if success { "success" } else { "error" };
    STORAGE_OPERATIONS
        .with_label_values(&[operation, status])
        .inc();
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
        assert_eq!(detect_registry("/simple/requests/pkg-1.0.0.tar.gz"), "pypi");
    }

    #[test]
    fn test_detect_registry_pub() {
        assert_eq!(detect_registry("/api/packages?q=http"), "pub");
        assert_eq!(
            detect_registry("/packages/http/versions/1.0.0.tar.gz"),
            "pub"
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
    fn test_record_cache_hit() {
        record_cache_hit("docker");
        // Doesn't panic — metric is recorded
    }

    #[test]
    fn test_record_cache_miss() {
        record_cache_miss("npm");
    }

    #[test]
    fn test_record_storage_op_success() {
        record_storage_op("get", true);
    }

    #[test]
    fn test_record_storage_op_error() {
        record_storage_op("put", false);
    }
}
