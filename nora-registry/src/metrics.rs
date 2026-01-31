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
    ).expect("metric can be created");

    /// HTTP request duration histogram
    pub static ref HTTP_REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "nora_http_request_duration_seconds",
        "HTTP request latency in seconds",
        &["registry", "method"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    ).expect("metric can be created");

    /// Cache requests counter (hit/miss)
    pub static ref CACHE_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "nora_cache_requests_total",
        "Total cache requests",
        &["registry", "result"]
    ).expect("metric can be created");

    /// Storage operations counter
    pub static ref STORAGE_OPERATIONS: IntCounterVec = register_int_counter_vec!(
        "nora_storage_operations_total",
        "Total storage operations",
        &["operation", "status"]
    ).expect("metric can be created");

    /// Artifacts count by registry
    pub static ref ARTIFACTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "nora_artifacts_total",
        "Total artifacts stored",
        &["registry"]
    ).expect("metric can be created");
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
    } else if path.starts_with("/simple") || path.starts_with("/packages") {
        "pypi".to_string()
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
