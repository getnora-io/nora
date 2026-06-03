// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

pub(crate) mod ansible;
mod cargo_registry;
mod conan;
pub mod docker;
pub mod docker_auth;
pub(crate) mod gems;
mod go;
mod maven;
mod npm;
pub(crate) mod nuget;
pub(crate) mod pub_dart;
mod pypi;
mod raw;
pub(crate) mod terraform;

pub use ansible::routes as ansible_routes;
pub use cargo_registry::routes as cargo_routes;
pub use conan::routes as conan_routes;
pub use docker::routes as docker_routes;
pub use docker_auth::DockerAuth;
pub use gems::routes as gems_routes;
pub use go::routes as go_routes;
pub use maven::routes as maven_routes;
pub use npm::routes as npm_routes;
pub use nuget::alias_routes as nuget_alias_routes;
pub use nuget::routes as nuget_routes;
pub use pub_dart::routes as pub_dart_routes;
pub use pypi::routes as pypi_routes;
pub use raw::routes as raw_routes;
pub use terraform::routes as terraform_routes;

use crate::circuit_breaker::CircuitBreakerRegistry;
use crate::config::basic_auth_header;
use crate::metrics::UPSTREAM_REQUEST_DURATION;
use crate::registry_type::RegistryType;
use crate::AppState;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use std::time::{Duration, Instant};

/// 405 Method Not Allowed with `Allow` header (RFC 9110 §15.5.6).
pub(crate) fn method_not_allowed(allow: &'static str) -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, allow)]).into_response()
}

/// Build NORA base URL from config (for URL rewriting).
///
/// Thin wrapper over [`ServerConfig::public_base_url`] — the single source of
/// truth for client-facing URLs.
pub(crate) fn nora_base_url(state: &AppState) -> String {
    state.config.server.public_base_url()
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ProxyError {
    NotFound,
    Upstream(u16),
    Network(String),
    CircuitOpen(String),
}

/// 503 response for circuit breaker open state with Retry-After header.
pub(crate) fn circuit_open_response(registry: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [("retry-after", "30")],
        format!("upstream {} temporarily unavailable", registry),
    )
        .into_response()
}

/// Core fetch logic with retry. Callers provide a response extractor.
#[allow(clippy::too_many_arguments)]
async fn proxy_fetch_core<T, F, Fut>(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<&str>,
    extra_headers: Option<(&str, &str)>,
    extract: F,
    cb: &CircuitBreakerRegistry,
    registry: RegistryType,
) -> Result<T, ProxyError>
where
    F: Fn(reqwest::Response) -> Fut + Copy,
    Fut: std::future::Future<Output = Result<T, reqwest::Error>>,
{
    let registry_str = registry.as_str();
    cb.check(registry_str)?;

    for attempt in 0..2 {
        let mut request = client.get(url).timeout(timeout);
        if let Some(credentials) = auth {
            request = request.header("Authorization", basic_auth_header(credentials));
        }
        if let Some((key, val)) = extra_headers {
            request = request.header(key, val);
        }

        let upstream_start = Instant::now();
        match request.send().await {
            Ok(response) => {
                let elapsed = upstream_start.elapsed().as_secs_f64();
                if response.status().is_success() {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "2xx"])
                        .observe(elapsed);
                    let result = extract(response)
                        .await
                        .map_err(|e| ProxyError::Network(e.to_string()));
                    if result.is_ok() {
                        cb.record_success(registry_str);
                    } else {
                        // 2xx but the body could not be read (e.g. a mid-stream
                        // drop) — treat as a fetch failure for the breaker.
                        cb.record_failure(registry_str);
                    }
                    return result;
                }
                let status = response.status().as_u16();
                if (400..500).contains(&status) {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "4xx"])
                        .observe(elapsed);
                    // A 4xx means the upstream is alive and answered — not an
                    // availability failure. `record_alive` closes the breaker
                    // from HalfOpen (so it recovers instead of slow-probing) but
                    // is a no-op in Closed, so a 4xx never clears a real failure
                    // tally (#606).
                    cb.record_alive(registry_str);
                    return Err(ProxyError::NotFound);
                }
                if attempt == 0 {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "5xx"])
                        .observe(elapsed);
                    tracing::debug!(url, status, "upstream 5xx, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                UPSTREAM_REQUEST_DURATION
                    .with_label_values(&[registry_str, "5xx"])
                    .observe(elapsed);
                cb.record_failure(registry_str);
                return Err(ProxyError::Upstream(status));
            }
            Err(e) => {
                let elapsed = upstream_start.elapsed().as_secs_f64();
                let status_label = if e.is_timeout() { "timeout" } else { "error" };
                UPSTREAM_REQUEST_DURATION
                    .with_label_values(&[registry_str, status_label])
                    .observe(elapsed);
                if attempt == 0 {
                    tracing::debug!(url, error = %e, "upstream error, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                cb.record_failure(registry_str);
                return Err(ProxyError::Network(e.to_string()));
            }
        }
    }
    cb.record_failure(registry_str);
    Err(ProxyError::Network("max retries exceeded".into()))
}

/// Fetch binary content from upstream proxy with timeout and 1 retry.
pub(crate) async fn proxy_fetch(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
    registry: RegistryType,
) -> Result<Vec<u8>, ProxyError> {
    proxy_fetch_core(
        client,
        url,
        timeout,
        auth,
        None,
        |r| async { r.bytes().await.map(|b| b.to_vec()) },
        cb,
        registry,
    )
    .await
}

/// Fetch text content from upstream proxy with timeout and 1 retry.
pub(crate) async fn proxy_fetch_text(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<&str>,
    extra_headers: Option<(&str, &str)>,
    cb: &CircuitBreakerRegistry,
    registry: RegistryType,
) -> Result<String, ProxyError> {
    proxy_fetch_core(
        client,
        url,
        timeout,
        auth,
        extra_headers,
        |r| r.text(),
        cb,
        registry,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_fetch_invalid_url() {
        let client = reqwest::Client::new();
        let cb = crate::circuit_breaker::CircuitBreakerRegistry::new(
            crate::config::CircuitBreakerConfig::default(),
        );
        let result = proxy_fetch(
            &client,
            "http://127.0.0.1:1/nonexistent",
            Duration::from_secs(2),
            None,
            &cb,
            RegistryType::Docker, // arbitrary variant, testing proxy logic not registry type
        )
        .await;
        assert!(matches!(result, Err(ProxyError::Network(_))));
    }
}
