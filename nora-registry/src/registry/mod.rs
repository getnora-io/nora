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

// Cross-registry regression suite for namespace isolation on metadata paths (contrib-kit#68).
#[cfg(test)]
mod ns_isolation_metadata_tests;

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
    let probe = cb.check(registry_str)?;

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
                        cb.record_success(registry_str, probe);
                    } else {
                        // 2xx but the body could not be read (e.g. a mid-stream
                        // drop) — treat as a fetch failure for the breaker.
                        cb.record_failure(registry_str, probe);
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
                    cb.record_alive(registry_str, probe);
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
                cb.record_failure(registry_str, probe);
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
                cb.record_failure(registry_str, probe);
                return Err(ProxyError::Network(e.to_string()));
            }
        }
    }
    cb.record_failure(registry_str, probe);
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

/// Forward a POST (request body + an allowlist of headers) to an upstream and
/// return its `(status, body, content-type)` verbatim. Mirrors `proxy_fetch_core`'s
/// circuit-breaker discipline (`check` → send → `record_success`/`record_alive`/
/// `record_failure`, one retry on 5xx/network).
///
/// Used for `npm audit` (#597): a query POST that must return the upstream's answer
/// as-is — including a 4xx (a real audit response, upstream is alive) — with only
/// 5xx / network / circuit-open surfaced as `ProxyError`.
///
/// `auth` is the configured proxy credential (Basic); the caller's own
/// `Authorization` is never forwarded — pass only the intended headers in
/// `fwd_headers` (allowlist). The body is not inspected or decompressed here.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_forward_post(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<&str>,
    fwd_headers: &[(&str, &str)],
    body: &[u8],
    cb: &CircuitBreakerRegistry,
    registry: RegistryType,
) -> Result<(u16, Vec<u8>, Option<String>), ProxyError> {
    let registry_str = registry.as_str();
    let probe = cb.check(registry_str)?;

    for attempt in 0..2 {
        let mut request = client.post(url).timeout(timeout).body(body.to_vec());
        if let Some(credentials) = auth {
            request = request.header("Authorization", basic_auth_header(credentials));
        }
        for (k, v) in fwd_headers {
            request = request.header(*k, *v);
        }

        let upstream_start = Instant::now();
        match request.send().await {
            Ok(response) => {
                let elapsed = upstream_start.elapsed().as_secs_f64();
                let code = response.status().as_u16();
                let content_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                if response.status().is_success() {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "2xx"])
                        .observe(elapsed);
                    match response.bytes().await {
                        Ok(b) => {
                            cb.record_success(registry_str, probe);
                            return Ok((code, b.to_vec(), content_type));
                        }
                        Err(e) => {
                            cb.record_failure(registry_str, probe);
                            return Err(ProxyError::Network(e.to_string()));
                        }
                    }
                }
                if (400..500).contains(&code) {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "4xx"])
                        .observe(elapsed);
                    // Upstream is alive and answered — a 4xx audit response is a real
                    // answer, forward it verbatim (not an availability failure). #606.
                    cb.record_alive(registry_str, probe);
                    let b = response
                        .bytes()
                        .await
                        .map(|b| b.to_vec())
                        .unwrap_or_default();
                    return Ok((code, b, content_type));
                }
                UPSTREAM_REQUEST_DURATION
                    .with_label_values(&[registry_str, "5xx"])
                    .observe(elapsed);
                if attempt == 0 {
                    tracing::debug!(url, status = code, "upstream 5xx on POST, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                cb.record_failure(registry_str, probe);
                return Err(ProxyError::Upstream(code));
            }
            Err(e) => {
                let elapsed = upstream_start.elapsed().as_secs_f64();
                let status_label = if e.is_timeout() { "timeout" } else { "error" };
                UPSTREAM_REQUEST_DURATION
                    .with_label_values(&[registry_str, status_label])
                    .observe(elapsed);
                if attempt == 0 {
                    tracing::debug!(url, error = %e, "upstream error on POST, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                cb.record_failure(registry_str, probe);
                return Err(ProxyError::Network(e.to_string()));
            }
        }
    }
    cb.record_failure(registry_str, probe);
    Err(ProxyError::Network("max retries exceeded".into()))
}

// ============================================================================
// Conditional revalidation (#596)
// ============================================================================

/// Upstream cache validators persisted next to a cached object so a later
/// revalidation can send `If-None-Match` / `If-Modified-Since`. Stored as a
/// `<key>.meta` JSON sidecar — filesystem-first, survives restarts (ADR-2).
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Validators {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

impl Validators {
    /// True if at least one validator is present to drive a conditional request.
    pub fn is_some(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }
}

/// Outcome of a conditional upstream request.
pub(crate) enum Revalidation {
    /// Upstream answered `304 Not Modified` — the cached body is still valid.
    NotModified,
    /// Upstream answered `200` with a (possibly) new body and fresh validators.
    Modified {
        body: Vec<u8>,
        validators: Validators,
    },
}

/// Storage key of the validator sidecar for a cached object.
pub(crate) fn validators_key(key: &str) -> String {
    format!("{key}.meta")
}

/// Read the stored upstream validators for `key`, if any. Fail-open: any
/// read/parse error yields `None` (caller does a full fetch).
pub(crate) async fn read_validators(storage: &crate::Storage, key: &str) -> Option<Validators> {
    let data = storage.get(&validators_key(key)).await.ok()?;
    serde_json::from_slice::<Validators>(&data).ok()
}

/// Persist upstream validators next to `key`. Written AFTER the body so a
/// sidecar never advertises freshness for a body that is not there. A no-op
/// when there is nothing to store.
pub(crate) async fn write_validators(storage: &crate::Storage, key: &str, v: &Validators) {
    if !v.is_some() {
        return;
    }
    if let Ok(data) = serde_json::to_vec(v) {
        if let Err(e) = storage.put(&validators_key(key), &data).await {
            tracing::warn!(key = %key, error = ?e, "failed to write validator sidecar");
        }
    }
}

fn header_string(resp: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Conditional upstream fetch (#596). Sends `If-None-Match`/`If-Modified-Since`
/// from `validators`; returns `NotModified` on 304 (no body downloaded) or
/// `Modified { body, validators }` on 200. With empty `validators` it sends no
/// conditional headers, so it always yields `Modified` — that is how the full
/// fetch path captures validators for the first time.
///
/// Circuit breaker: 304/200 record success; transport/5xx record failure; 4xx
/// returns `NotFound` (matching `proxy_fetch_core`). No retry — revalidation is
/// a lightweight check and the caller falls back to a full fetch on error.
pub(crate) async fn proxy_fetch_conditional(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<&str>,
    validators: &Validators,
    cb: &CircuitBreakerRegistry,
    registry: RegistryType,
) -> Result<Revalidation, ProxyError> {
    let registry_str = registry.as_str();
    let probe = cb.check(registry_str)?;

    let mut request = client.get(url).timeout(timeout);
    if let Some(credentials) = auth {
        request = request.header(header::AUTHORIZATION, basic_auth_header(credentials));
    }
    if let Some(ref etag) = validators.etag {
        request = request.header(header::IF_NONE_MATCH, etag);
    }
    if let Some(ref lm) = validators.last_modified {
        request = request.header(header::IF_MODIFIED_SINCE, lm);
    }

    match request.send().await {
        Ok(response) => {
            let status = response.status();
            if status == reqwest::StatusCode::NOT_MODIFIED {
                cb.record_success(registry_str, probe);
                return Ok(Revalidation::NotModified);
            }
            if status.is_success() {
                let new_validators = Validators {
                    etag: header_string(&response, header::ETAG),
                    last_modified: header_string(&response, header::LAST_MODIFIED),
                };
                let body = response
                    .bytes()
                    .await
                    .map_err(|e| ProxyError::Network(e.to_string()))?;
                cb.record_success(registry_str, probe);
                return Ok(Revalidation::Modified {
                    body: body.to_vec(),
                    validators: new_validators,
                });
            }
            let code = status.as_u16();
            if (400..500).contains(&code) {
                // 4xx — upstream alive; recover the breaker without clearing a
                // real failure tally, consistent with proxy_fetch_core (#606).
                cb.record_alive(registry_str, probe);
                return Err(ProxyError::NotFound);
            }
            cb.record_failure(registry_str, probe);
            Err(ProxyError::Upstream(code))
        }
        Err(e) => {
            cb.record_failure(registry_str, probe);
            Err(ProxyError::Network(e.to_string()))
        }
    }
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

    // --- Conditional revalidation (#596) ---

    fn noop_cb() -> CircuitBreakerRegistry {
        CircuitBreakerRegistry::new(crate::config::CircuitBreakerConfig::default())
    }

    /// With no stored validators, the conditional fetch sends no `If-None-Match`,
    /// always gets a 200, and captures the upstream validators (this is also the
    /// full-fetch path that seeds the sidecar for next time).
    #[tokio::test]
    async fn conditional_200_captures_validators() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"v1\"")
                    .set_body_string("BODY-V1"),
            )
            .mount(&upstream)
            .await;

        let cb = noop_cb();
        let out = proxy_fetch_conditional(
            &reqwest::Client::new(),
            &upstream.uri(),
            Duration::from_secs(5),
            None,
            &Validators::default(),
            &cb,
            RegistryType::Npm,
        )
        .await
        .unwrap();

        match out {
            Revalidation::Modified { body, validators } => {
                assert_eq!(body, b"BODY-V1");
                assert_eq!(validators.etag.as_deref(), Some("\"v1\""));
            }
            Revalidation::NotModified => panic!("expected Modified"),
        }
    }

    /// When validators are present they are sent as `If-None-Match`, and a 304
    /// yields `NotModified` with NO body download. The mock only answers 304 when
    /// the header is present, so a pass proves the header was sent.
    #[tokio::test]
    async fn conditional_304_sends_if_none_match_and_returns_not_modified() {
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;

        let validators = Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        };
        let cb = noop_cb();
        let out = proxy_fetch_conditional(
            &reqwest::Client::new(),
            &upstream.uri(),
            Duration::from_secs(5),
            None,
            &validators,
            &cb,
            RegistryType::Npm,
        )
        .await
        .unwrap();

        assert!(matches!(out, Revalidation::NotModified));
    }

    /// Validators round-trip through storage (the sidecar lives on disk, so they
    /// survive a restart) — acceptance criterion for #596.
    #[tokio::test]
    async fn validators_sidecar_roundtrips_through_storage() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = crate::Storage::new_local(dir.path().to_str().unwrap());

        // No body yet, but the sidecar is just another key — write then read.
        let key = "npm/pkg/metadata.json";
        let v = Validators {
            etag: Some("\"abc\"".to_string()),
            last_modified: Some("Wed, 21 Oct 2026 07:28:00 GMT".to_string()),
        };
        write_validators(&storage, key, &v).await;

        // Fresh Storage over the same dir = "after restart".
        let reloaded = crate::Storage::new_local(dir.path().to_str().unwrap());
        let got = read_validators(&reloaded, key)
            .await
            .expect("sidecar persists");
        assert_eq!(got, v);
        assert_eq!(validators_key(key), "npm/pkg/metadata.json.meta");
    }

    /// An empty validator set writes no sidecar (nothing to persist).
    #[tokio::test]
    async fn empty_validators_write_no_sidecar() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = crate::Storage::new_local(dir.path().to_str().unwrap());
        write_validators(&storage, "npm/x/metadata.json", &Validators::default()).await;
        assert!(read_validators(&storage, "npm/x/metadata.json")
            .await
            .is_none());
    }
}
