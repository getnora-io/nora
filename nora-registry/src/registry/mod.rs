// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

pub(crate) mod ansible;
mod cargo_registry;
mod conan;
pub(crate) mod deb;
pub mod docker;
pub mod docker_auth;
pub(crate) mod gems;
mod go;
mod maven;
mod named;
mod npm;
pub(crate) mod nuget;
pub(crate) mod pub_dart;
mod pypi;
mod raw;
pub(crate) mod rpm;
pub(crate) mod terraform;

// Cross-registry regression suite for namespace isolation on metadata paths (contrib-kit#68).
#[cfg(test)]
mod ns_isolation_metadata_tests;

pub use ansible::routes as ansible_routes;
pub use cargo_registry::routes as cargo_routes;
pub use conan::routes as conan_routes;
pub use deb::routes as deb_routes;
pub use docker::routes as docker_routes;
pub use docker_auth::DockerAuth;
pub use gems::routes as gems_routes;
pub use go::routes as go_routes;
pub use maven::routes as maven_routes;
pub use named::routes as named_repository_routes;
pub use npm::routes as npm_routes;

// Storage-key builders reused by `nora import` so imported keys are
// byte-identical to the keys these handlers serve — GC/retention/UI browse walk
// keys as strings (review R7, contract `import-key-format-equals-handler-key-format`).
pub(crate) use maven::storage_key as maven_storage_key;
pub(crate) use maven::update_hosted_metadata_after_retention;
pub use nuget::alias_routes as nuget_alias_routes;
pub use nuget::routes as nuget_routes;
pub use pub_dart::routes as pub_dart_routes;
pub use pypi::routes as pypi_routes;
pub use raw::routes as raw_routes;
pub(crate) use raw::storage_key as raw_storage_key;
pub use rpm::routes as rpm_routes;
pub use terraform::routes as terraform_routes;

use crate::circuit_breaker::CircuitBreakerRegistry;
use crate::config::basic_auth_header;
use crate::metrics::{UPSTREAM_POLICY_BLOCKED_TOTAL, UPSTREAM_REQUEST_DURATION};
use crate::registry_type::RegistryType;
use crate::AppState;
use axum::body::{Body, Bytes};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use std::time::{Duration, Instant};

/// 405 Method Not Allowed with `Allow` header (RFC 9110 §15.5.6).
pub(crate) fn method_not_allowed(allow: &'static str) -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, allow)]).into_response()
}

/// 409 for a write against a pull-through repo (rpm/deb `proxies` entry) —
/// its content mirrors the upstream; local publish/delete/reindex would
/// diverge from (and be clobbered by) the next upstream metadata refresh.
pub(crate) fn proxied_repo_conflict() -> Response {
    (
        StatusCode::CONFLICT,
        "Repository is a pull-through proxy (read-only)",
    )
        .into_response()
}

/// Replace `from`→`to` in raw JSON text, matching BOTH the plain form and the
/// JSON slash-escaped form (`\/`) of `from`.
///
/// Raw-text registry rewrites (ansible, nuget) `.replace()` on the unparsed
/// upstream response. A valid JSON escaping that many origins emit —
/// `"https:\/\/host\/path"` — dodges a plain `https://host/path` needle, so the
/// upstream URL survives the rewrite and leaks the host once the client's JSON
/// parser unescapes `\/`→`/` (#385, class of #377/#379/#380/#381). Handling the
/// `\/` form here closes that. NB: `\uXXXX`-escaped separators are a documented
/// residual — see `rewrite-drops-upstream-host` — caught by the runtime
/// `UPSTREAM_URL_LEAK_TOTAL` detector, not by this string pass.
pub(crate) fn replace_url_escape_aware(text: &str, from: &str, to: &str) -> String {
    let plain = text.replace(from, to);
    let esc_from = from.replace('/', "\\/");
    if !plain.contains(&esc_from) {
        return plain;
    }
    let esc_to = to.replace('/', "\\/");
    plain.replace(&esc_from, &esc_to)
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

/// Detect a policy/geo block signature on an upstream 4xx response, returning a
/// bounded reason label (low metric cardinality) or `None` for a genuine 4xx.
///
/// Currently keys off `x-amzn-waf-reason`, which AWS CloudFront + WAF sets when a
/// rule blocks a request — a trade-control/geo rule returns it as a 404 that is
/// otherwise indistinguishable from a not-found (#881). More signatures can be
/// added here without touching the call site.
fn policy_block_reason(headers: &reqwest::header::HeaderMap) -> Option<&'static str> {
    let reason = headers.get("x-amzn-waf-reason")?;
    let is_geo = reason
        .to_str()
        .map(|v| v.eq_ignore_ascii_case("geo"))
        .unwrap_or(false);
    Some(if is_geo { "geo" } else { "waf" })
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
                    // A policy/geo block (e.g. an AWS WAF geo rule) is a 4xx that is
                    // effectively an outage dressed up as a not-found: it logs nothing,
                    // never moves the breaker, and only bumps the 4xx metric — so an
                    // operator cannot tell it apart from a genuine 404. Surface it
                    // distinctly when the response carries a block signature (#881).
                    // A plain 4xx (no signature) stays silent, exactly as before.
                    let policy_block = policy_block_reason(response.headers());
                    if let Some(reason) = policy_block {
                        UPSTREAM_POLICY_BLOCKED_TOTAL
                            .with_label_values(&[registry_str, reason])
                            .inc();
                        tracing::warn!(
                            registry = registry_str,
                            url,
                            status,
                            reason,
                            "upstream returned a policy/geo block (not a genuine not-found) — check egress/region"
                        );
                    }
                    // A 4xx means the upstream is alive and answered — not an
                    // availability failure. `record_alive` closes the breaker
                    // from HalfOpen (so it recovers instead of slow-probing) but
                    // is a no-op in Closed, so a 4xx never clears a real failure
                    // tally (#606).
                    cb.record_alive(registry_str, probe);
                    return if response.status() == reqwest::StatusCode::NOT_FOUND
                        && policy_block.is_none()
                    {
                        Err(ProxyError::NotFound)
                    } else {
                        Err(ProxyError::Upstream(status))
                    };
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

fn is_followable_redirect(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::MOVED_PERMANENTLY
            | reqwest::StatusCode::FOUND
            | reqwest::StatusCode::SEE_OTHER
            | reqwest::StatusCode::TEMPORARY_REDIRECT
            | reqwest::StatusCode::PERMANENT_REDIRECT
    )
}

fn validate_initial_url<F>(url: &str, allowed: &F) -> Result<reqwest::Url, ProxyError>
where
    F: Fn(&reqwest::Url) -> bool,
{
    let parsed = reqwest::Url::parse(url)
        .map_err(|error| ProxyError::Network(format!("invalid upstream URL: {error}")))?;
    if !allowed(&parsed) {
        return Err(ProxyError::Network(
            "initial upstream URL rejected by repository URL policy".to_string(),
        ));
    }
    Ok(parsed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirectTargetError {
    MissingOrInvalidLocation,
    LimitExceeded,
    Disallowed,
}

impl RedirectTargetError {
    fn reason(self) -> &'static str {
        match self {
            Self::MissingOrInvalidLocation => "missing or invalid Location",
            Self::LimitExceeded => "redirect limit exceeded",
            Self::Disallowed => "target rejected by repository URL policy",
        }
    }
}

fn validated_redirect_target<F>(
    current_url: &reqwest::Url,
    response: &reqwest::Response,
    followed: usize,
    max_redirects: usize,
    allowed: &F,
) -> Result<reqwest::Url, RedirectTargetError>
where
    F: Fn(&reqwest::Url) -> bool,
{
    if followed >= max_redirects {
        return Err(RedirectTargetError::LimitExceeded);
    }
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(RedirectTargetError::MissingOrInvalidLocation)?;
    let target = current_url
        .join(location)
        .map_err(|_| RedirectTargetError::MissingOrInvalidLocation)?;
    if !allowed(&target) {
        return Err(RedirectTargetError::Disallowed);
    }
    Ok(target)
}

/// Fetch binary content while following only the initial URL and redirect
/// targets accepted by `redirect_allowed`.
///
/// `client` MUST have reqwest's automatic redirect policy disabled. The
/// initial URL and every resolved `Location` are checked before the request
/// (and its Authorization header) is built.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_fetch_with_validated_redirects<F>(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
    registry: RegistryType,
    max_redirects: usize,
    redirect_allowed: F,
) -> Result<Vec<u8>, ProxyError>
where
    F: Fn(&reqwest::Url) -> bool,
{
    proxy_fetch_with_validated_redirects_impl(
        client,
        url,
        timeout,
        auth,
        cb,
        registry,
        max_redirects,
        None,
        redirect_allowed,
    )
    .await
}

/// The redirect-validated GET flow with a strict response-body budget.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_fetch_with_validated_redirects_bounded<F>(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
    registry: RegistryType,
    max_redirects: usize,
    body_cap: usize,
    redirect_allowed: F,
) -> Result<Vec<u8>, ProxyError>
where
    F: Fn(&reqwest::Url) -> bool,
{
    proxy_fetch_with_validated_redirects_impl(
        client,
        url,
        timeout,
        auth,
        cb,
        registry,
        max_redirects,
        Some(body_cap),
        redirect_allowed,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn proxy_fetch_with_validated_redirects_impl<F>(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
    registry: RegistryType,
    max_redirects: usize,
    body_cap: Option<usize>,
    redirect_allowed: F,
) -> Result<Vec<u8>, ProxyError>
where
    F: Fn(&reqwest::Url) -> bool,
{
    let initial_url = validate_initial_url(url, &redirect_allowed)?;
    let registry_str = registry.as_str();
    let probe = cb.check(registry_str)?;

    for attempt in 0..2 {
        let mut current_url = initial_url.clone();
        let mut followed = 0;

        loop {
            let mut request = client.get(current_url.clone()).timeout(timeout);
            if let Some(credentials) = auth {
                request = request.header("Authorization", basic_auth_header(credentials));
            }

            let upstream_start = Instant::now();
            match request.send().await {
                Ok(response) => {
                    let elapsed = upstream_start.elapsed().as_secs_f64();
                    let status = response.status();
                    if status.is_success() {
                        UPSTREAM_REQUEST_DURATION
                            .with_label_values(&[registry_str, "2xx"])
                            .observe(elapsed);
                        let result = match body_cap {
                            Some(body_cap) => {
                                read_response_body_bounded(
                                    response,
                                    body_cap,
                                    "validated proxy response",
                                )
                                .await
                            }
                            None => response
                                .bytes()
                                .await
                                .map(|bytes| bytes.to_vec())
                                .map_err(|error| ProxyError::Network(error.to_string())),
                        };
                        if result.is_ok() {
                            cb.record_success(registry_str, probe);
                        } else {
                            cb.record_failure(registry_str, probe);
                        }
                        return result;
                    }

                    if is_followable_redirect(status) {
                        UPSTREAM_REQUEST_DURATION
                            .with_label_values(&[registry_str, "3xx"])
                            .observe(elapsed);
                        let next_url = match validated_redirect_target(
                            &current_url,
                            &response,
                            followed,
                            max_redirects,
                            &redirect_allowed,
                        ) {
                            Ok(target) => target,
                            Err(error) => {
                                cb.record_alive(registry_str, probe);
                                tracing::warn!(
                                    registry = registry_str,
                                    status = status.as_u16(),
                                    reason = error.reason(),
                                    "upstream redirect rejected"
                                );
                                return Err(ProxyError::Upstream(status.as_u16()));
                            }
                        };
                        followed += 1;
                        current_url = next_url;
                        continue;
                    }
                    if status.is_redirection() {
                        UPSTREAM_REQUEST_DURATION
                            .with_label_values(&[registry_str, "3xx"])
                            .observe(elapsed);
                        cb.record_alive(registry_str, probe);
                        tracing::warn!(
                            registry = registry_str,
                            status = status.as_u16(),
                            "unsupported upstream redirect status"
                        );
                        return Err(ProxyError::Upstream(status.as_u16()));
                    }

                    let status_code = status.as_u16();
                    if status.is_client_error() {
                        UPSTREAM_REQUEST_DURATION
                            .with_label_values(&[registry_str, "4xx"])
                            .observe(elapsed);
                        let policy_block = policy_block_reason(response.headers());
                        if let Some(reason) = policy_block {
                            UPSTREAM_POLICY_BLOCKED_TOTAL
                                .with_label_values(&[registry_str, reason])
                                .inc();
                            tracing::warn!(
                                registry = registry_str,
                                url = %current_url,
                                status = status_code,
                                reason,
                                "upstream returned a policy/geo block (not a genuine not-found) — check egress/region"
                            );
                        }
                        cb.record_alive(registry_str, probe);
                        return if status == reqwest::StatusCode::NOT_FOUND && policy_block.is_none()
                        {
                            Err(ProxyError::NotFound)
                        } else {
                            Err(ProxyError::Upstream(status_code))
                        };
                    }

                    if attempt == 0 {
                        UPSTREAM_REQUEST_DURATION
                            .with_label_values(&[registry_str, "5xx"])
                            .observe(elapsed);
                        tracing::debug!(
                            url = %current_url,
                            status = status_code,
                            "upstream 5xx, retrying in 1s"
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        break;
                    }
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "5xx"])
                        .observe(elapsed);
                    cb.record_failure(registry_str, probe);
                    return Err(ProxyError::Upstream(status_code));
                }
                Err(error) => {
                    let elapsed = upstream_start.elapsed().as_secs_f64();
                    let status_label = if error.is_timeout() {
                        "timeout"
                    } else {
                        "error"
                    };
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, status_label])
                        .observe(elapsed);
                    if attempt == 0 {
                        tracing::debug!(
                            url = %current_url,
                            error = %error,
                            "upstream error, retrying in 1s"
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        break;
                    }
                    cb.record_failure(registry_str, probe);
                    return Err(ProxyError::Network(error.to_string()));
                }
            }
        }
    }

    cb.record_failure(registry_str, probe);
    Err(ProxyError::Network("max retries exceeded".into()))
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

/// One pull-through download for a per-repo proxied rpm/deb repository.
///
/// Shared by `rpm::download` and `deb::download` — the flow is the Maven proxy
/// flow minus name-based curation (a proxied repo is declared in config and
/// disjoint from hosted repos, so dependency-confusion gating does not apply;
/// the digest quarantine still gates immutable packages):
/// fresh-cache serve → upstream fetch → background cache → stale fallback.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn repo_proxy_download(
    state: &AppState,
    registry: &'static str,
    rt: crate::registry_type::RegistryType,
    display: String,
    key: String,
    url: String,
    auth: Option<&str>,
    timeout_secs: u64,
    metadata_ttl: i64,
    immutable: bool,
    content_type: &'static str,
) -> Response {
    use crate::activity_log::{ActionType, ActivityEntry};
    use crate::audit::AuditEntry;

    let q_override = match registry {
        "rpm" => &state.config.curation.rpm,
        _ => &state.config.curation.deb,
    };
    let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
        q_override
            .quarantine
            .as_ref()
            .or(state.config.curation.quarantine.as_ref()),
        q_override
            .quarantine_ttl
            .as_deref()
            .or(state.config.curation.quarantine_ttl.as_deref()),
    );

    let serve = |data: Bytes| {
        let mut builder = axum::http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type);
        if !immutable {
            builder = builder.header(header::CACHE_CONTROL, "no-cache");
        }
        builder.body(Body::from(data)).expect("valid response")
    };

    let cached = state.storage.get(&key).await.ok();
    let cache_fresh = match &cached {
        None => false,
        Some(_) if immutable => true,
        Some(_) => {
            let modified = state.storage.stat(&key).await.map(|m| m.modified);
            crate::cache_ttl::mutable_ref_fresh(true, metadata_ttl, modified)
        }
    };

    if let Some(ref data) = cached {
        if cache_fresh {
            state.metrics.record_download(registry);
            state.metrics.record_cache_hit(registry);
            state.activity.push(ActivityEntry::new(
                ActionType::CacheHit,
                display,
                rt,
                "CACHE",
            ));
            state
                .audit
                .log(AuditEntry::new("cache_hit", "api", "", registry, ""));
            // Quarantine only immutable packages — metadata is rewritten
            // upstream on every sync and its digest would change forever.
            if immutable {
                if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                    &state.digest_store,
                    registry,
                    data,
                    &q_mode,
                    q_secs,
                    "cache",
                    None,
                ) {
                    return resp;
                }
            }
            return serve(data.clone()).into_response();
        }
    }

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(timeout_secs),
        auth,
        &state.circuit_breaker,
        rt,
    )
    .await
    {
        Ok(data) => {
            let data = Bytes::from(data);
            state.metrics.record_download(registry);
            state.metrics.record_cache_miss(registry);
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                display,
                rt,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", registry, ""));
            if immutable {
                state.spawn_cache_immutable(registry, key, data.clone());
                if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                    &state.digest_store,
                    registry,
                    &data,
                    &q_mode,
                    q_secs,
                    &url,
                    None,
                ) {
                    return resp;
                }
            } else {
                state.spawn_cache(registry, key, data.clone());
            }
            serve(data).into_response()
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            // Upstream failed — serve the stale cached copy if we have one.
            if let Some(data) = cached {
                tracing::warn!(registry, url = %url, error = ?e, "upstream failed, serving stale cached copy");
                if immutable {
                    if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                        &state.digest_store,
                        registry,
                        &data,
                        &q_mode,
                        q_secs,
                        "cache-stale",
                        None,
                    ) {
                        return resp;
                    }
                }
                let mut response = serve(data).into_response();
                response.headers_mut().insert(
                    header::HeaderName::from_static("x-nora-stale"),
                    header::HeaderValue::from_static("true"),
                );
                return response;
            }
            tracing::debug!(registry, url = %url, error = ?e, "proxy fetch failed with no cached copy");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

async fn read_response_body_bounded(
    response: reqwest::Response,
    cap: usize,
    description: &str,
) -> Result<Vec<u8>, ProxyError> {
    let content_length = response.content_length();
    if content_length.is_some_and(|length| length > cap as u64) {
        return Err(ProxyError::Network(format!(
            "upstream {description} exceeds {cap} byte limit"
        )));
    }

    let mut body = Vec::with_capacity(content_length.unwrap_or_default().min(cap as u64) as usize);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| ProxyError::Network(error.to_string()))?;
        if chunk.len() > cap.saturating_sub(body.len()) {
            return Err(ProxyError::Network(format!(
                "upstream {description} exceeds {cap} byte limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

const NPM_AUDIT_RESPONSE_BODY_CAP: usize = 8 * 1024 * 1024;

async fn read_npm_audit_response_body(response: reqwest::Response) -> Result<Vec<u8>, ProxyError> {
    read_response_body_bounded(response, NPM_AUDIT_RESPONSE_BODY_CAP, "npm audit response").await
}

/// Forward a POST (request body + an allowlist of headers) to an upstream and
/// return its `(status, body, content-type)` verbatim. Mirrors
/// `proxy_fetch_core`'s circuit-breaker discipline (`check` → send →
/// `record_success`/`record_alive`/`record_failure`). Request-send and 5xx
/// failures get one retry; response-body failures fail immediately.
///
/// Used for `npm audit` (#597): a query POST that must return the upstream's answer
/// as-is — including a 4xx (a real audit response, upstream is alive) — with only
/// 5xx / network / circuit-open surfaced as `ProxyError`.
///
/// `auth` is the configured proxy credential (Basic); the caller's own
/// `Authorization` is never forwarded — pass only the intended headers in
/// `fwd_headers` (allowlist). A 2xx or 4xx response is accepted only after its
/// body has been read completely within the strict 8 MiB npm-audit response
/// budget. A truncated or oversized body is an upstream failure, never an
/// empty successful response, and is recorded against the circuit breaker.
///
/// `client` must have automatic redirects disabled. The initial URL and every
/// redirect target are policy-checked before a request or Authorization header
/// is built. 307/308 preserve the method, body and headers. 301/302/303 switch
/// permanently to a bodyless GET and retain only `Accept` plus configured auth.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_forward_post<F>(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<&str>,
    fwd_headers: &[(&str, &str)],
    body: &[u8],
    cb: &CircuitBreakerRegistry,
    registry: RegistryType,
    max_redirects: usize,
    redirect_allowed: F,
) -> Result<(u16, Vec<u8>, Option<String>), ProxyError>
where
    F: Fn(&reqwest::Url) -> bool,
{
    let initial_url = validate_initial_url(url, &redirect_allowed)?;
    let registry_str = registry.as_str();
    let probe = cb.check(registry_str)?;

    for attempt in 0..2 {
        let mut current_url = initial_url.clone();
        let mut followed = 0;
        let mut send_body = true;

        loop {
            let mut request = if send_body {
                client
                    .post(current_url.clone())
                    .timeout(timeout)
                    .body(body.to_vec())
            } else {
                client.get(current_url.clone()).timeout(timeout)
            };
            if let Some(credentials) = auth {
                request = request.header(header::AUTHORIZATION, basic_auth_header(credentials));
            }
            for (name, value) in fwd_headers {
                if send_body || name.eq_ignore_ascii_case("accept") {
                    request = request.header(*name, *value);
                }
            }

            let upstream_start = Instant::now();
            match request.send().await {
                Ok(response) => {
                    let elapsed = upstream_start.elapsed().as_secs_f64();
                    let status = response.status();
                    let code = status.as_u16();
                    if is_followable_redirect(status) {
                        UPSTREAM_REQUEST_DURATION
                            .with_label_values(&[registry_str, "3xx"])
                            .observe(elapsed);
                        let next_url = match validated_redirect_target(
                            &current_url,
                            &response,
                            followed,
                            max_redirects,
                            &redirect_allowed,
                        ) {
                            Ok(target) => target,
                            Err(error) => {
                                cb.record_alive(registry_str, probe);
                                tracing::warn!(
                                    registry = registry_str,
                                    status = code,
                                    reason = error.reason(),
                                    "upstream POST redirect rejected"
                                );
                                return Err(ProxyError::Upstream(code));
                            }
                        };
                        if send_body
                            && matches!(
                                status,
                                reqwest::StatusCode::MOVED_PERMANENTLY
                                    | reqwest::StatusCode::FOUND
                                    | reqwest::StatusCode::SEE_OTHER
                            )
                        {
                            send_body = false;
                        }
                        followed += 1;
                        current_url = next_url;
                        continue;
                    }
                    if status.is_redirection() {
                        UPSTREAM_REQUEST_DURATION
                            .with_label_values(&[registry_str, "3xx"])
                            .observe(elapsed);
                        cb.record_alive(registry_str, probe);
                        tracing::warn!(
                            registry = registry_str,
                            status = code,
                            "unsupported upstream POST redirect status"
                        );
                        return Err(ProxyError::Upstream(code));
                    }

                    let content_type = response
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned);
                    if status.is_success() {
                        UPSTREAM_REQUEST_DURATION
                            .with_label_values(&[registry_str, "2xx"])
                            .observe(elapsed);
                        match read_npm_audit_response_body(response).await {
                            Ok(response_body) => {
                                cb.record_success(registry_str, probe);
                                return Ok((code, response_body, content_type));
                            }
                            Err(error) => {
                                cb.record_failure(registry_str, probe);
                                return Err(error);
                            }
                        }
                    }
                    if status.is_client_error() {
                        UPSTREAM_REQUEST_DURATION
                            .with_label_values(&[registry_str, "4xx"])
                            .observe(elapsed);
                        // A fully read 4xx audit response is a real answer and
                        // proves that the upstream is alive. A truncated or
                        // oversized body is instead an availability failure.
                        return match read_npm_audit_response_body(response).await {
                            Ok(response_body) => {
                                cb.record_alive(registry_str, probe);
                                Ok((code, response_body, content_type))
                            }
                            Err(error) => {
                                cb.record_failure(registry_str, probe);
                                Err(error)
                            }
                        };
                    }
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "5xx"])
                        .observe(elapsed);
                    if attempt == 0 {
                        tracing::debug!(
                            url = %current_url,
                            status = code,
                            "upstream 5xx on POST, retrying in 1s"
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        break;
                    }
                    cb.record_failure(registry_str, probe);
                    return Err(ProxyError::Upstream(code));
                }
                Err(error) => {
                    let elapsed = upstream_start.elapsed().as_secs_f64();
                    let status_label = if error.is_timeout() {
                        "timeout"
                    } else {
                        "error"
                    };
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, status_label])
                        .observe(elapsed);
                    if attempt == 0 {
                        tracing::debug!(
                            url = %current_url,
                            error = %error,
                            "upstream error on POST, retrying in 1s"
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        break;
                    }
                    cb.record_failure(registry_str, probe);
                    return Err(ProxyError::Network(error.to_string()));
                }
            }
        }
    }
    cb.record_failure(registry_str, probe);
    Err(ProxyError::Network("max retries exceeded".into()))
}

// ============================================================================
// Streaming upload helpers (shared by docker blob uploads and raw uploads)
// ============================================================================

/// Outcome of streaming a request body to a temp file with a byte budget.
pub(crate) enum StreamOutcome {
    /// Wrote N bytes successfully.
    Ok(u64),
    /// Budget exceeded — aborted before writing the offending frame (413).
    TooLarge,
    /// Request-body stream errored mid-flight (client disconnect).
    ClientGone,
    /// Local write/flush failure (500).
    Io(std::io::Error),
}

/// Stream `body` into `file`, bounded to `budget` bytes, never holding more than
/// one frame in RAM (#817). The running total is checked BEFORE each write, so at
/// most `budget` bytes ever reach disk — a request over budget aborts without
/// writing the offending frame.
///
/// CANCEL-SAFETY: a pure per-frame read→write loop with no lock held and no
/// shared state mutated. If the future is dropped mid-stream, the partially
/// written file is reclaimed by the caller's `TempFileGuard`; nothing is left
/// half-set.
pub(crate) async fn stream_body_to_file(
    body: Body,
    file: &mut tokio::fs::File,
    budget: u64,
) -> StreamOutcome {
    use tokio::io::AsyncWriteExt;
    let mut stream = body.into_data_stream();
    let mut written: u64 = 0;
    while let Some(frame) = stream.next().await {
        let chunk = match frame {
            Ok(c) => c,
            Err(_) => return StreamOutcome::ClientGone,
        };
        written = written.saturating_add(chunk.len() as u64);
        if written > budget {
            return StreamOutcome::TooLarge;
        }
        if let Err(e) = file.write_all(&chunk).await {
            return StreamOutcome::Io(e);
        }
    }
    if let Err(e) = file.flush().await {
        return StreamOutcome::Io(e);
    }
    // Durability: put_from_path's direct-rename commit relies on the caller
    // having fsync'd the source — without this, a power loss just after the
    // rename can leave the key's directory entry pointing at data that never
    // reached disk (latent for docker since the switch to streaming; #846).
    if let Err(e) = file.sync_all().await {
        return StreamOutcome::Io(e);
    }
    // Postcondition: a successful stream never exceeds the budget — the loop
    // returns TooLarge before writing any frame that would cross it.
    debug_assert!(
        written <= budget,
        "stream_body_to_file wrote {written} bytes > budget {budget}"
    );
    StreamOutcome::Ok(written)
}

/// Parse the `Content-Length` header, if present and well-formed.
pub(crate) fn content_length(headers: &axum::http::HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

/// RAII: delete a temp file on drop unless disarmed.
///
/// Ensures temp files are cleaned up on ALL error paths (network errors,
/// hash mismatch, panics, early returns via `?` operator) — #580.
pub(crate) struct TempFileGuard {
    path: Option<std::path::PathBuf>,
}

impl TempFileGuard {
    pub(crate) fn new(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Disarm the guard — caller takes ownership of cleanup.
    /// Call this after successful `put_from_path` (which moves/deletes the file).
    pub(crate) fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// sha256 of a file's contents, read in 256 KiB chunks — used to hash a
/// streamed upload without ever holding the body in memory.
pub(crate) async fn sha256_of_file(path: &std::path::Path) -> std::io::Result<String> {
    use sha2::Digest;
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path).await?;
    let mut reader = tokio::io::BufReader::new(file);
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match reader.read(&mut buf).await? {
            0 => break,
            n => hasher.update(&buf[..n]),
        }
    }
    Ok(hex::encode(hasher.finalize()))
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
                // Only an actual 404 is safe to feed a negative cache. Auth,
                // throttling and policy failures must remain distinguishable
                // from package absence.
                return if status == reqwest::StatusCode::NOT_FOUND {
                    Err(ProxyError::NotFound)
                } else {
                    Err(ProxyError::Upstream(code))
                };
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

/// Conditional upstream fetch with explicit validation of the initial URL and
/// every redirect target.
///
/// The client must have automatic redirects disabled. Conditional validators
/// are retained on every GET hop; the final response alone determines whether
/// the result is `NotModified` or captures a new body and validators. Like
/// [`proxy_fetch_conditional`], this helper never retries.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_fetch_conditional_with_validated_redirects<F>(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<&str>,
    validators: &Validators,
    cb: &CircuitBreakerRegistry,
    registry: RegistryType,
    max_redirects: usize,
    redirect_allowed: F,
) -> Result<Revalidation, ProxyError>
where
    F: Fn(&reqwest::Url) -> bool,
{
    let initial_url = validate_initial_url(url, &redirect_allowed)?;
    let registry_str = registry.as_str();
    let probe = cb.check(registry_str)?;
    let mut current_url = initial_url;
    let mut followed = 0;

    loop {
        let mut request = client.get(current_url.clone()).timeout(timeout);
        if let Some(credentials) = auth {
            request = request.header(header::AUTHORIZATION, basic_auth_header(credentials));
        }
        if let Some(ref etag) = validators.etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        if let Some(ref last_modified) = validators.last_modified {
            request = request.header(header::IF_MODIFIED_SINCE, last_modified);
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
                    let body = match response.bytes().await {
                        Ok(body) => body,
                        Err(error) => {
                            cb.record_failure(registry_str, probe);
                            return Err(ProxyError::Network(error.to_string()));
                        }
                    };
                    cb.record_success(registry_str, probe);
                    return Ok(Revalidation::Modified {
                        body: body.to_vec(),
                        validators: new_validators,
                    });
                }
                if is_followable_redirect(status) {
                    let next_url = match validated_redirect_target(
                        &current_url,
                        &response,
                        followed,
                        max_redirects,
                        &redirect_allowed,
                    ) {
                        Ok(target) => target,
                        Err(error) => {
                            cb.record_alive(registry_str, probe);
                            tracing::warn!(
                                registry = registry_str,
                                status = status.as_u16(),
                                reason = error.reason(),
                                "conditional upstream redirect rejected"
                            );
                            return Err(ProxyError::Upstream(status.as_u16()));
                        }
                    };
                    followed += 1;
                    current_url = next_url;
                    continue;
                }

                let code = status.as_u16();
                if status.is_redirection() {
                    cb.record_alive(registry_str, probe);
                    tracing::warn!(
                        registry = registry_str,
                        status = code,
                        "unsupported conditional upstream redirect status"
                    );
                    return Err(ProxyError::Upstream(code));
                }
                if status.is_client_error() {
                    let policy_block = policy_block_reason(response.headers());
                    if let Some(reason) = policy_block {
                        UPSTREAM_POLICY_BLOCKED_TOTAL
                            .with_label_values(&[registry_str, reason])
                            .inc();
                        tracing::warn!(
                            registry = registry_str,
                            url = %current_url,
                            status = code,
                            reason,
                            "conditional upstream returned a policy/geo block (not a genuine not-found) — check egress/region"
                        );
                    }
                    cb.record_alive(registry_str, probe);
                    return if status == reqwest::StatusCode::NOT_FOUND && policy_block.is_none() {
                        Err(ProxyError::NotFound)
                    } else {
                        Err(ProxyError::Upstream(code))
                    };
                }
                cb.record_failure(registry_str, probe);
                return Err(ProxyError::Upstream(code));
            }
            Err(error) => {
                cb.record_failure(registry_str, probe);
                return Err(ProxyError::Network(error.to_string()));
            }
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

    #[tokio::test]
    async fn proxy_fetch_only_classifies_exact_404_as_not_found() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        for status in [401_u16, 403, 429, 451] {
            upstream.reset().await;
            Mock::given(any())
                .respond_with(ResponseTemplate::new(status))
                .mount(&upstream)
                .await;

            let result = proxy_fetch(
                &reqwest::Client::new(),
                &upstream.uri(),
                Duration::from_secs(5),
                None,
                &noop_cb(),
                RegistryType::Maven,
            )
            .await;
            assert!(
                matches!(result, Err(ProxyError::Upstream(actual)) if actual == status),
                "HTTP {status} must remain distinguishable from a missing artifact"
            );
        }

        upstream.reset().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&upstream)
            .await;
        let result = proxy_fetch(
            &reqwest::Client::new(),
            &upstream.uri(),
            Duration::from_secs(5),
            None,
            &noop_cb(),
            RegistryType::Maven,
        )
        .await;
        assert!(matches!(result, Err(ProxyError::NotFound)));
    }

    // --- Policy/geo upstream block observability (#881) ---

    #[test]
    fn policy_block_reason_detects_waf_geo() {
        use reqwest::header::HeaderMap;
        let mut geo = HeaderMap::new();
        geo.insert("x-amzn-waf-reason", "geo".parse().unwrap());
        assert_eq!(policy_block_reason(&geo), Some("geo"));

        let mut other = HeaderMap::new();
        other.insert("x-amzn-waf-reason", "rate-based".parse().unwrap());
        assert_eq!(policy_block_reason(&other), Some("waf"));

        // A genuine 4xx (no WAF signature) is not a policy block.
        assert_eq!(policy_block_reason(&HeaderMap::new()), None);
    }

    /// A geo-blocked upstream 4xx (WAF `x-amzn-waf-reason: geo`) bumps the policy-block
    /// metric and remains distinguishable from `NotFound`; a plain 404 does neither (#881).
    #[tokio::test]
    async fn upstream_waf_geo_block_surfaced_but_plain_4xx_silent() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Geo-blocked upstream: 404 + x-amzn-waf-reason: geo.
        let blocked = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404).insert_header("x-amzn-waf-reason", "geo"))
            .mount(&blocked)
            .await;
        let reg = RegistryType::Terraform;
        let before = UPSTREAM_POLICY_BLOCKED_TOTAL
            .with_label_values(&[reg.as_str(), "geo"])
            .get();
        let r = proxy_fetch_text(
            &reqwest::Client::new(),
            &blocked.uri(),
            Duration::from_secs(5),
            None,
            None,
            &noop_cb(),
            reg,
        )
        .await;
        assert!(matches!(r, Err(ProxyError::Upstream(404))));
        assert_eq!(
            UPSTREAM_POLICY_BLOCKED_TOTAL
                .with_label_values(&[reg.as_str(), "geo"])
                .get(),
            before + 1,
            "a WAF geo 4xx must bump the policy-block metric"
        );

        // Control: a plain 404 (no WAF signature) must NOT bump the metric.
        let plain = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&plain)
            .await;
        let reg2 = RegistryType::Cargo;
        let before2 = UPSTREAM_POLICY_BLOCKED_TOTAL
            .with_label_values(&[reg2.as_str(), "geo"])
            .get();
        let r2 = proxy_fetch_text(
            &reqwest::Client::new(),
            &plain.uri(),
            Duration::from_secs(5),
            None,
            None,
            &noop_cb(),
            reg2,
        )
        .await;
        assert!(matches!(r2, Err(ProxyError::NotFound)));
        assert_eq!(
            UPSTREAM_POLICY_BLOCKED_TOTAL
                .with_label_values(&[reg2.as_str(), "geo"])
                .get(),
            before2,
            "a plain 4xx must NOT bump the policy-block metric"
        );
    }

    // --- Conditional revalidation (#596) ---

    fn noop_cb() -> CircuitBreakerRegistry {
        CircuitBreakerRegistry::new(crate::config::CircuitBreakerConfig::default())
    }

    fn one_failure_cb() -> CircuitBreakerRegistry {
        CircuitBreakerRegistry::new(crate::config::CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            reset_timeout: 30,
            overrides: std::collections::HashMap::new(),
        })
    }

    fn assert_npm_breaker_open(cb: &CircuitBreakerRegistry) {
        let health = cb
            .health_snapshot(RegistryType::Npm.as_str())
            .expect("npm breaker must have recorded the response-body failure");
        assert_eq!(health.status, "open");
        assert_eq!(health.failure_count, 1);
        assert!(matches!(
            cb.check(RegistryType::Npm.as_str()),
            Err(ProxyError::CircuitOpen(_))
        ));
    }

    fn no_redirect_client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    fn same_origin(expected: &reqwest::Url, candidate: &reqwest::Url) -> bool {
        expected.scheme() == candidate.scheme()
            && expected.host_str() == candidate.host_str()
            && expected.port_or_known_default() == candidate.port_or_known_default()
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

    #[tokio::test]
    async fn conditional_non_404_client_error_is_not_negative_cacheable() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(401))
            .mount(&upstream)
            .await;

        let result = proxy_fetch_conditional(
            &reqwest::Client::new(),
            &upstream.uri(),
            Duration::from_secs(5),
            None,
            &Validators::default(),
            &noop_cb(),
            RegistryType::Npm,
        )
        .await;
        assert!(matches!(result, Err(ProxyError::Upstream(401))));
    }

    #[tokio::test]
    async fn validated_fetch_rejects_initial_url_before_any_request() {
        use wiremock::MockServer;

        let upstream = MockServer::start().await;
        let result = proxy_fetch_with_validated_redirects(
            &no_redirect_client(),
            &format!("{}/artifact", upstream.uri()),
            Duration::from_secs(5),
            Some("user:password"),
            &noop_cb(),
            RegistryType::Npm,
            3,
            |_| false,
        )
        .await;

        assert!(matches!(result, Err(ProxyError::Network(_))));
        assert!(
            upstream
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a rejected initial URL must not receive a request or credentials"
        );
    }

    #[tokio::test]
    async fn validated_fetch_resolves_relative_location_and_rejects_invalid_location() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repo/start"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "artifact"))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/repo/artifact"))
            .respond_with(ResponseTemplate::new(200).set_body_string("artifact-body"))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/invalid"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "http://["))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(302))
            .mount(&upstream)
            .await;

        let origin = reqwest::Url::parse(&upstream.uri()).unwrap();
        let fetched = proxy_fetch_with_validated_redirects(
            &no_redirect_client(),
            &format!("{}/repo/start", upstream.uri()),
            Duration::from_secs(5),
            None,
            &noop_cb(),
            RegistryType::Npm,
            3,
            |candidate| same_origin(&origin, candidate),
        )
        .await
        .unwrap();
        assert_eq!(fetched, b"artifact-body");

        let invalid = proxy_fetch_with_validated_redirects(
            &no_redirect_client(),
            &format!("{}/invalid", upstream.uri()),
            Duration::from_secs(5),
            None,
            &noop_cb(),
            RegistryType::Npm,
            3,
            |candidate| same_origin(&origin, candidate),
        )
        .await;
        assert!(matches!(invalid, Err(ProxyError::Upstream(302))));

        let missing = proxy_fetch_with_validated_redirects(
            &no_redirect_client(),
            &format!("{}/missing", upstream.uri()),
            Duration::from_secs(5),
            None,
            &noop_cb(),
            RegistryType::Npm,
            3,
            |candidate| same_origin(&origin, candidate),
        )
        .await;
        assert!(matches!(missing, Err(ProxyError::Upstream(302))));
    }

    #[tokio::test]
    async fn validated_fetch_only_classifies_plain_404_as_not_found() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        for (request_path, status) in [("/unauthorized", 401), ("/throttled", 429)] {
            Mock::given(method("GET"))
                .and(path(request_path))
                .respond_with(ResponseTemplate::new(status))
                .expect(1)
                .mount(&upstream)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/blocked"))
            .respond_with(
                ResponseTemplate::new(404).insert_header("x-amzn-waf-reason", "rate-based"),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&upstream)
            .await;

        let origin = reqwest::Url::parse(&upstream.uri()).unwrap();
        for (request_path, expected) in [
            ("/unauthorized", ProxyError::Upstream(401)),
            ("/throttled", ProxyError::Upstream(429)),
            ("/blocked", ProxyError::Upstream(404)),
            ("/missing", ProxyError::NotFound),
        ] {
            let result = proxy_fetch_with_validated_redirects(
                &no_redirect_client(),
                &format!("{}{request_path}", upstream.uri()),
                Duration::from_secs(5),
                None,
                &noop_cb(),
                RegistryType::Npm,
                3,
                |candidate| same_origin(&origin, candidate),
            )
            .await;
            assert!(
                matches!(
                    (&result, &expected),
                    (Err(ProxyError::Upstream(actual)), ProxyError::Upstream(wanted))
                        if actual == wanted
                ) || matches!(
                    (&result, &expected),
                    (Err(ProxyError::NotFound), ProxyError::NotFound)
                ),
                "unexpected classification for {request_path}"
            );
        }
        upstream.verify().await;
    }

    #[tokio::test]
    async fn validated_bounded_fetch_rejects_oversized_response_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/search"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"oversized"))
            .expect(1)
            .mount(&upstream)
            .await;
        let origin = reqwest::Url::parse(&upstream.uri()).unwrap();
        let result = proxy_fetch_with_validated_redirects_bounded(
            &no_redirect_client(),
            &format!("{}/search", upstream.uri()),
            Duration::from_secs(5),
            None,
            &noop_cb(),
            RegistryType::Npm,
            3,
            4,
            |candidate| same_origin(&origin, candidate),
        )
        .await;
        assert!(matches!(result, Err(ProxyError::Network(_))));
        upstream.verify().await;
    }

    #[tokio::test]
    async fn conditional_redirect_preserves_validators_and_final_304() {
        use wiremock::matchers::{header, header_exists, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        for request_path in ["/metadata", "/revalidated"] {
            let response = if request_path == "/metadata" {
                ResponseTemplate::new(302).insert_header("location", "revalidated")
            } else {
                ResponseTemplate::new(304)
            };
            Mock::given(method("GET"))
                .and(path(request_path))
                .and(header("if-none-match", "\"v1\""))
                .and(header_exists("if-modified-since"))
                .and(header("authorization", basic_auth_header("user:password")))
                .respond_with(response)
                .mount(&upstream)
                .await;
        }

        let validators = Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: Some("Wed, 21 Oct 2026 07:28:00 GMT".to_string()),
        };
        let origin = reqwest::Url::parse(&upstream.uri()).unwrap();
        let result = proxy_fetch_conditional_with_validated_redirects(
            &no_redirect_client(),
            &format!("{}/metadata", upstream.uri()),
            Duration::from_secs(5),
            Some("user:password"),
            &validators,
            &noop_cb(),
            RegistryType::Npm,
            3,
            |candidate| same_origin(&origin, candidate),
        )
        .await
        .unwrap();

        assert!(matches!(result, Revalidation::NotModified));
        let requests = upstream.received_requests().await.unwrap_or_default();
        assert_eq!(
            requests.len(),
            2,
            "conditional redirects must not trigger a retry"
        );
        assert!(requests.iter().all(|request| {
            request
                .headers
                .get("if-modified-since")
                .and_then(|value| value.to_str().ok())
                == Some("Wed, 21 Oct 2026 07:28:00 GMT")
        }));
    }

    #[tokio::test]
    async fn conditional_validated_fetch_only_classifies_plain_404_as_not_found() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        for (request_path, status) in [("/unauthorized", 401), ("/throttled", 429)] {
            Mock::given(method("GET"))
                .and(path(request_path))
                .respond_with(ResponseTemplate::new(status))
                .expect(1)
                .mount(&upstream)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/blocked"))
            .respond_with(
                ResponseTemplate::new(404).insert_header("x-amzn-waf-reason", "rate-based"),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&upstream)
            .await;

        let origin = reqwest::Url::parse(&upstream.uri()).unwrap();
        for (request_path, expected) in [
            ("/unauthorized", ProxyError::Upstream(401)),
            ("/throttled", ProxyError::Upstream(429)),
            ("/blocked", ProxyError::Upstream(404)),
            ("/missing", ProxyError::NotFound),
        ] {
            let result = proxy_fetch_conditional_with_validated_redirects(
                &no_redirect_client(),
                &format!("{}{request_path}", upstream.uri()),
                Duration::from_secs(5),
                None,
                &Validators::default(),
                &noop_cb(),
                RegistryType::Npm,
                3,
                |candidate| same_origin(&origin, candidate),
            )
            .await;
            assert!(
                matches!(
                    (&result, &expected),
                    (Err(ProxyError::Upstream(actual)), ProxyError::Upstream(wanted))
                        if actual == wanted
                ) || matches!(
                    (&result, &expected),
                    (Err(ProxyError::NotFound), ProxyError::NotFound)
                ),
                "unexpected classification for {request_path}"
            );
        }
        upstream.verify().await;
    }

    #[tokio::test]
    async fn conditional_validated_fetch_does_not_retry_5xx() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&upstream)
            .await;

        let origin = reqwest::Url::parse(&upstream.uri()).unwrap();
        let result = proxy_fetch_conditional_with_validated_redirects(
            &no_redirect_client(),
            &format!("{}/metadata", upstream.uri()),
            Duration::from_secs(5),
            None,
            &Validators::default(),
            &noop_cb(),
            RegistryType::Npm,
            3,
            |candidate| same_origin(&origin, candidate),
        )
        .await;

        assert!(matches!(result, Err(ProxyError::Upstream(503))));
        assert_eq!(
            upstream.received_requests().await.unwrap_or_default().len(),
            1,
            "conditional fetches must not retry upstream failures"
        );
    }

    #[tokio::test]
    async fn post_forwards_fully_read_4xx_body_and_content_type_exactly() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let expected = vec![0, 1, 2, b'{', b'}', 0xff];
        Mock::given(method("POST"))
            .and(path("/audit"))
            .respond_with(
                ResponseTemplate::new(422)
                    .insert_header("content-type", "application/problem+json")
                    .set_body_bytes(expected.clone()),
            )
            .mount(&upstream)
            .await;

        let origin = reqwest::Url::parse(&upstream.uri()).unwrap();
        let result = proxy_forward_post(
            &no_redirect_client(),
            &format!("{}/audit", upstream.uri()),
            Duration::from_secs(5),
            None,
            &[("content-type", "application/json")],
            b"{}",
            &noop_cb(),
            RegistryType::Npm,
            3,
            |candidate| same_origin(&origin, candidate),
        )
        .await
        .unwrap();

        assert_eq!(
            result,
            (422, expected, Some("application/problem+json".into()))
        );
    }

    #[tokio::test]
    async fn post_rejects_oversized_2xx_body_and_opens_breaker() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/audit"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("transfer-encoding", "chunked")
                    .set_body_bytes(vec![b'x'; NPM_AUDIT_RESPONSE_BODY_CAP + 1]),
            )
            .mount(&upstream)
            .await;

        let origin = reqwest::Url::parse(&upstream.uri()).unwrap();
        let cb = one_failure_cb();
        let result = proxy_forward_post(
            &no_redirect_client(),
            &format!("{}/audit", upstream.uri()),
            Duration::from_secs(5),
            None,
            &[("content-type", "application/json")],
            b"{}",
            &cb,
            RegistryType::Npm,
            3,
            |candidate| same_origin(&origin, candidate),
        )
        .await;

        assert!(
            matches!(result, Err(ProxyError::Network(message)) if message.contains("exceeds")),
            "an oversized 2xx must fail specifically at the response-body cap"
        );
        assert_npm_breaker_open(&cb);
    }

    #[tokio::test]
    async fn post_rejects_oversized_4xx_body_and_opens_breaker() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/audit"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("transfer-encoding", "chunked")
                    .set_body_bytes(vec![b'x'; NPM_AUDIT_RESPONSE_BODY_CAP + 1]),
            )
            .mount(&upstream)
            .await;

        let origin = reqwest::Url::parse(&upstream.uri()).unwrap();
        let cb = one_failure_cb();
        let result = proxy_forward_post(
            &no_redirect_client(),
            &format!("{}/audit", upstream.uri()),
            Duration::from_secs(5),
            None,
            &[("content-type", "application/json")],
            b"{}",
            &cb,
            RegistryType::Npm,
            3,
            |candidate| same_origin(&origin, candidate),
        )
        .await;

        assert!(
            matches!(result, Err(ProxyError::Network(message)) if message.contains("exceeds")),
            "an oversized 4xx must fail specifically at the response-body cap"
        );
        assert_npm_breaker_open(&cb);
    }

    #[tokio::test]
    async fn post_rejects_truncated_4xx_body_and_opens_breaker() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\n\
                      Content-Type: application/json\r\n\
                      Content-Length: 64\r\n\
                      Connection: close\r\n\
                      \r\n\
                      {\"partial\":true}",
                )
                .await
                .unwrap();
            socket.shutdown().await.unwrap();
        });

        let url = format!("http://{address}/audit");
        let origin = reqwest::Url::parse(&url).unwrap();
        let cb = one_failure_cb();
        let result = proxy_forward_post(
            &no_redirect_client(),
            &url,
            Duration::from_secs(5),
            None,
            &[("content-type", "application/json")],
            b"{}",
            &cb,
            RegistryType::Npm,
            3,
            |candidate| same_origin(&origin, candidate),
        )
        .await;
        server.await.unwrap();

        assert!(matches!(result, Err(ProxyError::Network(_))));
        assert_npm_breaker_open(&cb);
    }

    #[tokio::test]
    async fn post_307_and_308_preserve_body_and_payload_headers() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for status in [307, 308] {
            let upstream = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audit"))
                .respond_with(
                    ResponseTemplate::new(status).insert_header("location", "/audit/final"),
                )
                .mount(&upstream)
                .await;
            Mock::given(method("POST"))
                .and(path("/audit/final"))
                .respond_with(ResponseTemplate::new(200).set_body_string("audit-result"))
                .mount(&upstream)
                .await;

            let origin = reqwest::Url::parse(&upstream.uri()).unwrap();
            let result = proxy_forward_post(
                &no_redirect_client(),
                &format!("{}/audit", upstream.uri()),
                Duration::from_secs(5),
                Some("user:password"),
                &[
                    ("content-type", "application/json"),
                    ("content-encoding", "gzip"),
                    ("accept", "application/json"),
                ],
                b"audit-body",
                &noop_cb(),
                RegistryType::Npm,
                3,
                |candidate| same_origin(&origin, candidate),
            )
            .await
            .unwrap();
            assert_eq!(result.0, 200);
            assert_eq!(result.1, b"audit-result");

            let requests = upstream.received_requests().await.unwrap_or_default();
            let final_request = requests
                .iter()
                .find(|request| request.url.path() == "/audit/final")
                .expect("redirect target received request");
            assert_eq!(final_request.method.as_str(), "POST");
            assert_eq!(final_request.body, b"audit-body");
            assert_eq!(
                final_request.headers["content-type"], "application/json",
                "{status} must preserve Content-Type"
            );
            assert_eq!(
                final_request.headers["content-encoding"], "gzip",
                "{status} must preserve Content-Encoding"
            );
            assert_eq!(final_request.headers["accept"], "application/json");
            assert_eq!(
                final_request.headers["authorization"],
                basic_auth_header("user:password")
            );
        }
    }

    #[tokio::test]
    async fn post_301_302_303_switch_permanently_to_bodyless_get() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for status in [301, 302, 303] {
            let upstream = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/audit"))
                .respond_with(
                    ResponseTemplate::new(status).insert_header("location", "/audit/get-hop"),
                )
                .mount(&upstream)
                .await;
            Mock::given(method("GET"))
                .and(path("/audit/get-hop"))
                .respond_with(ResponseTemplate::new(307).insert_header("location", "/audit/final"))
                .mount(&upstream)
                .await;
            Mock::given(method("GET"))
                .and(path("/audit/final"))
                .respond_with(ResponseTemplate::new(200).set_body_string("audit-result"))
                .mount(&upstream)
                .await;

            let origin = reqwest::Url::parse(&upstream.uri()).unwrap();
            let result = proxy_forward_post(
                &no_redirect_client(),
                &format!("{}/audit", upstream.uri()),
                Duration::from_secs(5),
                Some("user:password"),
                &[
                    ("content-type", "application/json"),
                    ("content-encoding", "gzip"),
                    ("accept", "application/json"),
                ],
                b"audit-body",
                &noop_cb(),
                RegistryType::Npm,
                3,
                |candidate| same_origin(&origin, candidate),
            )
            .await
            .unwrap();
            assert_eq!(result.1, b"audit-result");

            let requests = upstream.received_requests().await.unwrap_or_default();
            for request_path in ["/audit/get-hop", "/audit/final"] {
                let request = requests
                    .iter()
                    .find(|request| request.url.path() == request_path)
                    .expect("redirect target received request");
                assert_eq!(
                    request.method.as_str(),
                    "GET",
                    "{status} must switch POST to GET permanently"
                );
                assert!(
                    request.body.is_empty(),
                    "{status} redirected GET must have no body"
                );
                assert!(
                    !request.headers.contains_key("content-type"),
                    "{status} redirected GET must drop Content-Type"
                );
                assert!(
                    !request.headers.contains_key("content-encoding"),
                    "{status} redirected GET must drop Content-Encoding"
                );
                assert_eq!(request.headers["accept"], "application/json");
                assert_eq!(
                    request.headers["authorization"],
                    basic_auth_header("user:password")
                );
            }
        }
    }

    #[tokio::test]
    async fn post_redirect_rejects_disallowed_target_before_sending_auth_or_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let disallowed = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/audit"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/capture", disallowed.uri())),
            )
            .mount(&upstream)
            .await;
        Mock::given(method("POST"))
            .and(path("/capture"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&disallowed)
            .await;

        let allowed_origin = reqwest::Url::parse(&upstream.uri()).unwrap();
        let result = proxy_forward_post(
            &no_redirect_client(),
            &format!("{}/audit", upstream.uri()),
            Duration::from_secs(5),
            Some("user:password"),
            &[("content-type", "application/json")],
            b"sensitive-audit-body",
            &noop_cb(),
            RegistryType::Npm,
            3,
            |candidate| same_origin(&allowed_origin, candidate),
        )
        .await;

        assert!(matches!(result, Err(ProxyError::Upstream(307))));
        assert!(
            disallowed
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a disallowed target must receive neither configured auth nor the POST body"
        );
    }

    #[tokio::test]
    async fn post_redirect_rejects_fourth_hop_without_sending_fifth_request() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        for hop in 0..=3 {
            Mock::given(method("POST"))
                .and(path(format!("/hop/{hop}")))
                .respond_with(
                    ResponseTemplate::new(307)
                        .insert_header("location", format!("/hop/{}", hop + 1)),
                )
                .mount(&upstream)
                .await;
        }
        Mock::given(method("POST"))
            .and(path("/hop/4"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&upstream)
            .await;

        let origin = reqwest::Url::parse(&upstream.uri()).unwrap();
        let result = proxy_forward_post(
            &no_redirect_client(),
            &format!("{}/hop/0", upstream.uri()),
            Duration::from_secs(5),
            None,
            &[],
            b"audit-body",
            &noop_cb(),
            RegistryType::Npm,
            3,
            |candidate| same_origin(&origin, candidate),
        )
        .await;

        assert!(matches!(result, Err(ProxyError::Upstream(307))));
        let requests = upstream.received_requests().await.unwrap_or_default();
        assert_eq!(requests.len(), 4, "only the initial request plus 3 hops");
        assert!(
            requests
                .iter()
                .all(|request| request.url.path() != "/hop/4"),
            "the fourth redirect target must be rejected before request construction"
        );
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
