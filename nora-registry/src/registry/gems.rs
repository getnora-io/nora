// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! RubyGems proxy registry.
//!
//! Implements a caching proxy for rubygems.org:
//!   GET /gems/specs.4.8.gz             — full gem index (binary, mutable, TTL cache)
//!   GET /gems/latest_specs.4.8.gz      — latest gem index (binary, mutable, TTL cache)
//!   GET /gems/prerelease_specs.4.8.gz  — prerelease index (binary, mutable, TTL cache)
//!   GET /gems/info/{name}              — compact index (text, mutable, TTL cache)
//!   GET /gems/gems/{name}-{version}.gem — gem download (binary, immutable cache)
//!   GET /gems/quick/Marshal.4.8/{name}-{version}.gemspec.rz — gemspec (binary, immutable cache)
//!
//! Client config:
//!   bundle config mirror.https://rubygems.org http://nora:4000/gems/

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::{
    circuit_open_response, proxy_fetch, proxy_fetch_conditional, read_validators, write_validators,
    ProxyError, Revalidation, Validators,
};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::time::Duration;

const UPSTREAM_DEFAULT: &str = "https://rubygems.org";

pub fn routes() -> Router<AppState> {
    Router::new()
        // Index files (mutable)
        .route("/gems/specs.4.8.gz", get(specs_index))
        .route("/gems/latest_specs.4.8.gz", get(latest_specs_index))
        .route("/gems/prerelease_specs.4.8.gz", get(prerelease_specs_index))
        // Compact index (mutable)
        .route("/gems/info/{name}", get(compact_index))
        // Gem download (immutable) — wildcard because axum forbids two params per segment
        .route("/gems/gems/{filename}", get(download_gem))
        // Gemspec (immutable)
        .route("/gems/quick/Marshal.4.8/{filename}", get(download_gemspec))
}

use crate::cache_ttl::is_within_ttl;

// ── Index endpoints (mutable, TTL cached) ─────────────────────────────

async fn specs_index(State(state): State<AppState>) -> Response {
    fetch_index(&state, "specs.4.8.gz").await
}

async fn latest_specs_index(State(state): State<AppState>) -> Response {
    fetch_index(&state, "latest_specs.4.8.gz").await
}

async fn prerelease_specs_index(State(state): State<AppState>) -> Response {
    fetch_index(&state, "prerelease_specs.4.8.gz").await
}

async fn fetch_index(state: &AppState, filename: &str) -> Response {
    let storage_key = format!("gems/{}", filename);

    // Eager cache read — preserve data for serve-stale fallback
    let cached_data = state.storage.get(&storage_key).await.ok();
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.gems.metadata_ttl) {
                state.metrics.record_download("gems");
                state.metrics.record_cache_hit("gems");
                state.activity.push(ActivityEntry::new(
                    ActionType::CacheHit,
                    filename.to_string(),
                    "gems",
                    "CACHE",
                ));
                return with_binary(data.to_vec(), "application/gzip");
            }
        }
    }

    // Fetch from upstream
    let proxy_url = upstream_url(state);
    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), filename);

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.gems.proxy_timeout),
        expose_opt(&state.config.gems.proxy_auth),
        &state.circuit_breaker,
        RegistryType::Gems,
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("gems");
            state.metrics.record_cache_miss("gems");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                filename.to_string(),
                "gems",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "gems", ""));

            // Cache in background (overwrite — mutable content)
            state.spawn_cache("gems", storage_key, Bytes::from(bytes.clone()));
            with_binary(bytes, "application/gzip")
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            if let Some(ref data) = cached_data {
                if state.config.gems.serve_stale {
                    tracing::warn!(
                        registry = "gems",
                        filename,
                        error = ?e,
                        "RubyGems upstream error, serving stale index"
                    );
                    return (
                        StatusCode::OK,
                        [
                            (
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("application/gzip"),
                            ),
                            (
                                header::CACHE_CONTROL,
                                HeaderValue::from_static("public, max-age=0, must-revalidate"),
                            ),
                            (
                                axum::http::header::HeaderName::from_static("x-nora-stale"),
                                HeaderValue::from_static("true"),
                            ),
                        ],
                        data.to_vec(),
                    )
                        .into_response();
                }
            }
            tracing::debug!(filename, error = ?e, "RubyGems upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Compact index ──────────────────────────────────────────────────────

async fn compact_index(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if !is_valid_gem_name(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        crate::curation::RegistryType::Gems,
        &name,
        None,
        None,
    ) {
        return response;
    }

    let storage_key = format!("gems/info/{}", name);

    // Eager cache read — preserve data for serve-stale fallback
    let cached_data = state.storage.get(&storage_key).await.ok();
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.gems.metadata_ttl) {
                state.metrics.record_download("gems");
                state.metrics.record_cache_hit("gems");
                state.activity.push(ActivityEntry::new(
                    ActionType::CacheHit,
                    name.clone(),
                    "gems",
                    "CACHE",
                ));
                return with_text(data.to_vec());
            }
        }
    }

    let proxy_url = upstream_url(&state);
    let url = format!("{}/info/{}", proxy_url.trim_end_matches('/'), name);

    // Revalidate stale metadata with a conditional request when enabled (a cheap
    // 304 — RubyGems compact-index endpoints support validators) and fall back to
    // a full fetch otherwise. Empty validators ⇒ no conditional headers ⇒ always
    // a 200, which is also how the first fetch captures validators for next time.
    let validators = if state.config.gems.revalidate {
        read_validators(&state.storage, &storage_key)
            .await
            .unwrap_or_default()
    } else {
        Validators::default()
    };
    let had_validators = validators.is_some();

    match proxy_fetch_conditional(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.gems.proxy_timeout),
        expose_opt(&state.config.gems.proxy_auth),
        &validators,
        &state.circuit_breaker,
        RegistryType::Gems,
    )
    .await
    {
        // Upstream unchanged — serve the cached body and bump its freshness so we
        // do not revalidate again until the next TTL window. No body downloaded.
        Ok(Revalidation::NotModified) => {
            let cached = match state.storage.get(&storage_key).await {
                Ok(b) => b,
                // Body vanished under us — use the eagerly-read copy, or 502.
                Err(_) => match cached_data {
                    Some(b) => b,
                    None => return StatusCode::BAD_GATEWAY.into_response(),
                },
            };
            crate::metrics::PROXY_UPSTREAM_304_TOTAL
                .with_label_values(&["gems"])
                .inc();
            crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                .with_label_values(&["gems"])
                .inc_by(cached.len() as u64);
            state.metrics.record_download("gems");
            state.metrics.record_cache_hit("gems");
            // Re-put bumps the file mtime (the freshness source) without download.
            let storage = state.storage.clone();
            let key_clone = storage_key.clone();
            let body = cached.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &body).await;
            });
            with_text(cached.to_vec())
        }
        // New body — cache the raw bytes first, then persist the fresh validators.
        Ok(Revalidation::Modified { body, validators }) => {
            state.metrics.record_download("gems");
            state.metrics.record_cache_miss("gems");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                name,
                "gems",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "gems", ""));

            let raw = Bytes::from(body);
            let storage = state.storage.clone();
            let key_clone = storage_key.clone();
            let raw_for_cache = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = storage.put(&key_clone, &raw_for_cache).await {
                    tracing::warn!(key = %key_clone, error = ?e, "gems proxy: failed to cache compact index");
                    return;
                }
                write_validators(&storage, &key_clone, &validators).await;
            });
            with_text(raw.to_vec())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["gems"])
                    .inc();
            }
            if let Some(ref data) = cached_data {
                if state.config.gems.serve_stale {
                    tracing::warn!(
                        registry = "gems",
                        name = %name,
                        error = ?e,
                        "RubyGems upstream error, serving stale compact index"
                    );
                    return (
                        StatusCode::OK,
                        [
                            (
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("text/plain; charset=utf-8"),
                            ),
                            (
                                header::CACHE_CONTROL,
                                HeaderValue::from_static("public, max-age=0, must-revalidate"),
                            ),
                            (
                                axum::http::header::HeaderName::from_static("x-nora-stale"),
                                HeaderValue::from_static("true"),
                            ),
                        ],
                        data.to_vec(),
                    )
                        .into_response();
                }
            }
            tracing::debug!(error = ?e, "RubyGems compact index error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Gem download (immutable) ───────────────────────────────────────────

async fn download_gem(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(filename): Path<String>,
) -> Response {
    // filename = "name-version.gem" — strip .gem suffix and split
    let stem = match filename.strip_suffix(".gem") {
        Some(s) => s,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let (name, version) = match split_gem_filename(stem) {
        Some(nv) => nv,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    if !is_valid_gem_name(&name) || !is_valid_version(&version) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let artifact = format!("{}-{}", name, version);
    let storage_key = format!("gems/gems/{}.gem", artifact);

    // mtime fallback for hosted-only mode (proxy mtime = cache time, not publish time)
    let publish_date = if state.config.gems.proxy.is_none() {
        crate::curation::extract_mtime_as_publish_date(&state.storage, &storage_key).await
    } else {
        None
    };

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        crate::curation::RegistryType::Gems,
        &name,
        Some(&version),
        publish_date,
    ) {
        return response;
    }

    // Immutable: if cached, serve directly. get_verified discharges the integrity
    // witness at the serve site (compile-time guarantee — see crate::verified).
    if let Ok(outcome) = state.storage.get_verified(&storage_key).await {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        // Curation integrity
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Gems,
            &name,
            Some(&version),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("gems");
        state.metrics.record_cache_hit("gems");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            artifact,
            "gems",
            "CACHE",
        ));
        return with_binary(data.to_vec(), "application/octet-stream");
    }

    // Fetch from upstream
    let proxy_url = upstream_url(&state);
    let url = format!("{}/gems/{}.gem", proxy_url.trim_end_matches('/'), artifact);

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.gems.proxy_timeout),
        expose_opt(&state.config.gems.proxy_auth),
        &state.circuit_breaker,
        RegistryType::Gems,
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("gems");
            state.metrics.record_cache_miss("gems");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact,
                "gems",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "gems", ""));

            // Immutable cache: put_if_absent
            state.spawn_cache_immutable("gems", storage_key, Bytes::from(bytes.clone()));
            with_binary(bytes, "application/octet-stream")
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "RubyGems download error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Gemspec download (immutable) ───────────────────────────────────────

async fn download_gemspec(State(state): State<AppState>, Path(filename): Path<String>) -> Response {
    // filename = "name-version.gemspec.rz" — strip suffix and split
    let stem = match filename.strip_suffix(".gemspec.rz") {
        Some(s) => s,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let (name, version) = match split_gem_filename(stem) {
        Some(nv) => nv,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    if !is_valid_gem_name(&name) || !is_valid_version(&version) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let artifact = format!("{}-{}", name, version);
    let storage_key = format!("gems/quick/Marshal.4.8/{}.gemspec.rz", artifact);

    // Immutable cache. get_verified discharges the integrity witness at serve.
    if let Ok(outcome) = state.storage.get_verified(&storage_key).await {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        state.metrics.record_download("gems");
        state.metrics.record_cache_hit("gems");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            artifact,
            "gems",
            "CACHE",
        ));
        return with_binary(data.to_vec(), "application/octet-stream");
    }

    // #68 namespace isolation: a cached internal gem's spec was served above; an
    // internal name with no local copy must not be fetched upstream.
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Gems,
        &name,
    ) {
        return response;
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/quick/Marshal.4.8/{}.gemspec.rz",
        proxy_url.trim_end_matches('/'),
        artifact
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.gems.proxy_timeout),
        expose_opt(&state.config.gems.proxy_auth),
        &state.circuit_breaker,
        RegistryType::Gems,
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("gems");
            state.metrics.record_cache_miss("gems");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact,
                "gems",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "gems", ""));

            state.spawn_cache_immutable("gems", storage_key, Bytes::from(bytes.clone()));
            with_binary(bytes, "application/octet-stream")
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "RubyGems gemspec error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn upstream_url(state: &AppState) -> String {
    state
        .config
        .gems
        .proxy
        .clone()
        .unwrap_or_else(|| UPSTREAM_DEFAULT.to_string())
}

fn with_binary(data: Vec<u8>, content_type: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
        ],
        data,
    )
        .into_response()
}

fn with_text(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60, must-revalidate"),
            ),
        ],
        data,
    )
        .into_response()
}

/// Split gem filename "name-version" into (name, version).
/// The version starts at the last hyphen followed by a digit.
/// Examples:
///   "rails-7.0.0"      → ("rails", "7.0.0")
///   "rack-test-1.0.0"  → ("rack-test", "1.0.0")
///   "rspec-core-3.12"  → ("rspec-core", "3.12")
pub fn split_gem_filename(stem: &str) -> Option<(String, String)> {
    // Find the last '-' that is followed by a digit (start of version)
    let mut split_pos = None;
    for (i, c) in stem.char_indices() {
        if c == '-' {
            if let Some(next) = stem[i + 1..].chars().next() {
                if next.is_ascii_digit() {
                    split_pos = Some(i);
                }
            }
        }
    }
    let pos = split_pos?;
    let name = &stem[..pos];
    let version = &stem[pos + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// Validate gem name: alphanumeric, hyphens, underscores, dots.
/// No path traversal, no slashes, no null bytes.
fn is_valid_gem_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains('/')
        && !name.contains('\0')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Validate version string: digits, dots, hyphens, alphanumeric, ".pre", ".beta", etc.
fn is_valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && !version.contains('/')
        && !version.contains('\0')
        && !version.contains("..")
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_valid_gem_names() {
        assert!(is_valid_gem_name("rails"));
        assert!(is_valid_gem_name("activerecord"));
        assert!(is_valid_gem_name("rack-test"));
        assert!(is_valid_gem_name("ruby_parser"));
        assert!(is_valid_gem_name("nokogiri"));
        assert!(is_valid_gem_name("rspec-core"));
    }

    #[test]
    fn test_invalid_gem_names() {
        assert!(!is_valid_gem_name(""));
        assert!(!is_valid_gem_name("../evil"));
        assert!(!is_valid_gem_name("foo/bar"));
        assert!(!is_valid_gem_name("foo\0bar"));
        assert!(!is_valid_gem_name("foo bar"));
    }

    #[test]
    fn test_valid_versions() {
        assert!(is_valid_version("1.0.0"));
        assert!(is_valid_version("3.2.1"));
        assert!(is_valid_version("1.0.0.pre"));
        assert!(is_valid_version("2.0.0.beta1"));
        assert!(is_valid_version("1.0.0-rc1"));
    }

    #[test]
    fn test_invalid_versions() {
        assert!(!is_valid_version(""));
        assert!(!is_valid_version("../1.0"));
        assert!(!is_valid_version("1.0/evil"));
        assert!(!is_valid_version("1.0\0evil"));
    }

    #[test]
    fn test_split_gem_filename_simple() {
        let (name, ver) = split_gem_filename("rails-7.0.0").unwrap();
        assert_eq!(name, "rails");
        assert_eq!(ver, "7.0.0");
    }

    #[test]
    fn test_split_gem_filename_with_hyphens() {
        let (name, ver) = split_gem_filename("rack-test-1.0.0").unwrap();
        assert_eq!(name, "rack-test");
        assert_eq!(ver, "1.0.0");
    }

    #[test]
    fn test_split_gem_filename_complex() {
        let (name, ver) = split_gem_filename("rspec-core-3.12.0").unwrap();
        assert_eq!(name, "rspec-core");
        assert_eq!(ver, "3.12.0");
    }

    #[test]
    fn test_split_gem_filename_pre_release() {
        let (name, ver) = split_gem_filename("rails-7.0.0.pre").unwrap();
        assert_eq!(name, "rails");
        assert_eq!(ver, "7.0.0.pre");
    }

    #[test]
    fn test_split_gem_filename_no_version() {
        assert!(split_gem_filename("noversion").is_none());
    }

    #[test]
    fn test_split_gem_filename_empty() {
        assert!(split_gem_filename("").is_none());
    }

    #[test]
    fn test_ttl_fresh() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(is_within_ttl(now - 10, 3600)); // 10s ago, TTL 1h
    }

    #[test]
    fn test_ttl_expired() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(!is_within_ttl(now - 7200, 3600)); // 2h ago, TTL 1h
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_gems_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = false;
        });
        // Gems routes are not mounted when disabled, so 404
        let resp = send(&ctx.app, Method::GET, "/gems/info/rails", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_gems_invalid_name_rejected() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
        });
        let resp = send(&ctx.app, Method::GET, "/gems/info/../evil", "").await;
        // Route won't match since .. is not a valid {name} segment
        assert!(resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_gems_unreachable_proxy_returns_error() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            // Point to unreachable host to force error path
            cfg.gems.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.gems.proxy_timeout = 1;
        });
        let resp = send(&ctx.app, Method::GET, "/gems/gems/rails-7.0.0.gem", "").await;
        // Unreachable proxy → BAD_GATEWAY
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_gems_cached_gem_served() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
        });

        // Pre-populate cache
        ctx.state
            .storage
            .put("gems/gems/test-gem-1.0.0.gem", b"gem-binary-data")
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/gems/gems/test-gem-1.0.0.gem", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"gem-binary-data");
    }

    #[tokio::test]
    async fn test_gems_cached_gemspec_served() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
        });

        ctx.state
            .storage
            .put(
                "gems/quick/Marshal.4.8/test-gem-1.0.0.gemspec.rz",
                b"gemspec-data",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/gems/quick/Marshal.4.8/test-gem-1.0.0.gemspec.rz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"gemspec-data");
    }

    #[tokio::test]
    async fn test_gems_cached_compact_index() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.metadata_ttl = 3600; // 1 hour
        });

        ctx.state
            .storage
            .put("gems/info/rails", b"---\n1.0.0 |checksum:abc123")
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/gems/info/rails", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert!(body.starts_with(b"---"));
    }

    #[tokio::test]
    async fn test_gems_curation_enforce_blocks() {
        use crate::test_helpers::send_with_headers;

        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{"registry": "gems", "name": "evil-gem", "version": "*", "reason": "malware"}]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        ctx.state
            .storage
            .put("gems/gems/evil-gem-1.0.0.gem", b"evil-data")
            .await
            .unwrap();

        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/gems/gems/evil-gem-1.0.0.gem",
            vec![],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers()
                .get("x-nora-decision")
                .and_then(|v| v.to_str().ok()),
            Some("blocked")
        );
    }

    #[tokio::test]
    async fn test_gems_curation_audit_passes() {
        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{"registry": "gems", "name": "evil-gem", "version": "*", "reason": "malware"}]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Audit;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        ctx.state
            .storage
            .put("gems/gems/evil-gem-1.0.0.gem", b"evil-data")
            .await
            .unwrap();

        // Audit mode: logs but does NOT block
        let resp = send(&ctx.app, Method::GET, "/gems/gems/evil-gem-1.0.0.gem", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"evil-data");
    }

    #[tokio::test]
    async fn test_gems_curation_off_passes() {
        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{"registry": "gems", "name": "evil-gem", "version": "*", "reason": "malware"}]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Off;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        ctx.state
            .storage
            .put("gems/gems/evil-gem-1.0.0.gem", b"evil-data")
            .await
            .unwrap();

        // Off mode: no filtering
        let resp = send(&ctx.app, Method::GET, "/gems/gems/evil-gem-1.0.0.gem", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// #52 acceptance: with a cached compact-index body + stored validators, a
    /// stale request revalidates with `If-None-Match`; on upstream 304 the cached
    /// body is served and NO 200-with-body is ever fetched. Drives the real
    /// handler (RubyGems compact-index endpoints support validators per the
    /// official Compact Index API guide).
    #[tokio::test]
    async fn test_gems_revalidation_304_serves_cache_no_body_download() {
        use crate::registry::{write_validators, Validators};
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Conditional request (has If-None-Match) → 304. A request WITHOUT it
        // would 404 (no other mount), so any full fetch would visibly fail.
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(upstream.uri());
            cfg.gems.metadata_ttl = 0; // always stale → always revalidate
            cfg.gems.revalidate = true;
            cfg.gems.serve_stale = false;
        });

        let key = "gems/info/rails";
        ctx.state
            .storage
            .put(key, b"---\n1.0.0 |checksum:abc\n")
            .await
            .unwrap();
        write_validators(
            &ctx.state.storage,
            key,
            &Validators {
                etag: Some("\"v1\"".to_string()),
                last_modified: None,
            },
        )
        .await;

        let before = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["gems"])
            .get();

        let resp = send(&ctx.app, Method::GET, "/gems/info/rails", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert!(
            String::from_utf8_lossy(&body).contains("1.0.0"),
            "must serve the cached compact-index body"
        );

        let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["gems"])
            .get();
        assert!(after > before, "a 304 revalidation must be recorded");
    }
}
