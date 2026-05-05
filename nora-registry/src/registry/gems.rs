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
use crate::registry::{circuit_open_response, proxy_fetch, proxy_fetch_text, ProxyError};
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const UPSTREAM_DEFAULT: &str = "https://rubygems.org";

/// Storage prefix and file suffix for repo index scanning.
pub const INDEX_PATTERN: (&str, &str) = ("gems/gems/", ".gem");

pub fn routes() -> Router<Arc<AppState>> {
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

/// Check if a cached entry is within TTL based on unix timestamp
fn is_within_ttl(modified_unix: u64, ttl_secs: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(modified_unix) < ttl_secs
}

// ── Index endpoints (mutable, TTL cached) ─────────────────────────────

async fn specs_index(State(state): State<Arc<AppState>>) -> Response {
    fetch_index(&state, "specs.4.8.gz").await
}

async fn latest_specs_index(State(state): State<Arc<AppState>>) -> Response {
    fetch_index(&state, "latest_specs.4.8.gz").await
}

async fn prerelease_specs_index(State(state): State<Arc<AppState>>) -> Response {
    fetch_index(&state, "prerelease_specs.4.8.gz").await
}

async fn fetch_index(state: &AppState, filename: &str) -> Response {
    let storage_key = format!("gems/{}", filename);

    // Check TTL: if cached and fresh, serve from cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.gems.index_ttl) {
                state.metrics.record_download("gems");
                state.metrics.record_cache_hit();
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
        state.config.gems.proxy_timeout,
        state.config.gems.proxy_auth.as_deref(),
        &state.circuit_breaker,
        "gems",
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("gems");
            state.metrics.record_cache_miss();
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
            let storage = state.storage.clone();
            let key = storage_key;
            let data = bytes.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key, &data).await;
            });

            state.repo_index.invalidate("gems");
            with_binary(bytes, "application/gzip")
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(filename, error = ?e, "RubyGems upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Compact index ──────────────────────────────────────────────────────

async fn compact_index(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if !is_valid_gem_name(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::Gems,
        &name,
        None,
        None,
    ) {
        return response;
    }

    let storage_key = format!("gems/info/{}", name);

    // Check TTL cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.gems.index_ttl) {
                state.metrics.record_download("gems");
                state.metrics.record_cache_hit();
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

    match proxy_fetch_text(
        &state.http_client,
        &url,
        state.config.gems.proxy_timeout,
        state.config.gems.proxy_auth.as_deref(),
        None,
        &state.circuit_breaker,
        "gems",
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("gems");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                name,
                "gems",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "gems", ""));

            let storage = state.storage.clone();
            let key = storage_key;
            let data = text.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key, data.as_bytes()).await;
            });

            state.repo_index.invalidate("gems");
            with_text(text.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "RubyGems compact index error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Gem download (immutable) ───────────────────────────────────────────

async fn download_gem(
    State(state): State<Arc<AppState>>,
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
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::Gems,
        &name,
        Some(&version),
        publish_date,
    ) {
        return response;
    }

    // Immutable: if cached, serve directly
    if let Ok(data) = state.storage.get(&storage_key).await {
        // Curation integrity
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation,
            crate::curation::RegistryType::Gems,
            &name,
            Some(&version),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("gems");
        state.metrics.record_cache_hit();
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
        state.config.gems.proxy_timeout,
        state.config.gems.proxy_auth.as_deref(),
        &state.circuit_breaker,
        "gems",
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("gems");
            state.metrics.record_cache_miss();
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
            let storage = state.storage.clone();
            let key = storage_key;
            let data = bytes.clone();
            tokio::spawn(async move {
                if storage.stat(&key).await.is_none() {
                    let _ = storage.put(&key, &data).await;
                }
            });

            state.repo_index.invalidate("gems");
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

async fn download_gemspec(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> Response {
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

    // Immutable cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        state.metrics.record_download("gems");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            artifact,
            "gems",
            "CACHE",
        ));
        return with_binary(data.to_vec(), "application/octet-stream");
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
        state.config.gems.proxy_timeout,
        state.config.gems.proxy_auth.as_deref(),
        &state.circuit_breaker,
        "gems",
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("gems");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact,
                "gems",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "gems", ""));

            let storage = state.storage.clone();
            let key = storage_key;
            let data = bytes.clone();
            tokio::spawn(async move {
                if storage.stat(&key).await.is_none() {
                    let _ = storage.put(&key, &data).await;
                }
            });

            state.repo_index.invalidate("gems");
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
fn split_gem_filename(stem: &str) -> Option<(String, String)> {
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
            cfg.gems.index_ttl = 3600; // 1 hour
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
}
