// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! NuGet v3 registry proxy.
//!
//! Implements a caching proxy for api.nuget.org:
//!   GET /nuget/v3/index.json — service index (JSON, rewrite @id URLs)
//!   GET /nuget/v3/registration/{id}/index.json — package registration
//!   GET /nuget/v3/flatcontainer/{id}/index.json — version list
//!   GET /nuget/v3/flatcontainer/{id}/{ver}/{filename}.nupkg — package download (immutable)
//!   GET /nuget/v3/flatcontainer/{id}/{ver}/{filename}.nuspec — package spec (immutable)
//!
//! Client config:
//!   dotnet nuget add source http://nora:4000/nuget/v3/index.json -n nora

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::{
    circuit_open_response, nora_base_url, proxy_fetch, proxy_fetch_text, ProxyError,
};
use crate::validation::ends_with_ci;
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;

const UPSTREAM_DEFAULT: &str = "https://api.nuget.org";

/// Storage prefix and file suffix for repo index scanning.
pub const INDEX_PATTERN: (&str, &str) = ("nuget/flatcontainer/", "index.json");

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Service index
        .route("/nuget/v3/index.json", get(service_index))
        // Search (proxy to upstream SearchQueryService)
        .route("/nuget/v3/query", get(search_query))
        // Registration index
        .route(
            "/nuget/v3/registration/{id}/index.json",
            get(registration_index),
        )
        // Flat container: version list + package download (single wildcard)
        .route(
            "/nuget/v3/flatcontainer/{*path}",
            get(flatcontainer_handler),
        )
}

// ── Service index ──────────────────────────────────────────────────────

async fn service_index(State(state): State<Arc<AppState>>) -> Response {
    let base_url = nora_base_url(&state);
    let proxy_url = upstream_url(&state);
    let url = format!("{}/v3/index.json", proxy_url.trim_end_matches('/'));

    match proxy_fetch_text(
        &state.http_client,
        &url,
        state.config.nuget.proxy_timeout,
        state.config.nuget.proxy_auth.as_deref(),
        None,
        &state.circuit_breaker,
        "nuget",
    )
    .await
    {
        Ok(text) => {
            // Rewrite @id URLs to point through NORA
            let rewritten = rewrite_service_index(&text, &base_url);

            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                "service-index".to_string(),
                "nuget",
                "PROXY",
            ));

            with_json(rewritten.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "NuGet service index error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Search query (proxy to upstream SearchQueryService) ───────────────

async fn search_query(
    State(state): State<Arc<AppState>>,
    raw_query: axum::extract::RawQuery,
) -> Response {
    // Forward query string as-is to upstream search
    let qs = raw_query.0.unwrap_or_default();
    let url = format!("{}?{}", state.config.nuget.search_service, qs);

    match proxy_fetch_text(
        &state.http_client,
        &url,
        state.config.nuget.proxy_timeout,
        None, // search endpoint is public
        None,
        &state.circuit_breaker,
        "nuget",
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("search?{}", qs.chars().take(50).collect::<String>()),
                "nuget",
                "PROXY",
            ));
            with_json(text.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "NuGet search error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Registration index ─────────────────────────────────────────────────

async fn registration_index(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let id_lower = id.to_lowercase();
    if !is_valid_package_id(&id_lower) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::Nuget,
        &id_lower,
        None,
        None,
    ) {
        return response;
    }

    let storage_key = format!("nuget/registration/{}/index.json", id_lower);

    // TTL cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.nuget.metadata_ttl) {
                state.metrics.record_download("nuget");
                state.metrics.record_cache_hit();
                return with_json(data.to_vec());
            }
        }
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v3/registration5-gz-semver2/{}/index.json",
        proxy_url.trim_end_matches('/'),
        id_lower
    );

    match proxy_fetch_text(
        &state.http_client,
        &url,
        state.config.nuget.proxy_timeout,
        state.config.nuget.proxy_auth.as_deref(),
        None,
        &state.circuit_breaker,
        "nuget",
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                id_lower.clone(),
                "nuget",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "nuget", ""));

            let storage = state.storage.clone();
            let key = storage_key;
            let data = text.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key, data.as_bytes()).await;
            });

            state.repo_index.invalidate("nuget");
            with_json(text.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "NuGet registration error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Flat container dispatcher ───────────────────────────────────────────

async fn flatcontainer_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
) -> Response {
    // Path patterns:
    //   {id}/index.json              → version list
    //   {id}/{ver}/{filename}.nupkg  → package download
    //   {id}/{ver}/{filename}.nuspec → package spec
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    match parts.len() {
        2 if parts[1] == "index.json" => version_list(state, parts[0]).await,
        3 => flatcontainer_download(state, headers, &path, parts[0], parts[1], parts[2]).await,
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

// ── Version list ───────────────────────────────────────────────────────

async fn version_list(state: Arc<AppState>, id: &str) -> Response {
    let id = id.to_string();
    let id_lower = id.to_lowercase();
    if !is_valid_package_id(&id_lower) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!("nuget/flatcontainer/{}/index.json", id_lower);

    // TTL cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.nuget.metadata_ttl) {
                state.metrics.record_download("nuget");
                state.metrics.record_cache_hit();
                return with_json(data.to_vec());
            }
        }
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v3-flatcontainer/{}/index.json",
        proxy_url.trim_end_matches('/'),
        id_lower
    );

    match proxy_fetch_text(
        &state.http_client,
        &url,
        state.config.nuget.proxy_timeout,
        state.config.nuget.proxy_auth.as_deref(),
        None,
        &state.circuit_breaker,
        "nuget",
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/versions", id_lower),
                "nuget",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "nuget", ""));

            let storage = state.storage.clone();
            let key = storage_key;
            let data = text.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key, data.as_bytes()).await;
            });

            state.repo_index.invalidate("nuget");
            with_json(text.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "NuGet version list error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Flatcontainer download (nupkg/nuspec, immutable) ───────────────────

async fn flatcontainer_download(
    state: Arc<AppState>,
    headers: axum::http::HeaderMap,
    path: &str,
    id: &str,
    ver: &str,
    filename: &str,
) -> Response {
    if !is_safe_path(path) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Only serve .nupkg and .nuspec files
    if !ends_with_ci(filename, ".nupkg") && !ends_with_ci(filename, ".nuspec") {
        return StatusCode::NOT_FOUND.into_response();
    }

    let id_lower = id.to_lowercase();

    // Curation check for .nupkg downloads
    if ends_with_ci(filename, ".nupkg") {
        // Extract publish date from cached registration index
        let publish_date = extract_nuget_publish_date(&state.storage, &id_lower, ver).await;

        if let Some(response) = crate::curation::check_download(
            &state.curation,
            state.config.curation.bypass_token.as_deref(),
            &headers,
            crate::curation::RegistryType::Nuget,
            &id_lower,
            Some(ver),
            publish_date,
        ) {
            return response;
        }
    }

    let storage_key = format!("nuget/flatcontainer/{}", path.to_lowercase());
    let content_type = if ends_with_ci(filename, ".nuspec") {
        "application/xml"
    } else {
        "application/octet-stream"
    };

    // Immutable cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        if ends_with_ci(filename, ".nupkg") {
            if let Some(response) = crate::curation::verify_integrity(
                &state.curation,
                crate::curation::RegistryType::Nuget,
                &id_lower,
                Some(ver),
                &data,
            ) {
                return response;
            }
        }

        state.metrics.record_download("nuget");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            format!("{}/{}", id_lower, filename),
            "nuget",
            "CACHE",
        ));
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            data.to_vec(),
        )
            .into_response();
    }

    // Fetch from upstream
    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v3-flatcontainer/{}/{}/{}",
        proxy_url.trim_end_matches('/'),
        id_lower,
        ver.to_lowercase(),
        filename.to_lowercase()
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        state.config.nuget.proxy_timeout,
        state.config.nuget.proxy_auth.as_deref(),
        &state.circuit_breaker,
        "nuget",
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/{}", id_lower, filename),
                "nuget",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "nuget", ""));

            let storage = state.storage.clone();
            let key = storage_key;
            let data = bytes.clone();
            tokio::spawn(async move {
                if storage.stat(&key).await.is_none() {
                    let _ = storage.put(&key, &data).await;
                }
            });

            state.repo_index.invalidate("nuget");
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                ],
                bytes.to_vec(),
            )
                .into_response()
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "NuGet download error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Extract publish date from cached NuGet registration index.
///
/// NuGet registration index JSON has nested items:
/// ```json
/// { "items": [{ "items": [{ "catalogEntry": { "version": "1.0.0", "published": "2024-01-15T10:30:00Z" } }] }] }
/// ```
// TODO(v1.0): trust_upstream_dates config for high-security installs
async fn extract_nuget_publish_date(
    storage: &crate::storage::Storage,
    id: &str,
    version: &str,
) -> Option<i64> {
    let meta_key = format!("nuget/registration/{}/index.json", id.to_lowercase());
    let data = storage.get(&meta_key).await.ok()?;
    let json: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let pages = json.get("items")?.as_array()?;
    for page in pages {
        let items = page.get("items")?.as_array()?;
        for item in items {
            let entry = item.get("catalogEntry")?;
            let ver = entry.get("version")?.as_str()?;
            if ver.eq_ignore_ascii_case(version) {
                let date_str = entry.get("published")?.as_str()?;
                return crate::curation::parse_iso8601_to_unix(date_str);
            }
        }
    }
    None
}

fn upstream_url(state: &AppState) -> String {
    state
        .config
        .nuget
        .proxy
        .clone()
        .unwrap_or_else(|| UPSTREAM_DEFAULT.to_string())
}

fn is_within_ttl(modified_unix: u64, ttl_secs: u64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(modified_unix) < ttl_secs
}

fn with_json(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
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

/// Rewrite known Microsoft NuGet service index URLs with NORA endpoints.
/// `base_url` is the full NORA base URL including scheme (e.g. `https://artifact.company.local`).
/// Targets api.nuget.org and azuresearch-{usnc,ussc}.nuget.org specifically.
fn rewrite_service_index(json_text: &str, base_url: &str) -> String {
    let nora_nuget = format!("{}/nuget", base_url.trim_end_matches('/'));
    let nora_query = format!("{}/v3/query", nora_nuget);

    // Rewrite major service URLs to route through NORA
    json_text
        .replace(
            "https://api.nuget.org/v3-flatcontainer/",
            &format!("{}/v3/flatcontainer/", nora_nuget),
        )
        .replace(
            "https://api.nuget.org/v3/registration5-gz-semver2/",
            &format!("{}/v3/registration/", nora_nuget),
        )
        // Rewrite search endpoints to proxy through NORA
        .replace("https://azuresearch-usnc.nuget.org/query", &nora_query)
        .replace("https://azuresearch-ussc.nuget.org/query", &nora_query)
}

fn is_valid_package_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && !id.contains('/')
        && !id.contains('\0')
        && !id.contains("..")
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

fn is_safe_path(path: &str) -> bool {
    !path.contains("..")
        && !path.starts_with('/')
        && !path.contains("//")
        && !path.contains('\0')
        && !path.is_empty()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_package_ids() {
        assert!(is_valid_package_id("newtonsoft.json"));
        assert!(is_valid_package_id("system.text.json"));
        assert!(is_valid_package_id("microsoft.extensions.logging"));
        assert!(is_valid_package_id("xunit"));
    }

    #[test]
    fn test_invalid_package_ids() {
        assert!(!is_valid_package_id(""));
        assert!(!is_valid_package_id("../evil"));
        assert!(!is_valid_package_id("foo/bar"));
    }

    #[test]
    fn test_rewrite_service_index_http() {
        let input = r#"{"resources":[{"@id":"https://api.nuget.org/v3-flatcontainer/","@type":"PackageBaseAddress/3.0.0"}]}"#;
        let result = rewrite_service_index(input, "http://nora:4000");
        assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
        assert!(!result.contains("api.nuget.org/v3-flatcontainer/"));
    }

    #[test]
    fn test_rewrite_service_index_search_urls() {
        let input = r#"{"resources":[{"@id":"https://azuresearch-usnc.nuget.org/query","@type":"SearchQueryService"},{"@id":"https://azuresearch-ussc.nuget.org/query","@type":"SearchQueryService"}]}"#;
        let result = rewrite_service_index(input, "http://nora:4000");
        assert!(result.contains("http://nora:4000/nuget/v3/query"));
        assert!(!result.contains("azuresearch-usnc.nuget.org"));
        assert!(!result.contains("azuresearch-ussc.nuget.org"));
    }

    #[test]
    fn test_rewrite_service_index_https() {
        let input = r#"{"resources":[{"@id":"https://api.nuget.org/v3-flatcontainer/","@type":"PackageBaseAddress/3.0.0"},{"@id":"https://api.nuget.org/v3/registration5-gz-semver2/","@type":"RegistrationsBaseUrl/3.6.0"}]}"#;
        let result = rewrite_service_index(input, "https://artifact.company.local");
        assert!(result.contains("https://artifact.company.local/nuget/v3/flatcontainer/"));
        assert!(result.contains("https://artifact.company.local/nuget/v3/registration/"));
        assert!(!result.contains("http://artifact.company.local"));
        assert!(!result.contains("api.nuget.org"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_nuget_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = false;
        });
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/index.json", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_nuget_cached_nupkg() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
        });

        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
                b"nupkg-data",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"nupkg-data");
    }

    #[tokio::test]
    async fn test_nuget_unreachable_proxy() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/test-package/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_extract_nuget_publish_date_found() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let meta = serde_json::json!({
            "items": [{
                "items": [{
                    "catalogEntry": {
                        "version": "6.0.0",
                        "published": "2023-11-14T10:30:00Z"
                    }
                }]
            }]
        });
        storage
            .put(
                "nuget/registration/newtonsoft.json/index.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let result = super::extract_nuget_publish_date(&storage, "newtonsoft.json", "6.0.0").await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_extract_nuget_publish_date_version_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let meta = serde_json::json!({
            "items": [{"items": [{"catalogEntry": {"version": "1.0.0", "published": "2023-01-01T00:00:00Z"}}]}]
        });
        storage
            .put(
                "nuget/registration/test/index.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let result = super::extract_nuget_publish_date(&storage, "test", "9.9.9").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_extract_nuget_publish_date_no_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

        let result = super::extract_nuget_publish_date(&storage, "nonexistent", "1.0.0").await;
        assert!(result.is_none());
    }
}
