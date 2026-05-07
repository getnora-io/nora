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
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::Deserialize;
use std::sync::Arc;

const UPSTREAM_DEFAULT: &str = "https://api.nuget.org";
const SEARCH_TIMEOUT_SECS: u64 = 5;

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    skip: Option<usize>,
    take: Option<usize>,
    #[allow(dead_code)]
    prerelease: Option<bool>,
}

/// Storage prefix and file suffix for repo index scanning.
pub const INDEX_PATTERN: (&str, &str) = ("nuget/flatcontainer/", "index.json");

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Service index
        .route("/nuget/v3/index.json", get(service_index))
        // Search (proxy to upstream SearchQueryService)
        .route("/nuget/v3/query", get(search_query))
        // Autocomplete (proxy to upstream SearchAutocompleteService)
        .route("/nuget/v3/autocomplete", get(autocomplete_query))
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

// ── Search query (proxy to upstream SearchQueryService, local fallback) ──

async fn search_query(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<SearchParams>,
    raw_query: axum::extract::RawQuery,
) -> Response {
    let query = params.q.unwrap_or_default();
    let skip = params.skip.unwrap_or(0);
    let take = params.take.unwrap_or(20);

    // No upstream proxy configured → local search directly
    if state.config.nuget.proxy.is_none() {
        let data = local_search_results(&state, &headers, &query, skip, take).await;
        return with_json(data);
    }

    // Try upstream with short timeout (UX-critical path)
    let qs = raw_query.0.unwrap_or_default();
    let url = format!("{}?{}", state.config.nuget.search_service, qs);

    match proxy_fetch_text(
        &state.http_client,
        &url,
        SEARCH_TIMEOUT_SECS,
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
        Err(ProxyError::NotFound) => with_json(br#"{"totalHits":0,"data":[]}"#.to_vec()),
        Err(ProxyError::CircuitOpen(_) | ProxyError::Network(_) | ProxyError::Upstream(_)) => {
            tracing::info!("NuGet search: upstream unavailable, using local index");
            let data = local_search_results(&state, &headers, &query, skip, take).await;
            with_json(data)
        }
    }
}

// ── Autocomplete (proxy to upstream SearchAutocompleteService) ─────────

async fn autocomplete_query(
    State(state): State<Arc<AppState>>,
    raw_query: axum::extract::RawQuery,
) -> Response {
    // No upstream proxy configured → return empty results
    if state.config.nuget.proxy.is_none() {
        return with_json(br#"{"totalHits":0,"data":[]}"#.to_vec());
    }

    let qs = raw_query.0.unwrap_or_default();
    let url = format!("{}?{}", state.config.nuget.autocomplete, qs);

    match proxy_fetch_text(
        &state.http_client,
        &url,
        SEARCH_TIMEOUT_SECS,
        None, // autocomplete endpoint is public
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
                format!("autocomplete?{}", qs.chars().take(50).collect::<String>()),
                "nuget",
                "PROXY",
            ));
            with_json(text.into_bytes())
        }
        Err(_) => {
            // Autocomplete is UX convenience, not correctness-critical
            with_json(br#"{"totalHits":0,"data":[]}"#.to_vec())
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

        // Track last download time for .nupkg files
        if ends_with_ci(filename, ".nupkg") {
            let storage = state.storage.clone();
            let meta_key = format!("nuget/flatcontainer/{}/.nora-meta.json", id_lower);
            tokio::spawn(async move {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let meta = format!(r#"{{"last_downloaded_at":{}}}"#, now);
                let _ = storage.put(&meta_key, meta.as_bytes()).await;
            });
        }

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

            // Best-effort: fetch flatcontainer index.json if missing (for local search)
            if ends_with_ci(filename, ".nupkg") {
                let index_key = format!("nuget/flatcontainer/{}/index.json", id_lower);
                let state2 = Arc::clone(&state);
                let proxy_url2 = proxy_url.clone();
                let id2 = id_lower.clone();
                tokio::spawn(async move {
                    if state2.storage.stat(&index_key).await.is_none() {
                        let url = format!(
                            "{}/v3-flatcontainer/{}/index.json",
                            proxy_url2.trim_end_matches('/'),
                            id2
                        );
                        let client = reqwest::Client::new();
                        if let Ok(resp) = client.get(&url).send().await {
                            if let Ok(body) = resp.bytes().await {
                                let _ = state2.storage.put(&index_key, &body).await;
                                state2.repo_index.invalidate("nuget");
                            }
                        }
                    }
                });

                // Track last download time
                let storage3 = state.storage.clone();
                let meta_key = format!("nuget/flatcontainer/{}/.nora-meta.json", id_lower);
                tokio::spawn(async move {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let meta = format!(r#"{{"last_downloaded_at":{}}}"#, now);
                    let _ = storage3.put(&meta_key, meta.as_bytes()).await;
                });
            }

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

// ── Local search helpers ───────────────────────────────────────────────

/// Read cached version list from flatcontainer index.json.
async fn get_cached_versions(storage: &crate::storage::Storage, id: &str) -> Vec<String> {
    let key = format!("nuget/flatcontainer/{}/index.json", id.to_lowercase());
    let data = match storage.get(&key).await {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    json.get("versions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Build one NuGet V3 search result entry.
fn build_search_entry(
    base_url: &str,
    pkg: &crate::repo_index::RepoInfo,
    versions: &[String],
) -> serde_json::Value {
    let nora_nuget = format!("{}/nuget", base_url.trim_end_matches('/'));
    let id = &pkg.name;
    let latest = versions.last().map(|s| s.as_str()).unwrap_or("0.0.0");

    let version_entries: Vec<serde_json::Value> = versions
        .iter()
        .map(|v| {
            serde_json::json!({
                "version": v,
                "downloads": 0,
                "@id": format!("{}/v3/registration/{}/{}.json", nora_nuget, id.to_lowercase(), v)
            })
        })
        .collect();

    serde_json::json!({
        "id": id,
        "version": latest,
        "versions": version_entries,
        "description": "",
        "totalDownloads": 0,
        "packageTypes": [{"name": "Dependency"}],
        "registration": format!("{}/v3/registration/{}/index.json", nora_nuget, id.to_lowercase())
    })
}

/// Build local search results from the in-memory repo index.
async fn local_search_results(
    state: &AppState,
    _headers: &HeaderMap,
    query: &str,
    skip: usize,
    take: usize,
) -> Vec<u8> {
    let packages = state.repo_index.get("nuget", &state.storage).await;
    let base_url = nora_base_url(state);

    let query_lower = query.to_lowercase();
    let filtered: Vec<&crate::repo_index::RepoInfo> = packages
        .iter()
        .filter(|pkg| query_lower.is_empty() || pkg.name.to_lowercase().contains(&query_lower))
        .collect();

    let total_hits = filtered.len();
    let page: Vec<&crate::repo_index::RepoInfo> =
        filtered.into_iter().skip(skip).take(take).collect();

    let mut data = Vec::with_capacity(page.len());
    for pkg in &page {
        let versions = get_cached_versions(&state.storage, &pkg.name).await;
        data.push(build_search_entry(&base_url, pkg, &versions));
    }

    let result = serde_json::json!({
        "totalHits": total_hits,
        "data": data,
    });
    serde_json::to_vec(&result).unwrap_or_else(|_| br#"{"totalHits":0,"data":[]}"#.to_vec())
}

/// Rewrite known Microsoft NuGet service index URLs with NORA endpoints.
/// `base_url` is the full NORA base URL including scheme (e.g. `https://artifact.company.local`).
/// Targets api.nuget.org and azuresearch-{usnc,ussc}.nuget.org specifically.
fn rewrite_service_index(json_text: &str, base_url: &str) -> String {
    let nora_nuget = format!("{}/nuget", base_url.trim_end_matches('/'));
    let nora_query = format!("{}/v3/query", nora_nuget);
    let nora_autocomplete = format!("{}/v3/autocomplete", nora_nuget);

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
        // Rewrite autocomplete endpoints to proxy through NORA
        .replace(
            "https://azuresearch-usnc.nuget.org/autocomplete",
            &nora_autocomplete,
        )
        .replace(
            "https://azuresearch-ussc.nuget.org/autocomplete",
            &nora_autocomplete,
        )
        // Rewrite remaining azuresearch root URLs (SearchGalleryQueryService)
        // Must come AFTER query/autocomplete replaces to avoid partial matches
        .replace(
            "https://azuresearch-usnc.nuget.org/",
            &format!("{}/v3/", nora_nuget),
        )
        .replace(
            "https://azuresearch-ussc.nuget.org/",
            &format!("{}/v3/", nora_nuget),
        )
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

    #[test]
    fn test_rewrite_service_index_autocomplete_urls() {
        let input = r#"{"resources":[{"@id":"https://azuresearch-usnc.nuget.org/autocomplete","@type":"SearchAutocompleteService"},{"@id":"https://azuresearch-ussc.nuget.org/autocomplete","@type":"SearchAutocompleteService/3.5.0"}]}"#;
        let result = rewrite_service_index(input, "http://nora:4000");
        assert!(result.contains("http://nora:4000/nuget/v3/autocomplete"));
        assert!(!result.contains("azuresearch-usnc.nuget.org/autocomplete"));
        assert!(!result.contains("azuresearch-ussc.nuget.org/autocomplete"));
    }

    #[test]
    fn test_rewrite_service_index_gallery_urls() {
        let input = r#"{"resources":[{"@id":"https://azuresearch-usnc.nuget.org/query","@type":"SearchQueryService"},{"@id":"https://azuresearch-usnc.nuget.org/autocomplete","@type":"SearchAutocompleteService"},{"@id":"https://azuresearch-usnc.nuget.org/","@type":"SearchGalleryQueryService/3.0.0-rc"},{"@id":"https://azuresearch-ussc.nuget.org/","@type":"SearchGalleryQueryService/3.0.0-rc"}]}"#;
        let result = rewrite_service_index(input, "http://nora:4000");
        assert!(!result.contains("azuresearch-usnc.nuget.org"));
        assert!(!result.contains("azuresearch-ussc.nuget.org"));
        assert!(result.contains("http://nora:4000/nuget/v3/query"));
        assert!(result.contains("http://nora:4000/nuget/v3/autocomplete"));
        assert!(result.contains("http://nora:4000/nuget/v3/"));
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

    #[tokio::test]
    async fn test_local_search_empty_query() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        // Populate index for two packages
        for id in &["packagea", "packageb"] {
            let index = serde_json::json!({"versions": ["1.0.0"]});
            ctx.state
                .storage
                .put(
                    &format!("nuget/flatcontainer/{}/index.json", id),
                    serde_json::to_vec(&index).unwrap().as_slice(),
                )
                .await
                .unwrap();
        }
        ctx.state.repo_index.invalidate("nuget");

        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["totalHits"].as_u64().unwrap() >= 2);
        assert!(json["data"].as_array().unwrap().len() >= 2);
    }

    #[tokio::test]
    async fn test_local_search_substring_match() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        let index = serde_json::json!({"versions": ["13.0.1"]});
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/newtonsoft.json/index.json",
                serde_json::to_vec(&index).unwrap().as_slice(),
            )
            .await
            .unwrap();
        ctx.state.repo_index.invalidate("nuget");

        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=Newton", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totalHits"].as_u64().unwrap(), 1);
        assert_eq!(json["data"][0]["id"].as_str().unwrap(), "newtonsoft.json");
    }

    #[tokio::test]
    async fn test_local_search_case_insensitive() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        let index = serde_json::json!({"versions": ["13.0.1"]});
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/newtonsoft.json/index.json",
                serde_json::to_vec(&index).unwrap().as_slice(),
            )
            .await
            .unwrap();
        ctx.state.repo_index.invalidate("nuget");

        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=newton", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totalHits"].as_u64().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_local_search_pagination() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        for id in &["alpha", "beta", "gamma"] {
            let index = serde_json::json!({"versions": ["1.0.0"]});
            ctx.state
                .storage
                .put(
                    &format!("nuget/flatcontainer/{}/index.json", id),
                    serde_json::to_vec(&index).unwrap().as_slice(),
                )
                .await
                .unwrap();
        }
        ctx.state.repo_index.invalidate("nuget");

        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?skip=1&take=1", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totalHits"].as_u64().unwrap(), 3);
        assert_eq!(json["data"].as_array().unwrap().len(), 1);
        // Sorted alphabetically: alpha, beta, gamma — skip 1 = beta
        assert_eq!(json["data"][0]["id"].as_str().unwrap(), "beta");
    }

    #[tokio::test]
    async fn test_search_response_format() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        let index = serde_json::json!({"versions": ["1.0.0", "2.0.0"]});
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/testpkg/index.json",
                serde_json::to_vec(&index).unwrap().as_slice(),
            )
            .await
            .unwrap();
        ctx.state.repo_index.invalidate("nuget");

        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=testpkg", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Validate top-level structure
        assert!(json["totalHits"].is_number());
        assert!(json["data"].is_array());

        // Validate entry structure
        let entry = &json["data"][0];
        assert!(entry["id"].is_string());
        assert!(entry["version"].is_string());
        assert!(entry["versions"].is_array());
        assert_eq!(entry["version"].as_str().unwrap(), "2.0.0");
        assert_eq!(entry["versions"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_autocomplete_no_upstream_returns_empty() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/autocomplete?q=Newtonsoft&take=5",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totalHits"].as_u64().unwrap(), 0);
        assert!(json["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_autocomplete_unreachable_upstream_returns_empty() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
            cfg.nuget.autocomplete = "http://127.0.0.1:1/autocomplete".to_string();
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/autocomplete?q=Newtonsoft&take=5",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totalHits"].as_u64().unwrap(), 0);
        assert!(json["data"].as_array().unwrap().is_empty());
    }
}
