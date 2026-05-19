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
    body::Bytes,
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
/// Count .nupkg files (not index.json) so size reflects actual packages.
pub const INDEX_PATTERN: (&str, &str) = ("nuget/flatcontainer/", ".nupkg");

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
        // Registration page (paginated version ranges)
        .route(
            "/nuget/v3/registration/{id}/page/{lower}/{*upper}",
            get(registration_page),
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
            let base_url = nora_base_url(&state);
            let rewritten = rewrite_service_index(&text, &base_url);
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("search?{}", qs.chars().take(50).collect::<String>()),
                "nuget",
                "PROXY",
            ));
            with_json(rewritten.into_bytes())
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
            let base_url = nora_base_url(&state);
            let rewritten = rewrite_service_index(&text, &base_url);
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("autocomplete?{}", qs.chars().take(50).collect::<String>()),
                "nuget",
                "PROXY",
            ));
            with_json(rewritten.into_bytes())
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
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        crate::curation::RegistryType::Nuget,
        &id_lower,
        None,
        None,
    ) {
        return response;
    }

    let storage_key = format!("nuget/registration/{}/index.json", id_lower);

    let base_url = nora_base_url(&state);
    let upstream = upstream_url(&state);

    // TTL cache — rewrite URLs on read (cache may contain pre-fix entries)
    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.nuget.metadata_ttl) {
                state.metrics.record_download("nuget");
                state.metrics.record_cache_hit();
                let text = String::from_utf8_lossy(&data);
                let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
                return with_json(rewritten.into_bytes());
            }
        }
    }

    let url = format!(
        "{}/v3/registration5-gz-semver2/{}/index.json",
        upstream.trim_end_matches('/'),
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

            // Cache raw response, rewrite on serve
            state.spawn_cache("nuget", storage_key, Bytes::from(text.clone()));
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            with_json(rewritten.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "NuGet registration error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Registration page (paginated version ranges) ────────────────────────

async fn registration_page(
    State(state): State<Arc<AppState>>,
    Path((id, lower, upper_raw)): Path<(String, String, String)>,
) -> Response {
    let id_lower = id.to_lowercase();
    if !is_valid_package_id(&id_lower) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let upper = upper_raw
        .strip_suffix(".json")
        .unwrap_or(&upper_raw)
        .to_string();
    if !is_valid_version(&lower) || !is_valid_version(&upper) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let base_url = nora_base_url(&state);
    let upstream = upstream_url(&state);
    let storage_key = format!(
        "nuget/registration/{}/page/{}/{}.json",
        id_lower, lower, upper
    );

    // TTL cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.nuget.metadata_ttl) {
                state.metrics.record_download("nuget");
                state.metrics.record_cache_hit();
                let text = String::from_utf8_lossy(&data);
                let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
                return with_json(rewritten.into_bytes());
            }
        }
    }

    let url = format!(
        "{}/v3/registration5-gz-semver2/{}/page/{}/{}.json",
        upstream.trim_end_matches('/'),
        id_lower,
        lower,
        upper
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
                format!("{}/page/{}/{}", id_lower, lower, upper),
                "nuget",
                "PROXY",
            ));

            state.spawn_cache("nuget", storage_key, Bytes::from(text.clone()));
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            with_json(rewritten.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "NuGet registration page error");
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

            state.spawn_cache("nuget", storage_key, Bytes::from(text.clone()));
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
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
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
                &state.curation().curation_engine,
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

            state.spawn_cache_immutable("nuget", storage_key, Bytes::from(bytes.clone()));

            // Best-effort: fetch flatcontainer index.json if missing (for local search)
            if ends_with_ci(filename, ".nupkg") {
                let index_key = format!("nuget/flatcontainer/{}/index.json", id_lower);
                let state2 = Arc::clone(&state);
                let proxy_url2 = proxy_url.clone();
                let id2 = id_lower.clone();
                let client2 = state.http_client.clone();
                tokio::spawn(async move {
                    if state2.storage.stat(&index_key).await.is_none() {
                        let url = format!(
                            "{}/v3-flatcontainer/{}/index.json",
                            proxy_url2.trim_end_matches('/'),
                            id2
                        );
                        if let Ok(resp) = client2.get(&url).send().await {
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

use crate::cache_ttl::is_within_ttl;

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
/// Targets api.nuget.org, www.nuget.org, and azuresearch-{usnc,ussc}.nuget.org.
fn rewrite_service_index(json_text: &str, base_url: &str) -> String {
    let nora_nuget = format!("{}/nuget", base_url.trim_end_matches('/'));
    let nora_query = format!("{}/v3/query", nora_nuget);
    let nora_autocomplete = format!("{}/v3/autocomplete", nora_nuget);

    // Rewrite major service URLs to route through NORA
    let nora_registration = format!("{}/v3/registration/", nora_nuget);
    json_text
        .replace(
            "https://api.nuget.org/v3-flatcontainer/",
            &format!("{}/v3/flatcontainer/", nora_nuget),
        )
        // Rewrite all registration base URL variants (nuget.org serves 5)
        .replace(
            "https://api.nuget.org/v3/registration5-semver1/",
            &nora_registration,
        )
        .replace(
            "https://api.nuget.org/v3/registration5-gz-semver1/",
            &nora_registration,
        )
        .replace(
            "https://api.nuget.org/v3/registration5-gz-semver2/",
            &nora_registration,
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
        // Rewrite catalog endpoint (air-gap bypass if left as-is)
        .replace(
            "https://api.nuget.org/v3/catalog0/",
            &format!("{}/v3/catalog0/", nora_nuget),
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
        // Rewrite repository signatures URLs (prevents outbound in air-gap)
        .replace(
            "https://api.nuget.org/v3-index/repository-signatures/",
            &format!("{}/v3/repository-signatures/", nora_nuget),
        )
        // Rewrite vulnerability info URL
        .replace(
            "https://api.nuget.org/v3/vulnerabilities/",
            &format!("{}/v3/vulnerabilities/", nora_nuget),
        )
        // Rewrite www.nuget.org URLs (v2 gallery, publish, templates)
        .replace("https://www.nuget.org/", &format!("{}/v3/www/", nora_nuget))
}

/// Rewrite upstream registration URLs in NuGet registration index/page responses.
/// Replaces all registration5-* variants with NORA registration path,
/// and v3-flatcontainer packageContent URLs with NORA flatcontainer path.
fn rewrite_registration_urls(json_text: &str, upstream_url: &str, base_url: &str) -> String {
    let upstream = upstream_url.trim_end_matches('/');
    let nora_nuget = format!("{}/nuget", base_url.trim_end_matches('/'));
    let nora_reg = format!("{}/v3/registration/", nora_nuget);

    json_text
        .replace(
            &format!("{}/v3/registration5-semver1/", upstream),
            &nora_reg,
        )
        .replace(
            &format!("{}/v3/registration5-gz-semver1/", upstream),
            &nora_reg,
        )
        .replace(
            &format!("{}/v3/registration5-gz-semver2/", upstream),
            &nora_reg,
        )
        // Rewrite catalog0 URLs in catalogEntry fields (air-gap bypass)
        .replace(
            &format!("{}/v3/catalog0/", upstream),
            &format!("{}/v3/catalog0/", nora_nuget),
        )
        .replace(
            &format!("{}/v3-flatcontainer/", upstream),
            &format!("{}/v3/flatcontainer/", nora_nuget),
        )
}

/// Validate NuGet version string for use in URL path construction.
/// Allows: digits, dots, hyphens, plus, alphanumeric (SemVer 2.0 compatible).
fn is_valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 256
        && !version.contains('/')
        && !version.contains('\\')
        && !version.contains('\0')
        && !version.contains("..")
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
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
    fn test_rewrite_service_index_all_registration_variants() {
        // nuget.org serves 5 registration base URL variants plus URL templates
        let input = r#"{"resources":[
            {"@id":"https://api.nuget.org/v3/registration5-semver1/","@type":"RegistrationsBaseUrl"},
            {"@id":"https://api.nuget.org/v3/registration5-semver1/","@type":"RegistrationsBaseUrl/3.0.0-rc"},
            {"@id":"https://api.nuget.org/v3/registration5-semver1/","@type":"RegistrationsBaseUrl/3.0.0-beta"},
            {"@id":"https://api.nuget.org/v3/registration5-gz-semver1/","@type":"RegistrationsBaseUrl/3.4.0"},
            {"@id":"https://api.nuget.org/v3/registration5-gz-semver2/","@type":"RegistrationsBaseUrl/3.6.0"},
            {"@id":"https://api.nuget.org/v3/registration5-gz-semver2/","@type":"RegistrationsBaseUrl/Versioned"},
            {"@id":"https://api.nuget.org/v3/registration5-semver1/{id-lower}/index.json","@type":"PackageDisplayMetadataUriTemplate/3.0.0-rc"},
            {"@id":"https://api.nuget.org/v3/registration5-semver1/{id-lower}/{version-lower}.json","@type":"PackageVersionDisplayMetadataUriTemplate/3.0.0-rc"}
        ]}"#;
        let result = rewrite_service_index(input, "https://registry.company.local");
        // All registration URLs should be rewritten
        assert!(
            !result.contains("api.nuget.org"),
            "leaked upstream URL in: {result}"
        );
        // All should point to NORA registration endpoint
        assert!(result.contains("https://registry.company.local/nuget/v3/registration/"));
        // URL templates should also be rewritten (prefix match)
        assert!(
            result.contains("registry.company.local/nuget/v3/registration/{id-lower}/index.json")
        );
        assert!(result.contains(
            "registry.company.local/nuget/v3/registration/{id-lower}/{version-lower}.json"
        ));
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

    #[test]
    fn test_rewrite_registration_urls_all_variants() {
        let input = r#"{"items":[{"@id":"https://api.nuget.org/v3/registration5-gz-semver2/foo/page/1.0.0/2.0.0.json"},{"@id":"https://api.nuget.org/v3/registration5-semver1/foo/index.json"},{"@id":"https://api.nuget.org/v3/registration5-gz-semver1/foo/page/1.0.0/2.0.0.json"}]}"#;
        let result = rewrite_registration_urls(input, "https://api.nuget.org", "http://nora:4000");
        assert!(!result.contains("api.nuget.org"));
        assert!(result.contains("http://nora:4000/nuget/v3/registration/foo/page/1.0.0/2.0.0.json"));
        assert!(result.contains("http://nora:4000/nuget/v3/registration/foo/index.json"));
    }

    #[test]
    fn test_rewrite_registration_urls_rewrites_flatcontainer() {
        let input = r#"{"packageContent":"https://api.nuget.org/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg"}"#;
        let result = rewrite_registration_urls(input, "https://api.nuget.org", "http://nora:4000");
        assert!(!result.contains("api.nuget.org/v3-flatcontainer"));
        assert!(
            result.contains("http://nora:4000/nuget/v3/flatcontainer/foo/1.0.0/foo.1.0.0.nupkg")
        );
    }

    #[test]
    fn test_rewrite_registration_urls_custom_upstream() {
        let input =
            r#"{"@id":"https://private.registry.corp/v3/registration5-gz-semver2/bar/index.json"}"#;
        let result =
            rewrite_registration_urls(input, "https://private.registry.corp", "http://nora:4000");
        assert!(!result.contains("private.registry.corp"));
        assert!(result.contains("http://nora:4000/nuget/v3/registration/bar/index.json"));
    }

    #[test]
    fn test_valid_versions() {
        assert!(is_valid_version("1.0.0"));
        assert!(is_valid_version("1.0.0-alpha"));
        assert!(is_valid_version("1.0.0-beta.1"));
        assert!(is_valid_version("1.0.0+build.123"));
        assert!(is_valid_version("0.0.1-alpha"));
        assert!(is_valid_version("3.1.27"));
    }

    #[test]
    fn test_invalid_versions() {
        assert!(!is_valid_version(""));
        assert!(!is_valid_version("../evil"));
        assert!(!is_valid_version("1.0.0/../../etc/passwd"));
        assert!(!is_valid_version("foo\0bar"));
        assert!(!is_valid_version("1..0"));
        assert!(!is_valid_version("1.0.0\\evil"));
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

        // Populate index for two packages (index.json + .nupkg)
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
            ctx.state
                .storage
                .put(
                    &format!("nuget/flatcontainer/{}/1.0.0/{}.1.0.0.nupkg", id, id),
                    b"fake-nupkg",
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
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
                b"fake-nupkg",
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
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
                b"fake-nupkg",
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
            ctx.state
                .storage
                .put(
                    &format!("nuget/flatcontainer/{}/1.0.0/{}.1.0.0.nupkg", id, id),
                    b"fake-nupkg",
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
        for ver in &["1.0.0", "2.0.0"] {
            ctx.state
                .storage
                .put(
                    &format!("nuget/flatcontainer/testpkg/{}/testpkg.{}.nupkg", ver, ver),
                    b"fake-nupkg",
                )
                .await
                .unwrap();
        }
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

    #[tokio::test]
    async fn test_registration_page_rejects_path_traversal() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
        });

        // Path traversal in version
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/foo/page/1.0.0/../../etc/passwd.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Path traversal in package id — axum normalizes ../ so route doesn't match (404)
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/../evil/page/1.0.0/2.0.0.json",
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_registration_page_unreachable_upstream() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/dotnet-ef/page/0.0.1-alpha/3.1.27.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}

// ── Spec conformance tests (#390) ─────────────────────────────────────
//
// Invariant: after URL rewriting, no upstream domains remain in the response.
// Uses golden fixtures from testdata/nuget/ to validate against realistic
// upstream payloads, not just synthetic test data.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod spec_conformance_tests {
    use super::*;

    /// Known upstream domains that MUST NOT appear in rewritten responses.
    const NUGET_UPSTREAM_DOMAINS: &[&str] = &[
        "api.nuget.org",
        "azuresearch-usnc.nuget.org",
        "azuresearch-ussc.nuget.org",
    ];

    /// Known URL patterns in NuGet responses that are NOT client-fetchable:
    /// (all patterns now rewritten — kept for future use)
    const NUGET_EXCLUDED_PATTERNS: &[&str] = &[];

    /// Assert that no upstream URLs remain in a rewritten response body,
    /// excluding known non-client-fetchable URL patterns.
    /// This is the core air-gap invariant: any leaked URL means the client
    /// tries to reach the internet and fails in air-gapped environments.
    fn assert_no_upstream_urls(body: &str, context: &str) {
        for line in body.lines() {
            if NUGET_EXCLUDED_PATTERNS.iter().any(|p| line.contains(p)) {
                continue;
            }
            for domain in NUGET_UPSTREAM_DOMAINS {
                assert!(
                    !line.contains(domain),
                    "upstream domain '{}' leaked in {} (line: {})",
                    domain,
                    context,
                    line.trim()
                );
            }
        }
    }

    /// Load a golden fixture from testdata/nuget/.
    fn load_fixture(name: &str) -> String {
        let path = format!("{}/testdata/nuget/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to load fixture {}: {}", path, e))
    }

    // ── Service index rewrite: golden fixture ──

    #[test]
    fn test_service_index_golden_no_upstream_leak() {
        let fixture = load_fixture("service-index.json");
        let rewritten = rewrite_service_index(&fixture, "https://registry.airgap.local");
        assert_no_upstream_urls(&rewritten, "service-index rewrite");

        // Verify the rewritten JSON is still valid
        let json: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        assert!(json["resources"].is_array());
        assert!(!json["resources"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_service_index_golden_correct_replacements() {
        let fixture = load_fixture("service-index.json");
        let rewritten = rewrite_service_index(&fixture, "http://nora:4000");
        let json: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        let resources = json["resources"].as_array().unwrap();

        // Every @id must start with nora base — no exceptions (air-gap invariant)
        for res in resources {
            let id = res["@id"].as_str().unwrap();
            let res_type = res["@type"].as_str().unwrap_or("");
            assert!(
                id.starts_with("http://nora:4000/nuget/"),
                "resource @id not rewritten: {} (type: {})",
                id,
                res_type
            );
        }
    }

    #[test]
    fn test_service_index_golden_snapshot() {
        let fixture = load_fixture("service-index.json");
        let rewritten = rewrite_service_index(&fixture, "http://nora:4000");
        let json: serde_json::Value = serde_json::from_str(&rewritten).unwrap();

        // Snapshot only the @id fields (stable against upstream comment changes)
        let ids: Vec<&str> = json["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["@id"].as_str().unwrap())
            .collect();
        insta::assert_json_snapshot!("nuget_service_index_ids", ids);
    }

    #[test]
    fn test_catalog0_url_rewritten() {
        let input =
            r#"{"@id":"https://api.nuget.org/v3/catalog0/index.json","@type":"Catalog/3.0.0"}"#;
        let result = rewrite_service_index(input, "http://nora:4000");
        assert!(
            !result.contains("api.nuget.org"),
            "catalog0 URL must be rewritten, got: {}",
            result
        );
        assert!(result.contains("http://nora:4000/nuget/v3/catalog0/index.json"));
    }

    #[test]
    fn test_search_response_urls_rewritten() {
        let upstream_search = r#"{"totalHits":1,"data":[{"id":"Newtonsoft.Json","version":"13.0.3","registration":"https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json"}]}"#;
        let rewritten = rewrite_service_index(upstream_search, "http://nora:4000");
        assert_no_upstream_urls(&rewritten, "search response rewrite");
        assert!(
            rewritten.contains("http://nora:4000/nuget/v3/registration/newtonsoft.json/index.json")
        );
    }

    #[test]
    fn test_autocomplete_response_no_leak() {
        let upstream =
            r#"{"totalHits":5,"data":["Newtonsoft.Json","NUnit","NLog","Nancy","Noda"]}"#;
        let rewritten = rewrite_service_index(upstream, "http://nora:4000");
        assert_no_upstream_urls(&rewritten, "autocomplete response");
    }

    // ── Registration index rewrite: paginated fixture ──

    #[test]
    fn test_registration_paginated_golden_no_upstream_leak() {
        let fixture = load_fixture("registration-index-paginated.json");
        let rewritten = rewrite_registration_urls(
            &fixture,
            "https://api.nuget.org",
            "https://registry.airgap.local",
        );
        assert_no_upstream_urls(&rewritten, "registration-index-paginated rewrite");

        let json: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        assert_eq!(json["count"].as_u64().unwrap(), 2);

        // All page @id must point to NORA
        for item in json["items"].as_array().unwrap() {
            let id = item["@id"].as_str().unwrap();
            assert!(
                id.starts_with("https://registry.airgap.local/nuget/v3/registration/"),
                "page @id not rewritten: {}",
                id
            );
        }
    }

    #[test]
    fn test_registration_paginated_golden_snapshot() {
        let fixture = load_fixture("registration-index-paginated.json");
        let rewritten =
            rewrite_registration_urls(&fixture, "https://api.nuget.org", "http://nora:4000");
        let json: serde_json::Value = serde_json::from_str(&rewritten).unwrap();

        let page_ids: Vec<&str> = json["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["@id"].as_str().unwrap())
            .collect();
        insta::assert_json_snapshot!("nuget_registration_paginated_page_ids", page_ids);
    }

    // ── Registration index rewrite: inline fixture ──

    #[test]
    fn test_registration_inline_golden_no_upstream_leak() {
        let fixture = load_fixture("registration-index-inline.json");
        let rewritten =
            rewrite_registration_urls(&fixture, "https://api.nuget.org", "http://nora:4000");

        // registration5-gz-semver2 URLs must be rewritten
        assert!(!rewritten.contains("registration5-gz-semver2"));
        assert!(!rewritten.contains("registration5-semver1"));
        assert!(!rewritten.contains("registration5-gz-semver1"));

        let json: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        let page = &json["items"][0];
        let entry = &page["items"][0];

        // entry @id must be rewritten to NORA
        let entry_id = entry["@id"].as_str().unwrap();
        assert!(
            entry_id.starts_with("http://nora:4000/nuget/v3/registration/"),
            "inline entry @id not rewritten: {}",
            entry_id
        );
    }

    // ── Content-Type assertions ──

    #[tokio::test]
    async fn test_service_index_content_type() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        // Pre-populate a cached service index
        let fixture = load_fixture("service-index.json");
        ctx.state
            .storage
            .put("nuget/service-index.json", fixture.as_bytes())
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/nuget/v3/index.json", "").await;
        let content_type = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        assert!(
            content_type.contains("application/json"),
            "NuGet service index must return application/json, got: {}",
            content_type
        );
    }

    #[tokio::test]
    async fn test_cached_registration_content_type() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        let fixture = load_fixture("registration-index-inline.json");
        ctx.state
            .storage
            .put("nuget/registration/xunit/index.json", fixture.as_bytes())
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/xunit/index.json",
            "",
        )
        .await;

        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        assert!(
            content_type.contains("application/json"),
            "NuGet registration index must return application/json, got: {}",
            content_type
        );

        // Verify the rewritten body has no upstream URLs
        let body = body_bytes(resp).await;
        let body_str = String::from_utf8_lossy(&body);
        assert_no_upstream_urls(&body_str, "cached registration index response");
    }

    // ── Cache-Control assertions ──

    #[tokio::test]
    async fn test_nupkg_cache_control_immutable() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
        });

        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/testpkg/1.0.0/testpkg.1.0.0.nupkg",
                b"fake-nupkg",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/testpkg/1.0.0/testpkg.1.0.0.nupkg",
            "",
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let cache_control = resp
            .headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        assert!(
            cache_control.contains("immutable"),
            "nupkg must have immutable cache-control, got: {}",
            cache_control
        );
    }
}
