// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Conan V2 proxy registry (C/C++ packages).
//!
//! Implements a caching proxy for ConanCenter (center2.conan.io):
//!
//! ## Endpoints
//!   GET /conan/v2/ping                             — health + capabilities
//!   GET /conan/v2/conans/search                    — search recipes
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/latest — latest recipe revision
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions — list recipe revisions
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/files — list recipe files
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/files/{filename} — download recipe file (immutable)
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/latest — latest package revision
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/revisions — list package revisions
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/revisions/{prev}/files — list package files
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/revisions/{prev}/files/{filename} — download package file (immutable)
//!
//! ## Client config
//!   conan remote add nora http://nora:4000/conan
//!
//! ## Design
//! - All revision-scoped files are immutably cached (revisions never change)
//! - Metadata endpoints (latest, revisions, search) use TTL-based caching
//! - Uses a single wildcard route + dispatcher pattern (deep URL hierarchy)

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::{circuit_open_response, proxy_fetch, proxy_fetch_text, ProxyError};
use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const UPSTREAM_DEFAULT: &str = "https://center2.conan.io";

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Ping — must come before the wildcard
        .route("/conan/v2/ping", get(ping))
        // Search
        .route("/conan/v2/conans/search", get(search))
        // Recipe file download (deepest, most specific — must be before shorter patterns)
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/revisions/{prev}/files/{filename}",
            get(package_file_download),
        )
        // Package file listing
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/revisions/{prev}/files",
            get(package_file_list),
        )
        // Package revision list
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/revisions",
            get(package_revisions),
        )
        // Package latest revision
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/latest",
            get(package_latest),
        )
        // Recipe file download
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/files/{filename}",
            get(recipe_file_download),
        )
        // Recipe file listing
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/files",
            get(recipe_file_list),
        )
        // Recipe revision list
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions",
            get(recipe_revisions),
        )
        // Recipe latest revision
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/latest",
            get(recipe_latest),
        )
}

// ── Ping ──────────────────────────────────────────────────────────────

async fn ping() -> Response {
    (
        StatusCode::OK,
        [
            ("X-Conan-Server-Capabilities", "revisions"),
            ("Content-Type", "text/plain"),
        ],
        "",
    )
        .into_response()
}

// ── Search ────────────────────────────────────────────────────────────

async fn search(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let query = params.get("q").cloned().unwrap_or_default();
    if query.len() > 256 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let proxy_url = upstream_url(&state);
    // Percent-encode query for upstream
    let encoded_query: String = query
        .bytes()
        .flat_map(|b| {
            if b.is_ascii_alphanumeric()
                || b == b'-'
                || b == b'_'
                || b == b'.'
                || b == b'*'
                || b == b'/'
            {
                vec![b as char]
            } else if b == b' ' {
                vec!['+']
            } else {
                format!("%{:02X}", b).chars().collect()
            }
        })
        .collect();
    let url = format!(
        "{}/v2/conans/search?q={}",
        proxy_url.trim_end_matches('/'),
        encoded_query
    );

    match proxy_fetch_text(
        &state.http_client,
        &url,
        state.config.conan.proxy_timeout,
        state.config.conan.proxy_auth.as_deref(),
        None,
        &state.circuit_breaker,
        "conan",
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("conan");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("search:{}", query),
                "conan",
                "PROXY",
            ));
            with_json(text.into_bytes())
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, "Conan search error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Recipe latest revision (TTL cached) ───────────────────────────────

async fn recipe_latest(
    State(state): State<Arc<AppState>>,
    Path((name, ver, user, chan)): Path<(String, String, String, String)>,
) -> Response {
    if !is_valid_ref(&name) || !is_valid_ref(&ver) || !is_valid_ref(&user) || !is_valid_ref(&chan) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let storage_key = format!("conan/{}/latest.json", ref_str);

    // TTL cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.conan.metadata_ttl) {
                state.metrics.record_download("conan");
                state.metrics.record_cache_hit();
                return with_json(data.to_vec());
            }
        }
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v2/conans/{}/latest",
        proxy_url.trim_end_matches('/'),
        ref_str
    );

    fetch_and_cache_json(&state, &url, &storage_key, &ref_str).await
}

// ── Recipe revisions (TTL cached) ─────────────────────────────────────

async fn recipe_revisions(
    State(state): State<Arc<AppState>>,
    Path((name, ver, user, chan)): Path<(String, String, String, String)>,
) -> Response {
    if !is_valid_ref(&name) || !is_valid_ref(&ver) || !is_valid_ref(&user) || !is_valid_ref(&chan) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let storage_key = format!("conan/{}/revisions.json", ref_str);

    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.conan.metadata_ttl) {
                state.metrics.record_download("conan");
                state.metrics.record_cache_hit();
                return with_json(data.to_vec());
            }
        }
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v2/conans/{}/revisions",
        proxy_url.trim_end_matches('/'),
        ref_str
    );

    fetch_and_cache_json(&state, &url, &storage_key, &ref_str).await
}

// ── Recipe file listing (immutable — scoped to revision) ──────────────

async fn recipe_file_list(
    State(state): State<Arc<AppState>>,
    Path((name, ver, user, chan, rrev)): Path<(String, String, String, String, String)>,
) -> Response {
    if !is_valid_ref(&name)
        || !is_valid_ref(&ver)
        || !is_valid_ref(&user)
        || !is_valid_ref(&chan)
        || !is_valid_revision(&rrev)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let storage_key = format!("conan/{}/revisions/{}/files.json", ref_str, rrev);

    // Immutable: if cached, serve directly
    if let Ok(data) = state.storage.get(&storage_key).await {
        state.metrics.record_download("conan");
        state.metrics.record_cache_hit();
        return with_json(data.to_vec());
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v2/conans/{}/revisions/{}/files",
        proxy_url.trim_end_matches('/'),
        ref_str,
        rrev
    );

    fetch_and_cache_immutable_json(&state, &url, &storage_key, &ref_str).await
}

// ── Recipe file download (immutable) ──────────────────────────────────

async fn recipe_file_download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((name, ver, user, chan, rrev, filename)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    if !is_valid_ref(&name)
        || !is_valid_ref(&ver)
        || !is_valid_ref(&user)
        || !is_valid_ref(&chan)
        || !is_valid_revision(&rrev)
        || !is_valid_filename(&filename)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let artifact = format!("{} rrev={} {}", ref_str, rrev, filename);

    // Extract publish date from cached revision metadata
    let publish_date = extract_conan_publish_date(&state.storage, &name, &ver, &user, &chan).await;

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::Conan,
        &name,
        Some(&ver),
        publish_date,
    ) {
        return response;
    }

    let storage_key = format!("conan/{}/revisions/{}/files/{}", ref_str, rrev, filename);

    // Immutable cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        // Curation integrity
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation,
            crate::curation::RegistryType::Conan,
            &name,
            Some(&ver),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("conan");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            artifact,
            "conan",
            "CACHE",
        ));
        return with_binary(data.to_vec());
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v2/conans/{}/revisions/{}/files/{}",
        proxy_url.trim_end_matches('/'),
        ref_str,
        rrev,
        filename
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        state.config.conan.proxy_timeout,
        state.config.conan.proxy_auth.as_deref(),
        &state.circuit_breaker,
        "conan",
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("conan");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact,
                "conan",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "conan", ""));

            // Immutable cache: put_if_absent
            let storage = state.storage.clone();
            let key = storage_key;
            let data = bytes.clone();
            tokio::spawn(async move {
                if storage.stat(&key).await.is_none() {
                    let _ = storage.put(&key, &data).await;
                }
            });

            state.repo_index.invalidate("conan");
            with_binary(bytes)
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, "Conan recipe file download error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Package latest revision (TTL cached) ──────────────────────────────

async fn package_latest(
    State(state): State<Arc<AppState>>,
    Path((name, ver, user, chan, rrev, pkg_id)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    if !is_valid_ref(&name)
        || !is_valid_ref(&ver)
        || !is_valid_ref(&user)
        || !is_valid_ref(&chan)
        || !is_valid_revision(&rrev)
        || !is_valid_revision(&pkg_id)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let storage_key = format!(
        "conan/{}/revisions/{}/packages/{}/latest.json",
        ref_str, rrev, pkg_id
    );

    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.conan.metadata_ttl) {
                state.metrics.record_download("conan");
                state.metrics.record_cache_hit();
                return with_json(data.to_vec());
            }
        }
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v2/conans/{}/revisions/{}/packages/{}/latest",
        proxy_url.trim_end_matches('/'),
        ref_str,
        rrev,
        pkg_id
    );

    fetch_and_cache_json(&state, &url, &storage_key, &ref_str).await
}

// ── Package revisions (TTL cached) ────────────────────────────────────

async fn package_revisions(
    State(state): State<Arc<AppState>>,
    Path((name, ver, user, chan, rrev, pkg_id)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    if !is_valid_ref(&name)
        || !is_valid_ref(&ver)
        || !is_valid_ref(&user)
        || !is_valid_ref(&chan)
        || !is_valid_revision(&rrev)
        || !is_valid_revision(&pkg_id)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let storage_key = format!(
        "conan/{}/revisions/{}/packages/{}/revisions.json",
        ref_str, rrev, pkg_id
    );

    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.conan.metadata_ttl) {
                state.metrics.record_download("conan");
                state.metrics.record_cache_hit();
                return with_json(data.to_vec());
            }
        }
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v2/conans/{}/revisions/{}/packages/{}/revisions",
        proxy_url.trim_end_matches('/'),
        ref_str,
        rrev,
        pkg_id
    );

    fetch_and_cache_json(&state, &url, &storage_key, &ref_str).await
}

// ── Package file listing (immutable — scoped to PREV) ─────────────────

async fn package_file_list(
    State(state): State<Arc<AppState>>,
    Path((name, ver, user, chan, rrev, pkg_id, prev)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    if !is_valid_ref(&name)
        || !is_valid_ref(&ver)
        || !is_valid_ref(&user)
        || !is_valid_ref(&chan)
        || !is_valid_revision(&rrev)
        || !is_valid_revision(&pkg_id)
        || !is_valid_revision(&prev)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let storage_key = format!(
        "conan/{}/revisions/{}/packages/{}/revisions/{}/files.json",
        ref_str, rrev, pkg_id, prev
    );

    // Immutable
    if let Ok(data) = state.storage.get(&storage_key).await {
        state.metrics.record_download("conan");
        state.metrics.record_cache_hit();
        return with_json(data.to_vec());
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v2/conans/{}/revisions/{}/packages/{}/revisions/{}/files",
        proxy_url.trim_end_matches('/'),
        ref_str,
        rrev,
        pkg_id,
        prev
    );

    fetch_and_cache_immutable_json(&state, &url, &storage_key, &ref_str).await
}

// ── Package file download (immutable) ─────────────────────────────────

async fn package_file_download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((name, ver, user, chan, rrev, pkg_id, prev, filename)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    if !is_valid_ref(&name)
        || !is_valid_ref(&ver)
        || !is_valid_ref(&user)
        || !is_valid_ref(&chan)
        || !is_valid_revision(&rrev)
        || !is_valid_revision(&pkg_id)
        || !is_valid_revision(&prev)
        || !is_valid_filename(&filename)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let artifact = format!("{}#{}:{}#{} {}", ref_str, rrev, pkg_id, prev, filename);

    // Extract publish date from cached revision metadata
    let publish_date = extract_conan_publish_date(&state.storage, &name, &ver, &user, &chan).await;

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::Conan,
        &name,
        Some(&ver),
        publish_date,
    ) {
        return response;
    }

    let storage_key = format!(
        "conan/{}/revisions/{}/packages/{}/revisions/{}/files/{}",
        ref_str, rrev, pkg_id, prev, filename
    );

    // Immutable cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        // Curation integrity
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation,
            crate::curation::RegistryType::Conan,
            &name,
            Some(&ver),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("conan");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            artifact,
            "conan",
            "CACHE",
        ));
        return with_binary(data.to_vec());
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v2/conans/{}/revisions/{}/packages/{}/revisions/{}/files/{}",
        proxy_url.trim_end_matches('/'),
        ref_str,
        rrev,
        pkg_id,
        prev,
        filename
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        state.config.conan.proxy_timeout_download,
        state.config.conan.proxy_auth.as_deref(),
        &state.circuit_breaker,
        "conan",
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("conan");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact,
                "conan",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "conan", ""));

            // Immutable cache
            let storage = state.storage.clone();
            let key = storage_key;
            let data = bytes.clone();
            tokio::spawn(async move {
                if storage.stat(&key).await.is_none() {
                    let _ = storage.put(&key, &data).await;
                }
            });

            state.repo_index.invalidate("conan");
            with_binary(bytes)
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, "Conan package file download error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Shared fetch helpers ──────────────────────────────────────────────

/// Fetch JSON from upstream, cache with TTL (mutable content).
async fn fetch_and_cache_json(
    state: &AppState,
    url: &str,
    storage_key: &str,
    artifact: &str,
) -> Response {
    match proxy_fetch_text(
        &state.http_client,
        url,
        state.config.conan.proxy_timeout,
        state.config.conan.proxy_auth.as_deref(),
        None,
        &state.circuit_breaker,
        "conan",
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("conan");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact.to_string(),
                "conan",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "conan", ""));

            let storage = state.storage.clone();
            let key = storage_key.to_string();
            let data = text.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key, data.as_bytes()).await;
            });

            state.repo_index.invalidate("conan");
            with_json(text.into_bytes())
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(url, error = ?e, "Conan upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Fetch JSON from upstream, cache immutably (content scoped to revision, never changes).
async fn fetch_and_cache_immutable_json(
    state: &AppState,
    url: &str,
    storage_key: &str,
    artifact: &str,
) -> Response {
    match proxy_fetch_text(
        &state.http_client,
        url,
        state.config.conan.proxy_timeout,
        state.config.conan.proxy_auth.as_deref(),
        None,
        &state.circuit_breaker,
        "conan",
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("conan");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact.to_string(),
                "conan",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "conan", ""));

            let storage = state.storage.clone();
            let key = storage_key.to_string();
            let data = text.clone();
            tokio::spawn(async move {
                if storage.stat(&key).await.is_none() {
                    let _ = storage.put(&key, data.as_bytes()).await;
                }
            });

            state.repo_index.invalidate("conan");
            with_json(text.into_bytes())
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(url, error = ?e, "Conan upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Extract publish date from cached Conan recipe revision metadata.
///
/// Conan v2 `latest.json` contains:
/// ```json
/// { "revision": "abc123", "time": "2024-01-15T10:30:00.000+0000" }
/// ```
// TODO(v1.0): trust_upstream_dates config for high-security installs
async fn extract_conan_publish_date(
    storage: &crate::storage::Storage,
    name: &str,
    ver: &str,
    user: &str,
    chan: &str,
) -> Option<i64> {
    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let meta_key = format!("conan/{}/latest.json", ref_str);
    let data = storage.get(&meta_key).await.ok()?;
    let json: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let date_str = json.get("time")?.as_str()?;
    crate::curation::parse_iso8601_to_unix(date_str)
}

fn upstream_url(state: &AppState) -> String {
    state
        .config
        .conan
        .proxy
        .clone()
        .unwrap_or_else(|| UPSTREAM_DEFAULT.to_string())
}

fn is_within_ttl(modified_unix: u64, ttl_secs: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
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

fn with_binary(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
        ],
        data,
    )
        .into_response()
}

/// Validate a Conan reference component (name, version, user, channel).
/// Allows alphanumeric, hyphens, underscores, dots, and `_` (for `_/_` pattern).
fn is_valid_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.contains('/')
        && !s.contains('\0')
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '+')
}

/// Validate a revision hash (SHA-256 hex or short hash).
fn is_valid_revision(rev: &str) -> bool {
    !rev.is_empty()
        && rev.len() <= 128
        && rev
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c.is_ascii_alphanumeric())
}

/// Validate a filename in the Conan file listing.
fn is_valid_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains('/')
        && !name.contains('\0')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '+')
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_refs() {
        assert!(is_valid_ref("zlib"));
        assert!(is_valid_ref("1.2.13"));
        assert!(is_valid_ref("_")); // user/channel can be _
        assert!(is_valid_ref("my-org"));
        assert!(is_valid_ref("boost"));
        assert!(is_valid_ref("1.0.0+build1"));
    }

    #[test]
    fn test_invalid_refs() {
        assert!(!is_valid_ref(""));
        assert!(!is_valid_ref("../evil"));
        assert!(!is_valid_ref("foo/bar"));
        assert!(!is_valid_ref("foo\0bar"));
        assert!(!is_valid_ref("foo bar"));
    }

    #[test]
    fn test_valid_revisions() {
        assert!(is_valid_revision("abc123"));
        assert!(is_valid_revision(
            "e4f7c8d90ab1234567890abcdef1234567890abc"
        ));
        assert!(is_valid_revision("0"));
    }

    #[test]
    fn test_invalid_revisions() {
        assert!(!is_valid_revision(""));
        assert!(!is_valid_revision("abc/def"));
        assert!(!is_valid_revision("abc def"));
    }

    #[test]
    fn test_valid_filenames() {
        assert!(is_valid_filename("conanfile.py"));
        assert!(is_valid_filename("conanmanifest.txt"));
        assert!(is_valid_filename("conan_package.tgz"));
        assert!(is_valid_filename("conan_sources.tgz"));
        assert!(is_valid_filename("conaninfo.txt"));
        assert!(is_valid_filename("conan_export.tgz"));
    }

    #[test]
    fn test_invalid_filenames() {
        assert!(!is_valid_filename(""));
        assert!(!is_valid_filename("../evil.txt"));
        assert!(!is_valid_filename("path/to/file"));
        assert!(!is_valid_filename("file\0name"));
    }

    #[test]
    fn test_ttl_fresh() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(is_within_ttl(now - 10, 3600));
    }

    #[test]
    fn test_ttl_expired() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(!is_within_ttl(now - 7200, 3600));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_conan_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = false;
        });
        let resp = send(&ctx.app, Method::GET, "/conan/v2/ping", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_conan_ping() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
        });
        let resp = send(&ctx.app, Method::GET, "/conan/v2/ping", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("X-Conan-Server-Capabilities")
                .unwrap()
                .to_str()
                .unwrap(),
            "revisions"
        );
    }

    #[tokio::test]
    async fn test_conan_cached_recipe_file() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
        });

        // Pre-populate cache with immutable recipe file
        ctx.state
            .storage
            .put(
                "conan/zlib/1.2.13/_/_/revisions/abc123/files/conanfile.py",
                b"class ZlibConan(ConanFile):\n    pass",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/zlib/1.2.13/_/_/revisions/abc123/files/conanfile.py",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert!(body.starts_with(b"class Zlib"));
    }

    #[tokio::test]
    async fn test_conan_cached_package_file() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
        });

        ctx.state
            .storage
            .put(
                "conan/zlib/1.2.13/_/_/revisions/abc123/packages/deadbeef/revisions/cafe42/files/conan_package.tgz",
                b"fake-tgz-data",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/zlib/1.2.13/_/_/revisions/abc123/packages/deadbeef/revisions/cafe42/files/conan_package.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"fake-tgz-data");
    }

    #[tokio::test]
    async fn test_conan_unreachable_proxy() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
            cfg.conan.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.conan.proxy_timeout = 1;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/zlib/1.2.13/_/_/latest",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_conan_invalid_ref_rejected() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/../evil/_/_/latest",
            "",
        )
        .await;
        assert!(resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_conan_curation_enforce_blocks() {
        use crate::test_helpers::send_with_headers;

        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{"registry": "conan", "name": "evil-lib", "version": "*", "reason": "supply chain attack"}]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.conan.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        ctx.state
            .storage
            .put(
                "conan/evil-lib/1.0/_/_/revisions/abc123/files/conanfile.py",
                b"evil recipe",
            )
            .await
            .unwrap();

        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/evil-lib/1.0/_/_/revisions/abc123/files/conanfile.py",
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
    async fn test_conan_curation_audit_passes() {
        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{"registry": "conan", "name": "evil-lib", "version": "*", "reason": "supply chain attack"}]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.conan.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Audit;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        ctx.state
            .storage
            .put(
                "conan/evil-lib/1.0/_/_/revisions/abc123/files/conanfile.py",
                b"evil recipe",
            )
            .await
            .unwrap();

        // Audit mode: logs but passes through
        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/evil-lib/1.0/_/_/revisions/abc123/files/conanfile.py",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"evil recipe");
    }

    #[tokio::test]
    async fn test_conan_curation_enforce_allows_safe() {
        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{"registry": "conan", "name": "evil-lib", "version": "*", "reason": "supply chain attack"}]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.conan.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        ctx.state
            .storage
            .put(
                "conan/zlib/1.2.13/_/_/revisions/abc123/files/conanfile.py",
                b"safe recipe",
            )
            .await
            .unwrap();

        // zlib is NOT blocked — should pass
        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/zlib/1.2.13/_/_/revisions/abc123/files/conanfile.py",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"safe recipe");
    }

    #[tokio::test]
    async fn test_extract_conan_publish_date_found() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let meta = serde_json::json!({
            "revision": "abc123",
            "time": "2024-03-15T14:30:00.000+0000"
        });
        storage
            .put(
                "conan/zlib/1.3/_/_/latest.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let result = super::extract_conan_publish_date(&storage, "zlib", "1.3", "_", "_").await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_extract_conan_publish_date_no_time_field() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let meta = serde_json::json!({"revision": "abc123"});
        storage
            .put(
                "conan/zlib/1.3/_/_/latest.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let result = super::extract_conan_publish_date(&storage, "zlib", "1.3", "_", "_").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_extract_conan_publish_date_no_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

        let result =
            super::extract_conan_publish_date(&storage, "nonexistent", "1.0", "_", "_").await;
        assert!(result.is_none());
    }
}
