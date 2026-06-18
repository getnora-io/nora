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
use crate::registry::{
    circuit_open_response, proxy_fetch, proxy_fetch_conditional, proxy_fetch_text, read_validators,
    write_validators, ProxyError, Revalidation, Validators,
};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::collections::HashMap;
use std::time::Duration;

const UPSTREAM_DEFAULT: &str = "https://center2.conan.io";

pub fn routes() -> Router<AppState> {
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
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let query = params.get("q").cloned().unwrap_or_default();
    if query.len() > 256 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // #68 namespace isolation: never forward a search term matching an internal
    // namespace upstream (dependency confusion) — return an empty result set.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        &query,
    ) {
        return with_json(br#"{"results":[]}"#.to_vec());
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
        Duration::from_secs(state.config.conan.proxy_timeout),
        expose_opt(&state.config.conan.proxy_auth),
        None,
        &state.circuit_breaker,
        RegistryType::Conan,
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
    State(state): State<AppState>,
    Path((name, ver, user, chan)): Path<(String, String, String, String)>,
) -> Response {
    if !is_valid_ref(&name) || !is_valid_ref(&ver) || !is_valid_ref(&user) || !is_valid_ref(&chan) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let storage_key = format!("conan/{}/latest.json", ref_str);

    // Eager cache read — preserve data for serve-stale fallback
    let cached_data = state.storage.get(&storage_key).await.ok();
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.conan.metadata_ttl) {
                state.metrics.record_download("conan");
                state.metrics.record_cache_hit("conan");
                return with_json(data.to_vec());
            }
        }
    }

    // #68 namespace isolation: an internal-namespace recipe must never be fetched
    // upstream (dependency confusion). Serve any local copy (the fresh path returned
    // above), else block — never proxy.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        &name,
    ) {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("conan");
            state.metrics.record_cache_hit("conan");
            return with_json(data.to_vec());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Conan,
            &name,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v2/conans/{}/latest",
        proxy_url.trim_end_matches('/'),
        ref_str
    );

    fetch_and_cache_json(&state, &url, &storage_key, &ref_str, cached_data).await
}

// ── Recipe revisions (TTL cached) ─────────────────────────────────────

async fn recipe_revisions(
    State(state): State<AppState>,
    Path((name, ver, user, chan)): Path<(String, String, String, String)>,
) -> Response {
    if !is_valid_ref(&name) || !is_valid_ref(&ver) || !is_valid_ref(&user) || !is_valid_ref(&chan) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let storage_key = format!("conan/{}/revisions.json", ref_str);

    let cached_data = state.storage.get(&storage_key).await.ok();
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.conan.metadata_ttl) {
                state.metrics.record_download("conan");
                state.metrics.record_cache_hit("conan");
                return with_json(data.to_vec());
            }
        }
    }

    // #68 namespace isolation: an internal-namespace recipe must never be fetched
    // upstream (dependency confusion). Serve any local copy (the fresh path returned
    // above), else block — never proxy.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        &name,
    ) {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("conan");
            state.metrics.record_cache_hit("conan");
            return with_json(data.to_vec());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Conan,
            &name,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v2/conans/{}/revisions",
        proxy_url.trim_end_matches('/'),
        ref_str
    );

    fetch_and_cache_json(&state, &url, &storage_key, &ref_str, cached_data).await
}

// ── Recipe file listing (immutable — scoped to revision) ──────────────

async fn recipe_file_list(
    State(state): State<AppState>,
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
        state.metrics.record_cache_hit("conan");
        return with_json(data.to_vec());
    }

    // #68 namespace isolation: a cached internal recipe's file list was served above;
    // an internal name with no local copy must not be fetched upstream.
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        &name,
    ) {
        return response;
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
    State(state): State<AppState>,
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
    let publish_date = extract_conan_publish_date(
        &state.storage,
        &name,
        &ver,
        &user,
        &chan,
        state.config.server.trust_upstream_dates,
    )
    .await;

    // Curation check. #733 serve-local: an internal-namespace recipe is operator-owned — skip
    // curation and serve any local copy below; block the upstream branch separately.
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        &name,
    );
    if !internal {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Conan,
            &name,
            Some(&ver),
            publish_date,
        ) {
            return response;
        }
    }

    let storage_key = format!("conan/{}/revisions/{}/files/{}", ref_str, rrev, filename);

    // Immutable cache. get_verified discharges the integrity witness at serve
    // (compile-time guarantee — see crate::verified).
    if let Ok(outcome) = state.storage.get_verified(&storage_key).await {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        // Curation integrity
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Conan,
            &name,
            Some(&ver),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("conan");
        state.metrics.record_cache_hit("conan");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            artifact,
            "conan",
            "CACHE",
        ));
        let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
            state.config.curation.conan.quarantine.as_ref().or(state
                .config
                .curation
                .quarantine
                .as_ref()),
            state
                .config
                .curation
                .conan
                .quarantine_ttl
                .as_deref()
                .or(state.config.curation.quarantine_ttl.as_deref()),
        );
        if let Some(resp) = crate::digest_quarantine::proxy_gate(
            &state.digest_store,
            "conan",
            &data,
            &q_mode,
            q_secs,
            "cache",
        ) {
            return resp;
        }
        return with_binary(data.to_vec());
    }

    // #733: an internal-namespace recipe with no local copy is never proxied upstream.
    if internal {
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Conan,
            &name,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
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
        Duration::from_secs(state.config.conan.proxy_timeout),
        expose_opt(&state.config.conan.proxy_auth),
        &state.circuit_breaker,
        RegistryType::Conan,
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("conan");
            state.metrics.record_cache_miss("conan");
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
            state.spawn_cache_immutable("conan", storage_key, Bytes::from(bytes.clone()));
            let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                state.config.curation.conan.quarantine.as_ref().or(state
                    .config
                    .curation
                    .quarantine
                    .as_ref()),
                state
                    .config
                    .curation
                    .conan
                    .quarantine_ttl
                    .as_deref()
                    .or(state.config.curation.quarantine_ttl.as_deref()),
            );
            if let Some(resp) = crate::digest_quarantine::proxy_gate(
                &state.digest_store,
                "conan",
                &bytes,
                &q_mode,
                q_secs,
                &url,
            ) {
                return resp;
            }
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
    State(state): State<AppState>,
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

    let cached_data = state.storage.get(&storage_key).await.ok();
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.conan.metadata_ttl) {
                state.metrics.record_download("conan");
                state.metrics.record_cache_hit("conan");
                return with_json(data.to_vec());
            }
        }
    }

    // #68 namespace isolation: an internal-namespace package must never be fetched
    // upstream (dependency confusion). Serve any local copy (the fresh path returned
    // above), else block — never proxy.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        &name,
    ) {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("conan");
            state.metrics.record_cache_hit("conan");
            return with_json(data.to_vec());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Conan,
            &name,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v2/conans/{}/revisions/{}/packages/{}/latest",
        proxy_url.trim_end_matches('/'),
        ref_str,
        rrev,
        pkg_id
    );

    fetch_and_cache_json(&state, &url, &storage_key, &ref_str, cached_data).await
}

// ── Package revisions (TTL cached) ────────────────────────────────────

async fn package_revisions(
    State(state): State<AppState>,
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

    let cached_data = state.storage.get(&storage_key).await.ok();
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.conan.metadata_ttl) {
                state.metrics.record_download("conan");
                state.metrics.record_cache_hit("conan");
                return with_json(data.to_vec());
            }
        }
    }

    // #68 namespace isolation: an internal-namespace package must never be fetched
    // upstream (dependency confusion). Serve any local copy (the fresh path returned
    // above), else block — never proxy.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        &name,
    ) {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("conan");
            state.metrics.record_cache_hit("conan");
            return with_json(data.to_vec());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Conan,
            &name,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v2/conans/{}/revisions/{}/packages/{}/revisions",
        proxy_url.trim_end_matches('/'),
        ref_str,
        rrev,
        pkg_id
    );

    fetch_and_cache_json(&state, &url, &storage_key, &ref_str, cached_data).await
}

// ── Package file listing (immutable — scoped to PREV) ─────────────────

async fn package_file_list(
    State(state): State<AppState>,
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
        state.metrics.record_cache_hit("conan");
        return with_json(data.to_vec());
    }

    // #68 namespace isolation: a cached internal package's file list was served above;
    // an internal name with no local copy must not be fetched upstream.
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        &name,
    ) {
        return response;
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
    State(state): State<AppState>,
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
    let publish_date = extract_conan_publish_date(
        &state.storage,
        &name,
        &ver,
        &user,
        &chan,
        state.config.server.trust_upstream_dates,
    )
    .await;

    // Curation check. #733 serve-local: an internal-namespace package is operator-owned — skip
    // curation and serve any local copy below; block the upstream branch separately.
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        &name,
    );
    if !internal {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Conan,
            &name,
            Some(&ver),
            publish_date,
        ) {
            return response;
        }
    }

    let storage_key = format!(
        "conan/{}/revisions/{}/packages/{}/revisions/{}/files/{}",
        ref_str, rrev, pkg_id, prev, filename
    );

    // Immutable cache. get_verified discharges the integrity witness at serve
    // (compile-time guarantee — see crate::verified).
    if let Ok(outcome) = state.storage.get_verified(&storage_key).await {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        // Curation integrity
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Conan,
            &name,
            Some(&ver),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("conan");
        state.metrics.record_cache_hit("conan");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            artifact,
            "conan",
            "CACHE",
        ));
        let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
            state.config.curation.conan.quarantine.as_ref().or(state
                .config
                .curation
                .quarantine
                .as_ref()),
            state
                .config
                .curation
                .conan
                .quarantine_ttl
                .as_deref()
                .or(state.config.curation.quarantine_ttl.as_deref()),
        );
        if let Some(resp) = crate::digest_quarantine::proxy_gate(
            &state.digest_store,
            "conan",
            &data,
            &q_mode,
            q_secs,
            "cache",
        ) {
            return resp;
        }
        return with_binary(data.to_vec());
    }

    // #733: an internal-namespace package with no local copy is never proxied upstream.
    if internal {
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Conan,
            &name,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
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
        Duration::from_secs(state.config.conan.proxy_timeout_dl),
        expose_opt(&state.config.conan.proxy_auth),
        &state.circuit_breaker,
        RegistryType::Conan,
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("conan");
            state.metrics.record_cache_miss("conan");
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
            state.spawn_cache_immutable("conan", storage_key, Bytes::from(bytes.clone()));
            let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                state.config.curation.conan.quarantine.as_ref().or(state
                    .config
                    .curation
                    .quarantine
                    .as_ref()),
                state
                    .config
                    .curation
                    .conan
                    .quarantine_ttl
                    .as_deref()
                    .or(state.config.curation.quarantine_ttl.as_deref()),
            );
            if let Some(resp) = crate::digest_quarantine::proxy_gate(
                &state.digest_store,
                "conan",
                &bytes,
                &q_mode,
                q_secs,
                &url,
            ) {
                return resp;
            }
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
    cached: Option<Bytes>,
) -> Response {
    // Revalidate stale metadata with a conditional request when enabled and fall
    // back to a full fetch otherwise. Empty validators ⇒ no conditional headers ⇒
    // always a 200, which is also how the first fetch captures validators.
    let validators = if state.config.conan.revalidate {
        read_validators(&state.storage, storage_key)
            .await
            .unwrap_or_default()
    } else {
        Validators::default()
    };
    let had_validators = validators.is_some();

    match proxy_fetch_conditional(
        &state.http_client,
        url,
        Duration::from_secs(state.config.conan.proxy_timeout),
        expose_opt(&state.config.conan.proxy_auth),
        &validators,
        &state.circuit_breaker,
        RegistryType::Conan,
    )
    .await
    {
        // Upstream unchanged — serve the cached body and bump its freshness so we
        // do not revalidate again until the next TTL window. No body downloaded.
        Ok(Revalidation::NotModified) => {
            let body = match state.storage.get(storage_key).await {
                Ok(b) => b,
                // Body vanished under us — use the eagerly-read copy, or 502.
                Err(_) => match cached {
                    Some(b) => b,
                    None => return StatusCode::BAD_GATEWAY.into_response(),
                },
            };
            crate::metrics::PROXY_UPSTREAM_304_TOTAL
                .with_label_values(&["conan"])
                .inc();
            crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                .with_label_values(&["conan"])
                .inc_by(body.len() as u64);
            state.metrics.record_download("conan");
            state.metrics.record_cache_hit("conan");
            // Re-put bumps the file mtime (the freshness source) without download.
            let storage = state.storage.clone();
            let key_clone = storage_key.to_string();
            let bump = body.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &bump).await;
            });
            with_json(body.to_vec())
        }
        // New body — cache the raw bytes first, then persist the fresh validators.
        Ok(Revalidation::Modified { body, validators }) => {
            state.metrics.record_download("conan");
            state.metrics.record_cache_miss("conan");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact.to_string(),
                "conan",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "conan", ""));

            let raw = Bytes::from(body);
            let storage = state.storage.clone();
            let key_clone = storage_key.to_string();
            let raw_for_cache = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = storage.put(&key_clone, &raw_for_cache).await {
                    tracing::warn!(key = %key_clone, error = ?e, "conan proxy: failed to cache metadata");
                    return;
                }
                write_validators(&storage, &key_clone, &validators).await;
            });
            with_json(raw.to_vec())
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["conan"])
                    .inc();
            }
            if let Some(ref data) = cached {
                if state.config.conan.serve_stale {
                    tracing::warn!(
                        registry = "conan",
                        artifact,
                        error = ?e,
                        "Conan upstream error, serving stale metadata"
                    );
                    return (
                        StatusCode::OK,
                        [
                            (
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("application/json"),
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
        Duration::from_secs(state.config.conan.proxy_timeout),
        expose_opt(&state.config.conan.proxy_auth),
        None,
        &state.circuit_breaker,
        RegistryType::Conan,
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("conan");
            state.metrics.record_cache_miss("conan");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact.to_string(),
                "conan",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "conan", ""));

            state.spawn_cache_immutable(
                "conan",
                storage_key.to_string(),
                Bytes::from(text.clone()),
            );
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
async fn extract_conan_publish_date(
    storage: &crate::storage::Storage,
    name: &str,
    ver: &str,
    user: &str,
    chan: &str,
    trust_upstream: bool,
) -> Option<i64> {
    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let meta_key = format!("conan/{}/latest.json", ref_str);
    // #513: untrusted upstream dates → NORA cache mtime, never upstream time.
    if !trust_upstream {
        return crate::curation::extract_mtime_as_publish_date(storage, &meta_key).await;
    }
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
    use std::time::{SystemTime, UNIX_EPOCH};

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

        let result =
            super::extract_conan_publish_date(&storage, "zlib", "1.3", "_", "_", true).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_conan_untrusted_dates_use_cache_mtime_not_upstream() {
        // #513: with trust=false, a spoofed-OLD upstream `time` must be ignored
        // and NORA's own cache mtime used instead, so an attacker cannot backdate
        // a freshly-published package past the min-release-age quarantine.
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let meta = serde_json::json!({ "revision": "r1", "time": "2000-01-01T00:00:00.000+0000" });
        storage
            .put(
                "conan/zlib/1.3/_/_/latest.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let trusted =
            super::extract_conan_publish_date(&storage, "zlib", "1.3", "_", "_", true).await;
        let untrusted =
            super::extract_conan_publish_date(&storage, "zlib", "1.3", "_", "_", false).await;

        // trust=true honors the (spoofed, old) upstream date
        assert_eq!(trusted, Some(946_684_800)); // 2000-01-01T00:00:00Z
                                                // trust=false ignores it and uses the recent cache mtime instead
        let untrusted = untrusted.expect("cached file has an mtime");
        assert!(
            untrusted > 946_684_800,
            "trust=false must use recent cache mtime, not the old upstream date (got {untrusted})"
        );
    }

    #[tokio::test]
    async fn test_conan_untrusted_dates_fail_closed_when_uncached() {
        // #513 fail-closed: trust=false with no cached metadata yields None, which
        // curation's min-release-age treats as Block — never a bypass.
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let result =
            super::extract_conan_publish_date(&storage, "uncached", "1.0", "_", "_", false).await;
        assert_eq!(result, None);
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

        let result =
            super::extract_conan_publish_date(&storage, "zlib", "1.3", "_", "_", true).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_extract_conan_publish_date_no_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

        let result =
            super::extract_conan_publish_date(&storage, "nonexistent", "1.0", "_", "_", true).await;
        assert!(result.is_none());
    }

    /// #52 acceptance: a stale recipe-revision read revalidates with
    /// `If-None-Match`; on upstream 304 the cached body is served with no
    /// 200-body download. (ConanCenter sends no validators in production, but this
    /// proves NORA uses them when a fronting CDN / Artifactory does.)
    #[tokio::test]
    async fn test_conan_revalidation_304_serves_cache_no_body_download() {
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
            cfg.conan.enabled = true;
            cfg.conan.proxy = Some(upstream.uri());
            cfg.conan.metadata_ttl = 0; // always stale → always revalidate
            cfg.conan.revalidate = true;
            cfg.conan.serve_stale = false;
        });

        let key = "conan/zlib/1.3/_/_/latest.json";
        ctx.state
            .storage
            .put(key, br#"{"revision":"abc123"}"#)
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
            .with_label_values(&["conan"])
            .get();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/zlib/1.3/_/_/latest",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert!(
            String::from_utf8_lossy(&body).contains("abc123"),
            "must serve the cached recipe revision"
        );

        let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["conan"])
            .get();
        assert!(after > before, "a 304 revalidation must be recorded");
    }
}
