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
use crate::config::UpstreamAuth;
use crate::registry::{
    circuit_open_response, nora_base_url, proxy_fetch, proxy_fetch_conditional, proxy_fetch_text,
    read_validators, write_validators, ProxyError, Revalidation, Validators,
};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
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
use std::time::Duration;

const UPSTREAM_DEFAULT: &str = "https://api.nuget.org";
const SEARCH_TIMEOUT_SECS: u64 = 5;
const DEFAULT_SEARCH: &str = "https://azuresearch-usnc.nuget.org/query";
const DEFAULT_AUTOCOMPLETE: &str = "https://azuresearch-usnc.nuget.org/autocomplete";

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    skip: Option<usize>,
    take: Option<usize>,
    prerelease: Option<bool>,
    #[serde(rename = "semVerLevel")]
    sem_ver_level: Option<String>,
}

/// Storage prefix and file suffix for repo index scanning.
/// Count .nupkg files (not index.json) so size reflects actual packages.
pub const INDEX_PATTERN: (&str, &str) = ("nuget/flatcontainer/", ".nupkg");

/// Discover search and autocomplete endpoints from the upstream NuGet V3 service index.
///
/// When the proxy URL differs from the default (api.nuget.org), the hardcoded
/// Azure Search URLs won't work for private feeds. This function fetches the
/// feed's service index and extracts the correct SearchQueryService and
/// SearchAutocompleteService URLs.
///
/// Only runs if search_service/autocomplete are still at their default values
/// (user overrides via env vars take precedence). Falls back silently on error.
pub async fn discover_search_endpoints(
    client: &reqwest::Client,
    config: &mut crate::config::NugetConfig,
) {
    let proxy_url = match &config.proxy {
        Some(url) => url.clone(),
        None => return, // no proxy configured
    };

    // Only discover if proxy is non-default AND search/autocomplete are at defaults
    let proxy_base = strip_url_path(&proxy_url);
    if proxy_base == UPSTREAM_DEFAULT {
        return; // using default upstream, Azure Search URLs are correct
    }
    let search_is_default = config.search_service == DEFAULT_SEARCH;
    let autocomplete_is_default = config.autocomplete == DEFAULT_AUTOCOMPLETE;
    if !search_is_default && !autocomplete_is_default {
        return; // user has overridden both, respect their config
    }

    // Fetch the upstream service index
    let index_url = format!("{}/v3/index.json", proxy_base);
    tracing::info!(
        url = %index_url,
        "NuGet: discovering search endpoints from upstream service index"
    );

    let resp = match client
        .get(&index_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!(
                status = %r.status(),
                url = %index_url,
                "NuGet: service index discovery failed, keeping defaults"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                url = %index_url,
                "NuGet: service index discovery failed, keeping defaults"
            );
            return;
        }
    };

    let body = match resp.text().await {
        Ok(t) if t.len() > 1_048_576 => {
            tracing::warn!(
                size = t.len(),
                "NuGet: service index too large, skipping discovery"
            );
            return;
        }
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "NuGet: failed to read service index body");
            return;
        }
    };

    let index: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "NuGet: failed to parse service index JSON");
            return;
        }
    };

    let resources = match index.get("resources").and_then(|r| r.as_array()) {
        Some(arr) => arr,
        None => {
            tracing::warn!("NuGet: service index has no 'resources' array");
            return;
        }
    };

    // Find SearchQueryService and SearchAutocompleteService
    for resource in resources {
        let rtype = resource.get("@type").and_then(|t| t.as_str()).unwrap_or("");
        let rid = resource.get("@id").and_then(|id| id.as_str()).unwrap_or("");
        if rid.is_empty() || !(rid.starts_with("https://") || rid.starts_with("http://")) {
            continue;
        }

        if search_is_default && rtype.starts_with("SearchQueryService") {
            tracing::info!(url = %rid, "NuGet: discovered search endpoint");
            config.search_service = rid.to_string();
        }
        if autocomplete_is_default && rtype.starts_with("SearchAutocompleteService") {
            tracing::info!(url = %rid, "NuGet: discovered autocomplete endpoint");
            config.autocomplete = rid.to_string();
        }
    }
}

pub fn routes() -> Router<AppState> {
    routes_with_prefix("nuget")
}

/// Alias routes for Chocolatey and PowerShell Gallery clients.
/// These serve the same NuGet V3 handlers under alternate path prefixes.
/// The service index points back to /nuget/ paths, so clients follow those
/// URLs after initial discovery — storage and caching stay unified.
pub fn alias_routes() -> Router<AppState> {
    routes_with_prefix("chocolatey").merge(routes_with_prefix("pwsh"))
}

fn routes_with_prefix(prefix: &str) -> Router<AppState> {
    Router::new()
        .route(&format!("/{prefix}/v3/index.json"), get(service_index))
        .route(&format!("/{prefix}/v3/query"), get(search_query))
        .route(
            &format!("/{prefix}/v3/autocomplete"),
            get(autocomplete_query),
        )
        .route(
            &format!("/{prefix}/v3/registration/{{id}}/index.json"),
            get(registration_index),
        )
        .route(
            &format!("/{prefix}/v3/registration/{{id}}/page/{{lower}}/{{*upper}}"),
            get(registration_page),
        )
        .route(
            &format!("/{prefix}/v3/flatcontainer/{{*path}}"),
            get(flatcontainer_handler),
        )
        .route(&format!("/{prefix}/v3/{{*path}}"), get(nuget_catchall))
}

// ── Service index ──────────────────────────────────────────────────────

async fn service_index(State(state): State<AppState>) -> Response {
    let base_url = nora_base_url(&state);
    let index = generate_service_index(&base_url);

    state.metrics.record_download("nuget");
    state.activity.push(ActivityEntry::new(
        ActionType::CacheHit,
        "service-index".to_string(),
        crate::registry_type::RegistryType::Nuget,
        "LOCAL",
    ));

    with_json(index.into_bytes())
}

// ── Search query (proxy to upstream SearchQueryService, local fallback) ──

async fn search_query(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Query(params): Query<SearchParams>,
    raw_query: axum::extract::RawQuery,
) -> Response {
    let query = params.q.unwrap_or_default();
    let skip = params.skip.unwrap_or(0);
    let take = params.take.unwrap_or(20);
    let prerelease = params.prerelease.unwrap_or(false);
    let sem_ver_level = params.sem_ver_level;

    // No upstream proxy configured → local search directly
    if upstream_url(&state).is_none() {
        let data = local_search_results(
            &state,
            &query,
            skip,
            take,
            prerelease,
            sem_ver_level.as_deref(),
        )
        .await;
        return with_json(data);
    }

    // #68 namespace isolation: never forward a search term that matches an internal
    // namespace upstream (dependency confusion) — serve local results only.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &query,
    ) {
        let data = local_search_results(
            &state,
            &query,
            skip,
            take,
            prerelease,
            sem_ver_level.as_deref(),
        )
        .await;
        return with_json(data);
    }

    // Try upstream with short timeout (UX-critical path)
    let qs = raw_query.0.unwrap_or_default();
    let url = format!("{}?{}", state.config.nuget.search_service, qs);

    match proxy_fetch_text(
        &state.http_client,
        &url,
        Duration::from_secs(SEARCH_TIMEOUT_SECS),
        None, // search endpoint is public
        None,
        &state.circuit_breaker,
        RegistryType::Nuget,
    )
    .await
    {
        Ok(text) => {
            let base_url = nora_base_url(&state);
            let upstream = rewrite_host(&state);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss("nuget");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("search?{}", qs.chars().take(50).collect::<String>()),
                crate::registry_type::RegistryType::Nuget,
                "PROXY",
            ));
            with_json(rewritten.into_bytes())
        }
        Err(ProxyError::NotFound) => with_json(br#"{"totalHits":0,"data":[]}"#.to_vec()),
        Err(ProxyError::CircuitOpen(_) | ProxyError::Network(_) | ProxyError::Upstream(_)) => {
            if !state.config.nuget.serve_stale {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            tracing::info!("NuGet search: upstream unavailable, using local index");
            let data = local_search_results(
                &state,
                &query,
                skip,
                take,
                prerelease,
                sem_ver_level.as_deref(),
            )
            .await;
            with_json_stale(data)
        }
    }
}

// ── Autocomplete (proxy to upstream SearchAutocompleteService) ─────────

async fn autocomplete_query(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
    raw_query: axum::extract::RawQuery,
) -> Response {
    let query = params.q.unwrap_or_default();
    let skip = params.skip.unwrap_or(0);
    let take = params.take.unwrap_or(20);
    let prerelease = params.prerelease.unwrap_or(false);
    let sem_ver_level = params.sem_ver_level;

    // No upstream proxy configured → local autocomplete from cache
    if upstream_url(&state).is_none() {
        let data = local_autocomplete_results(
            &state,
            &query,
            skip,
            take,
            prerelease,
            sem_ver_level.as_deref(),
        )
        .await;
        return with_json(data);
    }

    // #68 namespace isolation: don't forward an internal-namespace autocomplete term.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &query,
    ) {
        let data = local_autocomplete_results(
            &state,
            &query,
            skip,
            take,
            prerelease,
            sem_ver_level.as_deref(),
        )
        .await;
        return with_json(data);
    }

    let qs = raw_query.0.unwrap_or_default();
    let url = format!("{}?{}", state.config.nuget.autocomplete, qs);

    match proxy_fetch_text(
        &state.http_client,
        &url,
        Duration::from_secs(SEARCH_TIMEOUT_SECS),
        None, // autocomplete endpoint is public
        None,
        &state.circuit_breaker,
        RegistryType::Nuget,
    )
    .await
    {
        Ok(text) => {
            let base_url = nora_base_url(&state);
            let upstream = rewrite_host(&state);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss("nuget");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("autocomplete?{}", qs.chars().take(50).collect::<String>()),
                crate::registry_type::RegistryType::Nuget,
                "PROXY",
            ));
            with_json(rewritten.into_bytes())
        }
        Err(ProxyError::NotFound) => with_json(br#"{"totalHits":0,"data":[]}"#.to_vec()),
        Err(ProxyError::CircuitOpen(_) | ProxyError::Network(_) | ProxyError::Upstream(_)) => {
            if !state.config.nuget.serve_stale {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            tracing::info!("NuGet autocomplete: upstream unavailable, using local index");
            let data = local_autocomplete_results(
                &state,
                &query,
                skip,
                take,
                prerelease,
                sem_ver_level.as_deref(),
            )
            .await;
            with_json_stale(data)
        }
    }
}

// ── Registration index ─────────────────────────────────────────────────

async fn registration_index(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let id_lower = id.to_lowercase();
    if !is_valid_package_id(&id_lower) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Curation check. #733 serve-local: an internal-namespace package is operator-owned — skip
    // curation and serve any local copy below; block the upstream branch separately.
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &id_lower,
    );
    if !internal {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Nuget,
            &id_lower,
            crate::curation::RequestVersion::Unspecified,
            None,
        ) {
            return response;
        }
    }

    let storage_key = format!("nuget/registration/{}/index.json", id_lower);

    // A hosted package's registration is built from its records; the upstream is not asked.
    match hosted_versions(&state.storage, &id_lower).await {
        Hosted::Yes(versions) => return hosted_registration(&state, &id_lower, &versions).await,
        Hosted::Unknown => {
            return crate::registry::storage_unavailable("nuget", &hosted_prefix(&id_lower))
        }
        Hosted::No => {}
    }

    let base_url = nora_base_url(&state);
    let upstream = rewrite_host(&state);

    // Read cache eagerly so stale data is available on upstream failure.
    let (cached_data, read_failure) =
        crate::registry::cached_read(state.storage.get(&storage_key).await);

    // TTL cache — rewrite URLs on read (cache may contain pre-fix entries)
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.nuget.metadata_ttl) {
                state.metrics.record_download("nuget");
                state.metrics.record_cache_hit("nuget");
                let text = String::from_utf8_lossy(data);
                let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
                return with_json_gzip(rewritten.into_bytes());
            }
        }
    }

    // #733: an internal-namespace package — serve any (stale) local registration, else block; never proxy.
    if internal {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            let text = String::from_utf8_lossy(data);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            return with_json_gzip(rewritten.into_bytes());
        }
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("nuget", &storage_key, e);
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Nuget,
            &id_lower,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // No upstream when the operator switched it off: what is stored is all there is.
    if upstream_url(&state).is_none() {
        return match cached_data {
            Some(data) => {
                let text = String::from_utf8_lossy(&data);
                with_json_gzip(rewrite_registration_urls(&text, &upstream, &base_url).into_bytes())
            }
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let url = format!(
        "{}/v3/registration5-gz-semver2/{}/index.json",
        upstream.trim_end_matches('/'),
        id_lower
    );

    // Revalidate stale metadata with a conditional request when enabled (a cheap
    // 304 — nuget.org returns validators) and fall back to a full fetch otherwise.
    let validators = if state.config.nuget.revalidate {
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
        Duration::from_secs(state.config.nuget.metadata_proxy_timeout),
        expose_opt(&state.config.nuget.proxy_auth).map(UpstreamAuth::Basic),
        &validators,
        &state.circuit_breaker,
        RegistryType::Nuget,
    )
    .await
    {
        // Upstream unchanged — serve the cached body (rewritten on read) and bump
        // its freshness so we do not revalidate again until the next TTL window.
        Ok(Revalidation::NotModified) => {
            let body = match state.storage.get(&storage_key).await {
                Ok(b) => b,
                Err(_) => {
                    let rewrite = Some((upstream.as_str(), base_url.as_str()));
                    return serve_stale_or_not_found(
                        &state,
                        cached_data,
                        "registration_index",
                        rewrite,
                    );
                }
            };
            crate::metrics::PROXY_UPSTREAM_304_TOTAL
                .with_label_values(&["nuget"])
                .inc();
            crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                .with_label_values(&["nuget"])
                .inc_by(body.len() as u64);
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            let storage = state.storage.clone();
            let key_clone = storage_key.clone();
            let bump = body.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &bump).await;
            });
            let text = String::from_utf8_lossy(&body);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            with_json_gzip(rewritten.into_bytes())
        }
        // New body — cache the raw bytes first, then persist the fresh validators,
        // and serve the rewritten form.
        Ok(Revalidation::Modified { body, validators }) => {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss("nuget");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                id_lower.clone(),
                crate::registry_type::RegistryType::Nuget,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "nuget", ""));

            let raw = Bytes::from(body);
            let storage = state.storage.clone();
            let key_clone = storage_key.clone();
            let raw_for_cache = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = storage.put(&key_clone, &raw_for_cache).await {
                    tracing::warn!(key = %key_clone, error = ?e, "nuget proxy: failed to cache registration");
                    return;
                }
                write_validators(&storage, &key_clone, &validators).await;
            });
            let text = String::from_utf8_lossy(&raw);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            with_json_gzip(rewritten.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["nuget"])
                    .inc();
            }
            tracing::debug!(error = ?e, "NuGet registration error");
            let rewrite = Some((upstream.as_str(), base_url.as_str()));
            serve_stale_or_not_found(&state, cached_data, "registration_index", rewrite)
        }
    }
}

// ── Registration page (paginated version ranges) ────────────────────────

async fn registration_page(
    State(state): State<AppState>,
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

    // A hosted package's registration lists every version inline: it has no pages, and the
    // upstream is not asked for one.
    match hosted_versions(&state.storage, &id_lower).await {
        Hosted::Yes(_) => return StatusCode::NOT_FOUND.into_response(),
        Hosted::Unknown => {
            return crate::registry::storage_unavailable("nuget", &hosted_prefix(&id_lower))
        }
        Hosted::No => {}
    }

    let base_url = nora_base_url(&state);
    let upstream = rewrite_host(&state);
    let storage_key = format!(
        "nuget/registration/{}/page/{}/{}.json",
        id_lower, lower, upper
    );

    // Read cache eagerly so stale data is available on upstream failure.
    let (cached_data, read_failure) =
        crate::registry::cached_read(state.storage.get(&storage_key).await);

    // TTL cache
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.nuget.metadata_ttl) {
                state.metrics.record_download("nuget");
                state.metrics.record_cache_hit("nuget");
                let text = String::from_utf8_lossy(data);
                let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
                return with_json_gzip(rewritten.into_bytes());
            }
        }
    }

    // #68 namespace isolation: an internal-namespace package's registration must
    // never be fetched upstream (dependency confusion). Serve any local copy
    // (hosted/cached; the fresh path returned above), else block — never proxy.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &id_lower,
    ) {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            let text = String::from_utf8_lossy(data);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            return with_json_gzip(rewritten.into_bytes());
        }
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("nuget", &storage_key, e);
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Nuget,
            &id_lower,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // No upstream when the operator switched it off: what is stored is all there is.
    if upstream_url(&state).is_none() {
        return match cached_data {
            Some(data) => {
                let text = String::from_utf8_lossy(&data);
                with_json_gzip(rewrite_registration_urls(&text, &upstream, &base_url).into_bytes())
            }
            None => StatusCode::NOT_FOUND.into_response(),
        };
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
        Duration::from_secs(state.config.nuget.metadata_proxy_timeout),
        expose_opt(&state.config.nuget.proxy_auth).map(UpstreamAuth::Basic),
        None,
        &state.circuit_breaker,
        RegistryType::Nuget,
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss("nuget");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/page/{}/{}", id_lower, lower, upper),
                crate::registry_type::RegistryType::Nuget,
                "PROXY",
            ));

            state.spawn_cache("nuget", storage_key, Bytes::from(text.clone()));
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            with_json_gzip(rewritten.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "NuGet registration page error");
            let rewrite = Some((upstream.as_str(), base_url.as_str()));
            serve_stale_or_not_found(&state, cached_data, "registration_page", rewrite)
        }
    }
}

// ── Flat container dispatcher ───────────────────────────────────────────

async fn flatcontainer_handler(
    State(state): State<AppState>,
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

async fn version_list(state: AppState, id: &str) -> Response {
    let id = id.to_string();
    let id_lower = id.to_lowercase();
    if !is_valid_package_id(&id_lower) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!("nuget/flatcontainer/{}/index.json", id_lower);

    // A hosted package's versions are its records — before any list an upstream gave for the id.
    match hosted_versions(&state.storage, &id_lower).await {
        Hosted::Yes(versions) => {
            state.metrics.record_download("nuget");
            return with_json(
                serde_json::json!({ "versions": versions })
                    .to_string()
                    .into_bytes(),
            );
        }
        Hosted::Unknown => {
            return crate::registry::storage_unavailable("nuget", &hosted_prefix(&id_lower))
        }
        Hosted::No => {}
    }

    // Read cache eagerly so stale data is available on upstream failure.
    let (cached_data, read_failure) =
        crate::registry::cached_read(state.storage.get(&storage_key).await);

    // TTL cache
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.nuget.metadata_ttl) {
                state.metrics.record_download("nuget");
                state.metrics.record_cache_hit("nuget");
                return with_json(data.to_vec());
            }
        }
    }

    // #68 namespace isolation: serve any local version list for an internal package,
    // else block — never fetch upstream (dependency confusion).
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &id_lower,
    ) {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            return with_json(data.to_vec());
        }
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("nuget", &storage_key, e);
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Nuget,
            &id_lower,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // No upstream when the operator switched it off: what is stored is all there is.
    let Some(proxy_url) = upstream_url(&state) else {
        return match cached_data {
            Some(data) => with_json(data.to_vec()),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    };
    let url = format!(
        "{}/v3-flatcontainer/{}/index.json",
        proxy_url.trim_end_matches('/'),
        id_lower
    );

    // Revalidate stale metadata with a conditional request when enabled (a cheap
    // 304 — nuget.org returns validators) and fall back to a full fetch otherwise.
    // Empty validators ⇒ no conditional headers ⇒ always a 200, which is also how
    // the first fetch captures validators for next time.
    let validators = if state.config.nuget.revalidate {
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
        Duration::from_secs(state.config.nuget.metadata_proxy_timeout),
        expose_opt(&state.config.nuget.proxy_auth).map(UpstreamAuth::Basic),
        &validators,
        &state.circuit_breaker,
        RegistryType::Nuget,
    )
    .await
    {
        // Upstream unchanged — serve the cached body and bump its freshness so we
        // do not revalidate again until the next TTL window. No body downloaded.
        Ok(Revalidation::NotModified) => {
            let body = match state.storage.get(&storage_key).await {
                Ok(b) => b,
                Err(_) => {
                    return serve_stale_or_not_found(&state, cached_data, "version_list", None)
                }
            };
            crate::metrics::PROXY_UPSTREAM_304_TOTAL
                .with_label_values(&["nuget"])
                .inc();
            crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                .with_label_values(&["nuget"])
                .inc_by(body.len() as u64);
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            let storage = state.storage.clone();
            let key_clone = storage_key.clone();
            let bump = body.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &bump).await;
            });
            with_json(body.to_vec())
        }
        // New body — cache the raw bytes first, then persist the fresh validators.
        Ok(Revalidation::Modified { body, validators }) => {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss("nuget");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/versions", id_lower),
                crate::registry_type::RegistryType::Nuget,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "nuget", ""));

            let raw = Bytes::from(body);
            let storage = state.storage.clone();
            let key_clone = storage_key.clone();
            let raw_for_cache = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = storage.put(&key_clone, &raw_for_cache).await {
                    tracing::warn!(key = %key_clone, error = ?e, "nuget proxy: failed to cache version list");
                    return;
                }
                write_validators(&storage, &key_clone, &validators).await;
            });
            with_json(raw.to_vec())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["nuget"])
                    .inc();
            }
            tracing::debug!(error = ?e, "NuGet version list error");
            serve_stale_or_not_found(&state, cached_data, "version_list", None)
        }
    }
}

// ── Flatcontainer download (nupkg/nuspec, immutable) ───────────────────
// LOCK-SAFE: cache-through proxy — get miss → fetch upstream → put; no RMW race
async fn flatcontainer_download(
    state: AppState,
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

    // #733 serve-local: an internal-namespace package is operator-owned — skip curation and serve
    // any local copy below; block the upstream branch separately. Its .nuspec is held the same:
    // asking an upstream for it would hand over the internal name.
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &id_lower,
    );

    let storage_key = format!("nuget/flatcontainer/{}", path.to_lowercase());

    // A hosted package serves the versions it has records of and nothing else: a version without
    // one is no version of it, whatever an upstream served under the id before it was imported.
    let hosted = match hosted_versions(&state.storage, &id_lower).await {
        Hosted::Yes(versions) => {
            if !versions.contains(&ver.to_lowercase()) {
                return StatusCode::NOT_FOUND.into_response();
            }
            true
        }
        Hosted::No => false,
        Hosted::Unknown => {
            return crate::registry::storage_unavailable("nuget", &hosted_prefix(&id_lower))
        }
    };

    // Hoisted to function scope for the digest-quarantine serve gate (#750).
    let mut publish_date: Option<i64> = None;
    // Curation check for .nupkg downloads
    if ends_with_ci(filename, ".nupkg") && !internal {
        // #754: the upstream is asked for a date only on a cache miss — a stored package's
        // digest is already recorded, and a cache hit pays no upstream round-trip. A hosted
        // package has no upstream date, and no cached registration of an upstream dates it.
        if !hosted {
            let ask_upstream = state.config.server.trust_upstream_dates
                && crate::registry::release_date_read(&state, RegistryType::Nuget)
                && state.storage.stat(&storage_key).await.is_none();
            publish_date = nuget_publish_date(&state, &id_lower, ver, ask_upstream).await;
        }

        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Nuget,
            &id_lower,
            crate::curation::RequestVersion::Known(ver.to_string()),
            publish_date,
        ) {
            return response;
        }
    }

    // The quarantine takes a release date only when upstream dates are trusted (#750). Without
    // trust the date above is a cached registration's age — when NORA last wrote a listing, not
    // when it first fetched these bytes — so the quarantine keeps its own clock.
    let first_seen = crate::digest_quarantine::first_seen_seed(
        state.config.server.trust_upstream_dates,
        publish_date,
    );
    let content_type = if ends_with_ci(filename, ".nuspec") {
        "application/xml"
    } else {
        "application/octet-stream"
    };

    // Immutable cache. get_verified discharges the integrity witness at serve
    // (compile-time guarantee — see crate::verified).
    let (cached, read_failure) =
        crate::registry::cached_read(state.storage.get_verified(&storage_key).await);
    if let Some(outcome) = cached {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
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
        state.metrics.record_cache_hit("nuget");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            format!("{}/{}", id_lower, filename),
            crate::registry_type::RegistryType::Nuget,
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

        let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
            state.config.curation.nuget.quarantine.as_ref().or(state
                .config
                .curation
                .quarantine
                .as_ref()),
            state
                .config
                .curation
                .nuget
                .quarantine_ttl
                .as_deref()
                .or(state.config.curation.quarantine_ttl.as_deref()),
        );
        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "nuget",
            &data,
            &q_mode,
            q_secs,
            "cache",
            first_seen,
        ) {
            return resp;
        }

        // Resume support: 206 for a `Range` request, 416 when the client asks past the
        // end. Only the .nupkg package — the .nuspec manifest is a metadata read. It
        // sits after the gates above because the quarantine digest check needs the whole
        // object. A partial body cannot be rehashed, so the serve relies on the package
        // hash the client verifies itself (docker did the same in #657). An
        // absent/malformed range falls through to the full 200.
        if ends_with_ci(filename, ".nupkg") {
            if let Some(response) = crate::registry::range::range_response(
                &state.storage,
                &[&storage_key],
                &headers,
                data.len() as u64,
                content_type,
                &[(
                    header::CACHE_CONTROL,
                    "public, max-age=31536000, immutable".to_string(),
                )],
            )
            .await
            {
                return response;
            }
        }
        let mut response = (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            data.to_vec(),
        )
            .into_response();
        if ends_with_ci(filename, ".nupkg") {
            response
                .headers_mut()
                .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        }
        return response;
    }

    // A hosted version NORA cannot read is unavailable, not absent; one it does not hold is not
    // asked of an upstream.
    if hosted {
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("nuget", &storage_key, e);
        }
        return StatusCode::NOT_FOUND.into_response();
    }

    // #733: an internal-namespace .nupkg or .nuspec with no local copy is never proxied upstream.
    if internal {
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("nuget", &storage_key, e);
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Nuget,
            &id_lower,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // Fetch from upstream — none when the operator switched it off.
    let Some(proxy_url) = upstream_url(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
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
        Duration::from_secs(state.config.nuget.proxy_timeout),
        expose_opt(&state.config.nuget.proxy_auth).map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        RegistryType::Nuget,
    )
    .await
    {
        Ok(bytes) => {
            // The allowlist's pinned integrity holds on the first download too, before anything is cached:
            // the cache-hit branch checks the same rule.
            if ends_with_ci(filename, ".nupkg") {
                if let Some(response) = crate::curation::verify_integrity(
                    &state.curation().curation_engine,
                    crate::curation::RegistryType::Nuget,
                    &id_lower,
                    Some(ver),
                    &bytes,
                ) {
                    return response;
                }
            }
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss("nuget");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/{}", id_lower, filename),
                crate::registry_type::RegistryType::Nuget,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "nuget", ""));

            state.spawn_cache_immutable("nuget", storage_key, Bytes::from(bytes.clone()));

            // Best-effort: fetch flatcontainer index.json if missing (for local search)
            if ends_with_ci(filename, ".nupkg") {
                let index_key = format!("nuget/flatcontainer/{}/index.json", id_lower);
                let state2 = state.clone();
                let proxy_url2 = proxy_url.clone();
                let id2 = id_lower.clone();
                tokio::spawn(async move {
                    if state2.storage.stat(&index_key).await.is_none() {
                        let url = format!(
                            "{}/v3-flatcontainer/{}/index.json",
                            proxy_url2.trim_end_matches('/'),
                            id2
                        );
                        if let Ok(text) = proxy_fetch_text(
                            &state2.http_client,
                            &url,
                            Duration::from_secs(state2.config.nuget.proxy_timeout),
                            expose_opt(&state2.config.nuget.proxy_auth).map(UpstreamAuth::Basic),
                            None,
                            &state2.circuit_breaker,
                            RegistryType::Nuget,
                        )
                        .await
                        {
                            let _ = state2.storage.put(&index_key, text.as_bytes()).await;
                            state2.repo_index.invalidate("nuget");
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
            let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                state.config.curation.nuget.quarantine.as_ref().or(state
                    .config
                    .curation
                    .quarantine
                    .as_ref()),
                state
                    .config
                    .curation
                    .nuget
                    .quarantine_ttl
                    .as_deref()
                    .or(state.config.curation.quarantine_ttl.as_deref()),
            );
            if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                &state.digest_store,
                "nuget",
                &bytes,
                &q_mode,
                q_secs,
                &url,
                first_seen,
            ) {
                return resp;
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
            // Binary was not cached and upstream is unreachable — package not available here.
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

// ── Stale-while-error helper ──────────────────────────────────────────

/// Serve stale cached metadata when upstream is unreachable, or 404 if no cache.
///
/// If `rewrite_ctx` is `Some((upstream, base_url))`, registration URL rewriting
/// is applied to the stale response (for registration endpoints).
fn serve_stale_or_not_found(
    state: &AppState,
    cached: Option<Bytes>,
    label: &str,
    rewrite_ctx: Option<(&str, &str)>,
) -> Response {
    if let Some(data) = cached {
        if state.config.nuget.serve_stale {
            tracing::warn!(
                registry = "nuget",
                endpoint = label,
                "Upstream unreachable, serving stale cached metadata"
            );
            let body = if let Some((upstream, base_url)) = rewrite_ctx {
                let text = String::from_utf8_lossy(&data);
                rewrite_registration_urls(&text, upstream, base_url).into_bytes()
            } else {
                data.to_vec()
            };
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
                        axum::http::header::HeaderValue::from_static("true"),
                    ),
                ],
                body,
            )
                .into_response();
        }
    }
    // No cached data or serve_stale disabled — package not available here.
    StatusCode::NOT_FOUND.into_response()
}

// ── Helpers ────────────────────────────────────────────────────────────

/// NuGet's `published` for an unlisted version, 1900-01-01T00:00:00Z: the date is not known.
const UNLISTED_PUBLISHED: i64 = -2_208_988_800;

/// What a registration document — the index or one of its pages — says of a version.
#[derive(Debug, PartialEq)]
enum Registered {
    /// Listed; its `published` as Unix time, `None` when absent, unparsable or unlisted.
    Listed(Option<i64>),
    /// In the range of a page the index names without inlining it.
    OnPage { lower: String, upper: String },
    /// Not in the document.
    Absent,
}

/// Find `version` in a registration index or page:
/// ```json
/// { "items": [{ "lower": "1.0.0", "upper": "2.0.0", "items": [{ "catalogEntry": { "version": "1.0.0", "published": "2024-01-15T10:30:00Z" } }] }] }
/// ```
/// An index past 128 versions names its pages by bounds only (#535); a page lists its leaves
/// directly under `items`.
fn registered(doc: &[u8], version: &str) -> Registered {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(doc) else {
        return Registered::Absent;
    };
    let Some(items) = json.get("items").and_then(|i| i.as_array()) else {
        return Registered::Absent;
    };
    let leaves = |items: &[serde_json::Value]| {
        items.iter().find_map(|item| {
            let entry = item.get("catalogEntry")?;
            let listed = entry.get("version")?.as_str()?;
            nuget_version_order(listed, version)
                .map_or_else(|| listed.eq_ignore_ascii_case(version), |o| o.is_eq())
                .then(|| {
                    entry
                        .get("published")
                        .and_then(|d| d.as_str())
                        .and_then(crate::curation::parse_iso8601_to_unix)
                        .filter(|&published| published > UNLISTED_PUBLISHED)
                })
        })
    };
    if items.iter().any(|item| item.get("catalogEntry").is_some()) {
        return leaves(items).map_or(Registered::Absent, Registered::Listed);
    }
    for page in items {
        if let Some(inline) = page.get("items").and_then(|i| i.as_array()) {
            if let Some(published) = leaves(inline) {
                return Registered::Listed(published);
            }
            continue;
        }
        let bound = |name: &str| page.get(name).and_then(|b| b.as_str());
        let (Some(lower), Some(upper)) = (bound("lower"), bound("upper")) else {
            continue;
        };
        let above = nuget_version_order(version, lower).is_some_and(|o| o.is_ge());
        let below = nuget_version_order(version, upper).is_some_and(|o| o.is_le());
        if above && below {
            return Registered::OnPage {
                lower: lower.to_lowercase(),
                upper: upper.to_lowercase(),
            };
        }
    }
    Registered::Absent
}

/// When `version` of `id` was published: its release age, and with trusted dates the quarantine's
/// first-seen too.
///
/// Without trusted upstream dates (#513) a version is as old as the cached registration that
/// lists it — NORA held it listed since that document was written — and undated when no cached
/// one lists it: a version published after the index was cached was not seen by NORA then.
///
/// With trusted dates a version is as old as its `published`. One the cached registration does
/// not date is looked up upstream when `ask_upstream`: a `dotnet restore` reads only the flat
/// container, so nothing else brings its registration in. The unlisted marker dates nothing.
async fn nuget_publish_date(
    state: &AppState,
    id: &str,
    version: &str,
    ask_upstream: bool,
) -> Option<i64> {
    let trust = state.config.server.trust_upstream_dates;
    let storage = &state.storage;
    let dated = |key: String, published: Option<i64>| async move {
        match trust {
            true => published,
            false => storage.stat(&key).await.map(|m| m.modified as i64),
        }
    };
    let index_key = format!("nuget/registration/{}/index.json", id);
    let mut page = None;
    if let Ok(doc) = storage.get(&index_key).await {
        match registered(&doc, version) {
            Registered::Listed(published) => return dated(index_key, published).await,
            Registered::OnPage { lower, upper } => page = Some((lower, upper)),
            Registered::Absent => {}
        }
    }
    if let Some((lower, upper)) = &page {
        let page_key = format!("nuget/registration/{}/page/{}/{}.json", id, lower, upper);
        if let Ok(doc) = storage.get(&page_key).await {
            if let Registered::Listed(published) = registered(&doc, version) {
                return dated(page_key, published).await;
            }
        }
    }
    if !trust || !ask_upstream {
        return None;
    }
    // The page the cached index named first; when that one does not list the version, the
    // upstream index — its pages may have moved since — and the page it names.
    if let Some((lower, upper)) = &page {
        if let Some(published) = upstream_page_date(state, id, lower, upper, version).await {
            return published;
        }
    }
    let doc = nuget_registration_fetch(state, id, RegistrationDoc::Index).await?;
    match registered(&doc, version) {
        Registered::Listed(published) => published,
        Registered::OnPage { lower, upper } => {
            upstream_page_date(state, id, &lower, &upper, version)
                .await
                .flatten()
        }
        Registered::Absent => None,
    }
}

/// `version`'s date on the upstream registration page `lower`..`upper`: `None` when the page
/// does not list it or could not be read, `Some(None)` when it lists it undated.
async fn upstream_page_date(
    state: &AppState,
    id: &str,
    lower: &str,
    upper: &str,
    version: &str,
) -> Option<Option<i64>> {
    let doc = nuget_registration_fetch(state, id, RegistrationDoc::Page { lower, upper }).await?;
    match registered(&doc, version) {
        Registered::Listed(published) => Some(published),
        _ => None,
    }
}

/// A registration document of a package NORA reads a date from: the index, or the page with
/// these bounds. A document is named by what it is, never by a URL — not one a response gave.
#[derive(Debug, Clone, Copy)]
enum RegistrationDoc<'a> {
    Index,
    Page { lower: &'a str, upper: &'a str },
}

/// Where `doc` of `id` is on `upstream`: the registration path of the configured upstream,
/// with a package id and versions as its only segments. `None` for anything else, so no
/// segment can lead the request off that path or that host.
fn registration_url(upstream: &str, id: &str, doc: RegistrationDoc) -> Option<String> {
    if !is_valid_package_id(id) {
        return None;
    }
    let base = format!(
        "{}/v3/registration5-gz-semver2/{}",
        upstream.trim_end_matches('/'),
        id
    );
    match doc {
        RegistrationDoc::Index => Some(format!("{base}/index.json")),
        RegistrationDoc::Page { lower, upper } => (is_valid_version(lower)
            && is_valid_version(upper))
        .then(|| format!("{base}/page/{lower}/{upper}.json")),
    }
}

/// `doc` of `id` from the configured upstream, read for a date only: it is not cached, so the
/// registration endpoints' TTL and validators stay theirs. Nothing is asked when the upstream
/// is switched off.
async fn nuget_registration_fetch(
    state: &AppState,
    id: &str,
    doc: RegistrationDoc<'_>,
) -> Option<Vec<u8>> {
    let url = registration_url(&upstream_url(state)?, id, doc)?;
    proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.nuget.metadata_proxy_timeout),
        expose_opt(&state.config.nuget.proxy_auth).map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        RegistryType::Nuget,
    )
    .await
    .map_err(|e| tracing::debug!(url = %url, error = ?e, "nuget: registration for a date not read"))
    .ok()
}

/// How NuGet orders two versions (`VersionComparer.Default`): by their numbers, then a
/// pre-release before its release, pre-release labels one by one — numbers by value and before
/// words, words without case — and a shorter run of equal labels first. Build metadata does not
/// count. `None` when either is not a NuGet version.
fn nuget_version_order(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    fn parts(version: &str) -> Option<(Vec<u64>, Option<String>)> {
        let key = crate::curation::nuget_version_key(version)?;
        let (release, pre) = match key.split_once('-') {
            Some((release, pre)) => (release.to_string(), Some(pre.to_string())),
            None => (key, None),
        };
        let mut numbers = release
            .split('.')
            .map(|n| n.parse().ok())
            .collect::<Option<Vec<u64>>>()?;
        numbers.resize(4, 0);
        Some((numbers, pre))
    }
    fn label(a: &str, b: &str) -> Ordering {
        let number = |s: &str| s.bytes().all(|c| c.is_ascii_digit());
        match (number(a), number(b)) {
            (true, true) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => a.cmp(b),
        }
    }
    let ((a_numbers, a_pre), (b_numbers, b_pre)) = (parts(a)?, parts(b)?);
    Some(
        a_numbers
            .cmp(&b_numbers)
            .then_with(|| match (a_pre, b_pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => {
                    let (mut a, mut b) = (a.split('.'), b.split('.'));
                    loop {
                        match (a.next(), b.next()) {
                            (None, None) => break Ordering::Equal,
                            (None, Some(_)) => break Ordering::Less,
                            (Some(_), None) => break Ordering::Greater,
                            (Some(x), Some(y)) => match label(x, y) {
                                Ordering::Equal => continue,
                                other => break other,
                            },
                        }
                    }
                }
            }),
    )
}

/// The configured upstream (`scheme://authority`), or None when the operator switched it off with
/// an empty NORA_NUGET_PROXY: then nothing is asked of any upstream.
fn upstream_url(state: &AppState) -> Option<String> {
    crate::config::configured_upstream(&state.config.nuget.proxy).map(strip_url_path)
}

/// The host stored registration bodies are rewritten from: the configured upstream, else the
/// default one a cached body may still name.
fn rewrite_host(state: &AppState) -> String {
    upstream_url(state).unwrap_or_else(|| UPSTREAM_DEFAULT.to_string())
}

/// Keep only `scheme://authority` from a URL, stripping path/query/fragment.
///
/// Callers append their own paths (e.g. `/v3-flatcontainer/`, `/v3/registration5-gz-semver2/`),
/// so the path component (e.g. `/v3/index.json`) must be stripped.
fn strip_url_path(url: &str) -> String {
    if let Some(idx) = url.find("://") {
        let after_scheme = &url[idx + 3..];
        let authority_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        url[..idx + 3 + authority_end].to_string()
    } else {
        url.to_string()
    }
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

/// Build a gzip-compressed JSON response for registration endpoints.
///
/// The service index advertises `RegistrationsBaseUrl/3.6.0`, which per NuGet spec
/// means responses are gzip-encoded.  Falls back to plain JSON if compression fails.
fn with_json_gzip(data: Vec<u8>) -> Response {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    match std::io::Write::write_all(&mut encoder, &data).and_then(|_| encoder.finish()) {
        Ok(compressed) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                ),
                (header::CONTENT_ENCODING, HeaderValue::from_static("gzip")),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=60, must-revalidate"),
                ),
            ],
            compressed,
        )
            .into_response(),
        Err(_) => with_json(data), // fallback: plain JSON if gzip fails
    }
}

/// JSON response with `X-Nora-Stale: true` header indicating degraded/fallback data.
fn with_json_stale(data: Vec<u8>) -> Response {
    (
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
///
/// When `prerelease` is false, versions containing a hyphen (SemVer pre-release)
/// are excluded. When `sem_ver_level` is not `"2.0.0"`, SemVer 2.0 versions
/// (dot-separated pre-release or build metadata) are hidden.
/// Packages with zero remaining versions are omitted entirely.
async fn local_search_results(
    state: &AppState,
    query: &str,
    skip: usize,
    take: usize,
    prerelease: bool,
    sem_ver_level: Option<&str>,
) -> Vec<u8> {
    let packages = state.repo_index.get("nuget", &state.storage).await;
    let base_url = nora_base_url(state);

    let query_lower = query.to_lowercase();
    let filtered: Vec<&crate::repo_index::RepoInfo> = packages
        .iter()
        .filter(|pkg| query_lower.is_empty() || pkg.name.to_lowercase().contains(&query_lower))
        .collect();

    let mut data = Vec::new();
    for pkg in &filtered {
        let all_versions = get_cached_versions(&state.storage, &pkg.name).await;
        let versions: Vec<String> = if prerelease {
            all_versions
        } else {
            all_versions
                .into_iter()
                .filter(|v| !v.contains('-'))
                .collect()
        };
        // Hide SemVer 2.0 versions unless semVerLevel=2.0.0
        let versions: Vec<String> = if sem_ver_level == Some("2.0.0") {
            versions
        } else {
            versions
                .into_iter()
                .filter(|v| !is_semver2_version(v))
                .collect()
        };
        if versions.is_empty() {
            continue;
        }
        data.push(build_search_entry(&base_url, pkg, &versions));
    }

    let total_hits = data.len();
    let page: Vec<serde_json::Value> = data.into_iter().skip(skip).take(take).collect();

    let result = serde_json::json!({
        "totalHits": total_hits,
        "data": page,
    });
    serde_json::to_vec(&result).unwrap_or_else(|_| br#"{"totalHits":0,"data":[]}"#.to_vec())
}

/// Build local autocomplete results from the in-memory repo index.
/// Returns package name strings (not full search objects) per NuGet autocomplete spec.
///
/// When `prerelease` is false, packages that have only pre-release versions are omitted.
/// When `sem_ver_level` is not `"2.0.0"`, packages with only SemVer 2.0 versions are hidden.
async fn local_autocomplete_results(
    state: &AppState,
    query: &str,
    skip: usize,
    take: usize,
    prerelease: bool,
    sem_ver_level: Option<&str>,
) -> Vec<u8> {
    let packages = state.repo_index.get("nuget", &state.storage).await;

    let query_lower = query.to_lowercase();
    let mut matched: Vec<&str> = Vec::new();
    for pkg in packages.iter() {
        if !query_lower.is_empty() && !pkg.name.to_lowercase().contains(&query_lower) {
            continue;
        }
        let versions = get_cached_versions(&state.storage, &pkg.name).await;
        // Apply prerelease filter
        let versions: Vec<&String> = if prerelease {
            versions.iter().collect()
        } else {
            versions.iter().filter(|v| !v.contains('-')).collect()
        };
        // Apply SemVer 2.0 filter
        let versions: Vec<&&String> = if sem_ver_level == Some("2.0.0") {
            versions.iter().collect()
        } else {
            versions.iter().filter(|v| !is_semver2_version(v)).collect()
        };
        if versions.is_empty() {
            continue;
        }
        matched.push(pkg.name.as_str());
    }

    let total_hits = matched.len();
    let names: Vec<&str> = matched.into_iter().skip(skip).take(take).collect();

    let result = serde_json::json!({
        "totalHits": total_hits,
        "data": names,
    });
    serde_json::to_vec(&result).unwrap_or_else(|_| br#"{"totalHits":0,"data":[]}"#.to_vec())
}

/// Generate NuGet v3 service index from scratch, advertising only resources
/// that NORA actually implements. This is the fail-closed approach: clients
/// only see resources with real handlers behind them. (#404)
///
/// `base_url` is the full NORA base URL including scheme (e.g. `https://artifact.company.local`).
fn generate_service_index(base_url: &str) -> String {
    let nora_nuget = format!("{}/nuget", base_url.trim_end_matches('/'));

    let index = serde_json::json!({
        "version": "3.0.0",
        "resources": [
            {
                "@id": format!("{}/v3/flatcontainer/", nora_nuget),
                "@type": "PackageBaseAddress/3.0.0",
                "comment": "Base URL of NuGet package storage"
            },
            {
                "@id": format!("{}/v3/registration/", nora_nuget),
                "@type": "RegistrationsBaseUrl/3.6.0",
                "comment": "Base URL of NuGet package registration info"
            },
            {
                "@id": format!("{}/v3/query", nora_nuget),
                "@type": "SearchQueryService",
                "comment": "NuGet search endpoint"
            },
            {
                "@id": format!("{}/v3/autocomplete", nora_nuget),
                "@type": "SearchAutocompleteService",
                "comment": "NuGet autocomplete endpoint"
            }
        ]
    });

    serde_json::to_string_pretty(&index).expect("static JSON serialization cannot fail")
}

/// Catch-all handler for unhandled NuGet v3 resource paths.
/// Returns 404 with diagnostic logging so operators can see which resources
/// clients are requesting that NORA doesn't implement yet. (#404)
async fn nuget_catchall(Path(path): Path<String>) -> Response {
    tracing::debug!(path = %path, "NuGet: unhandled resource requested");
    StatusCode::NOT_FOUND.into_response()
}

/// Rewrite upstream registration URLs in NuGet registration index/page responses: registration5-*
/// and v3-flatcontainer URLs point through NORA, catalog0 `@id`s are left as they are. The rewrite
/// is [`nora_registry::upstream_rewrite::rewrite_registration_urls`], the one the fuzz target
/// drives; this name is where the server calls it.
fn rewrite_registration_urls(json_text: &str, upstream_url: &str, base_url: &str) -> String {
    nora_registry::upstream_rewrite::rewrite_registration_urls(json_text, upstream_url, base_url)
}

// ── Hosted packages ─────────────────────────────────────────────────────
//
// NORA takes no push, but `nora import` brings packages in from the operator's own registry. An
// imported version is stored under the flat-container keys a client reads — the .nupkg and its
// .nuspec — and a record of it under `nuget/hosted/<id>/<version>.json`. A package with a record
// is NORA's own: its version list and registration are built from the records, a version
// without one is not served, and no upstream is asked for the id.

/// The flat-container key of the .nupkg of `id` at `version`, as a client asks for it: the id and
/// the normalized version, both in lowercase. `None` when either is not NuGet's. `nora import`
/// stores a package under this key (contract `import-key-format-equals-handler-key-format`).
pub(crate) fn package_key(id: &str, version: &str) -> Option<String> {
    let id = id.to_lowercase();
    let version = crate::curation::nuget_version_key(version)?;
    (is_valid_package_id(&id) && is_valid_version(&version))
        .then(|| format!("nuget/flatcontainer/{id}/{version}/{id}.{version}.nupkg"))
}

/// The id and version (lowercase, normalized) a [`package_key`] names.
fn package_key_parts(key: &str) -> Option<(&str, &str)> {
    let (id, rest) = key.strip_prefix("nuget/flatcontainer/")?.split_once('/')?;
    let (version, file) = rest.split_once('/')?;
    (file == format!("{id}.{version}.nupkg")).then_some((id, version))
}

fn nuspec_key(id_lower: &str, version: &str) -> String {
    format!("nuget/flatcontainer/{id_lower}/{version}/{id_lower}.nuspec")
}

fn hosted_prefix(id_lower: &str) -> String {
    format!("nuget/hosted/{id_lower}/")
}

fn hosted_record_key(id_lower: &str, version: &str) -> String {
    format!("{}{version}.json", hosted_prefix(id_lower))
}

/// Whether a package is hosted, from its records.
enum Hosted {
    /// These versions (lowercase, normalized), in NuGet's order.
    Yes(Vec<String>),
    No,
    /// The listing failed: nothing is decided on a guess.
    Unknown,
}

async fn hosted_versions(storage: &crate::storage::Storage, id_lower: &str) -> Hosted {
    let prefix = hosted_prefix(id_lower);
    if crate::validation::validate_storage_key(crate::validation::listing_key(&prefix)).is_err() {
        return Hosted::No;
    }
    match storage.list(&prefix).await {
        Ok(keys) => {
            let mut versions: Vec<String> = keys
                .iter()
                .filter_map(|k| k.strip_prefix(&prefix)?.strip_suffix(".json"))
                .filter(|v| !v.is_empty() && !v.contains('/'))
                .map(str::to_string)
                .collect();
            if versions.is_empty() {
                return Hosted::No;
            }
            versions.sort_by(|a, b| nuget_version_order(a, b).unwrap_or_else(|| a.cmp(b)));
            Hosted::Yes(versions)
        }
        Err(e) => {
            tracing::warn!(registry = "nuget", package = %id_lower, error = %e, "nuget: hosted records not listed");
            Hosted::Unknown
        }
    }
}

/// What NORA records of a hosted version: the .nuspec's id and version (normalized, in the case
/// the package gives it) and what a registration leaf shows of it.
#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq)]
struct HostedRecord {
    id: String,
    version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    authors: String,
    #[serde(rename = "dependencyGroups", default)]
    dependency_groups: Vec<DependencyGroup>,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq)]
struct DependencyGroup {
    #[serde(
        rename = "targetFramework",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    target_framework: String,
    #[serde(default)]
    dependencies: Vec<Dependency>,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq)]
struct Dependency {
    id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    range: String,
}

/// What `nora import` stores beside an imported .nupkg: its .nuspec and its record, each with
/// its key. The record is written last — it is what makes the version served.
pub(crate) struct ImportedPackage {
    pub nuspec_key: String,
    pub nuspec: Vec<u8>,
    pub record_key: String,
    pub record: Vec<u8>,
}

/// Why a .nupkg is not imported.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ImportedPackageError {
    #[error("not a NuGet package key: {0}")]
    NotAPackageKey(String),
    #[error("not a zip archive: {0}")]
    NotAZip(&'static str),
    #[error("the package has no .nuspec at its root")]
    NoNuspec,
    #[error("the package has more than one .nuspec at its root")]
    SeveralNuspecs,
    #[error("the .nuspec cannot be read: {0}")]
    Nuspec(&'static str),
    #[error("the .nuspec is not well-formed XML: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("the .nuspec is not well-formed XML: {0}")]
    Encoding(#[from] quick_xml::encoding::EncodingError),
    #[error("the .nuspec is not well-formed XML: {0}")]
    Escape(#[from] quick_xml::escape::EscapeError),
    #[error("the package is {found}, its key names {expected}")]
    Mismatch { found: String, expected: String },
    #[error("reading the package: {0}")]
    Io(#[from] std::io::Error),
    #[error("writing the record: {0}")]
    Record(#[from] serde_json::Error),
}

/// The .nuspec and the record of the .nupkg read from `nupkg`, to be stored under `package_key`.
/// The .nuspec must name the id and version the key does: a package of another id or version
/// is not imported under this one.
pub(crate) fn imported_package(
    package_key: &str,
    nupkg: impl std::io::Read + std::io::Seek,
) -> Result<ImportedPackage, ImportedPackageError> {
    let (id_lower, version) = package_key_parts(package_key)
        .ok_or_else(|| ImportedPackageError::NotAPackageKey(package_key.to_string()))?;
    let nuspec = root_nuspec(nupkg)?;
    let record = parse_nuspec(&nuspec)?;
    let found = format!(
        "{}@{}",
        record.id.to_lowercase(),
        crate::curation::nuget_version_key(&record.version).unwrap_or_default()
    );
    let expected = format!("{id_lower}@{version}");
    if found != expected {
        return Err(ImportedPackageError::Mismatch { found, expected });
    }
    Ok(ImportedPackage {
        nuspec_key: nuspec_key(id_lower, version),
        nuspec,
        record_key: hosted_record_key(id_lower, version),
        record: serde_json::to_vec(&record)?,
    })
}

/// The largest .nuspec read from a package. NuGet itself refuses a manifest a fraction this size.
const NUSPEC_MAX: u64 = 1 << 20;
/// The largest central directory read from a package: a few hundred thousand entries.
const CENTRAL_DIRECTORY_MAX: u64 = 64 << 20;

fn le16(b: &[u8], at: usize) -> Option<u64> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?).into())
}

fn le32(b: &[u8], at: usize) -> Option<u64> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?).into())
}

/// The bytes of the one .nuspec at the root of the zip archive `zip`, checked against the size and
/// CRC-32 the archive records for it. Stored and deflated entries are read; a zip64 archive is not.
fn root_nuspec(
    mut zip: impl std::io::Read + std::io::Seek,
) -> Result<Vec<u8>, ImportedPackageError> {
    use std::io::{Read, SeekFrom};
    use ImportedPackageError::{NotAZip, Nuspec};
    const END_OF_DIRECTORY: u64 = 0x0605_4b50;
    const DIRECTORY_ENTRY: u64 = 0x0201_4b50;
    const LOCAL_HEADER: u64 = 0x0403_4b50;

    let len = zip.seek(SeekFrom::End(0))?;
    if len < 22 {
        return Err(NotAZip("shorter than an empty archive"));
    }
    // The end-of-directory record is the last 22 bytes before a comment of up to 64 KiB.
    let tail_len = len.min(22 + 0xFFFF);
    zip.seek(SeekFrom::Start(len - tail_len))?;
    let mut tail = vec![0; tail_len as usize];
    zip.read_exact(&mut tail)?;
    let end = (0..=tail.len() - 22)
        .rev()
        .find(|&at| le32(&tail, at) == Some(END_OF_DIRECTORY))
        .ok_or(NotAZip("no end of central directory"))?;
    let entries = le16(&tail, end + 10).ok_or(NotAZip("truncated end record"))?;
    let directory_len = le32(&tail, end + 12).ok_or(NotAZip("truncated end record"))?;
    let directory_at = le32(&tail, end + 16).ok_or(NotAZip("truncated end record"))?;
    if entries == 0xFFFF || directory_at == 0xFFFF_FFFF || directory_len == 0xFFFF_FFFF {
        return Err(NotAZip("zip64 archives are not read"));
    }
    if directory_len > CENTRAL_DIRECTORY_MAX || directory_at + directory_len > len {
        return Err(NotAZip("central directory out of bounds"));
    }
    zip.seek(SeekFrom::Start(directory_at))?;
    let mut directory = vec![0; directory_len as usize];
    zip.read_exact(&mut directory)?;

    let mut at = 0usize;
    let mut found = None;
    for _ in 0..entries {
        let entry = directory
            .get(at..)
            .ok_or(NotAZip("truncated central directory"))?;
        let read = |offset: usize, width: usize| {
            match width {
                2 => le16(entry, offset),
                _ => le32(entry, offset),
            }
            .ok_or(NotAZip("truncated central directory"))
        };
        if read(0, 4)? != DIRECTORY_ENTRY {
            return Err(NotAZip("bad central directory entry"));
        }
        let (method, crc, packed, size) = (read(10, 2)?, read(16, 4)?, read(20, 4)?, read(24, 4)?);
        let name_len = read(28, 2)? as usize;
        let skip = (read(30, 2)? + read(32, 2)?) as usize;
        let local = read(42, 4)?;
        let name = entry
            .get(46..46 + name_len)
            .ok_or(NotAZip("truncated central directory"))?;
        if !name.contains(&b'/') && name.to_ascii_lowercase().ends_with(b".nuspec") {
            if found.is_some() {
                return Err(ImportedPackageError::SeveralNuspecs);
            }
            found = Some((method, crc, packed, size, local));
        }
        at += 46 + name_len + skip;
    }
    let (method, crc, packed, size, local) = found.ok_or(ImportedPackageError::NoNuspec)?;
    if size > NUSPEC_MAX {
        return Err(Nuspec("larger than 1 MiB"));
    }
    zip.seek(SeekFrom::Start(local))?;
    let mut header = [0u8; 30];
    zip.read_exact(&mut header)?;
    if le32(&header, 0) != Some(LOCAL_HEADER) {
        return Err(NotAZip("bad local header"));
    }
    let skip = le16(&header, 26).unwrap_or(0) + le16(&header, 28).unwrap_or(0);
    zip.seek(SeekFrom::Current(skip as i64))?;
    let packed_body = zip.take(packed);
    let mut nuspec = Vec::new();
    match method {
        0 => packed_body.take(NUSPEC_MAX + 1).read_to_end(&mut nuspec)?,
        8 => flate2::read::DeflateDecoder::new(packed_body)
            .take(NUSPEC_MAX + 1)
            .read_to_end(&mut nuspec)?,
        _ => return Err(Nuspec("compressed with a method other than deflate")),
    };
    let mut check = flate2::Crc::new();
    check.update(&nuspec);
    if nuspec.len() as u64 != size || u64::from(check.sum()) != crc {
        return Err(Nuspec(
            "its bytes do not match the size and CRC-32 the archive records",
        ));
    }
    Ok(nuspec)
}

/// The record of a .nuspec: `package/metadata`'s id, version (normalized), description, authors
/// and dependency groups — a `<dependencies>` without groups is one group for every framework.
fn parse_nuspec(nuspec: &[u8]) -> Result<HostedRecord, ImportedPackageError> {
    use quick_xml::events::{BytesStart, Event};
    use ImportedPackageError::Nuspec;
    fn attribute(element: &BytesStart, name: &[u8]) -> String {
        element
            .attributes()
            .flatten()
            .find(|a| a.key.local_name().as_ref() == name)
            .and_then(|a| {
                let raw = String::from_utf8(a.value.to_vec()).ok()?;
                Some(quick_xml::escape::unescape(&raw).ok()?.into_owned())
            })
            .unwrap_or_default()
    }

    let mut reader = quick_xml::Reader::from_reader(nuspec);
    reader.config_mut().trim_text(true);
    let mut record = HostedRecord::default();
    let mut path: Vec<Vec<u8>> = Vec::new();
    // The group the dependencies being read belong to, and the one of dependencies listed
    // without a group.
    let (mut group, mut flat): (Option<usize>, Option<usize>) = (None, None);
    loop {
        let event = reader.read_event()?;
        let (element, empty) = match &event {
            Event::Start(e) => (e, false),
            Event::Empty(e) => (e, true),
            Event::End(_) => {
                path.pop();
                continue;
            }
            // A document that ends inside an element is cut short.
            Event::Eof if path.is_empty() => break,
            Event::Eof => return Err(Nuspec("not well-formed XML")),
            _ => continue,
        };
        let name = element.local_name().as_ref().to_vec();
        let parents: Vec<&[u8]> = path.iter().map(Vec::as_slice).collect();
        match (parents.as_slice(), name.as_slice()) {
            (
                [b"package", b"metadata"],
                field @ (b"id" | b"version" | b"description" | b"authors"),
            ) if !empty => {
                let text = reader.read_text(element.name())?.decode()?.into_owned();
                let text = quick_xml::escape::unescape(&text)?.trim().to_string();
                match field {
                    b"id" => record.id = text,
                    b"version" => record.version = text,
                    b"description" => record.description = text,
                    _ => record.authors = text,
                }
                // `read_text` consumed the end tag.
                continue;
            }
            ([b"package", b"metadata", b"dependencies"], b"group") => {
                record.dependency_groups.push(DependencyGroup {
                    target_framework: attribute(element, b"targetFramework"),
                    dependencies: Vec::new(),
                });
                group = Some(record.dependency_groups.len() - 1);
            }
            ([b"package", b"metadata", b"dependencies", b"group"], b"dependency") => {
                if let Some(group) = group.and_then(|at| record.dependency_groups.get_mut(at)) {
                    group.dependencies.push(Dependency {
                        id: attribute(element, b"id"),
                        range: attribute(element, b"version"),
                    });
                }
            }
            ([b"package", b"metadata", b"dependencies"], b"dependency") => {
                let at = *flat.get_or_insert_with(|| {
                    record.dependency_groups.push(DependencyGroup::default());
                    record.dependency_groups.len() - 1
                });
                record.dependency_groups[at].dependencies.push(Dependency {
                    id: attribute(element, b"id"),
                    range: attribute(element, b"version"),
                });
            }
            _ => {}
        }
        if !empty {
            path.push(name);
        }
    }
    let normalized = crate::curation::nuget_version_key(&record.version)
        .ok_or(Nuspec("names no NuGet version"))?;
    if record.id.is_empty() || !is_valid_package_id(&record.id.to_lowercase()) {
        return Err(Nuspec("names no valid package id"));
    }
    // The normalized numbers, and the pre-release labels in the case the package gives them.
    let numbers = normalized
        .split_once('-')
        .map_or(normalized.as_str(), |(n, _)| n);
    let labels = record
        .version
        .split('+')
        .next()
        .and_then(|release| release.split_once('-'))
        .map(|(_, labels)| labels.trim());
    record.version = match labels {
        Some(labels) => format!("{numbers}-{labels}"),
        None => numbers.to_string(),
    };
    Ok(record)
}

/// The registration of a hosted package, built from its records: one inline page that lists every
/// version with its .nupkg in NORA's flat container and its dependency groups.
async fn hosted_registration(state: &AppState, id_lower: &str, versions: &[String]) -> Response {
    let nuget = format!("{}/nuget/v3", nora_base_url(state).trim_end_matches('/'));
    let registration = format!("{nuget}/registration/{id_lower}/index.json");
    let mut leaves = Vec::with_capacity(versions.len());
    let mut range: Option<(String, String)> = None;
    for version in versions {
        let key = hosted_record_key(id_lower, version);
        let record: HostedRecord = match state.storage.get(&key).await {
            Ok(data) => match serde_json::from_slice(&data) {
                Ok(record) => record,
                Err(e) => {
                    tracing::warn!(key = %key, error = %e, "nuget: hosted record not readable");
                    return crate::registry::storage_unavailable("nuget", &key);
                }
            },
            // Deleted since the listing: the version is no longer hosted.
            Err(crate::storage::StorageError::NotFound) => continue,
            Err(_) => return crate::registry::storage_unavailable("nuget", &key),
        };
        let content =
            format!("{nuget}/flatcontainer/{id_lower}/{version}/{id_lower}.{version}.nupkg");
        let leaf = format!("{nuget}/registration/{id_lower}/{version}.json");
        let groups: Vec<serde_json::Value> = record
            .dependency_groups
            .iter()
            .map(|group| {
                let mut value = serde_json::json!({
                    "@type": "PackageDependencyGroup",
                    "dependencies": group.dependencies.iter().map(|d| serde_json::json!({
                        "@type": "PackageDependency",
                        "id": d.id,
                        "range": d.range,
                    })).collect::<Vec<_>>(),
                });
                if !group.target_framework.is_empty() {
                    value["targetFramework"] = group.target_framework.clone().into();
                }
                value
            })
            .collect();
        range = Some(match range {
            None => (record.version.clone(), record.version.clone()),
            Some((lower, _)) => (lower, record.version.clone()),
        });
        leaves.push(serde_json::json!({
            "@id": leaf,
            "@type": "Package",
            "catalogEntry": {
                "@id": leaf,
                "@type": "PackageDetails",
                "id": record.id,
                "version": record.version,
                "description": record.description,
                "authors": record.authors,
                "listed": true,
                "packageContent": content,
                "dependencyGroups": groups,
            },
            "packageContent": content,
            "registration": registration,
        }));
    }
    let Some((lower, upper)) = range else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let doc = serde_json::json!({
        "@id": registration,
        "@type": ["catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink"],
        "count": 1,
        "items": [{
            "@id": format!("{registration}#page/{lower}/{upper}"),
            "@type": "catalog:CatalogPage",
            "count": leaves.len(),
            "lower": lower,
            "upper": upper,
            "parent": registration,
            "items": leaves,
        }],
    });
    state.metrics.record_download("nuget");
    with_json_gzip(doc.to_string().into_bytes())
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

/// Check if a version string uses SemVer 2.0.0 features.
///
/// SemVer 2.0 = dot-separated pre-release identifiers (`1.0.0-rc.1`)
/// OR build metadata (`1.0.0+build`).  NuGet V3 search/autocomplete hides
/// such versions unless `semVerLevel=2.0.0` is passed.
fn is_semver2_version(version: &str) -> bool {
    if version.contains('+') {
        return true;
    }
    if let Some(idx) = version.find('-') {
        return version[idx + 1..].contains('.');
    }
    false
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

    /// #385: a slash-escaped upstream registration URL must not survive the
    /// raw-text rewrite — otherwise the client, after unescaping `\/`, is sent
    /// back to the origin past Nora (host leak + air-gap bypass).
    #[test]
    fn rewrite_nuget_registration_drops_upstream_host_plain_and_escaped() {
        const HOST: &str = "api.nuget.org";
        let upstream = "https://api.nuget.org";
        let base = "http://nora.test";

        let plain = rewrite_registration_urls(
            r#"{"@id":"https://api.nuget.org/v3/registration5-semver1/pkg/index.json"}"#,
            upstream,
            base,
        );
        assert!(
            !plain.contains(HOST),
            "plain registration host leaked: {plain}"
        );

        let escaped = rewrite_registration_urls(
            r#"{"@id":"https:\/\/api.nuget.org\/v3\/registration5-semver1\/pkg\/index.json"}"#,
            upstream,
            base,
        );
        assert!(
            !escaped.contains(HOST),
            "slash-escaped registration host leaked (#385): {escaped}"
        );
    }

    /// A host that only starts like the upstream's is another origin: its registration and
    /// package links are left as they are.
    #[test]
    fn a_host_that_only_starts_like_the_upstream_is_not_rewritten() {
        let upstream = "https://api.example.org";
        for other in [
            r#"{"@id":"https://api.example.org.evil.net/v3/registration5-semver1/pkg/index.json"}"#,
            r#"{"@id":"https://api.example.org:8443/v3-flatcontainer/pkg/1.0.0/pkg.1.0.0.nupkg"}"#,
            r#"{"@id":"https:\/\/api.example.org.evil.net\/v3-flatcontainer\/pkg\/x.nupkg"}"#,
        ] {
            assert_eq!(
                rewrite_registration_urls(other, upstream, "http://nora.test"),
                other
            );
        }
    }

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
    fn test_strip_url_path_with_index_json() {
        assert_eq!(
            strip_url_path("https://api.nuget.org/v3/index.json"),
            "https://api.nuget.org"
        );
    }

    #[test]
    fn test_strip_url_path_no_path() {
        assert_eq!(
            strip_url_path("https://api.nuget.org"),
            "https://api.nuget.org"
        );
    }

    #[test]
    fn test_strip_url_path_trailing_slash() {
        assert_eq!(
            strip_url_path("https://api.nuget.org/"),
            "https://api.nuget.org"
        );
    }

    #[test]
    fn test_strip_url_path_custom_port() {
        assert_eq!(
            strip_url_path("https://artifact.company.local:8443/nuget/v3/index.json"),
            "https://artifact.company.local:8443"
        );
    }

    #[test]
    fn test_strip_url_path_http() {
        assert_eq!(
            strip_url_path("http://localhost:4000/nuget/v3/index.json"),
            "http://localhost:4000"
        );
    }

    #[test]
    fn test_generate_service_index_http() {
        let result = generate_service_index("http://nora:4000");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["version"], "3.0.0");
        let resources = json["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 4);
        assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
        assert!(result.contains("http://nora:4000/nuget/v3/registration/"));
        assert!(result.contains("http://nora:4000/nuget/v3/query"));
        assert!(result.contains("http://nora:4000/nuget/v3/autocomplete"));
    }

    #[test]
    fn test_generate_service_index_https() {
        let result = generate_service_index("https://artifact.company.local");
        assert!(result.contains("https://artifact.company.local/nuget/v3/flatcontainer/"));
        assert!(result.contains("https://artifact.company.local/nuget/v3/registration/"));
        assert!(!result.contains("http://artifact.company.local"));
    }

    #[test]
    fn test_generate_service_index_no_upstream_urls() {
        let result = generate_service_index("http://nora:4000");
        assert!(!result.contains("api.nuget.org"));
        assert!(!result.contains("azuresearch-usnc.nuget.org"));
        assert!(!result.contains("azuresearch-ussc.nuget.org"));
        assert!(!result.contains("www.nuget.org"));
        assert!(!result.contains("nuget.org"));
    }

    #[test]
    fn test_generate_service_index_only_implemented_resources() {
        let result = generate_service_index("http://nora:4000");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        let types: Vec<&str> = json["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["@type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"PackageBaseAddress/3.0.0"));
        assert!(types.contains(&"RegistrationsBaseUrl/3.6.0"));
        assert!(types.contains(&"SearchQueryService"));
        assert!(types.contains(&"SearchAutocompleteService"));
        // Must NOT include unimplemented resources
        assert!(!types.iter().any(|t| t.contains("Catalog")));
        assert!(!types.iter().any(|t| t.contains("RepositorySignatures")));
        assert!(!types.iter().any(|t| t.contains("Vulnerability")));
    }

    #[test]
    fn test_generate_service_index_trailing_slash() {
        let result = generate_service_index("http://nora:4000/");
        // Should not produce double slashes
        assert!(!result.contains("http://nora:4000//"));
        assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
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

    /// Deprecation fields survive URL rewriting — catalog0 @ids left as-is (#424)
    #[test]
    fn test_rewrite_preserves_deprecation_field() {
        let input = r#"{"items":[{"catalogEntry":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.09.20/ef.4.1.json","version":"4.1.10311","deprecation":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.09.20/ef.4.1.json#deprecation","@type":"deprecation","alternatePackage":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.09.20/ef.4.1.json#deprecation/alternatePackage","@type":"alternatePackage","id":"EntityFramework","range":"[6.5.1, )"},"reasons":["Legacy"]},"packageContent":"https://api.nuget.org/v3-flatcontainer/entityframework/4.1.10311/entityframework.4.1.10311.nupkg"}}]}"#;
        let result = rewrite_registration_urls(input, "https://api.nuget.org", "http://nora:4000");
        // deprecation block preserved intact (catalog0 URLs stay as-is)
        assert!(result.contains(r#""deprecation":{""#));
        assert!(result.contains(r#""reasons":["Legacy"]"#));
        assert!(result.contains(r#""id":"EntityFramework""#));
        assert!(result.contains("https://api.nuget.org/v3/catalog0/data/2024.09.20"));
        assert!(!result.contains("nora:4000/nuget/v3/catalog0"));
        // packageContent rewritten to Nora
        assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
    }

    /// Vulnerabilities array survives URL rewriting (#424)
    #[test]
    fn test_rewrite_preserves_vulnerabilities_field() {
        let input = r#"{"items":[{"catalogEntry":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.01.01/log4net.1.2.10.json","version":"1.2.10","vulnerabilities":[{"advisoryUrl":"https://github.com/advisories/GHSA-2cwj-8chv-9pp9","severity":"3"},{"advisoryUrl":"https://github.com/advisories/GHSA-4f7c-pmjv-c25w","severity":"1"}],"packageContent":"https://api.nuget.org/v3-flatcontainer/log4net/1.2.10/log4net.1.2.10.nupkg"}}]}"#;
        let result = rewrite_registration_urls(input, "https://api.nuget.org", "http://nora:4000");
        // vulnerabilities array preserved intact (external advisory URLs, not upstream registry)
        assert!(result.contains(r#""vulnerabilities":[{"#));
        assert!(result.contains("GHSA-2cwj-8chv-9pp9"));
        assert!(result.contains("GHSA-4f7c-pmjv-c25w"));
        assert!(result.contains(r#""severity":"3""#));
        assert!(result.contains(r#""advisoryUrl":"https://github.com/advisories/"#));
        // packageContent rewritten to Nora
        assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
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

    #[test]
    fn test_is_semver2_version() {
        // SemVer 2.0: dot-separated pre-release identifiers
        assert!(is_semver2_version("1.0.0-rc.1"));
        assert!(is_semver2_version("9.0.0-rc.1.24431.7"));
        assert!(is_semver2_version("1.0.0-beta.2.3"));

        // SemVer 2.0: build metadata
        assert!(is_semver2_version("1.0.0+build"));
        assert!(is_semver2_version("1.0.0-alpha+001"));

        // SemVer 1.0: simple pre-release (no dots after hyphen)
        assert!(!is_semver2_version("1.0.0-alpha"));
        assert!(!is_semver2_version("1.0.0-beta1"));
        assert!(!is_semver2_version("2.0.0-preview"));

        // Stable versions: not SemVer 2.0
        assert!(!is_semver2_version("1.0.0"));
        assert!(!is_semver2_version("13.0.3"));
    }

    #[test]
    fn test_registration_returns_gzip_content_encoding() {
        let resp = with_json_gzip(br#"{"count":1}"#.to_vec());
        let (parts, body) = resp.into_parts();
        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(
            parts.headers.get("content-encoding").map(|v| v.as_bytes()),
            Some(b"gzip".as_slice()),
        );
        assert_eq!(
            parts.headers.get("content-type").map(|v| v.as_bytes()),
            Some(b"application/json".as_slice()),
        );

        // Decompress body and verify round-trip
        use axum::body::Body;
        use flate2::read::GzDecoder;
        use std::io::Read;

        let body_bytes =
            futures::executor::block_on(axum::body::to_bytes(Body::new(body), 1 << 20)).unwrap();
        let mut decoder = GzDecoder::new(&body_bytes[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();
        assert_eq!(decompressed, r#"{"count":1}"#);
    }

    #[test]
    fn test_service_index_no_gzip() {
        let resp = with_json(br#"{"version":"3.0.0"}"#.to_vec());
        let (parts, _body) = resp.into_parts();
        assert!(
            parts.headers.get("content-encoding").is_none(),
            "service index (with_json) must NOT have Content-Encoding header"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    /// A .nuspec's record: its id, its version normalized with the labels in their own case, and
    /// its dependencies — in groups, or listed without one as a group for every framework.
    #[test]
    fn a_nuspec_record_keeps_its_id_version_and_dependencies() {
        let grouped = br#"<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>
  <id>Corp.Lib</id><version>01.2-RC.1+sha.5</version><authors>a &amp; b</authors>
  <dependencies>
    <group targetFramework=".NETStandard2.0"><dependency id="A" version="[1.0,2.0)"/></group>
    <group targetFramework="net8.0"/>
  </dependencies>
</metadata></package>"#;
        let record = super::parse_nuspec(grouped).unwrap();
        assert_eq!(record.id, "Corp.Lib");
        assert_eq!(record.version, "1.2.0-RC.1");
        assert_eq!(record.authors, "a & b");
        assert_eq!(record.dependency_groups.len(), 2);
        assert_eq!(
            record.dependency_groups[0].target_framework,
            ".NETStandard2.0"
        );
        assert_eq!(record.dependency_groups[0].dependencies[0].id, "A");
        assert_eq!(
            record.dependency_groups[0].dependencies[0].range,
            "[1.0,2.0)"
        );
        assert!(record.dependency_groups[1].dependencies.is_empty());

        let flat = br#"<package><metadata><id>Flat</id><version>1.0.0</version>
  <dependencies><dependency id="A" version="1.0"/><dependency id="B"/></dependencies>
</metadata></package>"#;
        let record = super::parse_nuspec(flat).unwrap();
        assert_eq!(record.dependency_groups.len(), 1);
        assert_eq!(record.dependency_groups[0].target_framework, "");
        let ids: Vec<&str> = record.dependency_groups[0]
            .dependencies
            .iter()
            .map(|d| d.id.as_str())
            .collect();
        assert_eq!(ids, ["A", "B"]);

        for bad in [
            &b"<package><metadata><id>X</id></metadata></package>"[..],
            b"<package><metadata><version>1.0</version></metadata></package>",
            b"<package><metadata><id>a/b</id><version>1.0</version></metadata></package>",
            b"<package><metadata><id>X</id><version>1.0</version>",
        ] {
            assert!(
                super::parse_nuspec(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// The flat-container key of a package is the one a client asks for: id and normalized
    /// version in lowercase.
    #[test]
    fn a_package_key_is_the_one_a_client_asks_for() {
        assert_eq!(
            super::package_key("Corp.Lib", "01.2-RC.1+sha.5").as_deref(),
            Some("nuget/flatcontainer/corp.lib/1.2.0-rc.1/corp.lib.1.2.0-rc.1.nupkg")
        );
        assert_eq!(super::package_key("a/b", "1.0"), None);
        assert_eq!(super::package_key("Corp.Lib", "latest"), None);
    }

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
    #[doc = "No cache + unreachable upstream → 404 (not 502) since #410"]
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
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Stale cache + unreachable upstream + serve_stale=true → 200 with X-Nora-Stale header (#409)
    #[tokio::test]
    async fn test_serve_stale_version_list() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
            cfg.nuget.metadata_ttl = 0; // force TTL expiry
            cfg.nuget.serve_stale = true;
        });
        // Seed cache
        let versions = br#"{"versions":["1.0.0","2.0.0"]}"#;
        ctx.state
            .storage
            .put("nuget/flatcontainer/test-package/index.json", versions)
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/test-package/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
            Some(b"true".as_slice())
        );
        let body = body_bytes(resp).await;
        assert!(body.starts_with(b"{\"versions\""));
    }

    /// Stale cache + unreachable upstream + serve_stale=false → 404 (#409)
    #[tokio::test]
    async fn test_serve_stale_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
            cfg.nuget.metadata_ttl = 0;
            cfg.nuget.serve_stale = false;
        });
        // Seed cache
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/test-package/index.json",
                br#"{"versions":["1.0.0"]}"#,
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/test-package/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(resp.headers().get("x-nora-stale").is_none());
    }

    /// Uncached .nupkg + unreachable upstream → 404 (not 502) (#410)
    #[tokio::test]
    async fn test_uncached_nupkg_returns_404_not_502() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/nosuch-pkg/1.0.0/nosuch-pkg.1.0.0.nupkg",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Stale registration index is served with URL rewriting (#409)
    #[tokio::test]
    async fn test_serve_stale_registration_index() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
            cfg.nuget.metadata_ttl = 0;
            cfg.nuget.serve_stale = true;
        });
        // Seed registration cache
        let reg_json =
            br#"{"items":[{"@id":"http://127.0.0.1:1/v3/registration/test-pkg/index.json"}]}"#;
        ctx.state
            .storage
            .put("nuget/registration/test-pkg/index.json", reg_json)
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/test-pkg/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
            Some(b"true".as_slice())
        );
    }

    /// Trusted upstream dates and no upstream: a date is what the cache holds.
    fn trusted_without_upstream() -> crate::test_helpers::TestContext {
        create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
            cfg.server.trust_upstream_dates = true;
        })
    }

    #[tokio::test]
    async fn test_extract_nuget_publish_date_found() {
        let ctx = trusted_without_upstream();
        let storage = &ctx.state.storage;
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

        let result = super::nuget_publish_date(&ctx.state, "newtonsoft.json", "6.0.0", true).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_extract_nuget_publish_date_version_not_found() {
        let ctx = trusted_without_upstream();
        let storage = &ctx.state.storage;
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

        let result = super::nuget_publish_date(&ctx.state, "test", "9.9.9", true).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_extract_nuget_publish_date_no_metadata() {
        let ctx = trusted_without_upstream();

        let result = super::nuget_publish_date(&ctx.state, "nonexistent", "1.0.0", true).await;
        assert!(result.is_none());
    }

    /// Regression test for #535: pages without inline items must not abort
    /// date extraction for subsequent pages.
    #[tokio::test]
    async fn test_extract_nuget_publish_date_sparse_pages() {
        let ctx = trusted_without_upstream();
        let storage = &ctx.state.storage;
        // Page 0: non-inline (only @id, no items array).
        // Page 1: inline with the target version.
        let meta = serde_json::json!({
            "items": [
                { "@id": "https://upstream/page/0" },
                {
                    "items": [{
                        "catalogEntry": {
                            "version": "2.0.0",
                            "published": "2024-06-15T12:00:00Z"
                        }
                    }]
                }
            ]
        });
        storage
            .put(
                "nuget/registration/sparse-pkg/index.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        // Before #535 fix: this returned None because page 0 had no "items".
        let result = super::nuget_publish_date(&ctx.state, "sparse-pkg", "2.0.0", true).await;
        assert!(result.is_some(), "date must be found despite sparse page 0");
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
    async fn test_local_search_sem_ver_level_filters_v2() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        // Package with SemVer 2.0 version (dot-separated pre-release)
        let index = serde_json::json!({"versions": ["1.0.0", "2.0.0-rc.1"]});
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/semver2pkg/index.json",
                serde_json::to_vec(&index).unwrap().as_slice(),
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/semver2pkg/1.0.0/semver2pkg.1.0.0.nupkg",
                b"fake-nupkg",
            )
            .await
            .unwrap();
        ctx.state.repo_index.invalidate("nuget");

        // Without semVerLevel → SemVer2 version hidden, only 1.0.0 visible
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/query?q=semver2pkg&prerelease=true",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entry = &json["data"][0];
        let versions = entry["versions"].as_array().unwrap();
        assert_eq!(
            versions.len(),
            1,
            "without semVerLevel, SemVer2 must be hidden"
        );
        assert_eq!(versions[0]["version"].as_str().unwrap(), "1.0.0");

        // With semVerLevel=2.0.0 → both versions visible
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/query?q=semver2pkg&prerelease=true&semVerLevel=2.0.0",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entry = &json["data"][0];
        let versions = entry["versions"].as_array().unwrap();
        assert_eq!(
            versions.len(),
            2,
            "with semVerLevel=2.0.0, SemVer2 must be visible"
        );
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
    #[doc = "No cache + unreachable upstream → 404 (not 502) since #410"]
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
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Search fallback adds X-Nora-Stale header when upstream is unreachable (#422)
    #[tokio::test]
    async fn test_search_fallback_has_stale_header() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.search_service = "http://127.0.0.1:1/query".to_string();
            cfg.nuget.serve_stale = true;
        });
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=test", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
            Some(b"true".as_slice())
        );
    }

    /// Search returns 503 when serve_stale=false and upstream is down (#422)
    #[tokio::test]
    async fn test_search_serve_stale_disabled_returns_503() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.search_service = "http://127.0.0.1:1/query".to_string();
            cfg.nuget.serve_stale = false;
        });
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=test", "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().get("x-nora-stale").is_none());
    }

    /// Autocomplete fallback adds X-Nora-Stale header when upstream is unreachable (#422)
    #[tokio::test]
    async fn test_autocomplete_fallback_has_stale_header() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.autocomplete = "http://127.0.0.1:1/autocomplete".to_string();
            cfg.nuget.serve_stale = true;
        });
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/autocomplete?q=test", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
            Some(b"true".as_slice())
        );
    }

    /// Autocomplete returns 503 when serve_stale=false and upstream is down (#422)
    #[tokio::test]
    async fn test_autocomplete_serve_stale_disabled_returns_503() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.autocomplete = "http://127.0.0.1:1/autocomplete".to_string();
            cfg.nuget.serve_stale = false;
        });
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/autocomplete?q=test", "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().get("x-nora-stale").is_none());
    }

    /// A cached .nupkg resumes: 206 for a satisfiable range, 416 once the client
    /// already holds the whole package, `Accept-Ranges` on the full 200.
    #[tokio::test]
    async fn test_nuget_nupkg_range_request() {
        use crate::test_helpers::send_with_headers;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
        });
        let nupkg = b"0123456789";
        ctx.state
            .storage
            .put("nuget/flatcontainer/rngpkg/1.0.0/rngpkg.1.0.0.nupkg", nupkg)
            .await
            .unwrap();
        let url = "/nuget/v3/flatcontainer/rngpkg/1.0.0/rngpkg.1.0.0.nupkg";

        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get("content-range")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes 2-5/10"
        );
        assert_eq!(
            resp.headers()
                .get("accept-ranges")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(&body_bytes(resp).await[..], b"2345");

        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=10-")], "").await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()
                .get("content-range")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes */10"
        );

        let resp = send(&ctx.app, Method::GET, url, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("accept-ranges")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(&body_bytes(resp).await[..], nupkg);
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

    /// Known URL patterns in NuGet responses that are NOT client-fetchable
    /// and intentionally left unrewritten. catalog0 URLs appear in
    /// catalogEntry.@id fields but NuGet clients never fetch them during restore.
    const NUGET_EXCLUDED_PATTERNS: &[&str] = &["/v3/catalog0/"];

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

    // ── Generated service index: air-gap invariants ──

    #[test]
    fn test_generated_service_index_no_upstream_leak() {
        let generated = generate_service_index("https://registry.airgap.local");
        assert_no_upstream_urls(&generated, "generated service-index");

        let json: serde_json::Value = serde_json::from_str(&generated).unwrap();
        assert!(json["resources"].is_array());
        assert!(!json["resources"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_generated_service_index_all_ids_point_to_nora() {
        let generated = generate_service_index("http://nora:4000");
        let json: serde_json::Value = serde_json::from_str(&generated).unwrap();
        let resources = json["resources"].as_array().unwrap();

        // Every @id must start with nora base — no exceptions (air-gap invariant)
        for res in resources {
            let id = res["@id"].as_str().unwrap();
            let res_type = res["@type"].as_str().unwrap_or("");
            assert!(
                id.starts_with("http://nora:4000/nuget/"),
                "resource @id not pointing to NORA: {} (type: {})",
                id,
                res_type
            );
        }
    }

    #[test]
    fn test_generated_service_index_snapshot() {
        let generated = generate_service_index("http://nora:4000");
        let json: serde_json::Value = serde_json::from_str(&generated).unwrap();

        let ids: Vec<&str> = json["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["@id"].as_str().unwrap())
            .collect();
        insta::assert_json_snapshot!("nuget_service_index_ids", ids);
    }

    #[test]
    fn test_search_response_registration_urls_rewritten() {
        let upstream_search = r#"{"totalHits":1,"data":[{"id":"Newtonsoft.Json","version":"13.0.3","registration":"https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json"}]}"#;
        let rewritten =
            rewrite_registration_urls(upstream_search, "https://api.nuget.org", "http://nora:4000");
        assert_no_upstream_urls(&rewritten, "search response rewrite");
        assert!(
            rewritten.contains("http://nora:4000/nuget/v3/registration/newtonsoft.json/index.json")
        );
    }

    #[test]
    fn test_autocomplete_response_no_leak() {
        // Autocomplete responses contain only package names, no URLs to rewrite
        let upstream =
            r#"{"totalHits":5,"data":["Newtonsoft.Json","NUnit","NLog","Nancy","Noda"]}"#;
        let rewritten =
            rewrite_registration_urls(upstream, "https://api.nuget.org", "http://nora:4000");
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
    async fn test_service_index_content_type_no_gzip() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        // Generated service index — no upstream or fixture needed
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/index.json", "").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
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

        // Service index must NOT be gzip-encoded (only registration endpoints are)
        assert!(
            resp.headers().get("content-encoding").is_none(),
            "service index must not have Content-Encoding header"
        );
    }

    #[tokio::test]
    async fn test_cached_registration_content_type_and_gzip() {
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

        // Registration must be gzip-encoded (RegistrationsBaseUrl/3.6.0 spec)
        let content_encoding = resp
            .headers()
            .get("content-encoding")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        assert_eq!(
            content_encoding, "gzip",
            "registration response must have Content-Encoding: gzip"
        );

        // Decompress and verify the rewritten body has no upstream URLs
        let body = body_bytes(resp).await;
        let mut decoder = flate2::read::GzDecoder::new(&body[..]);
        let mut decompressed = String::new();
        std::io::Read::read_to_string(&mut decoder, &mut decompressed).unwrap();
        assert_no_upstream_urls(&decompressed, "cached registration index response");
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

    /// #52 acceptance: with a cached flat-container version list + stored
    /// validators, a stale request revalidates with `If-None-Match`; on upstream
    /// 304 the cached body is served with no 200-body download. nuget.org returns
    /// validators on this endpoint, so this is a real revalidation.
    #[tokio::test]
    async fn test_nuget_revalidation_304_serves_cache_no_body_download() {
        use crate::registry::{write_validators, Validators};
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
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
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(upstream.uri());
            cfg.nuget.metadata_ttl = 0; // always stale → always revalidate
            cfg.nuget.revalidate = true;
            cfg.nuget.serve_stale = false;
        });

        let key = "nuget/flatcontainer/test-package/index.json";
        ctx.state
            .storage
            .put(key, br#"{"versions":["1.0.0","2.0.0"]}"#)
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
            .with_label_values(&["nuget"])
            .get();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/test-package/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert!(
            String::from_utf8_lossy(&body).contains("2.0.0"),
            "must serve the cached version list"
        );

        let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["nuget"])
            .get();
        assert!(after > before, "a 304 revalidation must be recorded");
    }
}

/// A NuGet version is the version NuGet reads, not its spelling: clients put the normal form
/// in lowercase into flat-container URLs (`NuGetVersion.ToNormalizedString()`), so a rule or an
/// allowlist entry holds however it spells its version — `13.0` is `13.0.0`, `1.0.0.0` is
/// `1.0.0`, `2.0.0-Beta1` is `2.0.0-beta1`, build metadata does not count.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod nuget_version_curation {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"NUPKG".to_vec()))
            .mount(&upstream)
            .await;
        upstream
    }

    fn write(dir: &tempfile::TempDir, file: &str, body: &str) -> String {
        let path = dir.path().join(file);
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn nupkg(id: &str, version: &str) -> String {
        format!("/nuget/v3/flatcontainer/{id}/{version}/{id}.{version}.nupkg")
    }

    #[tokio::test]
    async fn a_rule_holds_however_it_spells_its_version() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = write(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [
                {"registry": "nuget", "name": "Evil.Lib", "version": "13.0", "reason": "malware"},
                {"registry": "nuget", "name": "Evil.Lib", "version": "2.0.0-Beta1+build.7", "reason": "malware"},
                {"registry": "nuget", "name": "Evil.Lib", "version": "3.0.0.0", "reason": "malware"}
            ]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        for version in ["13.0.0", "2.0.0-beta1", "3.0.0"] {
            let resp = send(&ctx.app, Method::GET, &nupkg("evil.lib", version), "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{version}");
        }
        for version in ["13.0.1", "2.0.0", "3.0.0.1"] {
            let resp = send(&ctx.app, Method::GET, &nupkg("evil.lib", version), "").await;
            assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{version}");
        }
    }

    #[tokio::test]
    async fn an_allowlist_entry_admits_its_version_however_spelled() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = write(
            &dir,
            "allowlist.json",
            r#"{"version": 1, "entries": [
                {"registry": "nuget", "name": "Newtonsoft.Json", "version": "13.0.1.0"},
                {"registry": "nuget", "name": "Newtonsoft.Json", "version": "14.0.0-Preview.2"}
            ]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        for version in ["13.0.1", "14.0.0-preview.2"] {
            let resp = send(
                &ctx.app,
                Method::GET,
                &nupkg("newtonsoft.json", version),
                "",
            )
            .await;
            assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{version}");
        }
        let resp = send(
            &ctx.app,
            Method::GET,
            &nupkg("newtonsoft.json", "13.0.2"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}

/// How a NuGet download is dated for release age and the quarantine clock. The flat-container
/// download a `dotnet restore` makes never reads the registration, so the date comes from what
/// NORA holds of it, and from the upstream registration when that does not date the version.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod nuget_release_dates {
    use crate::digest_quarantine::QuarantineMode;
    use crate::test_helpers::{
        create_test_context_with_config, put_written_days_ago, reload_curation, send,
        upstream_paths, TestContext,
    };
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ID: &str = "repro.pkg";
    const REGISTRATION: &str = "/v3/registration5-gz-semver2/repro.pkg/index.json";
    const UNLISTED: &str = "1900-01-01T00:00:00+00:00";

    fn minutes_ago(minutes: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::minutes(minutes)).to_rfc3339()
    }

    fn leaf(version: &str, published: &str) -> serde_json::Value {
        serde_json::json!({"catalogEntry": {"version": version, "published": published}})
    }

    fn inline_page(lower: &str, upper: &str, leaves: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({"lower": lower, "upper": upper, "count": leaves.len(), "items": leaves})
    }

    /// A page the index names by its bounds only. Its `@id` is on `elsewhere`, a host that is
    /// not the configured upstream, at the path the page has there: the page is asked of the
    /// configured upstream, so `elsewhere` gets no request.
    fn remote_page(elsewhere: &str, lower: &str, upper: &str) -> serde_json::Value {
        serde_json::json!({
            "@id": format!("{elsewhere}/v3/registration5-gz-semver2/{ID}/page/{lower}/{upper}.json"),
            "lower": lower, "upper": upper, "count": 64
        })
    }

    /// A live host other than the configured upstream, which dates every version a page of it
    /// is asked about — both bounds — as old: a page fetched from it lets a new version pass.
    /// Tests count only its registration requests: wiremock hands a dropped server on to the
    /// next one started, and a background request of an earlier context may still reach it.
    async fn elsewhere() -> MockServer {
        let elsewhere = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/page/[^/]+/[^/]+\.json$"))
            .respond_with(|req: &wiremock::Request| {
                let bounds: Vec<&str> = req.url.path().rsplit('/').take(2).collect();
                let (upper, lower) = (bounds[0].trim_end_matches(".json"), bounds[1]);
                let page = serde_json::json!({
                    "lower": lower, "upper": upper,
                    "items": [leaf(lower, "2019-01-01T00:00:00Z"), leaf(upper, "2019-01-01T00:00:00Z")]
                });
                ResponseTemplate::new(200).set_body_string(page.to_string())
            })
            .mount(&elsewhere)
            .await;
        elsewhere
    }

    /// The prefixes a client reaches the NuGet routes by: its own and the aliases.
    const PREFIXES: [&str; 3] = ["nuget", "chocolatey", "pwsh"];

    fn registration(pages: Vec<serde_json::Value>) -> String {
        serde_json::json!({"count": pages.len(), "items": pages}).to_string()
    }

    /// An upstream whose every package is its own bytes: two versions never share a digest.
    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/v3-flatcontainer/[^/]+/[^/]+/[^/]+\.nupkg$"))
            .respond_with(|req: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_bytes(format!("NUPKG {}", req.url.path()))
            })
            .mount(&upstream)
            .await;
        upstream
    }

    async fn serve_registration(upstream: &MockServer, at: &str, body: String) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(upstream)
            .await;
    }

    fn context(
        upstream: &MockServer,
        trust: bool,
        customize: fn(&mut crate::config::Config),
    ) -> TestContext {
        let uri = upstream.uri();
        create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.server.trust_upstream_dates = trust;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            customize(cfg);
        })
    }

    fn quarantine_7d(cfg: &mut crate::config::Config) {
        cfg.curation.quarantine = Some(QuarantineMode::Enforce);
        cfg.curation.quarantine_ttl = Some("7d".to_string());
    }

    fn min_age_1h(cfg: &mut crate::config::Config) {
        cfg.curation.min_release_age = Some("1h".to_string());
        cfg.curation.quarantine = Some(QuarantineMode::Observe);
    }

    fn min_age_1h_quarantine_7d(cfg: &mut crate::config::Config) {
        cfg.curation.min_release_age = Some("1h".to_string());
        quarantine_7d(cfg);
    }

    /// The registration index as an earlier request cached it `days` ago.
    async fn cached_registration(ctx: &TestContext, body: &str, days: u64) {
        let key = format!("nuget/registration/{ID}/index.json");
        ctx.state.storage.put(&key, body.as_bytes()).await.unwrap();
        let then = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86400);
        std::fs::File::options()
            .write(true)
            .open(std::path::Path::new(&ctx.state.config.storage.path).join(&key))
            .unwrap()
            .set_modified(then)
            .unwrap();
    }

    async fn download(ctx: &TestContext, version: &str) -> StatusCode {
        download_via(ctx, "nuget", version).await
    }

    async fn download_via(ctx: &TestContext, prefix: &str, version: &str) -> StatusCode {
        let uri = format!("/{prefix}/v3/flatcontainer/{ID}/{version}/{ID}.{version}.nupkg");
        send(&ctx.app, Method::GET, &uri, "").await.status()
    }

    async fn registration_requests(upstream: &MockServer) -> usize {
        upstream
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path().starts_with("/v3/registration5-gz-semver2/"))
            .count()
    }

    /// Without trusted dates the quarantine counts from NORA's own first sight of the bytes: a
    /// cached registration's age says when NORA last wrote a listing, not when it first fetched
    /// this package, and a month-old index would let a version first fetched now pass as mature.
    #[tokio::test]
    async fn without_trusted_dates_the_quarantine_counts_from_the_first_fetch() {
        let up = upstream().await;
        let ctx = context(&up, false, quarantine_7d);
        let listed = registration(vec![inline_page(
            "1.2.3",
            "1.2.4",
            vec![
                leaf("1.2.3", "2019-01-01T00:00:00Z"),
                leaf("1.2.4", "2019-01-02T00:00:00Z"),
            ],
        )]);
        cached_registration(&ctx, &listed, 30).await;
        for version in ["1.2.4", "1.2.5"] {
            assert_eq!(
                download(&ctx, version).await,
                StatusCode::FORBIDDEN,
                "{version}: first fetched now, held for 7d whatever the index's age"
            );
        }
    }

    /// A package cached before the quarantine recorded it is counted from now on the cache path
    /// too: without trusted dates neither the month-old registration that lists it nor the
    /// package's own age seeds first-seen.
    #[tokio::test]
    async fn a_package_cached_before_the_quarantine_saw_it_counts_from_now() {
        let up = upstream().await;
        let ctx = context(&up, false, quarantine_7d);
        let listed = registration(vec![inline_page(
            "1.2.4",
            "1.2.4",
            vec![leaf("1.2.4", "2019-01-01T00:00:00Z")],
        )]);
        cached_registration(&ctx, &listed, 30).await;
        put_written_days_ago(
            &ctx,
            &format!("nuget/flatcontainer/{ID}/1.2.4/{ID}.1.2.4.nupkg"),
            b"stored",
            30,
        )
        .await;
        assert_eq!(download(&ctx, "1.2.4").await, StatusCode::FORBIDDEN);
        assert!(
            upstream_paths(&up).await.is_empty(),
            "served from the cache"
        );
    }

    /// Without trusted dates release age is the cached registration's age for a version it
    /// lists (#513), and unknown for one it does not: a version published after the index was
    /// cached was not seen by NORA then.
    #[tokio::test]
    async fn without_trusted_dates_the_index_dates_only_the_versions_it_lists() {
        let up = upstream().await;
        let ctx = context(&up, false, quarantine_7d);
        let listed = registration(vec![inline_page(
            "1.2.3",
            "1.2.3",
            vec![leaf("1.2.3", "2019-01-01T00:00:00Z")],
        )]);
        cached_registration(&ctx, &listed, 30).await;
        let month_ago = chrono::Utc::now().timestamp() - 30 * 86400;
        let listed = super::nuget_publish_date(&ctx.state, ID, "1.2.3", true).await;
        assert!(
            listed.is_some_and(|date| (date - month_ago).abs() < 60),
            "{listed:?}"
        );
        assert_eq!(
            super::nuget_publish_date(&ctx.state, ID, "1.2.4", true).await,
            None
        );
        assert_eq!(
            registration_requests(&up).await,
            0,
            "nothing asked upstream"
        );
    }

    /// Release age without trusted dates is NORA's own: a version the registration listed when
    /// NORA cached it minutes ago is minutes old, one it did not list is undated and left to the
    /// quarantine.
    #[tokio::test]
    async fn without_trusted_dates_release_age_is_the_listing_age() {
        let up = upstream().await;
        let ctx = context(&up, false, min_age_1h);
        let listed = registration(vec![inline_page(
            "1.2.3",
            "1.2.3",
            vec![leaf("1.2.3", "2019-01-01T00:00:00Z")],
        )]);
        cached_registration(&ctx, &listed, 0).await;
        assert_eq!(
            download(&ctx, "1.2.3").await,
            StatusCode::FORBIDDEN,
            "listed when NORA cached it just now"
        );
        assert_eq!(download(&ctx, "1.2.4").await, StatusCode::OK, "undated");
    }

    /// With trusted dates a version the cache has no date for is dated by the upstream
    /// registration: `dotnet restore` reads only the flat container, so a package published
    /// minutes ago would otherwise pass `min_release_age` undated.
    #[tokio::test]
    async fn an_undated_version_is_dated_by_the_upstream_registration() {
        let up = upstream().await;
        serve_registration(
            &up,
            REGISTRATION,
            registration(vec![inline_page(
                "1.0.0",
                "2.0.0",
                vec![
                    leaf("1.0.0", "2019-01-01T00:00:00Z"),
                    leaf("2.0.0", &minutes_ago(10)),
                ],
            )]),
        )
        .await;
        let ctx = context(&up, true, min_age_1h);
        assert_eq!(
            download(&ctx, "2.0.0").await,
            StatusCode::FORBIDDEN,
            "published 10 minutes ago, younger than 1h"
        );
        assert_eq!(download(&ctx, "1.0.0").await, StatusCode::OK);
    }

    /// A release-age rule of NuGet's own reads the date as the global one does: without a
    /// global rule or a quarantine, the upstream registration still dates the version.
    #[tokio::test]
    async fn a_release_age_rule_of_nuget_alone_asks_the_upstream_for_the_date() {
        let up = upstream().await;
        serve_registration(
            &up,
            REGISTRATION,
            registration(vec![inline_page(
                "1.0.0",
                "2.0.0",
                vec![
                    leaf("1.0.0", "2019-01-01T00:00:00Z"),
                    leaf("2.0.0", &minutes_ago(10)),
                ],
            )]),
        )
        .await;
        let ctx = context(&up, true, |cfg| {
            cfg.curation.nuget.min_release_age = Some("1h".to_string());
        });
        assert_eq!(
            download(&ctx, "2.0.0").await,
            StatusCode::FORBIDDEN,
            "published 10 minutes ago, younger than NuGet's 1h"
        );
        assert_eq!(download(&ctx, "1.0.0").await, StatusCode::OK);
    }

    /// A cached registration that predates the version does not date it either: the
    /// upstream one, which lists it, does.
    #[tokio::test]
    async fn a_version_newer_than_the_cached_registration_is_dated_by_the_upstream() {
        let up = upstream().await;
        serve_registration(
            &up,
            REGISTRATION,
            registration(vec![inline_page(
                "1.0.0",
                "2.0.0",
                vec![
                    leaf("1.0.0", "2019-01-01T00:00:00Z"),
                    leaf("2.0.0", &minutes_ago(10)),
                ],
            )]),
        )
        .await;
        let ctx = context(&up, true, min_age_1h);
        let stale = registration(vec![inline_page(
            "1.0.0",
            "1.0.0",
            vec![leaf("1.0.0", "2019-01-01T00:00:00Z")],
        )]);
        cached_registration(&ctx, &stale, 1).await;
        assert_eq!(download(&ctx, "2.0.0").await, StatusCode::FORBIDDEN);
        assert_eq!(download(&ctx, "1.0.0").await, StatusCode::OK);
    }

    /// Past 128 versions the registration index carries only page bounds: the version's date
    /// is on the page whose range holds it, its bounds included.
    #[tokio::test]
    async fn a_version_on_a_page_the_index_does_not_inline_is_dated_by_that_page() {
        let up = upstream().await;
        let elsewhere = elsewhere().await;
        serve_registration(
            &up,
            REGISTRATION,
            registration(vec![
                remote_page(&elsewhere.uri(), "1.0.0", "1.0.128"),
                remote_page(&elsewhere.uri(), "1.0.129", "1.0.140"),
            ]),
        )
        .await;
        serve_registration(
            &up,
            "/v3/registration5-gz-semver2/repro.pkg/page/1.0.129/1.0.140.json",
            serde_json::json!({
                "lower": "1.0.129", "upper": "1.0.140", "count": 3,
                "items": [
                    leaf("1.0.129", &minutes_ago(10)),
                    leaf("1.0.130", "2019-01-01T00:00:00Z"),
                    leaf("1.0.140", &minutes_ago(10))
                ]
            })
            .to_string(),
        )
        .await;
        let ctx = context(&up, true, min_age_1h);
        assert_eq!(
            download(&ctx, "1.0.129").await,
            StatusCode::FORBIDDEN,
            "lower bound"
        );
        assert_eq!(download(&ctx, "1.0.130").await, StatusCode::OK);
        assert_eq!(
            download(&ctx, "1.0.140").await,
            StatusCode::FORBIDDEN,
            "upper bound"
        );
        let pages: Vec<String> = up
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .filter(|p| p.contains("/page/"))
            .collect();
        assert!(
            pages
                .iter()
                .all(|p| p.ends_with("/page/1.0.129/1.0.140.json")),
            "only the page whose range holds the version is asked for: {pages:?}"
        );
        assert_eq!(registration_requests(&elsewhere).await, 0);
    }

    /// A page holds the versions from its lower bound to its upper bound, both included; a
    /// version outside every page's range — a pre-release between two pages too — is on none.
    #[test]
    fn a_page_holds_the_versions_between_its_bounds_inclusive() {
        use super::{registered, Registered};
        let index = registration(vec![
            remote_page("https://elsewhere.example", "1.0.0", "1.0.128"),
            remote_page("https://elsewhere.example", "1.0.129", "1.0.140"),
        ]);
        let on = |lower: &str, upper: &str| Registered::OnPage {
            lower: lower.to_string(),
            upper: upper.to_string(),
        };
        for (version, want) in [
            ("0.9.9", Registered::Absent),
            ("1.0.0", on("1.0.0", "1.0.128")),
            ("1.0.64", on("1.0.0", "1.0.128")),
            ("1.0.128", on("1.0.0", "1.0.128")),
            ("1.0.129-beta", Registered::Absent),
            ("1.0.129", on("1.0.129", "1.0.140")),
            ("1.0.140-rc.1", on("1.0.129", "1.0.140")),
            ("1.0.140", on("1.0.129", "1.0.140")),
            ("1.0.140.1", Registered::Absent),
            ("1.0.141", Registered::Absent),
        ] {
            assert_eq!(registered(index.as_bytes(), version), want, "{version}");
        }
    }

    /// NuGet publishes an unlisted version as `1900-01-01`: that marks the date unknown, it
    /// does not make the version 126 years old, nor as old as the cached document carrying the
    /// marker — the index or the page that lists it.
    #[tokio::test]
    async fn the_unlisted_marker_does_not_date_a_version() {
        let leaves = || {
            vec![
                leaf("0.9.0", "2019-01-01T00:00:00Z"),
                leaf("1.0.0", UNLISTED),
            ]
        };
        for on_page in [false, true] {
            let up = upstream().await;
            let elsewhere = elsewhere().await;
            let ctx = context(&up, true, min_age_1h_quarantine_7d);
            if on_page {
                let index = registration(vec![remote_page(&elsewhere.uri(), "0.9.0", "1.0.0")]);
                cached_registration(&ctx, &index, 30).await;
                let page =
                    serde_json::json!({"lower": "0.9.0", "upper": "1.0.0", "items": leaves()});
                put_written_days_ago(
                    &ctx,
                    &format!("nuget/registration/{ID}/page/0.9.0/1.0.0.json"),
                    page.to_string().as_bytes(),
                    30,
                )
                .await;
            } else {
                let index = registration(vec![inline_page("0.9.0", "1.0.0", leaves())]);
                cached_registration(&ctx, &index, 30).await;
            }
            assert_eq!(
                download(&ctx, "1.0.0").await,
                StatusCode::FORBIDDEN,
                "on a page: {on_page}; an undated version is held on NORA's own clock"
            );
            assert_eq!(
                download(&ctx, "0.9.0").await,
                StatusCode::OK,
                "on a page: {on_page}"
            );
            assert_eq!(registration_requests(&up).await, 0, "on a page: {on_page}");
            assert_eq!(
                registration_requests(&elsewhere).await,
                0,
                "on a page: {on_page}"
            );
        }
    }

    /// A package NORA already stores asks the upstream for no date, whatever case the client
    /// spells its path in and whichever prefix it comes by: its digest is recorded, and a cache
    /// hit does not pay an upstream round-trip.
    #[tokio::test]
    async fn a_stored_package_asks_the_upstream_for_no_date() {
        let up = upstream().await;
        let ctx = context(&up, true, min_age_1h);
        for version in ["3.0.0", "3.0.1-beta"] {
            ctx.state
                .storage
                .put(
                    &format!("nuget/flatcontainer/{ID}/{version}/{ID}.{version}.nupkg"),
                    b"stored",
                )
                .await
                .unwrap();
        }
        for uri in [
            "/nuget/v3/flatcontainer/repro.pkg/3.0.0/repro.pkg.3.0.0.nupkg",
            "/nuget/v3/flatcontainer/Repro.Pkg/3.0.0/Repro.Pkg.3.0.0.nupkg",
            "/nuget/v3/flatcontainer/repro.pkg/3.0.0/REPRO.PKG.3.0.0.NUPKG",
            "/nuget/v3/flatcontainer/Repro.Pkg/3.0.1-Beta/Repro.Pkg.3.0.1-Beta.nupkg",
            "/chocolatey/v3/flatcontainer/Repro.Pkg/3.0.0/Repro.Pkg.3.0.0.nupkg",
            "/pwsh/v3/flatcontainer/REPRO.PKG/3.0.1-BETA/repro.pkg.3.0.1-beta.nupkg",
        ] {
            assert_eq!(
                send(&ctx.app, Method::GET, uri, "").await.status(),
                StatusCode::OK,
                "{uri}"
            );
            assert_eq!(registration_requests(&up).await, 0, "{uri}");
        }
        assert!(
            upstream_paths(&up).await.is_empty(),
            "served from the cache"
        );
    }

    /// With trusted dates the quarantine takes the release date too (#750): a version published
    /// years ago is not held as new to this mirror, also when only the upstream dates it.
    #[tokio::test]
    async fn with_trusted_dates_an_old_version_matures_in_the_quarantine() {
        let up = upstream().await;
        serve_registration(
            &up,
            REGISTRATION,
            registration(vec![inline_page(
                "1.0.0",
                "2.0.0",
                vec![
                    leaf("1.0.0", "2019-01-01T00:00:00Z"),
                    leaf("2.0.0", &minutes_ago(10)),
                ],
            )]),
        )
        .await;
        let ctx = context(&up, true, quarantine_7d);
        assert_eq!(download(&ctx, "1.0.0").await, StatusCode::OK);
        assert_eq!(download(&ctx, "2.0.0").await, StatusCode::FORBIDDEN);
    }

    /// Nothing reads a date without a release-age rule or the quarantine: the upstream is not
    /// asked for one.
    #[tokio::test]
    async fn no_date_is_asked_for_when_nothing_reads_it() {
        let up = upstream().await;
        let uri = up.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
        });
        assert_eq!(download(&ctx, "4.0.0").await, StatusCode::OK);
        assert_eq!(registration_requests(&up).await, 0);
    }

    /// A release-age rule a reload brings in asks the upstream for the date from then on: the
    /// engine the reload installs is what curation decides with, not the configuration NORA
    /// started with — the global rule and NuGet's own alike.
    #[tokio::test]
    async fn a_release_age_rule_a_reload_brings_in_asks_the_upstream_for_the_date() {
        let rules: [(&str, fn(&mut crate::config::Config)); 2] = [
            ("global", min_age_1h),
            ("NuGet's own", |cfg| {
                cfg.curation.nuget.min_release_age = Some("1h".to_string());
                cfg.curation.quarantine = Some(QuarantineMode::Observe);
            }),
        ];
        for (rule, add) in rules {
            let up = upstream().await;
            serve_registration(
                &up,
                REGISTRATION,
                registration(vec![inline_page(
                    "1.0.0",
                    "2.0.0",
                    vec![
                        leaf("1.0.0", "2019-01-01T00:00:00Z"),
                        leaf("2.0.0", &minutes_ago(10)),
                    ],
                )]),
            )
            .await;
            let ctx = context(&up, true, |_| {});
            reload_curation(&ctx, add);
            assert_eq!(
                download(&ctx, "2.0.0").await,
                StatusCode::FORBIDDEN,
                "{rule}: published 10 minutes ago, younger than 1h"
            );
            assert_eq!(download(&ctx, "1.0.0").await, StatusCode::OK, "{rule}");
        }
    }

    /// A quarantine switched off reads no date, and neither does a release-age rule while
    /// curation is off: the upstream is not asked for one. NuGet's own `off` overrides a global
    /// quarantine.
    #[tokio::test]
    async fn a_policy_switched_off_asks_for_no_date() {
        let switched_off: [(&str, fn(&mut crate::config::Config)); 3] = [
            ("quarantine off", |cfg| {
                cfg.curation.quarantine = Some(QuarantineMode::Off);
            }),
            ("NuGet's quarantine off", |cfg| {
                cfg.curation.quarantine = Some(QuarantineMode::Enforce);
                cfg.curation.nuget.quarantine = Some(QuarantineMode::Off);
            }),
            ("curation off", |cfg| {
                cfg.curation.mode = crate::config::CurationMode::Off;
                cfg.curation.min_release_age = Some("1h".to_string());
                cfg.curation.nuget.min_release_age = Some("1h".to_string());
            }),
        ];
        for (policy, customize) in switched_off {
            let up = upstream().await;
            let ctx = context(&up, true, customize);
            assert_eq!(download(&ctx, "4.0.0").await, StatusCode::OK, "{policy}");
            assert_eq!(registration_requests(&up).await, 0, "{policy}");
        }
    }

    /// The date is asked of the configured upstream only: with the upstream switched off —
    /// absent or blank — no request leaves NORA for a date, the public default host included.
    #[tokio::test]
    async fn the_date_is_asked_of_the_configured_upstream_only() {
        use crate::test_helpers::{create_test_context_with_egress_proxy, EgressRecorder};
        for proxy in [None, Some("  ".to_string())] {
            let recorder = EgressRecorder::start().await;
            let switched_off = proxy.clone();
            let ctx = create_test_context_with_egress_proxy(&recorder.url, move |cfg| {
                cfg.nuget.enabled = true;
                cfg.nuget.proxy = switched_off;
                cfg.nuget.metadata_proxy_timeout = 2;
                cfg.server.trust_upstream_dates = true;
                cfg.circuit_breaker.enabled = true;
                min_age_1h_quarantine_7d(cfg);
            });
            assert_eq!(
                download(&ctx, "1.0.0").await,
                StatusCode::NOT_FOUND,
                "{proxy:?}"
            );
            // The breaker is asked before every upstream request; the recorder sees any request.
            assert!(
                ctx.state.circuit_breaker.keys().is_empty(),
                "{proxy:?}: {:?}",
                ctx.state.circuit_breaker.keys()
            );
            assert!(
                recorder.seen().await.is_empty(),
                "{proxy:?}: {:?}",
                recorder.seen().await
            );
        }
    }

    /// What a registration document says of a version, decided from the document alone: the
    /// version's own leaf dates it, on whichever inline page lists it — the first, a later one,
    /// the last — and never a leaf whose version merely begins with it; a version within the
    /// bounds of a page the index does not inline, both bounds included, is on that page; the
    /// unlisted marker dates nothing. Versions compare as NuGet compares them: case, a missing
    /// trailing zero and build metadata do not count.
    #[test]
    fn a_registration_document_dates_a_version_by_its_own_leaf() {
        use super::{registered, Registered};
        const Y2019: &str = "2019-01-01T00:00:00Z";
        const Y2023: &str = "2023-01-01T00:00:00Z";
        const Y2024: &str = "2024-01-01T00:00:00Z";
        const MID2024: &str = "2024-06-01T00:00:00Z";
        const Y2025: &str = "2025-01-01T00:00:00Z";
        let y2019 = || Registered::Listed(Some(1_546_300_800));
        let y2023 = || Registered::Listed(Some(1_672_531_200));
        let y2024 = || Registered::Listed(Some(1_704_067_200));
        let mid2024 = || Registered::Listed(Some(1_717_200_000));
        let y2025 = || Registered::Listed(Some(1_735_689_600));
        let unlisted = || Registered::Listed(None);
        let on = |lower: &str, upper: &str| Registered::OnPage {
            lower: lower.to_string(),
            upper: upper.to_string(),
        };
        let index = registration(vec![
            inline_page(
                "1.0.0",
                "1.0.10",
                vec![
                    leaf("1.0.10", Y2019),
                    leaf("1.0.1", MID2024),
                    leaf("1.0.1-beta", Y2023),
                    leaf("1.0.0", Y2024),
                ],
            ),
            inline_page(
                "2.0.0",
                "2.0.5",
                vec![leaf("2.0.0", Y2025), leaf("2.0.5-RC.1", Y2023)],
            ),
            remote_page("https://elsewhere.example", "3.0.0", "3.0.9"),
            inline_page("4.0.0", "4.0.0", vec![leaf("4.0.0", UNLISTED)]),
            inline_page("5.0.0", "5.0.0", vec![leaf("5.0.0", Y2024)]),
        ]);
        let page = serde_json::json!({
            "lower": "3.0.0", "upper": "3.0.9",
            "items": [
                leaf("3.0.0", UNLISTED),
                leaf("3.0.1-beta", Y2019),
                leaf("3.0.1", Y2023),
                leaf("3.0.9", Y2025)
            ]
        })
        .to_string();
        for (doc, version, want) in [
            (&index, "1.0.1", mid2024()),
            (&index, "1.0.1-beta", y2023()),
            (&index, "1.0.1-BETA", y2023()),
            (&index, "1.0", y2024()),
            (&index, "1.0.0+build", y2024()),
            (&index, "1.0.10", y2019()),
            (&index, "1.0.2", Registered::Absent),
            (&index, "2.0.0", y2025()),
            (&index, "2.0.5-rc.1", y2023()),
            (&index, "2.0.5", Registered::Absent),
            (&index, "2.9.9", Registered::Absent),
            (&index, "3.0.0", on("3.0.0", "3.0.9")),
            (&index, "3.0.1", on("3.0.0", "3.0.9")),
            (&index, "3.0.9", on("3.0.0", "3.0.9")),
            (&index, "3.0.9.1", Registered::Absent),
            (&index, "4.0.0", unlisted()),
            (&index, "5.0.0", y2024()),
            (&index, "5.0", y2024()),
            (&index, "5.0.0-alpha", Registered::Absent),
            (&page, "3.0.0", unlisted()),
            (&page, "3.0.1", y2023()),
            (&page, "3.0.1-beta", y2019()),
            (&page, "3.0.9", y2025()),
            (&page, "3.0.2", Registered::Absent),
            (&page, "3.0", unlisted()),
        ] {
            assert_eq!(registered(doc.as_bytes(), version), want, "{version}");
        }
    }

    /// The upstream index dates a version on whichever of its inline pages lists it, through
    /// every prefix a client comes by: one on the second page, published minutes ago, is held.
    #[tokio::test]
    async fn a_version_on_a_later_inline_page_of_the_upstream_index_is_dated() {
        for prefix in PREFIXES {
            let up = upstream().await;
            serve_registration(
                &up,
                REGISTRATION,
                registration(vec![
                    inline_page(
                        "1.0.0",
                        "1.0.0",
                        vec![leaf("1.0.0", "2019-01-01T00:00:00Z")],
                    ),
                    inline_page("2.0.0", "2.0.0", vec![leaf("2.0.0", &minutes_ago(10))]),
                ]),
            )
            .await;
            let ctx = context(&up, true, min_age_1h);
            assert_eq!(
                download_via(&ctx, prefix, "2.0.0").await,
                StatusCode::FORBIDDEN,
                "{prefix}: on the second page, published 10 minutes ago"
            );
            assert_eq!(
                download_via(&ctx, prefix, "1.0.0").await,
                StatusCode::OK,
                "{prefix}"
            );
        }
    }

    /// A version is dated by its own leaf, not one whose version begins with it: listed after
    /// a 2019 `1.0.10` and a 2019 `1.0.1-beta`, a `1.0.1` published minutes ago is held.
    #[tokio::test]
    async fn a_version_is_not_dated_by_one_it_prefixes() {
        for prefix in PREFIXES {
            let up = upstream().await;
            serve_registration(
                &up,
                REGISTRATION,
                registration(vec![inline_page(
                    "1.0.1-beta",
                    "1.0.10",
                    vec![
                        leaf("1.0.10", "2019-01-01T00:00:00Z"),
                        leaf("1.0.1-beta", "2019-01-01T00:00:00Z"),
                        leaf("1.0.1", &minutes_ago(10)),
                    ],
                )]),
            )
            .await;
            let ctx = context(&up, true, min_age_1h);
            assert_eq!(
                download_via(&ctx, prefix, "1.0.1").await,
                StatusCode::FORBIDDEN,
                "{prefix}: 1.0.1 is not 1.0.10 nor 1.0.1-beta"
            );
            assert_eq!(
                download_via(&ctx, prefix, "1.0.10").await,
                StatusCode::OK,
                "{prefix}"
            );
        }
    }

    /// The page a version is on is asked of the configured upstream, never of the host the
    /// upstream index names in the page's `@id`: that host, live and dating the version as
    /// old, gets no request, and the version published minutes ago is held.
    #[tokio::test]
    async fn the_page_is_asked_of_the_configured_upstream_not_the_index_s_at_id() {
        for prefix in PREFIXES {
            let up = upstream().await;
            let elsewhere = elsewhere().await;
            serve_registration(
                &up,
                REGISTRATION,
                registration(vec![remote_page(&elsewhere.uri(), "1.0.129", "1.0.140")]),
            )
            .await;
            serve_registration(
                &up,
                "/v3/registration5-gz-semver2/repro.pkg/page/1.0.129/1.0.140.json",
                serde_json::json!({
                    "lower": "1.0.129", "upper": "1.0.140",
                    "items": [leaf("1.0.129", &minutes_ago(10))]
                })
                .to_string(),
            )
            .await;
            let ctx = context(&up, true, min_age_1h);
            assert_eq!(
                download_via(&ctx, prefix, "1.0.129").await,
                StatusCode::FORBIDDEN,
                "{prefix}"
            );
            assert_eq!(
                registration_requests(&elsewhere).await,
                0,
                "{prefix}: the host of the page's @id was asked"
            );
        }
    }

    /// The URL a registration document is asked at is built from the configured upstream
    /// alone, with a package id and versions as its only segments: a segment that would leave
    /// the registration path or the host — a slash, `..`, a query, a scheme — names no URL.
    #[test]
    fn a_registration_document_is_asked_of_the_configured_upstream_only() {
        use super::{registration_url, RegistrationDoc};
        const UP: &str = "https://feed.internal";
        let page = |lower, upper| RegistrationDoc::Page { lower, upper };
        let base = "https://feed.internal/v3/registration5-gz-semver2/repro.pkg";
        for (upstream, id, doc, want) in [
            (
                UP,
                ID,
                RegistrationDoc::Index,
                Some(format!("{base}/index.json")),
            ),
            (
                "https://feed.internal/",
                ID,
                RegistrationDoc::Index,
                Some(format!("{base}/index.json")),
            ),
            (
                UP,
                ID,
                page("1.0.0", "2.0.0-rc.1+b"),
                Some(format!("{base}/page/1.0.0/2.0.0-rc.1+b.json")),
            ),
            (UP, "a/b", RegistrationDoc::Index, None),
            (UP, "..", RegistrationDoc::Index, None),
            (UP, "x?y", RegistrationDoc::Index, None),
            (UP, "", RegistrationDoc::Index, None),
            (UP, ID, page("1.0.0", "https://elsewhere.example/x"), None),
            (UP, ID, page("../../x", "2.0.0"), None),
            (UP, ID, page("1.0.0", "2.0.0?at=elsewhere"), None),
            (UP, ID, page("1.0.0", "2.0.0#x"), None),
            (UP, ID, page("1.0.0", "2.0.0\\x"), None),
            (UP, ID, page("", "2.0.0"), None),
            (UP, ID, page("1.0.0", "@elsewhere.example"), None),
        ] {
            let url = registration_url(upstream, id, doc);
            assert_eq!(url, want, "{upstream} {id} {doc:?}");
            if let Some(url) = url {
                assert!(url.starts_with("https://feed.internal/v3/registration5-gz-semver2/"));
            }
        }
    }

    #[test]
    fn nuget_versions_order_as_nuget_orders_them() {
        use super::nuget_version_order;
        use std::cmp::Ordering::{Equal, Greater, Less};
        for (a, b, want) in [
            ("1.0.0", "1.0.0", Equal),
            ("1.0", "1.0.0.0", Equal),
            ("1.0.0+build", "1.0.0", Equal),
            ("1.0.0-Beta", "1.0.0-beta", Equal),
            ("1.0.9", "1.0.10", Less),
            ("1.0.0.1", "1.0.0", Greater),
            ("1.0.0-alpha", "1.0.0", Less),
            ("1.0.0-alpha", "1.0.0-alpha.1", Less),
            ("1.0.0-alpha.2", "1.0.0-alpha.10", Less),
            ("1.0.0-2", "1.0.0-alpha", Less),
            ("1.0.0-beta", "1.0.0-alpha", Greater),
            ("2.0.0", "10.0.0", Less),
        ] {
            assert_eq!(nuget_version_order(a, b), Some(want), "{a} vs {b}");
        }
        assert_eq!(nuget_version_order("not.a.version.x", "1.0.0"), None);
    }
}
