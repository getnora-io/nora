// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Ansible Galaxy collection proxy (API v3).
//!
//! Implements a caching proxy for galaxy.ansible.com:
//!   GET /ansible/                                         — API discovery
//!   GET /ansible/v3/collections/                          — collection list (short path)
//!   GET /ansible/v3/collections/{ns}/{name}/              — collection detail
//!   GET /ansible/v3/collections/{ns}/{name}/versions/     — version list
//!   GET /ansible/v3/collections/{ns}/{name}/versions/{ver}/ — version detail
//!   GET /ansible/download/{ns}-{name}-{ver}.tar.gz        — tarball (immutable)
//!   GET /ansible/api/v3/.../artifacts/{file}              — tarball alias (Galaxy format)
//!
//! Also supports full Pulp-style paths under /ansible/api/v3/plugin/ansible/...
//!
//! Namespace and collection names follow Galaxy spec: [a-z0-9_]+ (no hyphens).
//!
//! Client config:
//!   ansible-galaxy collection install community.general -s http://nora:4000/ansible/

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::config::UpstreamAuth;
use crate::registry::{
    circuit_open_response, nora_base_url, proxy_fetch, proxy_fetch_conditional, read_validators,
    write_validators, ProxyError, Revalidation, Validators,
};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::time::Duration;

// The rewrite of upstream Galaxy URLs is the one the fuzz target drives.
use nora_registry::upstream_rewrite::{rewrite_ansible_urls, ANSIBLE_API_PREFIX as API_PREFIX};

const UPSTREAM_DEFAULT: &str = "https://galaxy.ansible.com";

/// Storage prefix and file suffix for repo index scanning.
pub const INDEX_PATTERN: (&str, &str) = ("ansible/", ".tar.gz");

pub fn routes() -> Router<AppState> {
    Router::new()
        // Galaxy API discovery (ansible-galaxy CLI hits this first)
        .route("/ansible/", get(api_discovery))
        .route("/ansible/api/", get(api_discovery))
        // Short v3 paths (ansible-galaxy --api-version 3 format)
        .route("/ansible/v3/collections/", get(collection_list))
        .route(
            "/ansible/v3/collections/{ns}/{name}/",
            get(collection_detail),
        )
        .route(
            "/ansible/v3/collections/{ns}/{name}/versions/",
            get(version_list),
        )
        .route(
            "/ansible/v3/collections/{ns}/{name}/versions/{ver}/",
            get(version_detail),
        )
        // Full pulp-style paths (direct API access)
        .route(
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/",
            get(collection_list),
        )
        .route(
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/{ns}/{name}/",
            get(collection_detail),
        )
        .route(
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/{ns}/{name}/versions/",
            get(version_list),
        )
        .route(
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/{ns}/{name}/versions/{ver}/",
            get(version_detail),
        )
        // Collection tarball download (immutable)
        .route("/ansible/download/{filename}", get(download_tarball))
        // Artifact path alias — upstream Galaxy serves tarballs here too (#438)
        .route(
            "/ansible/api/v3/plugin/ansible/content/published/collections/artifacts/{filename}",
            get(download_tarball),
        )
}

// ── API discovery ─────────────────────────────────────────────────────

async fn api_discovery() -> Response {
    let body = r#"{"available_versions":{"v3":"v3/"}}"#;
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}

// ── Collection list ────────────────────────────────────────────────────

async fn collection_list(State(state): State<AppState>, RawQuery(raw_query): RawQuery) -> Response {
    // proxy_json answers from storage alone when the upstream is switched off.
    let proxy_url = upstream_url(&state).unwrap_or_default();
    let base = format!("{}{}/", proxy_url.trim_end_matches('/'), API_PREFIX);
    let url = append_query(&base, raw_query.as_deref());

    let cache_key = match extract_page_param(raw_query.as_deref()) {
        Some(page) => format!("ansible/metadata/collections-page-{}.json", page),
        None => "ansible/metadata/collections.json".to_string(),
    };

    proxy_json(&state, &url, "ansible-collections", &cache_key, None).await
}

// ── Collection detail ──────────────────────────────────────────────────

async fn collection_detail(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> Response {
    if !is_valid_name(&ns) || !is_valid_name(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // proxy_json answers from storage alone when the upstream is switched off.
    let proxy_url = upstream_url(&state).unwrap_or_default();
    let url = format!(
        "{}{}/{}/{}/",
        proxy_url.trim_end_matches('/'),
        API_PREFIX,
        ns,
        name
    );

    let cache_key = format!("ansible/metadata/{}/{}.json", ns, name);
    proxy_json(
        &state,
        &url,
        &format!("{}.{}", ns, name),
        &cache_key,
        Some(&format!("{}.{}", ns, name)),
    )
    .await
}

// ── Version listing ────────────────────────────────────────────────────

async fn version_list(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    if !is_valid_name(&ns) || !is_valid_name(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // proxy_json answers from storage alone when the upstream is switched off.
    let proxy_url = upstream_url(&state).unwrap_or_default();
    let base = format!(
        "{}{}/{}/{}/versions/",
        proxy_url.trim_end_matches('/'),
        API_PREFIX,
        ns,
        name
    );
    let url = append_query(&base, raw_query.as_deref());

    let cache_key = match extract_page_param(raw_query.as_deref()) {
        Some(page) => format!(
            "ansible/metadata/{}/{}/versions-page-{}.json",
            ns, name, page
        ),
        None => format!("ansible/metadata/{}/{}/versions.json", ns, name),
    };

    proxy_json(
        &state,
        &url,
        &format!("{}.{}/versions", ns, name),
        &cache_key,
        Some(&format!("{}.{}", ns, name)),
    )
    .await
}

// ── Version detail ─────────────────────────────────────────────────────

async fn version_detail(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((ns, name, ver)): Path<(String, String, String)>,
) -> Response {
    if !is_valid_name(&ns) || !is_valid_name(&name) || !is_valid_version(&ver) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Curation check. #733: an internal-namespace collection is operator-owned — skip curation;
    // proxy_json below already serves any local copy and blocks the upstream branch for internal.
    if !crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Ansible,
        &format!("{}.{}", ns, name),
    ) {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Ansible,
            &format!("{}.{}", ns, name),
            crate::curation::RequestVersion::Known(ver.to_string()),
            None,
        ) {
            return response;
        }
    }

    // proxy_json answers from storage alone when the upstream is switched off.
    let proxy_url = upstream_url(&state).unwrap_or_default();
    let url = format!(
        "{}{}/{}/{}/versions/{}/",
        proxy_url.trim_end_matches('/'),
        API_PREFIX,
        ns,
        name,
        ver
    );

    let cache_key = format!("ansible/metadata/{}/{}/{}.json", ns, name, ver);
    proxy_json(
        &state,
        &url,
        &format!("{}.{} v{}", ns, name, ver),
        &cache_key,
        Some(&format!("{}.{}", ns, name)),
    )
    .await
}

/// Per-version `created_at` from cached Galaxy metadata (#748/#750).
///
/// Prefers the per-version detail JSON (`{ver}.json`, cached when the client
/// fetches version metadata immediately before download) — it carries the exact
/// version's `created_at` at top level with no pagination concern. Falls back to
/// the first page of the versions listing (`versions.json`), which only holds the
/// most recent versions for large collections (Galaxy paginates). Any miss →
/// `None` (the quarantine falls back to NORA's own first-seen clock).
async fn extract_ansible_publish_date(
    storage: &crate::storage::Storage,
    ns: &str,
    name: &str,
    ver: &str,
) -> Option<i64> {
    // Per-version detail (top-level created_at; works for any version).
    let ver_key = format!("ansible/metadata/{}/{}/{}.json", ns, name, ver);
    if let Ok(data) = storage.get(&ver_key).await {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) {
            if let Some(date_str) = json
                .get("created_at")
                .or_else(|| json.get("created"))
                .and_then(|v| v.as_str())
            {
                if let Some(ts) = crate::curation::parse_iso8601_to_unix(date_str) {
                    return Some(ts);
                }
            }
        }
    }

    // First-page versions listing (data[]; recent versions only).
    let key = format!("ansible/metadata/{}/{}/versions.json", ns, name);
    let data = storage.get(&key).await.ok()?;
    let json: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let entries = json.get("data").and_then(|d| d.as_array())?;
    let entry = entries
        .iter()
        .find(|e| e.get("version").and_then(|v| v.as_str()) == Some(ver))?;
    let date_str = entry
        .get("created_at")
        .or_else(|| entry.get("created"))?
        .as_str()?;
    crate::curation::parse_iso8601_to_unix(date_str)
}

// ── Tarball download (immutable) ───────────────────────────────────────

async fn download_tarball(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(filename): Path<String>,
) -> Response {
    // filename = "namespace-name-version.tar.gz"
    if !filename.ends_with(".tar.gz") || !is_safe_filename(&filename) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Parse namespace, name, version from filename
    let stem = filename.strip_suffix(".tar.gz").unwrap_or(&filename);
    let parts: Vec<&str> = stem.splitn(3, '-').collect();
    if parts.len() < 3 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let (ns, name, ver) = (parts[0], parts[1], parts[2]);

    if !is_valid_name(ns) || !is_valid_name(name) || !is_valid_version(ver) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!("ansible/download/{}", filename);

    // Release date for the digest-quarantine first-seen clock (#748/#750): the
    // Galaxy versions metadata (cached by version_list) carries per-version
    // created_at. Hosted-only uses mtime.
    let publish_date = if upstream_url(&state).is_none() {
        crate::curation::extract_mtime_as_publish_date(&state.storage, &storage_key).await
    } else if state.config.server.trust_upstream_dates {
        extract_ansible_publish_date(&state.storage, ns, name, ver).await
    } else {
        None
    };

    // Curation check. #733 serve-local: an internal-namespace collection is operator-owned — skip
    // curation and serve any local copy below; block the upstream branch separately.
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Ansible,
        &format!("{}.{}", ns, name),
    );
    if !internal {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Ansible,
            &format!("{}.{}", ns, name),
            crate::curation::RequestVersion::Known(ver.to_string()),
            publish_date,
        ) {
            return response;
        }
    }

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
        // Integrity check
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Ansible,
            &format!("{}.{}", ns, name),
            Some(ver),
            &data,
        ) {
            return response;
        }

        let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
            state.config.curation.ansible.quarantine.as_ref().or(state
                .config
                .curation
                .quarantine
                .as_ref()),
            state
                .config
                .curation
                .ansible
                .quarantine_ttl
                .as_deref()
                .or(state.config.curation.quarantine_ttl.as_deref()),
        );
        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "ansible",
            &data,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }

        // Range request: 206 Partial Content, or 416 when the client asks past the
        // end. The gates above ran on the whole object; the partial body itself
        // cannot be rehashed, so the client's own checksum covers it (#657).
        if let Some(response) = crate::registry::range::range_response(
            &state.storage,
            &[&storage_key],
            &headers,
            data.len() as u64,
            "application/gzip",
            &[],
        )
        .await
        {
            if response.status() == StatusCode::PARTIAL_CONTENT {
                state.metrics.record_download("ansible");
                state.metrics.record_cache_hit("ansible");
            }
            return response;
        }

        state.metrics.record_download("ansible");
        state.metrics.record_cache_hit("ansible");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            filename,
            crate::registry_type::RegistryType::Ansible,
            "CACHE",
        ));
        return with_binary(data.to_vec());
    }

    // #733: an internal-namespace collection with no local copy is never proxied upstream.
    if internal {
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("ansible", &storage_key, e);
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Ansible,
            &format!("{}.{}", ns, name),
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // Fetch from upstream — none when the operator switched it off.
    let Some(proxy_url) = upstream_url(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let url = format!(
        "{}/download/{}-{}-{}.tar.gz",
        proxy_url.trim_end_matches('/'),
        ns,
        name,
        ver
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.ansible.proxy_timeout),
        expose_opt(&state.config.ansible.proxy_auth).map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        RegistryType::Ansible,
    )
    .await
    {
        Ok(bytes) => {
            // The allowlist's pinned integrity holds on the first download too, before anything is cached:
            // the cache-hit branch checks the same rule.
            if let Some(response) = crate::curation::verify_integrity(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Ansible,
                &format!("{}.{}", ns, name),
                Some(ver),
                &bytes,
            ) {
                return response;
            }
            state.metrics.record_download("ansible");
            state.metrics.record_cache_miss("ansible");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                filename,
                crate::registry_type::RegistryType::Ansible,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "ansible", ""));

            state.spawn_cache_immutable("ansible", storage_key, Bytes::from(bytes.clone()));
            let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                state.config.curation.ansible.quarantine.as_ref().or(state
                    .config
                    .curation
                    .quarantine
                    .as_ref()),
                state
                    .config
                    .curation
                    .ansible
                    .quarantine_ttl
                    .as_deref()
                    .or(state.config.curation.quarantine_ttl.as_deref()),
            );
            if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                &state.digest_store,
                "ansible",
                &bytes,
                &q_mode,
                q_secs,
                &url,
                publish_date,
            ) {
                return resp;
            }
            with_binary(bytes)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "Ansible Galaxy download error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Generic JSON proxy with metadata caching ─────────────────────────

/// Proxy a Galaxy API JSON request with metadata caching and serve-stale.
///
/// `cache_key` is the storage path for the cached response (e.g.
/// `ansible/metadata/community/general.json`).
async fn proxy_json(
    state: &AppState,
    url: &str,
    artifact_name: &str,
    cache_key: &str,
    package_name: Option<&str>,
) -> Response {
    let base_url = nora_base_url(state);
    // The host stored bodies are rewritten from: the configured upstream, else the default one a
    // cached body may still name.
    let upstream = upstream_url(state).unwrap_or_else(|| UPSTREAM_DEFAULT.to_string());

    // Read cache eagerly so stale data is available on upstream failure.
    let cached_data = state.storage.get(cache_key).await.ok();

    // TTL check — serve fresh cache without hitting upstream.
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(cache_key).await {
            if crate::cache_ttl::is_within_ttl(meta.modified, state.config.ansible.metadata_ttl) {
                state.metrics.record_download("ansible");
                state.metrics.record_cache_hit("ansible");
                let text = String::from_utf8_lossy(data);
                let rewritten = rewrite_ansible_urls(&text, &upstream, &base_url);
                return with_json(rewritten.into_bytes());
            }
        }
    }

    // #68 namespace isolation: an internal-namespace collection's metadata must never
    // be fetched upstream (dependency confusion). Serve any local copy (fresh path
    // returned above), else block — never proxy. (collection_list passes None: the
    // catalog index has no single package name to gate.)
    if let Some(pkg) = package_name {
        if crate::curation::is_internal_namespace(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Ansible,
            pkg,
        ) {
            if let Some(ref data) = cached_data {
                state.metrics.record_download("ansible");
                state.metrics.record_cache_hit("ansible");
                let text = String::from_utf8_lossy(data);
                let rewritten = rewrite_ansible_urls(&text, &upstream, &base_url);
                return with_json(rewritten.into_bytes());
            }
            return crate::curation::check_namespace_isolation(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Ansible,
                pkg,
            )
            .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
        }
    }

    // No upstream when the operator switched it off: what is stored is all there is.
    if upstream_url(state).is_none() {
        return match cached_data {
            Some(data) => {
                let text = String::from_utf8_lossy(&data);
                with_json(rewrite_ansible_urls(&text, &upstream, &base_url).into_bytes())
            }
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }

    // Cache miss or stale — revalidate with a conditional request when enabled
    // (a cheap 304 when the upstream sends validators) and fall back to a full
    // fetch otherwise. Empty validators ⇒ no conditional headers ⇒ always a 200,
    // which is also how the first fetch captures validators for next time.
    let validators = if state.config.ansible.revalidate {
        read_validators(&state.storage, cache_key)
            .await
            .unwrap_or_default()
    } else {
        Validators::default()
    };
    let had_validators = validators.is_some();

    match proxy_fetch_conditional(
        &state.http_client,
        url,
        Duration::from_secs(state.config.ansible.proxy_timeout),
        expose_opt(&state.config.ansible.proxy_auth).map(UpstreamAuth::Basic),
        &validators,
        &state.circuit_breaker,
        RegistryType::Ansible,
    )
    .await
    {
        // Upstream unchanged — serve the cached body (rewritten at read time) and
        // bump its freshness so we don't revalidate again until the next TTL
        // window. No body was downloaded.
        Ok(Revalidation::NotModified) => {
            let Ok(cached) = state.storage.get(cache_key).await else {
                // Body vanished under us — fall back to serve-stale / 502.
                return serve_stale_or_bad_gateway(
                    state,
                    cached_data,
                    cache_key,
                    &upstream,
                    &base_url,
                );
            };
            crate::metrics::PROXY_UPSTREAM_304_TOTAL
                .with_label_values(&["ansible"])
                .inc();
            crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                .with_label_values(&["ansible"])
                .inc_by(cached.len() as u64);
            state.metrics.record_download("ansible");
            state.metrics.record_cache_hit("ansible");
            // Re-put bumps the file mtime (the freshness source) without download.
            let storage = state.storage.clone();
            let key_clone = cache_key.to_string();
            let body = cached.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &body).await;
            });
            let text = String::from_utf8_lossy(&cached);
            let rewritten = rewrite_ansible_urls(&text, &upstream, &base_url);
            with_json(rewritten.into_bytes())
        }
        // New body — cache the raw bytes first, then persist the fresh validators.
        Ok(Revalidation::Modified { body, validators }) => {
            state.metrics.record_download("ansible");
            state.metrics.record_cache_miss("ansible");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact_name.to_string(),
                crate::registry_type::RegistryType::Ansible,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "ansible", ""));

            // Cache raw response (before URL rewriting) for serve-stale; the
            // validator sidecar is written AFTER the body so it never advertises
            // freshness for a body that is not there.
            let raw = Bytes::from(body);
            let storage = state.storage.clone();
            let key_clone = cache_key.to_string();
            let raw_for_cache = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = storage.put(&key_clone, &raw_for_cache).await {
                    tracing::warn!(key = %key_clone, error = ?e, "ansible proxy: failed to cache metadata");
                    return;
                }
                write_validators(&storage, &key_clone, &validators).await;
            });

            let text = String::from_utf8_lossy(&raw);
            let rewritten = rewrite_ansible_urls(&text, &upstream, &base_url);
            state.repo_index.invalidate("ansible");
            with_json(rewritten.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["ansible"])
                    .inc();
            }
            tracing::debug!(error = ?e, "Ansible Galaxy upstream error");
            serve_stale_or_bad_gateway(state, cached_data, cache_key, &upstream, &base_url)
        }
    }
}

/// Serve stale cached metadata when upstream is unreachable, or 502 if no cache.
fn serve_stale_or_bad_gateway(
    state: &AppState,
    cached: Option<Bytes>,
    label: &str,
    upstream: &str,
    base_url: &str,
) -> Response {
    if let Some(data) = cached {
        if state.config.ansible.serve_stale {
            tracing::warn!(
                registry = "ansible",
                endpoint = label,
                "Upstream unreachable, serving stale cached metadata"
            );
            let text = String::from_utf8_lossy(&data);
            let rewritten = rewrite_ansible_urls(&text, upstream, base_url);
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
                rewritten.into_bytes(),
            )
                .into_response();
        }
    }
    StatusCode::BAD_GATEWAY.into_response()
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Append query string to a URL, rejecting oversized or malformed values.
fn append_query(base_url: &str, raw_query: Option<&str>) -> String {
    match raw_query {
        Some(q) if !q.is_empty() && q.len() <= 256 && !q.contains('#') && !q.contains('\0') => {
            format!("{}?{}", base_url, q)
        }
        _ => base_url.to_string(),
    }
}

/// Extract `page` or `offset` parameter from a query string for cache key differentiation.
fn extract_page_param(raw_query: Option<&str>) -> Option<String> {
    let q = raw_query?;
    for pair in q.split('&') {
        if let Some(val) = pair
            .strip_prefix("page=")
            .or_else(|| pair.strip_prefix("offset="))
        {
            if !val.is_empty() && val.len() <= 10 && val.chars().all(|c| c.is_ascii_digit()) {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// The configured upstream, or None when the operator switched it off with an empty
/// NORA_ANSIBLE_PROXY: then nothing is asked of any upstream.
fn upstream_url(state: &AppState) -> Option<String> {
    crate::config::configured_upstream(&state.config.ansible.proxy).map(str::to_string)
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
                HeaderValue::from_static("application/gzip"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
            (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        ],
        data,
    )
        .into_response()
}

fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains('/')
        && !name.contains('\0')
        && !name.contains("..")
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

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

fn is_safe_filename(name: &str) -> bool {
    !name.contains("..")
        && !name.contains('/')
        && !name.contains('\0')
        && !name.is_empty()
        && name.len() <= 512
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #385: a slash-escaped upstream URL (`https:\/\/host` — valid JSON many
    /// origins emit) must not survive the raw-text rewrite and leak the host.
    #[test]
    fn rewrite_ansible_drops_upstream_host_plain_and_escaped() {
        const HOST: &str = "galaxy.ansible.com";
        let upstream = "https://galaxy.ansible.com";
        let base = "http://nora.test";

        let plain = rewrite_ansible_urls(
            r#"{"download_url":"https://galaxy.ansible.com/download/x/a.tar.gz"}"#,
            upstream,
            base,
        );
        assert!(!plain.contains(HOST), "plain upstream host leaked: {plain}");

        let escaped = rewrite_ansible_urls(
            r#"{"download_url":"https:\/\/galaxy.ansible.com\/download\/x\/a.tar.gz"}"#,
            upstream,
            base,
        );
        assert!(
            !escaped.contains(HOST),
            "slash-escaped upstream host leaked (#385): {escaped}"
        );
        assert!(
            escaped.contains("nora.test"),
            "escaped url not rewritten to nora base: {escaped}"
        );
    }

    /// A host that only starts like the upstream's, or a longer last segment of its path, is
    /// another origin: the catch-all rewrite leaves it, plain or slash-escaped, while the
    /// upstream's own URL is rewritten wherever it ends.
    #[test]
    fn a_host_that_only_starts_like_the_upstream_is_not_rewritten() {
        let upstream = "https://galaxy.example.com";
        let base = "http://nora.test";
        for other in [
            "https://galaxy.example.com.evil.org/x",
            "https://galaxy.example.com:8443/x",
            "https://galaxy.example.com@evil.org/x",
            "https://galaxy.example.community/x",
        ] {
            let plain = format!(r#"{{"href":"{other}"}}"#);
            assert_eq!(rewrite_ansible_urls(&plain, upstream, base), plain);
            let escaped = plain.replace('/', "\\/");
            assert_eq!(rewrite_ansible_urls(&escaped, upstream, base), escaped);
        }
        for (own, expected) in [
            (
                r#"{"href":"https://galaxy.example.com"}"#,
                r#"{"href":"http://nora.test/ansible"}"#,
            ),
            (
                r#"{"href":"https://galaxy.example.com/x"}"#,
                r#"{"href":"http://nora.test/ansible/x"}"#,
            ),
            (
                r#"{"href":"https://galaxy.example.com?x"}"#,
                r#"{"href":"http://nora.test/ansible?x"}"#,
            ),
            (
                r#"{"href":"https:\/\/galaxy.example.com\/x"}"#,
                r#"{"href":"http:\/\/nora.test\/ansible\/x"}"#,
            ),
        ] {
            assert_eq!(rewrite_ansible_urls(own, upstream, base), expected);
        }
    }

    #[test]
    fn test_valid_names() {
        assert!(is_valid_name("community"));
        assert!(is_valid_name("ansible"));
        assert!(is_valid_name("cloud_common"));
    }

    #[test]
    fn test_invalid_names() {
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("../evil"));
        assert!(!is_valid_name("foo/bar"));
        // Galaxy spec: namespaces/names use underscores, not hyphens
        assert!(!is_valid_name("cloud-common"));
    }

    #[test]
    fn test_valid_version() {
        assert!(is_valid_version("7.0.0"));
        assert!(is_valid_version("1.2.3"));
        assert!(!is_valid_version(""));
        assert!(!is_valid_version("../evil"));
        assert!(!is_valid_version("foo/bar"));
    }

    #[test]
    fn test_safe_filename() {
        assert!(is_safe_filename("community-general-7.0.0.tar.gz"));
        assert!(!is_safe_filename("../evil.tar.gz"));
        assert!(!is_safe_filename("evil/path.tar.gz"));
    }

    #[test]
    fn test_rewrite_ansible_urls_download() {
        let input = r#"{"download_url":"https://galaxy.ansible.com/download/community-general-7.0.0.tar.gz"}"#;
        let result = rewrite_ansible_urls(input, "https://galaxy.ansible.com", "http://nora:4000");
        assert!(result.contains("http://nora:4000/ansible/download/community-general-7.0.0.tar.gz"));
        assert!(!result.contains("galaxy.ansible.com"));
    }

    #[test]
    fn test_rewrite_ansible_urls_href_and_pagination() {
        let input = r#"{"data":[{"href":"https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/community/general/"}],"links":{"next":"https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/?page=2"}}"#;
        let result = rewrite_ansible_urls(
            input,
            "https://galaxy.ansible.com",
            "https://registry.local",
        );
        assert!(result.contains("https://registry.local/ansible/v3/collections/community/general/"));
        assert!(result.contains("https://registry.local/ansible/v3/collections/?page=2"));
        assert!(!result.contains("galaxy.ansible.com"));
    }

    #[test]
    fn test_rewrite_ansible_urls_versions_url() {
        let input = r#"{"versions_url":"https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/"}"#;
        let result = rewrite_ansible_urls(input, "https://galaxy.ansible.com", "http://nora:4000");
        assert!(
            result.contains("http://nora:4000/ansible/v3/collections/community/general/versions/")
        );
        assert!(!result.contains("galaxy.ansible.com"));
    }

    #[test]
    fn test_append_query_basic() {
        let base = "https://galaxy.ansible.com/api/v3/versions/";
        assert_eq!(
            append_query(base, Some("limit=10&offset=20")),
            "https://galaxy.ansible.com/api/v3/versions/?limit=10&offset=20"
        );
    }

    #[test]
    fn test_append_query_empty() {
        let base = "https://galaxy.ansible.com/api/v3/versions/";
        assert_eq!(append_query(base, None), base);
        assert_eq!(append_query(base, Some("")), base);
    }

    #[test]
    fn test_append_query_rejects_oversized() {
        let base = "https://galaxy.ansible.com/api/v3/versions/";
        let huge = "a".repeat(257);
        assert_eq!(append_query(base, Some(&huge)), base);
    }

    #[test]
    fn test_append_query_rejects_fragment() {
        let base = "https://galaxy.ansible.com/api/v3/versions/";
        assert_eq!(append_query(base, Some("page=1#evil")), base);
    }

    #[test]
    fn test_append_query_rejects_null_byte() {
        let base = "https://galaxy.ansible.com/api/v3/versions/";
        assert_eq!(append_query(base, Some("page=1\0")), base);
    }

    #[test]
    fn test_extract_page_param() {
        assert_eq!(extract_page_param(Some("page=2")), Some("2".to_string()));
        assert_eq!(
            extract_page_param(Some("limit=10&offset=20")),
            Some("20".to_string())
        );
        assert_eq!(extract_page_param(Some("limit=10")), None);
        assert_eq!(extract_page_param(None), None);
        assert_eq!(extract_page_param(Some("")), None);
        // Reject non-numeric
        assert_eq!(extract_page_param(Some("page=abc")), None);
    }

    #[test]
    fn test_rewrite_preserves_pagination_query_params() {
        let input = r#"{"links":{"next":"https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/?limit=10&offset=20"}}"#;
        let result = rewrite_ansible_urls(input, "https://galaxy.ansible.com", "http://nora:4000");
        assert!(result.contains("http://nora:4000/ansible/v3/collections/community/general/versions/?limit=10&offset=20"));
        assert!(!result.contains("galaxy.ansible.com"));
    }

    #[test]
    fn test_rewrite_ansible_urls_artifacts_path() {
        // Upstream Galaxy returns download_url with artifacts path (#438)
        let input = r#"{"download_url":"https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/community-general-12.2.0.tar.gz"}"#;
        let result = rewrite_ansible_urls(input, "https://galaxy.ansible.com", "http://nora:4000");
        assert!(
            result.contains("http://nora:4000/ansible/download/community-general-12.2.0.tar.gz"),
            "artifacts path should rewrite to /ansible/download/: {}",
            result
        );
        assert!(!result.contains("galaxy.ansible.com"));
    }

    #[test]
    fn test_rewrite_relative_pagination_next_link() {
        // galaxy_ng emits root-relative pagination links (no scheme/host). The
        // absolute rewrites don't touch them; they must still land under /ansible
        // so the client's relative-link resolution stays on the mount. Regression
        // for community.docker (148 versions) 404ing on page 2.
        let input = r#"{"links":{"next":"/api/v3/plugin/ansible/content/published/collections/index/community/docker/versions/?limit=100&offset=100","first":"/api/v3/plugin/ansible/content/published/collections/index/community/docker/versions/?limit=100&offset=0"}}"#;
        let result = rewrite_ansible_urls(
            input,
            "https://galaxy.ansible.com",
            "https://nora.nuc.m8g.dev",
        );
        assert!(
            result.contains(
                "\"next\":\"/ansible/v3/collections/community/docker/versions/?limit=100&offset=100\""
            ),
            "relative next link not rewritten to /ansible path: {result}"
        );
        assert!(
            result.contains(
                "\"first\":\"/ansible/v3/collections/community/docker/versions/?limit=100&offset=0\""
            ),
            "relative first link not rewritten: {result}"
        );
        // No bare /api/v3/plugin path may survive (would drop the /ansible mount).
        assert!(
            !result.contains("\"/api/v3/plugin/"),
            "a root-relative pulp path leaked: {result}"
        );

        // Same link in the `\/`-escaped JSON form many origins emit (#385 class):
        // must be rewritten too, or the pulp path survives once the client
        // unescapes it.
        let escaped = r#"{"links":{"next":"\/api\/v3\/plugin\/ansible\/content\/published\/collections\/index\/community\/docker\/versions\/?limit=100&offset=100"}}"#;
        let result = rewrite_ansible_urls(
            escaped,
            "https://galaxy.ansible.com",
            "https://nora.nuc.m8g.dev",
        );
        assert!(
            result.contains(
                "\"next\":\"\\/ansible\\/v3\\/collections\\/community\\/docker\\/versions\\/?limit=100&offset=100\""
            ),
            "escaped relative next link not rewritten: {result}"
        );
        assert!(
            !result.contains("plugin"),
            "an escaped pulp path leaked: {result}"
        );
    }

    #[test]
    fn test_rewrite_relative_pagination_subpath_mount() {
        // NORA mounted under a sub-path (reverse proxy): the relative link must
        // carry the prefix so the client resolves it under `/prefix/ansible`, not
        // the host root. Exercises `url_path_component` inside the rewriter — the
        // reason it exists — which `test_url_path_component` only covers in isolation.
        let input = r#"{"links":{"next":"/api/v3/plugin/ansible/content/published/collections/index/community/docker/versions/?limit=100&offset=100"}}"#;
        let result = rewrite_ansible_urls(
            input,
            "https://galaxy.ansible.com",
            "https://nora.test/prefix",
        );
        assert!(
            result.contains(
                "\"next\":\"/prefix/ansible/v3/collections/community/docker/versions/?limit=100&offset=100\""
            ),
            "relative link did not carry the sub-path mount prefix: {result}"
        );
    }

    #[test]
    fn test_relative_rewrite_is_quote_anchored() {
        // The relative rules match a bare path only at the start of a JSON string
        // value (anchored on the opening quote). A pulp-looking path in the middle
        // of a *different* host's absolute URL, or in free text, must be left
        // untouched — otherwise the weakly-anchored rule mangles unrelated content.
        let foreign = r#"{"x":"https://mirror.example/api/v3/plugin/ansible/content/published/collections/index/foo/bar/"}"#;
        assert_eq!(
            rewrite_ansible_urls(foreign, "https://galaxy.ansible.com", "https://nora.test"),
            foreign,
            "a non-upstream absolute URL was mangled mid-path"
        );
        let prose = r#"{"description":"see /api/v3/plugin/ansible/content/published/collections/index/ here"}"#;
        assert_eq!(
            rewrite_ansible_urls(prose, "https://galaxy.ansible.com", "https://nora.test"),
            prose,
            "a literal path in free text was mangled"
        );
    }

    #[test]
    fn test_url_path_component() {
        use crate::config::url_path_component;
        assert_eq!(url_path_component("https://nora.nuc.m8g.dev"), "");
        assert_eq!(url_path_component("https://nora.test/prefix"), "/prefix");
        assert_eq!(url_path_component("http://nora:4000"), "");
        assert_eq!(url_path_component("/already/a/path"), "/already/a/path");
    }

    #[test]
    fn test_rewrite_ansible_urls_no_upstream_unchanged() {
        let input = r#"{"name":"community.general","version":"7.0.0"}"#;
        let result = rewrite_ansible_urls(input, "https://galaxy.ansible.com", "http://nora:4000");
        assert_eq!(input, result);
    }

    #[test]
    fn test_rewrite_ansible_urls_custom_upstream() {
        let input =
            r#"{"download_url":"https://hub.example.com/download/my-collection-1.0.0.tar.gz"}"#;
        let result = rewrite_ansible_urls(input, "https://hub.example.com", "http://nora:4000");
        assert!(result.contains("http://nora:4000/ansible/download/my-collection-1.0.0.tar.gz"));
        assert!(!result.contains("hub.example.com"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{
        body_bytes, create_test_context_with_config, send, send_with_headers,
    };
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_ansible_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = false;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_ansible_cached_tarball() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
        });

        ctx.state
            .storage
            .put(
                "ansible/download/community-general-7.0.0.tar.gz",
                b"tarball-data",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/download/community-general-7.0.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"tarball-data");
    }

    /// Resume support on a cached collection tarball: 206 for a byte range, 416
    /// past the end, `Accept-Ranges` on the full 200.
    #[tokio::test]
    async fn test_ansible_tarball_range_request() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
        });
        let url = "/ansible/download/community-general-7.0.1.tar.gz";
        ctx.state
            .storage
            .put(
                "ansible/download/community-general-7.0.1.tar.gz",
                b"0123456789",
            )
            .await
            .unwrap();

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
    }

    #[tokio::test]
    async fn test_ansible_unreachable_proxy() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
            cfg.ansible.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.ansible.proxy_timeout = 1;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_ansible_api_discovery() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
        });
        // /ansible/ discovery
        let resp = send(&ctx.app, Method::GET, "/ansible/", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["available_versions"]["v3"], "v3/");

        // /ansible/api/ discovery
        let resp = send(&ctx.app, Method::GET, "/ansible/api/", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["available_versions"]["v3"], "v3/");
    }

    #[tokio::test]
    async fn test_ansible_short_v3_path_tarball() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
        });
        ctx.state
            .storage
            .put(
                "ansible/download/community-general-7.0.0.tar.gz",
                b"tarball-v3",
            )
            .await
            .unwrap();

        // Short v3 path should still serve downloads
        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/download/community-general-7.0.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"tarball-v3");
    }

    #[tokio::test]
    async fn test_ansible_download_rejects_invalid_name_parts() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
        });

        // Path traversal in namespace
        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/download/..%2F-name-1.0.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Empty name part (double-hyphen)
        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/download/community--1.0.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Stale cache + unreachable upstream + serve_stale=true → 200 with X-Nora-Stale header (#466)
    #[tokio::test]
    async fn test_serve_stale_collection_detail() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
            cfg.ansible.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.ansible.proxy_timeout = 1;
            cfg.ansible.metadata_ttl = 0; // force TTL expiry → always stale
            cfg.ansible.serve_stale = true;
        });

        // Pre-populate cache
        ctx.state
            .storage
            .put(
                "ansible/metadata/community/general.json",
                br#"{"name":"community.general","namespace":{"name":"community"}}"#,
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/v3/collections/community/general/",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
            Some(b"true".as_ref()),
        );
        let body = body_bytes(resp).await;
        assert!(String::from_utf8_lossy(&body).contains("community.general"));
    }

    /// Stale cache + unreachable upstream + serve_stale=false → 502 (#466)
    #[tokio::test]
    async fn test_serve_stale_disabled_returns_502() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
            cfg.ansible.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.ansible.proxy_timeout = 1;
            cfg.ansible.metadata_ttl = 0;
            cfg.ansible.serve_stale = false;
        });

        ctx.state
            .storage
            .put(
                "ansible/metadata/community/general.json",
                br#"{"name":"community.general"}"#,
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/v3/collections/community/general/",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert!(resp.headers().get("x-nora-stale").is_none());
    }

    /// Fresh cache (within TTL) → 200 without upstream request (#466)
    #[tokio::test]
    async fn test_fresh_cache_served_without_upstream() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
            cfg.ansible.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.ansible.proxy_timeout = 1;
            cfg.ansible.metadata_ttl = -1; // cache forever
        });

        ctx.state
            .storage
            .put(
                "ansible/metadata/community/general.json",
                br#"{"name":"community.general","cached":true}"#,
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/v3/collections/community/general/",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // No stale header — cache is fresh
        assert!(resp.headers().get("x-nora-stale").is_none());
        let body = body_bytes(resp).await;
        assert!(String::from_utf8_lossy(&body).contains("community.general"));
    }

    /// No cache + unreachable upstream → 502 (not stale, just unavailable)
    #[tokio::test]
    async fn test_no_cache_unreachable_returns_502() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
            cfg.ansible.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.ansible.proxy_timeout = 1;
            cfg.ansible.serve_stale = true;
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/v3/collections/community/general/",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// #52 acceptance: with a cached versions-list body + stored validators, a
    /// stale request revalidates with `If-None-Match`; on upstream 304 the cached
    /// body is served and NO 200-with-body is ever fetched. Drives the real
    /// handler. (Self-hosted Galaxy NG sends no validators, but a fronting CDN
    /// like galaxy.ansible.com does — this proves NORA uses them when present.)
    #[tokio::test]
    async fn test_ansible_revalidation_304_serves_cache_no_body_download() {
        use crate::registry::{write_validators, Validators};
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Conditional request (has If-None-Match) → 304. A request WITHOUT it
        // would 404 (no other mount), so any full fetch would visibly fail —
        // proving the 304 path served from cache.
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
            cfg.ansible.proxy = Some(upstream.uri());
            cfg.ansible.metadata_ttl = 0; // always stale → always revalidate
            cfg.ansible.revalidate = true;
            cfg.ansible.serve_stale = false;
        });

        // Pre-seed the cached versions body + validator sidecar (as a prior 200
        // would have).
        let key = "ansible/metadata/community/general/versions.json";
        ctx.state
            .storage
            .put(key, br#"{"data":[{"version":"1.0.0"}]}"#)
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
            .with_label_values(&["ansible"])
            .get();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/v3/collections/community/general/versions/",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert!(
            String::from_utf8_lossy(&body).contains("1.0.0"),
            "must serve the cached versions body"
        );

        let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["ansible"])
            .get();
        assert!(after > before, "a 304 revalidation must be recorded");
    }

    /// Regression: galaxy_ng emits `links.next` as a *host-relative* path
    /// (no scheme/host). Driven through the real `version_list` handler, the
    /// rewritten body must land the pagination link under `/ansible` so the
    /// client stays on the mount — otherwise a >100-version collection (e.g.
    /// community.docker, 148 versions) 404s on page 2 with `cmd_arg` HTTP 404.
    #[tokio::test]
    async fn test_version_list_rewrites_relative_next_link() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Page 1 body carries galaxy_ng's root-relative pagination pointers.
        let page1 = r#"{"meta":{"count":148},"links":{"first":"/api/v3/plugin/ansible/content/published/collections/index/community/docker/versions/?limit=100&offset=0","previous":null,"next":"/api/v3/plugin/ansible/content/published/collections/index/community/docker/versions/?limit=100&offset=100","last":"/api/v3/plugin/ansible/content/published/collections/index/community/docker/versions/?limit=100&offset=48"},"data":[{"version":"4.4.0"}]}"#;
        Mock::given(method("GET"))
            .and(path(
                "/api/v3/plugin/ansible/content/published/collections/index/community/docker/versions/",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_raw(page1, "application/json"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
            cfg.ansible.proxy = Some(upstream.uri());
            cfg.ansible.metadata_ttl = 0; // force an upstream fetch (no fresh cache)
            cfg.ansible.revalidate = false; // no validators → plain 200 full fetch
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/v3/collections/community/docker/versions/?limit=100",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let text = String::from_utf8_lossy(&body);

        // Relative pagination links now point under /ansible (path-only, so the
        // client's relative-link resolution keeps the mount prefix).
        assert!(
            text.contains(
                "\"next\":\"/ansible/v3/collections/community/docker/versions/?limit=100&offset=100\""
            ),
            "next link not rewritten under /ansible: {text}"
        );
        assert!(
            text.contains(
                "\"first\":\"/ansible/v3/collections/community/docker/versions/?limit=100&offset=0\""
            ),
            "first link not rewritten under /ansible: {text}"
        );
        // No bare pulp path may survive — that is exactly what dropped the mount.
        assert!(
            !text.contains("/api/v3/plugin/"),
            "a root-relative pulp path leaked to the client: {text}"
        );
        // Payload is otherwise passed through untouched.
        assert!(text.contains("\"version\":\"4.4.0\""), "data lost: {text}");
    }
}

/// Collection names, versions and artifact file names as ansible-galaxy writes them
/// (testdata/ansible, regenerated by the script there).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod per_ansible_galaxy {
    use super::API_PREFIX;
    use crate::storage::{ObjectStorage, Storage};
    use crate::test_helpers::{create_test_context_with_storage_and_config, send, upstream_paths};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct Request {
        namespace: String,
        name: String,
        version: String,
        path: String,
    }

    /// Requests the client sent for collections whose version carries no build metadata.
    fn requests() -> Vec<Request> {
        let path = format!(
            "{}/testdata/ansible/client-requests.tsv",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|row| !row.starts_with('#'))
            .map(|row| row.split('\t').map(String::from).collect::<Vec<_>>())
            .filter(|row| row[0] != "build" && row[4].starts_with("GET "))
            .filter(|row| !row[3].contains('+'))
            .map(|row| Request {
                namespace: row[1].clone(),
                name: row[2].clone(),
                version: row[3].clone(),
                path: row[4].strip_prefix("GET ").unwrap().to_string(),
            })
            .collect()
    }

    /// What NORA asks upstream for a request, built from the collection the client asked for.
    fn upstream_path(r: &Request) -> Option<String> {
        let (ns, name, ver) = (&r.namespace, &r.name, &r.version);
        let short = format!("/ansible/v3/collections/{ns}/{name}/versions/");
        if r.path == format!("{short}?limit=100") {
            Some(format!("{API_PREFIX}/{ns}/{name}/versions/?limit=100"))
        } else if r.path == format!("{short}{ver}/") {
            Some(format!("{API_PREFIX}/{ns}/{name}/versions/{ver}/"))
        } else if r.path == format!("/ansible/download/{ns}-{name}-{ver}.tar.gz") {
            Some(format!("/download/{ns}-{name}-{ver}.tar.gz"))
        } else {
            None
        }
    }

    async fn upstream() -> MockServer {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
            .mount(&up)
            .await;
        up
    }

    // Every request ansible-galaxy sends, except the API root NORA answers itself, reaches
    // upstream for the namespace, name and version the client asked for.
    #[tokio::test]
    async fn every_request_ansible_galaxy_sends_is_asked_upstream_for_its_collection() {
        let rows = requests();
        assert_eq!(rows.len(), 92);
        let up = upstream().await;
        let proxy = up.uri();
        let storage = Storage::from_backend(std::sync::Arc::new(ObjectStorage::in_memory()));
        let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.ansible.enabled = true;
            cfg.ansible.proxy = Some(proxy);
        });
        let mut asked_upstream = 0;
        for r in rows {
            let resp = send(&ctx.app, Method::GET, &r.path, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{}", r.path);
            if r.path == "/ansible/" {
                continue;
            }
            let want = upstream_path(&r).unwrap_or_else(|| panic!("{}", r.path));
            let sent = upstream_paths(&up).await;
            let want_path = want.split('?').next().unwrap();
            assert!(
                sent.iter().any(|p| p == want_path),
                "{} → {want}: {sent:?}",
                r.path
            );
            asked_upstream += 1;
        }
        assert_eq!(asked_upstream, 66);
    }

    // Every version detail and artifact ansible-galaxy fetches is curated as the collection
    // `namespace.name` and the version the client asked for: a rule naming them refuses it before
    // upstream is asked.
    #[tokio::test]
    async fn every_version_ansible_galaxy_fetches_is_curated_as_its_collection() {
        let rows: Vec<Request> = requests()
            .into_iter()
            .filter(|r| upstream_path(r).is_some() && !r.path.ends_with("?limit=100"))
            .collect();
        assert_eq!(rows.len(), 40);
        let rules: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| serde_json::json!({"registry": "ansible", "name": format!("{}.{}", r.namespace, r.name), "version": r.version, "reason": "test"}))
            .collect();
        let dir = tempfile::TempDir::new().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            serde_json::json!({"version": 1, "rules": rules}).to_string(),
        )
        .unwrap();
        let up = upstream().await;
        let proxy = up.uri();
        let storage = Storage::from_backend(std::sync::Arc::new(ObjectStorage::in_memory()));
        let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.ansible.enabled = true;
            cfg.ansible.proxy = Some(proxy);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
        });
        for r in rows {
            let resp = send(&ctx.app, Method::GET, &r.path, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{}", r.path);
        }
        let sent = upstream_paths(&up).await;
        assert!(sent.is_empty(), "{sent:?}");
    }
}
