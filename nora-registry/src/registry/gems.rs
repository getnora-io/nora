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
use crate::config::UpstreamAuth;
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
                    crate::registry_type::RegistryType::Gems,
                    "CACHE",
                ));
                return with_binary(data.to_vec(), "application/gzip");
            }
        }
    }

    // Fetch from upstream — none when the operator switched it off: what is stored is all there is.
    let Some(proxy_url) = upstream_url(state) else {
        return match cached_data {
            Some(data) => with_binary(data.to_vec(), "application/gzip"),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    };
    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), filename);

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.gems.proxy_timeout),
        expose_opt(&state.config.gems.proxy_auth).map(UpstreamAuth::Basic),
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
                crate::registry_type::RegistryType::Gems,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "gems", ""));

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

    // Curation check. #733 serve-local: an internal-namespace gem is operator-owned — skip
    // curation and serve any local copy below; block the upstream branch separately.
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Gems,
        &name,
    );
    if !internal {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Gems,
            &name,
            crate::curation::RequestVersion::Unspecified,
            None,
        ) {
            return response;
        }
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
                    crate::registry_type::RegistryType::Gems,
                    "CACHE",
                ));
                return with_text(data.to_vec());
            }
        }
    }

    // #733: an internal-namespace gem — serve any (stale) local index, else block; never proxy.
    if internal {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("gems");
            state.metrics.record_cache_hit("gems");
            return with_text(data.to_vec());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Gems,
            &name,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    let Some(proxy_url) = upstream_url(&state) else {
        return match cached_data {
            Some(data) => with_text(data.to_vec()),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    };
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
        expose_opt(&state.config.gems.proxy_auth).map(UpstreamAuth::Basic),
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
                crate::registry_type::RegistryType::Gems,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "gems", ""));

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

/// Best-effort per-version `created_at` from the RubyGems API (the compact index
/// has no dates). Any failure → `None` (quarantine falls back to NORA's clock).
async fn fetch_gems_date(
    client: &reqwest::Client,
    proxy: &str,
    name: &str,
    version: &str,
    platform: Option<&str>,
    timeout_secs: u64,
) -> Option<i64> {
    let url = format!(
        "{}/api/v1/versions/{}.json",
        proxy.trim_end_matches('/'),
        name
    );
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let arr: Vec<serde_json::Value> = resp.json().await.ok()?;
    // The API lists each version once per platform (`ruby` for a pure-Ruby gem).
    let platform = platform.unwrap_or("ruby");
    let date_str = arr
        .iter()
        .find(|v| {
            v.get("number").and_then(|n| n.as_str()) == Some(version)
                && v.get("platform").and_then(|p| p.as_str()).unwrap_or("ruby") == platform
        })?
        .get("created_at")?
        .as_str()?;
    crate::curation::parse_iso8601_to_unix(date_str)
}

// ── Gem download (immutable) ───────────────────────────────────────────

async fn download_gem(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(filename): Path<String>,
) -> Response {
    // filename = "name-version[-platform].gem" — strip .gem suffix and split
    let stem = match filename.strip_suffix(".gem") {
        Some(s) => s,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    // The file is stored and fetched under its whole name, platform included.
    let artifact = stem.to_string();
    let storage_key = format!("gems/gems/{}.gem", artifact);
    let GemFileGate {
        internal,
        identities,
        publish_date,
    } = match gem_file_gate(&state, &headers, stem, &storage_key).await {
        Ok(gate) => gate,
        Err(refusal) => return *refusal,
    };
    let cached_meta = state.storage.stat(&storage_key).await;

    // Resolved here, not at the serve site, so the range branch below can see it.
    let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
        state.config.curation.gems.quarantine.as_ref().or(state
            .config
            .curation
            .quarantine
            .as_ref()),
        state
            .config
            .curation
            .gems
            .quarantine_ttl
            .as_deref()
            .or(state.config.curation.quarantine_ttl.as_deref()),
    );

    // Resumable download (#657): serve the requested bytes from the backend and skip
    // the full read below. .gem files only — the specs/compact indexes are mutable. A
    // partial read cannot be hashed, so neither the quarantine gate nor the curation
    // integrity check can run on it: the range serve stands down while quarantine holds
    // artifacts or an integrity rule applies to any identity of the file.
    let integrity_applies = identities.iter().any(|identity| {
        crate::curation::integrity_applies(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Gems,
            &identity.name,
            Some(&identity.version),
        )
    });
    if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) && !integrity_applies {
        if let Some(meta) = cached_meta.as_ref() {
            if let Some(response) = crate::registry::range::range_response(
                &state.storage,
                &[&storage_key],
                &headers,
                meta.size,
                "application/octet-stream",
                &[(
                    header::CACHE_CONTROL,
                    "public, max-age=31536000, immutable".to_string(),
                )],
            )
            .await
            {
                if response.status() == StatusCode::PARTIAL_CONTENT {
                    state.metrics.record_download("gems");
                    state.metrics.record_cache_hit("gems");
                }
                return response;
            }
        }
    }

    // Immutable: if cached, serve directly. get_verified discharges the integrity
    // witness at the serve site (compile-time guarantee — see crate::verified).
    let (cached, read_failure) =
        crate::registry::cached_read(state.storage.get_verified(&storage_key).await);
    if let Some(outcome) = cached {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        // Curation integrity, for every identity of the file.
        for identity in &identities {
            if let Some(response) = crate::curation::verify_integrity(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Gems,
                &identity.name,
                Some(&identity.version),
                &data,
            ) {
                return response;
            }
        }

        state.metrics.record_download("gems");
        state.metrics.record_cache_hit("gems");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            artifact,
            crate::registry_type::RegistryType::Gems,
            "CACHE",
        ));
        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "gems",
            &data,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }
        let mut response = with_binary(data.to_vec(), "application/octet-stream");
        response
            .headers_mut()
            .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        return response;
    }

    // #733: an internal-namespace gem with no local copy is never proxied upstream; one whose
    // copy the store could not read is unavailable, not absent.
    if let Some(name) = &internal {
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("gems", &storage_key, e);
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Gems,
            name,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // Fetch from upstream — none when the operator switched it off.
    let Some(proxy_url) = upstream_url(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let url = format!("{}/gems/{}.gem", proxy_url.trim_end_matches('/'), artifact);

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.gems.proxy_timeout),
        expose_opt(&state.config.gems.proxy_auth).map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        RegistryType::Gems,
    )
    .await
    {
        Ok(bytes) => {
            // The allowlist's pinned integrity holds on the first download too, before anything is cached:
            // the cache-hit branch checks the same rule.
            for identity in &identities {
                if let Some(response) = crate::curation::verify_integrity(
                    &state.curation().curation_engine,
                    crate::curation::RegistryType::Gems,
                    &identity.name,
                    Some(&identity.version),
                    &bytes,
                ) {
                    return response;
                }
            }
            state.metrics.record_download("gems");
            state.metrics.record_cache_miss("gems");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact,
                crate::registry_type::RegistryType::Gems,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "gems", ""));

            // Immutable cache: put_if_absent
            state.spawn_cache_immutable("gems", storage_key, Bytes::from(bytes.clone()));
            if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                &state.digest_store,
                "gems",
                &bytes,
                &q_mode,
                q_secs,
                &url,
                publish_date,
            ) {
                return resp;
            }
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
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(filename): Path<String>,
) -> Response {
    // filename = "name-version[-platform].gemspec.rz" — strip suffix and split
    let stem = match filename.strip_suffix(".gemspec.rz") {
        Some(s) => s,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    // The gemspec is stored and fetched under its whole name, platform included. It is decided
    // as its gem file is: the same readings, isolation, curation and release date.
    let artifact = stem.to_string();
    let storage_key = format!("gems/quick/Marshal.4.8/{}.gemspec.rz", artifact);
    let GemFileGate {
        internal,
        publish_date,
        ..
    } = match gem_file_gate(&state, &headers, stem, &storage_key).await {
        Ok(gate) => gate,
        Err(refusal) => return *refusal,
    };

    // Immutable cache. get_verified discharges the integrity witness at serve.
    let (cached, read_failure) =
        crate::registry::cached_read(state.storage.get_verified(&storage_key).await);
    if let Some(outcome) = cached {
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
            crate::registry_type::RegistryType::Gems,
            "CACHE",
        ));
        let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
            state.config.curation.gems.quarantine.as_ref().or(state
                .config
                .curation
                .quarantine
                .as_ref()),
            state
                .config
                .curation
                .gems
                .quarantine_ttl
                .as_deref()
                .or(state.config.curation.quarantine_ttl.as_deref()),
        );
        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "gems",
            &data,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }
        return with_binary(data.to_vec(), "application/octet-stream");
    }

    // #68 namespace isolation: a cached internal gem's spec was served above; an
    // internal name with no local copy must not be fetched upstream, and one whose copy the
    // store could not read is unavailable, not absent.
    if let Some(e) = read_failure.as_ref().filter(|_| internal.is_some()) {
        return crate::registry::local_copy_unreadable("gems", &storage_key, e);
    }
    if let Some(response) = internal.as_deref().and_then(|name| {
        crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Gems,
            name,
        )
    }) {
        return response;
    }

    let Some(proxy_url) = upstream_url(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let url = format!(
        "{}/quick/Marshal.4.8/{}.gemspec.rz",
        proxy_url.trim_end_matches('/'),
        artifact
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.gems.proxy_timeout),
        expose_opt(&state.config.gems.proxy_auth).map(UpstreamAuth::Basic),
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
                crate::registry_type::RegistryType::Gems,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "gems", ""));

            state.spawn_cache_immutable("gems", storage_key, Bytes::from(bytes.clone()));
            let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                state.config.curation.gems.quarantine.as_ref().or(state
                    .config
                    .curation
                    .quarantine
                    .as_ref()),
                state
                    .config
                    .curation
                    .gems
                    .quarantine_ttl
                    .as_deref()
                    .or(state.config.curation.quarantine_ttl.as_deref()),
            );
            if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                &state.digest_store,
                "gems",
                &bytes,
                &q_mode,
                q_secs,
                &url,
                publish_date,
            ) {
                return resp;
            }
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

/// The configured upstream, or None when the operator switched it off with an empty
/// NORA_GEMS_PROXY: then nothing is asked of any upstream.
fn upstream_url(state: &AppState) -> Option<String> {
    crate::config::configured_upstream(&state.config.gems.proxy).map(str::to_string)
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

/// One reading of a gem file name. RubyGems names a gem file `name-version[-suffix].gem`
/// (`Gem::BasicSpecification#full_name`): the version never holds a `-` (`Gem::Version` turns
/// a `-` into `.pre.`), and the suffix is the platform (`Gem::Platform#to_s`) or, for a
/// content-addressed gem, its address. A gem name may itself hold `-` and version-looking
/// fields, so one file name can read more than one way: `evil-1-2.0-java` is gem `evil` 1 for
/// platform `2.0-java`, or gem `evil-1` 2.0 for `java`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GemFile {
    pub name: String,
    pub version: String,
    /// The platform, or a content address; `None` for a pure-Ruby gem.
    pub platform: Option<String>,
}

/// A gem name as `Gem::SpecificationPolicy` takes one: letters, digits, `.`, `-` and `_`, not
/// starting with `.`, `-` or `_`. (The policy also wants a letter; a name from before it still
/// gets its reading.)
fn is_gem_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// A version as a file name carries it, `Gem::Version#to_s`: digits, then `.` and letters,
/// digits or dots (`7.0.0`, `1.0.0.pre.rc1`). `2fa` is not one.
fn is_gem_version_field(field: &str) -> bool {
    let mut segments = field.split('.');
    segments
        .next()
        .is_some_and(|first| !first.is_empty() && first.bytes().all(|b| b.is_ascii_digit()))
        && segments.all(|segment| {
            !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

/// A content address (`Gem::ContentAddress`, RubyGems after 3.6): 8 to 64 lowercase hex
/// digits where a platform goes.
fn is_gem_content_address(suffix: &str) -> bool {
    (8..=64).contains(&suffix.len())
        && suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A platform as `Gem::Platform` reads a string: CPU, OS and version, each as RubyGems keeps it.
type GemPlatformParts = (Option<String>, String, Option<String>);

fn ascii_digits(s: &str) -> &str {
    &s[..s.bytes().take_while(u8::is_ascii_digit).count()]
}

fn word_chars(s: &str) -> &str {
    &s[..s
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count()]
}

fn some_nonempty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// `\d+\.\d+` at the start of `s`, if there.
fn dotted_pair(s: &str) -> Option<String> {
    let major = ascii_digits(s);
    let rest = s[major.len()..].strip_prefix('.')?;
    let minor = ascii_digits(rest);
    (!major.is_empty() && !minor.is_empty()).then(|| format!("{major}.{minor}"))
}

/// `\d+(?:\.\d+)*` at the start of `s`, if there.
fn dotted_digits(s: &str) -> Option<String> {
    let mut end = ascii_digits(s).len();
    if end == 0 {
        return None;
    }
    while let Some(rest) = s[end..].strip_prefix('.') {
        let more = ascii_digits(rest).len();
        if more == 0 {
            break;
        }
        end += 1 + more;
    }
    Some(s[..end].to_string())
}

/// The leftmost `mswin` followed by a digit: the OS (`mswin32`) and what follows it.
fn mswin(os: &str) -> Option<(&str, &str)> {
    os.match_indices("mswin").find_map(|(at, _)| {
        let digits = ascii_digits(&os[at + 5..]);
        (!digits.is_empty()).then(|| {
            let end = at + 5 + digits.len();
            (&os[at..end], &os[end..])
        })
    })
}

/// `^(\w+_platform)` — RubyGems' test platforms: the word characters at the start up to and with
/// the last `_platform` among them, at least one character before it; and what follows.
fn test_platform(os: &str) -> Option<(&str, &str)> {
    let word = word_chars(os);
    word.rmatch_indices("_platform")
        .find(|(at, _)| *at >= 1)
        .map(|(at, _)| (&os[..at + 9], &os[at + 9..]))
}

/// `Gem::Platform#initialize` for a string, as RubyGems 3.6 reads it (`lib/rubygems/platform.rb`):
/// the fields split at every `-`, a non-numeric last field joined back to the one before
/// (`x86_64-linux-gnu`), the "command line" form `cpu-os-version` kept as written, and the OS
/// matched against its patterns.
fn gem_platform_v36(arch: &str) -> GemPlatformParts {
    let mut fields: Vec<String> = arch.split('-').map(String::from).collect();
    while fields.last().is_some_and(String::is_empty) {
        fields.pop();
    }
    if fields.len() > 2
        && !fields
            .last()
            .is_some_and(|f| f.ends_with(|c: char| c.is_ascii_digit()))
    {
        let extra = fields.pop().unwrap_or_default();
        if let Some(last) = fields.last_mut() {
            last.push('-');
            last.push_str(&extra);
        }
    }
    let mut fields = fields.into_iter();
    let cpu_written = fields.next();
    let rest: Vec<String> = fields.collect();
    let mut cpu = cpu_written.as_ref().map(|cpu| {
        if contains_i_86(cpu) {
            "x86".to_string()
        } else {
            cpu.clone()
        }
    });
    let numeric = |s: &str| {
        let major = ascii_digits(s);
        !major.is_empty()
            && (major.len() == s.len()
                || s[major.len()..]
                    .strip_prefix('.')
                    .is_some_and(|minor| !minor.is_empty() && ascii_digits(minor) == minor))
    };
    if rest.len() == 2 && numeric(&rest[1]) {
        return (cpu, rest[0].clone(), Some(rest[1].clone()));
    }
    let os = match rest.first() {
        Some(os) => os.clone(),
        None => {
            cpu = None;
            cpu_written.unwrap_or_default()
        }
    };
    let after = |lit: &str| os.find(lit).map(|at| &os[at + lit.len()..]);
    let (os_name, version) = if let Some(rest) = after("aix") {
        ("aix".to_string(), some_nonempty(ascii_digits(rest)))
    } else if os.contains("cygwin") {
        ("cygwin".to_string(), None)
    } else if let Some(rest) = after("darwin") {
        ("darwin".to_string(), some_nonempty(ascii_digits(rest)))
    } else if os == "macruby" {
        ("macruby".to_string(), None)
    } else if let Some(rest) = after("freebsd") {
        ("freebsd".to_string(), some_nonempty(ascii_digits(rest)))
    } else if os == "java" || os == "jruby" {
        ("java".to_string(), None)
    } else if let Some(rest) = os.strip_prefix("java") {
        let run = rest
            .bytes()
            .take_while(|b| b.is_ascii_digit() || *b == b'.')
            .count();
        ("java".to_string(), Some(rest[..run].to_string()))
    } else if let Some(rest) = os
        .strip_prefix("dalvik")
        .filter(|rest| rest.bytes().all(|b| b.is_ascii_digit()))
    {
        ("dalvik".to_string(), some_nonempty(rest))
    } else if os == "dotnet" {
        ("dotnet".to_string(), None)
    } else if let Some(rest) = os.strip_prefix("dotnet") {
        let run = rest
            .bytes()
            .take_while(|b| b.is_ascii_digit() || *b == b'.')
            .count();
        ("dotnet".to_string(), Some(rest[..run].to_string()))
    } else if let Some(rest) = after("linux") {
        let rest = rest.strip_prefix('-').unwrap_or(rest);
        ("linux".to_string(), some_nonempty(word_chars(rest)))
    } else if os.contains("mingw32") {
        ("mingw32".to_string(), None)
    } else if let Some(rest) = after("mingw") {
        let rest = rest.strip_prefix('-').unwrap_or(rest);
        ("mingw".to_string(), some_nonempty(word_chars(rest)))
    } else if let Some((name, rest)) = mswin(&os) {
        if cpu.is_none() && name.ends_with("32") {
            cpu = Some("x86".to_string());
        }
        let version = rest
            .strip_prefix('_')
            .and_then(|rest| some_nonempty(ascii_digits(rest)));
        (name.to_string(), version)
    } else if os.contains("netbsdelf") {
        ("netbsdelf".to_string(), None)
    } else if let Some(rest) = after("openbsd") {
        ("openbsd".to_string(), dotted_pair(rest))
    } else if let Some(rest) = after("solaris") {
        ("solaris".to_string(), dotted_pair(rest))
    } else if os.contains("wasi") {
        ("wasi".to_string(), None)
    } else if let Some((name, rest)) = test_platform(&os) {
        (name.to_string(), some_nonempty(ascii_digits(rest)))
    } else {
        ("unknown".to_string(), None)
    };
    (cpu, os_name, version)
}

/// `Gem::Platform#initialize` for a string, as RubyGems 4.0 and master read it: trailing `-`
/// dropped, the CPU before the first `-` and the OS (with any version) after it, matched against
/// its patterns, which take an optional `-` before a version.
fn gem_platform_v40(arch: &str) -> GemPlatformParts {
    let trimmed = arch.trim_end_matches('-');
    let (cpu_written, rest) = match trimmed.split_once('-') {
        Some((cpu, rest)) => (Some(cpu), Some(rest)),
        None if trimmed.is_empty() => (None, None),
        None => (Some(trimmed), None),
    };
    let mut cpu = cpu_written.map(|cpu| {
        if contains_i_86(cpu) {
            "x86".to_string()
        } else {
            cpu.to_string()
        }
    });
    let os = match rest {
        Some(os) => os.to_string(),
        None => {
            cpu = None;
            cpu_written.unwrap_or_default().to_string()
        }
    };
    let after = |lit: &str| {
        os.find(lit).map(|at| {
            let rest = &os[at + lit.len()..];
            rest.strip_prefix('-').unwrap_or(rest)
        })
    };
    let (os_name, version) = if let Some(rest) = after("aix") {
        ("aix".to_string(), some_nonempty(ascii_digits(rest)))
    } else if os.contains("cygwin") {
        ("cygwin".to_string(), None)
    } else if let Some(rest) = after("darwin") {
        ("darwin".to_string(), some_nonempty(ascii_digits(rest)))
    } else if os == "macruby" {
        ("macruby".to_string(), None)
    } else if let Some(rest) = os.strip_prefix("macruby") {
        let rest = rest.strip_prefix('-').unwrap_or(rest);
        ("macruby".to_string(), dotted_digits(rest))
    } else if let Some(rest) = after("freebsd") {
        ("freebsd".to_string(), some_nonempty(ascii_digits(rest)))
    } else if os == "java" || os == "jruby" {
        ("java".to_string(), None)
    } else if let Some(rest) = os.strip_prefix("java") {
        let rest = rest.strip_prefix('-').unwrap_or(rest);
        ("java".to_string(), dotted_digits(rest))
    } else if let Some(rest) = os.strip_prefix("dalvik").and_then(|rest| {
        let rest = rest.strip_prefix('-').unwrap_or(rest);
        rest.bytes().all(|b| b.is_ascii_digit()).then_some(rest)
    }) {
        ("dalvik".to_string(), some_nonempty(rest))
    } else if os == "dotnet" {
        ("dotnet".to_string(), None)
    } else if let Some(rest) = os.strip_prefix("dotnet") {
        let rest = rest.strip_prefix('-').unwrap_or(rest);
        ("dotnet".to_string(), dotted_digits(rest))
    } else if let Some(rest) = after("linux") {
        ("linux".to_string(), some_nonempty(word_chars(rest)))
    } else if os.contains("mingw32") {
        ("mingw32".to_string(), None)
    } else if let Some(rest) = after("mingw") {
        ("mingw".to_string(), some_nonempty(word_chars(rest)))
    } else if let Some((name, rest)) = mswin(&os) {
        if cpu.is_none() && name.ends_with("32") {
            cpu = Some("x86".to_string());
        }
        let version = rest
            .strip_prefix(['_', '-'])
            .and_then(|rest| some_nonempty(ascii_digits(rest)));
        (name.to_string(), version)
    } else if os.contains("netbsdelf") {
        ("netbsdelf".to_string(), None)
    } else if let Some(rest) = after("openbsd") {
        ("openbsd".to_string(), dotted_pair(rest))
    } else if let Some(rest) = after("solaris") {
        ("solaris".to_string(), dotted_pair(rest))
    } else if os.contains("wasi") {
        ("wasi".to_string(), None)
    } else if let Some((name, rest)) = test_platform(&os) {
        let rest = rest.strip_prefix('-').unwrap_or(rest);
        (name.to_string(), some_nonempty(ascii_digits(rest)))
    } else {
        ("unknown".to_string(), None)
    };
    (cpu, os_name, version)
}

/// `/i\d86/` anywhere: an Intel 32-bit CPU, which RubyGems writes as `x86`.
fn contains_i_86(cpu: &str) -> bool {
    cpu.as_bytes()
        .windows(4)
        .any(|w| w[0] == b'i' && w[1].is_ascii_digit() && w[2] == b'8' && w[3] == b'6')
}

/// `Gem::Platform#to_s`: the parts present, joined by `-` (RubyGems 4.0 and master join a
/// CPU-less platform without one: `darwin19`).
fn gem_platform_to_s((cpu, os, version): &GemPlatformParts, rubygems4: bool) -> String {
    let parts: Vec<&str> = [cpu.as_deref(), Some(os.as_str()), version.as_deref()]
        .into_iter()
        .flatten()
        .collect();
    parts.join(if rubygems4 && cpu.is_none() { "" } else { "-" })
}

/// Whether a RubyGems writes `suffix` as a platform: `Gem::Platform#to_s` of some platform, under
/// RubyGems 3.6 or 4.0 and master. `to_s` does not always read back as itself (3.6 writes the
/// CPU-less `darwin19` as `darwin-19`), so the platforms tried are the suffix itself and the
/// suffix with one `-` taken out or made `_` (`mswin32_60`).
fn rubygems_writes_platform(suffix: &str) -> bool {
    // `to_s` joins at most a CPU, an OS and a version, none of which holds a `-`: a suffix with
    // more than two is no platform's `to_s`, and is not parsed once per `-` it holds.
    if suffix.bytes().filter(|&b| b == b'-').count() > 2 {
        return false;
    }
    let mut candidates = vec![suffix.to_string()];
    for (at, _) in suffix.match_indices('-') {
        candidates.push(format!("{}{}", &suffix[..at], &suffix[at + 1..]));
        candidates.push(format!("{}_{}", &suffix[..at], &suffix[at + 1..]));
    }
    candidates.iter().any(|candidate| {
        gem_platform_to_s(&gem_platform_v36(candidate), false) == suffix
            || gem_platform_to_s(&gem_platform_v40(candidate), true) == suffix
    })
}

/// Platforms releases on rubygems.org carry that no current RubyGems writes: older gems keep the
/// spelling they were built with (`testdata/gems/platforms.tsv`, measured from rubygems.org's
/// specs indexes; the test `every_platform_on_rubygems_org_is_a_platform` keeps this list exact).
const RUBYGEMS_ORG_PLATFORMS: &[&str] = &[
    "1-2-3-4",
    "1.1.1",
    "Ruby",
    "RubyMotion",
    "amd64-windows",
    "android",
    "do_not_install",
    "i386-darwin",
    "i386-linux",
    "i386-mingw32",
    "i386-mswin32",
    "i386-mswin32-mq5.3",
    "i386-mswin32-mq6",
    "i386-mswin64",
    "i486-linux",
    "i586-linux",
    "i686-darwin10",
    "i686-darwin8.4.1",
    "i686-darwin8.8.2",
    "i686-darwin8.9.1",
    "i686-linux",
    "ironruby",
    "jruby",
    "jruby-java-universal-java-9",
    "mswin32",
    "powerpc-darwin8.10.0",
    "powerpc-darwin8.3.0",
    "ruby_2.6",
    "sparc-solaris2.8-mq5.3",
    "universal-.net",
    "universal-aix5",
    "universal-darwin16",
    "universal-darwin17",
    "universal-darwin18",
    "universal-darwin19",
    "universal-darwin8.0",
    "universal-darwin9.0",
    "universal-hpux",
    "universal-rubinius",
    "universal-rubinius-1.2.1",
    "universal-ruby-1.8.7",
    "universal-ruby-1.9.2",
    "universal-ruby-1.9.3",
    "windows",
    "x64-mingw-ucrt-3.2",
    "x64-mingw-ucrt-3.2-3.2.2",
    "x86-mingw32-1.9.1",
    "x86-mingw32-1.9.2",
    "x86-mswin32-1.9.1",
    "x86-mswin32-1.9.2",
    "x86_64-darwin10.7.0",
    "x86_64-darwin10.8.0",
    "x86_64-darwin11.3.0",
    "x86_64-darwin12.0.0",
    "x86_64-darwin13.0",
    "x86_64-darwin15",
    "x86_64-darwin16",
    "x86_64-darwin17",
    "x86_64-mingw64",
    "x86_64-netbsd",
    "x86_64-windows",
];

/// Whether a file-name suffix is a platform: one a RubyGems writes, one a release on
/// rubygems.org carries, or a content address.
fn is_gem_platform(suffix: &str) -> bool {
    rubygems_writes_platform(suffix) || RUBYGEMS_ORG_PLATFORMS.contains(&suffix)
}

/// Every reading of a gem file name (without `.gem`) that RubyGems' grammar allows, shortest
/// gem name first; a name RubyGems built has its own reading among them.
///
/// Examples:
///   "rails-7.0.0"                    → rails 7.0.0
///   "nokogiri-1.13.0-x86_64-linux"   → nokogiri 1.13.0 for x86_64-linux
///   "foo-2-bar-1.0.0"                → foo-2-bar 1.0.0 (`bar-1.0.0` is no platform)
///   "ffi-1.15.5-universal-darwin-19" → ffi 1.15.5 for universal-darwin-19, and
///                                      ffi-1.15.5-universal-darwin 19
pub fn gem_file_readings(stem: &str) -> Vec<GemFile> {
    let fields: Vec<&str> = stem.split('-').collect();
    (1..fields.len())
        // A field that is no version decides the split alone, before any part is built.
        .filter(|&at| is_gem_version_field(fields[at]))
        .filter_map(|at| {
            let name = fields[..at].join("-");
            if !is_gem_name(&name) {
                return None;
            }
            let platform = (at + 1 < fields.len()).then(|| fields[at + 1..].join("-"));
            let suffix_ok = platform
                .as_deref()
                .is_none_or(|p| is_gem_platform(p) || is_gem_content_address(p));
            suffix_ok.then(|| GemFile {
                name,
                version: fields[at].to_string(),
                platform,
            })
        })
        .collect()
}

/// The gem and version to show for a gem file name: its first reading. For display only —
/// curation weighs the file's identities ([`gem_file_identities`]).
pub fn split_gem_filename(stem: &str) -> Option<(String, String)> {
    gem_file_readings(stem)
        .into_iter()
        .next()
        .map(|file| (file.name, file.version))
}

/// Whether a compact index (`/info/<name>`) lists a reading: its rows after `---` start with
/// `version` or `version-platform` (rubygems `resolver/api_set/gem_parser.rb` splits that
/// field at its first `-`).
fn compact_index_lists(index: &str, file: &GemFile) -> bool {
    let wanted = match &file.platform {
        Some(platform) => format!("{}-{}", file.version, platform),
        None => file.version.clone(),
    };
    let lines: Vec<&str> = index.lines().collect();
    let rows = match lines.iter().position(|line| *line == "---") {
        Some(header) => &lines[header + 1..],
        None => &lines[..],
    };
    rows.iter()
        .any(|row| row.split(' ').next() == Some(wanted.as_str()))
}

/// The readings of a gem file name curation decides on. One reading is the file. Of several,
/// those the compact index NORA holds for their gem lists (`gems/info/<name>`: upstream's own
/// record of which versions and platforms exist; RubyGems gives a file name to one gem only,
/// so a listed reading is the file) — and every reading while none is listed.
async fn gem_file_identities(state: &AppState, readings: Vec<GemFile>) -> Vec<GemFile> {
    if readings.len() < 2 {
        return readings;
    }
    let mut listed = Vec::new();
    for reading in &readings {
        let Ok(index) = state
            .storage
            .get(&format!("gems/info/{}", reading.name))
            .await
        else {
            continue;
        };
        if compact_index_lists(&String::from_utf8_lossy(&index), reading) {
            listed.push(reading.clone());
        }
    }
    if listed.is_empty() {
        readings
    } else {
        listed
    }
}

/// A reading NORA serves under: name, version and platform within the key rules (no `/`,
/// no `..`, no NUL).
fn is_valid_gem_file(file: &GemFile) -> bool {
    is_valid_gem_name(&file.name)
        && is_valid_version(&file.version)
        && file.platform.as_deref().is_none_or(is_valid_gem_name)
}

/// What curation and namespace isolation decide for a gem file — its `.gem` and its gemspec
/// alike, so the two paths cannot decide differently.
struct GemFileGate {
    /// The name of a reading under an internal namespace (#733): the file is served from its local
    /// copy only, never fetched, not curated, and its release dates are never asked upstream.
    internal: Option<String>,
    /// The identities curation weighed, for the integrity check of a served file.
    identities: Vec<GemFile>,
    /// The newest release date among the identities: the file's quarantine clock.
    publish_date: Option<i64>,
}

/// The one decision for a gem file name (without its extension) stored at `storage_key`: a name
/// with no reading is refused (400); every identity is weighed at its own version and its own
/// release date, and the first refusal stands.
async fn gem_file_gate(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    stem: &str,
    storage_key: &str,
) -> Result<GemFileGate, Box<Response>> {
    // Reading a name costs more the longer it is, and it arrives from any client: a name no
    // reading of which NORA serves is refused unread.
    if stem.len() > GEM_FILE_STEM_MAX {
        return Err(Box::new(StatusCode::BAD_REQUEST.into_response()));
    }
    let readings = gem_file_readings(stem);
    if readings.is_empty() || !readings.iter().all(is_valid_gem_file) {
        return Err(Box::new(StatusCode::BAD_REQUEST.into_response()));
    }
    let internal = internal_gem_reading(state, &readings);
    let identities = gem_file_identities(state, readings).await;
    // #748/#750: release dates for the quarantine clock. #754: asked only on a cache miss — a
    // cached file's digest is already recorded. Hosted only: when the file was stored.
    let already_cached = state.storage.stat(storage_key).await.is_some();
    let dated = if upstream_url(state).is_none() {
        let stored =
            crate::curation::extract_mtime_as_publish_date(&state.storage, storage_key).await;
        identities
            .into_iter()
            .map(|identity| (identity, stored))
            .collect()
    } else {
        upstream_gem_release_dates(state, identities, !already_cached && internal.is_none()).await
    };
    let publish_date = dated.iter().filter_map(|(_, date)| *date).max();
    if internal.is_none() {
        for (identity, date) in &dated {
            if let Some(refusal) = crate::curation::check_download(
                &state.curation().curation_engine,
                state.bypass_token().as_deref(),
                headers,
                crate::curation::RegistryType::Gems,
                &identity.name,
                crate::curation::RequestVersion::Known(identity.version.clone()),
                *date,
            ) {
                return Err(Box::new(refusal));
            }
        }
    }
    Ok(GemFileGate {
        internal,
        identities: dated.into_iter().map(|(identity, _)| identity).collect(),
        publish_date,
    })
}

/// The first reading of a gem file name under an internal namespace (#733), if any.
fn internal_gem_reading(state: &AppState, readings: &[GemFile]) -> Option<String> {
    readings
        .iter()
        .find(|reading| {
            crate::curation::is_internal_namespace(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Gems,
                &reading.name,
            )
        })
        .map(|reading| reading.name.clone())
}

/// Each identity's release date from the RubyGems API (the compact index has no dates) when
/// a lookup is allowed and upstream dates are trusted; `None` otherwise.
async fn upstream_gem_release_dates(
    state: &AppState,
    identities: Vec<GemFile>,
    lookup: bool,
) -> Vec<(GemFile, Option<i64>)> {
    let mut dated = Vec::with_capacity(identities.len());
    let proxy = state
        .config
        .gems
        .proxy
        .as_deref()
        .filter(|_| lookup && state.config.server.trust_upstream_dates);
    for identity in identities {
        let date = match proxy {
            Some(proxy) => {
                fetch_gems_date(
                    &state.http_client,
                    proxy,
                    &identity.name,
                    &identity.version,
                    identity.platform.as_deref(),
                    state.config.gems.proxy_timeout,
                )
                .await
            }
            None => None,
        };
        dated.push((identity, date));
    }
    dated
}

/// The longest gem name, and platform, NORA serves.
const GEM_NAME_MAX: usize = 256;

/// The longest gem version NORA serves.
const GEM_VERSION_MAX: usize = 128;

/// The longest gem file name (without its extension) that can have a reading NORA serves: a name,
/// a version and a platform each at its longest, and the two `-` between them. Every reading of a
/// longer name has a part over its limit, so such a name is refused before it is read.
const GEM_FILE_STEM_MAX: usize = GEM_NAME_MAX + 1 + GEM_VERSION_MAX + 1 + GEM_NAME_MAX;

/// Validate gem name: alphanumeric, hyphens, underscores, dots.
/// No path traversal, no slashes, no null bytes.
fn is_valid_gem_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= GEM_NAME_MAX
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
        && version.len() <= GEM_VERSION_MAX
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
    use crate::test_helpers::{
        body_bytes, create_test_context_with_config, send, send_with_headers,
    };
    use axum::http::{header, Method, StatusCode};

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
    async fn test_gems_range_request() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
        });
        let gem = b"0123456789abcdef";
        ctx.state
            .storage
            .put("gems/gems/test-gem-1.0.0.gem", gem)
            .await
            .unwrap();
        let url = "/gems/gems/test-gem-1.0.0.gem";

        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes 2-5/{}", gem.len())
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(body_bytes(resp).await.as_ref(), &gem[2..=5]);

        // A client that already holds the whole gem resumes with `bytes=<size>-`.
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            url,
            vec![("range", &format!("bytes={}-", gem.len())[..])],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes */{}", gem.len())
        );

        let resp = send(&ctx.app, Method::GET, url, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(body_bytes(resp).await.as_ref(), &gem[..]);
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

/// Property tests of the gem file name split: curation decides on the name and version the
/// file carries, so a platform gem (`nokogiri-1.13.0-x86_64-linux.gem`) must read as gem
/// `nokogiri`, version `1.13.0`, with its platform apart.
#[cfg(test)]
mod gem_filename_split_properties {
    use super::split_gem_filename;
    use proptest::prelude::*;

    fn gem_name() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_]{0,8}(-[a-z][a-z0-9_]{0,8}){0,2}"
    }

    fn gem_version() -> impl Strategy<Value = String> {
        "[0-9]{1,2}(\\.[0-9]{1,3}){0,3}(\\.(pre|rc|beta)[0-9]{0,2})?"
    }

    fn platform() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just("x86_64-linux"),
            Just("aarch64-linux"),
            Just("x86_64-darwin"),
            Just("arm64-darwin"),
            Just("x86_64-darwin-19"),
            Just("universal-darwin-20"),
            Just("x64-mingw-ucrt"),
            Just("x86-mingw32"),
            Just("java"),
        ]
    }

    proptest! {
        // A plain gem reads back its name and version.
        #[test]
        fn a_gem_reads_back_its_name_and_version(name in gem_name(), version in gem_version()) {
            let stem = format!("{name}-{version}");
            prop_assert_eq!(split_gem_filename(&stem), Some((name, version)));
        }

        // A platform gem reads back the same name and version: the platform is no part of either.
        #[test]
        fn a_platform_gem_reads_back_its_name_and_version(
            name in gem_name(),
            version in gem_version(),
            platform in platform(),
        ) {
            let stem = format!("{name}-{version}-{platform}");
            let split = split_gem_filename(&stem);
            prop_assert_eq!(split.as_ref().map(|(n, _)| n.as_str()), Some(name.as_str()), "{}", stem);
            prop_assert_eq!(split.as_ref().map(|(_, v)| v.as_str()), Some(version.as_str()), "{}", stem);
        }
    }
}

/// Curation decides on a platform gem's own gem and version: a version-specific rule holds for
/// every platform of that version, and the release date is the platform's.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod platform_gem_curation {
    use super::{fetch_gems_date, gem_file_readings, GemFile};
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{any, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn a_platform_with_a_number_and_a_name_field_with_a_digit_stay_apart() {
        let first = |stem| gem_file_readings(stem).into_iter().next().unwrap();
        assert_eq!(
            first("ffi-1.15.5-universal-darwin-19"),
            GemFile {
                name: "ffi".into(),
                version: "1.15.5".into(),
                platform: Some("universal-darwin-19".into())
            }
        );
        assert_eq!(
            first("devise-2fa-1.0.0"),
            GemFile {
                name: "devise-2fa".into(),
                version: "1.0.0".into(),
                platform: None
            }
        );
        assert_eq!(first("rails-7.1.0.rc1").version, "7.1.0.rc1");
        assert!(gem_file_readings("noversion").is_empty());
        assert!(gem_file_readings("x-1.0-").is_empty());
    }

    #[tokio::test]
    async fn a_blocked_version_is_refused_on_every_platform() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"GEM".to_vec()))
            .mount(&upstream)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "gems", "name": "nokogiri", "version": "1.13.0", "reason": "malware"}]}"#,
        )
        .unwrap();
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
        });
        for file in [
            "nokogiri-1.13.0.gem",
            "nokogiri-1.13.0-x86_64-linux.gem",
            "nokogiri-1.13.0-arm64-darwin.gem",
            "nokogiri-1.13.0-x64-mingw-ucrt.gem",
        ] {
            let resp = send(&ctx.app, Method::GET, &format!("/gems/gems/{file}"), "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{file}");
        }
        let resp = send(
            &ctx.app,
            Method::GET,
            "/gems/gems/nokogiri-1.13.1-x86_64-linux.gem",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "another version passes");
    }

    #[tokio::test]
    async fn a_platform_gem_gets_its_platforms_release_date() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/versions/nokogiri.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"number": "1.13.0", "platform": "ruby", "created_at": "2022-01-01T00:00:00Z"},
                {"number": "1.13.0", "platform": "x86_64-linux", "created_at": "2022-01-02T00:00:00Z"}
            ])))
            .mount(&upstream)
            .await;
        let client = reqwest::Client::new();
        let date = |platform| {
            let (client, uri) = (client.clone(), upstream.uri());
            async move { fetch_gems_date(&client, &uri, "nokogiri", "1.13.0", platform, 5).await }
        };
        assert_eq!(date(None).await, Some(1_640_995_200));
        assert_eq!(date(Some("x86_64-linux")).await, Some(1_641_081_600));
        assert_eq!(date(Some("arm64-darwin")).await, None);
    }
}

/// Gem file names as RubyGems builds them (`Gem::Specification#file_name`): measured with
/// RubyGems itself (`testdata/gems`, regenerated by `full_names.rb`) and generated from its
/// grammar — names with `-` and version-looking fields, versions as `Gem::Version#to_s` writes
/// them, platforms as `Gem::Platform#to_s` writes them.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod gem_file_names_per_rubygems {
    use super::{compact_index_lists, gem_file_readings, GemFile};
    use proptest::prelude::*;

    fn file(name: &str, version: &str, platform: Option<&str>) -> GemFile {
        GemFile {
            name: name.into(),
            version: version.into(),
            platform: platform.map(Into::into),
        }
    }

    /// name, version, platform (empty for `ruby`) and the file name RubyGems built from them.
    fn measured() -> Vec<[String; 4]> {
        let path = format!(
            "{}/testdata/gems/full-names.tsv",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|row| !row.starts_with('#'))
            .map(|row| {
                let fields: Vec<String> = row.split('\t').map(String::from).collect();
                fields.try_into().unwrap()
            })
            .collect()
    }

    fn measured_platforms() -> Vec<String> {
        let mut platforms: Vec<String> = measured()
            .into_iter()
            .map(|[_, _, platform, _]| platform)
            .filter(|platform| !platform.is_empty())
            .collect();
        platforms.sort();
        platforms.dedup();
        platforms
    }

    #[test]
    fn every_name_rubygems_builds_has_its_own_reading() {
        let rows = measured();
        assert_eq!(rows.len(), 552);
        for [name, version, platform, file_name] in rows {
            let stem = file_name.strip_suffix(".gem").unwrap();
            let own = file(&name, &version, (!platform.is_empty()).then_some(&platform));
            let readings = gem_file_readings(stem);
            assert!(
                readings.contains(&own),
                "{file_name}: {own:?} not among {readings:?}"
            );
        }
    }

    /// Every platform a release on rubygems.org carries is a platform, and the list of those no
    /// RubyGems writes is exactly the measured one (`testdata/gems/platforms.tsv`).
    #[test]
    fn every_platform_on_rubygems_org_is_a_platform() {
        let text = include_str!("../../testdata/gems/platforms.tsv");
        let platforms: Vec<&str> = text
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.split('\t').next().unwrap_or(""))
            .filter(|p| *p != "ruby")
            .collect();
        assert_eq!(platforms.len(), 226);
        for platform in &platforms {
            assert!(super::is_gem_platform(platform), "{platform}");
        }
        let mut unwritten: Vec<&str> = platforms
            .into_iter()
            .filter(|p| !super::rubygems_writes_platform(p))
            .collect();
        unwritten.sort_unstable();
        let mut listed = super::RUBYGEMS_ORG_PLATFORMS.to_vec();
        listed.sort_unstable();
        assert_eq!(listed, unwritten);
    }

    // A file name has at most six readings — a reading's platform has at most five fields
    // (`x64-mingw-ucrt-3.2-3.2.2`), and one reading has none — so the lookups a request makes,
    // one per reading, stay bounded; and every reading builds the name back.
    proptest! {
        #[test]
        fn a_file_name_reads_few_ways_and_each_builds_it_back(
            fields in proptest::collection::vec(
                proptest::sample::select(vec![
                    "a", "1", "1.0", "x86", "x86_64", "linux", "gnu", "mingw", "ucrt", "3.2",
                    "java", "universal", "darwin", "19", "mswin32", "60", "deadbeef", "",
                ]),
                1..14,
            )
        ) {
            let stem = fields.join("-");
            let readings = gem_file_readings(&stem);
            prop_assert!(readings.len() <= 6, "{} {:?}", stem, readings);
            for reading in readings {
                let rebuilt = match &reading.platform {
                    Some(platform) => format!("{}-{}-{}", reading.name, reading.version, platform),
                    None => format!("{}-{}", reading.name, reading.version),
                };
                prop_assert_eq!(rebuilt, stem.clone());
            }
        }
    }

    /// Every reading RubyGems allows of each file name, and no other: the union over RubyGems
    /// 3.6.9, 4.0.20 and master (`testdata/gems/readings.tsv`, `readings.sh`), name|version|platform.
    #[test]
    fn every_file_name_reads_exactly_as_rubygems_reads_it() {
        let path = format!("{}/testdata/gems/readings.tsv", env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(path).unwrap();
        let mut rows = 0;
        let mut wrong = Vec::new();
        for row in text.lines().filter(|row| !row.starts_with('#')) {
            let (stem, expected) = row.split_once('\t').unwrap();
            let mut expected: Vec<String> = expected
                .split(';')
                .filter(|r| !r.is_empty())
                .map(String::from)
                .collect();
            expected.sort();
            let mut read: Vec<String> = gem_file_readings(stem)
                .into_iter()
                .map(|f| {
                    format!(
                        "{}|{}|{}",
                        f.name,
                        f.version,
                        f.platform.unwrap_or_default()
                    )
                })
                .collect();
            read.sort();
            if read != expected {
                wrong.push(format!("{stem}: nora {read:?} rubygems {expected:?}"));
            }
            rows += 1;
        }
        assert_eq!(rows, 17701);
        assert!(
            wrong.is_empty(),
            "{} of {rows}:\n{}",
            wrong.len(),
            wrong.join("\n")
        );
    }

    // `Gem::Version` turns a `-` pre-release into `.pre.`: a version in a file name has no `-`.
    #[test]
    fn a_version_in_a_file_name_holds_no_hyphen() {
        assert_eq!(
            gem_file_readings("foo-1.0.0.pre.rc1"),
            vec![file("foo", "1.0.0.pre.rc1", None)]
        );
        assert_eq!(gem_file_readings("foo-1.0.0-rc1"), vec![]);
    }

    // What follows a version-looking field is a platform only if `Gem::Platform` reads one;
    // otherwise the field belongs to the name.
    #[test]
    fn a_version_looking_field_before_no_platform_belongs_to_the_name() {
        assert_eq!(
            gem_file_readings("foo-2-bar-1.0.0"),
            vec![file("foo-2-bar", "1.0.0", None)]
        );
        assert_eq!(
            gem_file_readings("devise-2fa-1.0.0"),
            vec![file("devise-2fa", "1.0.0", None)]
        );
        assert_eq!(gem_file_readings("x-1.0-"), vec![]);
        assert_eq!(gem_file_readings("noversion"), vec![]);
    }

    // A name with a version-looking field and a platform after it reads both ways.
    #[test]
    fn a_name_that_reads_two_ways_has_both_readings() {
        assert_eq!(
            gem_file_readings("evil-1-2.0-java"),
            vec![
                file("evil", "1", Some("2.0-java")),
                file("evil-1", "2.0", Some("java"))
            ]
        );
        assert_eq!(
            gem_file_readings("ffi-1.15.5-universal-darwin-19"),
            vec![
                file("ffi", "1.15.5", Some("universal-darwin-19")),
                file("ffi-1.15.5-universal-darwin", "19", None)
            ]
        );
    }

    // A content-addressed gem (RubyGems after 3.6) carries its address where a platform goes.
    #[test]
    fn a_content_address_stands_where_a_platform_goes() {
        assert_eq!(
            gem_file_readings("nokogiri-1.19.0-1a2b3c4d"),
            vec![file("nokogiri", "1.19.0", Some("1a2b3c4d"))]
        );
    }

    // A compact index row starts with `version` or `version-platform`; only that field counts.
    #[test]
    fn the_compact_index_lists_a_reading_by_the_rows_first_field() {
        let index = "---\n1.15.5 rake:>= 0|checksum:aa\n1.15.5-universal-darwin-19 |checksum:bb\n";
        assert!(compact_index_lists(index, &file("ffi", "1.15.5", None)));
        assert!(compact_index_lists(
            index,
            &file("ffi", "1.15.5", Some("universal-darwin-19"))
        ));
        assert!(!compact_index_lists(
            index,
            &file("ffi", "1.15.5", Some("x86_64-linux"))
        ));
        assert!(!compact_index_lists(
            index,
            &file("ffi-1.15.5-universal-darwin", "19", None)
        ));
        assert!(!compact_index_lists(
            "---\n2.0 ffi:= 1.15.5|checksum:cc\n",
            &file("ffi", "1.15.5", None)
        ));
        assert!(compact_index_lists(
            "1.0 |checksum:dd\n",
            &file("x", "1.0", None)
        ));
    }

    proptest! {
        // Built as RubyGems builds it, a file name has its own reading, and every reading
        // puts the file name back together.
        #[test]
        fn a_built_name_has_its_own_reading(
            name in "[a-zA-Z0-9][a-zA-Z0-9._]{0,5}(-([a-zA-Z0-9._]{1,5}|[0-9]{1,2}(\\.[0-9])?|java|linux|x86_64)){0,3}",
            version in "[0-9]{1,3}(\\.[0-9a-zA-Z]{1,3}){0,3}(-[0-9A-Za-z]{1,3}(\\.[0-9A-Za-z]{1,2})?)?",
            suffix in prop_oneof![
                Just(None),
                proptest::sample::select(measured_platforms()).prop_map(Some),
                "[0-9a-f]{8,16}".prop_map(Some),
            ],
        ) {
            let version = version.replace('-', ".pre.");
            let stem = match &suffix {
                Some(suffix) => format!("{name}-{version}-{suffix}"),
                None => format!("{name}-{version}"),
            };
            let own = GemFile { name, version, platform: suffix };
            let readings = gem_file_readings(&stem);
            prop_assert!(readings.contains(&own), "{}: {:?}", stem, readings);
            for reading in &readings {
                let rejoined = match &reading.platform {
                    Some(platform) => format!("{}-{}-{platform}", reading.name, reading.version),
                    None => format!("{}-{}", reading.name, reading.version),
                };
                prop_assert_eq!(&rejoined, &stem);
            }
        }
    }
}

/// Curation decides on the gem a file belongs to. A file name that reads two ways is weighed
/// both ways until the compact index NORA holds names its gem, and an internal gem is never
/// asked about upstream.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod gem_file_identity_curation {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"GEM".to_vec()))
            .mount(&upstream)
            .await;
        upstream
    }

    fn write(dir: &tempfile::TempDir, file: &str, body: &str) -> String {
        let path = dir.path().join(file);
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    // A rule names the gem as published; a name with a version-looking field is still the
    // gem the rule names, on every platform.
    #[tokio::test]
    async fn a_rule_on_a_name_with_a_version_looking_field_holds() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = write(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [{"registry": "gems", "name": "evil-1", "version": "*", "reason": "malware"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        for file in [
            "evil-1-2.0.gem",
            "evil-1-2.0-java.gem",
            "evil-1-2.0-x86_64-linux.gem",
        ] {
            let resp = send(&ctx.app, Method::GET, &format!("/gems/gems/{file}"), "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{file}");
        }
    }

    // An allowlist entry admits its own gem's files, not those of another gem whose file name
    // begins the same: the compact index says `foo-1.0-x86_64-linux-1.gem` is gem
    // `foo-1.0-x86_64-linux` 1, not `foo` 1.0.
    #[tokio::test]
    async fn an_allowlisted_gem_does_not_admit_another_gems_file() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = write(
            &dir,
            "allowlist.json",
            r#"{"version": 1, "entries": [{"registry": "gems", "name": "foo", "version": "1.0"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        // foo's index lists 1.0, but not for platform x86_64-linux-1: no reading is listed,
        // so both are weighed.
        ctx.state
            .storage
            .put("gems/info/foo", b"---\n1.0 |checksum:ff\n")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/gems/gems/foo-1.0-x86_64-linux-1.gem",
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "foo 1.0 has no such platform"
        );
        ctx.state
            .storage
            .put("gems/info/foo-1.0-x86_64-linux", b"---\n1 |checksum:aa\n")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/gems/gems/foo-1.0-x86_64-linux-1.gem",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "another gem's file");
        let resp = send(
            &ctx.app,
            Method::GET,
            "/gems/gems/foo-1.0-x86_64-linux.gem",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "foo's own platform file");
    }

    // A file that reads two ways passes the allowlist once the compact index NORA holds names
    // its gem; until then each reading must pass.
    #[tokio::test]
    async fn a_file_that_reads_two_ways_passes_once_the_index_names_its_gem() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = write(
            &dir,
            "allowlist.json",
            r#"{"version": 1, "entries": [{"registry": "gems", "name": "ffi", "version": "1.15.5"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        let file = "/gems/gems/ffi-1.15.5-universal-darwin-19.gem";
        let resp = send(&ctx.app, Method::GET, file, "").await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "no index: both readings weighed"
        );
        ctx.state
            .storage
            .put(
                "gems/info/ffi",
                b"---\n1.15.5 |checksum:aa\n1.15.5-universal-darwin-19 |checksum:bb\n",
            )
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, file, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "the index names ffi");
    }

    // An internal gem never reaches upstream: not its file, not its gemspec, and no question
    // about its release date either.
    #[tokio::test]
    async fn an_internal_gem_is_never_asked_about_upstream() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.internal_namespaces = vec!["corp-*".to_string(), "acme-1*".to_string()];
        });
        for uri in [
            // Internal under its second reading: acme-1 2.0 for java.
            "/gems/gems/acme-1-2.0-java.gem",
            "/gems/gems/corp-tools-1.0.0.gem",
            "/gems/gems/corp-tools-1.0.0-x86_64-linux.gem",
            "/gems/quick/Marshal.4.8/corp-tools-1.0.0.gemspec.rz",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert!(!resp.status().is_success(), "{uri}: {}", resp.status());
        }
        let asked: Vec<String> = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert!(asked.is_empty(), "asked upstream: {asked:?}");
    }

    // A cached file is checked against the allowlist integrity of each of its identities.
    #[tokio::test]
    async fn a_cached_file_meets_the_integrity_of_every_identity() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = write(
            &dir,
            "allowlist.json",
            &format!(
                r#"{{"version": 1, "entries": [
                    {{"registry": "gems", "name": "evil", "version": "1"}},
                    {{"registry": "gems", "name": "evil-1", "version": "2.0", "integrity": "sha256:{}"}}
                ]}}"#,
                "0".repeat(64)
            ),
        );
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        ctx.state
            .storage
            .put("gems/gems/evil-1-2.0-java.gem", b"GEM")
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/gems/gems/evil-1-2.0-java.gem", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "evil-1 2.0 integrity differs"
        );
    }
}

/// Every reading of a file name counts: a file is internal when any reading is, an index row
/// lists a reading by its whole first field, and every reading the cached indexes list is weighed.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod gem_file_every_reading_counts {
    use super::{compact_index_lists, GemFile};
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn file(name: &str, version: &str, platform: Option<&str>) -> GemFile {
        GemFile {
            name: name.into(),
            version: version.into(),
            platform: platform.map(Into::into),
        }
    }

    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"GEM".to_vec()))
            .mount(&upstream)
            .await;
        upstream
    }

    fn write(dir: &tempfile::TempDir, file: &str, body: &str) -> String {
        let path = dir.path().join(file);
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    // A file is internal when any reading is, even when the cached index lists only a public
    // reading of it.
    #[tokio::test]
    async fn internal_under_an_unlisted_reading_never_reaches_upstream() {
        let upstream = upstream().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.internal_namespaces = vec!["acme-1*".to_string()];
        });
        ctx.state
            .storage
            .put("gems/info/acme", b"---\n1-2.0-java |checksum:aa\n")
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/gems/gems/acme-1-2.0-java.gem", "").await;
        assert!(!resp.status().is_success(), "{}", resp.status());
        let asked = upstream.received_requests().await.unwrap();
        assert!(
            asked.is_empty(),
            "asked upstream: {:?}",
            asked
                .iter()
                .map(|r| r.url.path().to_string())
                .collect::<Vec<_>>()
        );
    }

    // An index row lists a reading by its whole first field, not by a prefix of it.
    #[test]
    fn an_index_row_is_matched_whole_not_by_prefix() {
        assert!(!compact_index_lists(
            "---\n19.1 |checksum:aa\n",
            &file("ffi-1.15.5-universal-darwin", "19", None)
        ));
        assert!(!compact_index_lists(
            "---\n1.0.1 |checksum:aa\n",
            &file("foo", "1.0", None)
        ));
    }

    // End to end: a reading listed only by a prefix does not narrow the file's identities, so
    // the rule on the other reading still holds.
    #[tokio::test]
    async fn a_prefix_listed_reading_does_not_shadow_a_blocked_one() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = write(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [{"registry": "gems", "name": "ffi", "version": "1.15.5", "reason": "malware"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        ctx.state
            .storage
            .put(
                "gems/info/ffi-1.15.5-universal-darwin",
                b"---\n19.1 |checksum:aa\n",
            )
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/gems/gems/ffi-1.15.5-universal-darwin-19.gem",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // Every reading the cached indexes list is an identity, not only the first, and not only
    // those of the first index found.
    #[tokio::test]
    async fn every_listed_reading_is_weighed() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = write(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [{"registry": "gems", "name": "evil-1", "version": "*", "reason": "malware"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        ctx.state
            .storage
            .put("gems/info/evil", b"---\n1-2.0-java |checksum:aa\n")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("gems/info/evil-1", b"---\n2.0-java |checksum:bb\n")
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/gems/gems/evil-1-2.0-java.gem", "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // A file's digest-quarantine clock starts at the newest release among its readings, so a
    // file that also reads as an older release does not leave quarantine early, whichever
    // reading is the newer one; its gemspec matures with it. The control, a file with one
    // reading released long ago, shows that the dates are honored.
    #[tokio::test]
    async fn a_file_waits_for_the_newest_release_among_its_readings() {
        use crate::digest_quarantine::QuarantineMode;
        use wiremock::matchers::path;
        let upstream = MockServer::start().await;
        let now = chrono::Utc::now().to_rfc3339();
        let old = "2020-01-01T00:00:00.000Z";
        let versions = [
            (
                "ffi",
                serde_json::json!([
                    {"number": "1.15.5", "platform": "ruby", "created_at": old},
                    {"number": "1.15.5", "platform": "universal-darwin-19", "created_at": now},
                    {"number": "1.15.6", "platform": "universal-darwin-20", "created_at": old},
                ]),
            ),
            (
                "ffi-1.15.5-universal-darwin",
                serde_json::json!([{"number": "19", "platform": "ruby", "created_at": old}]),
            ),
            (
                "ffi-1.15.6-universal-darwin",
                serde_json::json!([{"number": "20", "platform": "ruby", "created_at": now}]),
            ),
        ];
        for (name, list) in versions {
            Mock::given(path(format!("/api/v1/versions/{name}.json")))
                .respond_with(ResponseTemplate::new(200).set_body_json(list))
                .mount(&upstream)
                .await;
        }
        let files = [
            "ffi-1.15.5",
            "ffi-1.15.5-universal-darwin-19",
            "ffi-1.15.6-universal-darwin-20",
        ];
        for file in files {
            for (url, body) in [
                (format!("/gems/{file}.gem"), format!("gem {file}")),
                (
                    format!("/quick/Marshal.4.8/{file}.gemspec.rz"),
                    format!("gemspec {file}"),
                ),
            ] {
                Mock::given(path(url))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(body.into_bytes()))
                    .mount(&upstream)
                    .await;
            }
        }
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("1h".to_string());
        });
        for (file, expected) in [
            ("ffi-1.15.5", StatusCode::OK),
            ("ffi-1.15.5-universal-darwin-19", StatusCode::FORBIDDEN),
            ("ffi-1.15.6-universal-darwin-20", StatusCode::FORBIDDEN),
        ] {
            for url in [
                format!("/gems/gems/{file}.gem"),
                format!("/gems/quick/Marshal.4.8/{file}.gemspec.rz"),
            ] {
                let resp = send(&ctx.app, Method::GET, &url, "").await;
                assert_eq!(resp.status(), expected, "{url}");
            }
        }
    }
}

/// How a gem file is decided: each case holds one point of it — every reading weighed at its own
/// version, a name with no reading refused, internal readings never asked upstream.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod gem_file_decisions {
    use super::{gem_file_readings, GemFile};
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn file(name: &str, version: &str, platform: Option<&str>) -> GemFile {
        GemFile {
            name: name.into(),
            version: version.into(),
            platform: platform.map(Into::into),
        }
    }

    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"GEM".to_vec()))
            .mount(&upstream)
            .await;
        upstream
    }

    fn write(dir: &tempfile::TempDir, file: &str, body: &str) -> String {
        let path = dir.path().join(file);
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    async fn asked(upstream: &MockServer) -> Vec<String> {
        upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    // hosted-only, every identity of a stored file is weighed, not only the first.
    #[tokio::test]
    async fn hosted_mode_weighs_every_identity() {
        let dir = tempfile::tempdir().unwrap();
        let blocklist = write(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [{"registry": "gems", "name": "evil-1", "version": "*", "reason": "malware"}]}"#,
        );
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = None;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        ctx.state
            .storage
            .put("gems/gems/evil-1-2.0-java.gem", b"GEM")
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/gems/gems/evil-1-2.0-java.gem", "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // G03/G04: a file name with no reading is no gem curation can decide on: refused, and an
    // internal one never reaches upstream.
    #[tokio::test]
    async fn a_name_with_no_reading_is_refused_and_never_asked_upstream() {
        let upstream = upstream().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.internal_namespaces = vec!["corp-*".to_string()];
        });
        assert!(gem_file_readings("corp-tools").is_empty());
        for path in [
            "/gems/gems/corp-tools.gem",
            "/gems/quick/Marshal.4.8/corp-tools.gemspec.rz",
        ] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{path}");
        }
        let asked = asked(&upstream).await;
        assert!(asked.is_empty(), "asked upstream: {asked:?}");
    }

    // each identity is weighed at its own version: `evil-1` 2.0 is blocked even though
    // the other reading of the file is version 1.
    #[tokio::test]
    async fn every_identity_is_weighed_at_its_own_version() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = write(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [{"registry": "gems", "name": "evil-1", "version": "2.0", "reason": "malware"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        let resp = send(&ctx.app, Method::GET, "/gems/gems/evil-1-2.0-java.gem", "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // the gemspec of a file internal under an unlisted reading never reaches upstream.
    #[tokio::test]
    async fn gemspec_internal_under_an_unlisted_reading_never_reaches_upstream() {
        let upstream = upstream().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.internal_namespaces = vec!["acme-1*".to_string()];
        });
        ctx.state
            .storage
            .put("gems/info/acme", b"---\n1-2.0-java |checksum:aa\n")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/gems/quick/Marshal.4.8/acme-1-2.0-java.gemspec.rz",
            "",
        )
        .await;
        assert!(!resp.status().is_success(), "{}", resp.status());
        let asked = asked(&upstream).await;
        assert!(asked.is_empty(), "asked upstream: {asked:?}");
    }

    // RubyGems 3.6.9 builds `foo-1.0-x86-my_platform.gem` and `foo-1.0-my_platform.gem`
    // (a test platform `Gem::Platform` reads): each has its own reading.
    #[test]
    fn a_test_platform_rubygems_builds_has_its_reading() {
        assert!(gem_file_readings("foo-1.0-x86-my_platform").contains(&file(
            "foo",
            "1.0",
            Some("x86-my_platform")
        )));
        assert!(gem_file_readings("foo-1.0-my_platform").contains(&file(
            "foo",
            "1.0",
            Some("my_platform")
        )));
    }

    // a version is `Gem::Version#to_s`; `Gem::Version.correct?("1.0_1")` is false.
    #[test]
    fn a_version_field_holds_no_underscore() {
        assert_eq!(gem_file_readings("foo-1.0_1"), vec![]);
    }

    // `Gem::Platform#to_s` writes no empty field (`x86--linux` becomes `x86-linux`).
    #[test]
    fn a_platform_has_no_empty_field() {
        assert_eq!(gem_file_readings("foo-1.0-x86--linux"), vec![]);
    }

    // a missing index of one reading does not stop the others being looked up: the
    // listed reading is the file's identity, and a rule on the unlisted one does not hold.
    #[tokio::test]
    async fn a_missing_index_does_not_hide_a_later_listing() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = write(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [{"registry": "gems", "name": "evil", "version": "*", "reason": "malware"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        ctx.state
            .storage
            .put("gems/info/evil-1", b"---\n2.0-java |checksum:bb\n")
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/gems/gems/evil-1-2.0-java.gem", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

/// A gem file is decided in one place: both download paths go through `gem_file_gate` before they
/// serve or fetch anything, and readings, identities, release dates and curation of a file are
/// asked nowhere else (the compact index keeps its own package-level check). A white list over
/// this file's production code, with controls.
#[cfg(test)]
mod gem_file_decided_once {
    use crate::test_helpers::source_reader::{body, holders, production};

    const SERVES_OR_FETCHES: [&str; 5] = [
        "get_verified(",
        "with_binary(",
        "proxy_fetch(",
        "range_response(",
        "spawn_cache",
    ];

    fn violations(source: &str) -> Vec<String> {
        let code = production(source);
        let mut wrong = Vec::new();
        for (needle, allowed) in [
            ("check_download(", &["compact_index", "gem_file_gate"][..]),
            ("upstream_gem_release_dates(", &["gem_file_gate"][..]),
            ("gem_file_identities(", &["gem_file_gate"][..]),
            (
                "gem_file_readings(",
                &["gem_file_gate", "split_gem_filename"][..],
            ),
            ("gem_file_gate(", &["download_gem", "download_gemspec"][..]),
        ] {
            for holder in holders(code, needle) {
                if !allowed.contains(&holder.as_str()) {
                    wrong.push(format!("{needle} in {holder}"));
                }
            }
        }
        for handler in ["download_gem", "download_gemspec"] {
            let Some(body) = body(code, handler) else {
                wrong.push(format!("{handler}: not found"));
                continue;
            };
            let Some(gate) = body.find("gem_file_gate(") else {
                wrong.push(format!("{handler}: no gate"));
                continue;
            };
            if let Some((at, token)) = SERVES_OR_FETCHES
                .iter()
                .filter_map(|token| body.find(token).map(|at| (at, token)))
                .min()
            {
                if at < gate {
                    wrong.push(format!("{handler}: {token} before the gate"));
                }
            }
        }
        wrong
    }

    #[test]
    fn both_paths_decide_through_the_gate() {
        let wrong = violations(include_str!("gems.rs"));
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    #[test]
    fn the_white_list_catches_a_second_decision_and_a_late_gate() {
        let source = include_str!("gems.rs");
        let second = source.replacen(
            "\nfn is_valid_gem_file(",
            "\nfn second(s: &AppState) { let _ = crate::curation::check_download(s); }\nfn is_valid_gem_file(",
            1,
        );
        assert_ne!(second, source);
        assert!(violations(&second).iter().any(|v| v.contains("in second")));
        let late = source.replacen(
            "    let artifact = stem.to_string();\n    let storage_key = format!(\"gems/gems/{}.gem\", artifact);",
            "    let _early = state.storage.get_verified(\"x\");\n    let artifact = stem.to_string();\n    let storage_key = format!(\"gems/gems/{}.gem\", artifact);",
            1,
        );
        assert_ne!(late, source);
        assert!(violations(&late)
            .iter()
            .any(|v| v.contains("download_gem: get_verified")));
    }
}

/// What a gem file name costs before it is answered (X03). The name arrives from any client, so
/// the work done on it before it is refused must not grow with what the client sends: the
/// handlers run that work inline, on a runtime worker.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod gem_file_name_work {
    use super::{
        gem_file_readings, gem_platform_to_s, gem_platform_v36, gem_platform_v40,
        is_valid_gem_file, rubygems_writes_platform,
    };
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use proptest::prelude::*;
    use std::time::Duration;

    /// The longest name a served gem file can carry: a name, a version and a platform each at the
    /// longest the key rules allow (256, 128, 256), and the two `-` between them.
    const LONGEST_SERVABLE: usize = 256 + 1 + 128 + 1 + 256;

    /// Run `work` on its own thread and fail unless it is done within `limit`. The work under test
    /// is synchronous: an async timeout could not interrupt it.
    fn done_within<T: Send + 'static>(
        limit: Duration,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (done, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(work());
        });
        wait.recv_timeout(limit)
            .unwrap_or_else(|_| panic!("not done within {limit:?}"))
    }

    /// `1-1-…-1`: every field reads as a version, so every split is a candidate reading and every
    /// suffix is weighed as a platform.
    fn all_versions(len: usize) -> String {
        let mut stem = "1-".repeat(len / 2);
        stem.truncate(len.saturating_sub(1));
        stem.push('1');
        stem
    }

    #[test]
    fn a_name_of_the_longest_servable_length_is_read_at_once() {
        let stem = all_versions(LONGEST_SERVABLE);
        assert_eq!(stem.len(), LONGEST_SERVABLE);
        let readings = done_within(Duration::from_secs(2), move || gem_file_readings(&stem));
        // Its readings take nearly the whole name as the gem name, longer than a gem name may
        // be: the gate refuses it.
        assert!(!readings.is_empty());
        assert!(!readings.iter().all(is_valid_gem_file), "{readings:?}");
    }

    #[test]
    fn an_overlong_gem_file_name_is_refused_at_once_on_both_paths() {
        let stem = all_versions(60_000);
        let statuses = done_within(Duration::from_secs(10), move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let ctx = create_test_context_with_config(|cfg| {
                        cfg.gems.enabled = true;
                        cfg.gems.proxy = None;
                    });
                    let gem =
                        send(&ctx.app, Method::GET, &format!("/gems/gems/{stem}.gem"), "").await;
                    let spec = send(
                        &ctx.app,
                        Method::GET,
                        &format!("/gems/quick/Marshal.4.8/{stem}.gemspec.rz"),
                        "",
                    )
                    .await;
                    (gem.status(), spec.status())
                })
        });
        assert_eq!(statuses, (StatusCode::BAD_REQUEST, StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn the_longest_servable_name_is_not_refused() {
        // A name, a version and a platform each at its longest (`<cpu>-linux` reads back as
        // written): its one reading is served, so the name is looked up, not refused.
        let stem = format!(
            "{}-1.{}-{}-linux",
            "a".repeat(256),
            "0".repeat(126),
            "c".repeat(250)
        );
        assert_eq!(stem.len(), LONGEST_SERVABLE);
        let readings = gem_file_readings(&stem);
        assert_eq!(readings.len(), 1, "{readings:?}");
        assert!(readings.iter().all(is_valid_gem_file));
        let ctx = create_test_context_with_config(|cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = None;
        });
        let gem = send(&ctx.app, Method::GET, &format!("/gems/gems/{stem}.gem"), "").await;
        assert_eq!(gem.status(), StatusCode::NOT_FOUND);
        let spec = send(
            &ctx.app,
            Method::GET,
            &format!("/gems/quick/Marshal.4.8/{stem}.gemspec.rz"),
            "",
        )
        .await;
        assert_eq!(spec.status(), StatusCode::NOT_FOUND);
    }

    /// `rubygems_writes_platform` as it reads without any shortcut: every candidate is parsed.
    fn writes_platform_trying_every_candidate(suffix: &str) -> bool {
        let mut candidates = vec![suffix.to_string()];
        for (at, _) in suffix.match_indices('-') {
            candidates.push(format!("{}{}", &suffix[..at], &suffix[at + 1..]));
            candidates.push(format!("{}_{}", &suffix[..at], &suffix[at + 1..]));
        }
        candidates.iter().any(|candidate| {
            gem_platform_to_s(&gem_platform_v36(candidate), false) == suffix
                || gem_platform_to_s(&gem_platform_v40(candidate), true) == suffix
        })
    }

    fn platform_word() -> impl Strategy<Value = &'static str> {
        prop::sample::select(vec![
            "x86_64",
            "x86",
            "i686",
            "i386",
            "arm64",
            "aarch64",
            "universal",
            "x64",
            "java",
            "jruby",
            "linux",
            "gnu",
            "musl",
            "darwin",
            "darwin19",
            "19",
            "8",
            "mingw32",
            "mingw",
            "ucrt",
            "mswin32",
            "mswin64",
            "60",
            "dalvik5",
            "dotnet",
            "dotnet4.0",
            "freebsd12",
            "openbsd7.1",
            "solaris2.8",
            "wasi",
            "cygwin",
            "aix5",
            "a_platform",
            "test_platform",
            "macruby",
            "netbsdelf",
            "1",
            "1.2",
            "",
            "x",
        ])
    }

    fn platform_suffix() -> impl Strategy<Value = String> {
        (
            prop::collection::vec(platform_word(), 1..7),
            prop::collection::vec(prop::sample::select(vec!["-", "-", "_", ""]), 6),
        )
            .prop_map(|(words, seps)| {
                let mut suffix = String::new();
                for (i, word) in words.iter().enumerate() {
                    if i > 0 {
                        suffix.push_str(seps[i - 1]);
                    }
                    suffix.push_str(word);
                }
                suffix
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        // However the platform check is cut short, it says what trying every candidate says.
        #[test]
        fn the_platform_check_says_what_every_candidate_says(suffix in platform_suffix()) {
            prop_assert_eq!(
                rubygems_writes_platform(&suffix),
                writes_platform_trying_every_candidate(&suffix),
                "{}", suffix
            );
        }

        // No name longer than the longest servable one has a reading NORA serves: refusing such a
        // name before it is read refuses nothing the gate would let through.
        #[test]
        fn no_overlong_name_has_only_servable_readings(
            name in "[a-z][a-z0-9_]{0,12}(-[a-z0-9]{1,6}){0,2}",
            name_pad in 0usize..300,
            version in "[0-9]{1,3}(\\.[0-9a-z]{1,4}){0,3}",
            version_pad in 0usize..140,
            platform in prop::option::of("[a-z0-9_]{1,8}-(linux|darwin|mingw32)(-[0-9]{1,2})?"),
            platform_pad in 0usize..300,
            grow in 0usize..3,
        ) {
            let mut name = format!("{name}{}", "n".repeat(name_pad));
            let mut version = format!("{version}{}", "0".repeat(version_pad));
            let mut platform = platform.map(|p| format!("{}{p}", "c".repeat(platform_pad)));
            let len = name.len() + 1 + version.len() + platform.as_ref().map_or(0, |p| p.len() + 1);
            // Made just longer than the bound, in the field `grow` names.
            let short = (LONGEST_SERVABLE + 1).saturating_sub(len);
            match (grow, platform.as_mut()) {
                (0, _) => name.push_str(&"n".repeat(short)),
                (1, _) | (_, None) => version.push_str(&"0".repeat(short)),
                (_, Some(p)) => p.insert_str(0, &"c".repeat(short)),
            }
            let stem = match &platform {
                Some(p) => format!("{name}-{version}-{p}"),
                None => format!("{name}-{version}"),
            };
            prop_assert!(stem.len() > LONGEST_SERVABLE);
            let readings = gem_file_readings(&stem);
            prop_assert!(
                readings.is_empty() || !readings.iter().all(is_valid_gem_file),
                "{} reads as {:?}", stem, readings
            );
        }
    }
}
