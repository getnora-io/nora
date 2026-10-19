// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Cargo registry with sparse index (RFC 2789).
//!
//! Implements:
//!   GET  /cargo/index/config.json                  — registry configuration
//!   GET  /cargo/index/{prefix}/{crate}             — sparse index entries
//!   GET  /cargo/api/v1/crates/{crate_name}         — crate metadata (proxy)
//!   GET  /cargo/api/v1/crates/{name}/{ver}/download — download .crate
//!   PUT  /cargo/api/v1/crates/new                  — cargo publish

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, NamespaceAuthority};
use crate::config::UpstreamAuth;
use crate::registry::{
    circuit_open_response, method_not_allowed, nora_base_url, proxy_fetch, ProxyError, UpstreamMiss,
};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::storage::Storage;
use crate::validation::validate_storage_key;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
    Extension, Router,
};
use sha2::Digest;
use std::time::Duration;

/// Resolve the effective quarantine mode and TTL for the cargo registry,
/// falling back to the global curation settings when no cargo-specific
/// override is configured. Extracted so the two cargo proxy paths stay in sync.
fn resolve_cargo_quarantine_config(
    state: &AppState,
) -> (crate::digest_quarantine::QuarantineMode, i64) {
    crate::digest_quarantine::resolve_global(
        state.config.curation.cargo.quarantine.as_ref().or(state
            .config
            .curation
            .quarantine
            .as_ref()),
        state
            .config
            .curation
            .cargo
            .quarantine_ttl
            .as_deref()
            .or(state.config.curation.quarantine_ttl.as_deref()),
    )
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/cargo/index/config.json", get(index_config))
        .route("/cargo/index/{*path}", get(sparse_index))
        .route("/cargo/api/v1/crates/{crate_name}", get(get_metadata))
        .route(
            "/cargo/api/v1/crates/{crate_name}/{version}/download",
            get(download),
        )
        .route(
            "/cargo/api/v1/crates/new",
            put(publish).fallback(|| async { method_not_allowed("PUT") }),
        )
}

// ============================================================================
// Sparse index — RFC 2789
// ============================================================================

/// GET /cargo/index/config.json — tells cargo where to download crates.
async fn index_config(State(state): State<AppState>) -> Response {
    let base = nora_base_url(&state);
    // Cargo only sends credentials to the sparse index and dl endpoints when
    // the registry advertises `auth-required` (RFC 3139). Without it, a
    // private deployment 401s every index fetch before publish even starts.
    let auth_required = state.config.auth.enabled && !state.config.auth.anonymous_read;
    let config = serde_json::json!({
        "dl": format!("{}/cargo/api/v1/crates", base),
        // Cargo appends `/api/v1/...` to this base for write and metadata requests,
        // so the advertised API root must be the registry mount, not `/cargo/api`.
        "api": format!("{}/cargo", base),
        "auth-required": auth_required
    });
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=300"),
            ),
        ],
        serde_json::to_vec(&config).unwrap_or_default(),
    )
        .into_response()
}

/// GET /cargo/index/{prefix}/{crate} — sparse index lookup.
///
/// Cargo sparse index uses a directory structure based on crate name length:
///   1 char:  /cargo/index/1/{name}
///   2 chars: /cargo/index/2/{name}
///   3 chars: /cargo/index/3/{first_char}/{name}
///   4+ chars: /cargo/index/{first_two}/{next_two}/{name}
///
/// Each entry is one JSON line per version (newline-delimited).
async fn sparse_index(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    // Extract crate name from the path (last segment), normalized to lowercase
    let crate_name = match path.rsplit('/').next() {
        Some(name) if !name.is_empty() => name.to_lowercase(),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };

    // Validate crate name
    if !is_valid_crate_name(&crate_name) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Verify prefix matches the crate name (case-insensitive)
    let expected_prefix = crate_index_prefix(&crate_name);
    if path.to_lowercase() != format!("{}/{}", expected_prefix, crate_name) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let index_key = format!("cargo/index/{}/{}", expected_prefix, crate_name);

    // A crate published here is served only from its own entries: no upstream is asked, and
    // nothing an upstream answers is written over its index.
    let published = published_state(&state.storage, &expected_prefix, &crate_name).await;
    if let Published::Yes(ref entries) = published {
        return published_index_response(&state, &headers, &expected_prefix, &crate_name, entries)
            .await;
    }

    // Another spelling of a published crate (`-` and `_` name one crate, as on crates.io) is
    // refused, never asked of an upstream: the upstream's crate of that name is not this one.
    let own = match published {
        Published::No => OwnSpelling::Known(false),
        _ => OwnSpelling::Read,
    };
    let refusal = match canon_record(&state.storage, &crate_name).await {
        Ok(record) => {
            another_published_spelling(&state.storage, &crate_name, record.as_deref(), own).await
        }
        Err(e) => Err(e),
    };
    match refusal {
        Ok(Some(published)) => return another_spelling_response(&crate_name, &published),
        Ok(None) => {}
        Err(e) => {
            tracing::error!(registry = "cargo", crate_name = %crate_name, error = %e, "cargo: reading the crate's name record failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    // An unpublished crate, or one whose listing failed: what is stored is read first, and one
    // pure decision (`index_answer`, a decision table) says what answers.
    let assembled = assembled_index(&state.storage, &expected_prefix, &crate_name).await;
    // What an older release left at the crate's index: its upstream cache, or a crate published
    // before per-version entries.
    let stored_index = state.storage.get(&index_key).await.ok();
    // NORA's copy of an upstream's index lives at its own key, never at the crate's index, so a
    // first publish never finds an upstream crate where its index goes.
    let copy_key = upstream_copy_key(&expected_prefix, &crate_name);
    let upstream_copy = state.storage.get(&copy_key).await.ok();
    // The sparse index is MUTABLE (new versions append and `yanked` flips at any time), so a
    // proxied copy is revalidated unless a positive `metadata_ttl` keeps it fresh; without an
    // upstream the copy is all there is. Only NORA's upstream copy has a TTL.
    let copy_fresh = match upstream_copy {
        Some(_) => {
            let modified = state.storage.stat(&copy_key).await.map(|m| m.modified);
            crate::cache_ttl::mutable_ref_fresh(
                state.config.cargo.proxy.is_some(),
                state.config.cargo.metadata_ttl,
                modified,
            )
        }
        None => false,
    };
    let facts = UnpublishedFacts {
        listing_failed: matches!(published, Published::Unknown),
        assembled: match &assembled {
            Ok(Some(_)) => Stored::Present,
            Ok(None) => Stored::Absent,
            Err(_) => Stored::Unreadable,
        },
        stored_index: stored_index.is_some(),
        embedded: is_import_embedded(&state, &crate_name),
        upstream_copy: match (&upstream_copy, copy_fresh) {
            (None, _) => CopyState::Absent,
            (Some(_), true) => CopyState::Fresh,
            (Some(_), false) => CopyState::Stale,
        },
        internal: crate::curation::is_internal_namespace(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Cargo,
            &crate_name,
        ),
        upstream: state.config.cargo.proxy.is_some(),
    };
    let fetch = match index_answer(facts) {
        IndexAnswer::Assembled => {
            if let Ok(Some(data)) = assembled {
                tracing::warn!(registry = "cargo", crate_name = %crate_name, "cargo: no entries listed beside an assembled index");
                state.metrics.record_cache_hit("cargo");
                return sparse_index_conditional(data.to_vec(), &headers);
            }
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        IndexAnswer::Unavailable => {
            if let Err(e) = assembled {
                tracing::error!(registry = "cargo", crate_name = %crate_name, error = %e, "cargo: reading the assembled index failed");
            }
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        IndexAnswer::StoredIndex => {
            return match stored_index {
                Some(data) => {
                    state.metrics.record_cache_hit("cargo");
                    sparse_index_conditional(data.to_vec(), &headers)
                }
                None => StatusCode::NOT_FOUND.into_response(),
            };
        }
        IndexAnswer::UpstreamCopy => {
            return match upstream_copy {
                Some(data) => {
                    state.metrics.record_download("cargo");
                    state.metrics.record_cache_hit("cargo");
                    state.activity.push(ActivityEntry::new(
                        ActionType::CacheHit,
                        crate_name.to_string(),
                        crate::registry_type::RegistryType::Cargo,
                        "CACHE",
                    ));
                    sparse_index_conditional(data.to_vec(), &headers)
                }
                None => StatusCode::NOT_FOUND.into_response(),
            };
        }
        // #68 namespace isolation: an internal-namespace crate is never fetched upstream.
        IndexAnswer::Refuse => {
            return crate::curation::check_namespace_isolation(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Cargo,
                &crate_name,
            )
            .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
        }
        IndexAnswer::NotFound => return StatusCode::NOT_FOUND.into_response(),
        IndexAnswer::Fetch { cache, fallback } => (cache, fallback),
    };
    let (cache, fallback) = fetch;
    let Some(proxy_url) = state.config.cargo.proxy.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    // crates.io sparse index lives at index.crates.io
    let upstream_index_url = if proxy_url.contains("crates.io") {
        format!("https://index.crates.io/{}/{}", expected_prefix, crate_name)
    } else {
        // Custom registry: assume sparse index at {proxy}/index/{prefix}/{crate}
        format!(
            "{}/index/{}/{}",
            proxy_url.trim_end_matches('/'),
            expected_prefix,
            crate_name
        )
    };

    match proxy_fetch(
        &state.http_client,
        &upstream_index_url,
        Duration::from_secs(state.config.cargo.proxy_timeout),
        expose_opt(&state.config.cargo.proxy_auth).map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        RegistryType::Cargo,
    )
    .await
    {
        Ok(data) => {
            state.metrics.record_download("cargo");
            state.metrics.record_cache_miss("cargo");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                crate_name.to_string(),
                crate::registry_type::RegistryType::Cargo,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "cargo", ""));
            // Cached only for a crate known not to be published here, and only at NORA's
            // upstream copy.
            if cache {
                state.spawn_cache("cargo", copy_key, Bytes::from(data.clone()));
            }
            sparse_index_conditional(data, &headers)
        }
        Err(e) => {
            // Upstream unreachable — serve the stored copy if there is one (graceful).
            let stale = match fallback {
                Fallback::UpstreamCopy => upstream_copy,
                Fallback::StoredIndex => stored_index,
                Fallback::None => None,
            };
            if let Some(data) = stale {
                tracing::warn!(
                    crate_name,
                    "Cargo upstream failed, serving stale cached index"
                );
                let mut response = sparse_index_conditional(data.to_vec(), &headers);
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static("x-nora-stale"),
                    axum::http::header::HeaderValue::from_static("true"),
                );
                return response;
            }
            match e {
                ProxyError::CircuitOpen(reg) => circuit_open_response(&reg),
                _ => {
                    tracing::debug!(
                        crate_name,
                        error = ?e,
                        "Cargo sparse index upstream error"
                    );
                    UpstreamMiss::of(&e).response("cargo", &crate_name)
                }
            }
        }
    }
}

// ============================================================================
// Metadata & download (existing, refactored)
// ============================================================================

/// GET /cargo/api/v1/crates/{crate_name} — JSON metadata.
async fn get_metadata(State(state): State<AppState>, Path(crate_name): Path<String>) -> Response {
    if !is_valid_crate_name(&crate_name) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let crate_name = crate_name.to_lowercase();
    let key = format!("cargo/{}/metadata.json", crate_name);

    if let Ok(data) = state.storage.get(&key).await {
        return (StatusCode::OK, data).into_response();
    }

    // #68 namespace isolation: a locally-published internal crate was served above;
    // an internal name with no local copy must not be fetched upstream.
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Cargo,
        &crate_name,
    ) {
        return response;
    }

    // Proxy fetch metadata from upstream
    let proxy_url = match &state.config.cargo.proxy {
        Some(url) => url.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let url = format!(
        "{}/api/v1/crates/{}",
        proxy_url.trim_end_matches('/'),
        crate_name
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.cargo.proxy_timeout),
        expose_opt(&state.config.cargo.proxy_auth).map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        RegistryType::Cargo,
    )
    .await
    {
        Ok(data) => {
            state.spawn_cache("cargo", key.clone(), Bytes::from(data.clone()));
            (StatusCode::OK, data).into_response()
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, crate_name = %crate_name, "Cargo metadata proxy fetch failed");
            UpstreamMiss::of(&e).response("cargo", &crate_name)
        }
    }
}

/// Self-prime `cargo/{name}/metadata.json` so the release-age date (#748) is
/// available on the download path itself.
///
/// `cargo build` uses the sparse index (`/cargo/index/...`) and then the download
/// endpoint; it never calls `/api/v1/crates/{name}`, which is the only writer of
/// `metadata.json` (the carrier of per-version `created_at`). Without this, the
/// quarantine on a proxied crate always falls back to NORA's own clock and the
/// release-age maturation never fires. Synchronous `put` (not `spawn_cache`) so the
/// date is readable on the same request. Best-effort: any failure leaves the date
/// `None` (fail-safe — the crate is held as new). Namespace-safe: an internal crate
/// is never fetched upstream (#68). Mirrors PyPI's `ensure_pypi_dates_cached`.
async fn ensure_cargo_metadata_cached(state: &AppState, crate_name: &str) {
    let key = format!("cargo/{}/metadata.json", crate_name);
    if state.storage.get(&key).await.is_ok() {
        return;
    }
    // #68: never fetch an internal-namespace crate's metadata upstream.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Cargo,
        crate_name,
    ) {
        return;
    }
    let proxy_url = match &state.config.cargo.proxy {
        Some(url) => url.clone(),
        None => return,
    };
    let url = format!(
        "{}/api/v1/crates/{}",
        proxy_url.trim_end_matches('/'),
        crate_name
    );
    if let Ok(data) = proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.cargo.proxy_timeout),
        expose_opt(&state.config.cargo.proxy_auth).map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        RegistryType::Cargo,
    )
    .await
    {
        let _ = state.storage.put(&key, &data).await;
    }
}

/// GET /cargo/api/v1/crates/{name}/{version}/download — download .crate file.
async fn download(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((crate_name, version)): Path<(String, String)>,
) -> Response {
    if !is_valid_crate_name(&crate_name) || !crate::validation::is_one_segment(&version) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    // The upstream path keeps the name as cargo sent it (the published name, from the index):
    // static.crates.io stores `Inflector` under its capitals and refuses `inflector`. It is
    // built before the name is lowercased, so every decision below — cache key, curation,
    // isolation, publish date, integrity — sees only the lowercase name.
    let upstream_path = format!("api/v1/crates/{}/{}/download", crate_name, version);
    let crate_name = crate_name.to_lowercase();

    // Another spelling of a published crate is refused here too: neither an upstream nor a copy
    // cached from one answers for it. A record naming this spelling is weighed before an upstream is
    // asked (below), so a download of a published crate lists nothing. The record is read once.
    let record = match canon_record(&state.storage, &crate_name).await {
        Ok(record) => record,
        Err(e) => {
            tracing::error!(registry = "cargo", crate_name = %crate_name, error = %e, "cargo: reading the crate's name record failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    match another_published_spelling(
        &state.storage,
        &crate_name,
        record.as_deref(),
        OwnSpelling::Defer,
    )
    .await
    {
        Ok(Some(published)) => return another_spelling_response(&crate_name, &published),
        Ok(None) => {}
        Err(e) => {
            tracing::error!(registry = "cargo", crate_name = %crate_name, error = %e, "cargo: reading the crate's name record failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    // Extract publish date from cached Cargo metadata
    let publish_date = {
        let meta_key = format!("cargo/{}/metadata.json", crate_name);
        // #748: a `cargo build` resolves via the sparse index and reaches this
        // download endpoint WITHOUT ever calling /api/v1/crates/{name} (the only
        // writer of metadata.json), so the per-version `created_at` would never be
        // cached and the quarantine would fall back to NORA's own clock. Self-prime
        // the metadata here (synchronously, so the date is readable on this same
        // request) — gated on trust, namespace-safe, best-effort. Mirrors PyPI's
        // ensure_pypi_dates_cached.
        // A name with a canon record is NORA's (published now or before): an upstream's dates for
        // that name belong to another crate, and asking for them gives the name away.
        if state.config.server.trust_upstream_dates && record.is_none() {
            ensure_cargo_metadata_cached(&state, &crate_name).await;
        }
        extract_cargo_publish_date(
            &state.storage,
            &meta_key,
            &version,
            state.config.server.trust_upstream_dates,
        )
        .await
    };

    // Curation check — before storage access. #733 serve-local: an internal-namespace crate
    // is operator-owned — skip curation and serve any local copy below; the upstream branch is
    // blocked separately (never proxy an internal name).
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Cargo,
        &crate_name,
    );
    if !internal {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Cargo,
            &crate_name,
            crate::curation::RequestVersion::Known(version.to_string()),
            publish_date,
        ) {
            return response;
        }
    }

    let key = format!(
        "cargo/{}/{}/{}-{}.crate",
        crate_name, version, crate_name, version
    );

    // Try local storage first. `get_verified` runs the same fail-closed pin gate
    // as `get`, but reflects the outcome in the type: the integrity witness is
    // discharged once, here at the serve site, through `verified_body` — serving
    // raw or merely tamper-evident bytes on this path is a compile error. An
    // open-world read (unpinned key / S3 backend) is served knowingly, never
    // silently. (Typestate rollout — see `crate::verified`, raw.rs is the PoC.)
    if let Ok(outcome) = state.storage.get_verified(&key).await {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };

        // Post-download integrity verification (issue #189) — a curation policy
        // check, separate from the typestate pin gate, run on the witnessed bytes.
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Cargo,
            &crate_name,
            Some(&version),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("cargo");
        state.metrics.record_cache_hit("cargo");
        state.activity.push(ActivityEntry::new(
            ActionType::Pull,
            format!("{}@{}", crate_name, version),
            crate::registry_type::RegistryType::Cargo,
            "LOCAL",
        ));
        state
            .audit
            .log(AuditEntry::new("pull", "proxy", "", "cargo", ""));
        let (q_mode, q_secs) = resolve_cargo_quarantine_config(&state);
        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "cargo",
            &data,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }
        // Resume support: 206 for a `Range` request, 416 when the client asks past
        // the end. It sits after the gates above because the quarantine digest check
        // needs the whole object. A partial body cannot be rehashed, so the serve
        // relies on the lockfile checksum cargo verifies itself (docker did the same
        // in #657). An absent/malformed range falls through to the full 200.
        if let Some(response) = crate::registry::range::range_response(
            &state.storage,
            &[&key],
            &headers,
            data.len() as u64,
            "application/x-tar",
            &[(
                header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".to_string(),
            )],
        )
        .await
        {
            return response;
        }
        return (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/x-tar"),
                ),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=31536000, immutable"),
                ),
                (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
            ],
            data,
        )
            .into_response();
    }

    // #733: an internal-namespace crate with no local copy is never proxied upstream.
    if internal {
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Cargo,
            &crate_name,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // Before an upstream is asked: a stale record naming this spelling (it is not published) while
    // another spelling of the canon is refuses as well.
    match another_published_spelling(
        &state.storage,
        &crate_name,
        record.as_deref(),
        OwnSpelling::Read,
    )
    .await
    {
        Ok(Some(published)) => return another_spelling_response(&crate_name, &published),
        Ok(None) => {}
        Err(e) => {
            tracing::error!(registry = "cargo", crate_name = %crate_name, error = %e, "cargo: reading the crate's name record failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    // Proxy fetch from upstream
    let proxy_url = match &state.config.cargo.proxy {
        Some(url) => url.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), upstream_path);

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.cargo.proxy_timeout),
        expose_opt(&state.config.cargo.proxy_auth).map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        RegistryType::Cargo,
    )
    .await
    {
        Ok(data) => {
            // The allowlist's pinned integrity holds on the first download too, before anything is cached:
            // the cache-hit branch checks the same rule.
            if let Some(response) = crate::curation::verify_integrity(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Cargo,
                &crate_name,
                Some(&version),
                &data,
            ) {
                return response;
            }
            state.spawn_cache("cargo", key.clone(), Bytes::from(data.clone()));
            state.metrics.record_download("cargo");
            state.metrics.record_cache_miss("cargo");
            state.activity.push(ActivityEntry::new(
                ActionType::Pull,
                format!("{}@{}", crate_name, version),
                crate::registry_type::RegistryType::Cargo,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "cargo", ""));
            let (q_mode, q_secs) = resolve_cargo_quarantine_config(&state);
            if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                &state.digest_store,
                "cargo",
                &data,
                &q_mode,
                q_secs,
                &url,
                publish_date,
            ) {
                return resp;
            }
            (
                StatusCode::OK,
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/x-tar"),
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
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, crate_name = %crate_name, version = %version, "Cargo crate proxy fetch failed");
            UpstreamMiss::of(&e).response("cargo", &format!("{crate_name}@{version}"))
        }
    }
}

// ============================================================================
// Cargo publish
// ============================================================================

/// PUT /cargo/api/v1/crates/new — publish a crate.
///
/// Wire format (cargo puts this as the body):
///   4 bytes LE: metadata JSON length
///   N bytes:    metadata JSON
///   4 bytes LE: .crate tarball length
///   M bytes:    .crate tarball
async fn publish(
    State(state): State<AppState>,
    Extension(authority): Extension<NamespaceAuthority>,
    user: Option<Extension<crate::auth::AuthenticatedUser>>,
    body: Bytes,
) -> Response {
    if body.len() < 8 {
        return (StatusCode::BAD_REQUEST, "Payload too small").into_response();
    }

    // Parse wire format
    let metadata_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if body.len() < 4 + metadata_len + 4 {
        return (StatusCode::BAD_REQUEST, "Truncated metadata").into_response();
    }

    let metadata_bytes = &body[4..4 + metadata_len];
    let metadata: serde_json::Value = match serde_json::from_slice(metadata_bytes) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid metadata JSON: {}", e),
            )
                .into_response()
        }
    };

    let crate_len_offset = 4 + metadata_len;
    let crate_len = u32::from_le_bytes([
        body[crate_len_offset],
        body[crate_len_offset + 1],
        body[crate_len_offset + 2],
        body[crate_len_offset + 3],
    ]) as usize;

    let crate_start = crate_len_offset + 4;
    if body.len() < crate_start + crate_len {
        return (StatusCode::BAD_REQUEST, "Truncated crate tarball").into_response();
    }

    let crate_data = &body[crate_start..crate_start + crate_len];

    // Extract required fields
    let name = match metadata.get("name").and_then(|n| n.as_str()) {
        Some(n) => n,
        None => return (StatusCode::BAD_REQUEST, "Missing crate name").into_response(),
    };

    let vers = match metadata.get("vers").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return (StatusCode::BAD_REQUEST, "Missing crate version").into_response(),
    };

    // Validate
    if !is_valid_crate_name(name) {
        return (StatusCode::BAD_REQUEST, "Invalid crate name").into_response();
    }
    if validate_storage_key(vers).is_err() {
        return (StatusCode::BAD_REQUEST, "Invalid version").into_response();
    }

    // Normalize to lowercase for consistent storage keys
    let name = name.to_lowercase();
    let vers = vers.to_string();

    // Enforce OIDC namespace_scope on the crate coordinate (#583).
    if enforce_namespace_scope(&authority, &name).is_err() {
        return (StatusCode::FORBIDDEN, "Outside namespace scope").into_response();
    }

    // One crate per canon (`-` and `_` name one crate, as on crates.io). The canon's record is read
    // under its own lock, taken before the crate's and held to the end, so two spellings published
    // at once cannot both pass. A first publish writes the record once it has succeeded: a refused
    // or failed publish leaves none (a crash in between is healed by the rebuild at startup).
    let name_key = crate_name_record_key(&name);
    let name_lock = state.publish_lock(&name_key);
    let _name_guard = name_lock.lock().await;
    let refusal = match canon_record(&state.storage, &name).await {
        Ok(record) => {
            another_published_spelling(&state.storage, &name, record.as_deref(), OwnSpelling::Read)
                .await
        }
        Err(e) => Err(e),
    };
    match refusal {
        Ok(Some(published)) => {
            let err = serde_json::json!({
                "errors": [{"detail": format!(
                    "crate `{name}` is published here as `{published}`: `-` and `_` name the same crate"
                )}]
            });
            return (
                StatusCode::CONFLICT,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )],
                serde_json::to_vec(&err).unwrap_or_default(),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(registry = "cargo", crate_name = %name, error = %e, "cargo publish: reading the crate's name record failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }

    // TOCTOU protection: lock per crate (not per version!) to serialize
    // index read-modify-write. The index file is shared across all versions
    // of the same crate, so concurrent publishes of different versions
    // must be serialized to prevent lost index entries.
    let crate_key = format!("cargo/{}/{}/{}-{}.crate", name, vers, name, vers);
    let prefix = crate_index_prefix(&name);
    let index_lock_key = format!("cargo/index/{}/{}", prefix, name);
    let lock = state.publish_lock(&index_lock_key);
    let _guard = lock.lock().await;

    // Check version immutability
    if state.storage.stat(&crate_key).await.is_some() {
        let err = serde_json::json!({
            "errors": [{"detail": format!("crate version `{}@{}` already exists", name, vers)}]
        });
        return (
            StatusCode::CONFLICT,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            serde_json::to_vec(&err).unwrap_or_default(),
        )
            .into_response();
    }

    // Compute checksum
    let cksum = hex::encode(sha2::Sha256::digest(crate_data));

    // Build sparse index entry (one JSON line per version)
    // Transform deps: Cargo publish sends `version_req` but index format requires `req`,
    // and `explicit_name_in_toml` becomes `package` in the index.
    let deps = metadata
        .get("deps")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .map(|dep| {
                    let mut d = dep.clone();
                    if let Some(obj) = d.as_object_mut() {
                        // version_req -> req
                        if let Some(vr) = obj.remove("version_req") {
                            obj.insert("req".to_string(), vr);
                        }
                        // explicit_name_in_toml -> package
                        if let Some(ent) = obj.remove("explicit_name_in_toml") {
                            if !ent.is_null() {
                                obj.insert("package".to_string(), ent);
                            }
                        }
                    }
                    d
                })
                .collect::<Vec<_>>()
        })
        .map(serde_json::Value::Array)
        .unwrap_or(serde_json::json!([]));
    let features = metadata
        .get("features")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let features2 = metadata.get("features2").cloned();
    let links = metadata.get("links").cloned();

    let mut index_entry = serde_json::json!({
        "name": name,
        "vers": vers,
        "deps": deps,
        "cksum": cksum,
        "features": features,
        "yanked": false,
    });

    if let Some(f2) = features2 {
        index_entry["features2"] = f2;
    }
    if let Some(l) = links {
        index_entry["links"] = l;
    }

    let entry_line = serde_json::to_string(&index_entry).unwrap_or_default();

    // Store the .crate tarball FIRST (immutable, per-version). If the index write fails after,
    // re-publish is possible (immutability checks the .crate, not the index).
    // Decided before anything is written, so a refusal leaves the store as it was.
    let migrate_from = match migration_source(&state, &prefix, &name).await {
        Ok(source) => source,
        Err(refusal) => return refusal,
    };

    if state.storage.put(&crate_key, crate_data).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Migrate an old single-file sparse index to per-version entries BEFORE writing the new one,
    // so the regenerate below lists both the migrated and the new versions (no loss).
    if let Some(index) = migrate_from {
        migrate_cargo_index(&state, &prefix, &name, &index).await;
    }

    // Write this version's index line as its OWN immutable key. Concurrent publishes of DIFFERENT
    // versions write distinct keys, so none is lost — the #39 fix (vs the old read-modify-write of
    // the shared index file under a process-local lock).
    let entry_key = format!("cargo/index-entries/{}/{}/{}.json", prefix, name, vers);
    if state
        .storage
        .put(&entry_key, entry_line.as_bytes())
        .await
        .is_err()
    {
        let _ = state.storage.delete(&crate_key).await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Regenerate the sparse index by listing the per-version entry keys (multi-replica-safe).
    if regenerate_cargo_index(&state.storage, &prefix, &name)
        .await
        .is_err()
    {
        tracing::error!(crate_name = %name, "cargo publish: failed to regenerate sparse index");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    state.metrics.record_upload("cargo");
    let artifact = format!("{}@{}", name, vers);
    state.audit.log(AuditEntry::new(
        "push",
        crate::auth::audit_actor(&user),
        &artifact,
        "cargo",
        "",
    ));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        artifact,
        crate::registry_type::RegistryType::Cargo,
        "LOCAL",
    ));
    state.repo_index.invalidate("cargo");

    settle_name_record(&state.storage, &name).await;

    // Cargo expects a JSON response with warnings array
    let response = serde_json::json!({
        "warnings": {
            "invalid_categories": [],
            "invalid_badges": [],
            "other": []
        }
    });

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::to_vec(&response).unwrap_or_default(),
    )
        .into_response()
}

// ============================================================================
// Helpers
// ============================================================================

/// Regenerate the cargo sparse index (`cargo/index/{prefix}/{crate}`) by LISTING the immutable
/// per-version entry keys and concatenating their lines. Multi-replica-safe: concurrent publishes
/// write distinct entry keys, so no version line is lost (vs the old read-modify-write of the
/// shared index file). Mirrors maven scan-regenerate.
async fn regenerate_cargo_index(storage: &Storage, prefix: &str, name: &str) -> Result<(), ()> {
    let index = assemble_cargo_index(storage, prefix, name)
        .await
        .ok_or(())?;
    store_assembled_index(storage, prefix, name, &index)
        .await
        .map_err(|_| ())
}

/// The per-version entries of a crate published here: the only source of its index.
fn entries_prefix(prefix: &str, name: &str) -> String {
    format!("cargo/index-entries/{prefix}/{name}/")
}

/// Where NORA keeps the index it assembled from a published crate's entries. Written in one put,
/// so finding it is proof the crate is NORA's: `cargo/index/<prefix>/<name>` is only a copy of it
/// for older releases, and anything else there (an older release's upstream cache, a crate
/// published before per-version entries) is not. No request reaches this key: no route builds
/// the prefix.
fn assembled_index_key(prefix: &str, name: &str) -> String {
    format!("cargo/index-assembled/{prefix}/{name}")
}

/// What an index request for a crate with no listed entries found, read before anything is
/// decided.
#[derive(Debug, Clone, Copy)]
struct UnpublishedFacts {
    /// The entries listing failed (the crate may be published) rather than finding none.
    listing_failed: bool,
    /// The index NORA assembled from entries (`cargo/index-assembled/…`).
    assembled: Stored,
    /// Something is stored at `cargo/index/…` (an older release's cache, or a crate published
    /// before per-version entries).
    stored_index: bool,
    /// The operator named the crate in `cargo.import_embedded`.
    embedded: bool,
    /// NORA's upstream copy (`cargo/index-upstream/…`) and whether it is fresh.
    upstream_copy: CopyState,
    /// The name is in an internal namespace.
    internal: bool,
    /// An upstream is configured.
    upstream: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Stored {
    Absent,
    Present,
    /// A storage error other than NotFound.
    Unreadable,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CopyState {
    Absent,
    Stale,
    Fresh,
}

/// What answers an index request for a crate with no listed entries.
#[derive(Debug, Clone, Copy, PartialEq)]
enum IndexAnswer {
    /// The index NORA assembled.
    Assembled,
    /// 503: the assembled index cannot be read, so the crate may be NORA's.
    Unavailable,
    /// What is stored at `cargo/index/…`.
    StoredIndex,
    /// NORA's upstream copy.
    UpstreamCopy,
    /// Namespace isolation refuses (internal name, nothing stored).
    Refuse,
    NotFound,
    /// Ask the upstream; cache its answer at the upstream copy only when `cache`; when it fails,
    /// serve `fallback`.
    Fetch {
        cache: bool,
        fallback: Fallback,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Fallback {
    UpstreamCopy,
    StoredIndex,
    None,
}

/// The decision table for a crate with no listed entries, as a
/// pure function: an assembled index is the crate's own (and an unreadable one may be); an index
/// the operator named its own is served as it is; a fresh upstream copy answers; otherwise an
/// internal name or a missing upstream is served from the stored copy (the upstream copy, else
/// `cargo/index/…`) or refused / not found, and anything else asks the upstream — caching its
/// answer only when the listing found nothing rather than failed.
fn index_answer(f: UnpublishedFacts) -> IndexAnswer {
    match f.assembled {
        Stored::Present => return IndexAnswer::Assembled,
        Stored::Unreadable => return IndexAnswer::Unavailable,
        Stored::Absent => {}
    }
    if f.embedded && f.stored_index {
        return IndexAnswer::StoredIndex;
    }
    if f.upstream_copy == CopyState::Fresh {
        return IndexAnswer::UpstreamCopy;
    }
    let stored = if f.upstream_copy != CopyState::Absent {
        Fallback::UpstreamCopy
    } else if f.stored_index {
        Fallback::StoredIndex
    } else {
        Fallback::None
    };
    let served = |none: IndexAnswer| match stored {
        Fallback::UpstreamCopy => IndexAnswer::UpstreamCopy,
        Fallback::StoredIndex => IndexAnswer::StoredIndex,
        Fallback::None => none,
    };
    if f.internal {
        return served(IndexAnswer::Refuse);
    }
    if !f.upstream {
        return served(IndexAnswer::NotFound);
    }
    IndexAnswer::Fetch {
        cache: !f.listing_failed,
        fallback: stored,
    }
}

/// Where NORA keeps its copy of an upstream's index for a crate not published here. No request
/// reaches this key (no route builds the prefix) and a publish never reads it: an upstream's
/// versions are never imported as published ones.
fn upstream_copy_key(prefix: &str, name: &str) -> String {
    format!("cargo/index-upstream/{prefix}/{name}")
}

/// Whether the operator named the crate in `cargo.import_embedded`: its stored index, found with no
/// entries beside it, is its own (published before per-version entries).
fn is_import_embedded(state: &AppState, name: &str) -> bool {
    state
        .config
        .cargo
        .import_embedded
        .iter()
        .any(|n| n.eq_ignore_ascii_case(name))
}

/// Whether a crate has versions published here, read from its entries.
enum Published {
    /// The entry keys listed.
    Yes(Vec<String>),
    No,
    /// The listing failed: the crate may be published, and nothing about it is written.
    Unknown,
}

async fn published_state(storage: &Storage, prefix: &str, name: &str) -> Published {
    match storage.list(&entries_prefix(prefix, name)).await {
        Ok(keys) if keys.is_empty() => Published::No,
        Ok(keys) => Published::Yes(keys),
        Err(e) => {
            tracing::warn!(registry = "cargo", crate_name = %name, error = %e, "cargo: listing published entries failed");
            Published::Unknown
        }
    }
}

/// The index NORA assembled for the crate, if any. Err on a storage error other than NotFound: the
/// crate may be NORA's, and the caller must not treat it as an upstream's.
async fn assembled_index(
    storage: &Storage,
    prefix: &str,
    name: &str,
) -> crate::storage::Result<Option<Bytes>> {
    match storage.get(&assembled_index_key(prefix, name)).await {
        Ok(index) => Ok(Some(index)),
        Err(crate::storage::StorageError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The versions the entry keys of a crate name (`<entries prefix><version>.json`).
fn entry_versions(prefix: &str, name: &str, keys: &[String]) -> std::collections::BTreeSet<String> {
    let entries = entries_prefix(prefix, name);
    keys.iter()
        .filter_map(|key| key.strip_prefix(&entries)?.strip_suffix(".json"))
        .map(str::to_string)
        .collect()
}

/// The versions a sparse index lists, one per line; None when a line is not an index line.
fn index_versions(index: &[u8]) -> Option<std::collections::BTreeSet<String>> {
    index
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice::<serde_json::Value>(line)
                .ok()?
                .get("vers")?
                .as_str()
                .map(str::to_string)
        })
        .collect()
}

/// The index of a published crate, one line per entry in a deterministic order (cargo accepts any
/// line order). None when the listing or an entry cannot be read.
async fn assemble_cargo_index(storage: &Storage, prefix: &str, name: &str) -> Option<Vec<u8>> {
    // All-or-fail: a transient list/read error must NOT silently produce a
    // truncated (or empty) index and publish it as authoritative — that would
    // drop versions a client already saw as published. Abort instead; the caller
    // returns 500 and the existing index stays intact until a clean rebuild. An
    // empty list is a legitimate empty crate, not an error, and is preserved.
    let mut keys = storage.list(&entries_prefix(prefix, name)).await.ok()?;
    keys.sort();
    let mut index: Vec<u8> = Vec::new();
    for key in &keys {
        let line = storage.get(key).await.ok()?;
        index.extend_from_slice(&line);
        if !line.ends_with(b"\n") {
            index.push(b'\n');
        }
    }
    Some(index)
}

/// Store an assembled index: first at its own key (one put — from then on the crate is NORA's),
/// then the copy at `cargo/index/<prefix>/<name>` that older releases read. A failed copy is
/// logged; this release never reads it.
async fn store_assembled_index(
    storage: &Storage,
    prefix: &str,
    name: &str,
    index: &[u8],
) -> Result<(), crate::storage::StorageError> {
    storage
        .put(&assembled_index_key(prefix, name), index)
        .await?;
    if let Err(e) = storage
        .put(&format!("cargo/index/{prefix}/{name}"), index)
        .await
    {
        tracing::warn!(registry = "cargo", crate_name = %name, error = %e, "cargo: copy of the assembled index for older releases not stored");
    }
    Ok(())
}

/// The sparse index of a crate published here: the index NORA assembled when it lists exactly the
/// versions the entries name, else one rebuilt from the entries under the publish lock (a version
/// published by an older release, or a publish that stopped before its rebuild). No upstream is
/// asked. Rebuilt bytes are served even when they cannot be stored; 503 only when they cannot be
/// assembled.
async fn published_index_response(
    state: &AppState,
    headers: &HeaderMap,
    prefix: &str,
    name: &str,
    entries: &[String],
) -> Response {
    let index_key = format!("cargo/index/{prefix}/{name}");
    let listed = entry_versions(prefix, name, entries);
    if let Ok(Some(data)) = assembled_index(&state.storage, prefix, name).await {
        if index_versions(&data).as_ref() == Some(&listed) {
            state.metrics.record_download("cargo");
            state.metrics.record_cache_hit("cargo");
            return sparse_index_conditional(data.to_vec(), headers);
        }
    }
    // LOCK-SAFE: tokio mutex, the one publish holds while it writes this crate's index; a reader
    // that finds no current index NORA assembled rebuilds it once. Nothing else is locked under it.
    let lock = state.publish_lock(&index_key);
    let _guard = lock.lock().await;
    if let Ok(Some(data)) = assembled_index(&state.storage, prefix, name).await {
        if index_versions(&data).as_ref() == Some(&listed) {
            return sparse_index_conditional(data.to_vec(), headers);
        }
    }
    let Some(index) = assemble_cargo_index(&state.storage, prefix, name).await else {
        tracing::error!(registry = "cargo", crate_name = %name, "cargo: a published entry cannot be read; not serving a partial index");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Err(e) = store_assembled_index(&state.storage, prefix, name, &index).await {
        tracing::warn!(registry = "cargo", crate_name = %name, error = %e, "cargo: rebuilt index not stored; served anyway");
    }
    state.metrics.record_download("cargo");
    sparse_index_conditional(index, headers)
}

/// The index a first publish imports as published versions, if any: the one NORA assembled (its
/// entries are gone), or the stored index of a crate the operator named in `cargo.import_embedded`. Otherwise it may be an upstream crate an older
/// release cached at the same key (this release keeps upstream answers at `upstream_copy_key`,
/// which a publish never reads), and importing it would publish the upstream's versions: the
/// publish is refused with 409 and the operator decides.
async fn migration_source(
    state: &AppState,
    prefix: &str,
    name: &str,
) -> Result<Option<Bytes>, Response> {
    match state.storage.list(&entries_prefix(prefix, name)).await {
        Ok(keys) if !keys.is_empty() => return Ok(None), // already migrated
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(registry = "cargo", crate_name = %name, error = %e, "cargo publish: listing published entries failed");
            return Err((StatusCode::SERVICE_UNAVAILABLE, "storage listing failed").into_response());
        }
    }
    match assembled_index(&state.storage, prefix, name).await {
        Ok(Some(index)) => return Ok(Some(index)),
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(registry = "cargo", crate_name = %name, error = %e, "cargo publish: reading the assembled index failed");
            return Err((StatusCode::SERVICE_UNAVAILABLE, "storage read failed").into_response());
        }
    }
    let index_key = format!("cargo/index/{prefix}/{name}");
    let Ok(index) = state.storage.get(&index_key).await else {
        return Ok(None);
    };
    if is_import_embedded(state, name) {
        return Ok(Some(index));
    }
    tracing::warn!(registry = "cargo", crate_name = %name, "cargo publish refused: stored index of unknown origin");
    let detail = format!(
        "{index_key} holds a sparse index with no record of where it came from: an upstream crate cached by an older NORA release, or a crate published to NORA before per-version entries. Publishing over it would import its versions as published ones. If it is a cache, delete {index_key} and publish again; if it is your own crate, set NORA_CARGO_IMPORT_EMBEDDED={name} and publish again."
    );
    Err((
        StatusCode::CONFLICT,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::to_vec(&serde_json::json!({ "errors": [{ "detail": detail }] }))
            .unwrap_or_default(),
    )
        .into_response())
}

/// Import a stored single-file index as per-version entries (see `migration_source`).
async fn migrate_cargo_index(state: &AppState, prefix: &str, name: &str, index: &[u8]) {
    for line in index.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_slice::<serde_json::Value>(line) {
            if let Some(vers) = entry.get("vers").and_then(|v| v.as_str()) {
                let key = format!("cargo/index-entries/{}/{}/{}.json", prefix, name, vers);
                let _ = state.storage.put(&key, line).await;
            }
        }
    }
}

/// Compute sparse index prefix for a crate name (RFC 2789).
/// The name crates.io treats a crate as: lowercase, `_` written as `-`. Spellings with one canon
/// (`my-crate`, `my_crate`, `My_Crate`) are one crate. Pure.
pub(crate) fn canonical_crate_name(name: &str) -> String {
    name.to_lowercase().replace('_', "-")
}

/// Where NORA records the spelling a crate was published under, by its canon.
fn crate_name_record_key(name: &str) -> String {
    format!("cargo/_names/{}", canonical_crate_name(name))
}

/// When a request for one spelling reads whether that spelling is published.
#[derive(Clone, Copy)]
enum OwnSpelling {
    /// The caller knows.
    Known(bool),
    /// Read where the answer depends on it.
    Read,
    /// A record naming this spelling decides nothing yet: the download asks again before an upstream.
    Defer,
}

/// Another published spelling of `name`'s canon that a request for `name` is refused for, or None
/// to go on, given the canon's record ([`canon_record`]). The record
/// names the spelling published first; a spelling published itself always goes on. A record naming
/// a spelling with no published entries (this one or another) is stale and decides nothing: the
/// entries are scanned for a published spelling of the canon instead. Err on a storage error other
/// than NotFound.
async fn another_published_spelling(
    storage: &Storage,
    name: &str,
    record: Option<&str>,
    own: OwnSpelling,
) -> crate::storage::Result<Option<String>> {
    let Some(record) = record else {
        return Ok(None);
    };
    let own_published = match own {
        OwnSpelling::Known(published) => published,
        OwnSpelling::Defer if record == name => return Ok(None),
        OwnSpelling::Defer | OwnSpelling::Read => is_published(storage, name).await?,
    };
    if own_published {
        return Ok(None);
    }
    if record != name && is_published(storage, record).await? {
        return Ok(Some(record.to_string()));
    }
    published_spelling_by_scan(storage, name).await
}

/// The spelling the record of `name`'s canon names, or None: no record, or a name without `-` or
/// `_`, which has no other spelling and reads none. Err on a storage error other than NotFound.
async fn canon_record(storage: &Storage, name: &str) -> crate::storage::Result<Option<String>> {
    if !name.contains(['-', '_']) {
        return Ok(None);
    }
    match storage.get(&crate_name_record_key(name)).await {
        Ok(data) => {
            let record = String::from_utf8_lossy(&data).trim().to_string();
            Ok((!record.is_empty()).then_some(record))
        }
        Err(crate::storage::StorageError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether `name` has published entries. Err when they cannot be listed: the caller must not guess.
async fn is_published(storage: &Storage, name: &str) -> crate::storage::Result<bool> {
    match published_state(storage, &crate_index_prefix(name), name).await {
        Published::Yes(_) => Ok(true),
        Published::No => Ok(false),
        Published::Unknown => Err(crate::storage::StorageError::Network(format!(
            "listing the entries of {name} failed"
        ))),
    }
}

/// The spellings of `name` that differ in the first four characters, where `-` and `_` are swapped:
/// the index directory depends on those characters, so these are every directory a spelling of the
/// canon can fall in. Pure.
fn spelling_heads(name: &str) -> Vec<String> {
    let lower = name.to_lowercase();
    let head: Vec<char> = lower.chars().take(4).collect();
    let rest: String = lower.chars().skip(4).collect();
    let seps: Vec<usize> = (0..head.len())
        .filter(|&i| head[i] == '-' || head[i] == '_')
        .collect();
    (0..1usize << seps.len())
        .map(|mask| {
            let mut h = head.clone();
            for (bit, &i) in seps.iter().enumerate() {
                h[i] = if mask & (1 << bit) != 0 { '_' } else { '-' };
            }
            h.into_iter().collect::<String>() + &rest
        })
        .collect()
}

/// Another spelling of `name`'s canon with published entries, found by listing the entries in each
/// index directory a spelling of the canon can fall in. Read only when the canon's record is stale.
async fn published_spelling_by_scan(
    storage: &Storage,
    name: &str,
) -> crate::storage::Result<Option<String>> {
    let canon = canonical_crate_name(name);
    let prefixes: std::collections::BTreeSet<String> = spelling_heads(name)
        .iter()
        .map(|spelling| crate_index_prefix(spelling))
        .collect();
    for prefix in prefixes {
        let dir = format!("cargo/index-entries/{prefix}/");
        for key in storage.list(&dir).await? {
            let Some(spelling) = key
                .strip_prefix(&dir)
                .and_then(|rest| rest.split('/').next())
            else {
                continue;
            };
            if spelling != name && canonical_crate_name(spelling) == canon {
                return Ok(Some(spelling.to_string()));
            }
        }
    }
    Ok(None)
}

/// After a successful publish, under the canon's lock: the record names this spelling, unless it
/// names another spelling that is published itself (both were, before records existed). A record
/// that cannot be read is left as it is; the rebuild at the next start writes a missing one.
async fn settle_name_record(storage: &Storage, name: &str) {
    let key = crate_name_record_key(name);
    let keep = match storage.get(&key).await {
        Ok(data) => {
            let record = String::from_utf8_lossy(&data).trim().to_string();
            record == name
                || (!record.is_empty() && is_published(storage, &record).await.unwrap_or(true))
        }
        Err(crate::storage::StorageError::NotFound) => false,
        Err(e) => {
            tracing::error!(registry = "cargo", crate_name = %name, error = %e, "cargo publish: reading the crate's name record failed; left as it is");
            true
        }
    };
    if !keep {
        if let Err(e) = storage.put(&key, name.as_bytes()).await {
            tracing::error!(registry = "cargo", crate_name = %name, error = %e, "cargo publish: writing the crate's name record failed; the rebuild at the next start writes it");
        }
    }
}

/// The refusal of another spelling of a published crate: 404, naming the published spelling.
fn another_spelling_response(name: &str, published: &str) -> Response {
    let err = serde_json::json!({
        "errors": [{"detail": format!(
            "crate `{name}` is published here as `{published}`: `-` and `_` name the same crate"
        )}]
    });
    (
        StatusCode::NOT_FOUND,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::to_vec(&err).unwrap_or_default(),
    )
        .into_response()
}

/// How many name records the startup rebuild writes at once.
const NAME_RECORD_WRITE_CONCURRENCY: usize = 16;

/// Writes the name record of every crate published before records existed (a store from an older
/// release, or crates published while rolled back to one), from its per-version entries. Runs at
/// startup, before the server listens; a publish writes its own record. What is recorded is read
/// with one listing, so a start with every record in place reads no record; the missing ones are
/// written a few at a time. Where two spellings of one canon were both published, the first in key
/// order is recorded, and each spelling still serves its own crate (a published spelling is
/// answered before the record is read). If the records cannot be listed, each is read before it is
/// written, so a record is never overwritten.
pub async fn rebuild_crate_name_records(storage: &Storage) {
    use futures::StreamExt;
    let keys = match storage.list("cargo/index-entries/").await {
        Ok(keys) => keys,
        Err(e) => {
            tracing::warn!(registry = "cargo", error = %e, "cargo: listing published crates for their name records failed");
            return;
        }
    };
    let names: std::collections::BTreeSet<String> = keys
        .iter()
        .filter_map(|key| key.strip_prefix("cargo/index-entries/"))
        .filter_map(|rest| rest.rsplit('/').nth(1))
        .filter(|name| is_valid_crate_name(name))
        .map(str::to_string)
        .collect();
    let recorded: Option<std::collections::HashSet<String>> = match storage
        .list("cargo/_names/")
        .await
    {
        Ok(keys) => Some(
            keys.iter()
                .filter_map(|key| key.strip_prefix("cargo/_names/"))
                .map(str::to_string)
                .collect(),
        ),
        Err(e) => {
            tracing::warn!(registry = "cargo", error = %e, "cargo: listing name records failed; each is read before it is written");
            None
        }
    };
    // The first spelling in key order of every canon without a record.
    let mut missing: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for name in names {
        let canon = canonical_crate_name(&name);
        if recorded.as_ref().is_some_and(|r| r.contains(&canon)) {
            continue;
        }
        missing.entry(canon).or_insert(name);
    }
    let read_first = recorded.is_none();
    let written: usize = futures::stream::iter(missing.into_values())
        .map(|name| async move {
            let key = crate_name_record_key(&name);
            if read_first && !matches!(storage.get(&key).await, Err(crate::storage::StorageError::NotFound)) {
                return 0;
            }
            match storage.put(&key, name.as_bytes()).await {
                Ok(()) => 1,
                Err(e) => {
                    tracing::warn!(registry = "cargo", crate_name = %name, error = %e, "cargo: writing a crate's name record failed");
                    0
                }
            }
        })
        .buffer_unordered(NAME_RECORD_WRITE_CONCURRENCY)
        .fold(0, |sum, n| async move { sum + n })
        .await;
    if written > 0 {
        tracing::info!(
            registry = "cargo",
            written,
            "cargo: name records written for crates published before them"
        );
    }
}

fn crate_index_prefix(name: &str) -> String {
    let lower = name.to_lowercase();
    match lower.len() {
        1 => "1".to_string(),
        2 => "2".to_string(),
        3 => format!("3/{}", &lower[..1]),
        _ => format!("{}/{}", &lower[..2], &lower[2..4]),
    }
}

/// Validate crate name per Cargo spec.
fn is_valid_crate_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    // Must start with alphanumeric
    let first = name.chars().next().unwrap_or('\0');
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    // Only alphanumeric, `-`, `_`
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Build sparse index response with ETag and conditional 304 support.
///
/// Computes a SHA-256 ETag from the response body. If the client sends
/// `If-None-Match` with a matching ETag, returns 304 Not Modified.
fn sparse_index_conditional(data: Vec<u8>, req_headers: &HeaderMap) -> Response {
    let etag_hash = hex::encode(sha2::Sha256::digest(&data));
    let etag_val = format!("\"{}\"", etag_hash);

    if let Some(inm) = req_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        if inm.trim() == etag_val || inm.trim() == "*" {
            return (
                StatusCode::NOT_MODIFIED,
                [
                    (header::ETAG, etag_val),
                    (header::CACHE_CONTROL, "public, max-age=300".to_string()),
                ],
            )
                .into_response();
        }
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::CACHE_CONTROL, "public, max-age=300".to_string()),
            (header::ETAG, etag_val),
        ],
        data,
    )
        .into_response()
}

/// Extract publish date for a specific version from cached Cargo metadata.
///
/// crates.io API metadata has `versions` array with `num` and `created_at`:
/// ```json
/// { "versions": [{ "num": "1.0.0", "created_at": "2024-01-15T10:30:00Z" }] }
/// ```
async fn extract_cargo_publish_date(
    storage: &crate::storage::Storage,
    metadata_key: &str,
    version: &str,
    trust_upstream: bool,
) -> Option<i64> {
    // #513: untrusted upstream dates → NORA cache mtime, never upstream created_at.
    if !trust_upstream {
        return crate::curation::extract_mtime_as_publish_date(storage, metadata_key).await;
    }
    let data = storage.get(metadata_key).await.ok()?;
    let json: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let versions = json.get("versions")?.as_array()?;
    for v in versions {
        if v.get("num")?.as_str()? == version {
            let date_str = v.get("created_at")?.as_str()?;
            return crate::curation::parse_iso8601_to_unix(date_str);
        }
    }
    None
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── Prefix computation (RFC 2789) ───────────────────────────────────

    #[test]
    fn test_prefix_single_char() {
        assert_eq!(crate_index_prefix("a"), "1");
        assert_eq!(crate_index_prefix("Z"), "1");
    }

    #[test]
    fn test_prefix_two_chars() {
        assert_eq!(crate_index_prefix("ab"), "2");
        assert_eq!(crate_index_prefix("IO"), "2");
    }

    #[test]
    fn test_prefix_three_chars() {
        assert_eq!(crate_index_prefix("abc"), "3/a");
        assert_eq!(crate_index_prefix("Foo"), "3/f");
    }

    #[test]
    fn test_prefix_four_plus_chars() {
        assert_eq!(crate_index_prefix("serde"), "se/rd");
        assert_eq!(crate_index_prefix("tokio"), "to/ki");
        assert_eq!(crate_index_prefix("Axum"), "ax/um");
        assert_eq!(crate_index_prefix("ab_cd_ef"), "ab/_c");
    }

    // ── Crate name validation ───────────────────────────────────────────

    #[test]
    fn test_valid_crate_names() {
        assert!(is_valid_crate_name("serde"));
        assert!(is_valid_crate_name("my-crate"));
        assert!(is_valid_crate_name("my_crate"));
        assert!(is_valid_crate_name("a"));
        assert!(is_valid_crate_name("crate123"));
    }

    #[test]
    fn test_invalid_crate_names() {
        assert!(!is_valid_crate_name(""));
        assert!(!is_valid_crate_name("-start"));
        assert!(!is_valid_crate_name("_start"));
        assert!(!is_valid_crate_name("has space"));
        assert!(!is_valid_crate_name("has/slash"));
        assert!(!is_valid_crate_name("has..dots"));
        assert!(!is_valid_crate_name("has\\backslash"));
        assert!(!is_valid_crate_name(&"a".repeat(65)));
    }

    #[test]
    fn test_crate_name_max_length() {
        assert!(is_valid_crate_name(&"a".repeat(64)));
        assert!(!is_valid_crate_name(&"a".repeat(65)));
    }

    // ── Index rebuild is all-or-fail ────────────────────────────────────

    #[tokio::test]
    async fn test_regenerate_cargo_index_aborts_on_read_error() {
        // A transient read error on a per-version entry must ABORT the rebuild,
        // never silently drop the version and publish a truncated index as
        // authoritative. The list reports two versions; every get fails, so a
        // correct rebuild returns Err and writes nothing — the `put` mock panics
        // if it is ever reached, proving the old "skip and write empty" path is
        // gone.
        use crate::storage::{Result as StorageResult, StorageBackend, StorageError};
        use axum::body::Bytes;
        use std::path::Path;
        use std::pin::Pin;
        use tokio::io::AsyncRead;

        struct FailingGetBackend;

        #[async_trait::async_trait]
        impl StorageBackend for FailingGetBackend {
            async fn list(&self, _prefix: &str) -> StorageResult<Vec<String>> {
                Ok(vec![
                    "cargo/index-entries/fa/il/failcrate/0.1.0.json".to_string(),
                    "cargo/index-entries/fa/il/failcrate/0.2.0.json".to_string(),
                ])
            }
            async fn get(&self, _key: &str) -> StorageResult<(Bytes, Option<String>)> {
                Err(StorageError::Io(std::io::Error::other(
                    "injected transient read error",
                )))
            }
            async fn pin(&self, _key: &str) -> Option<String> {
                None
            }
            async fn put(&self, _key: &str, _data: &[u8], _sha256: &str) -> StorageResult<()> {
                panic!("regenerate must abort before writing a truncated index");
            }
            async fn delete(&self, _key: &str) -> StorageResult<()> {
                Ok(())
            }
            async fn stat(&self, _key: &str) -> Option<crate::storage::FileMeta> {
                None
            }
            async fn health_check(&self) -> bool {
                true
            }
            async fn total_size(&self) -> u64 {
                0
            }
            fn backend_name(&self) -> &'static str {
                "failing-get-test"
            }
            async fn put_from_path(
                &self,
                _key: &str,
                _src: &Path,
                _sha256: Option<&str>,
            ) -> StorageResult<()> {
                Ok(())
            }
            async fn get_reader(
                &self,
                _key: &str,
            ) -> StorageResult<(u64, Option<String>, Pin<Box<dyn AsyncRead + Send + Unpin>>)>
            {
                Err(StorageError::NotFound)
            }
            async fn copy(
                &self,
                _src: &str,
                _dst: &str,
                _sha256: Option<&str>,
            ) -> StorageResult<()> {
                Err(StorageError::NotFound)
            }
        }

        let storage = Storage::from_backend(std::sync::Arc::new(FailingGetBackend));
        let result = regenerate_cargo_index(&storage, "fa/il", "failcrate").await;
        assert!(
            result.is_err(),
            "a transient read error must abort the rebuild, not publish a truncated index"
        );
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context, send};

    /// A cold miss is "not found" only when the upstream said so: the sparse index, the crate
    /// metadata and a `.crate` download whose upstream failed (5xx after the retry,
    /// unreachable) answer 502, not the 404 cargo reports as "no matching package".
    #[tokio::test]
    async fn a_cold_miss_is_404_only_when_the_upstream_said_not_found() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let down = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&down)
            .await;
        let missing = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&missing)
            .await;
        for (upstream, want) in [
            (down.uri(), StatusCode::BAD_GATEWAY),
            ("http://127.0.0.1:9".to_string(), StatusCode::BAD_GATEWAY),
            (missing.uri(), StatusCode::NOT_FOUND),
        ] {
            for uri in [
                "/cargo/index/se/rd/serde",
                "/cargo/api/v1/crates/serde",
                "/cargo/api/v1/crates/serde/1.0.0/download",
            ] {
                let url = upstream.clone();
                let ctx = crate::test_helpers::create_test_context_with_config(move |c| {
                    c.cargo.proxy = Some(url);
                });
                let resp = send(&ctx.app, axum::http::Method::GET, uri, "").await;
                assert_eq!(resp.status(), want, "{uri} {upstream}");
            }
        }
        assert!(!down.received_requests().await.unwrap().is_empty());
        assert!(!missing.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_cargo_namespace_scope_enforced() {
        use crate::auth::NamespaceAuthority;
        use crate::config::ScopeEnforcement;
        use axum::body::Bytes;
        use axum::extract::State;
        use axum::Extension;

        let ctx = create_test_context();
        let scoped = NamespaceAuthority::from_oidc_scope(
            "ci",
            &["acme/**".to_string()],
            ScopeEnforcement::Enforce,
        );

        // Crate name outside scope -> 403.
        let metadata =
            serde_json::json!({"name":"other-crate","vers":"0.1.0","deps":[],"features":{}});
        let payload = build_publish_payload(&metadata, b"data");
        let resp = super::publish(
            State(ctx.state.clone()),
            Extension(scoped.clone()),
            None,
            Bytes::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Crate name covered by the scope -> enforcement passes (not 403).
        let metadata = serde_json::json!({"name":"acme","vers":"0.1.0","deps":[],"features":{}});
        let payload = build_publish_payload(&metadata, b"data");
        let resp = super::publish(
            State(ctx.state.clone()),
            Extension(scoped),
            None,
            Bytes::from(payload),
        )
        .await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }
    use axum::body::Body;
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_cargo_index_config() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::GET, "/cargo/index/config.json", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let dl = json["dl"].as_str().unwrap();
        let api = json["api"].as_str().unwrap();
        assert!(
            dl.ends_with("/cargo/api/v1/crates"),
            "dl must end with /cargo/api/v1/crates, got: {}",
            dl
        );
        assert!(
            api.ends_with("/cargo"),
            "api must end with /cargo so Cargo can build {{api}}/api/v1/crates/... routes, got: {}",
            api
        );
        // Open test context (no auth): cargo must not be told to send creds.
        assert_eq!(json["auth-required"], serde_json::Value::Bool(false));
    }

    /// A private deployment (auth on, no anonymous read) must advertise
    /// `auth-required` or cargo never sends credentials to the sparse index
    /// and every fetch 401s (RFC 3139).
    #[tokio::test]
    async fn test_cargo_index_config_auth_required() {
        use crate::test_helpers::{
            create_test_context_with_anonymous_read, create_test_context_with_auth,
            send_with_headers,
        };
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let basic = format!("Basic {}", STANDARD.encode("alice:hunter2"));
        let ctx = create_test_context_with_auth(&[("alice", "hunter2")]);
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/cargo/index/config.json",
            vec![("authorization", &basic)],
            Vec::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["auth-required"], serde_json::Value::Bool(true));

        let ctx = create_test_context_with_anonymous_read(&[("alice", "hunter2")]);
        let resp = send(&ctx.app, Method::GET, "/cargo/index/config.json", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["auth-required"],
            serde_json::Value::Bool(false),
            "anonymous_read serves index reads without creds"
        );
    }

    /// Verify that config.json `api` field produces correct metadata route (#442).
    ///
    /// Cargo constructs `{api}/api/v1/crates/{name}` for metadata requests.
    /// The `api` field must match the route prefix so requests don't 404.
    #[tokio::test]
    async fn test_cargo_config_api_routes_to_metadata() {
        let ctx = create_test_context();

        // Put metadata in storage so the handler returns 200
        let meta = r#"{"name":"serde","versions":[]}"#;
        ctx.state
            .storage
            .put("cargo/serde/metadata.json", meta.as_bytes())
            .await
            .unwrap();

        // Get config.json to extract the api field
        let config_resp = send(&ctx.app, Method::GET, "/cargo/index/config.json", "").await;
        let config_body = body_bytes(config_resp).await;
        let config: serde_json::Value = serde_json::from_slice(&config_body).unwrap();
        let api_url = config["api"].as_str().unwrap();

        // Construct the metadata URL the way Cargo does: {api}/api/v1/crates/{name}
        let metadata_path = format!(
            "{}/api/v1/crates/serde",
            api_url.trim_start_matches("http://localhost")
        );

        let resp = send(&ctx.app, Method::GET, &metadata_path, "").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "metadata request via config.json api field must not 404 (#442)"
        );
    }

    /// Verify that config.json `api` field produces the correct publish route.
    ///
    /// Cargo constructs `{api}/api/v1/crates/new` for publish requests.
    /// The advertised `api` base must therefore be the registry mount (`/cargo`),
    /// not `/cargo/api`, or the client will hit `/cargo/api/api/v1/crates/new`.
    #[tokio::test]
    async fn test_cargo_config_api_routes_to_publish() {
        let ctx = create_test_context();

        // Get config.json to extract the api field
        let config_resp = send(&ctx.app, Method::GET, "/cargo/index/config.json", "").await;
        let config_body = body_bytes(config_resp).await;
        let config: serde_json::Value = serde_json::from_slice(&config_body).unwrap();
        let api_url = config["api"].as_str().unwrap();

        // Construct the publish URL the way Cargo does: {api}/api/v1/crates/new
        let publish_path = format!(
            "{}/api/v1/crates/new",
            api_url.trim_start_matches("http://localhost")
        );

        let metadata = serde_json::json!({
            "name": "publish-from-config",
            "vers": "0.1.0",
            "deps": [],
            "features": {},
        });
        let payload = build_publish_payload(&metadata, b"crate-data");

        let resp = send(&ctx.app, Method::PUT, &publish_path, Body::from(payload)).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "publish request via config.json api field must not 404"
        );
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_from_storage() {
        let ctx = create_test_context();
        let index_data = br#"{"name":"serde","vers":"1.0.0","deps":[],"cksum":"abc123","features":{},"yanked":false}"#;
        ctx.state
            .storage
            .put("cargo/index/se/rd/serde", index_data)
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/cargo/index/se/rd/serde", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], index_data);
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_wrong_prefix() {
        let ctx = create_test_context();
        // "serde" should be at se/rd/serde, not 1/serde
        let resp = send(&ctx.app, Method::GET, "/cargo/index/1/serde", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_single_char() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("cargo/index/1/a", b"index-data")
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/cargo/index/1/a", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_two_char() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("cargo/index/2/ab", b"index-data")
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/cargo/index/2/ab", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_three_char() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("cargo/index/3/f/foo", b"index-data")
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/cargo/index/3/f/foo", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_returns_etag() {
        use crate::test_helpers::send_with_headers;

        let ctx = create_test_context();
        let index_data = br#"{"name":"serde","vers":"1.0.0","deps":[]}"#;
        ctx.state
            .storage
            .put("cargo/index/se/rd/serde", index_data)
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/cargo/index/se/rd/serde", "").await;
        assert_eq!(resp.status(), StatusCode::OK);

        let etag = resp
            .headers()
            .get("etag")
            .expect("response must include ETag")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            etag.starts_with('"') && etag.ends_with('"'),
            "ETag must be quoted"
        );
        assert!(etag.len() > 2, "ETag must contain a hash");

        // Second request with matching If-None-Match → 304
        let resp2 = send_with_headers(
            &ctx.app,
            Method::GET,
            "/cargo/index/se/rd/serde",
            vec![("if-none-match", &etag)],
            "",
        )
        .await;
        assert_eq!(resp2.status(), StatusCode::NOT_MODIFIED);
        // 304 should also include ETag
        let etag2 = resp2.headers().get("etag").expect("304 must include ETag");
        assert_eq!(etag2.to_str().unwrap(), etag);
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_etag_mismatch_returns_200() {
        use crate::test_helpers::send_with_headers;

        let ctx = create_test_context();
        let index_data = br#"{"name":"serde","vers":"1.0.0","deps":[]}"#;
        ctx.state
            .storage
            .put("cargo/index/se/rd/serde", index_data)
            .await
            .unwrap();

        // Request with non-matching ETag → 200
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/cargo/index/se/rd/serde",
            vec![("if-none-match", "\"stale-etag\"")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("etag").is_some());
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_etag_changes_with_data() {
        let ctx = create_test_context();

        // First version
        ctx.state
            .storage
            .put("cargo/index/se/rd/serde", br#"{"vers":"1.0.0"}"#)
            .await
            .unwrap();
        let resp1 = send(&ctx.app, Method::GET, "/cargo/index/se/rd/serde", "").await;
        let etag1 = resp1
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Update data
        ctx.state
            .storage
            .put("cargo/index/se/rd/serde", br#"{"vers":"2.0.0"}"#)
            .await
            .unwrap();
        let resp2 = send(&ctx.app, Method::GET, "/cargo/index/se/rd/serde", "").await;
        let etag2 = resp2
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        assert_ne!(etag1, etag2, "ETag must change when data changes");
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_not_found_no_proxy() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::GET, "/cargo/index/se/rd/serde", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_cargo_metadata_not_found() {
        let ctx = create_test_context();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/nonexistent",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_cargo_metadata_from_storage() {
        let ctx = create_test_context();
        let meta = r#"{"name":"test-crate","versions":[]}"#;
        ctx.state
            .storage
            .put("cargo/test-crate/metadata.json", meta.as_bytes())
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/cargo/api/v1/crates/test-crate", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], meta.as_bytes());
    }

    #[tokio::test]
    async fn test_cargo_download_not_found() {
        let ctx = create_test_context();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/missing/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_cargo_download_from_storage() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("cargo/my-crate/1.2.3/my-crate-1.2.3.crate", b"crate-data")
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/my-crate/1.2.3/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"crate-data");
    }

    // ── Publish tests ───────────────────────────────────────────────────

    /// Build cargo publish wire format: 4-byte LE metadata len + metadata + 4-byte LE crate len + crate
    fn build_publish_payload(metadata: &serde_json::Value, crate_data: &[u8]) -> Vec<u8> {
        let meta_bytes = serde_json::to_vec(metadata).unwrap();
        let meta_len = (meta_bytes.len() as u32).to_le_bytes();
        let crate_len = (crate_data.len() as u32).to_le_bytes();

        let mut payload = Vec::new();
        payload.extend_from_slice(&meta_len);
        payload.extend_from_slice(&meta_bytes);
        payload.extend_from_slice(&crate_len);
        payload.extend_from_slice(crate_data);
        payload
    }

    #[tokio::test]
    async fn test_cargo_publish_basic() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "my-crate",
            "vers": "0.1.0",
            "deps": [],
            "features": {},
        });
        let crate_data = b"fake-crate-tarball";
        let payload = build_publish_payload(&metadata, crate_data);

        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify .crate stored
        let stored = ctx
            .state
            .storage
            .get("cargo/my-crate/0.1.0/my-crate-0.1.0.crate")
            .await
            .unwrap();
        assert_eq!(&stored[..], crate_data);

        // Verify sparse index entry created
        let index = ctx
            .state
            .storage
            .get("cargo/index/my/-c/my-crate")
            .await
            .unwrap();
        let index_str = String::from_utf8_lossy(&index);
        assert!(index_str.contains("\"name\":\"my-crate\""));
        assert!(index_str.contains("\"vers\":\"0.1.0\""));
        assert!(index_str.contains("\"cksum\":"));
    }

    #[tokio::test]
    async fn test_cargo_publish_version_immutability() {
        let ctx = create_test_context();

        // First publish
        let metadata = serde_json::json!({
            "name": "immut-test",
            "vers": "1.0.0",
            "deps": [],
            "features": {},
        });
        let payload = build_publish_payload(&metadata, b"crate-v1");
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Second publish with same version → CONFLICT
        let payload2 = build_publish_payload(&metadata, b"crate-v1-again");
        let resp2 = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload2),
        )
        .await;
        assert_eq!(resp2.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_cargo_publish_multiple_versions() {
        let ctx = create_test_context();

        // v0.1.0
        let m1 =
            serde_json::json!({"name": "multi-ver", "vers": "0.1.0", "deps": [], "features": {}});
        let p1 = build_publish_payload(&m1, b"crate-01");
        let r1 = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(p1),
        )
        .await;
        assert_eq!(r1.status(), StatusCode::OK);

        // v0.2.0
        let m2 =
            serde_json::json!({"name": "multi-ver", "vers": "0.2.0", "deps": [], "features": {}});
        let p2 = build_publish_payload(&m2, b"crate-02");
        let r2 = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(p2),
        )
        .await;
        assert_eq!(r2.status(), StatusCode::OK);

        // Index should have 2 lines
        let index = ctx
            .state
            .storage
            .get("cargo/index/mu/lt/multi-ver")
            .await
            .unwrap();
        let index_str = String::from_utf8_lossy(&index);
        let lines: Vec<&str> = index_str.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("0.1.0"));
        assert!(lines[1].contains("0.2.0"));

        // Each version is also its own immutable entry key (the #39 scan-regenerate source).
        assert!(ctx
            .state
            .storage
            .get("cargo/index-entries/mu/lt/multi-ver/0.1.0.json")
            .await
            .is_ok());
        assert!(ctx
            .state
            .storage
            .get("cargo/index-entries/mu/lt/multi-ver/0.2.0.json")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_cargo_publish_migrates_single_file_index() {
        // An old single-file sparse index (one line per version, no per-version entry keys) is
        // migrated on the next publish, preserving the old version (#39), once the operator has
        // named the crate in cargo.import_embedded: without a record NORA cannot tell it from an
        // upstream crate an older release cached at the same key.
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.cargo.import_embedded = vec!["legacy-crate".to_string()];
        });
        let old_line = serde_json::json!({
            "name": "legacy-crate", "vers": "1.0.0", "deps": [], "cksum": "a",
            "features": {}, "yanked": false
        })
        .to_string();
        ctx.state
            .storage
            .put(
                "cargo/index/le/ga/legacy-crate",
                format!("{}\n", old_line).as_bytes(),
            )
            .await
            .unwrap();
        let m = serde_json::json!({"name": "legacy-crate", "vers": "2.0.0", "deps": [], "features": {}});
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(build_publish_payload(&m, b"crate2")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // old version migrated to its own per-version entry key
        assert!(
            ctx.state
                .storage
                .get("cargo/index-entries/le/ga/legacy-crate/1.0.0.json")
                .await
                .is_ok(),
            "old single-file version not migrated to a per-version key"
        );
        // the regenerated index has BOTH the migrated old and the new version
        let index = ctx
            .state
            .storage
            .get("cargo/index/le/ga/legacy-crate")
            .await
            .unwrap();
        let s = String::from_utf8_lossy(&index);
        assert!(s.contains("\"vers\":\"1.0.0\""), "migrated v1 lost");
        assert!(s.contains("\"vers\":\"2.0.0\""), "new v2 lost");
    }

    #[tokio::test]
    async fn a_publish_over_an_index_of_unknown_origin_waits_for_the_operator() {
        let ctx = create_test_context();
        let cached = r#"{"name":"legacy-crate","vers":"9.9.9","deps":[],"cksum":"a","features":{},"yanked":false}"#;
        ctx.state
            .storage
            .put(
                "cargo/index/le/ga/legacy-crate",
                format!("{cached}\n").as_bytes(),
            )
            .await
            .unwrap();
        let m = serde_json::json!({"name": "legacy-crate", "vers": "2.0.0", "deps": [], "features": {}});
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(build_publish_payload(&m, b"crate2")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let detail = body["errors"][0]["detail"].as_str().unwrap();
        assert!(
            detail.contains("NORA_CARGO_IMPORT_EMBEDDED=legacy-crate"),
            "{detail}"
        );
        for key in [
            "cargo/legacy-crate/2.0.0/legacy-crate-2.0.0.crate",
            "cargo/index-entries/le/ga/legacy-crate/2.0.0.json",
            "cargo/index-entries/le/ga/legacy-crate/9.9.9.json",
        ] {
            assert!(ctx.state.storage.stat(key).await.is_none(), "{key} written");
        }
    }

    #[tokio::test]
    async fn test_cargo_publish_invalid_name() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "../traversal",
            "vers": "1.0.0",
            "deps": [],
            "features": {},
        });
        let payload = build_publish_payload(&metadata, b"bad");

        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_cargo_publish_truncated_payload() {
        let ctx = create_test_context();
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(vec![0u8; 3]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_cargo_publish_response_has_warnings() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "warn-test",
            "vers": "1.0.0",
            "deps": [],
            "features": {},
        });
        let payload = build_publish_payload(&metadata, b"crate-data");

        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("warnings").is_some());
    }

    #[tokio::test]
    async fn test_cargo_publish_then_download() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "roundtrip",
            "vers": "2.0.0",
            "deps": [],
            "features": {},
        });
        let crate_data = b"published-crate-content";
        let payload = build_publish_payload(&metadata, crate_data);

        // Publish
        let publish_resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(publish_resp.status(), StatusCode::OK);

        // Download
        let dl_resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/roundtrip/2.0.0/download",
            "",
        )
        .await;
        assert_eq!(dl_resp.status(), StatusCode::OK);
        let body = body_bytes(dl_resp).await;
        assert_eq!(&body[..], crate_data);
    }

    #[tokio::test]
    async fn test_cargo_publish_then_sparse_index() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "idx-test",
            "vers": "1.0.0",
            "deps": [{"name": "serde", "req": "^1", "features": [], "optional": false, "default_features": true, "target": null, "kind": "normal"}],
            "features": {"default": ["serde"]},
            "links": null,
        });
        let payload = build_publish_payload(&metadata, b"crate");

        let publish_resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(publish_resp.status(), StatusCode::OK);

        // Sparse index lookup
        let idx_resp = send(&ctx.app, Method::GET, "/cargo/index/id/x-/idx-test", "").await;
        assert_eq!(idx_resp.status(), StatusCode::OK);

        let body = body_bytes(idx_resp).await;
        let line: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&body).lines().next().unwrap()).unwrap();
        assert_eq!(line["name"], "idx-test");
        assert_eq!(line["vers"], "1.0.0");
        assert!(line["deps"].as_array().unwrap().len() == 1);
        assert!(line["cksum"].as_str().unwrap().len() == 64); // sha256 hex
    }

    #[tokio::test]
    async fn test_cargo_publish_transforms_deps_version_req_to_req() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "dep-test",
            "vers": "1.0.0",
            "deps": [{
                "name": "serde",
                "version_req": "^1.0",
                "features": ["derive"],
                "optional": false,
                "default_features": true,
                "target": null,
                "kind": "normal",
                "registry": null,
                "explicit_name_in_toml": null
            }, {
                "name": "my_serde",
                "version_req": "^1.0",
                "features": [],
                "optional": false,
                "default_features": true,
                "target": null,
                "kind": "normal",
                "registry": null,
                "explicit_name_in_toml": "serde_json"
            }],
            "features": {},
        });
        let payload = build_publish_payload(&metadata, b"crate-data");

        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Read the sparse index entry
        let index = ctx
            .state
            .storage
            .get("cargo/index/de/p-/dep-test")
            .await
            .unwrap();
        let line: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&index).lines().next().unwrap()).unwrap();

        let deps = line["deps"].as_array().unwrap();
        assert_eq!(deps.len(), 2);

        // version_req must be renamed to req
        assert!(
            deps[0].get("version_req").is_none(),
            "version_req should not be in index"
        );
        assert_eq!(deps[0]["req"], "^1.0", "version_req must be renamed to req");

        // explicit_name_in_toml=null should be dropped (not become package=null)
        assert!(deps[0].get("explicit_name_in_toml").is_none());
        assert!(
            deps[0].get("package").is_none(),
            "null explicit_name_in_toml should not create package field"
        );

        // explicit_name_in_toml="serde_json" should become package="serde_json"
        assert!(deps[1].get("explicit_name_in_toml").is_none());
        assert_eq!(
            deps[1]["package"], "serde_json",
            "explicit_name_in_toml must become package"
        );
    }

    #[tokio::test]
    async fn test_cargo_publish_conflict_json_format() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "conflict-fmt",
            "vers": "1.0.0",
            "deps": [],
            "features": {},
        });
        let payload = build_publish_payload(&metadata, b"v1");
        let r1 = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(r1.status(), StatusCode::OK);

        // Second publish -> CONFLICT with Cargo JSON format
        let payload2 = build_publish_payload(&metadata, b"v1-again");
        let r2 = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload2),
        )
        .await;
        assert_eq!(r2.status(), StatusCode::CONFLICT);

        let body = body_bytes(r2).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["errors"].as_array().unwrap().len() > 0);
        assert!(json["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("already exists"));
    }

    // ── Curation integration tests ──────────────────────────────────────

    #[tokio::test]
    async fn test_cargo_download_blocked_by_curation() {
        use crate::test_helpers::{create_test_context_with_config, send_with_headers};

        // Write blocklist file to a temp location
        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{
                "registry": "cargo",
                "name": "evil-crate",
                "version": "*",
                "reason": "known malware"
            }]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        // Put a crate in storage so it would normally be downloadable
        ctx.state
            .storage
            .put(
                "cargo/evil-crate/1.0.0/evil-crate-1.0.0.crate",
                b"evil-data",
            )
            .await
            .unwrap();

        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/evil-crate/1.0.0/download",
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
    async fn test_cargo_download_allowed_by_curation() {
        use crate::test_helpers::{create_test_context_with_config, send_with_headers};

        // Blocklist only blocks "evil-crate"
        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{
                "registry": "cargo",
                "name": "evil-crate",
                "version": "*",
                "reason": "known malware"
            }]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        // Put a SAFE crate in storage
        ctx.state
            .storage
            .put(
                "cargo/safe-crate/2.0.0/safe-crate-2.0.0.crate",
                b"safe-data",
            )
            .await
            .unwrap();

        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/safe-crate/2.0.0/download",
            vec![],
            "",
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"safe-data");
    }

    /// A cached .crate resumes: 206 for a satisfiable range, 416 once the client
    /// already holds the whole file, `Accept-Ranges` on the full 200.
    #[tokio::test]
    async fn test_cargo_download_range_request() {
        use crate::test_helpers::send_with_headers;

        let ctx = create_test_context();
        let krate = b"0123456789";
        ctx.state
            .storage
            .put("cargo/rng/1.0.0/rng-1.0.0.crate", krate)
            .await
            .unwrap();
        let url = "/cargo/api/v1/crates/rng/1.0.0/download";

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
        assert_eq!(&body_bytes(resp).await[..], krate);
    }

    /// `corp-secret%2F` decodes to `corp-secret/`, which the exact isolation pattern
    /// `corp-secret` does not match: it is refused, never requested upstream and never cached
    /// over `cargo/corp-secret/metadata.json`.
    #[tokio::test]
    async fn a_trailing_slash_name_never_takes_an_internal_crate_upstream() {
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"versions":[]}"#))
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.cargo.proxy = Some(upstream.uri());
            cfg.curation.internal_namespaces = vec!["corp-secret".to_string()];
        });
        let leaked = || async {
            upstream
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path().contains("corp-secret"))
                .count()
        };
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/corp-secret",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        assert_eq!(leaked().await, 0, "control: canonical name is not proxied");

        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/corp-secret%2F",
            "",
        )
        .await;
        assert_eq!(
            leaked().await,
            0,
            "internal crate name sent to the public upstream (alias answered {})",
            resp.status()
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod index_cost_tests {
    //! Serving a sparse index file must cost the same storage round-trips for 1 and 100 versions.
    use crate::test_helpers::{create_test_context_with_storage, op_counting_storage, send};
    use axum::http::{Method, StatusCode};

    async fn sparse_index_ops(n: usize) -> (usize, String) {
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        let mut lines = String::new();
        for i in 0..n {
            let version = format!("1.0.{i}");
            let crate_key = format!("cargo/costcrate/{version}/costcrate-{version}.crate");
            ctx.state.storage.put(&crate_key, b"CRATE").await.unwrap();
            lines.push_str(&format!(
                "{{\"name\":\"costcrate\",\"vers\":\"{version}\",\"deps\":[],\"cksum\":\"abc\",\"features\":{{}},\"yanked\":false}}\n"
            ));
        }
        ctx.state
            .storage
            .put("cargo/index/co/st/costcrate", lines.as_bytes())
            .await
            .unwrap();
        ops.reset();
        let resp = send(&ctx.app, Method::GET, "/cargo/index/co/st/costcrate", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "sparse index with {n} versions"
        );
        (ops.total(), format!("{:?}", ops.snapshot()))
    }

    #[tokio::test]
    async fn cargo_sparse_index_cost_is_independent_of_version_count() {
        let (small, small_ops) = sparse_index_ops(1).await;
        let (large, large_ops) = sparse_index_ops(100).await;
        assert_eq!(
            small, large,
            "a hosted sparse index file must cost the same storage round-trips for 1 and 100 versions: {small_ops} vs {large_ops}"
        );
    }
}

/// A crate whose published name has capitals (`Inflector`) downloads through the proxy: the
/// upstream path keeps the name as cargo sent it — static.crates.io stores the archive under
/// the published name and refuses the lowercased one — while the cache key stays lowercase,
/// so either spelling is served from one cached copy.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod crate_name_case_tests {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn a_capitalised_crate_downloads_under_its_published_name() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/crates/Inflector/0.11.4/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"CRATE".to_vec()))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.cargo.proxy = Some(uri);
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/Inflector/0.11.4/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"CRATE");

        // The copy is cached under the lowercase key: the other spelling is served from it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while ctx
            .state
            .storage
            .stat("cargo/inflector/0.11.4/inflector-0.11.4.crate")
            .await
            .is_none()
        {
            assert!(std::time::Instant::now() < deadline, "not cached");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/inflector/0.11.4/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"CRATE");
        let downloads: Vec<String> = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .filter(|p| p.ends_with("/download"))
            .collect();
        assert_eq!(
            downloads,
            vec!["/api/v1/crates/Inflector/0.11.4/download".to_string()],
            "one archive download, under the published name"
        );
    }
}

/// A crate published to NORA keeps its own index: an upstream crate of the same name never
/// replaces it, whatever the age of the stored index.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod published_index_ownership {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn payload(name: &str, vers: &str) -> Vec<u8> {
        let meta = serde_json::to_vec(&serde_json::json!({
            "name": name, "vers": vers, "deps": [], "features": {}
        }))
        .unwrap();
        let krate = b"internal-crate";
        let mut out = Vec::new();
        out.extend_from_slice(&(meta.len() as u32).to_le_bytes());
        out.extend_from_slice(&meta);
        out.extend_from_slice(&(krate.len() as u32).to_le_bytes());
        out.extend_from_slice(krate);
        out
    }

    #[tokio::test]
    async fn an_upstream_crate_of_the_same_name_never_replaces_a_published_index() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index/co/rp/corp-lib"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"name":"corp-lib","vers":"9.9.9","deps":[],"cksum":"00","features":{},"yanked":false}"#,
            ))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.cargo.proxy = Some(uri);
            cfg.cargo.metadata_ttl = 0;
        });
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload("corp-lib", "0.1.0")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = send(&ctx.app, Method::GET, "/cargo/index/co/rp/corp-lib", "").await;
        let served = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let stored = ctx
            .state
            .storage
            .get("cargo/index/co/rp/corp-lib")
            .await
            .unwrap();
        let stored = String::from_utf8_lossy(&stored).into_owned();
        assert!(
            stored.contains("\"0.1.0\"") && !stored.contains("9.9.9"),
            "stored: {stored}"
        );
        assert!(
            served.contains("\"0.1.0\"") && !served.contains("9.9.9"),
            "served: {served}"
        );
    }
}

/// `index_answer` over every combination of what a request can find, held to the decision table
/// written as properties (each one a row of the table or a guarantee), plus the table's
/// rows as examples.
#[cfg(test)]
mod index_answer_grid {
    use super::{index_answer, CopyState, Fallback, IndexAnswer, Stored, UnpublishedFacts};

    fn every_case() -> Vec<UnpublishedFacts> {
        let mut cases = Vec::new();
        for listing_failed in [false, true] {
            for assembled in [Stored::Absent, Stored::Present, Stored::Unreadable] {
                for stored_index in [false, true] {
                    for embedded in [false, true] {
                        for upstream_copy in [CopyState::Absent, CopyState::Stale, CopyState::Fresh]
                        {
                            for internal in [false, true] {
                                for upstream in [false, true] {
                                    cases.push(UnpublishedFacts {
                                        listing_failed,
                                        assembled,
                                        stored_index,
                                        embedded,
                                        upstream_copy,
                                        internal,
                                        upstream,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        cases
    }

    #[test]
    fn every_case_follows_the_table() {
        let cases = every_case();
        assert_eq!(cases.len(), 288);
        for f in cases {
            let answer = index_answer(f);
            let copy = f.upstream_copy != CopyState::Absent;
            // Rows 5 and 10: an assembled index is the crate's own; unreadable, it may be.
            match f.assembled {
                Stored::Present => assert_eq!(answer, IndexAnswer::Assembled, "{f:?}"),
                Stored::Unreadable => assert_eq!(answer, IndexAnswer::Unavailable, "{f:?}"),
                Stored::Absent => assert!(
                    !matches!(answer, IndexAnswer::Assembled | IndexAnswer::Unavailable),
                    "{f:?}"
                ),
            }
            if f.assembled != Stored::Absent {
                continue;
            }
            // Row 5e: the operator's word wins over every copy.
            if f.embedded && f.stored_index {
                assert_eq!(answer, IndexAnswer::StoredIndex, "{f:?}");
                continue;
            }
            // Row 6: a fresh upstream copy answers without asking.
            if f.upstream_copy == CopyState::Fresh {
                assert_eq!(answer, IndexAnswer::UpstreamCopy, "{f:?}");
                continue;
            }
            // Rows 8, 9, 12: no upstream is asked for an internal name or without an upstream.
            if f.internal || !f.upstream {
                assert!(!matches!(answer, IndexAnswer::Fetch { .. }), "{f:?}");
            }
            // The stored copy is the upstream copy, else the crate's index; never one not there.
            let expected_copy = if copy {
                Some(IndexAnswer::UpstreamCopy)
            } else if f.stored_index {
                Some(IndexAnswer::StoredIndex)
            } else {
                None
            };
            match answer {
                IndexAnswer::UpstreamCopy => assert!(copy, "{f:?}"),
                IndexAnswer::StoredIndex => assert!(f.stored_index && !copy, "{f:?}"),
                IndexAnswer::Refuse => assert!(f.internal && expected_copy.is_none(), "{f:?}"),
                IndexAnswer::NotFound => {
                    assert!(
                        !f.internal && !f.upstream && expected_copy.is_none(),
                        "{f:?}"
                    )
                }
                IndexAnswer::Fetch { cache, fallback } => {
                    // Rows 7, 11, 13: asked only with an upstream and a non-internal name;
                    // cached only when the listing found nothing (row 11: failed → no write).
                    assert!(f.upstream && !f.internal, "{f:?}");
                    assert_eq!(cache, !f.listing_failed, "{f:?}");
                    let want = match expected_copy {
                        Some(IndexAnswer::UpstreamCopy) => Fallback::UpstreamCopy,
                        Some(IndexAnswer::StoredIndex) => Fallback::StoredIndex,
                        _ => Fallback::None,
                    };
                    assert_eq!(fallback, want, "{f:?}");
                }
                other => panic!("{f:?} answered {other:?}"),
            }
            // With nothing asked, the stored copy answers when there is one.
            if (f.internal || !f.upstream) && expected_copy.is_some() {
                assert_eq!(Some(answer), expected_copy, "{f:?}");
            }
        }
    }

    #[test]
    fn the_table_rows() {
        let base = UnpublishedFacts {
            listing_failed: false,
            assembled: Stored::Absent,
            stored_index: false,
            embedded: false,
            upstream_copy: CopyState::Absent,
            internal: false,
            upstream: true,
        };
        let row = |f: UnpublishedFacts| index_answer(f);
        // 7: nothing stored, upstream on → ask, cache at the upstream copy.
        assert_eq!(
            row(base),
            IndexAnswer::Fetch {
                cache: true,
                fallback: Fallback::None
            }
        );
        // 11: the listing failed → ask, write nothing.
        let failed = UnpublishedFacts {
            listing_failed: true,
            ..base
        };
        assert_eq!(
            row(failed),
            IndexAnswer::Fetch {
                cache: false,
                fallback: Fallback::None
            }
        );
        // 13: a stale copy is the fallback, the older release's index only without one.
        let stale = UnpublishedFacts {
            upstream_copy: CopyState::Stale,
            stored_index: true,
            ..base
        };
        assert_eq!(
            row(stale),
            IndexAnswer::Fetch {
                cache: true,
                fallback: Fallback::UpstreamCopy
            }
        );
        let old = UnpublishedFacts {
            stored_index: true,
            ..base
        };
        assert_eq!(
            row(old),
            IndexAnswer::Fetch {
                cache: true,
                fallback: Fallback::StoredIndex
            }
        );
        // 5e: named own, even beside a fresh copy.
        let own = UnpublishedFacts {
            stored_index: true,
            embedded: true,
            upstream_copy: CopyState::Fresh,
            ..base
        };
        assert_eq!(row(own), IndexAnswer::StoredIndex);
        // 8: internal, nothing stored → refused; 9: no upstream → 404.
        assert_eq!(
            row(UnpublishedFacts {
                internal: true,
                ..base
            }),
            IndexAnswer::Refuse
        );
        assert_eq!(
            row(UnpublishedFacts {
                upstream: false,
                ..base
            }),
            IndexAnswer::NotFound
        );
    }
}

/// The rows of the decision table for a published crate's sparse index:
/// what the entries listing answers × what the stored index is × what an upstream says.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod published_index_table {
    use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};
    use crate::test_helpers::{
        body_bytes, create_test_context_with_config, create_test_context_with_storage_and_config,
        send,
    };
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(Clone, Copy, PartialEq)]
    enum Listing {
        Normal,
        Empty,
        Fails,
        /// The first listing of entries succeeds, every later one fails.
        FailsAfterFirst,
    }

    /// An object store whose entries listing, index writes or entry reads misbehave on demand.
    struct Faulty {
        inner: ObjectStorage,
        listing: Listing,
        index_put_fails: bool,
        entry_get_fails: bool,
        assembled_get_fails: bool,
        entries_listed: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl StorageBackend for Faulty {
        async fn get(
            &self,
            k: &str,
        ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
            if self.entry_get_fails && k.starts_with("cargo/index-entries/") {
                return Err(crate::storage::StorageError::Network("read failed".into()));
            }
            if self.assembled_get_fails && k.starts_with("cargo/index-assembled/") {
                return Err(crate::storage::StorageError::Network("read failed".into()));
            }
            self.inner.get(k).await
        }
        async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
            if self.index_put_fails
                && (k.starts_with("cargo/index/") || k.starts_with("cargo/index-assembled/"))
            {
                return Err(crate::storage::StorageError::Network("put failed".into()));
            }
            self.inner.put(k, d, sha256).await
        }
        async fn pin(&self, k: &str) -> Option<String> {
            self.inner.pin(k).await
        }
        async fn delete(&self, k: &str) -> crate::storage::Result<()> {
            self.inner.delete(k).await
        }
        async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
            if prefix.starts_with("cargo/index-entries/") {
                let earlier = self
                    .entries_listed
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                match self.listing {
                    Listing::Empty => return Ok(Vec::new()),
                    Listing::Fails => {
                        return Err(crate::storage::StorageError::Network(
                            "listing failed".into(),
                        ))
                    }
                    Listing::FailsAfterFirst if earlier > 0 => {
                        return Err(crate::storage::StorageError::Network(
                            "listing failed".into(),
                        ))
                    }
                    Listing::Normal | Listing::FailsAfterFirst => {}
                }
            }
            self.inner.list(prefix).await
        }
        async fn list_with_meta(&self, p: &str) -> crate::storage::Result<Vec<(String, FileMeta)>> {
            self.inner.list_with_meta(p).await
        }
        async fn stat(&self, k: &str) -> Option<FileMeta> {
            self.inner.stat(k).await
        }
        async fn health_check(&self) -> bool {
            self.inner.health_check().await
        }
        async fn total_size(&self) -> u64 {
            self.inner.total_size().await
        }
        fn backend_name(&self) -> &'static str {
            "faulty-test-store"
        }
        async fn put_from_path(
            &self,
            k: &str,
            src: &std::path::Path,
            sha256: Option<&str>,
        ) -> crate::storage::Result<()> {
            self.inner.put_from_path(k, src, sha256).await
        }
        async fn copy(&self, s: &str, d: &str, sha256: Option<&str>) -> crate::storage::Result<()> {
            self.inner.copy(s, d, sha256).await
        }
        async fn get_reader(
            &self,
            k: &str,
        ) -> crate::storage::Result<(
            u64,
            Option<String>,
            std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
        )> {
            self.inner.get_reader(k).await
        }
    }

    fn faulty(listing: Listing, index_put_fails: bool, entry_get_fails: bool) -> Storage {
        Storage::from_backend(std::sync::Arc::new(Faulty {
            inner: ObjectStorage::in_memory(),
            listing,
            index_put_fails,
            entry_get_fails,
            assembled_get_fails: false,
            entries_listed: Default::default(),
        }))
    }

    const OWN: &str =
        r#"{"name":"corp-lib","vers":"0.1.0","deps":[],"cksum":"aa","features":{},"yanked":false}"#;
    const UPSTREAM: &str =
        r#"{"name":"corp-lib","vers":"9.9.9","deps":[],"cksum":"00","features":{},"yanked":false}"#;
    const INDEX: &str = "cargo/index/co/rp/corp-lib";
    const ASSEMBLED: &str = "cargo/index-assembled/co/rp/corp-lib";

    /// An upstream that serves corp-lib 9.9.9 to anyone who asks: a squatter on a published name.
    async fn squatter() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index/co/rp/corp-lib"))
            .respond_with(ResponseTemplate::new(200).set_body_string(UPSTREAM))
            .mount(&server)
            .await;
        server
    }

    async fn asked(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    /// corp-lib 0.1.0 as a publish leaves it: the entry and, unless `assembled` is false, the
    /// index NORA assembles with its record.
    async fn seed(storage: &Storage, assembled: bool) {
        storage
            .put(
                "cargo/index-entries/co/rp/corp-lib/0.1.0.json",
                OWN.as_bytes(),
            )
            .await
            .unwrap();
        if assembled {
            let index = format!("{OWN}\n");
            super::store_assembled_index(storage, "co/rp", "corp-lib", index.as_bytes())
                .await
                .unwrap();
        }
    }

    async fn get_index(app: &axum::Router) -> (StatusCode, String) {
        let resp = send(app, Method::GET, "/cargo/index/co/rp/corp-lib", "").await;
        let status = resp.status();
        (
            status,
            String::from_utf8_lossy(&body_bytes(resp).await).into_owned(),
        )
    }

    fn proxied(storage: Storage, server: &MockServer) -> crate::test_helpers::TestContext {
        let uri = server.uri();
        create_test_context_with_storage_and_config(storage, move |cfg| {
            cfg.cargo.proxy = Some(uri);
            cfg.cargo.metadata_ttl = 0;
        })
    }

    /// Row 1: published, the stored index is NORA's → served as it is, no upstream.
    #[tokio::test]
    async fn row1_an_assembled_index_is_served_without_an_upstream() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Normal, false, false), &server);
        seed(&ctx.state.storage, true).await;
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("0.1.0") && !body.contains("9.9.9"), "{body}");
        assert_eq!(asked(&server).await, 0);
    }

    /// Row 2: published, an upstream copy an older release cached over the index (here with the
    /// same version and a dependency of its own) and no assembled index → rebuilt from the
    /// entries, stored at its own key and copied for older releases.
    #[tokio::test]
    async fn row2_an_old_copy_over_a_published_index_is_rebuilt() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Normal, false, false), &server);
        seed(&ctx.state.storage, false).await;
        let copy = r#"{"name":"corp-lib","vers":"0.1.0","deps":[{"name":"evil-dep","req":"*"}],"cksum":"bb","features":{},"yanked":false}"#;
        ctx.state
            .storage
            .put(INDEX, format!("{copy}\n").as_bytes())
            .await
            .unwrap();
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !body.contains("evil-dep") && body.contains("0.1.0"),
            "{body}"
        );
        assert_eq!(asked(&server).await, 0);
        let stored = ctx.state.storage.get(INDEX).await.unwrap();
        assert!(!String::from_utf8_lossy(&stored).contains("evil-dep"));
        let assembled = ctx.state.storage.get(ASSEMBLED).await.unwrap();
        assert_eq!(
            assembled, stored,
            "the copy for older releases is the assembled index"
        );
    }

    /// Row 3: published, the rebuilt index cannot be stored → served anyway.
    #[tokio::test]
    async fn row3_a_rebuilt_index_is_served_when_it_cannot_be_stored() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Normal, true, false), &server);
        seed(&ctx.state.storage, false).await;
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("0.1.0") && !body.contains("9.9.9"), "{body}");
        assert_eq!(asked(&server).await, 0);
    }

    /// Row 4: published, an entry cannot be read → 503, never a partial index or the upstream's.
    #[tokio::test]
    async fn row4_an_unreadable_entry_is_a_503() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Normal, false, true), &server);
        seed(&ctx.state.storage, false).await;
        let (status, _) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(asked(&server).await, 0);
    }

    /// Row 5: the listing answers "nothing here" beside NORA's index → served, no upstream.
    #[tokio::test]
    async fn row5_an_empty_listing_beside_an_assembled_index_stays_local() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Empty, false, false), &server);
        seed(&ctx.state.storage, true).await;
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("0.1.0") && !body.contains("9.9.9"), "{body}");
        assert_eq!(asked(&server).await, 0);
    }

    /// Row 10: the listing fails beside NORA's index → served, no upstream.
    #[tokio::test]
    async fn row10_a_failed_listing_beside_an_assembled_index_stays_local() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Fails, false, false), &server);
        seed(&ctx.state.storage, true).await;
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("0.1.0") && !body.contains("9.9.9"), "{body}");
        assert_eq!(asked(&server).await, 0);
    }

    /// Row 11: the listing fails and no index of NORA's is stored → the upstream answers this
    /// request, and nothing is written.
    #[tokio::test]
    async fn row11_a_failed_listing_without_an_own_index_caches_nothing() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Fails, false, false), &server);
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("9.9.9"), "{body}");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            ctx.state.storage.stat(INDEX).await.is_none(),
            "upstream answer cached"
        );
        assert!(
            ctx.state.storage.stat(COPY).await.is_none(),
            "upstream answer kept as the upstream copy"
        );
    }

    const COPY: &str = "cargo/index-upstream/co/rp/corp-lib";

    async fn publish(app: &axum::Router, vers: &str) -> StatusCode {
        let meta = serde_json::to_vec(&serde_json::json!({
            "name": "corp-lib", "vers": vers, "deps": [], "features": {}
        }))
        .unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&(meta.len() as u32).to_le_bytes());
        payload.extend_from_slice(&meta);
        payload.extend_from_slice(&3u32.to_le_bytes());
        payload.extend_from_slice(b"crt");
        send(
            app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            axum::body::Body::from(payload),
        )
        .await
        .status()
    }

    /// The upstream copy is written off the request path: wait for it.
    async fn wait_for(storage: &Storage, key: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while storage.stat(key).await.is_none() {
            assert!(std::time::Instant::now() < deadline, "{key} never written");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// Row P3: cargo asks for its crate's index before it publishes. The upstream's answer is kept
    /// as NORA's upstream copy, not at the crate's index, so the first publish of a name the
    /// upstream also has goes through, and the index holds the published version only.
    #[tokio::test]
    async fn p3_a_first_publish_after_cargo_asked_the_upstream_goes_through() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Normal, false, false), &server);
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("9.9.9"), "{body}");
        wait_for(&ctx.state.storage, COPY).await;
        assert!(
            ctx.state.storage.stat(INDEX).await.is_none(),
            "upstream answer stored at the crate's index"
        );
        assert_eq!(publish(&ctx.app, "0.1.0").await, StatusCode::OK);
        let before = asked(&server).await;
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("\"0.1.0\"") && !body.contains("9.9.9"),
            "{body}"
        );
        assert_eq!(
            asked(&server).await,
            before,
            "a published crate asked upstream"
        );
    }

    /// Row 7: an unpublished crate's upstream answer goes to the upstream copy; whatever an older
    /// release left at the crate's index stays as it was.
    #[tokio::test]
    async fn row7_an_upstream_answer_is_kept_beside_the_index_not_over_it() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Normal, false, false), &server);
        let old = format!("{OWN}\n");
        ctx.state.storage.put(INDEX, old.as_bytes()).await.unwrap();
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("9.9.9"), "{body}");
        wait_for(&ctx.state.storage, COPY).await;
        assert_eq!(
            ctx.state.storage.get(INDEX).await.unwrap().as_ref(),
            old.as_bytes()
        );
        assert_eq!(
            ctx.state.storage.get(COPY).await.unwrap().as_ref(),
            UPSTREAM.as_bytes()
        );
    }

    fn proxied_ttl(storage: Storage, server: &MockServer) -> crate::test_helpers::TestContext {
        let uri = server.uri();
        create_test_context_with_storage_and_config(storage, move |cfg| {
            cfg.cargo.proxy = Some(uri);
            cfg.cargo.metadata_ttl = 300;
        })
    }

    /// Row 6: a fresh upstream copy is served without asking; what an older release left at the
    /// crate's index is no cache with a TTL, however recent it is.
    #[tokio::test]
    async fn row6_only_the_upstream_copy_is_fresh() {
        let server = squatter().await;
        let ctx = proxied_ttl(faulty(Listing::Normal, false, false), &server);
        ctx.state
            .storage
            .put(COPY, UPSTREAM.as_bytes())
            .await
            .unwrap();
        let (_, body) = get_index(&ctx.app).await;
        assert!(body.contains("9.9.9"), "{body}");
        assert_eq!(asked(&server).await, 0);

        let server = squatter().await;
        let ctx = proxied_ttl(faulty(Listing::Normal, false, false), &server);
        ctx.state.storage.put(INDEX, OWN.as_bytes()).await.unwrap();
        let (_, body) = get_index(&ctx.app).await;
        assert!(body.contains("9.9.9"), "{body}");
        assert_eq!(asked(&server).await, 1);
    }

    /// Row 13: the upstream fails → the stored copy is served stale: the upstream copy first, else
    /// what an older release left at the crate's index.
    #[tokio::test]
    async fn row13_a_failed_upstream_serves_the_stored_copy() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let ctx = proxied(faulty(Listing::Normal, false, false), &server);
        ctx.state.storage.put(INDEX, OWN.as_bytes()).await.unwrap();
        ctx.state
            .storage
            .put(COPY, UPSTREAM.as_bytes())
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/cargo/index/co/rp/corp-lib", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key("x-nora-stale"));
        assert_eq!(body_bytes(resp).await.as_ref(), UPSTREAM.as_bytes());

        ctx.state.storage.delete(COPY).await.unwrap();
        let resp = send(&ctx.app, Method::GET, "/cargo/index/co/rp/corp-lib", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await.as_ref(), OWN.as_bytes());
    }

    /// Row 5e: the operator named the crate's stored index its own (published before per-version
    /// entries): it is served as it is, no upstream is asked and no upstream copy is written.
    #[tokio::test]
    async fn row5e_an_index_the_operator_named_own_stays_local() {
        let server = squatter().await;
        let uri = server.uri();
        let ctx = create_test_context_with_storage_and_config(
            faulty(Listing::Normal, false, false),
            move |cfg| {
                cfg.cargo.proxy = Some(uri);
                cfg.cargo.metadata_ttl = 0;
                cfg.cargo.import_embedded = vec!["Corp-Lib".to_string()];
            },
        );
        ctx.state.storage.put(INDEX, OWN.as_bytes()).await.unwrap();
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, OWN);
        assert_eq!(asked(&server).await, 0);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(ctx.state.storage.stat(COPY).await.is_none());
    }

    /// Row 9: no upstream configured → the stored copy is served: the upstream copy kept from when
    /// one was configured, else the crate's index.
    #[tokio::test]
    async fn row9_without_an_upstream_the_stored_copy_answers() {
        let ctx = create_test_context_with_storage_and_config(
            faulty(Listing::Normal, false, false),
            |cfg| cfg.cargo.proxy = None,
        );
        ctx.state
            .storage
            .put(COPY, UPSTREAM.as_bytes())
            .await
            .unwrap();
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, UPSTREAM);
    }

    /// Row 5, a crash between the two writes of an assembly: the assembled index is stored, its copy
    /// for older releases is not, and the listing answers "nothing here" → the assembled index.
    #[tokio::test]
    async fn row5_an_assembled_index_without_its_copy_stays_local() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Empty, false, false), &server);
        ctx.state
            .storage
            .put(ASSEMBLED, format!("{OWN}\n").as_bytes())
            .await
            .unwrap();
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("0.1.0") && !body.contains("9.9.9"), "{body}");
        assert_eq!(asked(&server).await, 0);
    }

    /// The path in any case, a published crate whose stored index an older release cached from the
    /// upstream: its own index, rebuilt from the entries, and no upstream.
    #[tokio::test]
    async fn a_published_crate_in_any_case_of_the_path_stays_local() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Normal, false, false), &server);
        seed(&ctx.state.storage, false).await;
        ctx.state
            .storage
            .put(INDEX, UPSTREAM.as_bytes())
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/cargo/index/CO/RP/Corp-Lib", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
        assert!(body.contains("0.1.0") && !body.contains("9.9.9"), "{body}");
        assert_eq!(asked(&server).await, 0);
        let stored = ctx.state.storage.get(INDEX).await.unwrap();
        assert!(!String::from_utf8_lossy(&stored).contains("9.9.9"));
    }

    /// Two published crates whose names share a prefix: each index holds its own entries only.
    #[tokio::test]
    async fn a_crate_index_never_holds_another_crates_entries() {
        let ctx = create_test_context_with_config(|cfg| cfg.cargo.proxy = None);
        let meta = serde_json::to_vec(&serde_json::json!({
            "name": "corp-lib-extra", "vers": "0.5.0", "deps": [], "features": {}
        }))
        .unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&(meta.len() as u32).to_le_bytes());
        payload.extend_from_slice(&meta);
        payload.extend_from_slice(&3u32.to_le_bytes());
        payload.extend_from_slice(b"crt");
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            axum::body::Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(publish(&ctx.app, "0.1.0").await, StatusCode::OK);
        let (_, body) = get_index(&ctx.app).await;
        assert!(
            body.contains("\"corp-lib\"") && !body.contains("corp-lib-extra"),
            "{body}"
        );
    }

    /// A publish of a further version over a stored index of unknown origin (the crate already has
    /// entries): nothing of that index is imported.
    #[tokio::test]
    async fn a_further_publish_never_imports_a_stored_index() {
        let ctx = create_test_context_with_config(|cfg| cfg.cargo.proxy = None);
        seed(&ctx.state.storage, false).await;
        let foreign = r#"{"name":"corp-lib","vers":"8.8.8","deps":[],"cksum":"88","features":{},"yanked":false}"#;
        ctx.state
            .storage
            .put(INDEX, format!("{foreign}\n").as_bytes())
            .await
            .unwrap();
        assert_eq!(publish(&ctx.app, "0.2.0").await, StatusCode::OK);
        let (_, body) = get_index(&ctx.app).await;
        assert!(
            body.contains("\"0.1.0\"") && body.contains("\"0.2.0\"") && !body.contains("8.8.8"),
            "{body}"
        );
        assert!(ctx
            .state
            .storage
            .stat("cargo/index-entries/co/rp/corp-lib/8.8.8.json")
            .await
            .is_none());
    }

    /// `import_embedded` names crates exactly: a name it does not list is neither imported at publish
    /// nor read as the crate's own.
    #[tokio::test]
    async fn import_embedded_names_crates_exactly() {
        let server = squatter().await;
        let uri = server.uri();
        let ctx = create_test_context_with_storage_and_config(
            faulty(Listing::Normal, false, false),
            move |cfg| {
                cfg.cargo.proxy = Some(uri);
                cfg.cargo.metadata_ttl = 0;
                cfg.cargo.import_embedded = vec!["corp".to_string(), "corp-lib-x".to_string()];
            },
        );
        ctx.state.storage.put(INDEX, OWN.as_bytes()).await.unwrap();
        let (_, body) = get_index(&ctx.app).await;
        assert!(body.contains("9.9.9"), "{body}");
        assert_eq!(publish(&ctx.app, "0.2.0").await, StatusCode::CONFLICT);
    }

    /// The assembled index cannot be read (a storage error, not "absent"): the crate may be NORA's,
    /// so no upstream answers for it, and a publish is not decided on a guess.
    #[tokio::test]
    async fn an_unreadable_assembled_index_is_a_503_not_the_upstream() {
        let server = squatter().await;
        let unreadable = Storage::from_backend(std::sync::Arc::new(Faulty {
            inner: ObjectStorage::in_memory(),
            listing: Listing::Empty,
            index_put_fails: false,
            entry_get_fails: false,
            assembled_get_fails: true,
            entries_listed: Default::default(),
        }));
        let ctx = proxied(unreadable, &server);
        ctx.state
            .storage
            .put(ASSEMBLED, OWN.as_bytes())
            .await
            .unwrap();
        let (status, _) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(asked(&server).await, 0);
        assert_eq!(
            publish(&ctx.app, "0.2.0").await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// GET and a first publish race: the upstream's answer to the GET arrives after the publish. It
    /// lands at the upstream copy, never at the crate's index, and the crate answers as published.
    #[tokio::test]
    async fn a_late_upstream_answer_never_lands_on_a_published_index() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index/co/rp/corp-lib"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(UPSTREAM)
                    .set_delay(std::time::Duration::from_millis(800)),
            )
            .mount(&server)
            .await;
        let ctx = proxied(faulty(Listing::Normal, false, false), &server);
        let app = ctx.app.clone();
        let get = tokio::spawn(async move { get_index(&app).await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(publish(&ctx.app, "0.1.0").await, StatusCode::OK);
        let _ = get.await.unwrap();
        wait_for(&ctx.state.storage, COPY).await;
        let stored = ctx.state.storage.get(INDEX).await.unwrap();
        assert!(!String::from_utf8_lossy(&stored).contains("9.9.9"));
        let (_, body) = get_index(&ctx.app).await;
        assert!(body.contains("0.1.0") && !body.contains("9.9.9"), "{body}");
    }

    #[test]
    fn index_and_entry_versions_compare_as_sets() {
        let keys = [
            "cargo/index-entries/co/rp/corp-lib/0.1.0.json".to_string(),
            "cargo/index-entries/co/rp/corp-lib/0.2.0.json".to_string(),
        ];
        let listed = super::entry_versions("co/rp", "corp-lib", &keys);
        let two = format!("{OWN}\n{}\n", OWN.replace("0.1.0", "0.2.0"));
        assert_eq!(super::index_versions(two.as_bytes()), Some(listed.clone()));
        assert_ne!(
            super::index_versions(format!("{OWN}\n").as_bytes()),
            Some(listed.clone())
        );
        assert_eq!(super::index_versions(b"not an index line\n"), None);
        assert!(super::entry_versions("co/rp", "corp", &keys).is_empty());
    }

    /// A version published while an older release ran (it rewrote only the copy at the crate's
    /// index) is served: the assembled index that does not list it is rebuilt from the entries.
    #[tokio::test]
    async fn an_assembled_index_missing_a_listed_version_is_rebuilt() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Normal, false, false), &server);
        seed(&ctx.state.storage, true).await;
        ctx.state
            .storage
            .put(
                "cargo/index-entries/co/rp/corp-lib/0.2.0.json",
                OWN.replace("0.1.0", "0.2.0").as_bytes(),
            )
            .await
            .unwrap();
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("\"0.1.0\"") && body.contains("\"0.2.0\"") && !body.contains("9.9.9"),
            "{body}"
        );
        assert_eq!(asked(&server).await, 0);
        let assembled = ctx.state.storage.get(ASSEMBLED).await.unwrap();
        assert!(String::from_utf8_lossy(&assembled).contains("0.2.0"));
    }

    /// The entries listed once, then their listing fails inside the rebuild: 503, never an empty
    /// index, and the assembled index is left as it was.
    #[tokio::test]
    async fn a_listing_that_fails_inside_the_rebuild_is_a_503_not_an_empty_index() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::FailsAfterFirst, false, false), &server);
        seed(&ctx.state.storage, true).await;
        ctx.state
            .storage
            .put(
                "cargo/index-entries/co/rp/corp-lib/0.2.0.json",
                OWN.replace("0.1.0", "0.2.0").as_bytes(),
            )
            .await
            .unwrap();
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let assembled = ctx.state.storage.get(ASSEMBLED).await.unwrap();
        assert_eq!(assembled.as_ref(), format!("{OWN}\n").as_bytes());
        assert_eq!(asked(&server).await, 0);
    }

    /// A publish names the crate in any case: it is stored under the lowercase name, so its index
    /// answers as published and no upstream is asked.
    #[tokio::test]
    async fn a_publish_in_any_case_is_published_under_the_lowercase_name() {
        let server = squatter().await;
        let ctx = proxied(faulty(Listing::Normal, false, false), &server);
        let meta = serde_json::to_vec(&serde_json::json!({
            "name": "Corp-Lib", "vers": "0.1.0", "deps": [], "features": {}
        }))
        .unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&(meta.len() as u32).to_le_bytes());
        payload.extend_from_slice(&meta);
        payload.extend_from_slice(&3u32.to_le_bytes());
        payload.extend_from_slice(b"crt");
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            axum::body::Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("\"0.1.0\"") && !body.contains("9.9.9"),
            "{body}"
        );
        assert_eq!(asked(&server).await, 0);
    }

    /// Row 5e with a fresh upstream copy beside it (cached before the operator named the crate):
    /// the operator's word wins, the copy is not served.
    #[tokio::test]
    async fn row5e_a_fresh_upstream_copy_does_not_shadow_an_index_named_own() {
        let server = squatter().await;
        let uri = server.uri();
        let ctx = create_test_context_with_storage_and_config(
            faulty(Listing::Normal, false, false),
            move |cfg| {
                cfg.cargo.proxy = Some(uri);
                cfg.cargo.metadata_ttl = 300;
                cfg.cargo.import_embedded = vec!["corp-lib".to_string()];
            },
        );
        ctx.state.storage.put(INDEX, OWN.as_bytes()).await.unwrap();
        ctx.state
            .storage
            .put(COPY, UPSTREAM.as_bytes())
            .await
            .unwrap();
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, OWN);
        assert_eq!(asked(&server).await, 0);
    }

    /// The assembled index fails its integrity check (its bytes changed under the stored digest):
    /// the crate may be NORA's, so 503 — not "absent", and never the upstream's answer.
    #[tokio::test]
    async fn a_corrupted_assembled_index_is_a_503_not_the_upstream() {
        let server = squatter().await;
        let uri = server.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.cargo.proxy = Some(uri);
            cfg.cargo.metadata_ttl = 0;
        });
        let index = format!("{OWN}\n");
        super::store_assembled_index(&ctx.state.storage, "co/rp", "corp-lib", index.as_bytes())
            .await
            .unwrap();
        std::fs::write(ctx._tempdir.path().join(ASSEMBLED), b"changed on disk\n").unwrap();
        assert!(matches!(
            ctx.state.storage.get(ASSEMBLED).await,
            Err(crate::storage::StorageError::IntegrityViolation)
        ));
        let (status, _) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(asked(&server).await, 0);
    }

    /// Rows 8 and 12: an internal name is never asked of the upstream — refused with nothing
    /// stored, answered from the stored copy (even a stale one) otherwise.
    #[tokio::test]
    async fn an_internal_crate_index_never_reaches_the_upstream() {
        let server = squatter().await;
        let uri = server.uri();
        let ctx = create_test_context_with_storage_and_config(
            faulty(Listing::Normal, false, false),
            move |cfg| {
                cfg.cargo.proxy = Some(uri);
                cfg.cargo.metadata_ttl = 0;
                cfg.curation.internal_namespaces = vec!["corp-*".to_string()];
            },
        );
        let (status, body) = get_index(&ctx.app).await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert!(!body.contains("9.9.9"), "{body}");
        ctx.state.storage.put(COPY, OWN.as_bytes()).await.unwrap();
        let (status, body) = get_index(&ctx.app).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, OWN);
        assert_eq!(asked(&server).await, 0);
    }

    /// A first publish over NORA's own index whose entries are gone imports it (no refusal).
    #[tokio::test]
    async fn a_publish_over_an_assembled_index_without_entries_imports_it() {
        let ctx = create_test_context_with_config(|_| {});
        let index = format!("{OWN}\n");
        super::store_assembled_index(&ctx.state.storage, "co/rp", "corp-lib", index.as_bytes())
            .await
            .unwrap();
        let meta = serde_json::to_vec(&serde_json::json!({
            "name": "corp-lib", "vers": "0.2.0", "deps": [], "features": {}
        }))
        .unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&(meta.len() as u32).to_le_bytes());
        payload.extend_from_slice(&meta);
        payload.extend_from_slice(&3u32.to_le_bytes());
        payload.extend_from_slice(b"crt");
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            axum::body::Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let (_, body) = get_index(&ctx.app).await;
        assert!(
            body.contains("\"0.1.0\"") && body.contains("\"0.2.0\""),
            "{body}"
        );
    }
}

/// The request's spelling reaches upstream as sent, while every local
/// decision (curation, integrity, isolation, publish date) is taken on the lowercase name.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod crate_name_every_decision_on_the_lowercase_name {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn write_json(dir: &tempfile::TempDir, file: &str, json: serde_json::Value) -> String {
        let p = dir.path().join(file);
        std::fs::write(&p, json.to_string()).unwrap();
        p.to_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn a_blocklisted_crate_is_blocked_in_any_spelling() {
        let dir = tempfile::TempDir::new().unwrap();
        let bl = write_json(
            &dir,
            "blocklist.json",
            serde_json::json!({"version": 1, "rules": [
                {"registry": "cargo", "name": "evil-crate", "version": "*", "reason": "malware"}
            ]}),
        );
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl);
        });
        ctx.state
            .storage
            .put("cargo/evil-crate/1.0.0/evil-crate-1.0.0.crate", b"evil")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/Evil-Crate/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_internal_crate_is_isolated_in_any_spelling() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SQUAT".to_vec()))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.curation.internal_namespaces = vec!["internal*".to_string()];
            cfg.cargo.proxy = Some(uri);
        });
        // A local internal crate is served whatever the spelling.
        ctx.state
            .storage
            .put("cargo/internal-lib/1.0.0/internal-lib-1.0.0.crate", b"OURS")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/Internal-Lib/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Without a local copy it is refused, and upstream is never asked.
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/Internal-Lib/2.0.0/download",
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::OK);
        assert!(upstream.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_publish_date_is_read_under_the_lowercase_name() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
            cfg.server.trust_upstream_dates = true;
            cfg.cargo.proxy = Some(uri);
        });
        // Released an hour ago: the 7-day gate holds it, whatever the spelling.
        let created = (chrono::Utc::now() - chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let meta = serde_json::json!({"versions": [
            {"num": "0.11.4", "created_at": created}
        ]});
        ctx.state
            .storage
            .put("cargo/inflector/metadata.json", meta.to_string().as_bytes())
            .await
            .unwrap();
        ctx.state
            .storage
            .put("cargo/inflector/0.11.4/inflector-0.11.4.crate", b"CRATE")
            .await
            .unwrap();
        for spelling in ["inflector", "Inflector"] {
            let resp = send(
                &ctx.app,
                Method::GET,
                &format!("/cargo/api/v1/crates/{spelling}/0.11.4/download"),
                "",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{spelling}");
        }
    }

    #[tokio::test]
    async fn an_underscored_name_reaches_upstream_as_sent() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/crates/Foo_Bar/1.0.0/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"CRATE".to_vec()))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.cargo.proxy = Some(uri);
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/Foo_Bar/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn integrity_is_verified_under_the_lowercase_name() {
        let dir = tempfile::TempDir::new().unwrap();
        let al = write_json(
            &dir,
            "allowlist.json",
            serde_json::json!({"version": 1, "entries": [{
                "registry": "cargo", "name": "pinned", "version": "1.0.0",
                "integrity": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "integrity_source": "manual"
            }]}),
        );
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(al);
        });
        ctx.state
            .storage
            .put("cargo/pinned/1.0.0/pinned-1.0.0.crate", b"tampered")
            .await
            .unwrap();
        for spelling in ["pinned", "Pinned"] {
            let resp = send(
                &ctx.app,
                Method::GET,
                &format!("/cargo/api/v1/crates/{spelling}/1.0.0/download"),
                "",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{spelling}");
        }
    }
}

/// An internal crate is refused alike in every spelling of its name.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod crate_name_isolation_in_any_spelling {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // The name as sent is bound once, to build the upstream path, before it is lowercased;
    // after that the upstream path is used only in the URL. No later decision can see the
    // published spelling.
    #[test]
    fn only_the_upstream_path_keeps_the_name_as_sent() {
        let src = include_str!("cargo_registry.rs");
        let body = &src[src.find("async fn download(").unwrap()..];
        let body = &body[..body.find("\n}\n").unwrap()];
        let (before, after) = body
            .split_once("let crate_name = crate_name.to_lowercase();")
            .unwrap();
        assert_eq!(before.matches("let ").count(), 1, "{before}");
        assert!(before.contains("let upstream_path = format!("), "{before}");
        assert_eq!(after.matches("upstream_path").count(), 1, "{after}");
        assert!(after.contains(
            "let url = format!(\"{}/{}\", proxy_url.trim_end_matches('/'), upstream_path);"
        ));
    }

    // An internal crate with no local copy is refused the same way whatever the spelling.
    #[tokio::test]
    async fn an_internal_crate_without_a_copy_is_refused_alike_in_any_spelling() {
        let upstream = MockServer::start().await;
        Mock::given(wiremock::matchers::method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SQUAT".to_vec()))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.curation.internal_namespaces = vec!["internal*".to_string()];
            cfg.cargo.proxy = Some(uri);
        });
        let mut statuses = Vec::new();
        for spelling in ["internal-lib", "Internal-Lib"] {
            let resp = send(
                &ctx.app,
                Method::GET,
                &format!("/cargo/api/v1/crates/{spelling}/2.0.0/download"),
                "",
            )
            .await;
            statuses.push(resp.status());
        }
        assert_eq!(statuses, vec![StatusCode::FORBIDDEN, StatusCode::FORBIDDEN]);
        assert!(upstream.received_requests().await.unwrap().is_empty());
    }
}

/// A name or path with an empty segment (or, where the name is one segment, any `/`) never
/// reaches curation, storage or an upstream: it would name another artifact's files, and an
/// upstream that normalises paths would answer for that other artifact.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod empty_segment_requests {
    use crate::test_helpers::{create_test_context_with_config, send, upstream_paths};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // A crate name is one cargo name (letters, digits, `-`, `_`) and a version one segment, on
    // every path that takes them: `corp-secret%2Fx` decodes to `corp-secret/x`, which the
    // isolation pattern `corp-secret` does not match and which names another crate's files.
    #[tokio::test]
    async fn a_crate_name_or_version_that_is_not_one_name_never_reaches_upstream() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&up)
            .await;
        let uri = up.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.cargo.proxy = Some(uri);
            cfg.curation.internal_namespaces = vec!["corp-secret".to_string()];
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/corp-secret",
            "",
        )
        .await;
        assert!(!resp.status().is_success(), "control");
        assert!(upstream_paths(&up).await.is_empty(), "control");
        for path in [
            "/cargo/api/v1/crates/corp-secret%2Fx",
            "/cargo/api/v1/crates/corp-secret%2F",
            "/cargo/api/v1/crates/corp-secret%2Fx/1.0.0/download",
            "/cargo/api/v1/crates/serde/1.0.0%2Fx/download",
            "/cargo/api/v1/crates/serde/1.0.0%2F/download",
        ] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{path}");
        }
        let sent = upstream_paths(&up).await;
        assert!(sent.is_empty(), "sent upstream: {sent:?}");
    }
}

/// A crate is the crate crates.io finds: crates.io looks names up without case and with `-` and
/// `_` as one character (`canon_crate_name`), so a rule, an allowlist entry or an internal
/// namespace holds for every spelling that resolves to the same crate.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod crate_name_canonical_curation {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"CRATE".to_vec()))
            .mount(&upstream)
            .await;
        upstream
    }

    fn write(dir: &tempfile::TempDir, file: &str, body: &str) -> String {
        let path = dir.path().join(file);
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn a_rule_holds_for_every_spelling_crates_io_resolves() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = write(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [{"registry": "cargo", "name": "evil-crate", "version": "*", "reason": "malware"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.cargo.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        for name in ["evil-crate", "evil_crate", "Evil_Crate", "EVIL-CRATE"] {
            let resp = send(
                &ctx.app,
                Method::GET,
                &format!("/cargo/api/v1/crates/{name}/1.0.0/download"),
                "",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{name}");
        }
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/evil-crates/1.0.0/download",
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN, "another crate");
    }

    #[tokio::test]
    async fn an_allowlist_entry_admits_every_spelling_of_its_crate() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = write(
            &dir,
            "allowlist.json",
            r#"{"version": 1, "entries": [{"registry": "cargo", "name": "serde_json", "version": "1.0.0"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.cargo.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        for name in ["serde_json", "serde-json"] {
            let resp = send(
                &ctx.app,
                Method::GET,
                &format!("/cargo/api/v1/crates/{name}/1.0.0/download"),
                "",
            )
            .await;
            assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{name}");
        }
    }

    #[tokio::test]
    async fn an_internal_namespace_isolates_every_spelling() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SQUAT".to_vec()))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.cargo.proxy = Some(uri);
            cfg.curation.internal_namespaces = vec!["corp_*".to_string()];
        });
        for name in ["corp_tools", "corp-tools", "Corp-Tools"] {
            let resp = send(
                &ctx.app,
                Method::GET,
                &format!("/cargo/api/v1/crates/{name}/1.0.0/download"),
                "",
            )
            .await;
            assert!(!resp.status().is_success(), "{name}: {}", resp.status());
        }
        let asked: Vec<String> = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert!(asked.is_empty(), "internal names sent upstream: {asked:?}");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod crate_name_one_canon {
    //! `-` and `_` name one crate, as on crates.io: another
    //! spelling of a published crate is refused and never asked of an upstream.
    use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};
    use crate::test_helpers::{body_bytes, create_test_context_with_storage_and_config, send};
    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// An object store whose reads of name records can be made to fail, or to take a while.
    struct Records {
        inner: ObjectStorage,
        record_get_fails: bool,
        record_get_delay: Option<std::time::Duration>,
        records_list_fails: bool,
    }

    #[async_trait::async_trait]
    impl StorageBackend for Records {
        async fn get(
            &self,
            k: &str,
        ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
            if self.record_get_fails && k.starts_with("cargo/_names/") {
                return Err(crate::storage::StorageError::Network("read failed".into()));
            }
            if let Some(delay) = self
                .record_get_delay
                .filter(|_| k.starts_with("cargo/_names/"))
            {
                tokio::time::sleep(delay).await;
            }
            self.inner.get(k).await
        }
        async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
            self.inner.put(k, d, sha256).await
        }
        async fn pin(&self, k: &str) -> Option<String> {
            self.inner.pin(k).await
        }
        async fn delete(&self, k: &str) -> crate::storage::Result<()> {
            self.inner.delete(k).await
        }
        async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
            if self.records_list_fails && prefix.starts_with("cargo/_names/") {
                return Err(crate::storage::StorageError::Network(
                    "listing failed".into(),
                ));
            }
            self.inner.list(prefix).await
        }
        async fn list_with_meta(&self, p: &str) -> crate::storage::Result<Vec<(String, FileMeta)>> {
            self.inner.list_with_meta(p).await
        }
        async fn stat(&self, k: &str) -> Option<FileMeta> {
            self.inner.stat(k).await
        }
        async fn health_check(&self) -> bool {
            self.inner.health_check().await
        }
        async fn total_size(&self) -> u64 {
            self.inner.total_size().await
        }
        fn backend_name(&self) -> &'static str {
            "records-test-store"
        }
        async fn put_from_path(
            &self,
            k: &str,
            src: &std::path::Path,
            sha256: Option<&str>,
        ) -> crate::storage::Result<()> {
            self.inner.put_from_path(k, src, sha256).await
        }
        async fn copy(&self, s: &str, d: &str, sha256: Option<&str>) -> crate::storage::Result<()> {
            self.inner.copy(s, d, sha256).await
        }
        async fn get_reader(
            &self,
            k: &str,
        ) -> crate::storage::Result<(
            u64,
            Option<String>,
            std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
        )> {
            self.inner.get_reader(k).await
        }
    }

    fn store(record_get_fails: bool) -> Storage {
        Storage::from_backend(std::sync::Arc::new(Records {
            inner: ObjectStorage::in_memory(),
            record_get_fails,
            record_get_delay: None,
            records_list_fails: false,
        }))
    }

    /// An upstream that answers every request: a squatter on every spelling.
    async fn squatter() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"name":"my_crate","vers":"9.9.9","deps":[],"cksum":"00","features":{},"yanked":false}"#,
            ))
            .mount(&server)
            .await;
        server
    }

    async fn asked(server: &MockServer) -> usize {
        server.received_requests().await.unwrap().len()
    }

    fn proxied(storage: Storage, server: &MockServer) -> crate::test_helpers::TestContext {
        let uri = server.uri();
        create_test_context_with_storage_and_config(storage, move |cfg| {
            cfg.cargo.proxy = Some(uri);
            cfg.cargo.metadata_ttl = 0;
        })
    }

    async fn publish(app: &axum::Router, name: &str, vers: &str) -> (StatusCode, String) {
        let meta = serde_json::to_vec(
            &serde_json::json!({"name": name, "vers": vers, "deps": [], "features": {}}),
        )
        .unwrap();
        let data = b"crate-data";
        let mut payload = Vec::new();
        payload.extend_from_slice(&(meta.len() as u32).to_le_bytes());
        payload.extend_from_slice(&meta);
        payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
        payload.extend_from_slice(data);
        let resp = send(
            app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        let status = resp.status();
        (
            status,
            String::from_utf8_lossy(&body_bytes(resp).await).into_owned(),
        )
    }

    async fn get(app: &axum::Router, uri: &str) -> (StatusCode, String) {
        let resp = send(app, Method::GET, uri, "").await;
        let status = resp.status();
        (
            status,
            String::from_utf8_lossy(&body_bytes(resp).await).into_owned(),
        )
    }

    #[test]
    fn a_canon_is_lowercase_with_hyphens() {
        for spelling in ["my-crate", "my_crate", "My_Crate", "MY-CRATE"] {
            assert_eq!(super::canonical_crate_name(spelling), "my-crate");
        }
        assert_eq!(super::canonical_crate_name("serde"), "serde");
        assert_eq!(super::canonical_crate_name("a_b-c_d"), "a-b-c-d");
    }

    /// C1, C2, C5, D1: with `my-crate` published, its own index answers; the index and downloads of
    /// `my_crate` (any case) are refused with the published spelling, and the upstream is never asked.
    #[tokio::test]
    async fn another_spelling_of_a_published_crate_is_refused() {
        let server = squatter().await;
        let ctx = proxied(store(false), &server);
        assert_eq!(
            publish(&ctx.app, "my-crate", "0.1.0").await.0,
            StatusCode::OK
        );
        let (status, body) = get(&ctx.app, "/cargo/index/my/-c/my-crate").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("0.1.0"), "{body}");
        for uri in [
            "/cargo/index/my/_c/my_crate",
            "/cargo/index/My/_C/My_Crate",
            "/cargo/api/v1/crates/my_crate/9.9.9/download",
        ] {
            let (status, body) = get(&ctx.app, uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert!(body.contains("`my-crate`"), "{uri}: {body}");
        }
        assert_eq!(asked(&server).await, 0);
    }

    /// Publish: `my_crate` with `my-crate` published is a conflict naming it and stores nothing;
    /// another version of `my-crate` publishes as before.
    #[tokio::test]
    async fn a_publish_of_another_spelling_is_a_conflict() {
        let server = squatter().await;
        let ctx = proxied(store(false), &server);
        assert_eq!(
            publish(&ctx.app, "my-crate", "0.1.0").await.0,
            StatusCode::OK
        );
        let (status, body) = publish(&ctx.app, "my_crate", "0.2.0").await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.contains("`my-crate`"), "{body}");
        assert!(ctx
            .state
            .storage
            .stat("cargo/my_crate/0.2.0/my_crate-0.2.0.crate")
            .await
            .is_none());
        assert_eq!(
            publish(&ctx.app, "my-crate", "0.2.0").await.0,
            StatusCode::OK
        );
    }

    /// A refused publish leaves no record: `my_crate` 0.1.0 over a copy cached at its key is a
    /// conflict, writes no name record, and `my-crate` then publishes.
    #[tokio::test]
    async fn a_refused_publish_leaves_no_record() {
        let server = squatter().await;
        let ctx = proxied(store(false), &server);
        ctx.state
            .storage
            .put("cargo/my_crate/0.1.0/my_crate-0.1.0.crate", b"cached")
            .await
            .unwrap();
        assert_eq!(
            publish(&ctx.app, "my_crate", "0.1.0").await.0,
            StatusCode::CONFLICT
        );
        assert!(ctx
            .state
            .storage
            .stat("cargo/_names/my-crate")
            .await
            .is_none());
        assert_eq!(
            publish(&ctx.app, "my-crate", "0.1.0").await.0,
            StatusCode::OK
        );
    }

    /// Two spellings published at once: the canon's lock lets one through and the other finds its
    /// record — one 200, one 409 — even when reading the record takes long enough for both to start.
    #[tokio::test]
    async fn two_spellings_published_at_once_do_not_both_pass() {
        let server = squatter().await;
        let ctx = proxied(
            Storage::from_backend(std::sync::Arc::new(Records {
                inner: ObjectStorage::in_memory(),
                record_get_fails: false,
                record_get_delay: Some(std::time::Duration::from_millis(200)),
                records_list_fails: false,
            })),
            &server,
        );
        let (a, b) = tokio::join!(
            publish(&ctx.app, "race-x", "0.1.0"),
            publish(&ctx.app, "race_x", "0.1.0")
        );
        let mut statuses = [a.0, b.0];
        statuses.sort();
        assert_eq!(
            statuses,
            [StatusCode::OK, StatusCode::CONFLICT],
            "{a:?} {b:?}"
        );
    }

    /// C6: a name record that cannot be read refuses (503) without asking the upstream; a name
    /// without `-` or `_` has no other spelling, reads no record and goes on as before.
    #[tokio::test]
    async fn an_unreadable_record_refuses_and_a_plain_name_reads_none() {
        let server = squatter().await;
        let ctx = proxied(store(true), &server);
        let (status, _) = get(&ctx.app, "/cargo/index/my/_c/my_crate").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(asked(&server).await, 0);
        let (status, _) = get(&ctx.app, "/cargo/index/se/rd/serde").await;
        assert_ne!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(asked(&server).await, 1);
    }

    async fn seed_entries(storage: &Storage, names: &[&str]) {
        for name in names {
            let key = format!(
                "cargo/index-entries/{}/{name}/0.1.0.json",
                super::crate_index_prefix(name)
            );
            let entry = format!(
                r#"{{"name":"{name}","vers":"0.1.0","deps":[],"cksum":"aa","features":{{}},"yanked":false}}"#
            );
            storage.put(&key, entry.as_bytes()).await.unwrap();
        }
    }

    /// A start with every record in place reads no record and writes none: what is recorded is one
    /// listing, not a read per crate.
    #[tokio::test]
    async fn a_rebuild_with_every_record_in_place_reads_no_record() {
        let (storage, ops) = crate::test_helpers::op_counting_storage();
        seed_entries(&storage, &["aa-x", "bb_y", "ccz"]).await;
        super::rebuild_crate_name_records(&storage).await;
        ops.reset();
        super::rebuild_crate_name_records(&storage).await;
        let snapshot = ops.snapshot();
        assert!(
            snapshot.get("get").is_none() && snapshot.get("put").is_none(),
            "{snapshot:?}"
        );
    }

    /// Only the missing records are written, and a record already there — here naming the other
    /// spelling — is never overwritten; with the records unlistable, each is read before it is
    /// written, so none is overwritten either.
    #[tokio::test]
    async fn a_rebuild_writes_only_missing_records_and_overwrites_none() {
        for records_list_fails in [false, true] {
            let storage = Storage::from_backend(std::sync::Arc::new(Records {
                inner: ObjectStorage::in_memory(),
                record_get_fails: false,
                record_get_delay: None,
                records_list_fails,
            }));
            seed_entries(&storage, &["aa-x", "bb_y"]).await;
            storage.put("cargo/_names/aa-x", b"aa_x").await.unwrap();
            super::rebuild_crate_name_records(&storage).await;
            assert_eq!(&*storage.get("cargo/_names/aa-x").await.unwrap(), b"aa_x");
            assert_eq!(&*storage.get("cargo/_names/bb-y").await.unwrap(), b"bb_y");
        }
    }

    #[test]
    fn spelling_heads_cover_every_index_directory() {
        let mut heads = super::spelling_heads("ab-cd");
        heads.sort();
        assert_eq!(heads, ["ab-cd", "ab_cd"]);
        let mut heads = super::spelling_heads("A-b-cdef");
        heads.sort();
        assert_eq!(heads, ["a-b-cdef", "a-b_cdef", "a_b-cdef", "a_b_cdef"]);
        assert_eq!(super::spelling_heads("abcd-e"), ["abcd-e"]);
    }

    /// F1c, F1d: a record naming the asked spelling while it is not published is stale. With another
    /// spelling published, the asked one is refused (index, download, publish) naming it and the
    /// upstream is not asked; with none published, the request goes on and a publish takes the name.
    #[tokio::test]
    async fn a_stale_record_naming_this_spelling_decides_nothing() {
        for other_published in [true, false] {
            let server = squatter().await;
            let ctx = proxied(store(false), &server);
            ctx.state
                .storage
                .put("cargo/_names/zz-q", b"zz_q")
                .await
                .unwrap();
            if other_published {
                seed_entries(&ctx.state.storage, &["zz-q"]).await;
                for uri in [
                    "/cargo/index/zz/_q/zz_q",
                    "/cargo/api/v1/crates/zz_q/9.9.9/download",
                ] {
                    let (status, body) = get(&ctx.app, uri).await;
                    assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
                    assert!(body.contains("`zz-q`"), "{uri}: {body}");
                }
                assert_eq!(asked(&server).await, 0);
                let (status, body) = publish(&ctx.app, "zz_q", "0.1.0").await;
                assert_eq!(status, StatusCode::CONFLICT);
                assert!(body.contains("`zz-q`"), "{body}");
            } else {
                let (status, _) = get(&ctx.app, "/cargo/index/zz/_q/zz_q").await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(asked(&server).await, 1);
                assert_eq!(publish(&ctx.app, "zz_q", "0.1.0").await.0, StatusCode::OK);
                assert_eq!(
                    &*ctx.state.storage.get("cargo/_names/zz-q").await.unwrap(),
                    b"zz_q"
                );
            }
        }
    }

    /// F1g, F1h: a record naming another spelling that is not published is stale too. With a third
    /// spelling published, the asked one is refused naming that one; with none, the request goes on,
    /// and a publish takes the name and rewrites the record.
    #[tokio::test]
    async fn a_stale_record_naming_another_spelling_decides_nothing() {
        for third_published in [true, false] {
            let server = squatter().await;
            let ctx = proxied(store(false), &server);
            ctx.state
                .storage
                .put("cargo/_names/a-b-c", b"a_b-c")
                .await
                .unwrap();
            if third_published {
                seed_entries(&ctx.state.storage, &["a-b_c"]).await;
                let (status, body) = get(&ctx.app, "/cargo/index/a-/b-/a-b-c").await;
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert!(body.contains("`a-b_c`"), "{body}");
                assert_eq!(asked(&server).await, 0);
                let (status, body) = publish(&ctx.app, "a-b-c", "0.1.0").await;
                assert_eq!(status, StatusCode::CONFLICT);
                assert!(body.contains("`a-b_c`"), "{body}");
            } else {
                let (status, _) = get(&ctx.app, "/cargo/index/a-/b-/a-b-c").await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(publish(&ctx.app, "a-b-c", "0.1.0").await.0, StatusCode::OK);
                assert_eq!(
                    &*ctx.state.storage.get("cargo/_names/a-b-c").await.unwrap(),
                    b"a-b-c"
                );
            }
        }
    }

    /// A download of a published crate whose name has `-` lists no more than one without: the record
    /// naming its own spelling is weighed only before an upstream would be asked.
    #[tokio::test]
    async fn a_download_of_a_published_crate_lists_nothing_more() {
        let (storage, ops) = crate::test_helpers::op_counting_storage();
        let ctx = crate::test_helpers::create_test_context_with_storage(storage);
        let mut lists = Vec::new();
        for name in ["my-crate", "mycrate"] {
            assert_eq!(publish(&ctx.app, name, "0.1.0").await.0, StatusCode::OK);
            ops.reset();
            let (status, _) = get(
                &ctx.app,
                &format!("/cargo/api/v1/crates/{name}/0.1.0/download"),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{name}");
            lists.push(ops.snapshot().get("list").copied().unwrap_or(0));
        }
        assert_eq!(lists[0], lists[1], "{lists:?}");
    }

    /// S1, C7: a store from an older release (`my-crate` published, no record) gets its records at
    /// startup, and `my_crate` is refused from then on; where both spellings were published, each
    /// still serves its own index.
    #[tokio::test]
    async fn records_are_rebuilt_for_crates_published_before_them() {
        let server = squatter().await;
        let ctx = proxied(store(false), &server);
        let own = |name: &str| {
            format!(
                r#"{{"name":"{name}","vers":"0.1.0","deps":[],"cksum":"aa","features":{{}},"yanked":false}}"#
            )
        };
        for (key, name) in [
            ("cargo/index-entries/my/-c/my-crate/0.1.0.json", "my-crate"),
            (
                "cargo/index-entries/bo/th/both-ways/0.1.0.json",
                "both-ways",
            ),
            (
                "cargo/index-entries/bo/th/both_ways/0.1.0.json",
                "both_ways",
            ),
        ] {
            ctx.state
                .storage
                .put(key, own(name).as_bytes())
                .await
                .unwrap();
        }
        super::rebuild_crate_name_records(&ctx.state.storage).await;
        let (status, body) = get(&ctx.app, "/cargo/index/my/_c/my_crate").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("`my-crate`"), "{body}");
        for (uri, name) in [
            ("/cargo/index/bo/th/both-ways", "both-ways"),
            ("/cargo/index/bo/th/both_ways", "both_ways"),
        ] {
            let (status, body) = get(&ctx.app, uri).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert!(body.contains(name), "{uri}: {body}");
        }
        // Each published spelling also downloads its own crate and takes a new version.
        for name in ["both-ways", "both_ways"] {
            ctx.state
                .storage
                .put(
                    &format!("cargo/{name}/0.1.0/{name}-0.1.0.crate"),
                    name.as_bytes(),
                )
                .await
                .unwrap();
            let uri = format!("/cargo/api/v1/crates/{name}/0.1.0/download");
            let (status, body) = get(&ctx.app, &uri).await;
            assert_eq!(status, StatusCode::OK, "{uri}: {body}");
            assert_eq!(body, name);
            assert_eq!(
                publish(&ctx.app, name, "0.2.0").await.0,
                StatusCode::OK,
                "{name}"
            );
        }
        assert_eq!(asked(&server).await, 0);
    }
}
