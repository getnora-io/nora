// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! PyPI registry — PEP 503 (Simple HTML) + PEP 691 (JSON) + twine upload.
//!
//! Implements:
//!   GET  /simple/                     — package index (HTML or JSON)
//!   GET  /simple/{name}/              — package versions (HTML or JSON)
//!   GET  /simple/{name}/{filename}    — download file
//!   POST /simple/                     — twine upload (multipart/form-data)

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, NamespaceAuthority};
use crate::circuit_breaker::BreakerScope;
use crate::config::UpstreamAuth;
use crate::registry::{
    circuit_open_response, method_not_allowed, nora_base_url, proxy_fetch, proxy_fetch_text,
    UpstreamMiss,
};
use crate::registry_type::RegistryType;
use crate::ui::components::html_escape;
use crate::validation::ends_with_ci;
use crate::AppState;
use axum::{
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use sha2::Digest;
use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

/// PEP 691 JSON content type
const PEP691_JSON: &str = "application/vnd.pypi.simple.v1+json";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/simple/",
            get(list_packages)
                .post(upload)
                .fallback(|| async { method_not_allowed("GET, POST") }),
        )
        .route("/simple/{name}/", get(package_versions))
        .route("/simple/{name}/{filename}", get(download_file))
}

// ============================================================================
// Package index
// ============================================================================

/// GET /simple/ — list all packages (PEP 503 HTML or PEP 691 JSON).
async fn list_packages(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let keys = match state.storage.list("pypi/").await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = ?e, "pypi: failed to list storage for packages");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let mut packages = std::collections::HashSet::new();

    for key in keys {
        if let Some(pkg) = key.strip_prefix("pypi/").and_then(|k| k.split('/').next()) {
            if !pkg.is_empty() {
                packages.insert(pkg.to_string());
            }
        }
    }

    let mut pkg_list: Vec<_> = packages.into_iter().collect();
    pkg_list.sort();

    if wants_json(&headers) {
        // PEP 691 JSON response
        let projects: Vec<serde_json::Value> = pkg_list
            .iter()
            .map(|name| serde_json::json!({"name": name}))
            .collect();
        let body = serde_json::json!({
            "meta": {"api-version": "1.0"},
            "projects": projects,
        });
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, PEP691_JSON),
                (header::CACHE_CONTROL, "public, max-age=60, must-revalidate"),
            ],
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response()
    } else {
        // PEP 503 HTML
        let mut html = String::from(
            "<!DOCTYPE html>\n<html><head><title>Simple Index</title></head><body><h1>Simple Index</h1>\n",
        );
        for pkg in pkg_list {
            let _ = writeln!(
                html,
                "<a href=\"/simple/{}/\">{}</a><br>",
                html_escape(&pkg),
                html_escape(&pkg)
            );
        }
        html.push_str("</body></html>");
        (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "public, max-age=60, must-revalidate")],
            Html(html),
        )
            .into_response()
    }
}

// ============================================================================
// Package versions
// ============================================================================

/// GET /simple/{name}/ — list files for a package (PEP 503 HTML or PEP 691 JSON).
///
/// When proxy is configured, always fetches the upstream index and merges with
/// locally cached/uploaded files. This ensures pip sees all available wheels
/// (e.g. both cp310 and cp314) regardless of which were cached first.
/// Falls back to local-only when upstream is unavailable.
async fn package_versions(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let normalized = normalize_name(&name);
    if !crate::validation::is_one_segment(&normalized) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let prefix = format!("pypi/{}/", normalized);
    let base_url = nora_base_url(&state);

    // #68 namespace isolation: an internal-namespace package must never be fetched
    // upstream (dependency confusion). Skip the upstream merge entirely; a locally
    // published copy is still served from the local-only branch below, and an
    // internal name with no local copy is blocked (never proxied). Computed without
    // the `blocked` metric — the metric fires only on the actual block path below.
    let is_internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::PyPI,
        &normalized,
    );
    let upstreams = state.config.pypi.upstreams();
    // A project imported from the operator's own registry is NORA's: neither its index nor its
    // dates are asked of an upstream, and it lists only its own files.
    let own_files = match hosted_state(&state.storage, &normalized).await {
        Hosted::Yes(files) => Some(files),
        Hosted::No => None,
        Hosted::Unknown => {
            return crate::registry::storage_unavailable("pypi", &own_prefix(&normalized))
        }
    };
    let hosted = own_files.is_some();

    // #896: for JSON (Renovate) clients, ensure upstream PEP 700 upload-times are cached
    // so the index can surface them. No-op if already cached / internal / no upstream.
    // The map is read ONCE here and threaded through to [`pep700_meta`] — re-reading
    // `dates.json` per response was a second round-trip on the hot path (#969).
    let dates = if wants_json(&headers) && !hosted {
        ensure_pypi_dates_cached(&state, &normalized).await
    } else {
        serde_json::Map::new()
    };

    // Collect local files with their hashes and sizes. `list_with_meta` carries the
    // size from the listing itself; a per-key `stat()` is a HEAD per file on S3 and
    // must never appear on this path (#738, regressed on the JSON index by #969).
    let keys = match state.storage.list_with_meta(&prefix).await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = ?e, "pypi: failed to list storage for package versions");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    // Digests come from the hash markers: one listing covers every file, where a sidecar
    // read per file is a request per file on an object store. A file without exactly one
    // marker (stored before markers existed, or left with a stale one) is served from its
    // sidecar and queued for backfill. If the listing fails, the sidecars still serve every
    // digest, and nothing is queued against a storage that is failing.
    let marker_prefix = format!("{HASH_MARKER_PREFIX}{normalized}/");
    let (marker_keys, markers_listed) = match state.storage.list(&marker_prefix).await {
        Ok(marker_keys) => (marker_keys, true),
        Err(e) => {
            tracing::warn!(error = ?e, "pypi: failed to list hash markers, reading sidecars");
            (Vec::new(), false)
        }
    };
    let mut markers: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for (filename, sha256) in marker_keys
        .iter()
        .filter_map(|key| parse_hash_marker(&marker_prefix, key))
    {
        markers.entry(filename).or_default().push(sha256);
    }
    let mut backfill: Vec<String> = Vec::new();
    let mut local_files: Vec<FileEntry> = Vec::new();
    let mut local_sizes: std::collections::HashMap<String, u64> =
        std::collections::HashMap::with_capacity(keys.len());
    for (key, meta) in &keys {
        if let Some(filename) = key.strip_prefix(&prefix) {
            if !filename.is_empty()
                && !ends_with_ci(filename, ".sha256")
                && is_valid_pypi_filename(filename)
                && own_files.as_ref().is_none_or(|own| own.contains(filename))
            {
                let sha256 = match markers.get(filename).map(Vec::as_slice) {
                    Some([sha256]) => Some((*sha256).to_string()),
                    _ => {
                        if markers_listed {
                            backfill.push(filename.to_string());
                        }
                        state
                            .storage
                            .get(&format!("{}.sha256", key))
                            .await
                            .ok()
                            .and_then(|d| String::from_utf8(d.to_vec()).ok())
                    }
                };
                local_sizes.insert(filename.to_string(), meta.size);
                local_files.push(FileEntry {
                    filename: filename.to_string(),
                    sha256,
                });
            }
        }
    }

    if !backfill.is_empty() {
        use futures::FutureExt as _;
        use std::panic::AssertUnwindSafe;
        let storage = state.storage.clone();
        let publish_locks = state.publish_locks.clone();
        let project = normalized.clone();
        let task = async move {
            for filename in backfill {
                backfill_hash_marker(&storage, &publish_locks, &project, &filename).await;
            }
        };
        tokio::spawn(AssertUnwindSafe(task).catch_unwind().map(|done| {
            if let Err(panic) = done {
                tracing::error!(panic = ?panic, "pypi: hash marker backfill panicked");
            }
        }));
    }

    // When proxy is configured, fetch upstream index and merge with local files.
    // This fixes the case where a cp314 wheel is cached but pip 3.10 needs to
    // see the full upstream file list to find a compatible cp310 wheel.
    // Fetch each configured upstream's index and merge them (#663). Precedence is
    // the upstream order: the first upstream that lists a file wins (local files
    // win over all upstreams). One upstream's failure or open breaker must not
    // sink the others — skip it and serve the merge of what answered.
    let mut circuit_open = false;
    let mut miss = UpstreamMiss::default();
    if !is_internal && !hosted && !upstreams.is_empty() {
        let mut upstream_files: Vec<FileEntry> = Vec::new();
        for up in &upstreams {
            let url = format!("{}/{}/", up.url().trim_end_matches('/'), normalized);
            match proxy_fetch_text(
                &state.http_client,
                &url,
                Duration::from_secs(state.config.pypi.proxy_timeout),
                up.auth().map(UpstreamAuth::Basic),
                Some(("Accept", "text/html")),
                &state.circuit_breaker,
                BreakerScope::upstream(RegistryType::PyPI, up.url()),
            )
            .await
            {
                Ok(html) => {
                    miss.answered();
                    upstream_files.extend(parse_upstream_files(&html));
                }
                Err(crate::registry::ProxyError::CircuitOpen(_)) => {
                    circuit_open = true;
                    continue;
                }
                Err(e) => {
                    tracing::debug!(error = ?e, package = %normalized, upstream = %up.url(), "PyPI upstream index fetch failed, skipping");
                    miss.record(&e);
                    continue;
                }
            }
        }
        let merged = merge_file_lists(upstream_files, &local_files);
        if !merged.is_empty() {
            return if wants_json(&headers) {
                let pep700 = pep700_meta(&merged, &local_sizes, &dates);
                versions_json_response(&normalized, &merged, &base_url, &pep700)
            } else {
                versions_html_response(&normalized, &merged, &base_url)
            };
        }
    }

    // Local files only — degrade gracefully when upstreams list nothing or are down.
    if !local_files.is_empty() {
        return if wants_json(&headers) {
            let pep700 = pep700_meta(&local_files, &local_sizes, &dates);
            versions_json_response(&normalized, &local_files, &base_url, &pep700)
        } else {
            versions_html_response(&normalized, &local_files, &base_url)
        };
    }

    // A hosted project with no file left lists nothing; the upstream was not asked.
    if hosted {
        return StatusCode::NOT_FOUND.into_response();
    }

    // #68: an internal-namespace package with no local copy is blocked, never
    // proxied — return the namespace 403 (the only pypi metadata path that
    // increments the blocked metric).
    if is_internal {
        if let Some(response) = crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::PyPI,
            &normalized,
        ) {
            return response;
        }
    }

    // No upstream result and no local copy: a tripped breaker means the upstream is
    // temporarily down — return 503 (retryable) rather than 404, which would poison
    // pip's negative cache; a failed upstream is 502 for the same reason.
    if circuit_open {
        return circuit_open_response(RegistryType::PyPI.as_str());
    }

    miss.response("pypi", &normalized)
}

// ============================================================================
// Download
// ============================================================================

/// GET /simple/{name}/{filename} — download a specific file.
// LOCK-SAFE: cache-through proxy — get miss → fetch upstream → put; no RMW race
async fn download_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((name, filename)): Path<(String, String)>,
) -> Response {
    let normalized = normalize_name(&name);
    if !crate::validation::is_one_segment(&normalized) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Block download of internal bookkeeping files (dates.json, etc.) that
    // live alongside packages in storage but are not real artifacts (#891).
    if !is_valid_pypi_filename(&filename) {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Curation check — before storage access
    let version = crate::curation::parse_pypi_version(&normalized, &filename);

    let key = storage_key(&normalized, &filename);

    // A hosted project serves its own files only: a file NORA holds under its name without a
    // record — one an upstream served before the import — is no file of it, and neither is one
    // NORA does not hold; the upstream is not asked.
    let hosted = match hosted_state(&state.storage, &normalized).await {
        Hosted::Yes(own) if own.contains(&filename) => true,
        Hosted::Yes(_) => return StatusCode::NOT_FOUND.into_response(),
        Hosted::No => false,
        Hosted::Unknown => {
            return crate::registry::storage_unavailable("pypi", &own_prefix(&normalized))
        }
    };

    // The release date of this file, for min-release-age and to seed the digest-quarantine
    // first-seen clock so a provably-old release is not held as "new to this mirror"
    // (#748/#750). Obtained here whatever index the client read. An own file of a hosted project
    // has no upstream release, and an upstream's listing cached before the import does not date it.
    let publish_date = match hosted {
        true => None,
        false => pypi_publish_date(&state, &normalized, &filename, &key).await,
    };

    // #733 serve-local: an internal-namespace package is operator-owned — skip curation
    // and serve any local copy below; the upstream branch is blocked separately (never proxy).
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::PyPI,
        &normalized,
    );
    if !internal {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::PyPI,
            &normalized,
            crate::curation::RequestVersion::of_artifact(version.as_deref()),
            publish_date,
        ) {
            return response;
        }
    }

    // Digest-quarantine: first-seen hold for proxy artifacts (generalizes the
    // Docker-only wiring). Resolved once; applied at each serve point below.
    let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
        state.config.curation.pypi.quarantine.as_ref().or(state
            .config
            .curation
            .quarantine
            .as_ref()),
        state
            .config
            .curation
            .pypi
            .quarantine_ttl
            .as_deref()
            .or(state.config.curation.quarantine_ttl.as_deref()),
    );

    // Resumable download (#657): serve the requested bytes from the backend and skip
    // the full read below. Package files only — the simple index is generated, never
    // ranged. A partial read cannot be hashed, so neither the quarantine gate nor the
    // curation integrity check can run on it: the range serve stands down while
    // quarantine holds artifacts or an integrity rule applies to the file.
    if headers.contains_key(header::RANGE)
        && matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off)
        && !crate::curation::integrity_applies(
            &state.curation().curation_engine,
            crate::curation::RegistryType::PyPI,
            &normalized,
            version.as_deref(),
        )
    {
        if let Some(meta) = state.storage.stat(&key).await {
            if let Some(response) = crate::registry::range::range_response(
                &state.storage,
                &[&key],
                &headers,
                meta.size,
                pypi_content_type(&filename),
                &[(
                    header::CACHE_CONTROL,
                    "public, max-age=31536000, immutable".to_string(),
                )],
            )
            .await
            {
                if response.status() == StatusCode::PARTIAL_CONTENT {
                    state.metrics.record_download("pypi");
                    state.metrics.record_cache_hit("pypi");
                }
                return response;
            }
        }
    }

    // Try local storage first. get_verified discharges the integrity witness at
    // the serve site (compile-time guarantee — see crate::verified).
    let (cached, read_failure) =
        crate::registry::cached_read(state.storage.get_verified(&key).await);
    if let Some(outcome) = cached {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        // Curation integrity verification (issue #189)
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::PyPI,
            &normalized,
            version.as_deref(),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("pypi");
        state.metrics.record_cache_hit("pypi");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            format!("{}/{}", name, filename),
            crate::registry_type::RegistryType::PyPI,
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "proxy", "", "pypi", ""));

        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "pypi",
            &data,
            &q_mode,
            q_secs,
            "cache",
            crate::digest_quarantine::first_seen_seed(
                state.config.server.trust_upstream_dates,
                publish_date,
            ),
        ) {
            return resp;
        }

        let content_type = pypi_content_type(&filename);
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                (header::ACCEPT_RANGES, "bytes"),
            ],
            data,
        )
            .into_response();
    }

    // #733: an internal-namespace package with no local copy is never proxied upstream.
    if internal {
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("pypi", &key, e);
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::PyPI,
            &normalized,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // An own file of a hosted project that NORA cannot read is unavailable, not absent; one it
    // no longer holds is not asked of the upstream either.
    if hosted {
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("pypi", &key, e);
        }
        return StatusCode::NOT_FOUND.into_response();
    }

    // Try each configured upstream in order; the first whose index lists the file
    // serves it, fetched from that same upstream with that upstream's auth. One
    // upstream's failure or open breaker skips to the next rather than failing (#663).
    let mut circuit_open = false;
    let mut miss = UpstreamMiss::default();
    for up in &state.config.pypi.upstreams() {
        let page_url = format!("{}/{}/", up.url().trim_end_matches('/'), normalized);

        let html = match proxy_fetch_text(
            &state.http_client,
            &page_url,
            Duration::from_secs(state.config.pypi.proxy_timeout),
            up.auth().map(UpstreamAuth::Basic),
            Some(("Accept", "text/html")),
            &state.circuit_breaker,
            BreakerScope::upstream(RegistryType::PyPI, up.url()),
        )
        .await
        {
            Ok(html) => html,
            Err(crate::registry::ProxyError::CircuitOpen(_)) => {
                circuit_open = true;
                continue;
            }
            Err(e) => {
                tracing::debug!(error = ?e, package = %normalized, upstream = %up.url(), "PyPI page proxy fetch failed, trying next upstream");
                miss.record(&e);
                continue;
            }
        };

        // The file may live on a later upstream — keep walking the list.
        let Some(indexed) = find_file_url(&html, &filename, &page_url) else {
            miss.answered();
            continue;
        };
        let file_url = indexed.url;

        // The upstream's credential goes to the upstream's own origin only: an index may name its
        // files on another host, which must not receive it (pip scopes a credential the same way).
        let file_auth = if same_origin(&file_url, up.url()) {
            up.auth().map(UpstreamAuth::Basic)
        } else {
            None
        };
        match proxy_fetch(
            &state.http_client,
            &file_url,
            Duration::from_secs(state.config.pypi.proxy_timeout),
            file_auth,
            &state.circuit_breaker,
            BreakerScope::upstream(RegistryType::PyPI, up.url()),
        )
        .await
        {
            Ok(data) => {
                // The bytes are the file the index named only when they have the digest it
                // gave: pip checks the same digest, and a cached file would be listed with
                // NORA's own instead, so wrong bytes are refused before anything is stored.
                let hash = hex::encode(sha2::Sha256::digest(&data));
                if indexed.sha256.as_ref().is_some_and(|want| *want != hash) {
                    tracing::warn!(
                        package = %normalized,
                        filename = %filename,
                        upstream = %up.url(),
                        "PyPI upstream file does not match the index sha256, refusing it"
                    );
                    return (
                        StatusCode::BAD_GATEWAY,
                        "upstream file does not match the sha256 its index gives",
                    )
                        .into_response();
                }
                // The allowlist's pinned integrity holds on the first download too, before anything
                // is cached: the cache-hit branch checks the same rule.
                if let Some(response) = crate::curation::verify_integrity(
                    &state.curation().curation_engine,
                    crate::curation::RegistryType::PyPI,
                    &normalized,
                    version.as_deref(),
                    &data,
                ) {
                    return response;
                }
                state.metrics.record_download("pypi");
                state.metrics.record_cache_miss("pypi");
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{}/{}", name, filename),
                    crate::registry_type::RegistryType::PyPI,
                    "PROXY",
                ));
                state
                    .audit
                    .log(AuditEntry::new("proxy_fetch", "proxy", "", "pypi", ""));

                // Cache in background + compute hash, invalidate AFTER write
                let storage = state.storage.clone();
                let key_clone = key.clone();
                let data_clone = data.clone();
                let project = normalized.clone();
                let file_name = filename.clone();
                let repo_index = Arc::clone(&state.repo_index);
                tokio::spawn(async move {
                    if storage.put(&key_clone, &data_clone).await.is_ok() {
                        let _ = storage
                            .put(&format!("{}.sha256", key_clone), hash.as_bytes())
                            .await;
                        put_hash_marker(&storage, &project, &file_name, &hash).await;
                        repo_index.invalidate("pypi");
                    }
                });

                if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                    &state.digest_store,
                    "pypi",
                    &data,
                    &q_mode,
                    q_secs,
                    &file_url,
                    crate::digest_quarantine::first_seen_seed(
                        state.config.server.trust_upstream_dates,
                        publish_date,
                    ),
                ) {
                    return resp;
                }

                let content_type = pypi_content_type(&filename);
                return (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], data)
                    .into_response();
            }
            Err(crate::registry::ProxyError::CircuitOpen(_)) => {
                circuit_open = true;
                continue;
            }
            Err(e) => {
                tracing::debug!(error = ?e, package = %normalized, filename = %filename, upstream = %up.url(), "PyPI file proxy fetch failed, trying next upstream");
                miss.record(&e);
                continue;
            }
        }
    }

    // A tripped breaker means an upstream is temporarily down — 503 (retryable)
    // rather than 404, which would poison pip's negative cache; a failed upstream is
    // 502 for the same reason.
    if circuit_open {
        return circuit_open_response(RegistryType::PyPI.as_str());
    }

    miss.response("pypi", &format!("{normalized}/{filename}"))
}

// ============================================================================
// Twine upload (PEP 503 — POST /simple/)
// ============================================================================

/// POST /simple/ — upload a package via twine.
///
/// twine sends multipart/form-data with fields:
///   :action = "file_upload"
///   name = package name
///   version = package version
///   filetype = "sdist" | "bdist_wheel"
///   content = the file bytes
///   sha256_digest = hex SHA-256 of file (optional)
///   metadata_version, summary, etc. (optional metadata)
async fn upload(
    State(state): State<AppState>,
    Extension(authority): Extension<NamespaceAuthority>,
    user: Option<Extension<crate::auth::AuthenticatedUser>>,
    mut multipart: Multipart,
) -> Response {
    let mut action = String::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut filename = String::new();
    let mut file_data: Option<Vec<u8>> = None;
    let mut sha256_digest = String::new();

    // Parse multipart fields
    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            ":action" => {
                action = field.text().await.ok().unwrap_or_default();
            }
            "name" => {
                name = field.text().await.ok().unwrap_or_default();
            }
            "version" => {
                version = field.text().await.ok().unwrap_or_default();
            }
            "sha256_digest" => {
                sha256_digest = field.text().await.ok().unwrap_or_default();
            }
            "content" => {
                filename = field.file_name().unwrap_or("unknown").to_string();
                match field.bytes().await {
                    Ok(b) => file_data = Some(b.to_vec()),
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            format!("Failed to read file: {}", e),
                        )
                            .into_response()
                    }
                }
            }
            _ => {
                // Skip other metadata fields (summary, author, etc.)
                let _ = field.bytes().await;
            }
        }
    }

    // Validate required fields
    if action != "file_upload" {
        return (StatusCode::BAD_REQUEST, "Unsupported action").into_response();
    }

    if name.is_empty() || version.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing name or version").into_response();
    }

    let data = match file_data {
        Some(d) if !d.is_empty() => d,
        _ => return (StatusCode::BAD_REQUEST, "Missing file content").into_response(),
    };

    // Validate filename
    if filename.is_empty() || !is_valid_pypi_filename(&filename) {
        return (StatusCode::BAD_REQUEST, "Invalid filename").into_response();
    }

    // Verify SHA-256 if provided
    let computed_hash = hex::encode(sha2::Sha256::digest(&data));
    if !sha256_digest.is_empty() && sha256_digest != computed_hash {
        tracing::warn!(
            package = %name,
            expected = %sha256_digest,
            computed = %computed_hash,
            "SECURITY: PyPI upload SHA-256 mismatch"
        );
        return (StatusCode::BAD_REQUEST, "SHA-256 digest mismatch").into_response();
    }

    // Normalize name and store
    let normalized = normalize_name(&name);

    // Enforce OIDC namespace_scope on the project coordinate (#583).
    if enforce_namespace_scope(&authority, &normalized).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }

    // TOCTOU protection: lock per file to prevent concurrent uploads
    let file_key = storage_key(&normalized, &filename);
    let lock = state.publish_lock(&file_key);
    let _guard = lock.lock().await;

    // Check immutability (same filename = already exists). In a hosted project a file NORA holds
    // without a record is not one of its files — an upstream served it before the import — and
    // the upload replaces it.
    if state.storage.stat(&file_key).await.is_some() {
        let replaceable = match hosted_state(&state.storage, &normalized).await {
            Hosted::Yes(own) => !own.contains(&filename),
            Hosted::No => false,
            Hosted::Unknown => {
                return crate::registry::storage_unavailable("pypi", &own_prefix(&normalized))
            }
        };
        if !replaceable {
            return (
                StatusCode::CONFLICT,
                format!("File {} already exists", filename),
            )
                .into_response();
        }
    }

    // The record first: in a hosted project a file is listed only once it is recorded.
    if let Err(e) = record_own_file(&state.storage, &normalized, &filename).await {
        tracing::warn!(key = %file_key, error = %e, "pypi: failed to record an uploaded file");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Store file
    if state.storage.put(&file_key, &data).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Store SHA-256 hash
    let hash_key = format!("{}.sha256", file_key);
    if let Err(e) = state.storage.put(&hash_key, computed_hash.as_bytes()).await {
        tracing::warn!(key = %hash_key, error = %e, "pypi: failed to store hash sidecar");
    }

    // Hash marker: the simple index reads every digest from one listing.
    put_hash_marker(&state.storage, &normalized, &filename, &computed_hash).await;

    state.metrics.record_upload("pypi");
    let artifact = format!("{}-{}", name, version);
    state.audit.log(AuditEntry::new(
        "push",
        crate::auth::audit_actor(&user),
        &artifact,
        "pypi",
        "",
    ));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        artifact,
        crate::registry_type::RegistryType::PyPI,
        "LOCAL",
    ));
    state.repo_index.invalidate("pypi");

    StatusCode::OK.into_response()
}

// ============================================================================
// PEP 691 JSON responses — typed structs per spec
// ============================================================================

struct FileEntry {
    filename: String,
    sha256: Option<String>,
}

/// PEP 691 top-level response — typed to prevent field-name drift.
#[derive(serde::Serialize)]
struct Pep691Response<'a> {
    meta: Pep691Meta,
    name: &'a str,
    /// PEP 700: sorted, de-duplicated release versions present in `files`.
    versions: Vec<String>,
    files: Vec<Pep691File>,
}

#[derive(serde::Serialize)]
struct Pep691Meta {
    #[serde(rename = "api-version")]
    api_version: &'static str,
}

/// PEP 691 file entry — field `hashes` (NOT `digests`) per spec.
/// `upload-time` and `size` are PEP 700 (api-version 1.1) additions.
#[derive(serde::Serialize)]
struct Pep691File {
    filename: String,
    url: String,
    /// Required by PEP 691 even when no digest is known — then it is `{}` (#1100).
    hashes: Pep691Hashes,
    /// PEP 700 upload-time (RFC3339), when known (from the cached dates.json).
    #[serde(rename = "upload-time", skip_serializing_if = "Option::is_none")]
    upload_time: Option<String>,
    /// PEP 700 file size in bytes, when the artifact is stored locally.
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
}

#[derive(serde::Serialize)]
struct Pep691Hashes {
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
}

/// Render the PEP 691 + PEP 700 simple JSON. `pep700` maps filename → (size,
/// upload-time), gathered by [`collect_pep700_meta`] from storage + the cached
/// dates.json; a missing entry omits those (optional) per-file fields. Pure/sync so
/// it stays unit-testable without a storage backend.
fn versions_json_response(
    normalized: &str,
    files: &[FileEntry],
    base_url: &str,
    pep700: &std::collections::HashMap<String, (Option<u64>, Option<String>)>,
) -> Response {
    let base = base_url.trim_end_matches('/');
    let pep691_files: Vec<Pep691File> = files
        .iter()
        .map(|f| {
            let (size, upload_time) = pep700.get(&f.filename).cloned().unwrap_or((None, None));
            Pep691File {
                filename: f.filename.clone(),
                url: format!("{}/simple/{}/{}", base, normalized, f.filename),
                hashes: Pep691Hashes {
                    sha256: f.sha256.clone(),
                },
                upload_time,
                size,
            }
        })
        .collect();

    let body = Pep691Response {
        // PEP 700 support is signalled by api-version 1.1.
        meta: Pep691Meta { api_version: "1.1" },
        name: normalized,
        versions: versions_from_filenames(files),
        files: pep691_files,
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, PEP691_JSON)],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response()
}

/// PEP 700 project `versions`: sorted, de-duplicated release versions parsed from
/// the wheel/sdist filenames in the file list (best-effort).
fn versions_from_filenames(files: &[FileEntry]) -> Vec<String> {
    let mut vs: Vec<String> = files
        .iter()
        .filter_map(|f| version_from_filename(&f.filename))
        .collect();
    vs.sort();
    vs.dedup();
    vs
}

/// Extract the release version from a wheel or sdist filename (best-effort).
/// wheel: `{distribution}-{version}(-{build})?-{py}-{abi}-{platform}.whl`
/// sdist: `{name}-{version}.tar.gz|.tar.bz2|.tar.xz|.tgz|.zip`
fn version_from_filename(filename: &str) -> Option<String> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        return stem
            .split('-')
            .nth(1)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
    }
    for ext in [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip"] {
        if let Some(stem) = filename.strip_suffix(ext) {
            return stem
                .rsplit_once('-')
                .map(|(_, v)| v.to_string())
                .filter(|s| !s.is_empty());
        }
    }
    None
}

/// Gather PEP 700 per-file metadata keyed by filename: `size` from the local
/// listing (`local_sizes`, built from `list_with_meta`) and `upload-time` from the
/// already-loaded `dates.json` map.
///
/// #969: this used to `stat()` every merged file — one HEAD per file on S3, issued
/// serially, so `/simple/{name}/` cost N round-trips against a proxied index of N
/// upstream files and uv timed out. Both inputs are now gathered by the single
/// listing and the single dates read the handler already performs, making this pure
/// and O(N) in memory only. Upstream-only files have no local size (a `stat()` would
/// have 404'd on them anyway), so both fields stay `None` and are omitted.
fn pep700_meta(
    files: &[FileEntry],
    local_sizes: &std::collections::HashMap<String, u64>,
    dates: &serde_json::Map<String, serde_json::Value>,
) -> std::collections::HashMap<String, (Option<u64>, Option<String>)> {
    let mut out = std::collections::HashMap::with_capacity(files.len());
    for f in files {
        let size = local_sizes.get(&f.filename).copied();
        let upload_time = dates
            .get(&f.filename)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        out.insert(f.filename.clone(), (size, upload_time));
    }
    out
}

fn versions_html_response(normalized: &str, files: &[FileEntry], base_url: &str) -> Response {
    let base = base_url.trim_end_matches('/');
    let escaped = html_escape(normalized);
    let mut html = format!(
        "<!DOCTYPE html>\n<html><head><title>Links for {}</title></head><body><h1>Links for {}</h1>\n",
        escaped, escaped
    );

    for f in files {
        let hash_fragment = f
            .sha256
            .as_ref()
            .map(|h| format!("#sha256={}", h))
            .unwrap_or_default();
        let _ = writeln!(
            html,
            "<a href=\"{}/simple/{}/{}{}\">{}</a><br>",
            base,
            normalized,
            html_escape(&f.filename),
            hash_fragment,
            html_escape(&f.filename)
        );
    }
    html.push_str("</body></html>");

    (StatusCode::OK, Html(html)).into_response()
}

// ============================================================================
// Helpers
// ============================================================================

/// A file's release date from the cached `dates.json` listing, which is cached by whichever
/// request reaches the package first — the PEP 691 index (#896) or a download — so a client
/// that only reads the PEP 503 HTML index gets the date a JSON client gets.
///
/// Trusted dates: the file's upstream `upload-time`. Untrusted (#513): the time NORA cached
/// the listing — never the (spoofable) upstream upload-time — and only for a file the listing
/// names. A file released after it was not seen by NORA at that time, so it gets no date
/// rather than an older one; min-release-age then defers to the quarantine, which records
/// it as first seen now.
///
/// With untrusted dates a missing listing is fetched on a cold miss only: that request goes
/// upstream anyway, while a cache hit (a hosted package above all) must not start asking an
/// upstream on every download.
async fn pypi_publish_date(
    state: &AppState,
    normalized: &str,
    filename: &str,
    artifact_key: &str,
) -> Option<i64> {
    let trust = state.config.server.trust_upstream_dates;
    let dates_key = format!("pypi/{}/dates.json", normalized);
    let dates = match state.storage.get(&dates_key).await {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
        Err(_) if trust => ensure_pypi_dates_cached(state, normalized).await,
        // Without trusted dates the listing is asked for only when a release-age rule reads
        // the date: otherwise nothing uses it, and the download asks the upstream nothing more.
        Err(_)
            if crate::registry::release_date_read(state, RegistryType::PyPI)
                && state.storage.stat(artifact_key).await.is_none() =>
        {
            ensure_pypi_dates_cached(state, normalized).await
        }
        Err(_) => return None,
    };
    let entry = dates.get(filename)?;
    if trust {
        crate::curation::parse_iso8601_to_unix(entry.as_str()?)
    } else {
        crate::curation::extract_mtime_as_publish_date(&state.storage, &dates_key).await
    }
}

/// Cache a `filename → upload-time` map (`pypi/{name}/dates.json`) from the
/// upstream PEP 691 simple JSON (PEP 700 `upload-time`, null for a file listed without
/// one) and return it. No-op if already cached. Best-effort: any failure leaves no
/// dates and the quarantine clock falls back to NORA's own time. The PEP 503 HTML
/// index NORA fetches for the file *listing* carries no dates, hence this JSON fetch.
///
/// #969: an upstream that answers but emits no `upload-time` (any pre-PEP-700 index —
/// devpi, Artifactory, an older NORA) used to leave nothing cached, so every single
/// `/simple/{name}/` JSON request re-downloaded the whole upstream JSON index. An
/// answered-but-dateless upstream is now recorded once, its files with null dates,
/// and the refetch stops. A failed/open-breaker fetch still caches nothing, so a
/// transient outage stays retryable.
async fn ensure_pypi_dates_cached(
    state: &AppState,
    normalized: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let key = format!("pypi/{}/dates.json", normalized);
    if let Ok(data) = state.storage.get(&key).await {
        return serde_json::from_slice(&data).unwrap_or_default();
    }
    // #68: never fetch an internal-namespace package's metadata upstream, nor a hosted
    // project's — nor one whose hosted state the store cannot tell.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::PyPI,
        normalized,
    ) || !matches!(hosted_state(&state.storage, normalized).await, Hosted::No)
    {
        return serde_json::Map::new();
    }
    let mut map = serde_json::Map::new();
    let mut upstream_answered = false;
    for up in &state.config.pypi.upstreams() {
        let url = format!("{}/{}/", up.url().trim_end_matches('/'), normalized);
        let Ok(text) = proxy_fetch_text(
            &state.http_client,
            &url,
            Duration::from_secs(state.config.pypi.proxy_timeout),
            up.auth().map(UpstreamAuth::Basic),
            Some(("Accept", PEP691_JSON)),
            &state.circuit_breaker,
            BreakerScope::upstream(RegistryType::PyPI, up.url()),
        )
        .await
        else {
            continue;
        };
        upstream_answered = true;
        // Every listed file gets an entry — null when the upstream gives no `upload-time` —
        // because the entry is what dates the file when upstream dates are untrusted. An
        // upstream without PEP 691 answers with its HTML index, which still lists the files.
        let listed: Vec<(String, Option<String>)> =
            match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(json) => json
                    .get("files")
                    .and_then(|f| f.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|fe| {
                        let fname = fe.get("filename")?.as_str()?;
                        let ut = fe.get("upload-time").and_then(|v| v.as_str());
                        Some((fname.to_string(), ut.map(str::to_string)))
                    })
                    .collect(),
                Err(_) => parse_upstream_files(&text)
                    .into_iter()
                    .map(|f| (f.filename, None))
                    .collect(),
            };
        for (fname, ut) in listed {
            let entry = map.entry(fname).or_insert(serde_json::Value::Null);
            if let (true, Some(ut)) = (entry.is_null(), ut) {
                *entry = serde_json::Value::String(ut);
            }
        }
        if map.values().any(serde_json::Value::is_string) {
            break; // first upstream that listed dated files wins
        }
    }
    // A map without dates is still worth persisting once an upstream has actually
    // answered: it spares every later request the full upstream JSON download (#969).
    if !map.is_empty() || upstream_answered {
        // Serialize from a reference — the map is returned to the caller and can hold
        // tens of thousands of entries for a large project, so do not clone it.
        if let Ok(bytes) = serde_json::to_vec(&map) {
            let _ = state.storage.put(&key, &bytes).await;
        }
    }
    map
}

/// Normalize package name according to PEP 503 — the one normalization curation also uses
/// (`curation::pep503_normalize`): lowercase, every run of `-`, `_` and `.` one `-`.
fn normalize_name(name: &str) -> String {
    crate::curation::pep503_normalize(name)
}

/// The key of distribution file `filename` of project `normalized` (PEP 503): the one an upload
/// writes and a download reads. `nora import` writes the same key (contract
/// `import-key-format-equals-handler-key-format`).
pub(crate) fn storage_key(normalized: &str, filename: &str) -> String {
    format!("pypi/{normalized}/{filename}")
}

/// Storage prefix of what NORA records of the projects it owns: `pypi-own/<project>/`.
///
/// - `pypi-own/<project>/files/<filename>` — a file of the project that is NORA's own: an upload
///   or an import writes it with the file.
/// - `pypi-own/<project>/imported` — the project is hosted: `nora import` writes it when it
///   brings in a file of the project from the operator's own registry. From then on neither the
///   project's index, its dates nor a file of it is asked of an upstream, and only its own files
///   are listed and served: a file an upstream served under the name before the import is not.
///
/// One listing of the prefix answers both. The records live outside `pypi/`, so the listings of
/// `pypi/` that retention, the web UI and the simple index read never take one for a
/// distribution file.
pub(crate) const OWN_PREFIX: &str = "pypi-own/";

/// The prefix of project `normalized`'s records.
fn own_prefix(normalized: &str) -> String {
    format!("{OWN_PREFIX}{normalized}/")
}

/// The record that file `filename` of project `normalized` is NORA's own.
pub(crate) fn own_file_key(normalized: &str, filename: &str) -> String {
    format!("{OWN_PREFIX}{normalized}/files/{filename}")
}

/// Whether a project is hosted, from a listing of its records.
enum Hosted {
    /// Hosted: these are its own files.
    Yes(std::collections::HashSet<String>),
    No,
    /// The listing failed: nothing is decided on a guess.
    Unknown,
}

async fn hosted_state(storage: &crate::storage::Storage, normalized: &str) -> Hosted {
    let prefix = own_prefix(normalized);
    if crate::validation::validate_storage_key(crate::validation::listing_key(&prefix)).is_err() {
        return Hosted::No;
    }
    let records = match storage.list(&prefix).await {
        Ok(records) => records,
        Err(e) => {
            tracing::warn!(registry = "pypi", project = %normalized, error = %e, "pypi: own records not listed");
            return Hosted::Unknown;
        }
    };
    if !records
        .iter()
        .any(|k| k.strip_prefix(&prefix) == Some("imported"))
    {
        return Hosted::No;
    }
    let files = format!("{prefix}files/");
    Hosted::Yes(
        records
            .iter()
            .filter_map(|k| k.strip_prefix(&files))
            .map(str::to_string)
            .collect(),
    )
}

/// Make project `normalized` hosted. Written before the first file of it is stored, so from the
/// moment an import stores anything of the project its name is no longer asked of an upstream.
pub(crate) async fn claim_imported_project(
    storage: &crate::storage::Storage,
    normalized: &str,
) -> crate::storage::Result<()> {
    storage
        .put(&format!("{}imported", own_prefix(normalized)), b"")
        .await
}

/// Record file `filename` of project `normalized` as NORA's own. Written before the file is
/// stored: a hosted project lists a file only once it is recorded, and a record of a file that
/// is not there lists nothing.
pub(crate) async fn record_own_file(
    storage: &crate::storage::Storage,
    normalized: &str,
    filename: &str,
) -> crate::storage::Result<()> {
    storage.put(&own_file_key(normalized, filename), b"").await
}

/// Record the SHA-256 of a distribution file stored at `storage_key(project, filename)`, as an
/// upload records it: the `.sha256` sidecar the index serves the digest from, then the hash
/// marker. A failed sidecar write is returned; a failed marker write is logged, and the index
/// serves the digest from the sidecar.
pub(crate) async fn record_stored_file(
    storage: &crate::storage::Storage,
    normalized: &str,
    filename: &str,
    sha256: &str,
) -> crate::storage::Result<()> {
    let file_key = storage_key(normalized, filename);
    storage
        .put(&format!("{file_key}.sha256"), sha256.as_bytes())
        .await?;
    put_hash_marker(storage, normalized, filename, sha256).await;
    Ok(())
}

/// Check Accept header for PEP 691 JSON.
fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains(PEP691_JSON))
        .unwrap_or(false)
}

/// Content-type for PyPI files.
fn pypi_content_type(filename: &str) -> &'static str {
    if ends_with_ci(filename, ".whl") {
        "application/zip"
    } else if ends_with_ci(filename, ".tar.gz") || ends_with_ci(filename, ".tgz") {
        "application/gzip"
    } else {
        "application/octet-stream"
    }
}

/// Storage prefix of the per-file SHA-256 markers: `pypi-sha256/<project>/<filename>/<sha256>`.
///
/// A marker is an empty object whose key carries the digest of one stored distribution
/// file, so one listing of `pypi-sha256/<project>/` yields every digest the simple index
/// needs instead of one sidecar read per file (a request per file on an object store).
/// Markers live outside `pypi/`, so listings of `pypi/` never take one for a distribution
/// file. The `.sha256` sidecar stays authoritative: a file without exactly one marker is
/// served from its sidecar.
pub(crate) const HASH_MARKER_PREFIX: &str = "pypi-sha256/";

/// Key of the marker recording `sha256` for `filename` of `project`.
fn hash_marker_key(project: &str, filename: &str, sha256: &str) -> String {
    format!("{HASH_MARKER_PREFIX}{project}/{filename}/{sha256}")
}

/// `(filename, sha256)` of a marker key under `project_prefix` (`pypi-sha256/<project>/`),
/// or `None` for a key that is not a well-formed marker.
fn parse_hash_marker<'a>(project_prefix: &str, key: &'a str) -> Option<(&'a str, &'a str)> {
    let (filename, sha256) = key.strip_prefix(project_prefix)?.split_once('/')?;
    (!filename.is_empty() && is_sha256_hex(sha256)).then_some((filename, sha256))
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Record `sha256` as the one hash marker of `filename`: delete markers left for it with
/// another digest (the file was deleted and stored again with other bytes), then write its
/// own. A failed step is logged; the index serves a file with no marker, or with more than
/// one, from its sidecar.
async fn put_hash_marker(
    storage: &crate::storage::Storage,
    project: &str,
    filename: &str,
    sha256: &str,
) {
    let marker = hash_marker_key(project, filename, sha256);
    let file_prefix = format!("{HASH_MARKER_PREFIX}{project}/{filename}/");
    match storage.list(&file_prefix).await {
        Ok(existing) => {
            for stale in existing.iter().filter(|key| **key != marker) {
                if let Err(e) = storage.delete(stale).await {
                    tracing::warn!(key = %stale, error = %e, "pypi: failed to delete stale hash marker");
                }
            }
        }
        Err(e) => {
            tracing::warn!(prefix = %file_prefix, error = %e, "pypi: failed to list hash markers");
        }
    }
    if let Err(e) = storage.put(&marker, b"").await {
        tracing::warn!(key = %marker, error = %e, "pypi: failed to store hash marker");
    }
}

/// Write the hash marker of a stored file from its `.sha256` sidecar.
///
/// The sidecar is read under the file's publish lock, which upload and retention take to
/// store or delete the file, so the digest cannot belong to an earlier file of the same
/// name that was deleted and uploaded again after the index request that queued it.
async fn backfill_hash_marker(
    storage: &crate::storage::Storage,
    publish_locks: &crate::PublishLocks,
    project: &str,
    filename: &str,
) {
    let file_key = format!("pypi/{project}/{filename}");
    let lock = crate::acquire_publish_lock(publish_locks, &file_key);
    let _guard = lock.lock().await;
    if storage.stat(&file_key).await.is_none() {
        return;
    }
    let Ok(data) = storage.get(&format!("{file_key}.sha256")).await else {
        return;
    };
    let text = String::from_utf8_lossy(&data);
    let sha256 = text.trim();
    if is_sha256_hex(sha256) {
        put_hash_marker(storage, project, filename, sha256).await;
    }
}

/// Validate PyPI filename.
fn is_valid_pypi_filename(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && nora_registry::pypi_files::served_extension(name).is_some()
}

/// Extract filename from PyPI download URL.
fn extract_filename(url: &str) -> Option<&str> {
    let url = url.split('#').next()?;
    let filename = url.rsplit('/').next()?;

    nora_registry::pypi_files::served_extension(filename).map(|_| filename)
}

/// Parse upstream PyPI simple index HTML into file entries.
///
/// Extracts filenames and optional `#sha256=` fragments from `<a href="...">` links.
fn parse_upstream_files(html: &str) -> Vec<FileEntry> {
    let mut files = Vec::new();
    let mut remaining = html;

    while let Some(href_start) = remaining.find("href=\"") {
        remaining = &remaining[href_start + 6..];
        if let Some(href_end) = remaining.find('"') {
            let url = &remaining[..href_end];
            if let Some(filename) = extract_filename(url) {
                let sha256 = url.find("#sha256=").map(|pos| url[pos + 8..].to_string());
                files.push(FileEntry {
                    filename: filename.to_string(),
                    sha256,
                });
            }
            remaining = &remaining[href_end..];
        }
    }
    files
}

/// Merge upstream and local file lists.
///
/// Local entries take precedence (they have verified hashes from storage).
/// Upstream entries are added only if no local file with the same name exists.
fn merge_file_lists(upstream: Vec<FileEntry>, local: &[FileEntry]) -> Vec<FileEntry> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut result = Vec::with_capacity(upstream.len() + local.len());

    // Local first (highest precedence). Dedup local against itself too: storage
    // listings are unique by construction, but keep the merge total so the output
    // never carries a duplicate filename regardless of caller input.
    for f in local {
        if seen.insert(f.filename.clone()) {
            result.push(FileEntry {
                filename: f.filename.clone(),
                sha256: f.sha256.clone(),
            });
        }
    }

    // `upstream` is concatenated across upstreams in precedence order; keep the
    // first entry seen for each filename so the highest-precedence upstream wins
    // and a file present on several upstreams (or already local) is not listed
    // twice (#663).
    for f in upstream {
        if seen.insert(f.filename.clone()) {
            result.push(f);
        }
    }

    result
}

/// Find the download URL for a specific file in the HTML.
///
/// `page_url` is the simple-index page URL used to resolve relative hrefs
/// returned by some mirrors (Tsinghua, USTC, Aliyun) (#877).
/// True when both URLs have the same scheme, host and port.
fn same_origin(a: &str, b: &str) -> bool {
    match (reqwest::Url::parse(a), reqwest::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            a.scheme() == b.scheme()
                && a.host_str() == b.host_str()
                && a.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

/// A file the upstream index names: where to fetch it, and the sha256 its href carries
/// (`#sha256=<hex>`, PEP 503) — the digest pip checks the bytes against.
#[derive(Debug, PartialEq)]
struct IndexedFile {
    url: String,
    sha256: Option<String>,
}

fn find_file_url(html: &str, target_filename: &str, page_url: &str) -> Option<IndexedFile> {
    let mut remaining = html;

    while let Some(href_start) = remaining.find("href=\"") {
        remaining = &remaining[href_start + 6..];

        if let Some(href_end) = remaining.find('"') {
            let url = &remaining[..href_end];

            if let Some(filename) = extract_filename(url) {
                // Index hrefs percent-encode characters such as '+' (PyTorch's
                // "+cu124" -> "%2Bcu124"); the requested filename arrives already
                // decoded, so compare decoded forms. The URL itself is returned
                // unchanged — it must stay encoded to fetch from the upstream (#664).
                let decoded = percent_encoding::percent_decode_str(filename).decode_utf8_lossy();
                if decoded.as_ref() == target_filename {
                    let (raw, fragment) = url.split_once('#').unwrap_or((url, ""));
                    let sha256 = fragment
                        .strip_prefix("sha256=")
                        .map(|digest| digest.to_ascii_lowercase());
                    // Resolve relative URLs against the page URL (#877).
                    let url = if raw.starts_with("http://") || raw.starts_with("https://") {
                        raw.to_string()
                    } else {
                        reqwest::Url::parse(page_url)
                            .ok()
                            .and_then(|base| base.join(raw).ok())
                            .map_or_else(|| raw.to_string(), |u| u.to_string())
                    };
                    return Some(IndexedFile { url, sha256 });
                }
            }

            remaining = &remaining[href_end..];
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
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn extract_filename_never_panics(s in "\\PC{0,500}") {
            let _ = extract_filename(&s);
        }

        #[test]
        fn extract_filename_valid_tarball(
            name in "[a-z][a-z0-9_-]{0,20}",
            version in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
        ) {
            let url = format!("https://files.example.com/packages/{}-{}.tar.gz", name, version);
            let result = extract_filename(&url);
            prop_assert!(result.is_some());
            prop_assert!(result.unwrap().ends_with(".tar.gz"));
        }

        #[test]
        fn extract_filename_valid_wheel(
            name in "[a-z][a-z0-9_]{0,20}",
            version in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
        ) {
            let url = format!("https://files.example.com/{}-{}-py3-none-any.whl", name, version);
            let result = extract_filename(&url);
            prop_assert!(result.is_some());
            prop_assert!(result.unwrap().ends_with(".whl"));
        }

        #[test]
        fn extract_filename_strips_hash(
            name in "[a-z]{1,10}",
            hash in "[a-f0-9]{64}"
        ) {
            let url = format!("https://example.com/{}.tar.gz#sha256={}", name, hash);
            let result = extract_filename(&url);
            prop_assert!(result.is_some());
            let fname = result.unwrap();
            prop_assert!(!fname.contains('#'));
        }

        #[test]
        fn extract_filename_rejects_unknown_ext(
            name in "[a-z]{1,10}",
            ext in "(exe|dll|so|bin|dat)"
        ) {
            let url = format!("https://example.com/{}.{}", name, ext);
            prop_assert!(extract_filename(&url).is_none());
        }
    }

    #[test]
    fn test_normalize_name_lowercase() {
        assert_eq!(normalize_name("Flask"), "flask");
        assert_eq!(normalize_name("REQUESTS"), "requests");
    }

    #[test]
    fn same_origin_compares_scheme_host_and_port() {
        assert!(super::same_origin(
            "https://pypi.corp/files/a.whl",
            "https://pypi.corp/simple/"
        ));
        assert!(super::same_origin(
            "https://pypi.corp:443/x",
            "https://pypi.corp/"
        ));
        assert!(!super::same_origin(
            "https://files.example/x",
            "https://pypi.corp/"
        ));
        // A host is compared whole: a name ending in the upstream's, or extending it, is another.
        assert!(!super::same_origin(
            "https://evilpypi.corp/x",
            "https://pypi.corp/"
        ));
        assert!(!super::same_origin(
            "https://pypi.corp.evil/x",
            "https://pypi.corp/"
        ));
        assert!(!super::same_origin("https://a.corp/x", "https://b.corp/"));
        assert!(!super::same_origin(
            "https://cdn.pypi.corp/x",
            "https://pypi.corp/"
        ));
        assert!(!super::same_origin(
            "https://pypi.corp/x",
            "https://cdn.pypi.corp/"
        ));
        assert!(!super::same_origin(
            "http://pypi.corp/x",
            "https://pypi.corp/"
        ));
        assert!(!super::same_origin(
            "https://pypi.corp:8443/x",
            "https://pypi.corp/"
        ));
        assert!(!super::same_origin(
            "https://pypi.corp.evil/x",
            "https://pypi.corp/"
        ));
        assert!(!super::same_origin("not a url", "https://pypi.corp/"));
    }

    #[test]
    fn find_file_url_matches_percent_encoded_plus() {
        // #664: PyTorch indexes encode '+' as %2B in hrefs, but the requested
        // filename arrives decoded — matching must decode, and the returned URL
        // must stay encoded so the upstream fetch resolves.
        let html = concat!(
            r#"<a href="https://download.pytorch.org/whl/cu124/"#,
            r#"torch-2.4.0%2Bcu124-cp310-cp310-linux_x86_64.whl#sha256=abc">"#,
            r#"torch-2.4.0+cu124-cp310-cp310-linux_x86_64.whl</a>"#,
        );
        assert_eq!(
            find_file_url(html, "torch-2.4.0+cu124-cp310-cp310-linux_x86_64.whl", "https://pypi.org/simple/torch/").map(|f| f.url).as_deref(),
            Some(
                "https://download.pytorch.org/whl/cu124/torch-2.4.0%2Bcu124-cp310-cp310-linux_x86_64.whl"
            )
        );
        // A plain filename (no encoding) still matches.
        let plain = r#"<a href="https://x/torch-0.1.10-cp36-cp36m-macosx.whl">x</a>"#;
        assert_eq!(
            find_file_url(
                plain,
                "torch-0.1.10-cp36-cp36m-macosx.whl",
                "https://pypi.org/simple/torch/"
            )
            .map(|f| f.url)
            .as_deref(),
            Some("https://x/torch-0.1.10-cp36-cp36m-macosx.whl")
        );
    }

    #[test]
    fn test_normalize_name_separators() {
        assert_eq!(normalize_name("my-package"), "my-package");
        assert_eq!(normalize_name("my_package"), "my-package");
        assert_eq!(normalize_name("my.package"), "my-package");
    }

    #[test]
    fn test_normalize_name_mixed() {
        assert_eq!(
            normalize_name("My_Complex.Package-Name"),
            "my-complex-package-name"
        );
    }

    #[test]
    fn test_normalize_name_empty() {
        assert_eq!(normalize_name(""), "");
    }

    #[test]
    fn test_normalize_name_already_normal() {
        assert_eq!(normalize_name("simple"), "simple");
    }

    #[test]
    fn test_extract_filename_tarball() {
        assert_eq!(
            extract_filename(
                "https://files.pythonhosted.org/packages/aa/bb/flask-2.0.0.tar.gz#sha256=abc123"
            ),
            Some("flask-2.0.0.tar.gz")
        );
    }

    #[test]
    fn test_extract_filename_wheel() {
        assert_eq!(
            extract_filename(
                "https://files.pythonhosted.org/packages/aa/bb/flask-2.0.0-py3-none-any.whl"
            ),
            Some("flask-2.0.0-py3-none-any.whl")
        );
    }

    #[test]
    fn test_extract_filename_tgz() {
        assert_eq!(
            extract_filename("https://example.com/package-1.0.tgz"),
            Some("package-1.0.tgz")
        );
    }

    #[test]
    fn test_extract_filename_zip() {
        assert_eq!(
            extract_filename("https://example.com/package-1.0.zip"),
            Some("package-1.0.zip")
        );
    }

    #[test]
    fn test_extract_filename_egg() {
        assert_eq!(
            extract_filename("https://example.com/package-1.0.egg"),
            Some("package-1.0.egg")
        );
    }

    #[test]
    fn test_extract_filename_unknown_ext() {
        assert_eq!(extract_filename("https://example.com/readme.txt"), None);
    }

    #[test]
    fn test_extract_filename_no_path() {
        assert_eq!(extract_filename(""), None);
    }

    #[test]
    fn test_extract_filename_bare() {
        assert_eq!(
            extract_filename("package-1.0.tar.gz"),
            Some("package-1.0.tar.gz")
        );
    }

    #[test]
    fn test_find_file_url_found() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/aa/bb/flask-2.0.tar.gz#sha256=abc">flask-2.0.tar.gz</a>"#;
        let result = find_file_url(html, "flask-2.0.tar.gz", "https://pypi.org/simple/flask/")
            .map(|f| f.url);
        assert_eq!(
            result,
            Some("https://files.pythonhosted.org/packages/aa/bb/flask-2.0.tar.gz".to_string())
        );
    }

    #[test]
    fn test_find_file_url_not_found() {
        let html = r#"<a href="https://example.com/other-1.0.tar.gz">other</a>"#;
        let result = find_file_url(html, "flask-2.0.tar.gz", "https://pypi.org/simple/flask/")
            .map(|f| f.url);
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_file_url_strips_hash() {
        let html = r#"<a href="https://example.com/pkg-1.0.whl#sha256=deadbeef">pkg</a>"#;
        let result = find_file_url(html, "pkg-1.0.whl", "https://pypi.org/simple/pkg/");
        assert_eq!(
            result,
            Some(IndexedFile {
                url: "https://example.com/pkg-1.0.whl".to_string(),
                sha256: Some("deadbeef".to_string()),
            })
        );
    }

    // -- #877: relative URL resolution --

    #[test]
    fn test_find_file_url_relative() {
        let html = r#"<a href="../../packages/torch-2.4.0.whl#sha256=abc">torch-2.4.0.whl</a>"#;
        let result = find_file_url(
            html,
            "torch-2.4.0.whl",
            "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple/torch/",
        )
        .map(|f| f.url);
        assert_eq!(
            result,
            Some(
                "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/packages/torch-2.4.0.whl"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_find_file_url_absolute_unchanged() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/ab/cd/pkg-1.0.whl">pkg-1.0.whl</a>"#;
        let result = find_file_url(
            html,
            "pkg-1.0.whl",
            "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple/pkg/",
        )
        .map(|f| f.url);
        assert_eq!(
            result,
            Some("https://files.pythonhosted.org/packages/ab/cd/pkg-1.0.whl".to_string())
        );
    }

    #[test]
    fn test_find_file_url_path_only() {
        let html = r#"<a href="/packages/pkg-1.0.whl#sha256=ff">pkg-1.0.whl</a>"#;
        let result = find_file_url(html, "pkg-1.0.whl", "https://pypi.example.com/simple/pkg/")
            .map(|f| f.url);
        assert_eq!(
            result,
            Some("https://pypi.example.com/packages/pkg-1.0.whl".to_string())
        );
    }

    #[test]
    fn test_is_valid_pypi_filename() {
        assert!(is_valid_pypi_filename("flask-2.0.tar.gz"));
        assert!(is_valid_pypi_filename("flask-2.0-py3-none-any.whl"));
        assert!(is_valid_pypi_filename("flask-2.0.tgz"));
        assert!(is_valid_pypi_filename("flask-2.0.zip"));
        assert!(is_valid_pypi_filename("flask-2.0.egg"));
        assert!(!is_valid_pypi_filename(""));
        assert!(!is_valid_pypi_filename("../evil.tar.gz"));
        assert!(!is_valid_pypi_filename("evil/path.tar.gz"));
        assert!(!is_valid_pypi_filename("noext"));
        assert!(!is_valid_pypi_filename("bad.exe"));
    }

    #[test]
    fn test_wants_json_pep691() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, PEP691_JSON.parse().unwrap());
        assert!(wants_json(&headers));
    }

    #[test]
    fn test_wants_json_html() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "text/html".parse().unwrap());
        assert!(!wants_json(&headers));
    }

    #[test]
    fn test_wants_json_no_header() {
        let headers = HeaderMap::new();
        assert!(!wants_json(&headers));
    }

    // --- parse_upstream_files ---

    #[test]
    fn test_parse_upstream_files_basic() {
        let html = r#"<a href="https://files.example.com/pkg-1.0-cp310-cp310-linux_x86_64.whl#sha256=aaa">pkg</a>
<a href="https://files.example.com/pkg-1.0-cp314-cp314-linux_x86_64.whl#sha256=bbb">pkg</a>"#;
        let files = parse_upstream_files(html);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].filename, "pkg-1.0-cp310-cp310-linux_x86_64.whl");
        assert_eq!(files[0].sha256.as_deref(), Some("aaa"));
        assert_eq!(files[1].filename, "pkg-1.0-cp314-cp314-linux_x86_64.whl");
        assert_eq!(files[1].sha256.as_deref(), Some("bbb"));
    }

    #[test]
    fn test_parse_upstream_files_no_hash() {
        let html = r#"<a href="https://example.com/pkg-1.0.tar.gz">pkg</a>"#;
        let files = parse_upstream_files(html);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, "pkg-1.0.tar.gz");
        assert!(files[0].sha256.is_none());
    }

    #[test]
    fn test_parse_upstream_files_empty() {
        assert!(parse_upstream_files("").is_empty());
        assert!(parse_upstream_files("<html><body></body></html>").is_empty());
    }

    #[test]
    fn test_parse_upstream_files_skips_non_package_links() {
        let html = r#"<a href="https://example.com/readme.txt">readme</a>
<a href="https://example.com/pkg-1.0.whl#sha256=abc">pkg</a>"#;
        let files = parse_upstream_files(html);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, "pkg-1.0.whl");
    }

    // --- merge_file_lists ---

    #[test]
    fn test_merge_disjoint() {
        let upstream = vec![FileEntry {
            filename: "pkg-1.0-cp314-cp314-linux_x86_64.whl".to_string(),
            sha256: Some("uuu".to_string()),
        }];
        let local = vec![FileEntry {
            filename: "pkg-1.0-cp310-cp310-linux_x86_64.whl".to_string(),
            sha256: Some("lll".to_string()),
        }];
        let merged = merge_file_lists(upstream, &local);
        assert_eq!(merged.len(), 2);
        // Local first
        assert_eq!(merged[0].filename, "pkg-1.0-cp310-cp310-linux_x86_64.whl");
        assert_eq!(merged[1].filename, "pkg-1.0-cp314-cp314-linux_x86_64.whl");
    }

    #[test]
    fn test_merge_local_wins_on_duplicate() {
        let upstream = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".to_string(),
            sha256: Some("upstream-hash".to_string()),
        }];
        let local = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".to_string(),
            sha256: Some("local-verified-hash".to_string()),
        }];
        let merged = merge_file_lists(upstream, &local);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].sha256.as_deref(), Some("local-verified-hash"));
    }

    #[test]
    fn test_merge_empty_upstream() {
        let local = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".to_string(),
            sha256: None,
        }];
        let merged = merge_file_lists(vec![], &local);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn test_merge_empty_local() {
        let upstream = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".to_string(),
            sha256: Some("hash".to_string()),
        }];
        let merged = merge_file_lists(upstream, &[]);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn test_merge_both_empty() {
        let merged = merge_file_lists(vec![], &[]);
        assert!(merged.is_empty());
    }

    #[test]
    fn test_merge_first_upstream_wins_and_dedups() {
        // Multi-upstream (#663): `upstream` is the upstreams concatenated in
        // precedence order. The same filename from upstream A (first) and B must
        // be deduped to a single entry, and A wins.
        let upstream = vec![
            FileEntry {
                filename: "torch-1.0.whl".to_string(),
                sha256: Some("from-A".to_string()),
            },
            FileEntry {
                filename: "torch-1.0.whl".to_string(),
                sha256: Some("from-B".to_string()),
            },
            FileEntry {
                filename: "torchvision-1.0.whl".to_string(),
                sha256: Some("from-B".to_string()),
            },
        ];
        let merged = merge_file_lists(upstream, &[]);
        assert_eq!(
            merged.len(),
            2,
            "duplicate filename across upstreams deduped"
        );
        let torch = merged
            .iter()
            .find(|f| f.filename == "torch-1.0.whl")
            .unwrap();
        assert_eq!(
            torch.sha256.as_deref(),
            Some("from-A"),
            "first upstream (A) wins precedence"
        );
        assert!(merged.iter().any(|f| f.filename == "torchvision-1.0.whl"));
    }

    proptest! {
        #[test]
        fn prop_merge_no_duplicate_filenames_and_local_wins(
            upstream_names in prop::collection::vec("[a-z]{1,6}", 0..20),
            local_names in prop::collection::vec("[a-z]{1,6}", 0..6),
        ) {
            let upstream: Vec<FileEntry> = upstream_names
                .iter()
                .map(|n| FileEntry { filename: n.clone(), sha256: None })
                .collect();
            let local: Vec<FileEntry> = local_names
                .iter()
                .map(|n| FileEntry { filename: n.clone(), sha256: Some("L".to_string()) })
                .collect();
            let merged = merge_file_lists(upstream, &local);
            // No filename appears twice.
            let mut seen = std::collections::HashSet::new();
            for f in &merged {
                prop_assert!(seen.insert(f.filename.clone()), "duplicate filename in merge");
            }
            // Every local file survives, and local wins on collision.
            for ln in &local_names {
                let e = merged.iter().find(|f| &f.filename == ln);
                prop_assert!(e.is_some());
                prop_assert_eq!(e.unwrap().sha256.as_deref(), Some("L"));
            }
        }
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context, send, send_with_headers};
    use axum::http::{header, Method, StatusCode};

    /// A cold miss is "not found" only when an upstream said so. The simple index and a file
    /// whose upstreams all failed (5xx after the retry, unreachable) answer 502, and so does a
    /// file the index lists on a host that is down. An index that answers without the file,
    /// or a 404, is still 404 — also while another upstream is down.
    #[tokio::test]
    async fn a_cold_miss_is_404_only_when_an_upstream_said_not_found() {
        use wiremock::matchers::{method, path};
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
        // The index answers and lists the file on the host that is down.
        let lists_down = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{}/files/flask-2.0.tar.gz">flask-2.0.tar.gz</a></body></html>"#,
                down.uri()
            )))
            .mount(&lists_down)
            .await;
        // The index answers without the file.
        let lists_other = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<html><body><a href="/files/flask-1.0.tar.gz">flask-1.0.tar.gz</a></body></html>"#,
            ))
            .mount(&lists_other)
            .await;
        // The index answers with no files at all.
        let lists_nothing = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html><body></body></html>"))
            .mount(&lists_nothing)
            .await;
        let refused = "http://127.0.0.1:9".to_string();
        let index = "/simple/flask/";
        let file = "/simple/flask/flask-2.0.tar.gz";
        for (upstreams, uri, want) in [
            (vec![down.uri()], index, StatusCode::BAD_GATEWAY),
            (vec![refused.clone()], index, StatusCode::BAD_GATEWAY),
            (vec![missing.uri()], index, StatusCode::NOT_FOUND),
            (
                vec![down.uri(), lists_nothing.uri()],
                index,
                StatusCode::NOT_FOUND,
            ),
            (vec![down.uri()], file, StatusCode::BAD_GATEWAY),
            (vec![refused.clone()], file, StatusCode::BAD_GATEWAY),
            (vec![missing.uri()], file, StatusCode::NOT_FOUND),
            (vec![lists_down.uri()], file, StatusCode::BAD_GATEWAY),
            (vec![lists_other.uri()], file, StatusCode::NOT_FOUND),
            (
                vec![down.uri(), lists_other.uri()],
                file,
                StatusCode::NOT_FOUND,
            ),
        ] {
            let urls = upstreams.clone();
            let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
                // Plain URL entries, as `proxies = ["https://..."]` reads from the config file.
                cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
            });
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), want, "{uri} {upstreams:?}");
        }
        assert!(!down.received_requests().await.unwrap().is_empty());
        assert!(!missing.received_requests().await.unwrap().is_empty());
        assert!(!lists_down.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_pypi_list_empty() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/simple/", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Simple Index"));
    }

    #[tokio::test]
    async fn test_pypi_list_with_packages() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"fake-tarball-data")
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("flask"));
    }

    #[tokio::test]
    async fn test_pypi_list_json_pep691() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["meta"]["api-version"].as_str() == Some("1.0"));
        assert!(json["projects"].as_array().unwrap().len() == 1);
    }

    #[tokio::test]
    async fn test_pypi_versions_local() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"fake-data")
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/flask/", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("flask-2.0.tar.gz"));
        // URL should contain base_url + /simple/flask/flask-2.0.tar.gz
        assert!(html.contains("/simple/flask/flask-2.0.tar.gz"));
    }

    #[tokio::test]
    async fn test_pypi_versions_with_hash() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"fake-data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                "pypi/flask/flask-2.0.tar.gz.sha256",
                b"abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
            )
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/flask/", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("#sha256=abc123"));
    }

    #[tokio::test]
    async fn test_pypi_versions_json_pep691() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz.sha256", b"deadbeef")
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "flask");
        assert_eq!(json["files"].as_array().unwrap().len(), 1);
        assert_eq!(json["files"][0]["filename"], "flask-2.0.tar.gz");
        assert_eq!(json["files"][0]["hashes"]["sha256"], "deadbeef");
    }

    /// #1100: every file in the simple JSON carries a `hashes` object, also a file NORA
    /// has no digest for — an upstream link without `#sha256=` (a mirror that publishes
    /// none) or a stored file without its sidecar. uv reads `hashes` as a required map
    /// and refused the whole index (`missing field hashes`) when one file lacked it.
    /// Parsed here the way uv parses it: absent or null fails, `{}` is read as no hashes.
    #[tokio::test]
    async fn test_pypi_json_every_file_has_hashes_object() {
        use crate::test_helpers::create_test_context_with_config;
        use std::collections::BTreeMap;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        #[derive(serde::Deserialize)]
        struct StrictIndex {
            files: Vec<StrictFile>,
        }
        #[derive(serde::Deserialize)]
        struct StrictFile {
            filename: String,
            hashes: BTreeMap<String, String>,
        }

        let up_sha = "a".repeat(64);
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body>
                <a href="https://up/flask-1.0.tar.gz">flask-1.0.tar.gz</a>
                <a href="https://up/flask-1.1.tar.gz#sha256={up_sha}">flask-1.1.tar.gz</a>
                </body></html>"#
            )))
            .mount(&upstream)
            .await;

        let proxied = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
        });
        let local_only = create_test_context();
        for ctx in [&proxied, &local_only] {
            // Stored before sidecars and markers existed: no digest anywhere.
            ctx.state
                .storage
                .put("pypi/flask/flask-0.9.tar.gz", b"old")
                .await
                .unwrap();
            ctx.state
                .storage
                .put("pypi/flask/flask-2.0.tar.gz", b"data")
                .await
                .unwrap();
            ctx.state
                .storage
                .put("pypi/flask/flask-2.0.tar.gz.sha256", b"deadbeef")
                .await
                .unwrap();
        }

        let none = BTreeMap::new();
        let sha = |h: &str| BTreeMap::from([("sha256".to_string(), h.to_string())]);
        for (ctx, want) in [
            (
                &proxied,
                vec![
                    ("flask-0.9.tar.gz", none.clone()),
                    ("flask-1.0.tar.gz", none.clone()),
                    ("flask-1.1.tar.gz", sha(&up_sha)),
                    ("flask-2.0.tar.gz", sha("deadbeef")),
                ],
            ),
            (
                &local_only,
                vec![
                    ("flask-0.9.tar.gz", none.clone()),
                    ("flask-2.0.tar.gz", sha("deadbeef")),
                ],
            ),
        ] {
            let response = send_with_headers(
                &ctx.app,
                Method::GET,
                "/simple/flask/",
                vec![("Accept", "application/vnd.pypi.simple.v1+json")],
                "",
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = body_bytes(response).await;
            let index: StrictIndex = serde_json::from_slice(&body).unwrap_or_else(|e| {
                panic!(
                    "a strict PEP 691 client cannot read the index: {e}\n{}",
                    String::from_utf8_lossy(&body)
                )
            });
            let mut got: Vec<(String, BTreeMap<String, String>)> = index
                .files
                .into_iter()
                .map(|f| (f.filename, f.hashes))
                .collect();
            got.sort();
            let want: Vec<(String, BTreeMap<String, String>)> =
                want.into_iter().map(|(f, h)| (f.to_string(), h)).collect();
            assert_eq!(got, want);
        }
    }

    /// #896: NORA's simple JSON must also carry PEP 700 fields so clients (e.g. Renovate)
    /// can compute a minimum release age: `meta.api-version` 1.1, a project-level
    /// `versions` list, and per-file `upload-time` + `size`. Upload-time is sourced from
    /// the cached `dates.json` (filename → RFC3339), size from storage.
    #[tokio::test]
    async fn test_pypi_versions_json_pep700() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz.sha256", b"deadbeef")
            .await
            .unwrap();
        // PEP 700 upload-time is read from the cached dates.json (filename → RFC3339).
        ctx.state
            .storage
            .put(
                "pypi/flask/dates.json",
                br#"{"flask-2.0.tar.gz":"2021-05-11T13:00:00Z"}"#,
            )
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // PEP 700 signals support via api-version 1.1
        assert_eq!(
            json["meta"]["api-version"], "1.1",
            "PEP 700 requires meta.api-version 1.1"
        );
        // project-level versions list (PEP 700)
        let versions = json["versions"]
            .as_array()
            .expect("PEP 700 project versions[] must be present");
        assert!(
            versions.iter().any(|v| v == "2.0"),
            "versions must include 2.0, got {versions:?}"
        );
        // per-file upload-time + size (PEP 700)
        let f = &json["files"][0];
        assert_eq!(
            f["upload-time"], "2021-05-11T13:00:00Z",
            "PEP 700 per-file upload-time from dates.json"
        );
        assert_eq!(f["size"], 4, "PEP 700 per-file size = bytes of 'data'");
    }

    #[tokio::test]
    async fn test_pypi_download_local() {
        let ctx = create_test_context();

        let tarball_data = b"fake-tarball-content";
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", tarball_data)
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/flask/flask-2.0.tar.gz", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        assert_eq!(&body[..], tarball_data);
    }

    #[tokio::test]
    async fn test_pypi_download_range_request() {
        let ctx = create_test_context();
        let sdist = b"0123456789abcdef";
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", sdist)
            .await
            .unwrap();
        let url = "/simple/flask/flask-2.0.tar.gz";

        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes 2-5/{}", sdist.len())
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "application/gzip"
        );
        assert_eq!(body_bytes(resp).await.as_ref(), &sdist[2..=5]);

        // A client that already holds the whole file resumes with `bytes=<size>-`.
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            url,
            vec![("range", &format!("bytes={}-", sdist.len())[..])],
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
            format!("bytes */{}", sdist.len())
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
        assert_eq!(body_bytes(resp).await.as_ref(), &sdist[..]);
    }

    #[tokio::test]
    async fn test_pypi_not_found_no_proxy() {
        let ctx = create_test_context();

        let response = send(&ctx.app, Method::GET, "/simple/nonexistent/", "").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Regression test for #891 path 1: internal `dates.json` must not leak
    /// into the PEP 691 simple index. `uv` and other strict clients require
    /// `hashes` on every file entry; `dates.json` has no sidecar → parse failure.
    #[tokio::test]
    async fn test_pypi_dates_json_excluded_from_index() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/loguru/loguru-0.7.0.tar.gz", b"fake-sdist")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/loguru/loguru-0.7.0.tar.gz.sha256", b"aabbccdd")
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                "pypi/loguru/dates.json",
                br#"{"loguru-0.7.0.tar.gz":"2023-08-20T12:00:00Z"}"#,
            )
            .await
            .unwrap();

        // HTML index must not contain dates.json
        let response = send(&ctx.app, Method::GET, "/simple/loguru/", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains("loguru-0.7.0.tar.gz"),
            "real package must appear"
        );
        assert!(
            !html.contains("dates.json"),
            "dates.json must NOT appear in index (#891)"
        );

        // PEP 691 JSON index must also exclude dates.json
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/loguru/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let files = json["files"].as_array().unwrap();
        assert_eq!(files.len(), 1, "only the real package file, not dates.json");
        assert_eq!(files[0]["filename"], "loguru-0.7.0.tar.gz");
    }

    /// Regression test for #891 path 2: `GET /simple/{name}/dates.json` must
    /// return 404, not serve the internal bookkeeping file.
    #[tokio::test]
    async fn test_pypi_dates_json_not_downloadable() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put(
                "pypi/loguru/dates.json",
                br#"{"loguru-0.7.0.tar.gz":"2023-08-20T12:00:00Z"}"#,
            )
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/loguru/dates.json", "").await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "internal dates.json must not be downloadable (#891)"
        );
    }

    /// Regression test for #905: `ensure_pypi_dates_cached` must never fetch
    /// an internal-namespace package's metadata upstream (#68 dependency
    /// A file whose version cannot be read from its name is refused by the
    /// allowlist, not passed on as a metadata request.
    #[tokio::test]
    async fn allowlist_refuses_a_file_whose_version_it_cannot_read() {
        use crate::test_helpers::create_test_context_with_config;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"version": 1, "entries": [{"registry": "pypi", "name": "pkg", "version": "1.0.0"}]}"#).unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        ctx.state
            .storage
            .put("pypi/pkg/weird.tar.gz", b"sdist")
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/simple/pkg/weird.tar.gz", "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = send(&ctx.app, Method::GET, "/simple/pkg/", "").await;
        assert_ne!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "control: the index passes"
        );
    }

    /// confusion). Verify that a tarball download for an internal-namespace
    /// package does not trigger any upstream requests for the dates endpoint.
    #[tokio::test]
    async fn test_pypi_self_prime_skips_internal_namespace() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;

        // Any request to the upstream = test failure (the guard must prevent it).
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
            cfg.server.trust_upstream_dates = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces = vec!["internal-*".to_string()];
        });

        // Pre-populate a tarball so the download path is exercised.
        ctx.state
            .storage
            .put(
                "pypi/internal-secret/internal_secret-1.0.0.tar.gz",
                b"fake-sdist",
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                "pypi/internal-secret/internal_secret-1.0.0.tar.gz.sha256",
                b"aabbccdd",
            )
            .await
            .unwrap();

        // Download the tarball — this triggers ensure_pypi_dates_cached.
        let _resp = send(
            &ctx.app,
            Method::GET,
            "/simple/internal-secret/internal_secret-1.0.0.tar.gz",
            "",
        )
        .await;

        // The internal-namespace guard must have prevented any upstream fetch.
        let upstream_hits = upstream.received_requests().await.unwrap().len();
        assert_eq!(
            upstream_hits, 0,
            "internal-namespace package dates must never be fetched upstream (#68, #905)"
        );

        // dates.json must NOT have been written for an internal package.
        assert!(
            ctx.state
                .storage
                .get("pypi/internal-secret/dates.json")
                .await
                .is_err(),
            "dates.json must not be created for internal-namespace packages"
        );
    }

    /// #969 A/B: the simple JSON must take each file's PEP 700 `size` from the listing
    /// (`list_with_meta`) and NEVER `stat()` per file. On S3 a `stat()` is a HEAD
    /// round-trip, and they were issued serially over the whole merged file list, so
    /// `/simple/{name}/` cost one HEAD per file — hundreds to tens of thousands for a
    /// proxied index — and uv timed out. A backend that counts `stat()` proves the JSON
    /// index now issues ZERO of them while still emitting the correct size.
    /// Same class as #738 on the Docker index rebuild.
    #[tokio::test]
    async fn pypi_simple_json_uses_list_with_meta_not_per_key_stat() {
        use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        /// Delegates every operation to a real in-memory object store, counting
        /// `stat()` calls. `list_with_meta` is inherited from the inner store, so the
        /// listing still carries real sizes.
        struct StatCounting {
            inner: ObjectStorage,
            stat_calls: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl StorageBackend for StatCounting {
            async fn stat(&self, key: &str) -> Option<FileMeta> {
                self.stat_calls.fetch_add(1, Ordering::SeqCst);
                self.inner.stat(key).await
            }
            async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
                self.inner.put(k, d, sha256).await
            }
            async fn get(
                &self,
                k: &str,
            ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
                self.inner.get(k).await
            }
            async fn pin(&self, k: &str) -> Option<String> {
                self.inner.pin(k).await
            }
            async fn delete(&self, k: &str) -> crate::storage::Result<()> {
                self.inner.delete(k).await
            }
            async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
                self.inner.list(prefix).await
            }
            async fn list_with_meta(
                &self,
                prefix: &str,
            ) -> crate::storage::Result<Vec<(String, FileMeta)>> {
                self.inner.list_with_meta(prefix).await
            }
            async fn health_check(&self) -> bool {
                self.inner.health_check().await
            }
            async fn total_size(&self) -> u64 {
                self.inner.total_size().await
            }
            fn backend_name(&self) -> &'static str {
                "stat-counting-test"
            }
            async fn put_from_path(
                &self,
                k: &str,
                src: &std::path::Path,
                sha256: Option<&str>,
            ) -> crate::storage::Result<()> {
                self.inner.put_from_path(k, src, sha256).await
            }
            async fn copy(
                &self,
                src: &str,
                dst: &str,
                sha256: Option<&str>,
            ) -> crate::storage::Result<()> {
                self.inner.copy(src, dst, sha256).await
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

        let stat_calls = Arc::new(AtomicUsize::new(0));
        let ctx = crate::test_helpers::create_test_context_with_storage(Storage::from_backend(
            Arc::new(StatCounting {
                inner: ObjectStorage::in_memory(),
                stat_calls: Arc::clone(&stat_calls),
            }),
        ));
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz.sha256", b"deadbeef")
            .await
            .unwrap();
        stat_calls.store(0, Ordering::SeqCst);

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        assert_eq!(
            stat_calls.load(Ordering::SeqCst),
            0,
            "#969: the simple JSON must not stat() per file — size comes from list_with_meta"
        );
        // Correctness preserved: the size still reaches the response.
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(
            json["files"][0]["size"], 4,
            "PEP 700 size must survive the stat-free path"
        );
    }

    /// #969: an upstream that answers the PEP 691 JSON but carries no `upload-time`
    /// (any pre-PEP-700 index) left nothing cached, so EVERY `/simple/{name}/` JSON
    /// request re-downloaded the whole upstream JSON index. The answered-but-dateless
    /// result is now cached once; the second request must not fetch it again.
    #[tokio::test]
    async fn test_pypi_dateless_upstream_json_is_fetched_once() {
        use super::PEP691_JSON;
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // PEP 691 JSON without any `upload-time` — a pre-PEP-700 upstream.
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .and(header("accept", PEP691_JSON))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"meta":{"api-version":"1.0"},"name":"flask","files":[{"filename":"flask-2.0.tar.gz","url":"https://up/flask-2.0.tar.gz"}]}"#,
            ))
            .mount(&upstream)
            .await;
        // The PEP 503 HTML listing the index itself merges.
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<html><body><a href="https://up/flask-2.0.tar.gz">flask-2.0.tar.gz</a></body></html>"#,
            ))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
        });

        for _ in 0..2 {
            let response = send_with_headers(
                &ctx.app,
                Method::GET,
                "/simple/flask/",
                vec![("Accept", "application/vnd.pypi.simple.v1+json")],
                "",
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
        }

        let json_fetches = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| {
                r.headers
                    .get("accept")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v == PEP691_JSON)
            })
            .count();
        assert_eq!(
            json_fetches, 1,
            "#969: a dateless upstream JSON index must be fetched once, not per request"
        );
        // The listing is what got cached, without a date: no upload-time for the file,
        // as for an absent dates.json, while the entry still records that it was listed.
        assert_eq!(
            &ctx.state
                .storage
                .get("pypi/flask/dates.json")
                .await
                .unwrap()[..],
            br#"{"flask-2.0.tar.gz":null}"#,
            "an answered-but-dateless upstream is recorded without dates"
        );
    }

    /// #969: a failed upstream fetch must cache nothing, so a transient outage stays
    /// retryable. Only an upstream that actually answered may record the empty map.
    #[tokio::test]
    async fn test_pypi_dates_not_cached_when_upstream_fetch_fails() {
        use super::PEP691_JSON;
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // The JSON index is down; the HTML listing still answers.
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .and(header("accept", PEP691_JSON))
            .respond_with(ResponseTemplate::new(500))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<html><body><a href="https://up/flask-2.0.tar.gz">flask-2.0.tar.gz</a></body></html>"#,
            ))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
        });

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", PEP691_JSON)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "the index still serves");
        assert!(
            ctx.state
                .storage
                .get("pypi/flask/dates.json")
                .await
                .is_err(),
            "#969: a failed upstream fetch must cache nothing — the outage must stay retryable"
        );
    }

    /// A corrupt `dates.json` (hand-edited, truncated write) must not fail the index:
    /// the PEP 700 `upload-time` is optional, so it is simply omitted while `size`
    /// still comes from the listing.
    #[tokio::test]
    async fn test_pypi_simple_json_survives_corrupt_dates_json() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/flask/dates.json", b"{ this is not json")
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(
            json["files"][0]["size"], 4,
            "size survives a corrupt dates.json"
        );
        assert!(
            json["files"][0].get("upload-time").is_none(),
            "an unparsable dates.json omits upload-time instead of failing the index"
        );
    }

    /// PEP 700 `size` is only knowable for files NORA actually stores. In a merged
    /// index the local file carries a size and the upstream-only file does not —
    /// the same outcome the old per-file `stat()` produced (it 404'd on those),
    /// reached without the round-trip.
    #[tokio::test]
    async fn test_pypi_simple_json_size_only_for_local_files() {
        use super::PEP691_JSON;
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<html><body>
                   <a href="https://up/flask-2.0.tar.gz">flask-2.0.tar.gz</a>
                   <a href="https://up/flask-3.0.tar.gz">flask-3.0.tar.gz</a>
                   </body></html>"#,
            ))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
        });
        // Only 2.0 is cached locally.
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"seven!!")
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", PEP691_JSON)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        let files = json["files"].as_array().expect("files array");
        assert_eq!(files.len(), 2, "both files are listed: {files:?}");
        let by_name = |n: &str| {
            files
                .iter()
                .find(|f| f["filename"] == n)
                .unwrap_or_else(|| panic!("{n} missing from {files:?}"))
        };
        assert_eq!(
            by_name("flask-2.0.tar.gz")["size"],
            7,
            "the locally stored file carries its real size"
        );
        assert!(
            by_name("flask-3.0.tar.gz").get("size").is_none(),
            "an upstream-only file has no local size and must omit the field"
        );
    }

    /// #969 class invariant (the one #738 should have carried): the simple JSON must
    /// cost the SAME number of storage round-trips whatever the size of the index it
    /// renders. Rendering a 1-file index and a 100-file index must issue an identical
    /// op count — anything proportional to the file list is an N+1 by construction,
    /// and on S3 every op is a network round-trip.
    #[tokio::test]
    async fn pypi_simple_json_cost_is_independent_of_index_size() {
        use super::PEP691_JSON;
        use crate::test_helpers::{
            create_test_context_with_storage_and_config, op_counting_storage,
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// Serve an upstream index of `n` files and return the storage ops one JSON
        /// index request costs.
        async fn ops_for_index(n: usize) -> usize {
            let links: String = (1..=n)
                .map(|i| format!("<a href=\"https://up/pkg-{i}.0.tar.gz\">pkg-{i}.0.tar.gz</a>\n"))
                .collect();
            let upstream = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/pkg/"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_string(format!("<html><body>{links}</body></html>")),
                )
                .mount(&upstream)
                .await;

            let (storage, ops) = op_counting_storage();
            let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
                cfg.pypi.proxy = Some(upstream.uri());
            });
            ops.reset();
            let response = send_with_headers(
                &ctx.app,
                Method::GET,
                "/simple/pkg/",
                vec![("Accept", PEP691_JSON)],
                "",
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "index of {n} files served"
            );
            ops.total()
        }

        let small = ops_for_index(1).await;
        let large = ops_for_index(100).await;
        assert_eq!(
            small, large,
            "#969: rendering the simple JSON must cost the same storage round-trips for a \
             1-file and a 100-file index — {small} vs {large} means the cost scales with N"
        );
    }

    // ── A name with an empty segment never names another key's file ─────────

    /// A project name is one segment: `/simple/evilpkg%2F/...` decodes to `evilpkg/` and
    /// `%2Fevilpkg` to `/evilpkg`, both naming the canonical file under a name the rule `evilpkg`
    /// does not cover — refused before curation and storage.
    #[tokio::test]
    async fn a_project_name_with_an_empty_segment_is_refused_before_curation() {
        use crate::test_helpers::create_test_context_with_config;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "pypi", "name": "evilpkg", "version": "*", "reason": "malware"}]}"#,
        )
        .unwrap();
        let bp = blocklist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bp);
        });
        ctx.state
            .storage
            .put("pypi/evilpkg/evilpkg-1.0.tar.gz", b"MALWARE")
            .await
            .unwrap();
        let canonical = send(
            &ctx.app,
            Method::GET,
            "/simple/evilpkg/evilpkg-1.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(canonical.status(), StatusCode::FORBIDDEN, "control");

        let mut served = Vec::new();
        for alias in [
            "/simple/evilpkg%2F/evilpkg-1.0.tar.gz",
            "/simple/%2Fevilpkg/evilpkg-1.0.tar.gz",
        ] {
            let resp = send(&ctx.app, Method::GET, alias, "").await;
            if resp.status() == StatusCode::OK {
                served.push(format!("{alias} -> {:?}", body_bytes(resp).await));
            }
        }
        assert!(served.is_empty(), "blocklisted file served: {served:?}");
    }

    /// `/simple/%2Finternalpkg/` decodes to `/internalpkg`, which the isolation pattern
    /// `internal*` does not match: it is refused, and the index of an internal project is never
    /// requested from the public upstream.
    #[tokio::test]
    async fn a_leading_slash_name_never_takes_an_internal_project_upstream() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("<html></html>"))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
            cfg.curation.internal_namespaces = vec!["internal*".to_string()];
        });
        let leaked = || async {
            upstream
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path().contains("internalpkg"))
                .count()
        };
        let resp = send(&ctx.app, Method::GET, "/simple/internalpkg/", "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        assert_eq!(leaked().await, 0, "control: canonical name is not proxied");

        let resp = send(&ctx.app, Method::GET, "/simple/%2Finternalpkg/", "").await;
        assert_eq!(
            leaked().await,
            0,
            "internal project name sent to the public upstream (alias answered {})",
            resp.status()
        );
    }

    /// An upload under `dup/` never replaces the released `dup-1.0.tar.gz`.
    #[tokio::test]
    async fn an_upload_under_an_empty_segment_name_never_overwrites_a_release() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("pypi/dup/dup-1.0.tar.gz", b"original")
            .await
            .unwrap();
        let boundary = "p1aliasboundary";
        let mut body = Vec::new();
        for (name, value) in [
            (":action", "file_upload"),
            ("name", "dup/"),
            ("version", "1.0"),
        ] {
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"content\"; filename=\"dup-1.0.tar.gz\"\r\nContent-Type: application/octet-stream\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(b"replacement\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let ct = format!("multipart/form-data; boundary={boundary}");
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/simple/",
            vec![("content-type", ct.as_str())],
            body,
        )
        .await;
        assert!(!resp.status().is_success(), "{}", resp.status());
        assert_eq!(
            &ctx.state
                .storage
                .get("pypi/dup/dup-1.0.tar.gz")
                .await
                .unwrap()[..],
            b"original"
        );
    }
}

// ============================================================================
// PEP 691 spec conformance tests
// ============================================================================

#[cfg(test)]
mod spec_conformance_tests {
    use super::*;

    /// PEP 691 requires the field name `hashes`, NOT `digests`.
    /// Regression test for bug where `digests` was used instead.
    #[test]
    fn test_pep691_uses_hashes_not_digests() {
        let files = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: Some("abcdef1234567890".into()),
        }];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
        let body = response.into_body();
        let bytes = futures::executor::block_on(axum::body::to_bytes(body, 1024 * 1024)).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert!(
            json["files"][0].get("hashes").is_some(),
            "PEP 691 requires 'hashes' field, not 'digests'"
        );
        assert!(
            json["files"][0].get("digests").is_none(),
            "PEP 691 forbids 'digests' — must be 'hashes'"
        );
        assert_eq!(json["files"][0]["hashes"]["sha256"], "abcdef1234567890");
    }

    /// The simple JSON carries `meta.api-version`. NORA advertises 1.1 (PEP 700,
    /// still within the `v1` media type) now that it emits upload-time/size/versions.
    #[test]
    fn test_pep691_meta_api_version() {
        let files = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: None,
        }];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(
            json["meta"]["api-version"], "1.1",
            "PEP 700 support is signalled by meta.api-version = '1.1'"
        );
    }

    /// PEP 691 JSON Content-Type must be `application/vnd.pypi.simple.v1+json`.
    #[test]
    fn test_pep691_content_type() {
        let files = vec![];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
        let ct = response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, PEP691_JSON,
            "PEP 691 requires Content-Type: {PEP691_JSON}"
        );
    }

    /// PEP 691: "The hashes dictionary MUST be present, even if no hashes are
    /// available for the file". With no digest it is the empty object — not absent
    /// (uv: `missing field hashes`, #1100) and not null.
    #[test]
    fn test_pep691_hashes_present_as_empty_object_when_none() {
        let files = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: None,
        }];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(
            json["files"][0].get("hashes"),
            Some(&serde_json::json!({})),
            "hashes must be present as {{}} when no hash is available"
        );
    }

    /// Every file carries the CORRECT `hashes` object across the matrix: filename extension
    /// (`.tar.gz` / `.whl`) × hash present/absent × each `(size, upload-time)` combination.
    /// `hashes` is exactly `{}` when no digest is known and exactly `{"sha256": <hex>}` when
    /// one is — never missing, `null`, an array, or an empty-string digest. The no-hash +
    /// upload-time cell is the production proxy case uv rejected (#1100).
    #[test]
    fn test_pep691_hashes_object_present_across_pep700_matrix() {
        use std::collections::HashMap;
        // Both extensions, with and without a hash.
        let specs: [(&str, Option<&str>); 4] = [
            ("hashed-1.0.tar.gz", Some("deadbeef")),
            ("nohash-1.0.tar.gz", None),
            ("hashed-1.0-py3-none-any.whl", Some("cafef00d")),
            ("nohash-1.0-py3-none-any.whl", None),
        ];
        let files: Vec<FileEntry> = specs
            .iter()
            .map(|(name, sha)| FileEntry {
                filename: (*name).into(),
                sha256: sha.map(str::to_string),
            })
            .collect();
        let combos: [(Option<u64>, Option<String>); 4] = [
            (None, None),
            (Some(1234), None),
            (None, Some("2026-01-01T00:00:00Z".to_string())),
            (Some(1234), Some("2026-01-01T00:00:00Z".to_string())),
        ];
        for (size, upload_time) in combos {
            let pep700: HashMap<String, (Option<u64>, Option<String>)> = specs
                .iter()
                .map(|(name, _)| ((*name).to_string(), (size, upload_time.clone())))
                .collect();
            let response = versions_json_response("pkg", &files, "http://nora:4000", &pep700);
            let bytes = futures::executor::block_on(axum::body::to_bytes(
                response.into_body(),
                1024 * 1024,
            ))
            .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let arr = json["files"].as_array().expect("files array");
            for (name, sha) in specs {
                let file = arr
                    .iter()
                    .find(|f| f["filename"] == name)
                    .unwrap_or_else(|| panic!("file {name} missing from response"));
                let want = match sha {
                    Some(h) => serde_json::json!({ "sha256": h }),
                    None => serde_json::json!({}),
                };
                assert_eq!(
                    file.get("hashes"),
                    Some(&want),
                    "wrong hashes for {name} (size={size:?} upload_time={upload_time:?})"
                );
            }
        }
    }

    /// PEP 691: `name` field must match the normalized package name.
    #[test]
    fn test_pep691_name_is_normalized() {
        let files = vec![];
        let normalized = normalize_name("Flask-RESTful");
        let response =
            versions_json_response(&normalized, &files, "http://nora:4000", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(json["name"], "flask-restful");
    }

    /// PEP 691: file URLs must point to NORA, not upstream.
    #[test]
    fn test_pep691_urls_point_to_nora() {
        let files = vec![
            FileEntry {
                filename: "pkg-1.0.tar.gz".into(),
                sha256: Some("aaa".into()),
            },
            FileEntry {
                filename: "pkg-2.0.whl".into(),
                sha256: Some("bbb".into()),
            },
        ];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        for file in json["files"].as_array().unwrap() {
            let url = file["url"].as_str().unwrap();
            assert!(
                url.starts_with("http://nora:4000/simple/"),
                "file URL must point to NORA base: {url}"
            );
        }
    }

    // ========================================================================
    // URL-rewrite systematic tests (#387)
    // ========================================================================

    /// URLs in HTML response must point to NORA, not upstream (#387).
    #[test]
    fn test_html_urls_point_to_nora_no_upstream_leak() {
        let files = vec![
            FileEntry {
                filename: "requests-2.31.0.tar.gz".into(),
                sha256: Some("aaa111".into()),
            },
            FileEntry {
                filename: "requests-2.31.0-py3-none-any.whl".into(),
                sha256: Some("bbb222".into()),
            },
        ];
        let response = versions_html_response("requests", &files, "http://nora:4000");
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();

        assert!(
            html.contains("http://nora:4000/simple/requests/requests-2.31.0.tar.gz"),
            "HTML must contain NORA URL for tarball"
        );
        assert!(
            html.contains("http://nora:4000/simple/requests/requests-2.31.0-py3-none-any.whl"),
            "HTML must contain NORA URL for wheel"
        );
        // No upstream host leak
        assert!(
            !html.contains("pypi.org") && !html.contains("pythonhosted"),
            "HTML must not contain upstream URLs"
        );
    }

    /// Trailing slash on base_url must not produce double-slash in URLs (#387).
    #[test]
    fn test_pep691_trailing_slash_handling() {
        let files = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: Some("abc".into()),
        }];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000/", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let url = json["files"][0]["url"].as_str().unwrap();
        assert!(
            !url.contains("//simple"),
            "trailing slash on base_url must not produce double-slash: {url}"
        );
        assert!(
            url.starts_with("http://nora:4000/"),
            "URL must start with base: {url}"
        );
    }

    /// Empty file list produces valid response with no file URLs (#387).
    #[test]
    fn test_pep691_no_files_clean_response() {
        let files: Vec<FileEntry> = vec![];
        let response =
            versions_json_response("empty-pkg", &files, "http://nora:4000", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["files"].as_array().unwrap().len(), 0);
        assert_eq!(json["name"], "empty-pkg");
    }

    /// Upstream HTML with no matching package links → empty file list (#387).
    #[test]
    fn test_parse_upstream_no_package_links_yields_empty() {
        let html = r#"<html><body>
            <a href="https://example.com/page">Not a package</a>
            <a href="/about">About</a>
        </body></html>"#;
        let files = parse_upstream_files(html);
        assert!(
            files.is_empty(),
            "HTML without package links should yield empty list"
        );
    }

    /// PEP 691 response must be valid JSON and deserializable back to typed struct.
    #[test]
    fn test_pep691_response_round_trip() {
        let files = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: Some("abc123".into()),
        }];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();

        // Must parse as valid JSON with expected top-level keys
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json.get("meta").is_some(), "missing 'meta' key");
        assert!(json.get("name").is_some(), "missing 'name' key");
        assert!(json.get("files").is_some(), "missing 'files' key");

        // Snapshot the structure
        insta::assert_json_snapshot!("pypi_pep691_response_structure", json);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod local_index_cost_tests {
    //! The simple index over locally stored files must cost the same storage round-trips
    //! for 1 and 100 files, in both the HTML and the JSON form.
    use crate::test_helpers::{
        body_bytes, create_test_context_with_storage, op_counting_storage, send_with_headers,
        TestContext,
    };
    use axum::http::{Method, StatusCode};

    pub(super) const BOUNDARY: &str = "nora-test-boundary";
    const JSON: &str = "application/vnd.pypi.simple.v1+json";
    const HTML: &str = "text/html";

    pub(super) fn upload_body(
        name: &str,
        version: &str,
        filename: &str,
        content: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        for (field, value) in [
            (":action", "file_upload"),
            ("name", name),
            ("version", version),
        ] {
            body.extend_from_slice(
                format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(content);
        body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
        body
    }

    async fn upload(ctx: &TestContext, version: &str) {
        let filename = format!("costpkg-{version}-py3-none-any.whl");
        let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
        let body = upload_body(
            "costpkg",
            version,
            &filename,
            format!("wheel {version}").as_bytes(),
        );
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/simple/",
            vec![("content-type", content_type.as_str())],
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "upload {filename}");
    }

    async fn index_ops(n: usize, accept: &str) -> (usize, String) {
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        for i in 0..n {
            upload(&ctx, &format!("1.0.{i}")).await;
        }
        ops.reset();
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/costpkg/",
            vec![("Accept", accept)],
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "index of {n} local files ({accept})"
        );
        let counted = (ops.total(), format!("{:?}", ops.snapshot()));
        let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        assert!(
            body.matches("sha256").count() >= n,
            "every one of the {n} local files must carry its sha256 ({accept})"
        );
        counted
    }

    #[tokio::test]
    async fn pypi_simple_json_cost_is_independent_of_local_file_count() {
        let (small, small_ops) = index_ops(1, JSON).await;
        let (large, large_ops) = index_ops(100, JSON).await;
        assert_eq!(
            small, large,
            "the JSON simple index must cost the same storage round-trips for 1 and 100 local files: {small_ops} vs {large_ops}"
        );
    }

    #[tokio::test]
    async fn pypi_simple_html_cost_is_independent_of_local_file_count() {
        let (small, small_ops) = index_ops(1, HTML).await;
        let (large, large_ops) = index_ops(100, HTML).await;
        assert_eq!(
            small, large,
            "the HTML simple index must cost the same storage round-trips for 1 and 100 local files: {small_ops} vs {large_ops}"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod hash_marker_tests {
    //! The index trusts a file's hash marker only when it has exactly one; every other case
    //! is served from the `.sha256` sidecar and repaired in the background.
    use super::local_index_cost_tests::{upload_body, BOUNDARY};
    use super::{hash_marker_key, parse_hash_marker, HASH_MARKER_PREFIX};
    use crate::test_helpers::{
        body_bytes, create_test_context, create_test_context_with_storage,
        create_test_context_with_storage_and_config, op_counting_storage, send, send_with_headers,
        TestContext,
    };
    use axum::http::{Method, StatusCode};
    use sha2::Digest as _;

    fn digest(content: &[u8]) -> String {
        hex::encode(sha2::Sha256::digest(content))
    }

    async fn html_index(ctx: &TestContext, project: &str) -> String {
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            &format!("/simple/{project}/"),
            vec![("Accept", "text/html")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "index of {project}");
        String::from_utf8(body_bytes(resp).await.to_vec()).unwrap()
    }

    /// Wait for the markers under `pypi-sha256/<project>/` to become exactly `expected`.
    ///
    /// Markers written by a background task appear some time after the response; the
    /// deadline only bounds a task that never finishes.
    async fn wait_for_markers(ctx: &TestContext, project: &str, expected: &[String]) {
        use std::time::{Duration, Instant};

        let prefix = format!("{HASH_MARKER_PREFIX}{project}/");
        let mut expected = expected.to_vec();
        expected.sort();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut markers = ctx.state.storage.list(&prefix).await.unwrap();
            markers.sort();
            if markers == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "markers under {prefix}: expected {expected:?}, found {markers:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn parse_hash_marker_reads_filename_and_digest() {
        let sha = "ab".repeat(32);
        let prefix = format!("{HASH_MARKER_PREFIX}pkg/");
        let filename = "pkg-1.0+local@x-py3-none-any.whl";
        let key = hash_marker_key("pkg", filename, &sha);
        assert_eq!(
            parse_hash_marker(&prefix, &key),
            Some((filename, sha.as_str()))
        );
        for (malformed, why) in [
            (format!("{prefix}pkg-1.0.tar.gz/abc"), "short digest"),
            (format!("{prefix}pkg-1.0.tar.gz"), "no digest"),
            (format!("{prefix}/{sha}"), "no filename"),
            (format!("{prefix}a/b/{sha}"), "nested path"),
        ] {
            assert_eq!(parse_hash_marker(&prefix, &malformed), None, "{why}");
        }
        assert_eq!(
            parse_hash_marker(&format!("{HASH_MARKER_PREFIX}other/"), &key),
            None,
            "marker of another project"
        );
    }

    /// Files stored before markers existed are served from their sidecars, backfilled, and
    /// then cost no sidecar read.
    #[tokio::test]
    async fn legacy_sidecar_digests_are_served_then_backfilled() {
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        let mut digests = Vec::new();
        let mut expected = Vec::new();
        for i in 0..3 {
            let filename = format!("legacypkg-1.0.{i}-py3-none-any.whl");
            let content = format!("legacy wheel {i}");
            let sha = digest(content.as_bytes());
            let key = format!("pypi/legacypkg/{filename}");
            ctx.state
                .storage
                .put(&key, content.as_bytes())
                .await
                .unwrap();
            ctx.state
                .storage
                .put(&format!("{key}.sha256"), sha.as_bytes())
                .await
                .unwrap();
            expected.push(hash_marker_key("legacypkg", &filename, &sha));
            digests.push(sha);
        }

        let body = html_index(&ctx, "legacypkg").await;
        for sha in &digests {
            assert!(
                body.contains(sha.as_str()),
                "sidecar digest {sha} served: {body}"
            );
        }
        wait_for_markers(&ctx, "legacypkg", &expected).await;

        ops.reset();
        let body = html_index(&ctx, "legacypkg").await;
        for sha in &digests {
            assert!(
                body.contains(sha.as_str()),
                "marker digest {sha} served: {body}"
            );
        }
        assert!(
            !ops.snapshot().contains_key("get"),
            "no sidecar is read once markers exist: {:?}",
            ops.snapshot()
        );
    }

    /// A file left with a stale marker next to its own is served from its sidecar, and the
    /// stale marker is removed.
    #[tokio::test]
    async fn conflicting_markers_fall_back_to_the_sidecar_and_are_repaired() {
        // In-memory object store: the repair runs in the background, and a local disk
        // would add fsync latency to what the test waits for.
        let (backend, _ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(backend);
        let filename = "dup-1.0-py3-none-any.whl";
        let key = format!("pypi/dup/{filename}");
        let current = digest(b"current bytes");
        let stale = digest(b"earlier bytes");
        let storage = &ctx.state.storage;
        storage.put(&key, b"current bytes").await.unwrap();
        storage
            .put(&format!("{key}.sha256"), current.as_bytes())
            .await
            .unwrap();
        for sha in [&current, &stale] {
            storage
                .put(&hash_marker_key("dup", filename, sha), b"")
                .await
                .unwrap();
        }

        let body = html_index(&ctx, "dup").await;
        assert!(
            body.contains(current.as_str()),
            "current digest served: {body}"
        );
        assert!(
            !body.contains(stale.as_str()),
            "stale digest not served: {body}"
        );
        wait_for_markers(&ctx, "dup", &[hash_marker_key("dup", filename, &current)]).await;
    }

    /// Uploading a filename that was deleted and is stored again with other bytes replaces
    /// the marker left by the earlier file.
    #[tokio::test]
    async fn upload_replaces_a_stale_marker_of_the_same_filename() {
        let ctx = create_test_context();
        let filename = "reup-1.0-py3-none-any.whl";
        let stale = digest(b"earlier bytes");
        ctx.state
            .storage
            .put(&hash_marker_key("reup", filename, &stale), b"")
            .await
            .unwrap();

        let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/simple/",
            vec![("content-type", content_type.as_str())],
            upload_body("reup", "1.0", filename, b"current bytes"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let current = digest(b"current bytes");
        let markers = ctx
            .state
            .storage
            .list(&format!("{HASH_MARKER_PREFIX}reup/"))
            .await
            .unwrap();
        assert_eq!(markers, vec![hash_marker_key("reup", filename, &current)]);
        let body = html_index(&ctx, "reup").await;
        assert!(
            body.contains(current.as_str()) && !body.contains(stale.as_str()),
            "{body}"
        );
    }

    /// A file cached from the upstream is stored with its hash marker.
    #[tokio::test]
    async fn proxied_file_is_cached_with_its_hash_marker() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let filename = "proxied-1.0.tar.gz";
        let content = b"proxied sdist";
        Mock::given(method("GET"))
            .and(path("/proxied/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                "<html><body><a href=\"{}/files/{filename}\">{filename}</a></body></html>",
                upstream.uri()
            )))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/files/{filename}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(content.to_vec()))
            .mount(&upstream)
            .await;
        // In-memory object store: the cache write runs in the background, and a local disk
        // would add fsync latency to what the test waits for.
        let (backend, _ops) = op_counting_storage();
        let ctx = create_test_context_with_storage_and_config(backend, |cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/simple/proxied/{filename}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "proxied download served");
        wait_for_markers(
            &ctx,
            "proxied",
            &[hash_marker_key("proxied", filename, &digest(content))],
        )
        .await;
    }
}

#[cfg(test)]
mod upstream_failure_cases {
    use crate::circuit_breaker::ProbeToken;
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// the index lists the file on a host that answers 404 — the upstream said
    /// "not found", so 404, not 502.
    #[tokio::test]
    async fn file_host_answering_404_is_404() {
        let missing = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&missing)
            .await;
        let lists_missing = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{}/files/flask-2.0.tar.gz">flask-2.0.tar.gz</a></body></html>"#,
                missing.uri()
            )))
            .mount(&lists_missing)
            .await;
        let urls = vec![lists_missing.uri()];
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
        });
        let resp = send(&ctx.app, Method::GET, "/simple/flask/flask-2.0.tar.gz", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(!missing.received_requests().await.unwrap().is_empty());
    }

    /// one upstream's breaker is open, the other failed — the open breaker still
    /// answers 503 (retryable), as before the change.
    #[tokio::test]
    async fn open_breaker_with_failed_peer_is_503() {
        let down = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&down)
            .await;
        let open = "http://127.0.0.1:1".to_string();
        let urls = vec![open.clone(), down.uri()];
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 2;
            cfg.circuit_breaker.reset_timeout = 3600;
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
        });
        let key = crate::circuit_breaker::upstream_key("pypi", &open);
        ctx.state
            .circuit_breaker
            .record_failure(&key, ProbeToken::BACKGROUND);
        ctx.state
            .circuit_breaker
            .record_failure(&key, ProbeToken::BACKGROUND);
        for uri in ["/simple/flask/flask-2.0.tar.gz", "/simple/flask/"] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        }
    }
}

#[cfg(test)]
mod upstream_failure_edge_cases {
    use crate::circuit_breaker::ProbeToken;
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The index alone, one upstream's breaker open and the other failed with
    /// its own breaker still closed — the open breaker answers 503, as before the change.
    #[tokio::test]
    async fn index_open_breaker_with_failed_peer_is_503() {
        let down = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&down)
            .await;
        let open = "http://127.0.0.1:1".to_string();
        let urls = vec![open.clone(), down.uri()];
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 2;
            cfg.circuit_breaker.reset_timeout = 3600;
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
        });
        let key = crate::circuit_breaker::upstream_key("pypi", &open);
        for _ in 0..2 {
            ctx.state
                .circuit_breaker
                .record_failure(&key, ProbeToken::BACKGROUND);
        }
        let resp = send(&ctx.app, Method::GET, "/simple/flask/", "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!down.received_requests().await.unwrap().is_empty());
    }
}

/// A name or path with an empty segment (or, where the name is one segment, any `/`) never
/// reaches curation, storage or an upstream: it would name another artifact's files, and an
/// upstream that normalises paths would answer for that other artifact.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod empty_segment_requests {
    use crate::test_helpers::{
        blocklist_file, create_test_context_with_config, send, send_with_headers, upstream_paths,
    };
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn upstream(body: &str) -> MockServer {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&up)
            .await;
        up
    }

    #[tokio::test]
    async fn a_download_under_an_empty_segment_name_never_reaches_upstream() {
        let up = upstream("<html></html>").await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(up.uri());
            cfg.curation.internal_namespaces = vec!["internal*".to_string()];
        });
        let control = "/simple/internalpkg/internalpkg-1.0.tar.gz";
        let resp = send(&ctx.app, Method::GET, control, "").await;
        assert!(!resp.status().is_success(), "control");
        assert!(upstream_paths(&up).await.is_empty(), "control");
        for uri in [
            "/simple/%2Finternalpkg/internalpkg-1.0.tar.gz",
            "/simple/internalpkg%2F%2Fx/internalpkg-1.0.tar.gz",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
        let sent = upstream_paths(&up).await;
        assert!(sent.is_empty(), "sent upstream: {sent:?}");
    }

    // The JSON index fetches release dates from the upstream; the name is refused first.
    #[tokio::test]
    async fn a_json_index_of_an_empty_segment_name_never_reaches_upstream() {
        let up = upstream(r#"{"files":[]}"#).await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(up.uri());
            cfg.curation.internal_namespaces = vec!["internal*".to_string()];
        });
        let accept = vec![("accept", "application/vnd.pypi.simple.v1+json")];
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/internalpkg/",
            accept.clone(),
            Vec::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        assert!(upstream_paths(&up).await.is_empty(), "control");
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/%2Finternalpkg/",
            accept,
            Vec::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let sent = upstream_paths(&up).await;
        assert!(sent.is_empty(), "sent upstream: {sent:?}");
    }

    // A project name is one segment: a `%2F` that decodes to an inner `/` names another
    // project's files (`corp-secret/x`, `evilpkg/evilpkg`) and is refused before curation,
    // namespace isolation or the upstream see it.
    #[tokio::test]
    async fn a_project_name_with_an_inner_slash_never_reaches_upstream() {
        let up = upstream("<html></html>").await;
        let (_dir, blocklist) = blocklist_file("pypi", "evilpkg");
        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(up.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
            cfg.curation.internal_namespaces = vec!["corp-secret".to_string()];
        });
        let resp = send(&ctx.app, Method::GET, "/simple/corp-secret/", "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        assert!(upstream_paths(&up).await.is_empty(), "control");
        for uri in [
            "/simple/corp-secret%2Fx/",
            "/simple/corp-secret%2Fx/corp-secret-1.0.tar.gz",
            "/simple/evilpkg%2Fevilpkg/evilpkg-1.0.tar.gz",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
        let sent = upstream_paths(&up).await;
        assert!(sent.is_empty(), "sent upstream: {sent:?}");
    }
}

/// Property tests against PEP 503: the normalized name is the registry's key for a project, so
/// every spelling a client or an uploader may use lands on the one key pip asks for.
#[cfg(test)]
mod name_normalization_properties {
    use super::normalize_name;
    use proptest::prelude::*;

    /// PEP 503: `re.sub(r"[-_.]+", "-", name).lower()`.
    fn pep503(name: &str) -> String {
        let mut out = String::with_capacity(name.len());
        let mut in_run = false;
        for c in name.chars() {
            if matches!(c, '-' | '_' | '.') {
                if !in_run {
                    out.push('-');
                }
                in_run = true;
            } else {
                out.extend(c.to_lowercase());
                in_run = false;
            }
        }
        out
    }

    proptest! {
        // Any PEP 508 project name normalizes as PEP 503 says.
        #[test]
        fn a_project_name_normalizes_as_pep_503_says(
            name in "[A-Za-z0-9]([A-Za-z0-9._-]{0,20}[A-Za-z0-9])?"
        ) {
            prop_assert_eq!(normalize_name(&name), pep503(&name));
        }

        // Normalizing twice changes nothing.
        #[test]
        fn normalization_is_idempotent(name in "[A-Za-z0-9._-]{1,24}") {
            let once = normalize_name(&name);
            prop_assert_eq!(normalize_name(&once), once);
        }
    }

    // An upload under a name with a run of separators is listed under the key pip asks for.
    #[tokio::test]
    async fn an_upload_is_listed_under_the_name_pip_asks_for() {
        use super::local_index_cost_tests::{upload_body, BOUNDARY};
        use crate::test_helpers::{body_bytes, create_test_context, send_with_headers};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context();
        let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
        let filename = "foo_bar-1.0-py3-none-any.whl";
        let body = upload_body("Foo__Bar", "1.0", filename, b"wheel");
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/simple/",
            vec![("content-type", content_type.as_str())],
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/foo-bar/",
            vec![("accept", "text/html")],
            Vec::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        assert!(html.contains(filename), "{html}");
    }

    #[test]
    fn a_run_of_separators_is_one_dash() {
        for (name, normalized) in [
            ("foo__bar", "foo-bar"),
            ("Foo._-Bar", "foo-bar"),
            ("a--b", "a-b"),
        ] {
            assert_eq!(normalize_name(name), normalized, "{name}");
        }
    }
}

/// A version-specific blocklist rule holds for every spelling of an sdist's file name.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod blocked_version_in_any_sdist_spelling {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn a_blocked_version_is_refused_whatever_the_sdist_spelling() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SDIST".to_vec()))
            .mount(&upstream)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "pypi", "name": "python-dateutil", "version": "2.8.2", "reason": "malware"}]}"#,
        )
        .unwrap();
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
        });
        for file in [
            "python_dateutil-2.8.2.tar.gz",
            "python-dateutil-2.8.2.tar.gz",
            "Python.Dateutil-2.8.2.zip",
            "python_dateutil-2.8.2-py2.py3-none-any.whl",
        ] {
            let resp = send(
                &ctx.app,
                Method::GET,
                &format!("/simple/python-dateutil/{file}"),
                "",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{file}");
        }
        // Another version passes.
        let resp = send(
            &ctx.app,
            Method::GET,
            "/simple/python-dateutil/python-dateutil-2.8.1.tar.gz",
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }
}

/// A PyPI version is the version PEP 440 reads, not its spelling: pip compares parsed versions
/// (`packaging.version.Version`), so a rule or an allowlist entry holds for every spelling of
/// its version — `1.0-1` is `1.0.post1`, `2.0.0.RC1` is `2.0rc1`, `1.0.0` is `1.0`.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod pep440_version_curation {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SDIST".to_vec()))
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
    async fn a_rule_holds_for_every_spelling_of_its_version() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = write(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [
                {"registry": "pypi", "name": "foo", "version": "1.0.post1", "reason": "malware"},
                {"registry": "pypi", "name": "foo", "version": "2.0rc1", "reason": "malware"}
            ]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        for file in [
            "foo-1.0.post1.tar.gz",
            "foo-1.0-1.tar.gz",
            "foo-1.0.POST1.zip",
            "foo-1.0.0.post1.tar.gz",
            "foo-1.0.0.post01.tar.gz",
            "foo-2.0.0.RC1-py3-none-any.whl",
            "foo-2.0-rc-1.tar.gz",
            "foo-2.0c1.tar.gz",
            "foo-v2.0rc1.tar.gz",
        ] {
            let resp = send(&ctx.app, Method::GET, &format!("/simple/foo/{file}"), "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{file}");
        }
        for file in ["foo-1.0.tar.gz", "foo-2.0.tar.gz", "foo-1.0.post2.tar.gz"] {
            let resp = send(&ctx.app, Method::GET, &format!("/simple/foo/{file}"), "").await;
            assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{file}");
        }
    }

    #[tokio::test]
    async fn an_allowlist_entry_admits_every_spelling_of_its_version() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = write(
            &dir,
            "allowlist.json",
            r#"{"version": 1, "entries": [{"registry": "pypi", "name": "foo", "version": "1.0"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        for file in ["foo-1.0.tar.gz", "foo-1.0.0.tar.gz", "foo-v1.0.zip"] {
            let resp = send(&ctx.app, Method::GET, &format!("/simple/foo/{file}"), "").await;
            assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{file}");
        }
        for file in ["foo-1.1.tar.gz", "foo-1.0.post1.tar.gz"] {
            let resp = send(&ctx.app, Method::GET, &format!("/simple/foo/{file}"), "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{file}");
        }
    }
}

/// Release age reaches a PEP 503 (HTML) client: pip before 22.2 never asks for the PEP 691
/// JSON index, which used to be the only request that cached `dates.json`, so its downloads
/// carried no date and min-release-age let every one of them through. A file is dated by the
/// listing NORA cached, and only if that listing names it.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod release_age_without_the_json_index {
    use super::PEP691_JSON;
    use crate::digest_quarantine::QuarantineMode;
    use crate::test_helpers::TestContext;
    use crate::test_helpers::{
        create_test_context_with_config, reload_curation, send, send_with_headers,
    };
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// What pip 22.0 sends for the index.
    const PIP_HTML: &str = "text/html";

    /// An upstream index for `foo` listing `files` (filename, upload-time); `json` is the
    /// body its PEP 691 request gets, `None` for an upstream that answers it with HTML.
    async fn upstream(files: &[(&str, Option<&str>)], json: bool) -> MockServer {
        let up = MockServer::start().await;
        let uri = up.uri();
        let links: String = files
            .iter()
            .map(|(f, _)| format!(r#"<a href="{uri}/files/{f}">{f}</a>"#))
            .collect();
        let html = format!("<html><body>{links}</body></html>");
        if json {
            let entries: Vec<serde_json::Value> = files
                .iter()
                .map(|(f, ut)| match ut {
                    Some(ut) => serde_json::json!({"filename": f, "url": format!("{uri}/files/{f}"), "hashes": {}, "upload-time": ut}),
                    None => serde_json::json!({"filename": f, "url": format!("{uri}/files/{f}"), "hashes": {}}),
                })
                .collect();
            let body = serde_json::json!({"meta": {"api-version": "1.1"}, "name": "foo", "files": entries});
            Mock::given(method("GET"))
                .and(path("/foo/"))
                .and(header("accept", PEP691_JSON))
                .respond_with(ResponseTemplate::new(200).set_body_string(body.to_string()))
                .mount(&up)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/foo/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html))
            .mount(&up)
            .await;
        for (f, _) in files {
            Mock::given(method("GET"))
                .and(path(format!("/files/{f}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(format!("BYTES {f}")))
                .mount(&up)
                .await;
        }
        up
    }

    fn context(
        up: &MockServer,
        trust: bool,
        customize: impl FnOnce(&mut crate::config::Config),
    ) -> TestContext {
        let uri = up.uri();
        create_test_context_with_config(move |cfg| {
            cfg.pypi.proxy = Some(uri);
            cfg.server.trust_upstream_dates = trust;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            customize(cfg);
        })
    }

    fn min_age(cfg: &mut crate::config::Config) {
        cfg.curation.min_release_age = Some("3d".to_string());
    }

    /// The index the client reads, then the download it makes from it.
    async fn index_then_download(ctx: &TestContext, accept: &str, file: &str) -> StatusCode {
        let index = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/foo/",
            vec![("Accept", accept)],
            "",
        )
        .await;
        assert_eq!(index.status(), StatusCode::OK);
        send(&ctx.app, Method::GET, &format!("/simple/foo/{file}"), "")
            .await
            .status()
    }

    /// `dates.json` as an earlier request cached it `days` ago.
    async fn cached_listing(ctx: &TestContext, body: &str, days: u64) {
        ctx.state
            .storage
            .put("pypi/foo/dates.json", body.as_bytes())
            .await
            .unwrap();
        let then = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86400);
        std::fs::File::options()
            .write(true)
            .open(std::path::Path::new(&ctx.state.config.storage.path).join("pypi/foo/dates.json"))
            .unwrap()
            .set_modified(then)
            .unwrap();
    }

    fn hour_ago() -> String {
        (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339()
    }

    #[tokio::test]
    async fn an_html_client_is_held_like_a_json_client() {
        for accept in [PIP_HTML, PEP691_JSON] {
            let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
            let ctx = context(&up, false, min_age);
            assert_eq!(
                index_then_download(&ctx, accept, "foo-1.0.tar.gz").await,
                StatusCode::FORBIDDEN,
                "{accept}: a file NORA first saw just now is younger than 3d on its own clock"
            );
        }
    }

    /// Requests the upstream got for the JSON listing, which NORA asks for the dates.
    async fn json_listings(up: &MockServer) -> usize {
        up.received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| {
                r.url.path() == "/foo/"
                    && r.headers.get("accept").and_then(|v| v.to_str().ok()) == Some(PEP691_JSON)
            })
            .count()
    }

    /// The listing is asked for on a download only when a release-age rule reads the date:
    /// with none, or with curation off, the download asks the upstream nothing more.
    #[tokio::test]
    async fn a_download_asks_for_the_dates_only_when_a_release_age_rule_reads_them() {
        type Setup = fn(&mut crate::config::Config);
        let cases: [(&str, Setup, usize); 4] = [
            ("enforce, no rule", |_| {}, 0),
            (
                "off, rule set",
                |cfg| {
                    cfg.curation.mode = crate::config::CurationMode::Off;
                    cfg.curation.min_release_age = Some("3d".to_string());
                },
                0,
            ),
            ("enforce, global rule", min_age, 1),
            (
                "enforce, pypi rule",
                |cfg| {
                    cfg.curation.pypi.min_release_age = Some("3d".to_string());
                },
                1,
            ),
        ];
        for (name, setup, want) in cases {
            let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
            let ctx = context(&up, false, setup);
            let index = send_with_headers(
                &ctx.app,
                Method::GET,
                "/simple/foo/",
                vec![("Accept", PIP_HTML)],
                "",
            )
            .await;
            assert_eq!(index.status(), StatusCode::OK);
            let before = json_listings(&up).await;
            let _ = send(&ctx.app, Method::GET, "/simple/foo/foo-1.0.tar.gz", "").await;
            assert_eq!(json_listings(&up).await - before, want, "{name}");
        }
    }

    /// A release-age rule a reload brings in reads the dates from then on: the engine the reload
    /// installs decides, not the configuration NORA started with — the global rule and PyPI's own
    /// alike.
    #[tokio::test]
    async fn a_release_age_rule_a_reload_brings_in_asks_for_the_dates() {
        type Setup = fn(&mut crate::config::Config);
        let rules: [(&str, Setup); 2] = [
            ("global", min_age),
            ("PyPI's own", |cfg| {
                cfg.curation.pypi.min_release_age = Some("3d".to_string());
            }),
        ];
        for (rule, add) in rules {
            let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
            let ctx = context(&up, false, |_| {});
            reload_curation(&ctx, add);
            let index = send_with_headers(
                &ctx.app,
                Method::GET,
                "/simple/foo/",
                vec![("Accept", PIP_HTML)],
                "",
            )
            .await;
            assert_eq!(index.status(), StatusCode::OK);
            let before = json_listings(&up).await;
            assert_eq!(
                send(&ctx.app, Method::GET, "/simple/foo/foo-1.0.tar.gz", "")
                    .await
                    .status(),
                StatusCode::FORBIDDEN,
                "{rule}: a file NORA first saw just now is younger than 3d on its own clock"
            );
            assert_eq!(json_listings(&up).await - before, 1, "{rule}");
        }
    }

    #[tokio::test]
    async fn an_html_client_gets_a_file_nora_listed_long_ago() {
        let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
        let ctx = context(&up, false, min_age);
        cached_listing(&ctx, r#"{"foo-1.0.tar.gz":"2019-01-01T00:00:00Z"}"#, 30).await;
        assert_eq!(
            index_then_download(&ctx, PIP_HTML, "foo-1.0.tar.gz").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn an_html_client_gets_the_upstream_date_when_dates_are_trusted() {
        let fresh = hour_ago();
        let up = upstream(
            &[
                ("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z")),
                ("foo-2.0.tar.gz", Some(fresh.as_str())),
            ],
            true,
        )
        .await;
        let ctx = context(&up, true, min_age);
        assert_eq!(
            index_then_download(&ctx, PIP_HTML, "foo-2.0.tar.gz").await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            index_then_download(&ctx, PIP_HTML, "foo-1.0.tar.gz").await,
            StatusCode::OK
        );
    }

    /// Without trusted dates the quarantine counts from NORA's first fetch of a file, whether
    /// or not a cached listing names it: the listing's age says when NORA wrote it, not when it
    /// first fetched these bytes.
    #[tokio::test]
    async fn without_trusted_dates_a_cached_listing_does_not_date_the_quarantine() {
        let up = upstream(
            &[
                ("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z")),
                ("foo-2.0.tar.gz", Some("2019-01-02T00:00:00Z")),
            ],
            true,
        )
        .await;
        let ctx = context(&up, false, |cfg| {
            cfg.curation.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("7d".to_string());
        });
        cached_listing(&ctx, r#"{"foo-1.0.tar.gz":"2019-01-01T00:00:00Z"}"#, 30).await;
        for file in ["foo-2.0.tar.gz", "foo-1.0.tar.gz"] {
            assert_eq!(
                index_then_download(&ctx, PIP_HTML, file).await,
                StatusCode::FORBIDDEN,
                "{file}: first fetched now, held for 7d whatever the listing's age"
            );
        }
    }

    /// A file cached before the quarantine recorded it is counted from now on the cache path.
    #[tokio::test]
    async fn a_file_cached_before_the_quarantine_saw_it_counts_from_now() {
        let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
        let ctx = context(&up, false, |cfg| {
            cfg.curation.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("7d".to_string());
        });
        cached_listing(&ctx, r#"{"foo-1.0.tar.gz":"2019-01-01T00:00:00Z"}"#, 30).await;
        ctx.state
            .storage
            .put("pypi/foo/foo-1.0.tar.gz", b"BYTES foo-1.0.tar.gz")
            .await
            .unwrap();
        assert_eq!(
            send(&ctx.app, Method::GET, "/simple/foo/foo-1.0.tar.gz", "")
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert!(!crate::test_helpers::upstream_paths(&up)
            .await
            .iter()
            .any(|p| p.starts_with("/files/")));
    }

    /// With trusted dates the upload time seeds the quarantine (#750): a file uploaded years
    /// ago is not held as new to this mirror.
    #[tokio::test]
    async fn with_trusted_dates_an_old_release_matures_in_the_quarantine() {
        let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
        let ctx = context(&up, true, |cfg| {
            cfg.curation.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("7d".to_string());
        });
        assert_eq!(
            index_then_download(&ctx, PIP_HTML, "foo-1.0.tar.gz").await,
            StatusCode::OK
        );
    }

    /// An upstream index without PEP 700 dates (devpi, Artifactory) or without PEP 691 at
    /// all (it answers the JSON request with its HTML) still lists the file.
    #[tokio::test]
    async fn an_upstream_without_dates_still_lists_the_file() {
        for json in [true, false] {
            let up = upstream(&[("foo-1.0.tar.gz", None)], json).await;
            let ctx = context(&up, false, min_age);
            assert_eq!(
                index_then_download(&ctx, PIP_HTML, "foo-1.0.tar.gz").await,
                StatusCode::FORBIDDEN,
                "json={json}"
            );
        }
    }

    /// An upstream that lists the file without a date does not stop the search: the
    /// date comes from the next upstream that has one, as when the first listed nothing.
    #[tokio::test]
    async fn a_listing_without_dates_does_not_hide_a_later_upstreams_date() {
        let fresh = hour_ago();
        let undated = upstream(&[("foo-1.0.tar.gz", None)], true).await;
        let dated = upstream(&[("foo-1.0.tar.gz", Some(fresh.as_str()))], true).await;
        let urls = vec![undated.uri(), dated.uri()];
        let ctx = context(&undated, true, move |cfg| {
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
            min_age(cfg);
        });
        assert_eq!(
            index_then_download(&ctx, PIP_HTML, "foo-1.0.tar.gz").await,
            StatusCode::FORBIDDEN
        );
    }

    /// A cache hit with no listing cached (a hosted package, or a file cached by an earlier
    /// version) must not start asking an upstream on every download.
    #[tokio::test]
    async fn a_cache_hit_does_not_fetch_the_listing() {
        let up = upstream(&[("foo-1.0.tar.gz", None)], true).await;
        let ctx = context(&up, false, min_age);
        ctx.state
            .storage
            .put("pypi/foo/foo-1.0.tar.gz", b"LOCAL")
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/simple/foo/foo-1.0.tar.gz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(up.received_requests().await.unwrap().is_empty());
    }
}

/// A file the upstream index names with `#sha256=` is served only when its bytes have that
/// digest: pip checks it against the index NORA serves, and once NORA cached the file its own
/// digest would stand in for the upstream's, so wrong bytes would pass on the next install.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod upstream_index_digest {
    use crate::test_helpers::{
        background_writes_done, body_bytes, create_test_context_with_config, send, TestContext,
    };
    use axum::http::{Method, StatusCode};
    use sha2::Digest;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const FILE: &str = "hm-1.0-py3-none-any.whl";

    fn sha256(bytes: &[u8]) -> String {
        hex::encode(sha2::Sha256::digest(bytes))
    }

    /// An upstream whose index names `FILE` with `fragment` and whose file host answers `bytes`.
    async fn upstream(fragment: &str, bytes: &[u8]) -> MockServer {
        let up = MockServer::start().await;
        let uri = up.uri();
        Mock::given(method("GET"))
            .and(path("/hm/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{uri}/files/{FILE}{fragment}">{FILE}</a></body></html>"#
            )))
            .mount(&up)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/files/{FILE}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
            .mount(&up)
            .await;
        up
    }

    fn context(up: &MockServer) -> TestContext {
        let uri = up.uri();
        create_test_context_with_config(move |cfg| cfg.pypi.proxy = Some(uri))
    }

    async fn download(ctx: &TestContext) -> (StatusCode, Vec<u8>) {
        let resp = send(&ctx.app, Method::GET, &format!("/simple/hm/{FILE}"), "").await;
        let status = resp.status();
        (status, body_bytes(resp).await.to_vec())
    }

    #[tokio::test]
    async fn bytes_that_do_not_match_the_index_digest_are_refused_and_not_cached() {
        let up = upstream(&format!("#sha256={}", sha256(b"genuine")), b"tampered").await;
        let ctx = context(&up);
        for attempt in 1..=2 {
            let (status, body) = download(&ctx).await;
            assert_eq!(status, StatusCode::BAD_GATEWAY, "attempt {attempt}");
            assert_ne!(body, b"tampered", "attempt {attempt}");
        }
        assert!(
            ctx.state
                .storage
                .stat(&format!("pypi/hm/{FILE}"))
                .await
                .is_none(),
            "refused bytes are not cached"
        );
    }

    #[tokio::test]
    async fn bytes_that_match_the_index_digest_are_served() {
        // The digest as the index writes it, any case.
        for digest in [sha256(b"genuine"), sha256(b"genuine").to_uppercase()] {
            let up = upstream(&format!("#sha256={digest}"), b"genuine").await;
            let ctx = context(&up);
            assert_eq!(
                download(&ctx).await,
                (StatusCode::OK, b"genuine".to_vec()),
                "{digest}"
            );
        }
    }

    /// An index that publishes no sha256 for the file leaves nothing to check it against.
    #[tokio::test]
    async fn a_file_the_index_gives_no_sha256_for_is_served() {
        for fragment in ["", "#md5=0123456789abcdef0123456789abcdef"] {
            let up = upstream(fragment, b"bytes").await;
            let ctx = context(&up);
            assert_eq!(download(&ctx).await.0, StatusCode::OK, "{fragment:?}");
        }
    }

    /// Every key the store holds that names the file — the file, its digest, its hash marker —
    /// once no work the downloads so far started is still running.
    async fn stored_under_file(ctx: &TestContext, holders: usize) -> Vec<String> {
        background_writes_done(&ctx.state.storage, holders).await;
        let keys = ctx.state.storage.list("").await.unwrap();
        keys.into_iter().filter(|k| k.contains(FILE)).collect()
    }

    /// A digest is the whole sha256 the index gives: an empty, shortened or lengthened one, or
    /// any part of the bytes' own, matches nothing — the bytes are refused and not cached.
    #[tokio::test]
    async fn only_the_whole_index_digest_matches() {
        let own = sha256(b"tampered");
        for fragment in [
            "#sha256=".to_string(),
            format!("#sha256={}", &own[..8]),
            format!("#sha256={}", &own[..63]),
            format!("#sha256={}", &own[1..]),
            format!("#sha256={own}00"),
        ] {
            let up = upstream(&fragment, b"tampered").await;
            let ctx = context(&up);
            let holders = ctx.state.storage.holders();
            let (status, body) = download(&ctx).await;
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{fragment}");
            assert_ne!(body, b"tampered", "{fragment}");
            let stored = stored_under_file(&ctx, holders).await;
            assert!(stored.is_empty(), "{fragment}: {stored:?}");
        }
    }

    /// Refused bytes are written nowhere: not by the request, nor by any work it leaves running.
    /// The control: bytes that match are written by that same background work, which the wait
    /// sees through.
    #[tokio::test]
    async fn refused_bytes_leave_nothing_in_the_store() {
        let up = upstream(&format!("#sha256={}", sha256(b"genuine")), b"tampered").await;
        let ctx = context(&up);
        let holders = ctx.state.storage.holders();
        assert_eq!(download(&ctx).await.0, StatusCode::BAD_GATEWAY);
        let stored = stored_under_file(&ctx, holders).await;
        assert!(stored.is_empty(), "refused bytes stored: {stored:?}");

        let up = upstream(&format!("#sha256={}", sha256(b"genuine")), b"genuine").await;
        let ctx = context(&up);
        let holders = ctx.state.storage.holders();
        assert_eq!(download(&ctx).await.0, StatusCode::OK);
        let stored = stored_under_file(&ctx, holders).await;
        for key in [format!("pypi/hm/{FILE}"), format!("pypi/hm/{FILE}.sha256")] {
            assert!(stored.contains(&key), "control: {key} not in {stored:?}");
        }
    }
}
