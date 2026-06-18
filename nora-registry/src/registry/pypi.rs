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
use crate::registry::{
    circuit_open_response, method_not_allowed, nora_base_url, proxy_fetch, proxy_fetch_text,
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
    let prefix = format!("pypi/{}/", normalized);
    let base_url = nora_base_url(&state);

    // Collect local files with their hashes
    let keys = match state.storage.list(&prefix).await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = ?e, "pypi: failed to list storage for package versions");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let mut local_files: Vec<FileEntry> = Vec::new();
    for key in &keys {
        if let Some(filename) = key.strip_prefix(&prefix) {
            if !filename.is_empty() && !ends_with_ci(filename, ".sha256") {
                let sha256 = state
                    .storage
                    .get(&format!("{}.sha256", key))
                    .await
                    .ok()
                    .and_then(|d| String::from_utf8(d.to_vec()).ok());
                local_files.push(FileEntry {
                    filename: filename.to_string(),
                    sha256,
                });
            }
        }
    }

    // When proxy is configured, fetch upstream index and merge with local files.
    // This fixes the case where a cp314 wheel is cached but pip 3.10 needs to
    // see the full upstream file list to find a compatible cp310 wheel.
    // Fetch each configured upstream's index and merge them (#663). Precedence is
    // the upstream order: the first upstream that lists a file wins (local files
    // win over all upstreams). One upstream's failure or open breaker must not
    // sink the others — skip it and serve the merge of what answered.
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
    let mut circuit_open = false;
    if !is_internal && !upstreams.is_empty() {
        let mut upstream_files: Vec<FileEntry> = Vec::new();
        for up in &upstreams {
            let url = format!("{}/{}/", up.url().trim_end_matches('/'), normalized);
            match proxy_fetch_text(
                &state.http_client,
                &url,
                Duration::from_secs(state.config.pypi.proxy_timeout),
                up.auth(),
                Some(("Accept", "text/html")),
                &state.circuit_breaker,
                RegistryType::PyPI,
            )
            .await
            {
                Ok(html) => upstream_files.extend(parse_upstream_files(&html)),
                Err(crate::registry::ProxyError::CircuitOpen(_)) => {
                    circuit_open = true;
                    continue;
                }
                Err(e) => {
                    tracing::debug!(error = ?e, package = %normalized, upstream = %up.url(), "PyPI upstream index fetch failed, skipping");
                    continue;
                }
            }
        }
        let merged = merge_file_lists(upstream_files, &local_files);
        if !merged.is_empty() {
            return if wants_json(&headers) {
                versions_json_response(&normalized, &merged, &base_url)
            } else {
                versions_html_response(&normalized, &merged, &base_url)
            };
        }
    }

    // Local files only — degrade gracefully when upstreams list nothing or are down.
    if !local_files.is_empty() {
        return if wants_json(&headers) {
            versions_json_response(&normalized, &local_files, &base_url)
        } else {
            versions_html_response(&normalized, &local_files, &base_url)
        };
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
    // pip's negative cache.
    if circuit_open {
        return circuit_open_response(RegistryType::PyPI.as_str());
    }

    StatusCode::NOT_FOUND.into_response()
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

    // Curation check — before storage access
    let version = crate::curation::parse_pypi_version(&normalized, &filename);

    // Extract publish date from cached PyPI metadata
    let publish_date = if let Some(ref ver) = version {
        let meta_key = format!("pypi/{}/metadata.json", normalized);
        extract_pypi_publish_date(
            &state.storage,
            &meta_key,
            ver,
            state.config.server.trust_upstream_dates,
        )
        .await
    } else {
        None
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
            version.as_deref(),
            publish_date,
        ) {
            return response;
        }
    }

    let key = format!("pypi/{}/{}", normalized, filename);

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

    // Try local storage first. get_verified discharges the integrity witness at
    // the serve site (compile-time guarantee — see crate::verified).
    if let Ok(outcome) = state.storage.get_verified(&key).await {
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
            "pypi",
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "api", "", "pypi", ""));

        if let Some(resp) = crate::digest_quarantine::proxy_gate(
            &state.digest_store,
            "pypi",
            &data,
            &q_mode,
            q_secs,
            "cache",
        ) {
            return resp;
        }

        let content_type = pypi_content_type(&filename);
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            data,
        )
            .into_response();
    }

    // #733: an internal-namespace package with no local copy is never proxied upstream.
    if internal {
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::PyPI,
            &normalized,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // Try each configured upstream in order; the first whose index lists the file
    // serves it, fetched from that same upstream with that upstream's auth. One
    // upstream's failure or open breaker skips to the next rather than failing (#663).
    let mut circuit_open = false;
    for up in &state.config.pypi.upstreams() {
        let page_url = format!("{}/{}/", up.url().trim_end_matches('/'), normalized);

        let html = match proxy_fetch_text(
            &state.http_client,
            &page_url,
            Duration::from_secs(state.config.pypi.proxy_timeout),
            up.auth(),
            Some(("Accept", "text/html")),
            &state.circuit_breaker,
            RegistryType::PyPI,
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
                continue;
            }
        };

        // The file may live on a later upstream — keep walking the list.
        let Some(file_url) = find_file_url(&html, &filename) else {
            continue;
        };

        match proxy_fetch(
            &state.http_client,
            &file_url,
            Duration::from_secs(state.config.pypi.proxy_timeout),
            up.auth(),
            &state.circuit_breaker,
            RegistryType::PyPI,
        )
        .await
        {
            Ok(data) => {
                state.metrics.record_download("pypi");
                state.metrics.record_cache_miss("pypi");
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{}/{}", name, filename),
                    "pypi",
                    "PROXY",
                ));
                state
                    .audit
                    .log(AuditEntry::new("proxy_fetch", "api", "", "pypi", ""));

                // Cache in background + compute hash, invalidate AFTER write
                let storage = state.storage.clone();
                let key_clone = key.clone();
                let data_clone = data.clone();
                let repo_index = Arc::clone(&state.repo_index);
                tokio::spawn(async move {
                    if storage.put(&key_clone, &data_clone).await.is_ok() {
                        let hash = hex::encode(sha2::Sha256::digest(&data_clone));
                        let _ = storage
                            .put(&format!("{}.sha256", key_clone), hash.as_bytes())
                            .await;
                        repo_index.invalidate("pypi");
                    }
                });

                if let Some(resp) = crate::digest_quarantine::proxy_gate(
                    &state.digest_store,
                    "pypi",
                    &data,
                    &q_mode,
                    q_secs,
                    &file_url,
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
                continue;
            }
        }
    }

    // A tripped breaker means an upstream is temporarily down — 503 (retryable)
    // rather than 404, which would poison pip's negative cache.
    if circuit_open {
        return circuit_open_response(RegistryType::PyPI.as_str());
    }

    StatusCode::NOT_FOUND.into_response()
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
    let file_key = format!("pypi/{}/{}", normalized, filename);
    let lock = state.publish_lock(&file_key);
    let _guard = lock.lock().await;

    // Check immutability (same filename = already exists)
    if state.storage.stat(&file_key).await.is_some() {
        return (
            StatusCode::CONFLICT,
            format!("File {} already exists", filename),
        )
            .into_response();
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

    state.metrics.record_upload("pypi");
    let artifact = format!("{}-{}", name, version);
    state
        .audit
        .log(AuditEntry::new("push", "api", &artifact, "pypi", ""));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        artifact,
        "pypi",
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
    files: Vec<Pep691File>,
}

#[derive(serde::Serialize)]
struct Pep691Meta {
    #[serde(rename = "api-version")]
    api_version: &'static str,
}

/// PEP 691 file entry — field `hashes` (NOT `digests`) per spec.
#[derive(serde::Serialize)]
struct Pep691File {
    filename: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<Pep691Hashes>,
}

#[derive(serde::Serialize)]
struct Pep691Hashes {
    sha256: String,
}

fn versions_json_response(normalized: &str, files: &[FileEntry], base_url: &str) -> Response {
    let base = base_url.trim_end_matches('/');
    let pep691_files: Vec<Pep691File> = files
        .iter()
        .map(|f| Pep691File {
            filename: f.filename.clone(),
            url: format!("{}/simple/{}/{}", base, normalized, f.filename),
            hashes: f
                .sha256
                .as_ref()
                .map(|h| Pep691Hashes { sha256: h.clone() }),
        })
        .collect();

    let body = Pep691Response {
        meta: Pep691Meta { api_version: "1.0" },
        name: normalized,
        files: pep691_files,
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, PEP691_JSON)],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response()
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

/// Extract publish date for a specific version from cached PyPI metadata.
///
/// PyPI metadata JSON has `releases` mapping versions to file arrays:
/// ```json
/// { "releases": { "1.0.0": [{ "upload_time_iso_8601": "2024-01-15T10:30:00Z" }] } }
/// ```
async fn extract_pypi_publish_date(
    storage: &crate::storage::Storage,
    metadata_key: &str,
    version: &str,
    trust_upstream: bool,
) -> Option<i64> {
    // #513: untrusted upstream dates → use NORA's own cache mtime, never the
    // (spoofable) upstream upload_time.
    if !trust_upstream {
        return crate::curation::extract_mtime_as_publish_date(storage, metadata_key).await;
    }
    let data = storage.get(metadata_key).await.ok()?;
    let json: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let files = json.get("releases")?.get(version)?.as_array()?;
    let date_str = files.first()?.get("upload_time_iso_8601")?.as_str()?;
    crate::curation::parse_iso8601_to_unix(date_str)
}

/// Normalize package name according to PEP 503.
fn normalize_name(name: &str) -> String {
    name.to_lowercase().replace(['-', '_', '.'], "-")
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

/// Validate PyPI filename.
fn is_valid_pypi_filename(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && (ends_with_ci(name, ".tar.gz")
            || ends_with_ci(name, ".tgz")
            || ends_with_ci(name, ".whl")
            || ends_with_ci(name, ".zip")
            || ends_with_ci(name, ".egg"))
}

/// Extract filename from PyPI download URL.
fn extract_filename(url: &str) -> Option<&str> {
    let url = url.split('#').next()?;
    let filename = url.rsplit('/').next()?;

    if ends_with_ci(filename, ".tar.gz")
        || ends_with_ci(filename, ".tgz")
        || ends_with_ci(filename, ".whl")
        || ends_with_ci(filename, ".zip")
        || ends_with_ci(filename, ".egg")
    {
        Some(filename)
    } else {
        None
    }
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
fn find_file_url(html: &str, target_filename: &str) -> Option<String> {
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
                    return Some(url.split('#').next().unwrap_or(url).to_string());
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
            find_file_url(html, "torch-2.4.0+cu124-cp310-cp310-linux_x86_64.whl").as_deref(),
            Some(
                "https://download.pytorch.org/whl/cu124/torch-2.4.0%2Bcu124-cp310-cp310-linux_x86_64.whl"
            )
        );
        // A plain filename (no encoding) still matches.
        let plain = r#"<a href="https://x/torch-0.1.10-cp36-cp36m-macosx.whl">x</a>"#;
        assert_eq!(
            find_file_url(plain, "torch-0.1.10-cp36-cp36m-macosx.whl").as_deref(),
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
        let result = find_file_url(html, "flask-2.0.tar.gz");
        assert_eq!(
            result,
            Some("https://files.pythonhosted.org/packages/aa/bb/flask-2.0.tar.gz".to_string())
        );
    }

    #[test]
    fn test_find_file_url_not_found() {
        let html = r#"<a href="https://example.com/other-1.0.tar.gz">other</a>"#;
        let result = find_file_url(html, "flask-2.0.tar.gz");
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_file_url_strips_hash() {
        let html = r#"<a href="https://example.com/pkg-1.0.whl#sha256=deadbeef">pkg</a>"#;
        let result = find_file_url(html, "pkg-1.0.whl");
        assert_eq!(result, Some("https://example.com/pkg-1.0.whl".to_string()));
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
    use axum::http::{Method, StatusCode};

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
    async fn test_pypi_not_found_no_proxy() {
        let ctx = create_test_context();

        let response = send(&ctx.app, Method::GET, "/simple/nonexistent/", "").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
        let response = versions_json_response("pkg", &files, "http://nora:4000");
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

    /// PEP 691 requires `meta.api-version` field.
    #[test]
    fn test_pep691_meta_api_version() {
        let files = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: None,
        }];
        let response = versions_json_response("pkg", &files, "http://nora:4000");
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(
            json["meta"]["api-version"], "1.0",
            "PEP 691 requires meta.api-version = '1.0'"
        );
    }

    /// PEP 691 JSON Content-Type must be `application/vnd.pypi.simple.v1+json`.
    #[test]
    fn test_pep691_content_type() {
        let files = vec![];
        let response = versions_json_response("pkg", &files, "http://nora:4000");
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

    /// PEP 691: `hashes` field must be omitted when no hash is available,
    /// not set to null or empty object.
    #[test]
    fn test_pep691_hashes_omitted_when_none() {
        let files = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: None,
        }];
        let response = versions_json_response("pkg", &files, "http://nora:4000");
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert!(
            json["files"][0].get("hashes").is_none(),
            "hashes must be omitted (not null) when no hash available"
        );
    }

    /// PEP 691: `name` field must match the normalized package name.
    #[test]
    fn test_pep691_name_is_normalized() {
        let files = vec![];
        let normalized = normalize_name("Flask-RESTful");
        let response = versions_json_response(&normalized, &files, "http://nora:4000");
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
        let response = versions_json_response("pkg", &files, "http://nora:4000");
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
        let response = versions_json_response("pkg", &files, "http://nora:4000/");
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
        let response = versions_json_response("empty-pkg", &files, "http://nora:4000");
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
        let response = versions_json_response("pkg", &files, "http://nora:4000");
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
