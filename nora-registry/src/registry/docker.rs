// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::circuit_breaker::CircuitBreakerRegistry;
use crate::config::basic_auth_header;
use crate::registry::docker_auth::DockerAuth;
use crate::registry::{circuit_open_response, method_not_allowed, ProxyError};
use crate::storage::Storage;
use crate::validation::{
    ends_with_ci, validate_digest, validate_docker_name, validate_docker_reference,
};
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderName, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use futures::StreamExt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Namespaced key builders (issue #323)
// ============================================================================

/// Build a namespaced storage key for Docker blobs.
///
/// With namespace: `docker/{ns}/{name}/blobs/{digest}`
/// Without (local push): `docker/{name}/blobs/{digest}`
fn blob_key(namespace: Option<&str>, name: &str, digest: &str) -> String {
    match namespace {
        Some(ns) => format!("docker/{}/{}/blobs/{}", ns, name, digest),
        None => format!("docker/{}/blobs/{}", name, digest),
    }
}

/// Build a namespaced storage key for Docker manifests.
fn manifest_key(namespace: Option<&str>, name: &str, reference: &str) -> String {
    match namespace {
        Some(ns) => format!("docker/{}/{}/manifests/{}.json", ns, name, reference),
        None => format!("docker/{}/manifests/{}.json", name, reference),
    }
}

/// Build a namespaced storage key for Docker manifest metadata.
fn manifest_meta_key(namespace: Option<&str>, name: &str, reference: &str) -> String {
    match namespace {
        Some(ns) => format!("docker/{}/{}/manifests/{}.meta.json", ns, name, reference),
        None => format!("docker/{}/manifests/{}.meta.json", name, reference),
    }
}

/// Build a namespaced storage key prefix for listing manifests.
fn manifest_prefix(namespace: Option<&str>, name: &str) -> String {
    match namespace {
        Some(ns) => format!("docker/{}/{}/manifests/", ns, name),
        None => format!("docker/{}/manifests/", name),
    }
}

/// Result of Docker image name canonicalization.
///
/// Unifies both config-aware prefix routing and hostname-based namespace
/// detection into a single entry point, eliminating the asymmetry between
/// write-path (former `resolve_upstream`) and read-path (`strip_docker_namespace`).
pub(crate) struct Canonical {
    /// Cleaned image name (prefix/hostname stripped).
    pub name: String,
    /// Namespace for storage key construction (e.g. `"docker.io"`).
    pub namespace: Option<String>,
    /// Index of the prefix-matched upstream in the config, if any.
    matched_upstream_idx: Option<usize>,
}

impl Canonical {
    /// Get the list of upstreams to try for fetching this image.
    ///
    /// If a specific upstream was matched by prefix, returns only that one.
    /// Otherwise returns all configured upstreams (fallback chain).
    pub fn upstreams_to_try<'a>(
        &self,
        upstreams: &'a [crate::config::DockerUpstream],
    ) -> Vec<&'a crate::config::DockerUpstream> {
        match self.matched_upstream_idx {
            Some(idx) => vec![&upstreams[idx]],
            None => upstreams.iter().collect(),
        }
    }
}

/// Canonicalize a Docker image name: resolve upstream, strip prefix/hostname,
/// and determine the storage namespace.
///
/// This is the single entry point for Docker name resolution. Use instead of
/// the heuristic `strip_docker_namespace()` whenever upstream config is available.
///
/// Resolution order (early-return):
/// 1. Prefix match — first path segment matches a configured upstream prefix
/// 2. Hostname detection — first segment contains a dot (FQDN like `docker.io`)
/// 3. Fallback — use the first configured upstream, keep name as-is
pub(crate) fn canonicalize(
    raw_name: &str,
    upstreams: &[crate::config::DockerUpstream],
) -> Canonical {
    // Step 1: Check for prefix-based routing
    if let Some((first_segment, rest)) = raw_name.split_once('/') {
        for (idx, upstream) in upstreams.iter().enumerate() {
            if let Some(ref prefix) = upstream.prefix {
                if first_segment == prefix {
                    tracing::debug!(
                        prefix = %prefix,
                        upstream = %upstream.url,
                        stripped_name = %rest,
                        routing = "prefix",
                        "Docker path-based upstream routing"
                    );
                    return Canonical {
                        name: rest.to_string(),
                        namespace: Some(upstream.resolved_namespace()),
                        matched_upstream_idx: Some(idx),
                    };
                }
            }
        }

        // Step 2: Hostname detection (dot in first segment = FQDN)
        if first_segment.contains('.') && !rest.is_empty() {
            // Check if it matches a known upstream's namespace
            for (idx, upstream) in upstreams.iter().enumerate() {
                let ns = upstream.resolved_namespace();
                if first_segment == ns {
                    return Canonical {
                        name: rest.to_string(),
                        namespace: Some(ns),
                        matched_upstream_idx: Some(idx),
                    };
                }
            }
            // Unknown hostname — strip it but use default upstream
            let ns = upstreams.first().map(|u| u.resolved_namespace());
            return Canonical {
                name: rest.to_string(),
                namespace: ns,
                matched_upstream_idx: None,
            };
        }
    }

    // Step 3: Fallback — first upstream, name unchanged
    let ns = upstreams.first().map(|u| u.resolved_namespace());
    Canonical {
        name: raw_name.to_string(),
        namespace: ns,
        matched_upstream_idx: None,
    }
}

/// Try to get content from namespaced key, falling back to legacy (non-namespaced) key.
///
/// This provides backward compatibility during migration from flat to namespaced storage.
async fn storage_get_with_fallback(
    storage: &Storage,
    ns_key: &str,
    legacy_key: &str,
) -> Result<Bytes, crate::storage::StorageError> {
    match storage.get(ns_key).await {
        Ok(data) => Ok(data),
        Err(_) if ns_key != legacy_key => storage.get(legacy_key).await,
        Err(e) => Err(e),
    }
}

/// Check if a key exists in namespaced or legacy location.
async fn storage_stat_with_fallback(
    storage: &Storage,
    ns_key: &str,
    legacy_key: &str,
) -> Option<crate::storage::FileMeta> {
    if let Some(meta) = storage.stat(ns_key).await {
        return Some(meta);
    }
    if ns_key != legacy_key {
        return storage.stat(legacy_key).await;
    }
    None
}

/// Metadata for a Docker image stored alongside manifests
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImageMetadata {
    pub push_timestamp: u64,
    pub last_pulled: u64,
    pub downloads: u64,
    pub size_bytes: u64,
    pub os: String,
    pub arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub layers: Vec<LayerInfo>,
}

/// Information about a single layer in a Docker image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerInfo {
    pub digest: String,
    pub size: u64,
}

/// In-progress upload session with metadata.
///
/// Blob data is streamed to a temporary file instead of being buffered in memory.
/// This prevents 100 concurrent 2GB uploads from consuming 200GB of RAM.
pub struct UploadSession {
    /// Path to the temporary file holding blob data.
    temp_path: std::path::PathBuf,
    /// Current size of data written to temp file.
    size: u64,
    name: String,
    created_at: std::time::Instant,
}

/// Max concurrent upload sessions (prevent memory exhaustion)
const DEFAULT_MAX_UPLOAD_SESSIONS: usize = 100;
/// Max data per session (default 2 GB, configurable via NORA_MAX_UPLOAD_SESSION_SIZE_MB)
const DEFAULT_MAX_SESSION_SIZE_MB: usize = 2048;
/// Session TTL (30 minutes)
const SESSION_TTL: Duration = Duration::from_secs(30 * 60);

/// Read max upload sessions from env or use default
fn max_upload_sessions() -> usize {
    std::env::var("NORA_MAX_UPLOAD_SESSIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_UPLOAD_SESSIONS)
}

/// Read max session size from env (in MB) or use default
fn max_session_size() -> usize {
    let mb = std::env::var("NORA_MAX_UPLOAD_SESSION_SIZE_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_SESSION_SIZE_MB);
    mb.saturating_mul(1024 * 1024)
}

/// Remove expired upload sessions and their temp files (called by background task)
pub fn cleanup_expired_sessions(sessions: &RwLock<HashMap<String, UploadSession>>) {
    let mut guard = sessions.write();
    let before = guard.len();
    guard.retain(|_, s| {
        if s.created_at.elapsed() >= SESSION_TTL {
            let _ = std::fs::remove_file(&s.temp_path);
            false
        } else {
            true
        }
    });
    let removed = before - guard.len();
    if removed > 0 {
        tracing::info!(
            removed = removed,
            remaining = guard.len(),
            "Cleaned up expired upload sessions"
        );
    }
}

/// Get the temp directory for Docker uploads, creating it if needed.
fn upload_temp_dir(data_dir: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(data_dir).join("tmp/docker-uploads");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::error!(path = %dir.display(), error = %e, "failed to create upload temp directory");
    }
    dir
}

/// Resolve effective quarantine mode and TTL (seconds) for Docker.
///
/// Returns `(QuarantineMode, quarantine_secs)`. Per-registry override takes
/// precedence over global curation config. Returns `(Off, 0)` when disabled.
fn resolve_quarantine(state: &AppState) -> (crate::digest_quarantine::QuarantineMode, i64) {
    use crate::digest_quarantine::QuarantineMode;

    let mode_str = state
        .config
        .curation
        .docker
        .quarantine
        .as_deref()
        .or(state.config.curation.quarantine.as_deref())
        .unwrap_or("off");

    let mode = QuarantineMode::from_str_lossy(mode_str);
    if matches!(mode, QuarantineMode::Off) {
        return (QuarantineMode::Off, 0);
    }

    let ttl_str = state
        .config
        .curation
        .docker
        .quarantine_ttl
        .as_deref()
        .or(state.config.curation.quarantine_ttl.as_deref())
        .unwrap_or("14d");

    let secs = crate::curation::parse_duration(ttl_str).unwrap_or(14 * 86400);
    (mode, secs)
}

/// Build an HTTP 403 response for a quarantined digest.
fn quarantine_forbidden(
    digest: &str,
    status: &crate::digest_quarantine::QuarantineStatus,
    quarantine_secs: i64,
) -> Response {
    let remaining = match status {
        crate::digest_quarantine::QuarantineStatus::New => quarantine_secs,
        crate::digest_quarantine::QuarantineStatus::Pending { remaining_secs } => *remaining_secs,
        crate::digest_quarantine::QuarantineStatus::Mature => 0,
    };
    let quarantine_until = chrono::Utc::now().timestamp() + remaining;

    let body = json!({
        "errors": [{
            "code": "DENIED",
            "message": "digest is in quarantine",
            "detail": {
                "digest": digest,
                "quarantine_until": quarantine_until,
            }
        }]
    });

    (
        StatusCode::FORBIDDEN,
        [
            (
                HeaderName::from_static("x-nora-quarantine"),
                status.header_value(),
            ),
            (header::CONTENT_TYPE, "application/json"),
        ],
        body.to_string(),
    )
        .into_response()
}

/// Docker v2 routes.
/// Uses a `{*rest}` wildcard to support image names with arbitrary path depth
/// (e.g., `library/astra/ubi18-cpp122`), per OCI Distribution spec.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/v2/",
            get(check).fallback(|| async { method_not_allowed("GET") }),
        )
        .route("/v2/_catalog", get(catalog))
        .route("/v2/{*rest}", axum::routing::any(docker_v2_dispatch))
}

/// Unified dispatcher for all Docker v2 image endpoints.
/// Parses the image name (arbitrary depth) and operation from the wildcard path,
/// then delegates to the appropriate handler with correct method routing.
async fn docker_v2_dispatch(
    state: State<Arc<AppState>>,
    method: Method,
    Path(wildcard): Path<String>,
    uri: Uri,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let rest = wildcard.trim_start_matches('/');
    if rest.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Parse endpoint pattern from right — handles names containing "blobs", "manifests", etc.
    // Order matters: check blob uploads before blobs (substring overlap).

    // 1. Blob uploads: {name}/blobs/uploads/ or {name}/blobs/uploads/{uuid}
    if let Some((name, after)) = rest.rsplit_once("/blobs/uploads/") {
        if name.is_empty() {
            return StatusCode::NOT_FOUND.into_response();
        }
        if validate_docker_name(name).is_err() {
            return (StatusCode::BAD_REQUEST, "Invalid image name").into_response();
        }
        return if after.is_empty() {
            match method {
                Method::POST => start_upload(state, Path(name.to_string())).await,
                _ => method_not_allowed("POST"),
            }
        } else {
            match method {
                Method::PATCH => {
                    patch_blob(state, Path((name.to_string(), after.to_string())), body).await
                }
                Method::PUT => {
                    let params = parse_query_string(uri.query());
                    upload_blob(
                        state,
                        Path((name.to_string(), after.to_string())),
                        axum::extract::Query(params),
                        body,
                    )
                    .await
                }
                _ => method_not_allowed("PATCH, PUT"),
            }
        };
    }

    // 2. Blobs: {name}/blobs/{digest}
    if let Some((name, digest)) = rest.rsplit_once("/blobs/") {
        if name.is_empty() || digest.is_empty() {
            return StatusCode::NOT_FOUND.into_response();
        }
        if validate_docker_name(name).is_err() {
            return (StatusCode::BAD_REQUEST, "Invalid image name").into_response();
        }
        return match method {
            Method::HEAD => check_blob(state, Path((name.to_string(), digest.to_string()))).await,
            Method::GET => {
                download_blob(state, headers, Path((name.to_string(), digest.to_string()))).await
            }
            Method::DELETE => {
                delete_blob(state, Path((name.to_string(), digest.to_string()))).await
            }
            _ => method_not_allowed("GET, HEAD, DELETE"),
        };
    }

    // 3. Manifests: {name}/manifests/{reference}
    if let Some((name, reference)) = rest.rsplit_once("/manifests/") {
        if name.is_empty() || reference.is_empty() {
            return StatusCode::NOT_FOUND.into_response();
        }
        if validate_docker_name(name).is_err() {
            return (StatusCode::BAD_REQUEST, "Invalid image name").into_response();
        }
        return match method {
            Method::GET | Method::HEAD => {
                let resp = get_manifest(
                    state,
                    headers,
                    Path((name.to_string(), reference.to_string())),
                )
                .await;
                if method == Method::HEAD {
                    let (parts, _) = resp.into_parts();
                    Response::from_parts(parts, axum::body::Body::empty())
                } else {
                    resp
                }
            }
            Method::PUT => {
                put_manifest(state, Path((name.to_string(), reference.to_string())), body).await
            }
            Method::DELETE => {
                delete_manifest(state, Path((name.to_string(), reference.to_string()))).await
            }
            _ => method_not_allowed("GET, HEAD, PUT, DELETE"),
        };
    }

    // 4. Tags list: {name}/tags/list
    if let Some(name) = rest.strip_suffix("/tags/list") {
        if name.is_empty() {
            return StatusCode::NOT_FOUND.into_response();
        }
        if validate_docker_name(name).is_err() {
            return (StatusCode::BAD_REQUEST, "Invalid image name").into_response();
        }
        return match method {
            Method::GET => list_tags(state, Path(name.to_string())).await,
            _ => method_not_allowed("GET"),
        };
    }

    StatusCode::NOT_FOUND.into_response()
}

fn parse_query_string(query: Option<&str>) -> HashMap<String, String> {
    use percent_encoding::percent_decode_str;
    query
        .unwrap_or_default()
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((
                percent_decode_str(k).decode_utf8_lossy().into_owned(),
                percent_decode_str(v).decode_utf8_lossy().into_owned(),
            ))
        })
        .collect()
}

async fn check() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            HeaderName::from_static("docker-distribution-api-version"),
            "registry/2.0",
        )],
        Json(json!({})),
    )
}

/// Strip hostname prefix from a Docker repository name (config-free heuristic).
///
/// Detects hostnames by checking for a dot in the first path segment
/// (e.g. `docker.io/library/nginx` → `library/nginx`).
///
/// **When to use:** Only in config-free contexts like storage key classification
/// (e.g., `docker_key_migration`). For request-time routing, use [`canonicalize()`]
/// which is config-aware and handles prefix-based upstream matching.
pub(crate) fn strip_docker_namespace(name: &str) -> &str {
    if let Some((first, rest)) = name.split_once('/') {
        if first.contains('.') && !rest.is_empty() {
            return rest;
        }
    }
    name
}

/// List all repositories in the registry
async fn catalog(State(state): State<Arc<AppState>>) -> Json<Value> {
    let keys = state.storage.list("docker/").await;

    // Extract unique repository names from paths like "docker/{name}/manifests/..."
    let mut repos: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            let rest = k.strip_prefix("docker/")?;
            // Find the first known directory separator (manifests/ or blobs/)
            let name = if let Some(idx) = rest.find("/manifests/") {
                &rest[..idx]
            } else if let Some(idx) = rest.find("/blobs/") {
                &rest[..idx]
            } else {
                return None;
            };
            if name.is_empty() {
                return None;
            }
            // Canonicalize to strip upstream namespace prefix (e.g. "docker.io/")
            // so that images proxied through different upstreams are deduplicated.
            Some(canonicalize(name, &state.config.docker.upstreams).name)
        })
        .collect();

    repos.sort();
    repos.dedup();

    Json(json!({ "repositories": repos }))
}

async fn check_blob(
    State(state): State<Arc<AppState>>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker.upstreams);
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = blob_key(c.namespace.as_deref(), &name, &digest);
    let legacy_key = blob_key(None, &name, &digest);
    match storage_get_with_fallback(&state.storage, &key, &legacy_key).await {
        Ok(data) => (
            StatusCode::OK,
            [(header::CONTENT_LENGTH, data.len().to_string())],
        )
            .into_response(),
        Err(crate::storage::StorageError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, key = %key, "Failed to check blob existence");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn download_blob(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker.upstreams);
    let upstreams_to_try = c.upstreams_to_try(&state.config.docker.upstreams);
    let ns = c.namespace;
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Curation check — defense in depth: check blobs too
    if let Some(response) = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        crate::curation::RegistryType::Docker,
        &name,
        Some(&digest),
        None,
    ) {
        return response;
    }

    let key = blob_key(ns.as_deref(), &name, &digest);
    let legacy_key = blob_key(None, &name, &digest);

    // Try local storage first (namespaced key, then legacy fallback)
    if let Ok(data) = storage_get_with_fallback(&state.storage, &key, &legacy_key).await {
        // Curation integrity verification (issue #189)
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Docker,
            &name,
            Some(&digest),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("docker");
        state.metrics.record_cache_hit("docker");
        state.activity.push(ActivityEntry::new(
            ActionType::Pull,
            format!("{}@{}", name, &digest[..19.min(digest.len())]),
            "docker",
            "LOCAL",
        ));
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            data,
        )
            .into_response();
    }

    // Try upstream proxies (prefix-matched → single upstream, otherwise → fallback chain)
    for upstream in &upstreams_to_try {
        match fetch_blob_from_upstream(
            &state.http_client,
            &upstream.url,
            &name,
            &digest,
            &state.docker_auth,
            state.config.docker.proxy_timeout,
            state.config.docker.read_timeout,
            upstream.auth.as_deref(),
            &state.circuit_breaker,
        )
        .await
        {
            Ok(data) => {
                state.metrics.record_download("docker");
                state.metrics.record_cache_miss("docker");
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{}@{}", name, &digest[..19.min(digest.len())]),
                    "docker",
                    "PROXY",
                ));

                // Cache in storage (fire and forget, panic-safe)
                state.spawn_cache("docker", key.clone(), Bytes::from(data.clone()));

                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/octet-stream")],
                    Bytes::from(data),
                )
                    .into_response();
            }
            Err(ProxyError::CircuitOpen(reg)) => return circuit_open_response(&reg),
            Err(e) => {
                tracing::debug!(error = ?e, upstream = %upstream.url, name = %name, "Docker blob proxy fetch failed, trying next");
                continue;
            }
        }
    }

    // Auto-prepend library/ for single-segment names (Docker Hub official images)
    if !name.contains('/') {
        let library_name = format!("library/{}", name);
        for upstream in &upstreams_to_try {
            match fetch_blob_from_upstream(
                &state.http_client,
                &upstream.url,
                &library_name,
                &digest,
                &state.docker_auth,
                state.config.docker.proxy_timeout,
                state.config.docker.read_timeout,
                upstream.auth.as_deref(),
                &state.circuit_breaker,
            )
            .await
            {
                Ok(data) => {
                    state.spawn_cache("docker", key.clone(), Bytes::from(data.clone()));

                    return (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/octet-stream")],
                        Bytes::from(data),
                    )
                        .into_response();
                }
                Err(ProxyError::CircuitOpen(reg)) => return circuit_open_response(&reg),
                Err(e) => {
                    tracing::debug!(error = ?e, upstream = %upstream.url, name = %library_name, "Docker blob proxy fetch failed, trying next");
                    continue;
                }
            }
        }
    }

    if !state.config.docker.upstreams.is_empty() {
        tracing::warn!(registry = "docker", name = %name, digest = %digest, "Proxy failed, returning 404");
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn start_upload(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    let name = canonicalize(&name, &state.config.docker.upstreams).name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let uuid = uuid::Uuid::new_v4().to_string();

    // Create temp file for blob data
    let temp_dir = upload_temp_dir(&state.config.storage.path);
    let temp_path = temp_dir.join(&uuid);

    // Single write lock: check limit + insert atomically (no TOCTOU)
    {
        let mut sessions = state.upload_sessions.write();
        let max_sessions = max_upload_sessions();
        if sessions.len() >= max_sessions {
            tracing::warn!(
                max = max_sessions,
                current = sessions.len(),
                "Upload session limit reached — rejecting new upload"
            );
            return (StatusCode::TOO_MANY_REQUESTS, "Too many concurrent uploads").into_response();
        }
        sessions.insert(
            uuid.clone(),
            UploadSession {
                temp_path,
                size: 0,
                name: name.clone(),
                created_at: std::time::Instant::now(),
            },
        );
    }

    let location = format!("/v2/{}/blobs/uploads/{}", name, uuid);
    (
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, location),
            (HeaderName::from_static("docker-upload-uuid"), uuid),
        ],
    )
        .into_response()
}

/// PATCH handler for chunked blob uploads
/// Docker client sends data chunks via PATCH, then finalizes with PUT
async fn patch_blob(
    State(state): State<Arc<AppState>>,
    Path((name, uuid)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let name = canonicalize(&name, &state.config.docker.upstreams).name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Phase 1: Validate session under lock, extract temp_path (no file I/O)
    let (temp_path, new_size) = {
        let mut sessions = state.upload_sessions.write();
        let session = match sessions.get_mut(&uuid) {
            Some(s) => s,
            None => {
                return (StatusCode::NOT_FOUND, "Upload session not found or expired")
                    .into_response();
            }
        };

        // Verify session belongs to this repository
        if session.name != name {
            tracing::warn!(
                session_name = %session.name,
                request_name = %name,
                "SECURITY: upload session name mismatch — possible session fixation"
            );
            return (
                StatusCode::BAD_REQUEST,
                "Session does not belong to this repository",
            )
                .into_response();
        }

        // Check session TTL
        if session.created_at.elapsed() >= SESSION_TTL {
            let _ = std::fs::remove_file(&session.temp_path);
            sessions.remove(&uuid);
            return (StatusCode::NOT_FOUND, "Upload session expired").into_response();
        }

        // Check size limit
        let new_size = session.size as usize + body.len();
        if new_size > max_session_size() {
            let _ = std::fs::remove_file(&session.temp_path);
            sessions.remove(&uuid);
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload session exceeds size limit",
            )
                .into_response();
        }

        (session.temp_path.clone(), new_size)
    }; // lock released before file I/O

    // Phase 2: Append to temp file outside lock (non-blocking)
    {
        use tokio::io::AsyncWriteExt;
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&temp_path)
            .await;
        match file {
            Ok(mut f) => {
                if let Err(e) = f.write_all(&body).await {
                    tracing::error!(error = %e, "Failed to write to upload temp file");
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    state.upload_sessions.write().remove(&uuid);
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                // Flush to ensure data is visible to subsequent reads (e.g.
                // the PUT handler that finalizes this upload). Without an
                // explicit flush, data may remain in OS page cache only and
                // can be invisible on overlay-fs / CI runners under I/O
                // pressure.
                if let Err(e) = f.flush().await {
                    tracing::error!(error = %e, "Failed to flush upload temp file");
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    state.upload_sessions.write().remove(&uuid);
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to open upload temp file");
                let _ = tokio::fs::remove_file(&temp_path).await;
                state.upload_sessions.write().remove(&uuid);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }

    // Phase 3: Update session size (brief lock, no I/O)
    {
        let mut sessions = state.upload_sessions.write();
        if let Some(session) = sessions.get_mut(&uuid) {
            session.size = new_size as u64;
        }
    }

    let total_size = new_size;

    let location = format!("/v2/{}/blobs/uploads/{}", name, uuid);
    // Range header indicates bytes 0 to (total_size - 1) have been received
    let range = if total_size > 0 {
        format!("0-{}", total_size - 1)
    } else {
        "0-0".to_string()
    };

    (
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, location),
            (header::RANGE, range),
            (HeaderName::from_static("docker-upload-uuid"), uuid),
        ],
    )
        .into_response()
}

/// PUT handler for completing blob uploads
/// Handles both monolithic uploads (body contains all data) and
/// chunked upload finalization (body may be empty, data in session)
async fn upload_blob(
    State(state): State<Arc<AppState>>,
    Path((name, uuid)): Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> Response {
    let name = canonicalize(&name, &state.config.docker.upstreams).name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let digest = match params.get("digest") {
        Some(d) => d,
        None => return (StatusCode::BAD_REQUEST, "Missing digest parameter").into_response(),
    };

    if let Err(e) = validate_digest(digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Remove session from map under brief lock, then do file I/O outside
    let session_opt = {
        let mut sessions = state.upload_sessions.write();
        sessions.remove(&uuid)
    }; // lock released before file I/O

    // Only sha256 digests are supported for verification
    if !digest.starts_with("sha256:") {
        return (
            StatusCode::BAD_REQUEST,
            "Only sha256 digests are supported for blob uploads",
        )
            .into_response();
    }

    // Resolve temp file path: either from a PATCH session or write body to a new temp file
    let temp_path = if let Some(session) = session_opt {
        // Verify session belongs to this repository
        if session.name != name {
            tracing::warn!(
                session_name = %session.name,
                request_name = %name,
                "SECURITY: upload finalization name mismatch"
            );
            let _ = tokio::fs::remove_file(&session.temp_path).await;
            return (
                StatusCode::BAD_REQUEST,
                "Session does not belong to this repository",
            )
                .into_response();
        }
        // If PUT body is non-empty, append it to the temp file
        if !body.is_empty() {
            use tokio::io::AsyncWriteExt;
            match tokio::fs::OpenOptions::new()
                .append(true)
                .open(&session.temp_path)
                .await
            {
                Ok(mut f) => {
                    if let Err(e) = f.write_all(&body).await {
                        tracing::error!(error = %e, "Failed to append PUT body to temp file");
                        let _ = tokio::fs::remove_file(&session.temp_path).await;
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    let _ = f.flush().await;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // No temp file (no PATCH was sent) — create one with body
                    if let Err(e) = tokio::fs::write(&session.temp_path, &body).await {
                        tracing::error!(error = %e, "Failed to write temp file for PUT body");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to open temp file for append");
                    let _ = tokio::fs::remove_file(&session.temp_path).await;
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        }
        session.temp_path
    } else {
        // Monolithic upload (no session): write body to a temp file
        let temp_dir = upload_temp_dir(&state.config.storage.path);
        let temp_path = temp_dir.join(format!("mono-{}", uuid));
        if let Err(e) = tokio::fs::write(&temp_path, &body).await {
            tracing::error!(error = %e, "Failed to write monolithic upload temp file");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        temp_path
    };

    // Verify digest by streaming SHA-256 — O(chunk_size) memory, not O(blob_size)
    {
        use sha2::Digest as _;
        use tokio::io::AsyncReadExt;
        let file = match tokio::fs::File::open(&temp_path).await {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, "Failed to open temp file for digest verification");
                let _ = tokio::fs::remove_file(&temp_path).await;
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let mut reader = tokio::io::BufReader::new(file);
        let mut hasher = sha2::Sha256::new();
        let mut buf = vec![0u8; 256 * 1024]; // 256 KiB read chunks
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to read temp file for digest");
                    let _ = tokio::fs::remove_file(&temp_path).await;
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            hasher.update(&buf[..n]);
        }
        let computed = format!("sha256:{}", hex::encode(hasher.finalize()));
        if computed != *digest {
            tracing::warn!(
                expected = %digest,
                computed = %computed,
                name = %name,
                "SECURITY: blob digest mismatch — rejecting upload"
            );
            let _ = tokio::fs::remove_file(&temp_path).await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "errors": [{
                        "code": "DIGEST_INVALID",
                        "message": "provided digest did not match uploaded content",
                        "detail": { "expected": digest, "computed": computed }
                    }]
                })),
            )
                .into_response();
        }
    }

    // Move temp file into storage — no RAM copy of the blob
    let key = format!("docker/{}/blobs/{}", name, digest);
    match state.storage.put_from_path(&key, &temp_path).await {
        Ok(()) => {
            state.metrics.record_upload("docker");
            state.audit.log(AuditEntry::new(
                "push",
                "api",
                &format!("{}@{}", name, digest),
                "docker",
                "blob",
            ));
            state.activity.push(ActivityEntry::new(
                ActionType::Push,
                format!("{}@{}", name, &digest[..19.min(digest.len())]),
                "docker",
                "LOCAL",
            ));
            state.repo_index.invalidate("docker");
            let location = format!("/v2/{}/blobs/{}", name, digest);
            (
                StatusCode::CREATED,
                [
                    (header::LOCATION, location),
                    (
                        HeaderName::from_static("docker-content-digest"),
                        digest.to_string(),
                    ),
                ],
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, key = %key, name = %name, "Failed to store blob");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Try to fetch a manifest from upstream(s) and cache it locally.
///
/// Iterates over `upstreams`, fetching `upstream_name` (which may differ from
/// the user-facing `name` — e.g. `library/nginx` vs `nginx`). On success:
/// records metrics/activity, runs quarantine, spawns a cache task that writes
/// the manifest by tag, by digest, plus metadata sidecars.
///
/// Returns `Some(Response)` on first successful upstream (or quarantine block),
/// `None` if all upstreams failed.
async fn try_fetch_and_cache(
    state: &Arc<AppState>,
    upstreams: &[&crate::config::DockerUpstream],
    upstream_name: &str,
    name: &str,
    reference: &str,
    cache_key: &str,
) -> Option<Response> {
    for upstream in upstreams {
        tracing::debug!(upstream_url = %upstream.url, upstream_name = %upstream_name, "Trying upstream");
        match fetch_manifest_from_upstream(
            &state.http_client,
            &upstream.url,
            upstream_name,
            reference,
            &state.docker_auth,
            state.config.docker.proxy_timeout,
            upstream.auth.as_deref(),
            &state.circuit_breaker,
        )
        .await
        {
            Ok((data, content_type)) => {
                state.metrics.record_download("docker");
                state.metrics.record_cache_miss("docker");
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{}:{}", name, reference),
                    "docker",
                    "PROXY",
                ));

                // Calculate digest for Docker-Content-Digest header
                use sha2::Digest;
                let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));

                // Quarantine: record digest, check status
                let (q_mode, q_secs) = resolve_quarantine(state);
                if !matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
                    state.digest_store.record("docker", &digest, &upstream.url);
                    let q_status = state.digest_store.check("docker", &digest, q_secs);
                    match &q_status {
                        crate::digest_quarantine::QuarantineStatus::Mature => {}
                        _ => {
                            tracing::warn!(
                                digest = %digest,
                                upstream = %upstream.url,
                                status = %q_status.header_value(),
                                mode = ?q_mode,
                                "Quarantine: proxy-fetched manifest"
                            );
                        }
                    }
                    // In enforce mode, still cache but block the client
                    if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce)
                        && !matches!(q_status, crate::digest_quarantine::QuarantineStatus::Mature)
                    {
                        let storage = state.storage.clone();
                        let key_clone = cache_key.to_string();
                        let state_clone = Arc::clone(state);
                        tokio::spawn(async move {
                            if let Err(e) = storage.put(&key_clone, &data).await {
                                tracing::warn!(key = %key_clone, error = %e, "cache write failed (quarantine pre-cache)");
                                crate::metrics::CACHE_WRITE_ERRORS
                                    .with_label_values(&["docker", "manifest"])
                                    .inc();
                            }
                            state_clone.repo_index.invalidate("docker");
                        });
                        return Some(quarantine_forbidden(&digest, &q_status, q_secs));
                    }
                }

                // Cache manifest and create metadata (fire and forget)
                let upstream_ns = Some(upstream.resolved_namespace());
                let storage = state.storage.clone();
                let key_clone = cache_key.to_string();
                let data_clone = data.clone();
                let name_clone = name.to_string();
                let reference_clone = reference.to_string();
                let digest_clone = digest.clone();
                let state_clone = Arc::clone(state);
                tokio::spawn(async move {
                    // Store manifest by tag and digest (namespaced)
                    if let Err(e) = storage.put(&key_clone, &data_clone).await {
                        tracing::warn!(key = %key_clone, error = %e, "cache write failed (manifest by tag)");
                        crate::metrics::CACHE_WRITE_ERRORS
                            .with_label_values(&["docker", "manifest"])
                            .inc();
                    }
                    let digest_key =
                        manifest_key(upstream_ns.as_deref(), &name_clone, &digest_clone);
                    if let Err(e) = storage.put(&digest_key, &data_clone).await {
                        tracing::warn!(key = %digest_key, error = %e, "cache write failed (manifest by digest)");
                        crate::metrics::CACHE_WRITE_ERRORS
                            .with_label_values(&["docker", "manifest"])
                            .inc();
                    }

                    // Extract and save metadata
                    let metadata = extract_metadata(&data_clone, &storage, &name_clone).await;
                    if let Ok(meta_json) = serde_json::to_vec(&metadata) {
                        let meta_key = manifest_meta_key(
                            upstream_ns.as_deref(),
                            &name_clone,
                            &reference_clone,
                        );
                        if let Err(e) = storage.put(&meta_key, &meta_json).await {
                            tracing::warn!(key = %meta_key, error = %e, "cache write failed (metadata by tag)");
                            crate::metrics::CACHE_WRITE_ERRORS
                                .with_label_values(&["docker", "metadata"])
                                .inc();
                        }

                        let digest_meta_key =
                            manifest_meta_key(upstream_ns.as_deref(), &name_clone, &digest_clone);
                        if let Err(e) = storage.put(&digest_meta_key, &meta_json).await {
                            tracing::warn!(key = %digest_meta_key, error = %e, "cache write failed (metadata by digest)");
                            crate::metrics::CACHE_WRITE_ERRORS
                                .with_label_values(&["docker", "metadata"])
                                .inc();
                        }
                    }
                    state_clone.repo_index.invalidate("docker");
                });

                return Some(manifest_response(data, content_type, digest));
            }
            Err(ProxyError::CircuitOpen(reg)) => return Some(circuit_open_response(&reg)),
            Err(e) => {
                tracing::debug!(error = ?e, upstream = %upstream.url, name = %upstream_name, reference = %reference, "Docker manifest proxy fetch failed, trying next");
                continue;
            }
        }
    }
    None
}

async fn get_manifest(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker.upstreams);
    let upstreams_to_try = c.upstreams_to_try(&state.config.docker.upstreams);
    let ns = c.namespace;
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Extract publish date from .meta.json sidecar
    let publish_date = extract_docker_publish_date(
        &state.storage,
        &name,
        &reference,
        state.config.docker.upstreams.is_empty(),
        ns.as_deref(),
    )
    .await;

    // Curation check — manifests carry the image identity
    if let Some(response) = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        crate::curation::RegistryType::Docker,
        &name,
        Some(&reference),
        publish_date,
    ) {
        return response;
    }

    let key = manifest_key(ns.as_deref(), &name, &reference);
    let legacy_key = manifest_key(None, &name, &reference);

    // Try local storage first, with TTL-based revalidation (namespaced key, then legacy fallback)
    let cached = storage_get_with_fallback(&state.storage, &key, &legacy_key)
        .await
        .ok();
    let cache_fresh = if cached.is_some() {
        let meta = storage_stat_with_fallback(&state.storage, &key, &legacy_key).await;
        meta.map(|m| crate::cache_ttl::is_within_ttl(m.modified, state.config.docker.metadata_ttl))
            .unwrap_or(false)
    } else {
        false
    };

    // Serve fresh cache immediately
    if let Some(ref data) = cached {
        if cache_fresh {
            return serve_cached_manifest(&state, data, &name, &reference, ns.as_deref());
        }
    }

    // Try upstream proxies (always if no cache, or if cache is stale)
    tracing::debug!(
        upstreams_count = upstreams_to_try.len(),
        "Trying upstream proxies"
    );
    if let Some(response) =
        try_fetch_and_cache(&state, &upstreams_to_try, &name, &name, &reference, &key).await
    {
        return response;
    }

    // Auto-prepend library/ for single-segment names (Docker Hub official images)
    // e.g., "nginx" -> "library/nginx", "alpine" -> "library/alpine"
    if !name.contains('/') {
        let library_name = format!("library/{}", name);
        if let Some(response) = try_fetch_and_cache(
            &state,
            &upstreams_to_try,
            &library_name,
            &name,
            &reference,
            &key,
        )
        .await
        {
            return response;
        }
    }

    // Stale-while-error: serve stale cached manifest when upstream is unreachable
    if let Some(ref data) = cached {
        if state.config.docker.serve_stale {
            tracing::warn!(
                registry = "docker",
                name = %name,
                reference = %reference,
                "Upstream failed, serving stale cached manifest"
            );
            return serve_cached_manifest(&state, data, &name, &reference, ns.as_deref());
        }
    }

    if !state.config.docker.upstreams.is_empty() {
        tracing::warn!(registry = "docker", name = %name, reference = %reference, "Proxy failed, returning 404");
    }
    StatusCode::NOT_FOUND.into_response()
}

/// Serve a manifest from local cache with all required headers and side-effects.
fn serve_cached_manifest(
    state: &Arc<AppState>,
    data: &[u8],
    name: &str,
    reference: &str,
    ns: Option<&str>,
) -> Response {
    // Curation integrity verification (issue #189)
    if let Some(response) = crate::curation::verify_integrity(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Docker,
        name,
        Some(reference),
        data,
    ) {
        return response;
    }

    state.metrics.record_download("docker");
    state.metrics.record_cache_hit("docker");
    state.activity.push(ActivityEntry::new(
        ActionType::Pull,
        format!("{}:{}", name, reference),
        "docker",
        "LOCAL",
    ));

    // Calculate digest for Docker-Content-Digest header
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(data)));

    // Quarantine check (local cache hit may still be pending)
    let (q_mode, q_secs) = resolve_quarantine(state);
    if !matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
        let q_status = state.digest_store.check("docker", &digest, q_secs);
        match &q_status {
            crate::digest_quarantine::QuarantineStatus::Mature => {}
            _ => {
                tracing::warn!(
                    digest = %digest,
                    status = %q_status.header_value(),
                    mode = ?q_mode,
                    "Quarantine: cached manifest"
                );
                if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce) {
                    return quarantine_forbidden(&digest, &q_status, q_secs);
                }
            }
        }
    }

    // Detect manifest media type from content
    let content_type = detect_manifest_media_type(data);

    // Update metadata (downloads, last_pulled) in background
    let meta_key = manifest_meta_key(ns, name, reference);
    let state_clone = state.clone();
    let storage_clone = state.storage.clone();
    tokio::spawn(update_metadata_on_pull(
        state_clone,
        storage_clone,
        meta_key,
    ));

    manifest_response(Bytes::copy_from_slice(data), content_type, digest)
}

async fn put_manifest(
    State(state): State<Arc<AppState>>,
    Path((name, reference)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let name = canonicalize(&name, &state.config.docker.upstreams).name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Calculate digest
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&body)));

    // Local push → mark as immediately mature in quarantine store
    let (q_mode, q_secs) = resolve_quarantine(&state);
    if !matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
        state.digest_store.record_trusted("docker", &digest, q_secs);
    }

    // Store by tag/reference
    let key = format!("docker/{}/manifests/{}.json", name, reference);
    if state.storage.put(&key, &body).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Also store by digest for direct digest lookups
    let digest_key = format!("docker/{}/manifests/{}.json", name, digest);
    if state.storage.put(&digest_key, &body).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Extract and save metadata
    let metadata = extract_metadata(&body, &state.storage, &name).await;
    let meta_key = format!("docker/{}/manifests/{}.meta.json", name, reference);
    if let Ok(meta_json) = serde_json::to_vec(&metadata) {
        if let Err(e) = state.storage.put(&meta_key, &meta_json).await {
            tracing::warn!(key = %meta_key, error = %e, "cache write failed (push metadata by tag)");
            crate::metrics::CACHE_WRITE_ERRORS
                .with_label_values(&["docker", "metadata"])
                .inc();
        }

        // Also save metadata by digest
        let digest_meta_key = format!("docker/{}/manifests/{}.meta.json", name, digest);
        if let Err(e) = state.storage.put(&digest_meta_key, &meta_json).await {
            tracing::warn!(key = %digest_meta_key, error = %e, "cache write failed (push metadata by digest)");
            crate::metrics::CACHE_WRITE_ERRORS
                .with_label_values(&["docker", "metadata"])
                .inc();
        }
    }

    state.metrics.record_upload("docker");
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        format!("{}:{}", name, reference),
        "docker",
        "LOCAL",
    ));
    state.audit.log(AuditEntry::new(
        "push",
        "api",
        &format!("{}:{}", name, reference),
        "docker",
        "manifest",
    ));
    state.repo_index.invalidate("docker");

    let location = format!("/v2/{}/manifests/{}", name, reference);
    (
        StatusCode::CREATED,
        [
            (header::LOCATION, location),
            (HeaderName::from_static("docker-content-digest"), digest),
        ],
    )
        .into_response()
}

async fn list_tags(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    let c = canonicalize(&name, &state.config.docker.upstreams);
    let ns = c.namespace;
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    let prefix = manifest_prefix(ns.as_deref(), &name);
    let legacy_prefix = manifest_prefix(None, &name);
    let mut keys = state.storage.list(&prefix).await;
    // Also include legacy non-namespaced keys during migration
    if prefix != legacy_prefix {
        keys.extend(state.storage.list(&legacy_prefix).await);
        keys.sort();
        keys.dedup();
    }
    let tags: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            k.strip_prefix(&prefix)
                .or_else(|| k.strip_prefix(&legacy_prefix))
                .and_then(|t| t.strip_suffix(".json"))
                .map(String::from)
        })
        .filter(|t| !ends_with_ci(t, ".meta") && !t.contains(".meta."))
        .collect();
    (StatusCode::OK, Json(json!({"name": name, "tags": tags}))).into_response()
}

// ============================================================================
// Delete handlers (Docker Registry V2 spec)
// ============================================================================

async fn delete_manifest(
    State(state): State<Arc<AppState>>,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker.upstreams);
    let ns = c.namespace;
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = manifest_key(ns.as_deref(), &name, &reference);
    let legacy_key = manifest_key(None, &name, &reference);

    // Serialize tag delete with put_manifest via publish_lock to prevent
    // concurrent put from updating the tag between our read and delete
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;

    // If reference is a tag, also delete digest-keyed copy
    let is_tag = !reference.starts_with("sha256:");
    if is_tag {
        if let Ok(data) = storage_get_with_fallback(&state.storage, &key, &legacy_key).await {
            use sha2::Digest;
            let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));
            // Delete from both namespaced and legacy locations
            let _ = state
                .storage
                .delete(&manifest_key(ns.as_deref(), &name, &digest))
                .await;
            let _ = state
                .storage
                .delete(&manifest_key(None, &name, &digest))
                .await;
            let _ = state
                .storage
                .delete(&manifest_meta_key(ns.as_deref(), &name, &digest))
                .await;
            let _ = state
                .storage
                .delete(&manifest_meta_key(None, &name, &digest))
                .await;
        }
    }

    // Delete manifest — try namespaced key first, then legacy fallback
    match state.storage.delete(&key).await {
        Ok(()) => {
            // Delete associated metadata
            let meta_key = manifest_meta_key(ns.as_deref(), &name, &reference);
            let _ = state
                .storage
                .delete(&manifest_meta_key(None, &name, &reference))
                .await;
            let _ = state.storage.delete(&meta_key).await;

            state.audit.log(AuditEntry::new(
                "delete",
                "api",
                &format!("{}:{}", name, reference),
                "docker",
                "manifest",
            ));
            state.repo_index.invalidate("docker");
            tracing::info!(name = %name, reference = %reference, "Docker manifest deleted");
            StatusCode::ACCEPTED.into_response()
        }
        Err(crate::storage::StorageError::NotFound) if key != legacy_key => {
            // Try legacy (non-namespaced) key
            match state.storage.delete(&legacy_key).await {
                Ok(()) => {
                    let _ = state
                        .storage
                        .delete(&manifest_meta_key(None, &name, &reference))
                        .await;
                    state.audit.log(AuditEntry::new(
                        "delete",
                        "api",
                        &format!("{}:{}", name, reference),
                        "docker",
                        "manifest",
                    ));
                    state.repo_index.invalidate("docker");
                    tracing::info!(name = %name, reference = %reference, "Docker manifest deleted (legacy key)");
                    StatusCode::ACCEPTED.into_response()
                }
                _ => (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "errors": [{
                            "code": "MANIFEST_UNKNOWN",
                            "message": "manifest unknown",
                            "detail": { "name": name, "reference": reference }
                        }]
                    })),
                )
                    .into_response(),
            }
        }
        Err(crate::storage::StorageError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "errors": [{
                    "code": "MANIFEST_UNKNOWN",
                    "message": "manifest unknown",
                    "detail": { "name": name, "reference": reference }
                }]
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, key = %key, name = %name, reference = %reference, "Failed to delete manifest");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn delete_blob(
    State(state): State<Arc<AppState>>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker.upstreams);
    let ns = c.namespace;
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = blob_key(ns.as_deref(), &name, &digest);
    let legacy_key = blob_key(None, &name, &digest);
    // Delete from both locations during migration
    if key != legacy_key {
        let _ = state.storage.delete(&legacy_key).await;
    }
    match state.storage.delete(&key).await {
        Ok(()) => {
            state.audit.log(AuditEntry::new(
                "delete",
                "api",
                &format!("{}@{}", name, &digest[..19.min(digest.len())]),
                "docker",
                "blob",
            ));
            state.repo_index.invalidate("docker");
            tracing::info!(name = %name, digest = %digest, "Docker blob deleted");
            StatusCode::ACCEPTED.into_response()
        }
        Err(crate::storage::StorageError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "errors": [{
                    "code": "BLOB_UNKNOWN",
                    "message": "blob unknown to registry",
                    "detail": { "digest": digest }
                }]
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, key = %key, name = %name, digest = %digest, "Failed to delete blob");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ============================================================================

/// Fetch a blob from an upstream Docker registry.
///
/// Uses per-chunk `read_timeout` instead of a total request timeout so that
/// large blob downloads (multi-GB images) don't time out on slow connections.
/// The `timeout` parameter is kept as the connection/header timeout.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_blob_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    digest: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    read_timeout: u64,
    basic_auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
) -> Result<Vec<u8>, ProxyError> {
    let cb_key = format!("docker:{}", upstream_url.trim_end_matches('/'));
    cb.check(&cb_key)?;

    let url = format!(
        "{}/v2/{}/blobs/{}",
        upstream_url.trim_end_matches('/'),
        name,
        digest
    );

    // Connection timeout only — body is read with per-chunk timeout below
    let mut request = client.get(&url).timeout(Duration::from_secs(timeout));
    if let Some(credentials) = basic_auth {
        request = request.header("Authorization", basic_auth_header(credentials));
    }
    let response = request.send().await.map_err(|e| {
        cb.record_failure(&cb_key);
        ProxyError::Network(e.to_string())
    })?;

    let response = if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        // Get Www-Authenticate header and fetch token
        let www_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        if let Some(token) = docker_auth
            .get_token(upstream_url, name, www_auth.as_deref(), basic_auth)
            .await
        {
            client
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
                .map_err(|e| {
                    cb.record_failure(&cb_key);
                    ProxyError::Network(e.to_string())
                })?
        } else {
            // Auth issue (token fetch failed), not upstream down
            return Err(ProxyError::Network("token fetch failed".into()));
        }
    } else {
        response
    };

    if !response.status().is_success() {
        let status = response.status().as_u16();
        cb.record_failure(&cb_key);
        return Err(ProxyError::Upstream(status));
    }

    // Stream body with per-chunk read timeout
    let content_length = response.content_length().unwrap_or(0) as usize;
    let mut stream = response.bytes_stream();
    let mut data = Vec::with_capacity(content_length);
    let chunk_timeout = Duration::from_secs(read_timeout);

    loop {
        // CANCEL-SAFETY: timeout wraps a single stream.next() call. On timeout,
        // the partial chunk is discarded and we return a ProxyError — no
        // accumulated state is lost since `data` is local and the error aborts.
        match tokio::time::timeout(chunk_timeout, stream.next()).await {
            Ok(Some(Ok(chunk))) => data.extend_from_slice(&chunk),
            Ok(Some(Err(e))) => {
                cb.record_failure(&cb_key);
                return Err(ProxyError::Network(format!("chunk read error: {}", e)));
            }
            Ok(None) => break, // stream finished
            Err(_) => {
                cb.record_failure(&cb_key);
                return Err(ProxyError::Network(format!(
                    "read timeout ({}s per chunk)",
                    read_timeout
                )));
            }
        }
    }

    cb.record_success(&cb_key);
    Ok(data)
}

/// Fetch a manifest from an upstream Docker registry
/// Returns (manifest_bytes, content_type)
#[allow(clippy::too_many_arguments)]
pub async fn fetch_manifest_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    reference: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    basic_auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
) -> Result<(Vec<u8>, String), ProxyError> {
    let cb_key = format!("docker:{}", upstream_url.trim_end_matches('/'));
    cb.check(&cb_key)?;

    let url = format!(
        "{}/v2/{}/manifests/{}",
        upstream_url.trim_end_matches('/'),
        name,
        reference
    );

    tracing::debug!(url = %url, "Fetching manifest from upstream");

    // Request with Accept header for manifest types
    let accept_header = "application/vnd.docker.distribution.manifest.v2+json, \
                         application/vnd.docker.distribution.manifest.list.v2+json, \
                         application/vnd.oci.image.manifest.v1+json, \
                         application/vnd.oci.image.index.v1+json";

    // First try — with basic auth if configured
    let mut request = client
        .get(&url)
        .timeout(Duration::from_secs(timeout))
        .header("Accept", accept_header);
    if let Some(credentials) = basic_auth {
        request = request.header("Authorization", basic_auth_header(credentials));
    }
    let response = request.send().await.map_err(|e| {
        tracing::error!(error = %e, url = %url, "Failed to send request to upstream");
        cb.record_failure(&cb_key);
        ProxyError::Network(e.to_string())
    })?;

    tracing::debug!(status = %response.status(), "Initial upstream response");

    let response = if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        // Get Www-Authenticate header and fetch token
        let www_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        tracing::debug!(www_auth = ?www_auth, "Got 401, fetching token");

        if let Some(token) = docker_auth
            .get_token(upstream_url, name, www_auth.as_deref(), basic_auth)
            .await
        {
            tracing::debug!("Token acquired, retrying with auth");
            client
                .get(&url)
                .header("Accept", accept_header)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to send authenticated request");
                    cb.record_failure(&cb_key);
                    ProxyError::Network(e.to_string())
                })?
        } else {
            tracing::error!("Failed to acquire token");
            // Auth issue (token fetch failed), not upstream down
            return Err(ProxyError::Network("token fetch failed".into()));
        }
    } else {
        response
    };

    tracing::debug!(status = %response.status(), "Final upstream response");

    if !response.status().is_success() {
        let status = response.status().as_u16();
        tracing::warn!(status = %response.status(), "Upstream returned non-success status");
        cb.record_failure(&cb_key);
        return Err(ProxyError::Upstream(status));
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.docker.distribution.manifest.v2+json")
        .to_string();

    let bytes = response.bytes().await.map_err(|e| {
        cb.record_failure(&cb_key);
        ProxyError::Network(e.to_string())
    })?;

    cb.record_success(&cb_key);
    Ok((bytes.to_vec(), content_type))
}

/// Detect manifest media type from its JSON content
/// Build a standard Docker manifest response with Content-Type and Docker-Content-Digest headers.
fn manifest_response(data: impl Into<Bytes>, content_type: String, digest: String) -> Response {
    let body: Bytes = data.into();
    let content_length = body.len().to_string();
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (HeaderName::from_static("docker-content-digest"), digest),
            (header::CONTENT_LENGTH, content_length),
        ],
        body,
    )
        .into_response()
}

fn detect_manifest_media_type(data: &[u8]) -> String {
    // Try to parse as JSON and extract mediaType
    if let Ok(json) = serde_json::from_slice::<Value>(data) {
        if let Some(media_type) = json.get("mediaType").and_then(|v| v.as_str()) {
            return media_type.to_string();
        }

        // Check schemaVersion for older manifests
        if let Some(schema_version) = json.get("schemaVersion").and_then(|v| v.as_u64()) {
            if schema_version == 1 {
                return "application/vnd.docker.distribution.manifest.v1+json".to_string();
            }
            // schemaVersion 2 without mediaType - check config.mediaType to distinguish OCI vs Docker
            if let Some(config) = json.get("config") {
                if let Some(config_mt) = config.get("mediaType").and_then(|v| v.as_str()) {
                    if config_mt.starts_with("application/vnd.docker.") {
                        return "application/vnd.docker.distribution.manifest.v2+json".to_string();
                    }
                    // OCI or Helm or any non-docker config mediaType
                    return "application/vnd.oci.image.manifest.v1+json".to_string();
                }
                // No config.mediaType - assume docker v2
                return "application/vnd.docker.distribution.manifest.v2+json".to_string();
            }
            // If it has "manifests" array, it's an index/list
            if json.get("manifests").is_some() {
                return "application/vnd.oci.image.index.v1+json".to_string();
            }
        }
    }

    // Default fallback
    "application/vnd.docker.distribution.manifest.v2+json".to_string()
}

/// Extract publish date from Docker manifest `.meta.json` sidecar.
///
/// Docker metadata sidecar stores `push_timestamp` (Unix seconds) when the
/// manifest was first pushed or cached.
// TODO(v1.0): trust_upstream_dates config for high-security installs
async fn extract_docker_publish_date(
    storage: &Storage,
    name: &str,
    reference: &str,
    upstreams_empty: bool,
    ns: Option<&str>,
) -> Option<i64> {
    // Try .meta.json sidecar (has push_timestamp) — namespaced, then legacy
    let meta = manifest_meta_key(ns, name, reference);
    let legacy_meta = manifest_meta_key(None, name, reference);
    if let Ok(data) = storage_get_with_fallback(storage, &meta, &legacy_meta).await {
        if let Ok(meta) = serde_json::from_slice::<ImageMetadata>(&data) {
            if meta.push_timestamp > 0 {
                return Some(meta.push_timestamp as i64);
            }
        }
    }

    // mtime fallback — only for hosted mode (no upstreams configured)
    if upstreams_empty {
        let key = manifest_key(ns, name, reference);
        let legacy = manifest_key(None, name, reference);
        // Try namespaced first, then legacy
        if let Some(date) = crate::curation::extract_mtime_as_publish_date(storage, &key).await {
            return Some(date);
        }
        if key != legacy {
            return crate::curation::extract_mtime_as_publish_date(storage, &legacy).await;
        }
    }

    None
}

/// Extract metadata from a Docker manifest
/// Handles both single-arch manifests and multi-arch indexes
async fn extract_metadata(manifest: &[u8], storage: &Storage, name: &str) -> ImageMetadata {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut metadata = ImageMetadata {
        push_timestamp: now,
        last_pulled: 0,
        downloads: 0,
        ..Default::default()
    };

    let Ok(json) = serde_json::from_slice::<Value>(manifest) else {
        return metadata;
    };

    // Check if this is a manifest list/index (multi-arch)
    if json.get("manifests").is_some() {
        // For multi-arch, extract info from the first platform manifest
        if let Some(manifests) = json.get("manifests").and_then(|m| m.as_array()) {
            // Sum sizes from all platform manifests
            let total_size: u64 = manifests
                .iter()
                .filter_map(|m| m.get("size").and_then(|s| s.as_u64()))
                .sum();
            metadata.size_bytes = total_size;

            // Get OS/arch from first platform (usually linux/amd64)
            if let Some(first) = manifests.first() {
                if let Some(platform) = first.get("platform") {
                    metadata.os = platform
                        .get("os")
                        .and_then(|v| v.as_str())
                        .unwrap_or("multi-arch")
                        .to_string();
                    metadata.arch = platform
                        .get("architecture")
                        .and_then(|v| v.as_str())
                        .unwrap_or("multi")
                        .to_string();
                    metadata.variant = platform
                        .get("variant")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
            }
        }
        return metadata;
    }

    // Single-arch manifest - extract layers
    if let Some(layers) = json.get("layers").and_then(|l| l.as_array()) {
        let mut total_size: u64 = 0;
        for layer in layers {
            let digest = layer
                .get("digest")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            let size = layer.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            total_size += size;
            metadata.layers.push(LayerInfo { digest, size });
        }
        metadata.size_bytes = total_size;
    }

    // Try to get OS/arch from config blob
    if let Some(config) = json.get("config") {
        if let Some(config_digest) = config.get("digest").and_then(|d| d.as_str()) {
            let (os, arch, variant) = get_config_info(storage, name, config_digest).await;
            metadata.os = os;
            metadata.arch = arch;
            metadata.variant = variant;
        }
    }

    // If we couldn't get OS/arch, set defaults
    if metadata.os.is_empty() {
        metadata.os = "unknown".to_string();
    }
    if metadata.arch.is_empty() {
        metadata.arch = "unknown".to_string();
    }

    metadata
}

/// Get OS/arch information from a config blob
async fn get_config_info(
    storage: &Storage,
    name: &str,
    config_digest: &str,
) -> (String, String, Option<String>) {
    let key = format!("docker/{}/blobs/{}", name, config_digest);

    let Ok(data) = storage.get(&key).await else {
        return ("unknown".to_string(), "unknown".to_string(), None);
    };

    let Ok(config) = serde_json::from_slice::<Value>(&data) else {
        return ("unknown".to_string(), "unknown".to_string(), None);
    };

    let os = config
        .get("os")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let arch = config
        .get("architecture")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let variant = config
        .get("variant")
        .and_then(|v| v.as_str())
        .map(String::from);

    (os, arch, variant)
}

/// Update metadata when a manifest is pulled
/// Increments download counter and updates last_pulled timestamp
async fn update_metadata_on_pull(state: Arc<AppState>, storage: Storage, meta_key: String) {
    // Lock to prevent lost counter increments from concurrent pulls
    let lock = state.publish_lock(&meta_key);
    let _guard = lock.lock().await;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Try to read existing metadata
    let mut metadata = if let Ok(data) = storage.get(&meta_key).await {
        serde_json::from_slice::<ImageMetadata>(&data).unwrap_or_default()
    } else {
        ImageMetadata::default()
    };

    // Update pull stats
    metadata.downloads += 1;
    metadata.last_pulled = now;

    // Save back
    if let Ok(json) = serde_json::to_vec(&metadata) {
        if let Err(e) = storage.put(&meta_key, &json).await {
            tracing::warn!(key = %meta_key, error = %e, "cache write failed (pull stats update)");
            crate::metrics::CACHE_WRITE_ERRORS
                .with_label_values(&["docker", "metadata"])
                .inc();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_image_metadata_default() {
        let meta = ImageMetadata::default();
        assert_eq!(meta.push_timestamp, 0);
        assert_eq!(meta.last_pulled, 0);
        assert_eq!(meta.downloads, 0);
        assert_eq!(meta.size_bytes, 0);
        assert_eq!(meta.os, "");
        assert_eq!(meta.arch, "");
        assert!(meta.variant.is_none());
        assert!(meta.layers.is_empty());
    }

    #[test]
    fn test_image_metadata_serialization() {
        let meta = ImageMetadata {
            push_timestamp: 1700000000,
            last_pulled: 1700001000,
            downloads: 42,
            size_bytes: 1024000,
            os: "linux".to_string(),
            arch: "amd64".to_string(),
            variant: None,
            layers: vec![LayerInfo {
                digest: "sha256:abc123".to_string(),
                size: 512000,
            }],
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"os\":\"linux\""));
        assert!(json.contains("\"arch\":\"amd64\""));
        assert!(!json.contains("variant")); // None => skipped
    }

    #[test]
    fn test_image_metadata_with_variant() {
        let meta = ImageMetadata {
            variant: Some("v8".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"variant\":\"v8\""));
    }

    #[test]
    fn test_image_metadata_deserialization() {
        let json = r#"{
            "push_timestamp": 1700000000,
            "last_pulled": 0,
            "downloads": 5,
            "size_bytes": 2048,
            "os": "linux",
            "arch": "arm64",
            "variant": "v8",
            "layers": [
                {"digest": "sha256:aaa", "size": 1024},
                {"digest": "sha256:bbb", "size": 1024}
            ]
        }"#;
        let meta: ImageMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.os, "linux");
        assert_eq!(meta.arch, "arm64");
        assert_eq!(meta.variant, Some("v8".to_string()));
        assert_eq!(meta.layers.len(), 2);
        assert_eq!(meta.layers[0].digest, "sha256:aaa");
        assert_eq!(meta.layers[1].size, 1024);
    }

    #[test]
    fn test_layer_info_serialization_roundtrip() {
        let layer = LayerInfo {
            digest: "sha256:deadbeef".to_string(),
            size: 999999,
        };
        let json = serde_json::to_value(&layer).unwrap();
        let restored: LayerInfo = serde_json::from_value(json).unwrap();
        assert_eq!(layer.digest, restored.digest);
        assert_eq!(layer.size, restored.size);
    }

    #[test]
    fn test_cleanup_expired_sessions_empty() {
        let sessions: RwLock<HashMap<String, UploadSession>> = RwLock::new(HashMap::new());
        cleanup_expired_sessions(&sessions);
        assert_eq!(sessions.read().len(), 0);
    }

    #[test]
    fn test_cleanup_expired_sessions_fresh() {
        let sessions: RwLock<HashMap<String, UploadSession>> = RwLock::new(HashMap::new());
        let temp_dir = tempfile::TempDir::new().unwrap();
        let temp_path = temp_dir.path().join("uuid-1");
        std::fs::write(&temp_path, b"test data").unwrap();
        sessions.write().insert(
            "uuid-1".to_string(),
            UploadSession {
                temp_path,
                size: 9,
                name: "test/image".to_string(),
                created_at: std::time::Instant::now(),
            },
        );
        cleanup_expired_sessions(&sessions);
        assert_eq!(sessions.read().len(), 1); // not expired
    }

    #[test]
    fn test_max_upload_sessions_default() {
        // Without env var set, should return default
        let max = max_upload_sessions();
        assert!(max > 0);
        assert_eq!(max, DEFAULT_MAX_UPLOAD_SESSIONS);
    }

    #[test]
    fn test_max_session_size_default() {
        let max = max_session_size();
        assert_eq!(max, DEFAULT_MAX_SESSION_SIZE_MB * 1024 * 1024);
    }

    // --- detect_manifest_media_type tests ---

    #[test]
    fn test_detect_manifest_explicit_media_type() {
        let manifest = serde_json::json!({
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "schemaVersion": 2
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(
            result,
            "application/vnd.docker.distribution.manifest.v2+json"
        );
    }

    #[test]
    fn test_detect_manifest_oci_media_type() {
        let manifest = serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(result, "application/vnd.oci.image.manifest.v1+json");
    }

    #[test]
    fn test_detect_manifest_schema_v1() {
        let manifest = serde_json::json!({
            "schemaVersion": 1,
            "name": "test/image"
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(
            result,
            "application/vnd.docker.distribution.manifest.v1+json"
        );
    }

    #[test]
    fn test_detect_manifest_docker_v2_from_config() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "digest": "sha256:abc"
            }
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(
            result,
            "application/vnd.docker.distribution.manifest.v2+json"
        );
    }

    #[test]
    fn test_detect_manifest_oci_from_config() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:abc"
            }
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(result, "application/vnd.oci.image.manifest.v1+json");
    }

    #[test]
    fn test_detect_manifest_no_config_media_type() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "digest": "sha256:abc"
            }
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(
            result,
            "application/vnd.docker.distribution.manifest.v2+json"
        );
    }

    #[test]
    fn test_detect_manifest_index() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [
                {"digest": "sha256:aaa", "platform": {"os": "linux", "architecture": "amd64"}}
            ]
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(result, "application/vnd.oci.image.index.v1+json");
    }

    #[test]
    fn test_detect_manifest_invalid_json() {
        let result = detect_manifest_media_type(b"not json at all");
        assert_eq!(
            result,
            "application/vnd.docker.distribution.manifest.v2+json"
        );
    }

    #[test]
    fn test_detect_manifest_empty() {
        let result = detect_manifest_media_type(b"{}");
        assert_eq!(
            result,
            "application/vnd.docker.distribution.manifest.v2+json"
        );
    }

    #[test]
    fn test_detect_manifest_helm_chart() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.cncf.helm.config.v1+json",
                "digest": "sha256:abc"
            }
        });
        let result = detect_manifest_media_type(manifest.to_string().as_bytes());
        assert_eq!(result, "application/vnd.oci.image.manifest.v1+json");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::body::Body;
    use axum::http::{header, Method, StatusCode};
    use sha2::Digest;

    #[tokio::test]
    async fn test_docker_v2_check() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::GET, "/v2/", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_docker_catalog_empty() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::GET, "/v2/_catalog", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["repositories"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_docker_put_get_manifest() {
        let ctx = create_test_context();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

        let put_resp = send(
            &ctx.app,
            Method::PUT,
            "/v2/alpine/manifests/latest",
            Body::from(manifest_bytes.clone()),
        )
        .await;
        assert_eq!(put_resp.status(), StatusCode::CREATED);
        let digest_header = put_resp
            .headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(digest_header.starts_with("sha256:"));

        let get_resp = send(
            &ctx.app,
            Method::GET,
            "/v2/alpine/manifests/latest",
            Body::empty(),
        )
        .await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let get_digest = get_resp
            .headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(get_digest, digest_header);
        let body = body_bytes(get_resp).await;
        assert_eq!(body.as_ref(), manifest_bytes.as_slice());
    }

    #[tokio::test]
    async fn test_docker_list_tags() {
        let ctx = create_test_context();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        });
        send(
            &ctx.app,
            Method::PUT,
            "/v2/alpine/manifests/latest",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;

        let list_resp = send(&ctx.app, Method::GET, "/v2/alpine/tags/list", Body::empty()).await;
        assert_eq!(list_resp.status(), StatusCode::OK);
        let body = body_bytes(list_resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "alpine");
        let tags = json["tags"].as_array().unwrap();
        assert!(tags.contains(&serde_json::json!("latest")));
    }

    #[tokio::test]
    async fn test_docker_delete_manifest() {
        let ctx = create_test_context();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        });
        let put_resp = send(
            &ctx.app,
            Method::PUT,
            "/v2/alpine/manifests/latest",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;
        let digest = put_resp
            .headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let del = send(
            &ctx.app,
            Method::DELETE,
            &format!("/v2/alpine/manifests/{}", digest),
            Body::empty(),
        )
        .await;
        assert_eq!(del.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_docker_monolithic_upload() {
        let ctx = create_test_context();
        let blob_data = b"test blob data";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

        let post_resp = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        assert_eq!(post_resp.status(), StatusCode::ACCEPTED);
        let location = post_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let uuid = location.rsplit('/').next().unwrap();

        let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
        let put_resp = send(&ctx.app, Method::PUT, &put_url, Body::from(&blob_data[..])).await;
        assert_eq!(put_resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_docker_chunked_upload() {
        let ctx = create_test_context();
        let blob_data = b"test chunked blob";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

        let post_resp = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        assert_eq!(post_resp.status(), StatusCode::ACCEPTED);
        let location = post_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let uuid = location.rsplit('/').next().unwrap();

        let patch_url = format!("/v2/alpine/blobs/uploads/{}", uuid);
        let patch_resp = send(
            &ctx.app,
            Method::PATCH,
            &patch_url,
            Body::from(&blob_data[..]),
        )
        .await;
        assert_eq!(patch_resp.status(), StatusCode::ACCEPTED);

        let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
        let put_resp = send(&ctx.app, Method::PUT, &put_url, Body::empty()).await;
        assert_eq!(put_resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_docker_check_blob() {
        let ctx = create_test_context();
        let blob_data = b"test blob for head";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

        let post_resp = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        let location = post_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let uuid = location.rsplit('/').next().unwrap();
        let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
        send(&ctx.app, Method::PUT, &put_url, Body::from(&blob_data[..])).await;

        let head_url = format!("/v2/alpine/blobs/{}", digest);
        let head_resp = send(&ctx.app, Method::HEAD, &head_url, Body::empty()).await;
        assert_eq!(head_resp.status(), StatusCode::OK);
        let cl = head_resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(cl, blob_data.len());
    }

    #[tokio::test]
    async fn test_docker_download_blob() {
        let ctx = create_test_context();
        let blob_data = b"test blob for download";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

        let post_resp = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        let location = post_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let uuid = location.rsplit('/').next().unwrap();
        let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
        send(&ctx.app, Method::PUT, &put_url, Body::from(&blob_data[..])).await;

        let get_url = format!("/v2/alpine/blobs/{}", digest);
        let get_resp = send(&ctx.app, Method::GET, &get_url, Body::empty()).await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = body_bytes(get_resp).await;
        assert_eq!(body.as_ref(), &blob_data[..]);
    }

    #[tokio::test]
    async fn test_docker_blob_not_found() {
        let ctx = create_test_context();
        let fake_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let head_url = format!("/v2/alpine/blobs/{}", fake_digest);
        let resp = send(&ctx.app, Method::HEAD, &head_url, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_docker_delete_blob() {
        let ctx = create_test_context();
        let blob_data = b"test blob for delete";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

        let post_resp = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        let location = post_resp
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let uuid = location.rsplit('/').next().unwrap();
        let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
        send(&ctx.app, Method::PUT, &put_url, Body::from(&blob_data[..])).await;

        let delete_url = format!("/v2/alpine/blobs/{}", digest);
        let delete_resp = send(&ctx.app, Method::DELETE, &delete_url, Body::empty()).await;
        assert_eq!(delete_resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_docker_namespaced_routes() {
        let ctx = create_test_context();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        });
        let put_resp = send(
            &ctx.app,
            Method::PUT,
            "/v2/library/alpine/manifests/latest",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;
        assert_eq!(put_resp.status(), StatusCode::CREATED);
        assert!(put_resp
            .headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("sha256:"));
    }

    #[tokio::test]
    async fn test_extract_docker_publish_date_from_meta() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let meta = super::ImageMetadata {
            push_timestamp: 1700000000,
            ..Default::default()
        };
        storage
            .put(
                "docker/library/nginx/manifests/latest.meta.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let result = super::extract_docker_publish_date(
            &storage,
            "library/nginx",
            "latest",
            true, // no upstreams
            None, // no namespace
        )
        .await;
        assert_eq!(result, Some(1700000000));
    }

    #[tokio::test]
    async fn test_extract_docker_publish_date_mtime_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

        // No .meta.json, but manifest exists — should fall back to mtime (hosted mode)
        storage
            .put("docker/library/nginx/manifests/latest.json", b"{}")
            .await
            .unwrap();

        let result = super::extract_docker_publish_date(
            &storage,
            "library/nginx",
            "latest",
            true, // hosted mode (no upstreams)
            None, // no namespace
        )
        .await;
        assert!(result.is_some());
        assert!(result.unwrap() > 0);
    }

    #[tokio::test]
    async fn test_extract_docker_publish_date_proxy_no_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

        // No .meta.json, manifest exists, but proxy mode — no fallback
        storage
            .put("docker/library/nginx/manifests/latest.json", b"{}")
            .await
            .unwrap();

        let result = super::extract_docker_publish_date(
            &storage,
            "library/nginx",
            "latest",
            false, // proxy mode (has upstreams)
            None,  // no namespace
        )
        .await;
        assert!(result.is_none());
    }

    /// Circuit breaker open on Docker upstream MUST return 503 + Retry-After.
    #[tokio::test]
    async fn test_docker_circuit_breaker_trips() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};

        let ctx = create_test_context_with_config(|cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 2;
            cfg.circuit_breaker.reset_timeout = 3600;
            // Unreachable upstream
            cfg.docker.upstreams = vec![DockerUpstream {
                url: "http://127.0.0.1:1".into(),
                auth: None,
                namespace: None,
                prefix: None,
            }];
        });

        // Trip the breaker for this upstream
        ctx.state
            .circuit_breaker
            .record_failure("docker:http://127.0.0.1:1");
        ctx.state
            .circuit_breaker
            .record_failure("docker:http://127.0.0.1:1");

        // Request a manifest NOT in local storage → proxy path → cb.check() → 503
        let response = send(
            &ctx.app,
            Method::GET,
            "/v2/library/nonexistent/manifests/latest",
            Body::empty(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("30")
        );
        let body = body_bytes(response).await;
        assert!(String::from_utf8_lossy(&body).contains("temporarily unavailable"));
    }

    // ── OCI Distribution Spec conformance ──

    /// OCI spec: GET /v2/ must return `Docker-Distribution-API-Version: registry/2.0`.
    #[tokio::test]
    async fn test_oci_v2_api_version_header() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::GET, "/v2/", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let api_ver = resp
            .headers()
            .get("docker-distribution-api-version")
            .expect("OCI spec requires Docker-Distribution-API-Version header")
            .to_str()
            .unwrap();
        assert_eq!(api_ver, "registry/2.0");
    }

    /// OCI spec: GET /v2/_catalog must return `{"repositories": [...]}`.
    #[tokio::test]
    async fn test_oci_catalog_json_structure() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::GET, "/v2/_catalog", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.get("repositories").is_some(),
            "OCI spec requires 'repositories' key in catalog response"
        );
        assert!(json["repositories"].is_array());
    }

    /// OCI spec: GET /v2/{name}/tags/list must return `{"name": ..., "tags": [...]}`.
    #[tokio::test]
    async fn test_oci_tags_list_json_structure() {
        let ctx = create_test_context();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        });
        send(
            &ctx.app,
            Method::PUT,
            "/v2/myapp/manifests/v1",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;

        let resp = send(&ctx.app, Method::GET, "/v2/myapp/tags/list", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(
            json.get("name").is_some(),
            "OCI spec requires 'name' in tags/list"
        );
        assert!(
            json.get("tags").is_some(),
            "OCI spec requires 'tags' in tags/list"
        );
        assert_eq!(json["name"], "myapp");
        assert!(json["tags"].is_array());
    }

    /// OCI spec: manifest response MUST include Docker-Content-Digest = sha256 of body.
    #[tokio::test]
    async fn test_oci_manifest_digest_matches_body() {
        let ctx = create_test_context();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        send(
            &ctx.app,
            Method::PUT,
            "/v2/verify/manifests/latest",
            Body::from(manifest_bytes),
        )
        .await;

        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/verify/manifests/latest",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let digest_header = resp
            .headers()
            .get("docker-content-digest")
            .expect("OCI spec requires Docker-Content-Digest header")
            .to_str()
            .unwrap()
            .to_string();

        let body = body_bytes(resp).await;
        let computed = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&body)));
        assert_eq!(
            digest_header, computed,
            "Docker-Content-Digest must equal sha256 of response body"
        );
    }

    /// OCI spec: Content-Type of manifest response must match the manifest's mediaType.
    #[tokio::test]
    async fn test_oci_manifest_content_type_matches_media_type() {
        let ctx = create_test_context();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        });
        send(
            &ctx.app,
            Method::PUT,
            "/v2/ctcheck/manifests/v1",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;

        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/ctcheck/manifests/v1",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("OCI spec requires Content-Type header on manifest")
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/vnd.docker.distribution.manifest.v2+json");
    }

    /// OCI spec: Content-Length must match actual body length.
    #[tokio::test]
    async fn test_oci_manifest_content_length_matches() {
        let ctx = create_test_context();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        });
        send(
            &ctx.app,
            Method::PUT,
            "/v2/clcheck/manifests/v1",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;

        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/clcheck/manifests/v1",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cl: usize = resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .expect("OCI spec requires Content-Length on manifest")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let body = body_bytes(resp).await;
        assert_eq!(cl, body.len(), "Content-Length must match body size");
    }

    /// Per-upstream circuit breaker isolation: upstream A down, upstream B serves.
    #[tokio::test]
    async fn test_docker_circuit_breaker_per_upstream() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 2;
            cfg.circuit_breaker.reset_timeout = 3600;
            cfg.docker.upstreams = vec![
                DockerUpstream {
                    url: "http://127.0.0.1:1".into(), // upstream A (will be tripped)
                    auth: None,
                    namespace: None,
                    prefix: None,
                },
                DockerUpstream {
                    url: "http://127.0.0.1:2".into(), // upstream B (stays closed)
                    auth: None,
                    namespace: None,
                    prefix: None,
                },
            ];
        });

        // Trip only upstream A
        ctx.state
            .circuit_breaker
            .record_failure("docker:http://127.0.0.1:1");
        ctx.state
            .circuit_breaker
            .record_failure("docker:http://127.0.0.1:1");

        // Upstream A should be open
        assert!(ctx
            .state
            .circuit_breaker
            .check("docker:http://127.0.0.1:1")
            .is_err());

        // Upstream B should still be closed (requests allowed)
        assert!(ctx
            .state
            .circuit_breaker
            .check("docker:http://127.0.0.1:2")
            .is_ok());
    }

    #[test]
    fn test_strip_docker_namespace() {
        // Namespace prefix (hostname with dot) should be stripped
        assert_eq!(
            super::strip_docker_namespace("docker.io/library/nginx"),
            "library/nginx"
        );
        assert_eq!(
            super::strip_docker_namespace("ghcr.io/requarks/wiki"),
            "requarks/wiki"
        );
        assert_eq!(
            super::strip_docker_namespace("registry.example.com/myapp"),
            "myapp"
        );

        // No namespace prefix — returned as-is
        assert_eq!(
            super::strip_docker_namespace("library/nginx"),
            "library/nginx"
        );
        assert_eq!(super::strip_docker_namespace("alpine"), "alpine");

        // Edge: empty or slash-only
        assert_eq!(super::strip_docker_namespace(""), "");
        assert_eq!(super::strip_docker_namespace("docker.io/"), "docker.io/");

        // Org name with no dots — not a namespace
        assert_eq!(
            super::strip_docker_namespace("myorg/myimage"),
            "myorg/myimage"
        );
    }

    #[tokio::test]
    async fn test_catalog_dedup_across_namespaces() {
        use crate::test_helpers::create_test_context;

        let ctx = create_test_context();

        // Simulate keys from two different upstream namespaces for the same image
        ctx.state
            .storage
            .put(
                "docker/docker.io/library/nginx/manifests/latest.json",
                b"{}",
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put("docker/ghcr.io/library/nginx/manifests/v1.json", b"{}")
            .await
            .unwrap();
        // And a non-namespaced (legacy) key for the same image
        ctx.state
            .storage
            .put("docker/library/nginx/manifests/old.json", b"{}")
            .await
            .unwrap();

        let keys = ctx.state.storage.list("docker/").await;
        let mut repos: Vec<String> = keys
            .iter()
            .filter_map(|k| {
                let rest = k.strip_prefix("docker/")?;
                let name = if let Some(idx) = rest.find("/manifests/") {
                    &rest[..idx]
                } else {
                    return None;
                };
                if name.is_empty() {
                    return None;
                }
                Some(super::strip_docker_namespace(name).to_string())
            })
            .collect();
        repos.sort();
        repos.dedup();

        // All three keys should resolve to a single repo: "library/nginx"
        assert_eq!(repos, vec!["library/nginx"]);
    }

    #[test]
    fn test_canonicalize_prefix_routing() {
        let upstreams = vec![crate::config::DockerUpstream {
            url: "https://registry-1.docker.io".to_string(),
            auth: None,
            namespace: Some("docker.io".to_string()),
            prefix: Some("docker-hub".to_string()),
        }];

        let c = super::canonicalize("docker-hub/library/nginx", &upstreams);
        assert_eq!(c.name, "library/nginx");
        assert_eq!(c.namespace.as_deref(), Some("docker.io"));
        assert_eq!(c.upstreams_to_try(&upstreams).len(), 1);
    }

    #[test]
    fn test_canonicalize_hostname_detection() {
        let upstreams = vec![crate::config::DockerUpstream {
            url: "https://registry-1.docker.io".to_string(),
            auth: None,
            namespace: Some("docker.io".to_string()),
            prefix: None,
        }];

        let c = super::canonicalize("docker.io/library/nginx", &upstreams);
        assert_eq!(c.name, "library/nginx");
        assert_eq!(c.namespace.as_deref(), Some("docker.io"));
        // Known namespace matches specific upstream
        assert_eq!(c.upstreams_to_try(&upstreams).len(), 1);

        // Unknown hostname → strip but use default upstream
        let c2 = super::canonicalize("ghcr.io/requarks/wiki", &upstreams);
        assert_eq!(c2.name, "requarks/wiki");
        assert_eq!(c2.namespace.as_deref(), Some("docker.io"));
        // No specific match → all upstreams
        assert_eq!(c2.upstreams_to_try(&upstreams).len(), 1); // only 1 configured
    }

    #[test]
    fn test_canonicalize_fallback() {
        let upstreams = vec![crate::config::DockerUpstream {
            url: "https://registry-1.docker.io".to_string(),
            auth: None,
            namespace: Some("docker.io".to_string()),
            prefix: None,
        }];

        // No prefix, no dot in first segment → fallback
        let c = super::canonicalize("library/nginx", &upstreams);
        assert_eq!(c.name, "library/nginx");
        assert_eq!(c.namespace.as_deref(), Some("docker.io"));
        assert_eq!(c.upstreams_to_try(&upstreams).len(), 1);

        // Single segment
        let c2 = super::canonicalize("alpine", &upstreams);
        assert_eq!(c2.name, "alpine");
        assert_eq!(c2.namespace.as_deref(), Some("docker.io"));
    }

    #[test]
    fn test_canonicalize_empty_upstreams() {
        let upstreams: Vec<crate::config::DockerUpstream> = vec![];

        let c = super::canonicalize("library/nginx", &upstreams);
        assert_eq!(c.name, "library/nginx");
        assert!(c.namespace.is_none());
        assert!(c.upstreams_to_try(&upstreams).is_empty());
    }

    #[test]
    fn test_canonicalize_multi_upstream() {
        let upstreams = vec![
            crate::config::DockerUpstream {
                url: "https://registry-1.docker.io".to_string(),
                auth: None,
                namespace: Some("docker.io".to_string()),
                prefix: Some("docker-hub".to_string()),
            },
            crate::config::DockerUpstream {
                url: "https://ghcr.io".to_string(),
                auth: None,
                namespace: Some("ghcr.io".to_string()),
                prefix: Some("ghcr".to_string()),
            },
        ];

        // Prefix routes to specific upstream
        let c1 = super::canonicalize("ghcr/requarks/wiki", &upstreams);
        assert_eq!(c1.name, "requarks/wiki");
        assert_eq!(c1.namespace.as_deref(), Some("ghcr.io"));
        let targets = c1.upstreams_to_try(&upstreams);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].url, "https://ghcr.io");

        // No prefix match → all upstreams
        let c2 = super::canonicalize("library/nginx", &upstreams);
        assert_eq!(c2.name, "library/nginx");
        assert_eq!(c2.upstreams_to_try(&upstreams).len(), 2);
    }
}
