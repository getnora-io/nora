// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::config::basic_auth_header;
use crate::registry::docker_auth::DockerAuth;
use crate::storage::Storage;
use crate::validation::{validate_digest, validate_docker_name, validate_docker_reference};
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderName, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, head, patch, put},
    Json, Router,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

/// In-progress upload session with metadata
pub struct UploadSession {
    data: Vec<u8>,
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

/// Remove expired upload sessions (called by background task)
pub fn cleanup_expired_sessions(sessions: &RwLock<HashMap<String, UploadSession>>) {
    let mut guard = sessions.write();
    let before = guard.len();
    guard.retain(|_, s| s.created_at.elapsed() < SESSION_TTL);
    let removed = before - guard.len();
    if removed > 0 {
        tracing::info!(
            removed = removed,
            remaining = guard.len(),
            "Cleaned up expired upload sessions"
        );
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v2/", get(check))
        .route("/v2/_catalog", get(catalog))
        // Single-segment name routes (e.g., /v2/alpine/...)
        .route("/v2/{name}/blobs/{digest}", head(check_blob))
        .route("/v2/{name}/blobs/{digest}", get(download_blob))
        .route(
            "/v2/{name}/blobs/uploads/",
            axum::routing::post(start_upload),
        )
        .route(
            "/v2/{name}/blobs/uploads/{uuid}",
            patch(patch_blob).put(upload_blob),
        )
        .route("/v2/{name}/manifests/{reference}", get(get_manifest))
        .route("/v2/{name}/manifests/{reference}", put(put_manifest))
        .route("/v2/{name}/manifests/{reference}", delete(delete_manifest))
        .route("/v2/{name}/blobs/{digest}", delete(delete_blob))
        .route("/v2/{name}/tags/list", get(list_tags))
        // Two-segment name routes (e.g., /v2/library/alpine/...)
        .route("/v2/{ns}/{name}/blobs/{digest}", head(check_blob_ns))
        .route("/v2/{ns}/{name}/blobs/{digest}", get(download_blob_ns))
        .route(
            "/v2/{ns}/{name}/blobs/uploads/",
            axum::routing::post(start_upload_ns),
        )
        .route(
            "/v2/{ns}/{name}/blobs/uploads/{uuid}",
            patch(patch_blob_ns).put(upload_blob_ns),
        )
        .route(
            "/v2/{ns}/{name}/manifests/{reference}",
            get(get_manifest_ns),
        )
        .route(
            "/v2/{ns}/{name}/manifests/{reference}",
            put(put_manifest_ns),
        )
        .route(
            "/v2/{ns}/{name}/manifests/{reference}",
            delete(delete_manifest_ns),
        )
        .route("/v2/{ns}/{name}/blobs/{digest}", delete(delete_blob_ns))
        .route("/v2/{ns}/{name}/tags/list", get(list_tags_ns))
}

async fn check() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({})))
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
            Some(name.to_string())
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
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/blobs/{}", name, digest);
    match state.storage.get(&key).await {
        Ok(data) => (
            StatusCode::OK,
            [(header::CONTENT_LENGTH, data.len().to_string())],
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn download_blob(
    State(state): State<Arc<AppState>>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/blobs/{}", name, digest);

    // Try local storage first
    if let Ok(data) = state.storage.get(&key).await {
        state.metrics.record_download("docker");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::Pull,
            format!("{}@{}", name, &digest[..19.min(digest.len())]),
            "docker",
            "LOCAL",
        ));
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response();
    }

    // Try upstream proxies
    for upstream in &state.config.docker.upstreams {
        if let Ok(data) = fetch_blob_from_upstream(
            &state.http_client,
            &upstream.url,
            &name,
            &digest,
            &state.docker_auth,
            state.config.docker.proxy_timeout,
            upstream.auth.as_deref(),
        )
        .await
        {
            state.metrics.record_download("docker");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}@{}", name, &digest[..19.min(digest.len())]),
                "docker",
                "PROXY",
            ));

            // Cache in storage (fire and forget)
            let storage = state.storage.clone();
            let key_clone = key.clone();
            let data_clone = data.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &data_clone).await;
            });

            state.repo_index.invalidate("docker");

            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                Bytes::from(data),
            )
                .into_response();
        }
    }

    // Auto-prepend library/ for single-segment names (Docker Hub official images)
    if !name.contains('/') {
        let library_name = format!("library/{}", name);
        for upstream in &state.config.docker.upstreams {
            if let Ok(data) = fetch_blob_from_upstream(
                &state.http_client,
                &upstream.url,
                &library_name,
                &digest,
                &state.docker_auth,
                state.config.docker.proxy_timeout,
                upstream.auth.as_deref(),
            )
            .await
            {
                let storage = state.storage.clone();
                let key_clone = key.clone();
                let data_clone = data.clone();
                tokio::spawn(async move {
                    if let Err(e) = storage.put(&key_clone, &data_clone).await {
                        tracing::warn!(key = %key_clone, error = %e, "Failed to cache blob in storage");
                    }
                });

                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/octet-stream")],
                    Bytes::from(data),
                )
                    .into_response();
            }
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

async fn start_upload(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Enforce max concurrent sessions
    {
        let sessions = state.upload_sessions.read();
        let max_sessions = max_upload_sessions();
        if sessions.len() >= max_sessions {
            tracing::warn!(
                max = max_sessions,
                current = sessions.len(),
                "Upload session limit reached — rejecting new upload"
            );
            return (StatusCode::TOO_MANY_REQUESTS, "Too many concurrent uploads").into_response();
        }
    }

    let uuid = uuid::Uuid::new_v4().to_string();

    // Create session with metadata
    {
        let mut sessions = state.upload_sessions.write();
        sessions.insert(
            uuid.clone(),
            UploadSession {
                data: Vec::new(),
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
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Append data to the upload session and get total size
    let total_size = {
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
            sessions.remove(&uuid);
            return (StatusCode::NOT_FOUND, "Upload session expired").into_response();
        }

        // Check size limit
        let new_size = session.data.len() + body.len();
        if new_size > max_session_size() {
            sessions.remove(&uuid);
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload session exceeds size limit",
            )
                .into_response();
        }

        session.data.extend_from_slice(&body);
        session.data.len()
    };

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

    // Get data from chunked session if exists, otherwise use body directly
    let data = {
        let mut sessions = state.upload_sessions.write();
        if let Some(session) = sessions.remove(&uuid) {
            // Verify session belongs to this repository
            if session.name != name {
                tracing::warn!(
                    session_name = %session.name,
                    request_name = %name,
                    "SECURITY: upload finalization name mismatch"
                );
                return (
                    StatusCode::BAD_REQUEST,
                    "Session does not belong to this repository",
                )
                    .into_response();
            }
            // Chunked upload: append any final body data and use session
            let mut session_data = session.data;
            if !body.is_empty() {
                session_data.extend_from_slice(&body);
            }
            session_data
        } else {
            // Monolithic upload: use body directly
            body.to_vec()
        }
    };

    // Only sha256 digests are supported for verification
    if !digest.starts_with("sha256:") {
        return (
            StatusCode::BAD_REQUEST,
            "Only sha256 digests are supported for blob uploads",
        )
            .into_response();
    }

    // Verify digest matches uploaded content (Docker Distribution Spec)
    {
        use sha2::Digest as _;
        let computed = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));
        if computed != *digest {
            tracing::warn!(
                expected = %digest,
                computed = %computed,
                name = %name,
                "SECURITY: blob digest mismatch — rejecting upload"
            );
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

    let key = format!("docker/{}/blobs/{}", name, digest);
    match state.storage.put(&key, &data).await {
        Ok(()) => {
            state.metrics.record_upload("docker");
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
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_manifest(
    State(state): State<Arc<AppState>>,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/manifests/{}.json", name, reference);

    // Try local storage first
    if let Ok(data) = state.storage.get(&key).await {
        state.metrics.record_download("docker");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::Pull,
            format!("{}:{}", name, reference),
            "docker",
            "LOCAL",
        ));

        // Calculate digest for Docker-Content-Digest header
        use sha2::Digest;
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));

        // Detect manifest media type from content
        let content_type = detect_manifest_media_type(&data);

        // Update metadata (downloads, last_pulled) in background
        let meta_key = format!("docker/{}/manifests/{}.meta.json", name, reference);
        let storage_clone = state.storage.clone();
        tokio::spawn(update_metadata_on_pull(storage_clone, meta_key));

        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (HeaderName::from_static("docker-content-digest"), digest),
            ],
            data,
        )
            .into_response();
    }

    // Try upstream proxies
    tracing::debug!(
        upstreams_count = state.config.docker.upstreams.len(),
        "Trying upstream proxies"
    );
    for upstream in &state.config.docker.upstreams {
        tracing::debug!(upstream_url = %upstream.url, "Trying upstream");
        if let Ok((data, content_type)) = fetch_manifest_from_upstream(
            &state.http_client,
            &upstream.url,
            &name,
            &reference,
            &state.docker_auth,
            state.config.docker.proxy_timeout,
            upstream.auth.as_deref(),
        )
        .await
        {
            state.metrics.record_download("docker");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}:{}", name, reference),
                "docker",
                "PROXY",
            ));

            // Calculate digest for Docker-Content-Digest header
            use sha2::Digest;
            let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));

            // Cache manifest and create metadata (fire and forget)
            let storage = state.storage.clone();
            let key_clone = key.clone();
            let data_clone = data.clone();
            let name_clone = name.clone();
            let reference_clone = reference.clone();
            let digest_clone = digest.clone();
            tokio::spawn(async move {
                // Store manifest by tag and digest
                let _ = storage.put(&key_clone, &data_clone).await;
                let digest_key = format!("docker/{}/manifests/{}.json", name_clone, digest_clone);
                let _ = storage.put(&digest_key, &data_clone).await;

                // Extract and save metadata
                let metadata = extract_metadata(&data_clone, &storage, &name_clone).await;
                if let Ok(meta_json) = serde_json::to_vec(&metadata) {
                    let meta_key = format!(
                        "docker/{}/manifests/{}.meta.json",
                        name_clone, reference_clone
                    );
                    let _ = storage.put(&meta_key, &meta_json).await;

                    let digest_meta_key =
                        format!("docker/{}/manifests/{}.meta.json", name_clone, digest_clone);
                    let _ = storage.put(&digest_meta_key, &meta_json).await;
                }
            });

            state.repo_index.invalidate("docker");

            return (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, content_type),
                    (HeaderName::from_static("docker-content-digest"), digest),
                ],
                Bytes::from(data),
            )
                .into_response();
        }
    }

    // Auto-prepend library/ for single-segment names (Docker Hub official images)
    // e.g., "nginx" -> "library/nginx", "alpine" -> "library/alpine"
    if !name.contains('/') {
        let library_name = format!("library/{}", name);
        for upstream in &state.config.docker.upstreams {
            if let Ok((data, content_type)) = fetch_manifest_from_upstream(
                &state.http_client,
                &upstream.url,
                &library_name,
                &reference,
                &state.docker_auth,
                state.config.docker.proxy_timeout,
                upstream.auth.as_deref(),
            )
            .await
            {
                state.metrics.record_download("docker");
                state.metrics.record_cache_miss();
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{}:{}", name, reference),
                    "docker",
                    "PROXY",
                ));

                use sha2::Digest;
                let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));

                // Cache under original name for future local hits
                let storage = state.storage.clone();
                let key_clone = key.clone();
                let data_clone = data.clone();
                tokio::spawn(async move {
                    if let Err(e) = storage.put(&key_clone, &data_clone).await {
                        tracing::warn!(key = %key_clone, error = %e, "Failed to cache blob in storage");
                    }
                });

                state.repo_index.invalidate("docker");

                return (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, content_type),
                        (HeaderName::from_static("docker-content-digest"), digest),
                    ],
                    Bytes::from(data),
                )
                    .into_response();
            }
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

async fn put_manifest(
    State(state): State<Arc<AppState>>,
    Path((name, reference)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Calculate digest
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&body)));

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
        let _ = state.storage.put(&meta_key, &meta_json).await;

        // Also save metadata by digest
        let digest_meta_key = format!("docker/{}/manifests/{}.meta.json", name, digest);
        let _ = state.storage.put(&digest_meta_key, &meta_json).await;
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
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let prefix = format!("docker/{}/manifests/", name);
    let keys = state.storage.list(&prefix).await;
    let tags: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            k.strip_prefix(&prefix)
                .and_then(|t| t.strip_suffix(".json"))
                .map(String::from)
        })
        .filter(|t| !t.ends_with(".meta") && !t.contains(".meta."))
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
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/manifests/{}.json", name, reference);

    // If reference is a tag, also delete digest-keyed copy
    let is_tag = !reference.starts_with("sha256:");
    if is_tag {
        if let Ok(data) = state.storage.get(&key).await {
            use sha2::Digest;
            let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));
            let digest_key = format!("docker/{}/manifests/{}.json", name, digest);
            let _ = state.storage.delete(&digest_key).await;
            let digest_meta = format!("docker/{}/manifests/{}.meta.json", name, digest);
            let _ = state.storage.delete(&digest_meta).await;
        }
    }

    // Delete manifest
    match state.storage.delete(&key).await {
        Ok(()) => {
            // Delete associated metadata
            let meta_key = format!("docker/{}/manifests/{}.meta.json", name, reference);
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
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn delete_blob(
    State(state): State<Arc<AppState>>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = format!("docker/{}/blobs/{}", name, digest);
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
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// ============================================================================
// Namespace handlers (for two-segment names like library/alpine)
// These combine ns/name into a single name and delegate to the main handlers
// ============================================================================

async fn check_blob_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, digest)): Path<(String, String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    check_blob(state, Path((full_name, digest))).await
}

async fn download_blob_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, digest)): Path<(String, String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    download_blob(state, Path((full_name, digest))).await
}

async fn start_upload_ns(
    state: State<Arc<AppState>>,
    Path((ns, name)): Path<(String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    start_upload(state, Path(full_name)).await
}

async fn patch_blob_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, uuid)): Path<(String, String, String)>,
    body: Bytes,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    patch_blob(state, Path((full_name, uuid)), body).await
}

async fn upload_blob_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, uuid)): Path<(String, String, String)>,
    query: axum::extract::Query<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    upload_blob(state, Path((full_name, uuid)), query, body).await
}

async fn get_manifest_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, reference)): Path<(String, String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    get_manifest(state, Path((full_name, reference))).await
}

async fn put_manifest_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, reference)): Path<(String, String, String)>,
    body: Bytes,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    put_manifest(state, Path((full_name, reference)), body).await
}

async fn list_tags_ns(
    state: State<Arc<AppState>>,
    Path((ns, name)): Path<(String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    list_tags(state, Path(full_name)).await
}

async fn delete_manifest_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, reference)): Path<(String, String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    delete_manifest(state, Path((full_name, reference))).await
}

async fn delete_blob_ns(
    state: State<Arc<AppState>>,
    Path((ns, name, digest)): Path<(String, String, String)>,
) -> Response {
    let full_name = format!("{}/{}", ns, name);
    delete_blob(state, Path((full_name, digest))).await
}

/// Fetch a blob from an upstream Docker registry
async fn fetch_blob_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    digest: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    basic_auth: Option<&str>,
) -> Result<Vec<u8>, ()> {
    let url = format!(
        "{}/v2/{}/blobs/{}",
        upstream_url.trim_end_matches('/'),
        name,
        digest
    );

    // First try — with basic auth if configured
    let mut request = client.get(&url).timeout(Duration::from_secs(timeout));
    if let Some(credentials) = basic_auth {
        request = request.header("Authorization", basic_auth_header(credentials));
    }
    let response = request.send().await.map_err(|_| ())?;

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
                .map_err(|_| ())?
        } else {
            return Err(());
        }
    } else {
        response
    };

    if !response.status().is_success() {
        return Err(());
    }

    response.bytes().await.map(|b| b.to_vec()).map_err(|_| ())
}

/// Fetch a manifest from an upstream Docker registry
/// Returns (manifest_bytes, content_type)
async fn fetch_manifest_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    reference: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    basic_auth: Option<&str>,
) -> Result<(Vec<u8>, String), ()> {
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
                })?
        } else {
            tracing::error!("Failed to acquire token");
            return Err(());
        }
    } else {
        response
    };

    tracing::debug!(status = %response.status(), "Final upstream response");

    if !response.status().is_success() {
        tracing::warn!(status = %response.status(), "Upstream returned non-success status");
        return Err(());
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.docker.distribution.manifest.v2+json")
        .to_string();

    let bytes = response.bytes().await.map_err(|_| ())?;

    Ok((bytes.to_vec(), content_type))
}

/// Detect manifest media type from its JSON content
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
async fn update_metadata_on_pull(storage: Storage, meta_key: String) {
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
        let _ = storage.put(&meta_key, &json).await;
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
        sessions.write().insert(
            "uuid-1".to_string(),
            UploadSession {
                data: vec![1, 2, 3],
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
}
