// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, NamespaceAuthority};
use crate::circuit_breaker::CircuitBreakerRegistry;
use crate::config::basic_auth_header;
use crate::registry::docker_auth::DockerAuth;
use crate::registry::{circuit_open_response, method_not_allowed, ProxyError};
use crate::secrets::expose_opt;
use crate::storage::Storage;
use crate::validation::{
    ends_with_ci, validate_digest, validate_docker_name, validate_docker_reference,
};
use crate::AppState;
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{header, HeaderName, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use futures::StreamExt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_util::io::ReaderStream;

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
    /// When true, the request should be rejected (no prefix match in deny mode).
    pub denied: bool,
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

    /// Return a 403 response if this request was denied by `default_action = "deny"`.
    pub fn denied_response(&self) -> Option<axum::response::Response> {
        if self.denied {
            tracing::warn!(
                name = %self.name,
                "Docker request denied: image name did not match any configured upstream prefix"
            );
            Some(
                (
                    axum::http::StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({
                        "errors": [{
                            "code": "DENIED",
                            "message": "image name does not match any configured upstream prefix",
                            "detail": "default_action is set to deny"
                        }]
                    })),
                )
                    .into_response(),
            )
        } else {
            None
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
/// 3. Fallback — if `default_action = deny`, mark as denied; otherwise use
///    the first configured upstream
pub(crate) fn canonicalize(
    raw_name: &str,
    docker_config: &crate::config::DockerConfig,
) -> Canonical {
    let upstreams = &docker_config.upstreams;
    let deny_mode = docker_config.default_action == crate::config::DefaultAction::Deny;

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
                        denied: false,
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
                        denied: false,
                    };
                }
            }
            // Unknown hostname — strip it but use default upstream
            let ns = upstreams.first().map(|u| u.resolved_namespace());
            return Canonical {
                name: rest.to_string(),
                namespace: ns,
                matched_upstream_idx: None,
                denied: deny_mode,
            };
        }
    }

    // Step 3: Fallback — first upstream, name unchanged
    let ns = upstreams.first().map(|u| u.resolved_namespace());
    Canonical {
        name: raw_name.to_string(),
        namespace: ns,
        matched_upstream_idx: None,
        denied: deny_mode,
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

/// Open a streaming reader for a blob, trying namespaced then legacy key (#580).
async fn storage_get_reader_with_fallback(
    storage: &Storage,
    ns_key: &str,
    legacy_key: &str,
) -> Result<
    (
        u64,
        std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    ),
    crate::storage::StorageError,
> {
    match storage.get_reader(ns_key).await {
        Ok(reader) => Ok(reader),
        Err(_) if ns_key != legacy_key => storage.get_reader(legacy_key).await,
        Err(e) => Err(e),
    }
}

/// Parse a single `Range: bytes=start-end` header against a known object size, returning the
/// inclusive `(start, end)` clamped to the object, or `None` if it is absent, unparsable,
/// multipart, or unsatisfiable (the caller then serves the full object). Suffix ranges
/// (`bytes=-N`, the last N bytes) are supported.
fn parse_byte_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let spec = value.strip_prefix("bytes=")?.split(',').next()?.trim();
    let (s, e) = spec.split_once('-')?;
    if s.is_empty() {
        // suffix form "bytes=-N": the last N bytes
        let n: u64 = e.trim().parse().ok()?;
        byte_range_core(true, 0, false, n, size)
    } else {
        let start: u64 = s.trim().parse().ok()?;
        let (end_empty, end_in) = if e.trim().is_empty() {
            (true, 0)
        } else {
            (false, e.trim().parse::<u64>().ok()?)
        };
        byte_range_core(false, start, end_empty, end_in, size)
    }
}

/// Arithmetic core of [`parse_byte_range`], split out so the out-of-bounds /
/// inverted-range / overflow bug-class can be *proven* absent over the whole
/// `u64` space. String lexing stays in the caller — symbolically lexing a
/// UTF-8 string is intractable for a bounded model checker, while the bounds
/// invariant lives entirely in this arithmetic. For any inputs it never
/// panics/overflows; any `Some((start, end))` satisfies `start <= end < size`.
fn byte_range_core(
    suffix: bool,
    start_in: u64,
    end_empty: bool,
    end_in: u64,
    size: u64,
) -> Option<(u64, u64)> {
    let (start, end) = if suffix {
        let n = end_in;
        if n == 0 || size == 0 {
            return None;
        }
        (size.saturating_sub(n), size - 1)
    } else {
        let start = start_in;
        let end = if end_empty {
            size.saturating_sub(1)
        } else {
            end_in.min(size.saturating_sub(1))
        };
        (start, end)
    };
    if size == 0 || start > end || start >= size {
        return None;
    }
    Some((start, end))
}

/// Kani proof: [`byte_range_core`] is total and bounds-safe. For ANY
/// `(suffix, start_in, end_empty, end_in, size)` over the full `u64` space it
/// never panics or overflows, and any `Some((start, end))` is well-formed:
/// `start <= end < size` — the whole "out-of-bounds / inverted Range" bug-class
/// discharged at verification time, not at runtime. (Verified GREEN in-crate,
/// 17/17 checks in ~0.3s.)
///
/// Run: `make kani`, or `cargo kani -p nora-registry` (CI: `.github/workflows/kani.yml`).
/// Compiled only under `--cfg kani`; invisible to the normal build/clippy/test.
#[cfg(kani)]
#[kani::proof]
fn byte_range_core_is_bounds_safe() {
    let suffix: bool = kani::any();
    let start_in: u64 = kani::any();
    let end_empty: bool = kani::any();
    let end_in: u64 = kani::any();
    let size: u64 = kani::any();
    if let Some((start, end)) = byte_range_core(suffix, start_in, end_empty, end_in, size) {
        assert!(start <= end, "Range start must never exceed end");
        assert!(end < size, "Range end must stay within the object size");
        assert!(start < size, "Range start must stay within the object size");
    }
}

async fn storage_get_range_with_fallback(
    storage: &Storage,
    ns_key: &str,
    legacy_key: &str,
    start: u64,
    end: u64,
) -> Result<
    (
        u64,
        std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    ),
    crate::storage::StorageError,
> {
    match storage.get_range(ns_key, start, end).await {
        Ok(r) => Ok(r),
        Err(_) if ns_key != legacy_key => storage.get_range(legacy_key, start, end).await,
        Err(e) => Err(e),
    }
}

/// An `AsyncRead` wrapper that hashes the bytes it streams and, on a SHA-256
/// mismatch at EOF, fails the stream instead of letting a tampered blob complete
/// cleanly. `get_reader` (#580) streams large docker blobs without buffering, so
/// the buffered-`get()` fail-closed verify (#582) does not run on this path; this
/// restores NORA-side tamper *detection* for the streaming path (the docker
/// client's own content-digest check is the complementary layer). It cannot
/// un-send bytes already streamed, but it errors the response and logs on tamper
/// rather than serving a clean 200. Recomputing the digest on the streaming path
/// is the same deliberate cost #582 accepts for buffered reads.
struct VerifyingReader<R> {
    inner: R,
    hasher: sha2::Sha256,
    expected_hex: String,
    finished: bool,
}

impl<R> VerifyingReader<R> {
    fn new(inner: R, digest: &str) -> Self {
        let expected_hex = digest
            .strip_prefix("sha256:")
            .unwrap_or(digest)
            .to_ascii_lowercase();
        Self {
            inner,
            hasher: sha2::Sha256::default(),
            expected_hex,
            finished: false,
        }
    }
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for VerifyingReader<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use sha2::Digest as _;
        use std::task::Poll;
        // VerifyingReader<R: Unpin> is itself Unpin, so this projection is safe
        // (no `unsafe`, honouring `#![forbid(unsafe_code)]`).
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        match std::pin::Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled();
                if filled.len() > before {
                    this.hasher.update(&filled[before..]);
                    Poll::Ready(Ok(()))
                } else {
                    // EOF — verify the accumulated digest before a clean end.
                    this.finished = true;
                    let got = hex::encode(this.hasher.clone().finalize());
                    if got == this.expected_hex {
                        Poll::Ready(Ok(()))
                    } else {
                        tracing::error!(
                            expected = %this.expected_hex,
                            got = %got,
                            "blob integrity verification failed while streaming — aborting response"
                        );
                        Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "blob integrity verification failed",
                        )))
                    }
                }
            }
            other => other,
        }
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

fn proxy_temp_dir(data_dir: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(data_dir).join("tmp/docker-proxy");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::error!(path = %dir.display(), error = %e, "failed to create proxy temp directory");
    }
    dir
}

/// RAII guard that deletes a temp file on drop unless disarmed.
///
/// Ensures temp files are cleaned up on ALL error paths (network errors,
/// hash mismatch, panics, early returns via `?` operator) — #580.
pub(crate) struct TempFileGuard {
    path: Option<std::path::PathBuf>,
}

impl TempFileGuard {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Disarm the guard — caller takes ownership of cleanup.
    /// Call this after successful `put_from_path` (which moves/deletes the file).
    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// RAII guard for `PROXY_ACTIVE_DOWNLOADS` gauge — decrements on drop (#580).
///
/// Guarantees the gauge stays accurate on all exit paths including panics,
/// early `?` returns, and tokio task cancellation.
struct ProxyDownloadGuard;

impl Drop for ProxyDownloadGuard {
    fn drop(&mut self) {
        crate::metrics::PROXY_ACTIVE_DOWNLOADS.dec();
    }
}

/// Validate that an upload UUID from URL path is safe (no path traversal).
///
/// Accepts only lowercase hex + hyphens (UUID-4 format) up to 36 chars.
/// Rejects `/`, `..`, null bytes, and anything that could escape the temp directory.
fn validate_upload_uuid(uuid: &str) -> Result<(), &'static str> {
    if uuid.is_empty() || uuid.len() > 36 {
        return Err("invalid upload UUID length");
    }
    if uuid
        .bytes()
        .any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'-'))
    {
        return Err("invalid upload UUID characters");
    }
    Ok(())
}

/// Remove stale temp files from the Docker upload directory.
///
/// Files older than `SESSION_TTL` are removed regardless of name format.
/// Called at startup and periodically from the background task (mirrors
/// [`cleanup_proxy_temp_dir`]), so an upload temp orphaned by a storage-write
/// failure — whose session entry is already gone, so `cleanup_expired_sessions`
/// will never free it — is reclaimed without waiting for a restart. The
/// `SESSION_TTL` age guard keeps in-progress uploads safe under the periodic call.
pub fn cleanup_upload_temp_dir(data_dir: &str) {
    let dir = std::path::PathBuf::from(data_dir).join("tmp/docker-uploads");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            tracing::warn!(path = %dir.display(), error = %e, "Failed to read upload temp directory for cleanup");
            return;
        }
    };
    let mut removed = 0u64;
    for entry in entries.flatten() {
        let is_stale = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= SESSION_TTL);
        if is_stale && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        tracing::info!(removed, dir = %dir.display(), "Cleaned up stale Docker upload temp files");
    }
}

/// Max age for proxy temp files before cleanup removes them (#580).
///
/// 4 hours — long enough for slow multi-GB downloads over constrained links,
/// short enough to reclaim disk from orphaned files (crash, cancel, OOM).
const PROXY_TEMP_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(4 * 60 * 60);

/// Remove stale temp files from the Docker proxy download directory (#580).
///
/// Files older than `PROXY_TEMP_MAX_AGE` are removed. Called at startup
/// (catches orphans from crashes) and periodically from the background task.
/// Logs warnings on errors but never panics — cleanup is best-effort.
pub fn cleanup_proxy_temp_dir(data_dir: &str) {
    let dir = std::path::PathBuf::from(data_dir).join("tmp/docker-proxy");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            tracing::warn!(path = %dir.display(), error = %e, "Failed to read proxy temp directory for cleanup");
            return;
        }
    };
    let mut removed = 0u64;
    for entry in entries.flatten() {
        let is_stale = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= PROXY_TEMP_MAX_AGE);
        if is_stale && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        tracing::info!(removed, dir = %dir.display(), "Cleaned up stale proxy temp files");
    }
}

/// Resolve effective quarantine mode and TTL (seconds) for Docker.
///
/// Returns `(QuarantineMode, quarantine_secs)`. Per-registry override takes
/// precedence over global curation config. Returns `(Off, 0)` when disabled.
fn resolve_quarantine(state: &AppState) -> (crate::digest_quarantine::QuarantineMode, i64) {
    use crate::digest_quarantine::QuarantineMode;

    let mode = state
        .config
        .curation
        .docker
        .quarantine
        .as_ref()
        .or(state.config.curation.quarantine.as_ref())
        .cloned()
        .unwrap_or(QuarantineMode::Off);
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

/// Cache-serve quarantine gate for an already-cached artifact with a known digest.
///
/// Blocks (403 in enforce) ONLY when a proxy record for this digest is still
/// `Pending`. A digest with no proxy record (`New` — a locally-pushed or internal
/// artifact, or a record pruned past 90d) is served, and `Mature` is served. Local
/// pushes are not recorded, so they always read as `New` and serve; a trusted push
/// can therefore neither hold nor mature a digest on the proxy path. Returns
/// `Some(403)` to block, `None` to proceed.
#[must_use = "the returned response blocks a quarantined artifact; dropping it serves it"]
fn quarantine_cache_serve_gate(state: &AppState, digest: &str) -> Option<Response> {
    let (q_mode, q_secs) = resolve_quarantine(state);
    if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
        return None;
    }
    let status = state.digest_store.check("docker", digest, q_secs);
    if let crate::digest_quarantine::QuarantineStatus::Pending { .. } = status {
        tracing::warn!(
            digest = %digest,
            status = %status.header_value(),
            mode = ?q_mode,
            "Quarantine: held cached artifact (proxy cooldown)"
        );
        if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce) {
            return Some(quarantine_forbidden(digest, &status, q_secs));
        }
    }
    None
}

/// Post-proxy-fetch quarantine gate for a blob with a known content digest.
///
/// Records the digest as first-seen on the proxy path, then blocks (403 in enforce)
/// until it matures. Mirrors the manifest proxy-fetch path. `record` is idempotent,
/// so the cooldown clock starts at the first proxy fetch and never resets. The caller
/// caches the blob before calling this, so a held blob is still cached (the client is
/// blocked, not the cache) — identical to the manifest behaviour.
#[must_use = "the returned response blocks a quarantined artifact; dropping it serves it"]
fn quarantine_proxy_fetch_gate(state: &AppState, digest: &str, upstream: &str) -> Option<Response> {
    let (q_mode, q_secs) = resolve_quarantine(state);
    if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
        return None;
    }
    state.digest_store.record("docker", digest, upstream);
    let status = state.digest_store.check("docker", digest, q_secs);
    if !matches!(status, crate::digest_quarantine::QuarantineStatus::Mature) {
        tracing::warn!(
            digest = %digest,
            upstream = %upstream,
            status = %status.header_value(),
            mode = ?q_mode,
            "Quarantine: proxy-fetched blob held (new to this mirror)"
        );
        if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce) {
            return Some(quarantine_forbidden(digest, &status, q_secs));
        }
    }
    None
}

/// Docker v2 routes.
/// Uses a `{*rest}` wildcard to support image names with arbitrary path depth
/// (e.g., `library/astra/ubi18-cpp122`), per OCI Distribution spec.
pub fn routes() -> Router<AppState> {
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
    state: State<AppState>,
    method: Method,
    Path(wildcard): Path<String>,
    Extension(authority): Extension<NamespaceAuthority>,
    uri: Uri,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let rest = wildcard.trim_start_matches('/');
    if rest.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Writes (push/delete) are gated by OIDC namespace_scope on the image name,
    // which is the docker namespace coordinate (#583). Reads are never gated here.
    let is_write = matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );

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
        if is_write && enforce_namespace_scope(&authority, name).is_err() {
            return StatusCode::FORBIDDEN.into_response();
        }
        return if after.is_empty() {
            match method {
                Method::POST => {
                    let params = parse_query_string(uri.query());
                    if params.contains_key("digest") {
                        // OCI single-POST monolithic upload (#688): the blob is in
                        // the body and ?digest= is set, so complete it in one
                        // request instead of opening a session. Reuse the upload
                        // finalizer with a fresh upload id — no session exists, so
                        // it takes the monolithic branch.
                        let upload_id = uuid::Uuid::new_v4().to_string();
                        upload_blob(
                            state,
                            Path((name.to_string(), upload_id)),
                            axum::extract::Query(params),
                            body,
                        )
                        .await
                    } else {
                        start_upload(state, Path(name.to_string())).await
                    }
                }
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
        if is_write && enforce_namespace_scope(&authority, name).is_err() {
            return StatusCode::FORBIDDEN.into_response();
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
        if is_write && enforce_namespace_scope(&authority, name).is_err() {
            return StatusCode::FORBIDDEN.into_response();
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
async fn catalog(State(state): State<AppState>) -> Response {
    let keys = match state.storage.list("docker/").await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = ?e, "docker: failed to list storage for catalog");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

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
            Some(canonicalize(name, &state.config.docker).name)
        })
        .collect();

    repos.sort();
    repos.dedup();

    Json(json!({ "repositories": repos })).into_response()
}

async fn check_blob(
    State(state): State<AppState>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = blob_key(c.namespace.as_deref(), &name, &digest);
    let legacy_key = blob_key(None, &name, &digest);
    // Use stat() instead of get() to avoid loading multi-GB blobs into memory
    // just to return Content-Length on a HEAD request (#526).
    match storage_stat_with_fallback(&state.storage, &key, &legacy_key).await {
        Some(meta) => {
            // Mirror download_blob / HEAD-manifest: a proxy-cached blob still within its
            // cooldown is reported as held (403), not available — so HEAD and GET agree.
            // A local/internal blob has no proxy record (`New`) and acks normally.
            if let Some(resp) = quarantine_cache_serve_gate(&state, &digest) {
                return resp;
            }
            (
                StatusCode::OK,
                [(header::CONTENT_LENGTH, meta.size.to_string())],
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn download_blob(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let upstreams_to_try = c.upstreams_to_try(&state.config.docker.upstreams);
    let ns = c.namespace;
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Curation check — defense in depth: check blobs too. #733 serve-local: an internal-namespace
    // image is operator-owned — skip curation and serve any local blob below; block the upstream
    // branch separately (never proxy an internal name).
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Docker,
        &name,
    );
    if !internal {
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
    }

    let key = blob_key(ns.as_deref(), &name, &digest);
    let legacy_key = blob_key(None, &name, &digest);

    // Try local storage first — streaming read, never loads full blob into RAM (#580)
    if let Ok((size, reader)) =
        storage_get_reader_with_fallback(&state.storage, &key, &legacy_key).await
    {
        // Curation integrity check using digest from URL (no full-data rehash).
        // Docker blobs are content-addressed: the URL digest IS the integrity.
        if let Some(response) = crate::curation::verify_integrity_by_hash(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Docker,
            &name,
            Some(&digest),
            &digest,
        ) {
            return response;
        }

        // Quarantine: a proxy-cached blob still within its cooldown window is held.
        // A blob with no proxy record (a local push, or an entry pruned past 90d)
        // reads as `New` and is served; only `Pending` blocks (enforce). Covers both
        // the 206 range serve and the 200 full serve below.
        if let Some(resp) = quarantine_cache_serve_gate(&state, &digest) {
            return resp;
        }

        // Range request: serve the requested byte range (206 Partial Content). A ranged
        // response is partial, so the streaming SHA-256 verify (full-GET only) does not
        // apply — a ranged serve relies on the content-addressed storage key plus the
        // client's own content-digest check, as Docker/Harbor do. An absent/invalid range
        // falls through to the full 200 below.
        if let Some((start, end)) = headers
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| parse_byte_range(v, size))
        {
            drop(reader);
            let ranged = match storage_get_range_with_fallback(
                &state.storage,
                &key,
                &legacy_key,
                start,
                end,
            )
            .await
            {
                Ok((_, r)) => r,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            state.metrics.record_download("docker");
            state.metrics.record_cache_hit("docker");
            return Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_LENGTH, end - start + 1)
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", start, end, size),
                )
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
                .header("docker-content-digest", &digest)
                .body(Body::from_stream(ReaderStream::new(ranged)))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }

        state.metrics.record_download("docker");
        state.metrics.record_cache_hit("docker");
        state.activity.push(ActivityEntry::new(
            ActionType::Pull,
            format!("{}@{}", name, &digest[..19.min(digest.len())]),
            "docker",
            "LOCAL",
        ));
        let stream = ReaderStream::new(VerifyingReader::new(reader, &digest));
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, size)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
            .header("docker-content-digest", &digest)
            .body(Body::from_stream(stream))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    // #733: an internal-namespace image's blob with no local copy is never proxied upstream.
    if internal {
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Docker,
            &name,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    let temp_dir = proxy_temp_dir(&state.config.storage.path);

    // Try upstream proxies (prefix-matched → single upstream, otherwise → fallback chain)
    // Includes library/ fallback for single-segment names (Docker Hub official images).
    let names_to_try: Vec<String> = if name.contains('/') {
        vec![name.clone()]
    } else {
        vec![name.clone(), format!("library/{}", name)]
    };

    for try_name in &names_to_try {
        for upstream in &upstreams_to_try {
            match fetch_blob_from_upstream(
                &state.http_client,
                &upstream.url,
                try_name,
                &digest,
                &state.docker_auth,
                state.config.docker.proxy_timeout,
                state.config.docker.read_timeout,
                expose_opt(&upstream.auth),
                &state.circuit_breaker,
                &temp_dir,
            )
            .await
            {
                Ok(mut fetched) => {
                    // Verify SHA-256 against digest from URL (curation fail-closed)
                    let expected_hash = digest.strip_prefix("sha256:").unwrap_or(&digest);
                    if fetched.sha256 != expected_hash {
                        tracing::warn!(
                            name = %try_name,
                            digest = %digest,
                            expected = %expected_hash,
                            actual = %fetched.sha256,
                            "Docker blob SHA-256 mismatch from upstream — rejecting"
                        );
                        // TempFileGuard drops and cleans up
                        return StatusCode::BAD_GATEWAY.into_response();
                    }

                    // Curation integrity check with pre-computed hash (#580)
                    let hash_with_prefix = format!("sha256:{}", fetched.sha256);
                    if let Some(response) = crate::curation::verify_integrity_by_hash(
                        &state.curation().curation_engine,
                        crate::curation::RegistryType::Docker,
                        try_name,
                        Some(&digest),
                        &hash_with_prefix,
                    ) {
                        return response;
                    }

                    state.metrics.record_download("docker");
                    state.metrics.record_cache_miss("docker");
                    state.activity.push(ActivityEntry::new(
                        ActionType::ProxyFetch,
                        format!("{}@{}", try_name, &digest[..19.min(digest.len())]),
                        "docker",
                        "PROXY",
                    ));

                    // Read temp file size for Content-Length (always known — file is complete)
                    let file_size = tokio::fs::metadata(&fetched.path)
                        .await
                        .map(|m| m.len())
                        .unwrap_or(0);

                    // Store blob: atomic move temp → storage with SHA-256 pin (#580)
                    let sha_for_pin = fetched.sha256.clone();
                    match state
                        .storage
                        .put_from_path(&key, &fetched.path, Some(&sha_for_pin))
                        .await
                    {
                        Ok(()) => {
                            // put_from_path moved/deleted the file — disarm guard
                            fetched._guard.disarm();
                            state.repo_index.invalidate("docker");
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                key = %key,
                                "Failed to store proxied blob — serving from upstream anyway"
                            );
                            // Guard will clean up temp file on drop
                        }
                    }

                    // Quarantine: the blob is cached above; hold it during the cooldown.
                    // Records the digest as first-seen on the proxy path and 403s in
                    // enforce until it matures (mirrors the manifest proxy path). Covers
                    // both serve paths below (stored and temp-file fallback).
                    if let Some(resp) = quarantine_proxy_fetch_gate(&state, &digest, &upstream.url)
                    {
                        return resp;
                    }

                    // Serve response via streaming — never load full blob into RAM (#580).
                    // Two paths: storage (put succeeded) or temp file (put failed).
                    if fetched._guard.path.is_none() {
                        // Successfully stored — stream from storage
                        match state.storage.get_reader(&key).await {
                            Ok((size, reader)) => {
                                let stream =
                                    ReaderStream::new(VerifyingReader::new(reader, &digest));
                                return Response::builder()
                                    .status(StatusCode::OK)
                                    .header(header::CONTENT_TYPE, "application/octet-stream")
                                    .header(header::CONTENT_LENGTH, size)
                                    .header(
                                        header::CACHE_CONTROL,
                                        "public, max-age=31536000, immutable",
                                    )
                                    .header("docker-content-digest", &digest)
                                    .body(Body::from_stream(stream))
                                    .unwrap_or_else(|_| {
                                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                                    });
                            }
                            Err(e) => {
                                tracing::error!(error = %e, key = %key, "Failed to read just-stored blob");
                                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                            }
                        }
                    } else {
                        // put_from_path failed — stream from temp file directly
                        match tokio::fs::File::open(&fetched.path).await {
                            Ok(file) => {
                                let stream = ReaderStream::new(VerifyingReader::new(file, &digest));
                                return Response::builder()
                                    .status(StatusCode::OK)
                                    .header(header::CONTENT_TYPE, "application/octet-stream")
                                    .header(header::CONTENT_LENGTH, file_size)
                                    .header("docker-content-digest", &digest)
                                    .body(Body::from_stream(stream))
                                    .unwrap_or_else(|_| {
                                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                                    });
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "Failed to open temp blob file for streaming");
                                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                            }
                        }
                    }
                }
                Err(ProxyError::CircuitOpen(reg)) => return circuit_open_response(&reg),
                Err(e) => {
                    tracing::debug!(error = ?e, upstream = %upstream.url, name = %try_name, "Docker blob proxy fetch failed, trying next");
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

async fn start_upload(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let uuid = uuid::Uuid::new_v4().to_string();

    // Create temp file for blob data on disk BEFORE inserting into session map.
    // This ensures patch_blob can use .append(true) without .create(true),
    // preventing orphan re-creation if cleanup_expired_sessions deletes the file (#530).
    let temp_dir = upload_temp_dir(&state.config.storage.path);
    let temp_path = temp_dir.join(&uuid);
    if let Err(e) = tokio::fs::File::create(&temp_path).await {
        tracing::error!(path = %temp_path.display(), error = %e, "Failed to create upload temp file");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

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
    State(state): State<AppState>,
    Path((name, uuid)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_upload_uuid(&uuid) {
        return (StatusCode::BAD_REQUEST, e).into_response();
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

    // Phase 2: Append to temp file outside lock (non-blocking).
    // No .create(true) — temp file was created by start_upload.
    // If cleanup_expired_sessions deleted the file while we were unlocked,
    // open() returns NotFound and we return 404 instead of re-creating an orphan (#530).
    {
        use tokio::io::AsyncWriteExt;
        let file = tokio::fs::OpenOptions::new()
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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Temp file was deleted by cleanup_expired_sessions between
                // Phase 1 and Phase 2 — session is gone, return 404.
                tracing::warn!(uuid = %uuid, "Upload temp file deleted by cleanup during PATCH — session race");
                state.upload_sessions.write().remove(&uuid);
                return (StatusCode::NOT_FOUND, "Upload session expired").into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to open upload temp file");
                let _ = tokio::fs::remove_file(&temp_path).await;
                state.upload_sessions.write().remove(&uuid);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }

    // Phase 3: Update session size (brief lock, no I/O).
    // If session is gone (cleanup raced, or upload_blob consumed it), log and return 404.
    // Do NOT delete the temp file here — upload_blob may be using it (#530).
    {
        let mut sessions = state.upload_sessions.write();
        match sessions.get_mut(&uuid) {
            Some(session) => session.size = new_size as u64,
            None => {
                tracing::warn!(uuid = %uuid, "Upload session disappeared between Phase 1 and Phase 3");
                return (StatusCode::NOT_FOUND, "Upload session not found or expired")
                    .into_response();
            }
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
    State(state): State<AppState>,
    Path((name, uuid)): Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_upload_uuid(&uuid) {
        return (StatusCode::BAD_REQUEST, e).into_response();
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
    match state.storage.put_from_path(&key, &temp_path, None).await {
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
    state: &AppState,
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
            expose_opt(&upstream.auth),
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
                        let repo_index = Arc::clone(&state.repo_index);
                        tokio::spawn(async move {
                            if let Err(e) = storage.put(&key_clone, &data).await {
                                tracing::warn!(key = %key_clone, error = %e, "cache write failed (quarantine pre-cache)");
                                crate::metrics::CACHE_WRITE_ERRORS
                                    .with_label_values(&["docker", "manifest"])
                                    .inc();
                            }
                            repo_index.invalidate("docker");
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
                let repo_index = Arc::clone(&state.repo_index);
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
                    repo_index.invalidate("docker");
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

/// Whether a cached manifest may be served WITHOUT revalidating against upstream.
///
/// A **digest** reference is immutable (content-addressed) → always fresh. A **tag** on a
/// **hosted** name (no upstream to revalidate against) is locally authoritative → fresh. A
/// **tag** on a **proxied** name is mutable: it must be revalidated against upstream unless it
/// is still within a POSITIVE `metadata_ttl` staleness window. The default (and any non-positive
/// ttl) revalidates every pull, so a re-pushed upstream tag is reflected (#638).
fn manifest_cache_fresh(
    is_digest: bool,
    has_upstream: bool,
    metadata_ttl: i64,
    modified: Option<u64>,
) -> bool {
    if is_digest || !has_upstream {
        return true;
    }
    metadata_ttl > 0
        && modified
            .map(|m| crate::cache_ttl::is_within_ttl(m, metadata_ttl))
            .unwrap_or(false)
}

async fn get_manifest(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
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

    // Curation check — manifests carry the image identity. #733 serve-local: an internal-namespace
    // image is operator-owned — skip curation and serve any local manifest below; block the
    // upstream branch separately (never proxy an internal name).
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Docker,
        &name,
    );
    if !internal {
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
    }

    let key = manifest_key(ns.as_deref(), &name, &reference);
    let legacy_key = manifest_key(None, &name, &reference);

    // Try local storage first (namespaced key, then legacy fallback).
    let cached = storage_get_with_fallback(&state.storage, &key, &legacy_key)
        .await
        .ok();
    // Digest references are immutable (content-addressed) → the cache is authoritative forever.
    // Tag references are MUTABLE: a tag can be re-pushed to point at a different manifest, so a
    // proxied tag must be revalidated against upstream before it is served — otherwise a
    // re-pushed upstream tag is never reflected (#638). `metadata_ttl` is an optional staleness
    // window for tags: only a POSITIVE value serves a tag from cache without revalidating (within
    // the window); otherwise the latest is fetched. A tag with no upstream (hosted) is
    // authoritative and served from cache; when upstream is unreachable the stale-while-error
    // path below still serves the cached manifest.
    let is_digest = reference.starts_with("sha256:");
    let cache_fresh = if cached.is_some() {
        let modified = storage_stat_with_fallback(&state.storage, &key, &legacy_key)
            .await
            .map(|m| m.modified);
        manifest_cache_fresh(
            is_digest,
            !upstreams_to_try.is_empty(),
            state.config.docker.metadata_ttl,
            modified,
        )
    } else {
        false
    };

    // Serve fresh cache immediately
    if let Some(ref data) = cached {
        if cache_fresh {
            return serve_cached_manifest(&state, data, &name, &reference, ns.as_deref());
        }
    }

    // #733: an internal-namespace image's manifest — serve any (stale) local copy, else block;
    // never proxy upstream (the fresh path already returned above).
    if internal {
        if let Some(ref data) = cached {
            return serve_cached_manifest(&state, data, &name, &reference, ns.as_deref());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Docker,
            &name,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
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
            let mut response =
                serve_cached_manifest(&state, data, &name, &reference, ns.as_deref());
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-nora-stale"),
                axum::http::header::HeaderValue::from_static("true"),
            );
            response.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::header::HeaderValue::from_static("public, max-age=0, must-revalidate"),
            );
            return response;
        }
    }

    if !state.config.docker.upstreams.is_empty() {
        tracing::warn!(registry = "docker", name = %name, reference = %reference, "Proxy failed, returning 404");
    }
    StatusCode::NOT_FOUND.into_response()
}

/// Serve a manifest from local cache with all required headers and side-effects.
fn serve_cached_manifest(
    state: &AppState,
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

    // Quarantine: a cached manifest still within its proxy cooldown is held. A manifest
    // with no proxy record (a local push, or a pruned entry) reads as `New` and serves —
    // only `Pending` blocks, so a local push is never held and never matures a proxy
    // digest. (A just-proxied manifest is recorded + checked on the fetch path above.)
    if let Some(resp) = quarantine_cache_serve_gate(state, &digest) {
        return resp;
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

/// Return the first blob / sub-manifest digest a manifest references that is NOT present
/// in storage, or `None` when every referenced item exists. Per the OCI Distribution Spec
/// a manifest pointing at content we do not have must be rejected (`MANIFEST_BLOB_UNKNOWN`)
/// rather than stored as a broken image. Bodies we cannot parse return `None` — malformed
/// manifests are out of scope here.
async fn missing_manifest_ref(body: &[u8], storage: &Storage, name: &str) -> Option<String> {
    let json = serde_json::from_slice::<serde_json::Value>(body).ok()?;

    // Image index / manifest list: referenced sub-manifests live under manifests/.
    if let Some(manifests) = json.get("manifests").and_then(|v| v.as_array()) {
        for m in manifests {
            if let Some(d) = m.get("digest").and_then(|v| v.as_str()) {
                if storage
                    .stat(&format!("docker/{}/manifests/{}.json", name, d))
                    .await
                    .is_none()
                {
                    return Some(d.to_string());
                }
            }
        }
        return None;
    }

    // Image manifest: the config descriptor and every layer are blobs.
    let mut refs: Vec<&str> = Vec::new();
    if let Some(d) = json
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|v| v.as_str())
    {
        refs.push(d);
    }
    if let Some(layers) = json.get("layers").and_then(|v| v.as_array()) {
        for l in layers {
            if let Some(d) = l.get("digest").and_then(|v| v.as_str()) {
                refs.push(d);
            }
        }
    }
    for d in refs {
        if storage
            .stat(&format!("docker/{}/blobs/{}", name, d))
            .await
            .is_none()
        {
            return Some(d.to_string());
        }
    }
    None
}

async fn put_manifest(
    State(state): State<AppState>,
    Path((name, reference)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    let ns = c.namespace;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Calculate digest
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&body)));

    // Reject a manifest that references content (config / layers / sub-manifests) we do
    // not have — a broken image must not be pushable (OCI MANIFEST_BLOB_UNKNOWN).
    if let Some(missing) = missing_manifest_ref(&body, &state.storage, &name).await {
        tracing::warn!(
            name = %name,
            reference = %reference,
            missing = %missing,
            "rejecting manifest push: references an absent blob/sub-manifest"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errors": [{
                    "code": "MANIFEST_BLOB_UNKNOWN",
                    "message": "manifest references an unknown blob",
                    "detail": { "digest": missing }
                }]
            })),
        )
            .into_response();
    }

    // Local push: NOT recorded in the quarantine ledger. The cooldown is a control on
    // content arriving from upstream; a local push has no proxy record, so the
    // cache-serve gate reads it as `New` and serves it. Not recording here also keeps a
    // local push from setting the first-seen clock for a digest later fetched upstream.

    // Store by tag/reference. Hold the SAME publish_lock key as delete_manifest so a
    // concurrent push/push or push/delete of one tag cannot interleave (the tag + digest
    // + metadata writes below stay consistent). Held until the end of the handler.
    let key = format!("docker/{}/manifests/{}.json", name, reference);
    let manifest_lock = state.publish_lock(&manifest_key(ns.as_deref(), &name, &reference));
    let _manifest_guard = manifest_lock.lock().await;
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

async fn list_tags(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let ns = c.namespace;
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    let prefix = manifest_prefix(ns.as_deref(), &name);
    let legacy_prefix = manifest_prefix(None, &name);
    let mut keys = match state.storage.list(&prefix).await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = ?e, "docker: failed to list manifests for tags");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    // Also include legacy non-namespaced keys during migration
    if prefix != legacy_prefix {
        match state.storage.list(&legacy_prefix).await {
            Ok(legacy_keys) => {
                keys.extend(legacy_keys);
                keys.sort();
                keys.dedup();
            }
            Err(e) => {
                tracing::warn!(error = ?e, "docker: failed to list legacy manifests, continuing with namespaced only");
            }
        }
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

/// Delete every tag manifest that resolves to `digest` (#658).
///
/// NORA stores a tag and its digest as independent files, so deleting a manifest
/// by digest would otherwise leave the tag still serving it. Each candidate tag
/// is locked and re-read under the lock, and only deleted if it *still* hashes to
/// `digest`, so a concurrent re-tag is never clobbered.
async fn delete_tags_for_digest(state: &AppState, ns: Option<&str>, name: &str, digest: &str) {
    use sha2::Digest as _;

    let prefix = manifest_prefix(ns, name);
    let legacy_prefix = manifest_prefix(None, name);
    let mut keys = state.storage.list(&prefix).await.unwrap_or_default();
    if prefix != legacy_prefix {
        if let Ok(legacy) = state.storage.list(&legacy_prefix).await {
            keys.extend(legacy);
        }
    }
    // Distinct tag references only — skip digest files and `.meta` sidecars.
    let mut tags: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            k.strip_prefix(&prefix)
                .or_else(|| k.strip_prefix(&legacy_prefix))
                .and_then(|t| t.strip_suffix(".json"))
                .map(String::from)
        })
        .filter(|t| !t.starts_with("sha256:") && !ends_with_ci(t, ".meta") && !t.contains(".meta."))
        .collect();
    tags.sort();
    tags.dedup();

    for tag in tags {
        let key = manifest_key(ns, name, &tag);
        let legacy_key = manifest_key(None, name, &tag);
        // Serialize with put_manifest on this tag.
        let lock = state.publish_lock(&key);
        let _guard = lock.lock().await;
        // Re-read under the lock; only delete if it STILL resolves to `digest`.
        let data = match storage_get_with_fallback(&state.storage, &key, &legacy_key).await {
            Ok(d) => d,
            Err(_) => continue,
        };
        let resolved = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));
        if resolved != digest {
            continue;
        }
        let _ = state.storage.delete(&key).await;
        let _ = state.storage.delete(&legacy_key).await;
        let _ = state
            .storage
            .delete(&manifest_meta_key(ns, name, &tag))
            .await;
        let _ = state
            .storage
            .delete(&manifest_meta_key(None, name, &tag))
            .await;
        tracing::info!(
            name = %name, tag = %tag, digest = %digest,
            "Docker tag removed because its manifest was deleted by digest (#658)"
        );
    }
}

async fn delete_manifest(
    State(state): State<AppState>,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
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
    } else {
        // #658: deleting by digest must also drop the tags that resolve to it,
        // so the registry stops serving a tag whose manifest is now gone.
        delete_tags_for_digest(&state, ns.as_deref(), &name, &reference).await;
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
    State(state): State<AppState>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
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

/// Result of a successful streaming blob fetch from upstream (#580).
pub struct FetchedBlob {
    /// Path to temp file containing the complete blob data.
    pub path: std::path::PathBuf,
    /// SHA-256 hex digest computed incrementally during download (64 chars, lowercase).
    pub sha256: String,
    /// Content-Length from upstream response, if provided (None for chunked responses).
    /// Used by mirror and future streaming response paths.
    #[allow(dead_code)]
    pub content_length: Option<u64>,
    /// RAII guard — deletes temp file on drop unless disarmed.
    pub _guard: TempFileGuard,
}

/// Fetch a blob from an upstream Docker registry, streaming to a temp file (#580).
///
/// Streams the upstream response to a temp file in `temp_dir` with incremental
/// SHA-256 hashing. Never accumulates the full blob in RAM.
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
    temp_dir: &std::path::Path,
) -> Result<FetchedBlob, ProxyError> {
    use crate::metrics::{PROXY_ACTIVE_DOWNLOADS, PROXY_DOWNLOAD_BYTES};

    // Track active concurrent proxy downloads. ProxyDownloadGuard decrements
    // on drop (success, error, or cancellation — all paths).
    PROXY_ACTIVE_DOWNLOADS.inc();
    let _download_gauge_guard = ProxyDownloadGuard;

    tracing::info!(
        blob.name = %name,
        blob.digest = %digest,
        upstream = %upstream_url,
        "Proxy blob download started"
    );

    let cb_key = format!("docker:{}", upstream_url.trim_end_matches('/'));
    let probe = cb.check(&cb_key)?;

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
        cb.record_failure(&cb_key, probe);
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
                    cb.record_failure(&cb_key, probe);
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
        if (400..500).contains(&status) {
            // 4xx — upstream is alive and answered (e.g. blob not found); not an
            // availability failure, so recover the breaker instead of counting
            // it against the upstream (#606).
            cb.record_alive(&cb_key, probe);
        } else {
            cb.record_failure(&cb_key, probe);
        }
        return Err(ProxyError::Upstream(status));
    }

    // Upstream Content-Length (None if chunked transfer-encoding)
    let upstream_content_length = response.content_length();

    // Create temp file in storage directory (same filesystem for atomic rename)
    let temp_path = temp_dir.join(format!("proxy-{}", uuid::Uuid::new_v4()));
    let guard = TempFileGuard::new(temp_path.clone());
    let mut file = tokio::fs::File::create(&temp_path)
        .await
        .map_err(|e| ProxyError::Network(format!("temp file create: {}", e)))?;

    // Stream body with per-chunk read timeout + incremental SHA-256
    use sha2::Digest;
    let mut stream = response.bytes_stream();
    let mut hasher = sha2::Sha256::new();
    let chunk_timeout = Duration::from_secs(read_timeout);
    let mut bytes_written: u64 = 0;

    loop {
        // CANCEL-SAFETY: timeout wraps a single stream.next() call. On timeout,
        // TempFileGuard drops and deletes the partial file — no leaked state.
        match tokio::time::timeout(chunk_timeout, stream.next()).await {
            Ok(Some(Ok(chunk))) => {
                hasher.update(&chunk);
                use tokio::io::AsyncWriteExt;
                file.write_all(&chunk)
                    .await
                    .map_err(|e| ProxyError::Network(format!("temp file write: {}", e)))?;
                bytes_written += chunk.len() as u64;
            }
            Ok(Some(Err(e))) => {
                cb.record_failure(&cb_key, probe);
                return Err(ProxyError::Network(format!("chunk read error: {}", e)));
            }
            Ok(None) => break, // stream finished
            Err(_) => {
                cb.record_failure(&cb_key, probe);
                return Err(ProxyError::Network(format!(
                    "read timeout ({}s per chunk)",
                    read_timeout
                )));
            }
        }
    }

    // Flush to disk before returning
    use tokio::io::AsyncWriteExt;
    file.flush()
        .await
        .map_err(|e| ProxyError::Network(format!("temp file flush: {}", e)))?;
    drop(file);

    let sha256 = hex::encode(sha2::Digest::finalize(hasher));
    cb.record_success(&cb_key, probe);
    PROXY_DOWNLOAD_BYTES.inc_by(bytes_written);

    tracing::info!(
        bytes = bytes_written,
        content_length = ?upstream_content_length,
        "Proxy blob download complete"
    );

    // Transfer guard ownership to FetchedBlob — caller is responsible for
    // disarming after successful put_from_path (which moves the temp file).
    // If caller drops FetchedBlob without disarming, temp file is cleaned up.
    Ok(FetchedBlob {
        path: temp_path,
        sha256,
        content_length: upstream_content_length,
        _guard: guard,
    })
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
    let probe = cb.check(&cb_key)?;

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
        cb.record_failure(&cb_key, probe);
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
                    cb.record_failure(&cb_key, probe);
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
        if (400..500).contains(&status) {
            // 4xx — upstream is alive and answered (e.g. manifest not found);
            // recover the breaker rather than counting it as a failure (#606).
            cb.record_alive(&cb_key, probe);
        } else {
            cb.record_failure(&cb_key, probe);
        }
        return Err(ProxyError::Upstream(status));
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.docker.distribution.manifest.v2+json")
        .to_string();

    let bytes = response.bytes().await.map_err(|e| {
        cb.record_failure(&cb_key, probe);
        ProxyError::Network(e.to_string())
    })?;

    cb.record_success(&cb_key, probe);
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
/// manifest was first pushed or cached. This is a NORA-side timestamp (not an
/// upstream-supplied date), so it is unaffected by `server.trust_upstream_dates`
/// (#513) — there is no spoofable upstream date on this path.
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
async fn update_metadata_on_pull(state: AppState, storage: Storage, meta_key: String) {
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

    #[tokio::test]
    async fn verifying_reader_passes_match_and_aborts_mismatch() {
        use sha2::Digest as _;
        use tokio::io::AsyncReadExt;

        let data = b"hello-blob-content-1234567890";
        let good = format!("sha256:{}", hex::encode(sha2::Sha256::digest(data)));

        // Matching digest: the stream reads fully with no error.
        let mut ok = VerifyingReader::new(&data[..], &good);
        let mut buf = Vec::new();
        assert!(ok.read_to_end(&mut buf).await.is_ok());
        assert_eq!(buf, data);

        // Wrong digest: the error surfaces at EOF, aborting the stream rather
        // than letting a tampered blob complete cleanly.
        let bad = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(b"different-bytes"))
        );
        let mut tampered = VerifyingReader::new(&data[..], &bad);
        let mut buf2 = Vec::new();
        assert!(
            tampered.read_to_end(&mut buf2).await.is_err(),
            "a digest mismatch must error the stream, not complete cleanly"
        );
    }

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

    // --- validate_upload_uuid tests ---

    #[test]
    fn test_validate_upload_uuid_valid() {
        assert!(validate_upload_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_upload_uuid("abcdef01-2345-4678-9abc-def012345678").is_ok());
    }

    #[test]
    fn test_validate_upload_uuid_rejects_path_traversal() {
        assert!(validate_upload_uuid("../../../etc/passwd").is_err());
        assert!(validate_upload_uuid("x/../../etc/cron.d/backdoor").is_err());
        assert!(validate_upload_uuid("..").is_err());
    }

    #[test]
    fn test_validate_upload_uuid_rejects_invalid() {
        assert!(validate_upload_uuid("").is_err()); // empty
        assert!(validate_upload_uuid("ABCDEF01-2345-4678-9ABC-DEF012345678").is_err()); // uppercase
        assert!(validate_upload_uuid("hello world").is_err()); // spaces
        assert!(validate_upload_uuid("a".repeat(37).as_str()).is_err()); // too long
    }

    // --- cleanup_upload_temp_dir tests ---

    #[test]
    fn test_cleanup_upload_temp_dir_removes_old_files() {
        use std::fs::FileTimes;
        use std::time::SystemTime;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let upload_dir = temp_dir.path().join("tmp/docker-uploads");
        std::fs::create_dir_all(&upload_dir).unwrap();

        // Create an old file (set mtime to 2 hours ago)
        let old_file = upload_dir.join("old-uuid");
        std::fs::write(&old_file, b"stale data").unwrap();
        let old_time = SystemTime::now() - std::time::Duration::from_secs(7200);
        let times = FileTimes::new().set_modified(old_time);
        std::fs::File::options()
            .write(true)
            .open(&old_file)
            .unwrap()
            .set_times(times)
            .unwrap();

        // Create a recent file
        let new_file = upload_dir.join("new-uuid");
        std::fs::write(&new_file, b"fresh data").unwrap();

        cleanup_upload_temp_dir(temp_dir.path().to_str().unwrap());

        assert!(!old_file.exists(), "old file should be removed");
        assert!(new_file.exists(), "recent file should be preserved");
    }

    #[test]
    fn test_cleanup_upload_temp_dir_nonexistent_dir() {
        // Should not panic when directory doesn't exist
        cleanup_upload_temp_dir("/nonexistent/path/that/does/not/exist");
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
    use crate::circuit_breaker::ProbeToken;
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::body::Body;
    use axum::http::{header, Method, StatusCode};
    use sha2::Digest;

    #[tokio::test]
    async fn test_docker_namespace_scope_enforced() {
        use crate::auth::NamespaceAuthority;
        use crate::config::ScopeEnforcement;
        use axum::body::Bytes;
        use axum::extract::{Path, State};
        use axum::http::Uri;
        use axum::Extension;

        let ctx = create_test_context();
        let scoped = NamespaceAuthority::from_oidc_scope(
            "ci",
            &["myorg/**".to_string()],
            ScopeEnforcement::Enforce,
        );

        // Out-of-scope blob upload (POST) -> 403.
        let resp = super::docker_v2_dispatch(
            State(ctx.state.clone()),
            Method::POST,
            Path("other/app/blobs/uploads/".to_string()),
            Extension(scoped.clone()),
            "/v2/other/app/blobs/uploads/".parse::<Uri>().unwrap(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // In-scope blob upload start -> not denied (enforcement passes).
        let resp = super::docker_v2_dispatch(
            State(ctx.state.clone()),
            Method::POST,
            Path("myorg/app/blobs/uploads/".to_string()),
            Extension(scoped.clone()),
            "/v2/myorg/app/blobs/uploads/".parse::<Uri>().unwrap(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);

        // Reads are never gated, even out of scope (404, not 403).
        let resp = super::docker_v2_dispatch(
            State(ctx.state.clone()),
            Method::GET,
            Path("other/app/manifests/latest".to_string()),
            Extension(scoped.clone()),
            "/v2/other/app/manifests/latest".parse::<Uri>().unwrap(),
            axum::http::HeaderMap::new(),
            Bytes::new(),
        )
        .await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

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

    /// Seed the all-zero config blob a test manifest references, so the manifest PUT passes
    /// the OCI blob-existence check (real clients push referenced blobs before the manifest).
    async fn seed_zero_config(state: &crate::AppState, name: &str) {
        let _ = state
            .storage
            .put(
                &format!(
                    "docker/{}/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    name
                ),
                b"x",
            )
            .await;
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

        seed_zero_config(&ctx.state, "alpine").await;
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
    async fn test_manifest_push_rejects_absent_blob() {
        let ctx = create_test_context();
        // A manifest referencing a config blob we never uploaded must be rejected
        // (OCI MANIFEST_BLOB_UNKNOWN) rather than stored as a broken image.
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            },
            "layers": []
        });
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/v2/reject/manifests/latest",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
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
        seed_zero_config(&ctx.state, "alpine").await;
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
        seed_zero_config(&ctx.state, "alpine").await;
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
    async fn test_docker_delete_by_digest_removes_tag() {
        // #658: deleting a manifest by digest must also drop the tags that
        // resolve to it, so the registry stops serving a now-gone manifest.
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
        seed_zero_config(&ctx.state, "alpine").await;
        let put_resp = send(
            &ctx.app,
            Method::PUT,
            "/v2/alpine/manifests/v1",
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

        // Delete the manifest by digest.
        let del = send(
            &ctx.app,
            Method::DELETE,
            &format!("/v2/alpine/manifests/{}", digest),
            Body::empty(),
        )
        .await;
        assert_eq!(del.status(), StatusCode::ACCEPTED);

        // The tag must no longer resolve.
        let tag_get = send(
            &ctx.app,
            Method::GET,
            "/v2/alpine/manifests/v1",
            Body::empty(),
        )
        .await;
        assert_eq!(
            tag_get.status(),
            StatusCode::NOT_FOUND,
            "tag must 404 after its manifest is deleted by digest (#658)"
        );

        // ...and it must not appear in tags/list.
        let list = send(&ctx.app, Method::GET, "/v2/alpine/tags/list", Body::empty()).await;
        let body = body_bytes(list).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let tags = json["tags"].as_array().unwrap();
        assert!(
            !tags.contains(&serde_json::json!("v1")),
            "v1 must be gone from tags/list after digest delete (#658)"
        );
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
    async fn test_docker_single_post_monolithic_upload() {
        // #688: POST /blobs/uploads/?digest= with the blob in the body must store
        // it and return 201 in one request (the OCI "single POST" form).
        let ctx = create_test_context();
        let blob_data = b"single-post monolithic blob";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

        let resp = send(
            &ctx.app,
            Method::POST,
            &format!("/v2/alpine/blobs/uploads/?digest={}", digest),
            Body::from(&blob_data[..]),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "single-POST monolithic upload must return 201"
        );
        assert_eq!(
            resp.headers()
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            digest
        );

        // The blob must now exist.
        let head = send(
            &ctx.app,
            Method::HEAD,
            &format!("/v2/alpine/blobs/{}", digest),
            Body::empty(),
        )
        .await;
        assert_eq!(
            head.status(),
            StatusCode::OK,
            "blob must exist after a single-POST upload"
        );
    }

    #[tokio::test]
    async fn test_docker_single_post_digest_mismatch_rejected() {
        // A single-POST upload whose body does not match ?digest= must be rejected.
        let ctx = create_test_context();
        let wrong = format!("sha256:{}", "0".repeat(64));
        let resp = send(
            &ctx.app,
            Method::POST,
            &format!("/v2/alpine/blobs/uploads/?digest={}", wrong),
            Body::from(&b"some other bytes"[..]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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

    #[test]
    fn test_parse_byte_range() {
        use super::parse_byte_range;
        assert_eq!(parse_byte_range("bytes=0-3", 10), Some((0, 3)));
        assert_eq!(parse_byte_range("bytes=5-", 10), Some((5, 9))); // open-ended
        assert_eq!(parse_byte_range("bytes=-4", 10), Some((6, 9))); // suffix (last 4)
        assert_eq!(parse_byte_range("bytes=8-100", 10), Some((8, 9))); // clamp end to size
        assert_eq!(parse_byte_range("bytes=10-12", 10), None); // start past end
        assert_eq!(parse_byte_range("bytes=5-3", 10), None); // reversed
        assert_eq!(parse_byte_range("nonsense", 10), None); // unparsable
        assert_eq!(parse_byte_range("bytes=0-3", 0), None); // empty object

        // mutation-found gaps (cargo-mutants): exercise the single-byte range
        // and the suffix form against an empty object.
        assert_eq!(parse_byte_range("bytes=5-5", 10), Some((5, 5))); // single byte (kills `>`→`>=`)
        assert_eq!(parse_byte_range("bytes=-5", 0), None); // suffix + empty (kills `||`→`&&`)
    }

    proptest::proptest! {
        /// Property test (#3): fuzz the string LEXER of `parse_byte_range` — the
        /// part Kani cannot symbolically execute. Over biased range-like strings
        /// and any size it must never panic, and any `Some((s, e))` is
        /// well-formed: `s <= e < size`. Pairs with the Kani proof of
        /// `byte_range_core` (the arithmetic) for full-function coverage.
        #[test]
        fn parse_byte_range_lexer_invariant(
            value in "bytes=-?[0-9]{0,9}-?[0-9]{0,9}",
            size in proptest::prelude::any::<u64>(),
        ) {
            if let Some((s, e)) = super::parse_byte_range(&value, size) {
                proptest::prop_assert!(s <= e, "inverted: {} > {}", s, e);
                proptest::prop_assert!(e < size, "oob end: {} >= {}", e, size);
                proptest::prop_assert!(s < size, "oob start: {} >= {}", s, size);
            }
        }
    }

    #[tokio::test]
    async fn test_docker_blob_range_request() {
        use tower::ServiceExt;
        let ctx = create_test_context();
        let blob = b"0123456789abcdef";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob)));

        let post = send(
            &ctx.app,
            Method::POST,
            "/v2/rng/blobs/uploads/",
            Body::empty(),
        )
        .await;
        let loc = post
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let uuid = loc.rsplit('/').next().unwrap();
        let put_url = format!("/v2/rng/blobs/uploads/{}?digest={}", uuid, digest);
        send(&ctx.app, Method::PUT, &put_url, Body::from(&blob[..])).await;

        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri(format!("/v2/rng/blobs/{}", digest))
            .header(header::RANGE, "bytes=4-7")
            .body(Body::empty())
            .unwrap();
        let resp = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes 4-7/{}", blob.len())
        );
        let body = body_bytes(resp).await;
        assert_eq!(body.as_ref(), &blob[4..=7]);
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
        seed_zero_config(&ctx.state, "library/alpine").await;
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
            .record_failure("docker:http://127.0.0.1:1", ProbeToken::BACKGROUND);
        ctx.state
            .circuit_breaker
            .record_failure("docker:http://127.0.0.1:1", ProbeToken::BACKGROUND);

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
        seed_zero_config(&ctx.state, "verify").await;
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
        seed_zero_config(&ctx.state, "ctcheck").await;
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
        seed_zero_config(&ctx.state, "clcheck").await;
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
            .record_failure("docker:http://127.0.0.1:1", ProbeToken::BACKGROUND);
        ctx.state
            .circuit_breaker
            .record_failure("docker:http://127.0.0.1:1", ProbeToken::BACKGROUND);

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

        let keys = ctx.state.storage.list("docker/").await.unwrap();
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

    /// Build a DockerConfig with the given upstreams and default_action = Allow.
    fn docker_config_allow(
        upstreams: Vec<crate::config::DockerUpstream>,
    ) -> crate::config::DockerConfig {
        crate::config::DockerConfig {
            upstreams,
            default_action: crate::config::DefaultAction::Allow,
            ..Default::default()
        }
    }

    /// Build a DockerConfig with the given upstreams and default_action = Deny.
    fn docker_config_deny(
        upstreams: Vec<crate::config::DockerUpstream>,
    ) -> crate::config::DockerConfig {
        crate::config::DockerConfig {
            upstreams,
            default_action: crate::config::DefaultAction::Deny,
            ..Default::default()
        }
    }

    #[test]
    fn test_canonicalize_prefix_routing() {
        let upstreams = vec![crate::config::DockerUpstream {
            url: "https://registry-1.docker.io".to_string(),
            auth: None,
            namespace: Some("docker.io".to_string()),
            prefix: Some("docker-hub".to_string()),
        }];
        let cfg = docker_config_allow(upstreams.clone());

        let c = super::canonicalize("docker-hub/library/nginx", &cfg);
        assert_eq!(c.name, "library/nginx");
        assert_eq!(c.namespace.as_deref(), Some("docker.io"));
        assert_eq!(c.upstreams_to_try(&upstreams).len(), 1);
        assert!(!c.denied);
    }

    #[test]
    fn test_canonicalize_hostname_detection() {
        let upstreams = vec![crate::config::DockerUpstream {
            url: "https://registry-1.docker.io".to_string(),
            auth: None,
            namespace: Some("docker.io".to_string()),
            prefix: None,
        }];
        let cfg = docker_config_allow(upstreams.clone());

        let c = super::canonicalize("docker.io/library/nginx", &cfg);
        assert_eq!(c.name, "library/nginx");
        assert_eq!(c.namespace.as_deref(), Some("docker.io"));
        // Known namespace matches specific upstream
        assert_eq!(c.upstreams_to_try(&upstreams).len(), 1);
        assert!(!c.denied);

        // Unknown hostname → strip but use default upstream
        let c2 = super::canonicalize("ghcr.io/requarks/wiki", &cfg);
        assert_eq!(c2.name, "requarks/wiki");
        assert_eq!(c2.namespace.as_deref(), Some("docker.io"));
        // No specific match → all upstreams
        assert_eq!(c2.upstreams_to_try(&upstreams).len(), 1); // only 1 configured
        assert!(!c2.denied); // Allow mode → not denied
    }

    #[test]
    fn test_canonicalize_fallback() {
        let upstreams = vec![crate::config::DockerUpstream {
            url: "https://registry-1.docker.io".to_string(),
            auth: None,
            namespace: Some("docker.io".to_string()),
            prefix: None,
        }];
        let cfg = docker_config_allow(upstreams.clone());

        // No prefix, no dot in first segment → fallback
        let c = super::canonicalize("library/nginx", &cfg);
        assert_eq!(c.name, "library/nginx");
        assert_eq!(c.namespace.as_deref(), Some("docker.io"));
        assert_eq!(c.upstreams_to_try(&upstreams).len(), 1);
        assert!(!c.denied);

        // Single segment
        let c2 = super::canonicalize("alpine", &cfg);
        assert_eq!(c2.name, "alpine");
        assert_eq!(c2.namespace.as_deref(), Some("docker.io"));
        assert!(!c2.denied);
    }

    #[test]
    fn test_canonicalize_empty_upstreams() {
        let upstreams: Vec<crate::config::DockerUpstream> = vec![];
        let cfg = docker_config_allow(upstreams.clone());

        let c = super::canonicalize("library/nginx", &cfg);
        assert_eq!(c.name, "library/nginx");
        assert!(c.namespace.is_none());
        assert!(c.upstreams_to_try(&upstreams).is_empty());
        assert!(!c.denied);
    }

    #[test]
    fn test_manifest_cache_fresh_tag_vs_digest() {
        use super::manifest_cache_fresh;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Digest references are immutable → always fresh, regardless of upstream/ttl.
        assert!(manifest_cache_fresh(true, true, -1, Some(now)));
        assert!(manifest_cache_fresh(true, true, 0, None));

        // Hosted tag (no upstream to revalidate against) is authoritative → fresh.
        assert!(manifest_cache_fresh(false, false, -1, Some(now)));

        // Proxied tag with the default ttl (-1) must REVALIDATE (#638) — not fresh.
        assert!(!manifest_cache_fresh(false, true, -1, Some(now)));
        // ttl=0 also revalidates every pull.
        assert!(!manifest_cache_fresh(false, true, 0, Some(now)));

        // Proxied tag within a POSITIVE ttl window → may serve from cache.
        assert!(manifest_cache_fresh(false, true, 3600, Some(now)));
        // Proxied tag beyond the window → revalidate.
        assert!(!manifest_cache_fresh(
            false,
            true,
            3600,
            Some(now.saturating_sub(7200))
        ));
        // Proxied tag with unknown mtime → revalidate.
        assert!(!manifest_cache_fresh(false, true, 3600, None));
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
        let cfg = docker_config_allow(upstreams.clone());

        // Prefix routes to specific upstream
        let c1 = super::canonicalize("ghcr/requarks/wiki", &cfg);
        assert_eq!(c1.name, "requarks/wiki");
        assert_eq!(c1.namespace.as_deref(), Some("ghcr.io"));
        let targets = c1.upstreams_to_try(&upstreams);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].url, "https://ghcr.io");
        assert!(!c1.denied);

        // No prefix match → all upstreams (allow mode)
        let c2 = super::canonicalize("library/nginx", &cfg);
        assert_eq!(c2.name, "library/nginx");
        assert_eq!(c2.upstreams_to_try(&upstreams).len(), 2);
        assert!(!c2.denied);
    }

    #[test]
    fn test_canonicalize_deny_mode_blocks_unmatched() {
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
        let cfg = docker_config_deny(upstreams.clone());

        // Prefix match → allowed even in deny mode
        let c1 = super::canonicalize("ghcr/requarks/wiki", &cfg);
        assert!(!c1.denied);
        assert_eq!(c1.name, "requarks/wiki");

        // No prefix match → denied
        let c2 = super::canonicalize("library/nginx", &cfg);
        assert!(c2.denied);
        assert!(c2.denied_response().is_some());

        // Single segment (no slash) → denied
        let c3 = super::canonicalize("alpine", &cfg);
        assert!(c3.denied);

        // Unknown hostname → denied
        let c4 = super::canonicalize("quay.io/prometheus/node-exporter", &cfg);
        assert!(c4.denied);
    }

    #[test]
    fn test_canonicalize_deny_mode_allows_known_hostname() {
        let upstreams = vec![crate::config::DockerUpstream {
            url: "https://registry-1.docker.io".to_string(),
            auth: None,
            namespace: Some("docker.io".to_string()),
            prefix: None,
        }];
        let cfg = docker_config_deny(upstreams.clone());

        // Known namespace hostname → matched upstream → allowed
        let c = super::canonicalize("docker.io/library/nginx", &cfg);
        assert!(!c.denied);
        assert_eq!(c.name, "library/nginx");
        assert_eq!(c.namespace.as_deref(), Some("docker.io"));
    }

    #[test]
    fn test_denied_response_format() {
        let upstreams = vec![crate::config::DockerUpstream {
            url: "https://registry-1.docker.io".to_string(),
            auth: None,
            namespace: Some("docker.io".to_string()),
            prefix: Some("hub".to_string()),
        }];
        let cfg = docker_config_deny(upstreams);

        let c = super::canonicalize("library/nginx", &cfg);
        assert!(c.denied);

        // denied_response returns Some for denied requests
        let resp = c.denied_response();
        assert!(resp.is_some());

        // Non-denied request returns None
        let c2 = super::canonicalize("hub/library/nginx", &cfg);
        assert!(!c2.denied);
        assert!(c2.denied_response().is_none());
    }

    // ── #580/#581: streaming proxy blob integrity (content-addressable) ──

    /// Security-critical (#581): an upstream that returns bytes whose SHA-256 does
    /// not match the requested content-addressable digest must be rejected with
    /// 502, and the poisoned bytes must never enter the cache, the pin store, or
    /// be served — and the streaming temp file must be cleaned up.
    #[tokio::test]
    async fn test_docker_proxy_blob_sha256_mismatch_rejected() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;

        // The requested digest is the SHA-256 of the *real* content...
        let requested_digest = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(b"the real layer"))
        );
        // ...but the upstream serves unrelated (poisoned) bytes for that digest.
        let poisoned = b"poisoned bytes that do not hash to the requested digest".to_vec();

        Mock::given(method("GET"))
            .and(path(format!("/v2/library/test/blobs/{requested_digest}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(poisoned))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: upstream.uri(),
                auth: None,
                namespace: None,
                prefix: None,
            }];
        });

        let response = send(
            &ctx.app,
            Method::GET,
            &format!("/v2/library/test/blobs/{requested_digest}"),
            Body::empty(),
        )
        .await;

        // Mismatch → 502 Bad Gateway (verify-before-serve, no tee to client).
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        // Poisoned blob must NOT have been cached under the docker blob key
        // (computed via the same canonicalize/blob_key path the handler uses).
        let c = super::canonicalize("library/test", &ctx.state.config.docker);
        let key = super::blob_key(c.namespace.as_deref(), &c.name, &requested_digest);
        assert!(
            ctx.state.storage.get(&key).await.is_err(),
            "poisoned blob must not be cached"
        );

        // TempFileGuard must have cleaned up — no leftover proxy temp files.
        let proxy_tmp =
            std::path::Path::new(&ctx.state.config.storage.path).join("tmp/docker-proxy");
        let leftover = std::fs::read_dir(&proxy_tmp)
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0);
        assert_eq!(leftover, 0, "temp files must be cleaned up after rejection");
    }

    /// #638 regression: a proxied tag whose cached manifest is outdated must be revalidated
    /// against upstream, not served stale. The cache is pre-seeded with the OLD manifest
    /// (deterministic — manifest caching on the proxy path is spawned async, so a back-to-back
    /// pull would race the write). RED on the pre-fix code (a cached tag was served forever
    /// because the metadata_ttl default is -1), GREEN after proxied tags are revalidated.
    #[tokio::test]
    async fn test_docker_proxy_tag_revalidates_on_upstream_change() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let ct = "application/vnd.oci.image.manifest.v1+json";
        let manifest_old =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa"},"layers":[]}"#.to_vec();
        let manifest_new =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:bbbb"},"layers":[{"digest":"sha256:cccc"}]}"#.to_vec();

        // Upstream now serves the NEW manifest for the tag.
        Mock::given(method("GET"))
            .and(path("/v2/library/test/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", ct)
                    .set_body_bytes(manifest_new.clone()),
            )
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: upstream.uri(),
                auth: None,
                namespace: None,
                prefix: None,
            }];
        });

        // Pre-seed the cache with the OLD manifest (what NORA fetched earlier).
        let c = super::canonicalize("library/test", &ctx.state.config.docker);
        let key = super::manifest_key(c.namespace.as_deref(), &c.name, "latest");
        ctx.state
            .storage
            .put(&key, &manifest_old)
            .await
            .expect("seed cache");

        // Pull the tag: the cached manifest is outdated, so a proxied (mutable) tag must be
        // revalidated and return the upstream NEW manifest — not the stale cached OLD one (#638).
        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/library/test/manifests/latest",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_bytes(resp).await.as_ref(),
            manifest_new.as_slice(),
            "a proxied tag with an outdated cached manifest must revalidate and return the upstream version (#638)"
        );
    }

    /// Positive control for the integrity check: when the upstream bytes hash to
    /// the requested digest, the blob is verified, cached, and streamed back to
    /// the client via the get_reader path (#580) with a 200.
    #[tokio::test]
    async fn test_docker_proxy_blob_sha256_match_served_and_cached() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let content = b"a genuine docker layer payload".to_vec();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&content)));

        Mock::given(method("GET"))
            .and(path(format!("/v2/library/ok/blobs/{digest}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(content.clone()))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: upstream.uri(),
                auth: None,
                namespace: None,
                prefix: None,
            }];
        });

        let response = send(
            &ctx.app,
            Method::GET,
            &format!("/v2/library/ok/blobs/{digest}"),
            Body::empty(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        assert_eq!(
            body.as_ref(),
            content.as_slice(),
            "served body must match upstream"
        );

        // Verified blob is cached synchronously under the docker blob key
        // (computed via the same canonicalize/blob_key path the handler uses).
        let c = super::canonicalize("library/ok", &ctx.state.config.docker);
        let key = super::blob_key(c.namespace.as_deref(), &c.name, &digest);
        assert!(
            ctx.state.storage.get(&key).await.is_ok(),
            "verified blob must be cached"
        );
    }
}
