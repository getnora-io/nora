// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, NamespaceAuthority};
use crate::circuit_breaker::{upstream_key, CircuitBreakerRegistry, ProbeToken};
use crate::config::basic_auth_header;
use crate::proxy_coalesce::Flight;
use crate::registry::docker_auth::DockerAuth;
use crate::registry::{circuit_open_response, method_not_allowed, ProxyError, UpstreamMiss};
use crate::registry::{
    content_length, sha256_of_file, stream_body_to_file, StreamOutcome, TempFileGuard,
};
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
use nora_registry::annotations::Annotations;
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

/// Stems of the sidecars stored beside a manifest `<reference>.json`: `<reference>.meta.json`
/// (push metadata) and `<reference>.stats.json` (pull counts, #1114).
const MANIFEST_SIDECAR_STEMS: [&str; 2] = [".meta", ".stats"];

/// The tag a file under `…/manifests/` stores, or `None` if it stores no tag: a digest copy
/// (`sha256:….json`), a sidecar (`<tag>.meta.json`, `<tag>.stats.json`) or any name that is not
/// a valid tag. Every listing of tags (tags/list, delete by digest, retention, the UI, the
/// repository index) asks this one function.
pub(crate) fn tag_from_manifest_file(file_name: &str) -> Option<&str> {
    let tag = file_name.strip_suffix(".json")?;
    let is_tag = validate_docker_reference(tag).is_ok() && !tag.contains(':');
    let is_sidecar = MANIFEST_SIDECAR_STEMS.iter().any(|s| ends_with_ci(tag, s));
    (is_tag && !is_sidecar).then_some(tag)
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

/// Open a streaming reader for a blob, trying namespaced then legacy key (#580).
///
/// This provides backward compatibility during migration from flat to namespaced storage.
/// The fallback fires ONLY on `NotFound`: the two keys can hold different bytes (a
/// proxied-current copy vs a pre-migration one), so falling back on a transient backend
/// error would make which copy is served depend on backend weather — a per-request
/// divergent answer for the same reference. Transient errors propagate instead.
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
        Err(crate::storage::StorageError::NotFound) if ns_key != legacy_key => {
            storage.get_reader(legacy_key).await
        }
        other => other,
    }
    // Docker blobs are content-addressed: the URL digest is the integrity
    // check, so the stored pin is not needed here.
    .map(|(size, _pin, reader)| (size, reader))
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

// #849: `VerifyingReader` verifies the blob digest at EOF, so it may be served through the
// `reader_stream_body` sole-sink. A raw reader carries neither impl, so it cannot be handed
// to it — a compile-time serve-integrity witness on the streaming path.
impl<R: tokio::io::AsyncRead + Send + Unpin + 'static>
    nora_registry::verified::stream_sealed::Sealed for VerifyingReader<R>
{
}
impl<R: tokio::io::AsyncRead + Send + Unpin + 'static> nora_registry::verified::VerifiedByteReader
    for VerifyingReader<R>
{
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
    /// Set on a push: the digest of the manifest pushed to this tag. A push answers its tag
    /// whatever an upstream holds for it; a manifest without this record (pushed before 1.4.0,
    /// or a flat proxy cache from before #349) keeps its old place in the lookup order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushed_digest: Option<String>,
}

/// Information about a single layer in a Docker image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerInfo {
    pub digest: String,
    pub size: u64,
}

/// One manifest's un-flushed pull statistics (#1114).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct PullDelta {
    /// Pulls counted since the last flush.
    pub downloads: u64,
    /// Most recent pull time (unix secs) seen since the last flush.
    pub last_pulled: u64,
}

/// In-memory, off-request-path accumulator for docker pull statistics (#1114).
///
/// A manifest GET bumps the per-key counter here (a microsecond lock, no I/O)
/// instead of rewriting the manifest's `.meta.json` — which every pull used to
/// do and which raced the request-path publish-date read, logging INTEGRITY
/// VIOLATION on healthy data. A background task drains this in batches into a
/// separate `.stats.json` sidecar, so `.meta.json` is immutable after publish.
///
/// Soft state: the map is rebuildable-empty after a restart, so at most one
/// flush interval of counts is lost on a crash (accepted — pull stats are
/// best-effort, like the in-memory indexes). Mirrors the `publish_locks`
/// pattern (`parking_lot::Mutex<HashMap>`) to add no new dependency.
#[derive(Default)]
pub(crate) struct PullStatsAccumulator {
    inner: parking_lot::Mutex<std::collections::HashMap<String, PullDelta>>,
}

impl PullStatsAccumulator {
    /// Record one pull of `meta_key` at `now` (unix secs). Cheap: a brief lock,
    /// no storage I/O, no spawn, no publish lock.
    pub(crate) fn record(&self, meta_key: &str, now: u64) {
        let mut g = self.inner.lock();
        let e = g.entry(meta_key.to_string()).or_default();
        e.downloads += 1;
        if now > e.last_pulled {
            e.last_pulled = now;
        }
    }

    /// Take and clear every accumulated delta — for the flush task.
    pub(crate) fn drain(&self) -> Vec<(String, PullDelta)> {
        std::mem::take(&mut *self.inner.lock())
            .into_iter()
            .collect()
    }

    /// The current un-flushed delta for one key (for the UI read path to add on
    /// top of the flushed sidecar value). Default (zeros) when nothing pending.
    pub(crate) fn peek(&self, meta_key: &str) -> PullDelta {
        self.inner.lock().get(meta_key).copied().unwrap_or_default()
    }
}

/// In-progress upload session with metadata.
///
/// Blob data is streamed frame-by-frame to a temporary file, bounded per request
/// by [`effective_upload_cap`] and globally by [`IN_FLIGHT_UPLOADS`]; the request
/// body is never fully buffered in RAM (#817). Finalization hashes the temp file
/// and moves it into storage via `put_from_path` without an in-RAM copy.
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

/// OCI-conformant 429 for the concurrent-upload ceiling. containers/common
/// retry logic only backs off on errcode TOOMANYREQUESTS in a JSON body; a
/// plain-text 429 aborts the client push outright.
fn too_many_uploads() -> Response {
    let body = json!({
        "errors": [{
            "code": "TOOMANYREQUESTS",
            "message": "too many concurrent uploads",
            "detail": { "limit": max_upload_sessions() }
        }]
    });
    // Jittered, not fixed: a constant retry window re-synchronizes every refused
    // client onto the same cadence, so the herd returns together and the same
    // subset wins each round.
    let retry_after = rand::Rng::gen_range(&mut rand::thread_rng(), 3..=10).to_string();
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::RETRY_AFTER, retry_after.as_str()),
            (header::CONTENT_TYPE, "application/json"),
        ],
        body.to_string(),
    )
        .into_response()
}

/// Read max session size from env (in MB) or use default
fn max_session_size() -> usize {
    let mb = std::env::var("NORA_MAX_UPLOAD_SESSION_SIZE_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_SESSION_SIZE_MB);
    mb.saturating_mul(1024 * 1024)
}

/// Max bytes buffered for a manifest PUT. Manifests/indexes are small JSON
/// (layer lists + a config reference); a streaming `Body` extractor is not
/// bounded by `DefaultBodyLimit`, so the dispatcher caps the manifest collect
/// explicitly — otherwise the OOM this fix removes from blobs would just move to
/// the manifest path (#817). 4 MiB matches common registry limits.
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// Per-request byte ceiling for a blob upload: the smaller of the upload-session
/// cap and the operator's global `body_limit_mb`. A streaming `Body` extractor
/// is NOT subject to `DefaultBodyLimit` (that only bounds `Bytes`-based
/// extractors), so the streaming paths must re-apply the tuned-down limit
/// themselves, or lowering `body_limit_mb` would silently stop bounding uploads.
fn effective_upload_cap(body_limit_mb: usize) -> u64 {
    let body_limit = (body_limit_mb as u64).saturating_mul(1024 * 1024);
    std::cmp::min(max_session_size() as u64, body_limit)
}

/// Global count of in-flight streaming blob uploads. Bounds concurrent uploads —
/// including monolithic POSTs, which never open a session and so bypass
/// `max_upload_sessions` — so streaming to disk cannot fan out unboundedly and
/// exhaust the disk (#817). Ceiling mirrors `max_upload_sessions`.
static IN_FLIGHT_UPLOADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// RAII guard: reserves an in-flight-upload slot, releasing it on drop (all exit
/// paths incl. cancellation/panic). `try_acquire` returns `None` if the ceiling
/// is already reached (caller returns 429).
struct InFlightGuard;

impl InFlightGuard {
    fn try_acquire() -> Option<Self> {
        use std::sync::atomic::Ordering;
        let prev = IN_FLIGHT_UPLOADS.fetch_add(1, Ordering::AcqRel);
        if prev >= max_upload_sessions() {
            IN_FLIGHT_UPLOADS.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(InFlightGuard)
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        IN_FLIGHT_UPLOADS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Current in-flight streaming upload count, sampled by the `/metrics` scrape.
pub fn in_flight_uploads() -> usize {
    IN_FLIGHT_UPLOADS.load(std::sync::atomic::Ordering::Acquire)
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

/// Remove expired upload sessions and their temp files (called by background task)
pub fn cleanup_expired_sessions(sessions: &RwLock<HashMap<String, UploadSession>>) {
    let mut guard = sessions.write();
    let before = guard.len();
    guard.retain(|_, s| {
        // Reap only sessions that are BOTH past their creation TTL AND whose temp
        // file has not been written recently. `created_at` never advances, so a
        // slow multi-GB upload that streams for many minutes (#817) would be
        // unlinked mid-flight if we keyed off creation alone — losing the open
        // fd's data and 404-ing an otherwise-successful push. The temp's mtime
        // advances with every frame, so an in-flight stream stays safe (same
        // active-write-safe check `cleanup_upload_temp_dir` already uses).
        if s.created_at.elapsed() < SESSION_TTL {
            return true;
        }
        let temp_active = std::fs::metadata(&s.temp_path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < SESSION_TTL);
        if temp_active {
            return true;
        }
        let _ = std::fs::remove_file(&s.temp_path);
        false
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

/// `SESSION_TTL` age guard keeps in-progress uploads safe under the periodic call.
pub fn cleanup_upload_temp_dir(data_dir: &str) {
    let dir = std::path::PathBuf::from(data_dir).join("tmp/docker-uploads");
    let removed = super::remove_stale_temp_files(&dir, SESSION_TTL);
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
    let removed = super::remove_stale_temp_files(&dir, PROXY_TEMP_MAX_AGE);
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

    // Config validation refuses a TTL that does not parse (#1099); the default only
    // covers a config built without it.
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
            "message": "held by quarantine policy on registry 'docker': digest must age past the quarantine window",
            "detail": {
                "registry": "docker",
                "digest": digest,
                "policy": {
                    "control": "quarantine",
                    "quarantine_ttl_secs": quarantine_secs,
                },
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

/// Build a 404 `MANIFEST_UNKNOWN` response per the OCI Distribution Spec.
///
/// Used for a genuine not-found on a manifest we do not hold — including the local
/// miss on a hosted internal-namespace repo (#821): namespace isolation refuses to
/// proxy an internal name upstream, but a hosted image's absent tag is a not-found,
/// not an authorization denial. Docker/BuildKit treats `403` on a manifest
/// `HEAD`/`GET` as fatal, whereas `404 MANIFEST_UNKNOWN` lets push pre-flight probes
/// and OCI referrers lookups proceed.
fn manifest_unknown_response(name: &str, reference: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "errors": [{
                "code": "MANIFEST_UNKNOWN",
                "message": "manifest unknown",
                "detail": { "name": name, "reference": reference }
            }]
        })),
    )
        .into_response()
}

/// Build a 404 `BLOB_UNKNOWN` response per the OCI Distribution Spec.
///
/// Companion to [`manifest_unknown_response`] for blobs; used for the internal-
/// namespace local miss (#821) so `GET` agrees with the `HEAD` probe (`check_blob`
/// already 404s) and never conflates not-found with `403 Forbidden`.
fn blob_unknown_response(digest: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "errors": [{
                "code": "BLOB_UNKNOWN",
                "message": "blob unknown to registry",
                "detail": { "digest": digest }
            }]
        })),
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
        let outcome = if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce) {
            "blocked"
        } else {
            "observed"
        };
        crate::metrics::QUARANTINE_HOLDS_TOTAL
            .with_label_values(&["docker", outcome])
            .inc();
        tracing::warn!(
            digest = %digest,
            status = %status.header_value(),
            mode = ?q_mode,
            quarantine_ttl_secs = q_secs,
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
/// Decide, without recording, whether a proxy-fetched blob is served or held: a digest
/// this mirror has never seen is treated as freshly quarantined for the decision, and is
/// recorded by [`quarantine_record_verified`] only once its fetch has verified — a fetch
/// that fails must not leave a first-seen timestamp behind for the real blob to inherit.
fn quarantine_proxy_fetch_gate(state: &AppState, digest: &str, upstream: &str) -> Option<Response> {
    let (q_mode, q_secs) = resolve_quarantine(state);
    if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
        return None;
    }
    let status = match state.digest_store.check("docker", digest, q_secs) {
        crate::digest_quarantine::QuarantineStatus::New => {
            crate::digest_quarantine::QuarantineStatus::Pending {
                remaining_secs: q_secs,
            }
        }
        status => status,
    };
    if !matches!(status, crate::digest_quarantine::QuarantineStatus::Mature) {
        let outcome = if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce) {
            "blocked"
        } else {
            "observed"
        };
        crate::metrics::QUARANTINE_HOLDS_TOTAL
            .with_label_values(&["docker", outcome])
            .inc();
        tracing::warn!(
            digest = %digest,
            upstream = %upstream,
            status = %status.header_value(),
            mode = ?q_mode,
            quarantine_ttl_secs = q_secs,
            "Quarantine: proxy-fetched blob held (new to this mirror)"
        );
        if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce) {
            return Some(quarantine_forbidden(digest, &status, q_secs));
        }
    }
    None
}

/// Record a verified proxy-fetched blob as first seen now. Docker quarantine never
/// trusts an upstream date (digest-addressed) — always NORA's own clock, preserving the
/// GHSA-4j4m fix. Idempotent: an existing record keeps its timestamp.
fn quarantine_record_verified(state: &AppState, digest: &str, upstream: &str) {
    let (q_mode, _) = resolve_quarantine(state);
    if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
        return;
    }
    state.digest_store.record("docker", digest, upstream, None);
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
    body: Body,
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
        // Fast-reject oversized uploads before reading a byte: docker clients send
        // Content-Length on monolithic PUT/POST. The streaming paths also enforce
        // this incrementally, but this rejects the common case up front (#817).
        if is_write {
            if let Some(len) = content_length(&headers) {
                if len > effective_upload_cap(state.0.config.server.body_limit_mb) {
                    return (StatusCode::PAYLOAD_TOO_LARGE, "Upload exceeds size limit")
                        .into_response();
                }
            }
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
                    } else if let (Some(digest), Some(from)) =
                        (params.get("mount"), params.get("from"))
                    {
                        mount_blob(state, name, from, digest).await
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
                Method::DELETE => {
                    cancel_upload(state, Path((name.to_string(), after.to_string()))).await
                }
                _ => method_not_allowed("PATCH, PUT, DELETE"),
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
            Method::PUT => match axum::body::to_bytes(body, MAX_MANIFEST_BYTES).await {
                Ok(b) => {
                    put_manifest(state, Path((name.to_string(), reference.to_string())), b).await
                }
                Err(_) => (StatusCode::PAYLOAD_TOO_LARGE, "Manifest too large").into_response(),
            },
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

/// Serve a blob already in storage (`key`, or the pre-namespace `legacy_key`): curation
/// integrity, the quarantine cooldown, `Range` (206/416), else the whole blob through the
/// streaming digest check. `None` when storage has neither key.
async fn serve_local_blob(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    name: &str,
    digest: &str,
    key: &str,
    legacy_key: &str,
) -> Option<Response> {
    let (size, reader) = storage_get_reader_with_fallback(&state.storage, key, legacy_key)
        .await
        .ok()?;
    // Curation integrity check using digest from URL (no full-data rehash).
    // Docker blobs are content-addressed: the URL digest IS the integrity.
    if let Some(response) = crate::curation::verify_integrity_by_hash(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Docker,
        name,
        Some(digest),
        digest,
    ) {
        return Some(response);
    }

    // Quarantine: a proxy-cached blob still within its cooldown window is held.
    // A blob with no proxy record (a local push, or an entry pruned past 90d)
    // reads as `New` and is served; only `Pending` blocks (enforce). Covers both
    // the 206 range serve and the 200 full serve below.
    if let Some(resp) = quarantine_cache_serve_gate(state, digest) {
        return Some(resp);
    }

    // Range request: 206 Partial Content, or 416 when the client asks past the end
    // (#657). A ranged response is partial, so the streaming SHA-256 verify (full-GET
    // only) does not apply — a ranged serve relies on the content-addressed storage
    // key plus the client's own content-digest check, as Docker/Harbor do. An
    // absent/malformed range falls through to the full 200 below.
    if let Some(response) = crate::registry::range::range_response(
        &state.storage,
        &[key, legacy_key],
        headers,
        size,
        "application/octet-stream",
        &[
            (
                header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".to_string(),
            ),
            (
                HeaderName::from_static("docker-content-digest"),
                digest.to_string(),
            ),
        ],
    )
    .await
    {
        if response.status() == StatusCode::PARTIAL_CONTENT {
            state.metrics.record_download("docker");
            state.metrics.record_cache_hit("docker");
        }
        return Some(response);
    }

    state.metrics.record_download("docker");
    state.metrics.record_cache_hit("docker");
    state.activity.push(ActivityEntry::new(
        ActionType::Pull,
        format!("{}@{}", name, &digest[..19.min(digest.len())]),
        crate::registry_type::RegistryType::Docker,
        "LOCAL",
    ));
    let stream = VerifyingReader::new(reader, digest);
    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, size)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
            .header("docker-content-digest", digest)
            .body(nora_registry::verified::reader_stream_body(stream))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    )
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
            crate::curation::RequestVersion::Known(digest.to_string()),
            None,
        ) {
            return response;
        }
    }

    let key = blob_key(ns.as_deref(), &name, &digest);
    let legacy_key = blob_key(None, &name, &digest);

    // Try local storage first — streaming read, never loads full blob into RAM (#580)
    if let Some(response) =
        serve_local_blob(&state, &headers, &name, &digest, &key, &legacy_key).await
    {
        return response;
    }

    // #733/#821: an internal-namespace image's blob with no local copy is never proxied
    // upstream (dependency-confusion defense — this early return precedes the proxy loop).
    // A hosted image's absent blob is a not-found, not an authz denial: return 404
    // BLOB_UNKNOWN so GET agrees with the HEAD probe (check_blob, which already 404s)
    // instead of the fatal-to-clients 403.
    if internal {
        crate::metrics::record_namespace_isolation_refused("docker");
        return blob_unknown_response(&digest);
    }

    let temp_dir = proxy_temp_dir(&state.config.storage.path);

    // Try upstream proxies (prefix-matched → single upstream, otherwise → fallback chain)
    // Includes library/ fallback for single-segment names (Docker Hub official images).
    let names_to_try: Vec<String> = if name.contains('/') {
        vec![name.clone()]
    } else {
        vec![name.clone(), format!("library/{}", name)]
    };

    // One record per upstream, across both names it may be asked under.
    let mut misses: Vec<UpstreamMiss> = upstreams_to_try
        .iter()
        .map(|_| UpstreamMiss::default())
        .collect();
    for try_name in &names_to_try {
        for (upstream, miss) in upstreams_to_try.iter().zip(misses.iter_mut()) {
            // Content-addressed: the URL digest is the hash the spool verifies before
            // storing, so the curation integrity check runs on it before upstream is
            // opened — a rejection must not strand a circuit-breaker probe.
            if let Some(response) = crate::curation::verify_integrity_by_hash(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Docker,
                try_name,
                Some(&digest),
                &digest,
            ) {
                return response;
            }
            // One upstream fetch per blob, shared by every request that asks while it fills
            // (#1003). The key is the storage key plus the name and upstream this request
            // resolved to, so a request only ever joins a fill it could have started itself;
            // it joins here, after every check above ran on its own request.
            let flight_key = format!("{key}\n{try_name}\n{}", upstream.url);
            for _attempt in 0..2 {
                let mut failure = None;
                let flight = state
                    .blob_flights
                    .leased(
                        &flight_key,
                        "docker",
                        crate::proxy_coalesce::follower_budget(state.config.docker.proxy_timeout),
                        || {
                            start_fill(
                                &state,
                                &upstream.url,
                                expose_opt(&upstream.auth),
                                try_name,
                                &digest,
                                &temp_dir,
                                &mut failure,
                            )
                        },
                    )
                    .await;
                let target = BlobTarget {
                    name: &name,
                    upstream_name: try_name,
                    digest: &digest,
                    key: &key,
                    legacy_key: &legacy_key,
                    upstream_url: &upstream.url,
                };
                match flight {
                    Some(Flight::Leader { value, own, lease }) => {
                        return lead_fill(&state, value, own, Some(lease), &target, &headers).await;
                    }
                    Some(Flight::Alone { value, own }) => {
                        return lead_fill(&state, value, own, None, &target, &headers).await;
                    }
                    Some(Flight::Follower(share)) => {
                        if let Some(response) = follow_fill(&state, share, &target, &headers).await
                        {
                            return response;
                        }
                        // The fill failed and its slot is released: take another turn.
                        miss.record(&ProxyError::Network("shared fill failed".into()));
                    }
                    None => match failure {
                        Some(FillStartError::Spool) => {
                            return StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                        Some(FillStartError::Upstream(ProxyError::CircuitOpen(reg))) => {
                            return circuit_open_response(&reg)
                        }
                        Some(FillStartError::Upstream(e)) => {
                            tracing::debug!(error = ?e, upstream = %upstream.url, name = %try_name, "Docker blob proxy fetch failed, trying next");
                            miss.record(&e);
                            break;
                        }
                        None => break,
                    },
                }
            }
        }
    }

    let mut miss = UpstreamMiss::default();
    for asked in &misses {
        miss.record_upstream(asked);
    }
    miss.response("docker", &format!("{name}@{digest}"))
}

/// 201 for a blob that is now present in `name`, in the shape `upload_blob`
/// returns.
fn blob_created(name: &str, digest: &str) -> Response {
    (
        StatusCode::CREATED,
        [
            (header::LOCATION, format!("/v2/{}/blobs/{}", name, digest)),
            (
                HeaderName::from_static("docker-content-digest"),
                digest.to_string(),
            ),
        ],
    )
        .into_response()
}

/// Cross-repo blob mount: `POST /v2/{name}/blobs/uploads/?mount=<digest>&from=<repo>`
/// links a blob that `from` already holds into `name` with no re-upload.
///
/// Every reason a mount cannot happen — unknown digest, unusable source repo,
/// storage failure, a digest still held by quarantine — degrades to a normal
/// upload session (202) instead of an error, as the OCI distribution spec
/// requires: the client then pushes the blob itself.
async fn mount_blob(state: State<AppState>, raw_name: &str, from: &str, digest: &str) -> Response {
    let c = canonicalize(raw_name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let Some(hex) = digest.strip_prefix("sha256:") else {
        return start_upload(state, Path(raw_name.to_string())).await;
    };
    if validate_digest(digest).is_err() {
        return start_upload(state, Path(raw_name.to_string())).await;
    }

    // Reads are never namespace-gated (see docker_v2_dispatch); the write scope
    // on `name` was already enforced there.
    let c_from = canonicalize(from, &state.config.docker);
    if c_from.denied || validate_docker_name(&c_from.name).is_err() {
        return start_upload(state, Path(raw_name.to_string())).await;
    }

    // Must match the key upload finalization writes.
    let dst_key = format!("docker/{}/blobs/{}", name, digest);
    if state.storage.stat(&dst_key).await.is_some() {
        return blob_created(&name, digest);
    }

    // A digest still inside its proxy cooldown must not be laundered into a
    // local repository by a mount.
    if quarantine_cache_serve_gate(&state, digest).is_some() {
        return start_upload(state, Path(raw_name.to_string())).await;
    }

    let ns_key = blob_key(c_from.namespace.as_deref(), &c_from.name, digest);
    let legacy_key = blob_key(None, &c_from.name, digest);
    let src_key = if state.storage.stat(&ns_key).await.is_some() {
        ns_key
    } else if ns_key != legacy_key && state.storage.stat(&legacy_key).await.is_some() {
        legacy_key
    } else {
        return start_upload(state, Path(raw_name.to_string())).await;
    };

    if let Err(e) = state.storage.copy(&src_key, &dst_key, Some(hex)).await {
        tracing::warn!(error = %e, src = %src_key, dst = %dst_key, "Blob mount failed, falling back to upload");
        return start_upload(state, Path(raw_name.to_string())).await;
    }

    state.audit.log(AuditEntry::new(
        "mount",
        "api",
        &format!("{}@{}", name, digest),
        "docker",
        "blob",
    ));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        format!("{}@{}", name, &digest[..19.min(digest.len())]),
        crate::registry_type::RegistryType::Docker,
        "LOCAL",
    ));
    state.repo_index.invalidate("docker");
    blob_created(&name, digest)
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

    // Single write lock: check limit + insert atomically (no TOCTOU). The guard's
    // scope must end before the reject path awaits, so the temp to reclaim is
    // handed back out of the block rather than removed inside it.
    let rejected_temp = {
        let mut sessions = state.upload_sessions.write();
        let max_sessions = max_upload_sessions();
        if sessions.len() >= max_sessions {
            tracing::warn!(
                max = max_sessions,
                current = sessions.len(),
                "Upload session limit reached — rejecting new upload"
            );
            Some(temp_path)
        } else {
            sessions.insert(
                uuid.clone(),
                UploadSession {
                    temp_path,
                    size: 0,
                    name: name.clone(),
                    created_at: std::time::Instant::now(),
                },
            );
            None
        }
    };
    if let Some(p) = rejected_temp {
        let _ = tokio::fs::remove_file(&p).await;
        return too_many_uploads();
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
    body: Body,
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

    // Bound concurrent streaming uploads (covers monolithic POSTs, which bypass
    // the session map) so streaming to disk cannot fan out unboundedly (#817).
    let _inflight = match InFlightGuard::try_acquire() {
        Some(g) => g,
        None => return too_many_uploads(),
    };

    // Phase 1: Validate session under lock, extract temp_path + current size (no I/O)
    let (temp_path, current_size) = {
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

        (session.temp_path.clone(), session.size)
    }; // lock released before file I/O

    // Remaining byte budget for this session. The body length is unknown until
    // streamed, so the cap is enforced incrementally inside the stream loop —
    // DefaultBodyLimit does NOT bound a streaming Body extractor (#817).
    //
    // ACCEPTED LIMITATION: the per-session cap is best-effort under CONCURRENT
    // PATCHes to the SAME upload uuid — each reads `session.size` before the
    // other's Phase-3 update, so a single temp can exceed one session cap. No new
    // exhaustion vector: total upload disk stays <= IN_FLIGHT_UPLOADS * cap
    // regardless, and blob integrity is still enforced by the finalize digest
    // check. OCI clients PATCH sequentially (await each 202 Range), so this only
    // bites a misbehaving client. Upgrade path: per-uuid serialization.
    let budget =
        effective_upload_cap(state.config.server.body_limit_mb).saturating_sub(current_size);

    // Phase 2: stream the chunk to the temp file outside the lock, bounded by
    // `budget`. No .create(true) — the temp file was created by start_upload; if
    // cleanup deleted it, open() returns NotFound and we 404 rather than
    // re-creating an orphan (#530).
    let mut file = match tokio::fs::OpenOptions::new()
        .append(true)
        .open(&temp_path)
        .await
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(uuid = %uuid, "Upload temp file deleted by cleanup during PATCH — session race");
            state.upload_sessions.write().remove(&uuid);
            return (StatusCode::NOT_FOUND, "Upload session expired").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to open upload temp file");
            state.upload_sessions.write().remove(&uuid);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    // CANCEL-SAFETY: if this future is dropped mid-stream, `guard` drops and
    // removes the partially appended temp; on success we disarm to keep it for
    // the next PATCH/PUT.
    let mut guard = TempFileGuard::new(temp_path.clone());
    let written = match stream_body_to_file(body, &mut file, budget).await {
        StreamOutcome::Ok(n) => {
            guard.disarm();
            n
        }
        StreamOutcome::TooLarge => {
            state.upload_sessions.write().remove(&uuid);
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload session exceeds size limit",
            )
                .into_response();
        }
        StreamOutcome::ClientGone => {
            state.upload_sessions.write().remove(&uuid);
            return StatusCode::BAD_REQUEST.into_response();
        }
        StreamOutcome::Io(e) => {
            tracing::error!(error = %e, "Failed to write to upload temp file");
            state.upload_sessions.write().remove(&uuid);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let new_size = current_size + written;

    // Phase 3: Update session size (brief lock, no I/O).
    // If session is gone (cleanup raced, or upload_blob consumed it), log and return 404.
    // Do NOT delete the temp file here — upload_blob may be using it (#530).
    {
        let mut sessions = state.upload_sessions.write();
        match sessions.get_mut(&uuid) {
            Some(session) => session.size = new_size,
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

/// DELETE handler: cancel an in-progress upload (OCI end-blob-upload cancel).
///
/// Without it the session is only reclaimed by `SESSION_TTL`, so a client that
/// correctly cancels still holds a `max_upload_sessions` slot for 30 minutes.
/// Concurrent CI pushes then saturate the ceiling and 429 each other while the
/// map is mostly dead entries.
async fn cancel_upload(
    State(state): State<AppState>,
    Path((name, uuid)): Path<(String, String)>,
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

    // `map` yields an owned bool so no borrow of `sessions` outlives the match.
    let temp_path = {
        let mut sessions = state.upload_sessions.write();
        match sessions.get(&uuid).map(|s| s.name == name) {
            None => None,
            Some(false) => {
                tracing::warn!(
                    request_name = %name,
                    uuid = %uuid,
                    "SECURITY: upload cancel name mismatch — possible session fixation"
                );
                return (
                    StatusCode::BAD_REQUEST,
                    "Session does not belong to this repository",
                )
                    .into_response();
            }
            Some(true) => sessions.remove(&uuid).map(|s| s.temp_path),
        }
    }; // lock released before file I/O

    match temp_path {
        Some(p) => {
            let _ = tokio::fs::remove_file(&p).await;
            StatusCode::NO_CONTENT.into_response()
        }
        None => (StatusCode::NOT_FOUND, "Upload session not found or expired").into_response(),
    }
}

/// PUT handler for completing blob uploads
/// Handles both monolithic uploads (body contains all data) and
/// chunked upload finalization (body may be empty, data in session)
async fn upload_blob(
    State(state): State<AppState>,
    Path((name, uuid)): Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    body: Body,
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

    // Bound concurrent streaming uploads. Monolithic POSTs bypass the session
    // map, so `max_upload_sessions` alone does not cap their concurrency (#817).
    let _inflight = match InFlightGuard::try_acquire() {
        Some(g) => g,
        None => return too_many_uploads(),
    };

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

    let cap = effective_upload_cap(state.config.server.body_limit_mb);

    // Resolve the temp file and stream the request body into it, bounded by the
    // per-request cap (DefaultBodyLimit does not bound a streaming Body — #817).
    // `guard` reclaims a partial temp on ANY early return below (cap exceeded,
    // client disconnect, digest mismatch, storage failure, cancellation) — #580.
    let (temp_path, mut guard) = if let Some(session) = session_opt {
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
        // create(true) covers the "no PATCH was sent, data all in the PUT body"
        // case; the session was already removed from the map, so we own this
        // temp exclusively.
        let mut file = match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&session.temp_path)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, "Failed to open temp file for PUT body");
                let _ = tokio::fs::remove_file(&session.temp_path).await;
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let guard = TempFileGuard::new(session.temp_path.clone());
        let budget = cap.saturating_sub(session.size);
        // CANCEL-SAFETY: partial temp reclaimed by `guard` if this future drops.
        match stream_body_to_file(body, &mut file, budget).await {
            StreamOutcome::Ok(_) => {}
            StreamOutcome::TooLarge => {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Upload session exceeds size limit",
                )
                    .into_response()
            }
            StreamOutcome::ClientGone => return StatusCode::BAD_REQUEST.into_response(),
            StreamOutcome::Io(e) => {
                tracing::error!(error = %e, "Failed to append PUT body to temp file");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        (session.temp_path, guard)
    } else {
        // Monolithic upload (no session): create a fresh temp and stream into it.
        let temp_dir = upload_temp_dir(&state.config.storage.path);
        let temp_path = temp_dir.join(format!("mono-{}", uuid));
        let mut file = match tokio::fs::File::create(&temp_path).await {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create monolithic upload temp file");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let guard = TempFileGuard::new(temp_path.clone());
        // CANCEL-SAFETY: partial temp reclaimed by `guard` if this future drops.
        match stream_body_to_file(body, &mut file, cap).await {
            StreamOutcome::Ok(_) => {}
            StreamOutcome::TooLarge => {
                return (StatusCode::PAYLOAD_TOO_LARGE, "Upload exceeds size limit").into_response()
            }
            StreamOutcome::ClientGone => return StatusCode::BAD_REQUEST.into_response(),
            StreamOutcome::Io(e) => {
                tracing::error!(error = %e, "Failed to write monolithic upload temp file");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        (temp_path, guard)
    };

    // Verify digest by streaming SHA-256 — O(chunk_size) memory, not O(blob_size)
    {
        let computed = match sha256_of_file(&temp_path).await {
            Ok(h) => format!("sha256:{h}"),
            Err(e) => {
                tracing::error!(error = %e, "Failed to hash temp file for digest verification");
                let _ = tokio::fs::remove_file(&temp_path).await;
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
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

    // Move temp file into storage — no RAM copy of the blob. The digest was just checked
    // against the bytes (`sha256:` and their hex), so it pins them (#1154).
    let key = format!("docker/{}/blobs/{}", name, digest);
    match state
        .storage
        .put_from_path(
            &key,
            &temp_path,
            digest.strip_prefix("sha256:"),
            &Annotations::default(),
        )
        .await
    {
        Ok(()) => {
            guard.disarm(); // temp moved into storage — nothing left to clean up
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
                crate::registry_type::RegistryType::Docker,
                "LOCAL",
            ));
            state.repo_index.invalidate("docker");
            blob_created(&name, digest)
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
    misses: &mut [UpstreamMiss],
    upstream_name: &str,
    name: &str,
    reference: &str,
    cache_key: &str,
) -> Option<Response> {
    for (upstream, miss) in upstreams.iter().zip(misses.iter_mut()) {
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
                // A digest reference is content-addressed: an answer that hashes to another digest
                // is not this manifest. It counts as a failed upstream, and is neither served nor
                // cached under the requested digest.
                if !content_has_digest(reference, &data) {
                    tracing::warn!(upstream = %upstream.url, name = %upstream_name, reference = %reference, "Docker manifest from the upstream does not have the requested digest; trying next");
                    miss.record(&ProxyError::Upstream(502));
                    continue;
                }
                // The allowlist's pinned integrity holds on the first download too, before anything
                // is cached: serve_cached_manifest checks the same rule.
                if let Some(response) = crate::curation::verify_integrity(
                    &state.curation().curation_engine,
                    crate::curation::RegistryType::Docker,
                    name,
                    Some(reference),
                    &data,
                ) {
                    return Some(response);
                }
                state.metrics.record_download("docker");
                state.metrics.record_cache_miss("docker");
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{}:{}", name, reference),
                    crate::registry_type::RegistryType::Docker,
                    "PROXY",
                ));

                // Calculate digest for Docker-Content-Digest header
                use sha2::Digest;
                let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));

                // Quarantine: record digest, check status
                let (q_mode, q_secs) = resolve_quarantine(state);
                if !matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
                    state
                        .digest_store
                        .record("docker", &digest, &upstream.url, None);
                    let q_status = state.digest_store.check("docker", &digest, q_secs);
                    match &q_status {
                        crate::digest_quarantine::QuarantineStatus::Mature => {}
                        _ => {
                            let outcome = if matches!(
                                q_mode,
                                crate::digest_quarantine::QuarantineMode::Enforce
                            ) {
                                "blocked"
                            } else {
                                "observed"
                            };
                            crate::metrics::QUARANTINE_HOLDS_TOTAL
                                .with_label_values(&["docker", outcome])
                                .inc();
                            tracing::warn!(
                                digest = %digest,
                                upstream = %upstream.url,
                                status = %q_status.header_value(),
                                mode = ?q_mode,
                                quarantine_ttl_secs = q_secs,
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
                let state_clone = state.clone();
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
                    // The manifest is stored first; its metadata goes under the metadata lock, so
                    // a pull's statistics on this copy cannot write over it.
                    if let Ok(meta_json) = serde_json::to_vec(&metadata) {
                        if let Err(e) = write_manifest_meta(
                            &state_clone,
                            upstream_ns.as_deref(),
                            &name_clone,
                            &reference_clone,
                            &meta_json,
                        )
                        .await
                        {
                            tracing::warn!(name = %name_clone, reference = %reference_clone, error = %e, "cache write failed (metadata by tag)");
                            crate::metrics::CACHE_WRITE_ERRORS
                                .with_label_values(&["docker", "metadata"])
                                .inc();
                        }

                        if let Err(e) = write_manifest_meta(
                            &state_clone,
                            upstream_ns.as_deref(),
                            &name_clone,
                            &digest_clone,
                            &meta_json,
                        )
                        .await
                        {
                            tracing::warn!(name = %name_clone, digest = %digest_clone, error = %e, "cache write failed (metadata by digest)");
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
                miss.record(&e);
            }
        }
    }
    None
}

/// Whether `data` is the content a digest reference names (`sha256:` or `sha512:`, lowercase
/// hex as the OCI spec writes it). A tag names no content, so any bytes may answer it.
fn content_has_digest(reference: &str, data: &[u8]) -> bool {
    use sha2::Digest;
    if let Some(hex) = reference.strip_prefix("sha256:") {
        return hex::encode(sha2::Sha256::digest(data)) == hex;
    }
    if let Some(hex) = reference.strip_prefix("sha512:") {
        return hex::encode(sha2::Sha512::digest(data)) == hex;
    }
    true
}

/// Whether a reference is a digest (content-addressed) rather than a tag.
fn is_digest_reference(reference: &str) -> bool {
    reference.starts_with("sha256:") || reference.starts_with("sha512:")
}

/// Whether resolving a reference consults its push record: a tag whose namespaced (proxied) key
/// is not its bare (pushed) one. Only then is the tag's bare metadata needed to answer it.
fn consults_push_record(ns: Option<&str>, name: &str, reference: &str) -> bool {
    !is_digest_reference(reference)
        && manifest_key(ns, name, reference) != manifest_key(None, name, reference)
}

/// The stored copy that answers a manifest reference, and whether it is hosted (pushed or bare)
/// rather than proxied — one resolution for every reader: GET and HEAD, and the deletes that
/// follow a tag. A tag whose push record names the digest of the bare manifest answers with it
/// (a push answers its tag); otherwise the namespaced (proxied) copy, then the bare one.
/// Digest references are content-addressed and skip the record. A storage error other than
/// NotFound is the answer: a failed read never hands the reference to another copy.
async fn resolve_manifest(
    state: &AppState,
    ns: Option<&str>,
    name: &str,
    reference: &str,
    pushed: Option<crate::storage::Result<PushedTag>>,
) -> crate::storage::Result<Option<(Bytes, bool)>> {
    use crate::storage::StorageError;
    let key = manifest_key(ns, name, reference);
    let legacy_key = manifest_key(None, name, reference);
    if consults_push_record(ns, name, reference) {
        let pushed = match pushed {
            Some(pushed) => pushed,
            None => pushed_tag(&state.storage, name, reference).await,
        };
        if let PushedTag::Push { manifest, .. } = pushed? {
            return Ok(Some((manifest, true)));
        }
    }
    match state.storage.get(&key).await {
        Ok(data) => Ok(Some((data, key == legacy_key))),
        Err(StorageError::NotFound) if key != legacy_key => {
            match state.storage.get(&legacy_key).await {
                Ok(data) => Ok(Some((data, true))),
                Err(StorageError::NotFound) => Ok(None),
                Err(e) => Err(e),
            }
        }
        Err(StorageError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// What a pull reads of a tag a push may answer: the one decision that the tag is the push's.
enum PushedTag {
    /// The bare metadata holds a push record and the bare manifest is stored: the tag is the push's.
    /// Its manifest answers it — whatever bytes it holds, since the bare key is written only by a
    /// push, so other bytes are a re-push in progress — and curation dates it by the record.
    Push {
        manifest: Bytes,
        record: ImageMetadata,
    },
    /// No push answers the tag: no record, or a record without its manifest (an interrupted
    /// delete left it). The bare metadata as read, for the publish date.
    NotPushed { bare_meta: Option<Bytes> },
}

/// Reads whether a push answers a tag: its bare metadata and, with a push record
/// ([`push_record`]) there, its bare manifest. Err on a storage error other than NotFound, so that a
/// failed read never hands the tag to another copy.
async fn pushed_tag(
    storage: &Storage,
    name: &str,
    reference: &str,
) -> crate::storage::Result<PushedTag> {
    use crate::storage::StorageError;
    let bare_meta = read_bare_meta(storage, name, reference).await?;
    let Some(record) = bare_meta.as_deref().and_then(push_record) else {
        return Ok(PushedTag::NotPushed { bare_meta });
    };
    match storage.get(&manifest_key(None, name, reference)).await {
        Ok(manifest) => Ok(PushedTag::Push { manifest, record }),
        Err(StorageError::NotFound) => Ok(PushedTag::NotPushed { bare_meta }),
        Err(e) => Err(e),
    }
}

/// The push record in a tag's bare metadata: the metadata, when it names a pushed digest
/// (`sha256:` or `sha512:`). A tag with one is the push's: the bare
/// manifest answers it and curation dates it by the push. Pure: the whole test is this function.
pub(crate) fn push_record(meta: &[u8]) -> Option<ImageMetadata> {
    serde_json::from_slice::<ImageMetadata>(meta)
        .ok()
        .filter(|m| {
            m.pushed_digest
                .as_deref()
                .is_some_and(|d| d.starts_with("sha256:") || d.starts_with("sha512:"))
        })
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

    // Whether a push answers the tag, read once: a tag that is the push's is dated by its record and
    // answered by its manifest; otherwise the date comes from the .meta.json sidecars (namespaced,
    // then the bare one already read) and the resolver goes on to the other copies.
    let pushed = if consults_push_record(ns.as_deref(), &name, &reference) {
        Some(pushed_tag(&state.storage, &name, &reference).await)
    } else {
        None
    };
    let publish_date = match &pushed {
        Some(Ok(PushedTag::Push { record, .. })) => {
            (record.push_timestamp > 0).then_some(record.push_timestamp as i64)
        }
        Some(Ok(PushedTag::NotPushed { bare_meta })) => {
            extract_docker_publish_date(
                &state.storage,
                &name,
                &reference,
                state.config.docker.upstreams.is_empty(),
                ns.as_deref(),
                &mut BareMeta::Read(Ok(bare_meta.clone())),
            )
            .await
        }
        _ => {
            extract_docker_publish_date(
                &state.storage,
                &name,
                &reference,
                state.config.docker.upstreams.is_empty(),
                ns.as_deref(),
                &mut BareMeta::Unread,
            )
            .await
        }
    };

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
            crate::curation::RequestVersion::Known(reference.to_string()),
            publish_date,
        ) {
            return response;
        }
    }

    let key = manifest_key(ns.as_deref(), &name, &reference);
    let legacy_key = manifest_key(None, &name, &reference);

    // Try local storage first (namespaced key, then bare-key fallback). Provenance lives in
    // the key layout: the namespaced key only ever holds an upstream-proxied copy, while the
    // bare key is what `put_manifest` writes — a bare-key hit is a locally pushed (hosted)
    // manifest. (Pre-#349 flat-keyed proxy caches are consequently read as hosted; the cost
    // is skipped tag revalidation on those legacy entries.)
    // Provenance decides freshness below, so a transient storage error must fail closed
    // (500) rather than fall through to the legacy key or the proxy: an error-driven
    // fallback silently flips WHICH copy answers (proxied-current vs legacy/hosted), and
    // an error-driven proxy would resolve a hosted name against an upstream that may be
    // squatted. Only `NotFound` may advance to the next source.
    let (cached, hosted) = match resolve_manifest(&state, ns.as_deref(), &name, &reference, pushed)
        .await
    {
        Ok(Some((data, hosted))) => (Some(data), hosted),
        Ok(None) => (None, true),
        Err(e) => {
            tracing::error!(error = %e, name = %name, reference = %reference, "manifest read failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    // A copy under a digest reference that hashes to another digest (cached before fetches were
    // checked) is not that manifest: it is neither served nor treated as cached.
    let cached = cached.filter(|data| content_has_digest(&reference, data));
    // A served copy's pull statistics live beside it: a bare-key (hosted) hit counts against
    // the pushed image's own metadata, a namespaced hit against the proxied copy's.
    let served_ns = if hosted { None } else { ns.as_deref() };
    // Digest references are immutable (content-addressed) → the cache is authoritative forever.
    // Tag references on PROXIED copies are MUTABLE: a tag can be re-pushed to point at a
    // different manifest, so a proxied tag must be revalidated against upstream before it is
    // served — otherwise a re-pushed upstream tag is never reflected (#638). `metadata_ttl` is
    // an optional staleness window for tags: only a POSITIVE value serves a tag from cache
    // without revalidating (within the window); otherwise the latest is fetched. A HOSTED
    // manifest (bare-key hit, or no upstreams configured) is authoritative and served without
    // any upstream round trip — before this distinction a hosted tag was revalidated against
    // an upstream that never had it, 404ing local images when upstream was down and
    // serve_stale off, and stale-marking every pull otherwise.
    let is_digest = reference.starts_with("sha256:");
    let revalidate = !hosted && !upstreams_to_try.is_empty();
    let cache_fresh = if cached.is_some() {
        let modified = if revalidate && !is_digest {
            storage_stat_with_fallback(&state.storage, &key, &legacy_key)
                .await
                .map(|m| m.modified)
        } else {
            None
        };
        manifest_cache_fresh(
            is_digest,
            revalidate,
            state.config.docker.metadata_ttl,
            modified,
        )
    } else {
        false
    };

    // Serve fresh cache immediately
    if let Some(ref data) = cached {
        if cache_fresh {
            return serve_cached_manifest(&state, data, &name, &reference, served_ns);
        }
    }

    // #733/#821: an internal-namespace image's manifest — serve any (stale) local copy, else
    // return a genuine not-found; never proxy upstream (the fresh path already returned above,
    // and this branch precedes the proxy loop — dependency-confusion defense intact). A hosted
    // image's absent tag is 404 MANIFEST_UNKNOWN, NOT 403: Docker/BuildKit treats 403 on a
    // manifest HEAD/GET as fatal, breaking push HEAD-probes and OCI referrers (sha256-<digest>)
    // lookups on locally-hosted images.
    if internal {
        if let Some(ref data) = cached {
            return serve_cached_manifest(&state, data, &name, &reference, served_ns);
        }
        crate::metrics::record_namespace_isolation_refused("docker");
        return manifest_unknown_response(&name, &reference);
    }

    // Try upstream proxies (always if no cache, or if cache is stale)
    tracing::debug!(
        upstreams_count = upstreams_to_try.len(),
        "Trying upstream proxies"
    );
    // One record per upstream, across both names it may be asked under (library/ below).
    let mut misses: Vec<UpstreamMiss> = upstreams_to_try
        .iter()
        .map(|_| UpstreamMiss::default())
        .collect();
    if let Some(response) = try_fetch_and_cache(
        &state,
        &upstreams_to_try,
        &mut misses,
        &name,
        &name,
        &reference,
        &key,
    )
    .await
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
            &mut misses,
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
            let mut response = serve_cached_manifest(&state, data, &name, &reference, served_ns);
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

    let mut miss = UpstreamMiss::default();
    for asked in &misses {
        miss.record_upstream(asked);
    }
    miss.response("docker", &format!("{name}:{reference}"))
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
        crate::registry_type::RegistryType::Docker,
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

    // Count the pull OFF the request path (#1114): bump the in-memory
    // accumulator instead of rewriting `.meta.json`. A background task flushes
    // it to a `.stats.json` sidecar. No spawn, no publish lock, no storage write
    // here — so the request-path publish-date read never races a pull.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    state
        .pull_stats
        .record(&manifest_meta_key(ns, name, reference), now);

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
    // A manifest pushed by digest is that digest's content (OCI DIGEST_INVALID otherwise).
    if !content_has_digest(&reference, &body) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errors": [{
                    "code": "DIGEST_INVALID",
                    "message": "provided digest did not match uploaded content",
                    "detail": { "digest": reference }
                }]
            })),
        )
            .into_response();
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

    // Extract and save metadata, with the record that this tag was pushed here.
    let mut metadata = extract_metadata(&body, &state.storage, &name).await;
    metadata.pushed_digest = Some(digest.clone());
    if let Ok(meta_json) = serde_json::to_vec(&metadata) {
        if let Err(e) = write_manifest_meta(&state, None, &name, &reference, &meta_json).await {
            tracing::warn!(name = %name, reference = %reference, error = %e, "cache write failed (push metadata by tag)");
            crate::metrics::CACHE_WRITE_ERRORS
                .with_label_values(&["docker", "metadata"])
                .inc();
        }

        // Also save metadata by digest
        if let Err(e) = write_manifest_meta(&state, None, &name, &digest, &meta_json).await {
            tracing::warn!(name = %name, digest = %digest, error = %e, "cache write failed (push metadata by digest)");
            crate::metrics::CACHE_WRITE_ERRORS
                .with_label_values(&["docker", "metadata"])
                .inc();
        }
    }

    // A push takes its tag back from the upstream: the proxied copy of this tag goes, with its
    // metadata (this handler holds the manifest lock; the metadata lock is taken after it).
    if let Some(ns) = ns.as_deref() {
        if manifest_key(Some(ns), &name, &reference) != key {
            delete_proxied_tag(&state, ns, &name, &reference).await;
        }
    }

    state.metrics.record_upload("docker");
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        format!("{}:{}", name, reference),
        crate::registry_type::RegistryType::Docker,
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
                .and_then(tag_from_manifest_file)
                .map(String::from)
        })
        .collect();
    (StatusCode::OK, Json(json!({"name": name, "tags": tags}))).into_response()
}

// ============================================================================
// Delete handlers (Docker Registry V2 spec)
// ============================================================================

// ── Manifest metadata (`*.meta.json`) ──────────────────────────────────────────────
//
// Only the functions in this section build a metadata key — `manifest_meta_key`'s callers are
// `write_manifest_meta`, `delete_manifest_and_meta`, `delete_proxied_tag`, `update_metadata_on_pull`
// and the readers `extract_docker_publish_date` and `read_bare_meta` (checked by
// `only_the_metadata_section_builds_metadata_keys`).
// They keep one order:
// - a manifest is written and deleted under its own lock (push, delete); its metadata under the
//   metadata lock, taken after the manifest's and never the other way round;
// - a manifest is deleted before its metadata, and its metadata only once it is gone;
// - a pull's statistics take only the metadata lock and write only while the manifest is stored.

/// Write a manifest's metadata (push, proxy fill) under the metadata lock: a pull's statistics
/// that read the file before this write cannot write the old contents back over it. A push
/// calls it while holding the manifest's lock.
async fn write_manifest_meta(
    state: &AppState,
    ns: Option<&str>,
    name: &str,
    reference: &str,
    json: &[u8],
) -> crate::storage::Result<()> {
    let key = manifest_meta_key(ns, name, reference);
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;
    state.storage.put(&key, json).await
}

/// Delete a manifest — the namespaced copy and the bare one (`both`), or the namespaced copy
/// and, when it is missing, the bare one — and then, once the manifest is gone, its metadata
/// (namespaced and bare), each under the metadata lock. The caller holds the manifest's lock.
/// Returns the manifest delete's result.
async fn delete_manifest_and_meta(
    state: &AppState,
    ns: Option<&str>,
    name: &str,
    reference: &str,
) -> crate::storage::Result<()> {
    let key = manifest_key(ns, name, reference);
    let legacy_key = manifest_key(None, name, reference);
    // Every copy goes, the namespaced one and a pre-migration bare one: a read falls back to the
    // bare copy, so a delete that stopped at the first copy left the manifest served. A failure
    // other than "not there" is the answer, so the client retries instead of believing it gone.
    use crate::storage::StorageError;
    let mut results = vec![state.storage.delete(&key).await];
    if legacy_key != key {
        results.push(state.storage.delete(&legacy_key).await);
    }
    let (mut failure, mut deleted) = (None, false);
    for r in results {
        match r {
            Ok(()) => deleted = true,
            Err(StorageError::NotFound) => {}
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
    }
    let result = match (failure, deleted) {
        (Some(e), _) => Err(e),
        (None, true) => Ok(()),
        (None, false) => Err(StorageError::NotFound),
    };
    // Metadata goes only once the manifest is gone (deleted now, or not there at all).
    if matches!(result, Ok(()) | Err(crate::storage::StorageError::NotFound)) {
        let mut meta_keys = vec![manifest_meta_key(ns, name, reference)];
        if ns.is_some() {
            meta_keys.push(manifest_meta_key(None, name, reference));
        }
        for meta_key in meta_keys {
            let lock = state.publish_lock(&meta_key);
            let _guard = lock.lock().await;
            let _ = state.storage.delete(&meta_key).await;
            // #1114: drop the pull-stats sidecar under the same lock, so a
            // concurrent flush cannot leave a stale .stats.json for a gone manifest.
            let _ = state.storage.delete(&manifest_stats_key(&meta_key)).await;
        }
    }
    result
}

/// A tag's bare metadata as one request reads it. A push records itself there: a tag with a push
/// record is answered by the bare manifest and dated by the push, and a tag without one takes its
/// publish date from it when no proxied metadata exists. `get_manifest` lets the publish date read
/// it and hands what was read to the resolver; the deletes, which need only the push record, leave
/// it unread.
enum BareMeta {
    /// Not read: the reader that needs it reads it.
    Unread,
    /// Read once: Ok(None) when the tag has none; Err on a storage error other than NotFound.
    Read(crate::storage::Result<Option<Bytes>>),
}

/// A tag's bare metadata (see [`BareMeta`]). Err on a storage error other than NotFound.
async fn read_bare_meta(
    storage: &Storage,
    name: &str,
    reference: &str,
) -> crate::storage::Result<Option<Bytes>> {
    match storage.get(&manifest_meta_key(None, name, reference)).await {
        Ok(meta) => Ok(Some(meta)),
        Err(crate::storage::StorageError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Remove the proxied copy of a tag that has just been pushed, then its metadata under the
/// metadata lock. The caller holds the manifest's lock; the bare (pushed) copy is untouched.
async fn delete_proxied_tag(state: &AppState, ns: &str, name: &str, reference: &str) {
    let proxied = manifest_key(Some(ns), name, reference);
    if let Err(e) = state.storage.delete(&proxied).await {
        if !matches!(e, crate::storage::StorageError::NotFound) {
            tracing::warn!(key = %proxied, error = %e, "push: proxied copy of the tag not removed");
            return;
        }
    }
    let meta_key = manifest_meta_key(Some(ns), name, reference);
    let lock = state.publish_lock(&meta_key);
    let _guard = lock.lock().await;
    let _ = state.storage.delete(&meta_key).await;
}

/// Delete every tag manifest that resolves to `digest` (#658).
///
/// NORA stores a tag and its digest as independent files, so deleting a manifest
/// by digest would otherwise leave the tag still serving it. Every tag is resolved
/// first, deleting nothing: a listing or a tag that cannot be read is the answer (Err),
/// so a delete never leaves a tag serving a manifest it removed. Each candidate tag
/// is then locked and re-read under the lock, and only deleted if it *still* hashes
/// to `digest`, so a concurrent re-tag is never clobbered.
async fn delete_tags_for_digest(
    state: &AppState,
    ns: Option<&str>,
    name: &str,
    digest: &str,
) -> crate::storage::Result<()> {
    use sha2::Digest as _;

    let prefix = manifest_prefix(ns, name);
    let legacy_prefix = manifest_prefix(None, name);
    let mut keys = state.storage.list(&prefix).await?;
    if prefix != legacy_prefix {
        keys.extend(state.storage.list(&legacy_prefix).await?);
    }
    // Distinct tag references only — skip digest files and sidecars.
    let mut tags: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            k.strip_prefix(&prefix)
                .or_else(|| k.strip_prefix(&legacy_prefix))
                .and_then(tag_from_manifest_file)
                .map(String::from)
        })
        .collect();
    tags.sort();
    tags.dedup();

    let resolves_to_digest =
        |data: &Bytes| format!("sha256:{}", hex::encode(sha2::Sha256::digest(data))) == digest;
    // Every tag resolved before anything is deleted: an unreadable one stops the delete here.
    let mut candidates = Vec::new();
    for tag in tags {
        if let Some((data, _)) = resolve_manifest(state, ns, name, &tag, None).await? {
            if resolves_to_digest(&data) {
                candidates.push(tag);
            }
        }
    }
    for tag in candidates {
        let key = manifest_key(ns, name, &tag);
        // Serialize with put_manifest on this tag.
        let lock = state.publish_lock(&key);
        let _guard = lock.lock().await;
        // Re-read under the lock, as a read resolves the tag (a recorded push first); only delete if
        // it STILL resolves to `digest`.
        match resolve_manifest(state, ns, name, &tag, None).await? {
            Some((data, _)) if resolves_to_digest(&data) => {}
            _ => continue,
        }
        let _ = delete_manifest_and_meta(state, ns, name, &tag).await;
        tracing::info!(
            name = %name, tag = %tag, digest = %digest,
            "Docker tag removed because its manifest was deleted by digest (#658)"
        );
    }
    Ok(())
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

    // Serialize tag delete with put_manifest via publish_lock to prevent
    // concurrent put from updating the tag between our read and delete
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;

    // If reference is a tag, also delete digest-keyed copy
    let is_tag = !reference.starts_with("sha256:");
    if is_tag {
        // The manifest the tag answers with, as a read resolves it (a recorded push first). A read
        // that fails is the answer: a delete that cannot tell what the tag answers with removes
        // nothing, as a pull of the tag answers 500 — never the tag without its manifest.
        match resolve_manifest(&state, ns.as_deref(), &name, &reference, None).await {
            Ok(Some((data, _))) => {
                use sha2::Digest;
                let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));
                // Delete from both namespaced and legacy locations, then the metadata.
                let _ = delete_manifest_and_meta(&state, ns.as_deref(), &name, &digest).await;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, name = %name, reference = %reference, "delete: reading what the tag answers with failed; nothing deleted");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        // #658: deleting by digest must also drop the tags that resolve to it,
        // so the registry stops serving a tag whose manifest is now gone. A tag
        // that cannot be read stops the delete before anything is removed.
        if let Err(e) = delete_tags_for_digest(&state, ns.as_deref(), &name, &reference).await {
            tracing::error!(error = %e, name = %name, reference = %reference, "delete by digest: reading the tags failed; nothing deleted");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // Delete manifest — try namespaced key first, then legacy fallback — then its metadata.
    match delete_manifest_and_meta(&state, ns.as_deref(), &name, &reference).await {
        Ok(()) => {
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
        Err(crate::storage::StorageError::NotFound) => manifest_unknown_response(&name, &reference),
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
        Err(crate::storage::StorageError::NotFound) => blob_unknown_response(&digest),
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
    #[allow(dead_code)]
    pub content_length: Option<u64>,
    /// RAII guard — deletes temp file on drop unless disarmed.
    pub _guard: TempFileGuard,
}

/// An upstream blob whose response headers have arrived but whose body has not been
/// read: the point at which `download_blob` can answer the client, before the bytes
/// are on disk.
pub struct UpstreamBlob {
    response: reqwest::Response,
    /// Content-Length from upstream, None for a chunked response.
    pub content_length: Option<u64>,
    /// Where to ask for the rest if the body breaks off.
    source: BlobSource,
    cb_key: String,
    probe: ProbeToken,
    _download_gauge_guard: ProxyDownloadGuard,
}

/// Progress of an in-flight spool, published to the response followers reading it.
#[derive(Clone, Debug, Default)]
pub(crate) struct SpoolStatus {
    /// Bytes flushed to the spool file so far.
    pub written: u64,
    /// `Some` once the spool has finished: the upstream body is complete and verified
    /// (`Ok`) or the fetch failed and the file is being discarded (`Err`).
    pub done: Option<Result<(), String>>,
}

/// Temp file a spool writes into. Created by the caller so a follower can open its own
/// handle before the first byte lands and keep reading it after storage moves or the
/// guard deletes the path.
pub(crate) struct SpoolFile {
    path: std::path::PathBuf,
    file: tokio::fs::File,
    guard: TempFileGuard,
}

impl SpoolFile {
    pub(crate) async fn create(temp_dir: &std::path::Path) -> Result<Self, ProxyError> {
        let path = temp_dir.join(format!("proxy-{}", uuid::Uuid::new_v4()));
        let guard = TempFileGuard::new(path.clone());
        let file = tokio::fs::File::create(&path)
            .await
            .map_err(|e| ProxyError::Network(format!("temp file create: {}", e)))?;
        Ok(Self { path, file, guard })
    }

    /// A second, read-only handle on the spool file for a response to follow.
    pub(crate) async fn follower(&self) -> std::io::Result<tokio::fs::File> {
        tokio::fs::File::open(&self.path).await
    }
}

/// Read a spool file as it is being written, ending when the spool reports completion.
///
/// Bytes are released only up to what the spool has flushed, less a one-byte holdback
/// until it reports `done`: with a `Content-Length` body hyper stops reading once the
/// declared bytes are out, so the digest verdict has to gate the final byte, not EOF. A
/// failed spool surfaces as a read error, so the response aborts short instead of ending
/// cleanly. Progress is re-read after every short read, so bytes flushed between a read
/// and the next status check are never waited on.
///
/// `file` is positioned at byte `start` of the blob: a ranged response follows the
/// spool from there. A spool that reports nothing for `stall` fails the read.
fn spool_follower(
    file: tokio::fs::File,
    status: tokio::sync::watch::Receiver<SpoolStatus>,
    start: u64,
    stall: Duration,
) -> impl futures::Stream<Item = std::io::Result<Bytes>> + Send {
    const READ_BUF: usize = 256 * 1024;
    const HOLDBACK_BYTES: u64 = 1;
    // Flushed bytes are visible to a second handle at once; a run of empty reads below
    // the published count means the file is gone or truncated, not still in flight.
    const MAX_EMPTY_READS: u32 = 1_000;
    futures::stream::unfold(
        (file, status, start, 0u32),
        move |(mut file, mut status, mut offset, mut empty_reads)| async move {
            use tokio::io::AsyncReadExt;
            loop {
                let current = status.borrow_and_update().clone();
                let released = match &current.done {
                    Some(Ok(())) => current.written,
                    Some(Err(reason)) => {
                        let err =
                            std::io::Error::other(format!("upstream blob fetch failed: {reason}"));
                        return Some((Err(err), (file, status, offset, empty_reads)));
                    }
                    None => current.written.saturating_sub(HOLDBACK_BYTES),
                };
                if offset < released {
                    let want = usize::try_from(released - offset)
                        .unwrap_or(READ_BUF)
                        .min(READ_BUF);
                    let mut buf = vec![0u8; want];
                    match file.read(&mut buf).await {
                        Ok(0) => {
                            empty_reads += 1;
                            if empty_reads > MAX_EMPTY_READS {
                                let err = std::io::Error::other(format!(
                                    "spool published {} bytes but only {} were readable",
                                    current.written, offset
                                ));
                                return Some((Err(err), (file, status, offset, empty_reads)));
                            }
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        Ok(n) => {
                            empty_reads = 0;
                            offset += n as u64;
                            buf.truncate(n);
                            return Some((
                                Ok(Bytes::from(buf)),
                                (file, status, offset, empty_reads),
                            ));
                        }
                        Err(e) => return Some((Err(e), (file, status, offset, empty_reads))),
                    }
                    continue;
                }
                if current.done.is_some() {
                    return None;
                }
                // CANCEL-SAFETY: `changed()` only borrows the receiver; a timeout drops the
                // wait and the stream ends with an error, the file handle goes with it.
                match tokio::time::timeout(stall, status.changed()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        let err = std::io::Error::other("upstream blob fetch abandoned");
                        return Some((Err(err), (file, status, offset, empty_reads)));
                    }
                    Err(_) => {
                        let err = std::io::Error::other(format!(
                            "upstream blob fill reported nothing for {stall:?}"
                        ));
                        return Some((Err(err), (file, status, offset, empty_reads)));
                    }
                }
            }
        },
    )
}

/// Answer a blob cache miss from the spool as it fills.
///
/// The last byte is withheld until the spool has verified the digest, so a poisoned
/// upstream can never complete a `Content-Length` body. A `Range` against a blob whose
/// length upstream declared is served 206 from that offset, or 416 past the end, the
/// way the cache-hit path does: a client resuming a broken pull (containerd sends
/// `bytes=N-`) gets the tail, not the blob again from byte zero, which it would have to
/// read and discard up to N. A ranged body is partial, so it has no whole-blob digest to
/// verify (as on the cache-hit path). Without a declared length, or for a range that
/// does not parse, the whole blob goes out as 200.
async fn spool_response(
    mut follower: tokio::fs::File,
    status: tokio::sync::watch::Receiver<SpoolStatus>,
    content_length: Option<u64>,
    digest: &str,
    headers: &axum::http::HeaderMap,
    stall: Duration,
) -> Response {
    use crate::registry::range::{parse_byte_range, ParsedRange};
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    // A declared zero length would let hyper complete the response from the headers
    // alone, before the digest verdict; an empty body goes chunked.
    let len = content_length.filter(|&len| len > 0);
    let range = match (
        len,
        headers.get(header::RANGE).and_then(|v| v.to_str().ok()),
    ) {
        (Some(len), Some(value)) => parse_byte_range(value, len),
        _ => ParsedRange::None,
    };
    let builder = Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header("docker-content-digest", digest);
    let response = match (range, len) {
        (ParsedRange::Unsatisfiable, Some(len)) => builder
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_RANGE, format!("bytes */{len}"))
            .body(Body::empty()),
        (ParsedRange::Satisfiable(start, end), Some(len)) => {
            debug_assert!(
                start <= end && end < len,
                "parse_byte_range clamps to the blob"
            );
            if let Err(e) = follower.seek(std::io::SeekFrom::Start(start)).await {
                tracing::error!(error = %e, "Failed to position proxy spool follower");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            let wanted = end - start + 1;
            let reader = tokio_util::io::StreamReader::new(Box::pin(spool_follower(
                follower, status, start, stall,
            )))
            .take(wanted);
            builder
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"))
                .header(header::CONTENT_LENGTH, wanted)
                .body(nora_registry::verified::open_world_stream_body(
                    tokio_util::io::ReaderStream::new(reader),
                ))
        }
        _ => {
            let reader = tokio_util::io::StreamReader::new(Box::pin(spool_follower(
                follower, status, 0, stall,
            )));
            let stream = VerifyingReader::new(reader, digest);
            let mut builder = builder.status(StatusCode::OK);
            if let Some(len) = len {
                builder = builder
                    .header(header::CONTENT_LENGTH, len)
                    .header(header::ACCEPT_RANGES, "bytes");
            }
            builder.body(nora_registry::verified::reader_stream_body(stream))
        }
    };
    response.unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// What a request joining a running blob fill needs — the value a fill's leader publishes
/// through `blob_flights` (#1003): the spool file to open its own read handle on, the fill's
/// progress, and upstream's declared length for `Range`.
#[derive(Clone)]
pub(crate) struct SpoolShare {
    path: std::path::PathBuf,
    status: tokio::sync::watch::Receiver<SpoolStatus>,
    content_length: Option<u64>,
}

/// The leader's own part of a fill, never shared: what the spool task consumes and the
/// read handle the leader's response follows.
struct LeaderFill {
    blob: UpstreamBlob,
    spool: SpoolFile,
    follower: tokio::fs::File,
    progress: tokio::sync::watch::Sender<SpoolStatus>,
}

/// Why [`start_fill`] could not open a fill.
enum FillStartError {
    /// The local spool file could not be created or reopened.
    Spool,
    /// Upstream refused or failed before answering headers.
    Upstream(ProxyError),
}

/// Open a fill: the spool file and its first read handle, then the upstream request. The
/// spool exists before upstream answers, so once a circuit-breaker probe is taken the
/// only exits left are the ones the spool task records.
async fn start_fill(
    state: &AppState,
    upstream_url: &str,
    upstream_auth: Option<&str>,
    name: &str,
    digest: &str,
    temp_dir: &std::path::Path,
    failure: &mut Option<FillStartError>,
) -> Option<(SpoolShare, LeaderFill)> {
    let spool = match SpoolFile::create(temp_dir).await {
        Ok(spool) => spool,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to create proxy spool file");
            *failure = Some(FillStartError::Spool);
            return None;
        }
    };
    let follower = match spool.follower().await {
        Ok(follower) => follower,
        Err(e) => {
            tracing::error!(error = %e, "Failed to open proxy spool file for streaming");
            *failure = Some(FillStartError::Spool);
            return None;
        }
    };
    match open_blob_from_upstream(
        &state.http_client,
        upstream_url,
        name,
        digest,
        &state.docker_auth,
        state.config.docker.proxy_timeout,
        upstream_auth,
        &state.circuit_breaker,
    )
    .await
    {
        Ok(blob) => {
            let (progress, status) = tokio::sync::watch::channel(SpoolStatus::default());
            let share = SpoolShare {
                path: spool.path.clone(),
                status,
                content_length: blob.content_length,
            };
            Some((
                share,
                LeaderFill {
                    blob,
                    spool,
                    follower,
                    progress,
                },
            ))
        }
        Err(e) => {
            *failure = Some(FillStartError::Upstream(e));
            None
        }
    }
}

/// Run a fill this request leads: start the detached spool task (it holds `lease`, so
/// requests arriving until the blob is stored join this fill) and answer from the spool.
async fn lead_fill(
    state: &AppState,
    share: SpoolShare,
    own: LeaderFill,
    lease: Option<crate::proxy_coalesce::Lease<SpoolShare>>,
    blob: &BlobTarget<'_>,
    headers: &axum::http::HeaderMap,
) -> Response {
    let (name, digest, upstream_url) = (blob.upstream_name, blob.digest, blob.upstream_url);
    state.metrics.record_download("docker");
    state.metrics.record_cache_miss("docker");
    state.activity.push(ActivityEntry::new(
        ActionType::ProxyFetch,
        format!("{}@{}", name, &digest[..19.min(digest.len())]),
        crate::registry_type::RegistryType::Docker,
        "PROXY",
    ));
    spawn_blob_spool(
        state.clone(),
        own.blob,
        own.spool,
        blob,
        own.progress,
        lease,
    );
    // Quarantine: the fill continues in the background and lands in the cache;
    // a held digest is answered 403 now (mirrors the manifest proxy path).
    if let Some(resp) = quarantine_proxy_fetch_gate(state, digest, upstream_url) {
        return resp;
    }
    // Answer as soon as upstream has answered: the body follows the spool file
    // as it grows, so a client that caps time-to-first-header (containerd ≥ 2.3
    // gives up after 30 s) is never left waiting for a multi-GB fill.
    spool_response(
        own.follower,
        share.status,
        share.content_length,
        digest,
        headers,
        fill_stall_ceiling(state.config.docker.read_timeout),
    )
    .await
}

/// Follow a fill another request leads, from the joiner's own read handle on the spool.
/// `None` when the fill can no longer be joined — it failed, or it finished and its spool
/// has already moved into storage — so the caller looks in storage or leads a new fill.
async fn join_fill(
    state: &AppState,
    share: SpoolShare,
    digest: &str,
    upstream_url: &str,
    headers: &axum::http::HeaderMap,
) -> Option<Response> {
    if matches!(share.status.borrow().done, Some(Err(_))) {
        return None;
    }
    // An open handle survives the spool's later rename into storage or its removal.
    let follower = tokio::fs::File::open(&share.path).await.ok()?;
    state.metrics.record_download("docker");
    if let Some(resp) = quarantine_proxy_fetch_gate(state, digest, upstream_url) {
        return Some(resp);
    }
    Some(
        spool_response(
            follower,
            share.status,
            share.content_length,
            digest,
            headers,
            fill_stall_ceiling(state.config.docker.read_timeout),
        )
        .await,
    )
}

/// The blob a request asked for, as its own request resolved it: the canonical name and
/// storage keys, and the upstream (with the name it goes by there) it is fetched from.
struct BlobTarget<'a> {
    name: &'a str,
    upstream_name: &'a str,
    digest: &'a str,
    key: &'a str,
    legacy_key: &'a str,
    upstream_url: &'a str,
}

/// Serve a follower of a running fill: join it, or — when the fill is gone because its
/// spool already moved into storage — serve the stored blob. `None` only when the fill
/// failed and nothing is stored, so the caller leads a new fill.
async fn follow_fill(
    state: &AppState,
    share: SpoolShare,
    blob: &BlobTarget<'_>,
    headers: &axum::http::HeaderMap,
) -> Option<Response> {
    if let Some(response) = join_fill(state, share, blob.digest, blob.upstream_url, headers).await {
        return Some(response);
    }
    serve_local_blob(
        state,
        headers,
        blob.name,
        blob.digest,
        blob.key,
        blob.legacy_key,
    )
    .await
}

/// Longest a response may wait on a fill that reports nothing: past the fill's own worst
/// case — a stalled chunk (`read_timeout`) on every resume attempt, plus their back-off —
/// with a margin. The fill always ends in bytes or a verdict before that; the ceiling only
/// guards against a fill that never reports at all.
fn fill_stall_ceiling(read_timeout: u64) -> Duration {
    let backoff: Duration = (1..=UPSTREAM_RESUME_ATTEMPTS)
        .map(|attempt| UPSTREAM_RESUME_BACKOFF * attempt)
        .sum();
    Duration::from_secs(read_timeout * (u64::from(UPSTREAM_RESUME_ATTEMPTS) + 1))
        + backoff
        + Duration::from_secs(30)
}

/// Spool an upstream blob to disk and store it, detached from the request that started
/// it: a client that gives up mid-fill (containerd retries a slow pull from scratch) no
/// longer discards the bytes already fetched, and the next request is a cache hit.
///
/// A panic inside the fill is caught like the other detached tasks (`spawn_cache`, the
/// PyPI backfill): it is logged, counted, and published to the follower as a failed
/// spool, so the response aborts instead of hanging on a dropped sender.
fn spawn_blob_spool(
    state: AppState,
    blob: UpstreamBlob,
    spool: SpoolFile,
    target: &BlobTarget<'_>,
    progress: tokio::sync::watch::Sender<SpoolStatus>,
    lease: Option<crate::proxy_coalesce::Lease<SpoolShare>>,
) {
    use futures::FutureExt as _;
    use std::panic::AssertUnwindSafe;

    let (key, digest, upstream) = (
        target.key.to_string(),
        target.digest.to_string(),
        target.upstream_url.to_string(),
    );

    let read_timeout = state.config.docker.read_timeout;
    let progress = Arc::new(progress);
    let on_panic = Arc::clone(&progress);
    let panic_key = key.clone();
    let task = async move {
        let outcome = spool_upstream_blob(
            blob,
            spool,
            read_timeout,
            &state.circuit_breaker,
            Some(progress.as_ref()),
        )
        .await;
        let mut fetched = match outcome {
            Ok(fetched) => fetched,
            Err(e) => {
                tracing::warn!(error = ?e, key = %key, "Docker blob proxy fetch failed mid-stream");
                // Release the flight before announcing the failure, so a request that sees
                // it can only start a fresh fill, never join this dead one.
                drop(lease);
                progress.send_modify(|s| s.done = Some(Err(format!("{e:?}"))));
                return;
            }
        };
        let expected_hash = digest.strip_prefix("sha256:").unwrap_or(&digest);
        if fetched.sha256 != expected_hash {
            tracing::warn!(
                digest = %digest,
                expected = %expected_hash,
                actual = %fetched.sha256,
                "Docker blob SHA-256 mismatch from upstream — not cached"
            );
            // TempFileGuard drops and cleans up; the follower's own handle still reads
            // to the end, and VerifyingReader fails the response there.
            drop(lease);
            progress.send_modify(|s| s.done = Some(Err("SHA-256 mismatch".to_string())));
            return;
        }
        // The digest is the verdict the response is waiting on; release the last byte
        // now rather than after the storage upload, which can take as long again.
        progress.send_modify(|s| s.done = Some(Ok(())));
        quarantine_record_verified(&state, &digest, &upstream);
        let sha_for_pin = fetched.sha256.clone();
        match state
            .storage
            .put_from_path(
                &key,
                &fetched.path,
                Some(&sha_for_pin),
                &Annotations::default(),
            )
            .await
        {
            Ok(()) => {
                fetched._guard.disarm();
                state.repo_index.invalidate("docker");
            }
            Err(e) => {
                crate::metrics::CACHE_WRITE_ERRORS
                    .with_label_values(&["docker", "proxy_blob_store"])
                    .inc();
                tracing::error!(
                    error = %e,
                    key = %key,
                    "Failed to store proxied blob — the response still completes from the spool"
                );
            }
        }
        // Held until the blob is in storage (an S3 upload can take as long as the fill),
        // so a request arriving in between still joins instead of refetching.
        drop(lease);
    };
    tokio::spawn(AssertUnwindSafe(task).catch_unwind().map(move |done| {
        if let Err(panic) = done {
            crate::metrics::CACHE_WRITE_ERRORS
                .with_label_values(&["docker", "proxy_blob_spool_panic"])
                .inc();
            tracing::error!(panic = ?panic, key = %panic_key, "Docker blob spool task panicked");
            on_panic.send_modify(|s| {
                if s.done.is_none() {
                    s.done = Some(Err("spool task panicked".to_string()));
                }
            });
        }
    }));
}

/// How to ask upstream for a blob again: kept with an opened blob so a spool that loses
/// the connection mid-body can request the missing tail instead of failing the fill.
struct BlobSource {
    client: reqwest::Client,
    upstream_url: String,
    name: String,
    url: String,
    docker_auth: DockerAuth,
    basic_auth: Option<String>,
    /// Seconds to wait for the response headers of each request.
    timeout: u64,
}

/// Why a blob request produced no response.
enum BlobRequestError {
    /// Connection, TLS or header timeout: counts against the upstream's breaker.
    Network(String),
    /// Upstream challenged for a token and the token server gave none.
    Token,
}

impl From<BlobRequestError> for ProxyError {
    fn from(e: BlobRequestError) -> Self {
        match e {
            BlobRequestError::Network(reason) => ProxyError::Network(reason),
            BlobRequestError::Token => ProxyError::Network("token fetch failed".into()),
        }
    }
}

/// Why a blob fill stopped, split the way the circuit breaker needs it.
enum FillFailure {
    /// The upstream failed us: connection, stalled or short body, 5xx, bad range.
    Unavailable(ProxyError),
    /// The upstream answered but refused (4xx, no token): alive, not down.
    Refused(ProxyError),
}

impl FillFailure {
    fn as_proxy_error(&self) -> &ProxyError {
        match self {
            FillFailure::Unavailable(e) | FillFailure::Refused(e) => e,
        }
    }

    fn into_proxy_error(self) -> ProxyError {
        match self {
            FillFailure::Unavailable(e) | FillFailure::Refused(e) => e,
        }
    }
}

impl BlobSource {
    /// One blob GET, answering a 401 challenge with a bearer token. `range_from` asks for
    /// the tail from that byte and reuses the cached bearer token that opened the blob.
    async fn send(&self, range_from: Option<u64>) -> Result<reqwest::Response, BlobRequestError> {
        let cached_bearer = match range_from {
            Some(_) => self
                .docker_auth
                .get_token(
                    &self.upstream_url,
                    &self.name,
                    None,
                    self.basic_auth.as_deref(),
                )
                .await
                .map(|token| format!("Bearer {token}")),
            None => None,
        };
        let first_auth =
            cached_bearer.or_else(|| self.basic_auth.as_deref().map(basic_auth_header));
        let response = self.send_once(first_auth, range_from).await?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        let www_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let token = self
            .docker_auth
            .get_token(
                &self.upstream_url,
                &self.name,
                www_auth.as_deref(),
                self.basic_auth.as_deref(),
            )
            .await
            .ok_or(BlobRequestError::Token)?;
        self.send_once(Some(format!("Bearer {token}")), range_from)
            .await
    }

    /// `timeout` bounds the wait for the response headers only. The body of a multi-GB
    /// layer is paced by the spool's per-chunk `read_timeout`: reqwest's
    /// `RequestBuilder::timeout` is a total deadline that would cut the body instead.
    async fn send_once(
        &self,
        authorization: Option<String>,
        range_from: Option<u64>,
    ) -> Result<reqwest::Response, BlobRequestError> {
        let mut request = self.client.get(&self.url);
        if let Some(value) = authorization {
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        if let Some(from) = range_from {
            request = request.header(reqwest::header::RANGE, format!("bytes={from}-"));
        }
        // CANCEL-SAFETY: `send` resolves once the response headers are in; dropping it on
        // timeout drops the connection attempt before any body byte reaches the spool.
        match tokio::time::timeout(Duration::from_secs(self.timeout), request.send()).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(BlobRequestError::Network(e.to_string())),
            Err(_) => Err(BlobRequestError::Network(format!(
                "no response headers within {}s",
                self.timeout
            ))),
        }
    }

    /// Ask for the rest of a blob from byte `offset`. Returns the response and how many
    /// leading body bytes to drop: none for a 206 that starts at `offset`, `offset` for an
    /// upstream that ignores `Range` and sends the whole blob again with 200.
    async fn resume(
        &self,
        offset: u64,
        total: Option<u64>,
    ) -> Result<(reqwest::Response, u64), FillFailure> {
        let response = match self.send(Some(offset)).await {
            Ok(response) => response,
            Err(BlobRequestError::Network(reason)) => {
                return Err(FillFailure::Unavailable(ProxyError::Network(reason)))
            }
            Err(e @ BlobRequestError::Token) => return Err(FillFailure::Refused(e.into())),
        };
        match response.status() {
            reqwest::StatusCode::PARTIAL_CONTENT => {
                let range = response
                    .headers()
                    .get(reqwest::header::CONTENT_RANGE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(parse_content_range);
                match range {
                    Some((start, size))
                        if start == offset && (total.is_none() || size == total) =>
                    {
                        Ok((response, 0))
                    }
                    other => Err(FillFailure::Unavailable(ProxyError::Network(format!(
                        "resume from byte {offset}: upstream answered range {other:?}"
                    )))),
                }
            }
            reqwest::StatusCode::OK => match (total, response.content_length()) {
                (Some(want), Some(got)) if want != got => {
                    Err(FillFailure::Unavailable(ProxyError::Network(format!(
                        "resume from byte {offset}: upstream now sends {got} bytes, not {want}"
                    ))))
                }
                _ => Ok((response, offset)),
            },
            // 4xx: upstream is alive and answered (a rejected token, say), as on open (#606)
            status if status.is_client_error() => {
                Err(FillFailure::Refused(ProxyError::Upstream(status.as_u16())))
            }
            status => Err(FillFailure::Unavailable(ProxyError::Upstream(
                status.as_u16(),
            ))),
        }
    }
}

/// `Content-Range: bytes <start>-<end>/<size>` → `(start, size)`; `size` is `None` for `*`.
fn parse_content_range(value: &str) -> Option<(u64, Option<u64>)> {
    let (span, size) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (start, end) = span.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end: u64 = end.trim().parse().ok()?;
    if end < start {
        return None;
    }
    let size = match size.trim() {
        "*" => None,
        n => {
            let size: u64 = n.parse().ok()?;
            if end >= size {
                return None;
            }
            Some(size)
        }
    };
    Some((start, size))
}

/// Open a blob on an upstream Docker registry: request, token auth and status check,
/// stopping once the response headers are in. The body is read by
/// [`spool_upstream_blob`].
///
/// `timeout` bounds the wait for the response headers; the body itself is paced by the
/// per-chunk `read_timeout` of the spool, which also resumes a cut body.
#[allow(clippy::too_many_arguments)]
pub async fn open_blob_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    digest: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    basic_auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
) -> Result<UpstreamBlob, ProxyError> {
    use crate::metrics::PROXY_ACTIVE_DOWNLOADS;

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

    let cb_key = upstream_key(
        crate::registry_type::RegistryType::Docker.as_str(),
        upstream_url,
    );
    let probe = cb.check(&cb_key)?;

    let source = BlobSource {
        client: client.clone(),
        upstream_url: upstream_url.to_string(),
        name: name.to_string(),
        url: format!(
            "{}/v2/{}/blobs/{}",
            upstream_url.trim_end_matches('/'),
            name,
            digest
        ),
        docker_auth: docker_auth.clone(),
        basic_auth: basic_auth.map(String::from),
        timeout,
    };
    let response = match source.send(None).await {
        Ok(response) => response,
        Err(BlobRequestError::Network(reason)) => {
            cb.record_failure(&cb_key, probe);
            return Err(ProxyError::Network(reason));
        }
        // The registry answered (401) and the token server gave no token: an auth
        // issue, not the registry down — alive, as on resume (`FillFailure::Refused`).
        Err(e @ BlobRequestError::Token) => {
            cb.record_alive(&cb_key, probe);
            return Err(e.into());
        }
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

    Ok(UpstreamBlob {
        content_length: response.content_length(),
        response,
        source,
        cb_key,
        probe,
        _download_gauge_guard,
    })
}

/// Resume attempts a spool makes in a row, without receiving a byte, before it fails.
const UPSTREAM_RESUME_ATTEMPTS: u32 = 5;
/// Pause before resume attempt `n` is `n` times this.
const UPSTREAM_RESUME_BACKOFF: Duration = Duration::from_millis(500);

/// A spool write failed on the local disk. The upstream answered and was sending the
/// body, so the probe goes back as alive: counting our disk against the upstream would
/// open its breaker, and dropping the probe would hold the half-open slot (#585).
fn spool_write_failed(
    cb: &CircuitBreakerRegistry,
    cb_key: &str,
    probe: ProbeToken,
    op: &str,
    e: std::io::Error,
) -> ProxyError {
    cb.record_alive(cb_key, probe);
    ProxyError::Network(format!("temp file {op}: {e}"))
}

/// Stream an opened upstream blob to its spool file with a per-chunk `read_timeout` and
/// incremental SHA-256. Never accumulates the blob in RAM. Each chunk is flushed before
/// `progress` advances, so a follower never reads past what is on disk.
///
/// A body that breaks off (connection reset, stalled chunk, short body) is resumed with
/// `Range: bytes=<written>-`, up to [`UPSTREAM_RESUME_ATTEMPTS`] times in a row without
/// progress; the digest is still computed over every byte in order.
pub(crate) async fn spool_upstream_blob(
    blob: UpstreamBlob,
    spool: SpoolFile,
    read_timeout: u64,
    cb: &CircuitBreakerRegistry,
    progress: Option<&tokio::sync::watch::Sender<SpoolStatus>>,
) -> Result<FetchedBlob, ProxyError> {
    use crate::metrics::PROXY_DOWNLOAD_BYTES;
    use sha2::Digest;
    use tokio::io::AsyncWriteExt;

    let UpstreamBlob {
        mut response,
        content_length,
        source,
        cb_key,
        probe,
        _download_gauge_guard,
    } = blob;
    let SpoolFile {
        path: temp_path,
        mut file,
        guard,
    } = spool;
    let mut hasher = sha2::Sha256::new();
    let chunk_timeout = Duration::from_secs(read_timeout);
    let mut bytes_written: u64 = 0;
    // Leading bytes of the current response that are already on disk (a resume that
    // upstream answered with the whole blob).
    let mut skip: u64 = 0;
    let mut stalls: u32 = 0;
    'fill: loop {
        let mut stream = response.bytes_stream();
        let failure = loop {
            // CANCEL-SAFETY: timeout wraps a single stream.next() call. On timeout the
            // spool resumes or fails, and TempFileGuard deletes the partial file.
            match tokio::time::timeout(chunk_timeout, stream.next()).await {
                Ok(Some(Ok(mut chunk))) => {
                    if skip > 0 {
                        let dropped = usize::try_from(skip).unwrap_or(usize::MAX).min(chunk.len());
                        chunk = chunk.slice(dropped..);
                        skip -= dropped as u64;
                        if chunk.is_empty() {
                            continue;
                        }
                    }
                    stalls = 0;
                    hasher.update(&chunk);
                    if let Err(e) = file.write_all(&chunk).await {
                        return Err(spool_write_failed(cb, &cb_key, probe, "write", e));
                    }
                    bytes_written += chunk.len() as u64;
                    if let Some(progress) = progress {
                        if let Err(e) = file.flush().await {
                            return Err(spool_write_failed(cb, &cb_key, probe, "flush", e));
                        }
                        progress.send_modify(|s| s.written = bytes_written);
                    }
                }
                Ok(Some(Err(e))) => {
                    break ProxyError::Network(format!("chunk read error: {}", e));
                }
                Ok(None) => {
                    let short = skip > 0 || content_length.is_some_and(|len| bytes_written < len);
                    if !short {
                        break 'fill;
                    }
                    break ProxyError::Network(format!(
                        "upstream body ended at byte {} of {:?}",
                        bytes_written, content_length
                    ));
                }
                Err(_) => {
                    break ProxyError::Network(format!(
                        "read timeout ({}s per chunk)",
                        read_timeout
                    ));
                }
            }
        };
        let mut last = FillFailure::Unavailable(failure);
        (response, skip) = loop {
            stalls += 1;
            if stalls > UPSTREAM_RESUME_ATTEMPTS {
                match last {
                    FillFailure::Unavailable(_) => cb.record_failure(&cb_key, probe),
                    FillFailure::Refused(_) => cb.record_alive(&cb_key, probe),
                }
                return Err(last.into_proxy_error());
            }
            tracing::warn!(
                error = ?last.as_proxy_error(),
                offset = bytes_written,
                attempt = stalls,
                upstream = %source.upstream_url,
                "Proxy blob body interrupted, resuming from upstream"
            );
            tokio::time::sleep(UPSTREAM_RESUME_BACKOFF * stalls).await;
            match source.resume(bytes_written, content_length).await {
                Ok(next) => break next,
                Err(e) => last = e,
            }
        };
    }
    debug_assert_eq!(skip, 0, "a finished fill has no bytes left to skip");
    if let Err(e) = file.flush().await {
        return Err(spool_write_failed(cb, &cb_key, probe, "flush", e));
    }
    drop(file);
    let sha256 = hex::encode(sha2::Digest::finalize(hasher));
    cb.record_success(&cb_key, probe);
    PROXY_DOWNLOAD_BYTES.inc_by(bytes_written);
    tracing::info!(
        bytes = bytes_written,
        content_length = ?content_length,
        "Proxy blob download complete"
    );
    Ok(FetchedBlob {
        path: temp_path,
        sha256,
        content_length,
        _guard: guard,
    })
}

/// Fetch a blob from an upstream Docker registry into a temp file (#580): open it,
/// spool it, return once the complete, hashed blob is on disk. Callers that want to
/// serve while the spool is still running use [`open_blob_from_upstream`] and
/// [`spool_upstream_blob`] separately.
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
    // The spool first, as in `start_fill`: once `open_blob_from_upstream` takes a
    // circuit-breaker probe, the only exits left are the ones the spool records.
    let spool = SpoolFile::create(temp_dir).await?;
    let blob = open_blob_from_upstream(
        client,
        upstream_url,
        name,
        digest,
        docker_auth,
        timeout,
        basic_auth,
        cb,
    )
    .await?;
    spool_upstream_blob(blob, spool, read_timeout, cb, None).await
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
    let cb_key = upstream_key(
        crate::registry_type::RegistryType::Docker.as_str(),
        upstream_url,
    );
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
            // The registry answered (401) and the token server gave no token: an auth
            // issue, not the registry down — alive, so the probe is returned.
            cb.record_alive(&cb_key, probe);
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
    bare: &mut BareMeta,
) -> Option<i64> {
    // The .meta.json sidecar (has push_timestamp) — namespaced, then legacy. The legacy (bare) one is
    // read only when no namespaced one exists, and not again when the request already holds it. (A
    // tag a push answers is dated by its record before this is asked: see `get_manifest`.)
    let meta = manifest_meta_key(ns, name, reference);
    let legacy_meta = manifest_meta_key(None, name, reference);
    let namespaced = if meta != legacy_meta {
        Some(storage.get(&meta).await)
    } else {
        None
    };
    let read = match namespaced {
        Some(Ok(data)) => Some(data),
        Some(Err(crate::storage::StorageError::NotFound)) | None => {
            if let BareMeta::Unread = bare {
                *bare = BareMeta::Read(read_bare_meta(storage, name, reference).await);
            }
            match bare {
                BareMeta::Read(Ok(Some(data))) => Some(data.clone()),
                _ => None,
            }
        }
        Some(Err(_)) => None,
    };
    if let Some(data) = read {
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

/// How often the background task folds accumulated pull counts into the
/// sidecars (#1114). Soft state: a crash loses at most this much (accepted).
pub(crate) const PULL_STATS_FLUSH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(45);

/// Fold accumulated pull counts into their `.stats.json` sidecars every
/// `interval`, and once more on shutdown, so a hard crash loses at most one
/// interval of counts. Extracted from `main` (with the interval injected) so a
/// test can drive the tick path (not only the shutdown path): the loss bound
/// depends on the tick flush running, not just the final flush on cancel (#1114).
pub(crate) async fn pull_stats_flush_loop(state: AppState, interval: std::time::Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        // CANCEL-SAFETY: both arms are cancel-safe (an interval tick and a
        // cancellation token). On shutdown we run one final flush, then stop.
        tokio::select! {
            _ = tick.tick() => {
                flush_pull_stats(&state).await;
            }
            _ = state.cancel_token.cancelled() => {
                flush_pull_stats(&state).await;
                break;
            }
        }
    }
}

/// Cumulative pull statistics for one manifest, stored in a `.stats.json`
/// sidecar beside its `.meta.json` (#1114). Kept out of `.meta.json` so a pull
/// never rewrites the integrity metadata a concurrent request reads.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub(crate) struct StatsSidecar {
    pub downloads: u64,
    pub last_pulled: u64,
}

/// The `.stats.json` sidecar key for a manifest's `.meta.json` key.
fn manifest_stats_key(meta_key: &str) -> String {
    let base = meta_key.strip_suffix(".meta.json").unwrap_or(meta_key);
    format!("{base}.stats.json")
}

/// Cumulative stats for a manifest: the `.stats.json` sidecar if present, else
/// the legacy counts still in a pre-V3 `.meta.json` (migrated on the next flush),
/// else zero.
async fn read_cumulative_stats(storage: &Storage, meta_key: &str) -> StatsSidecar {
    let stats_key = manifest_stats_key(meta_key);
    if let Ok(data) = storage.get(&stats_key).await {
        if let Ok(s) = serde_json::from_slice::<StatsSidecar>(&data) {
            return s;
        }
    }
    // Migration: a manifest pushed before V3 still carries counts in .meta.json.
    if let Ok(data) = storage.get(meta_key).await {
        if let Ok(m) = serde_json::from_slice::<ImageMetadata>(&data) {
            return StatsSidecar {
                downloads: m.downloads,
                last_pulled: m.last_pulled,
            };
        }
    }
    StatsSidecar::default()
}

/// Current pull stats for the UI and reports: the flushed cumulative value plus
/// the un-flushed in-memory delta.
pub(crate) async fn current_pull_stats(state: &AppState, meta_key: &str) -> StatsSidecar {
    let base = read_cumulative_stats(&state.storage, meta_key).await;
    let delta = state.pull_stats.peek(meta_key);
    StatsSidecar {
        downloads: base.downloads + delta.downloads,
        last_pulled: base.last_pulled.max(delta.last_pulled),
    }
}

/// Drain the pull-stats accumulator and fold each delta into its `.stats.json`
/// sidecar (#1114). Keeps the deleted-manifest guard of the old per-pull
/// writer: a delta for a manifest no longer stored is dropped, never
/// resurrecting its stats. Replaces the per-pull `.meta.json` rewrite.
pub(crate) async fn flush_pull_stats(state: &AppState) {
    for (meta_key, delta) in state.pull_stats.drain() {
        if delta.downloads == 0 && delta.last_pulled == 0 {
            continue;
        }
        // Serialize with push/delete on this manifest, as the old per-pull writer
        // did: take the publish lock, THEN re-check the manifest is stored, so a
        // delete that landed since the pull cannot be undone by writing a stale
        // sidecar after it (the sidecar is removed under the same lock on delete).
        let lock = state.publish_lock(&meta_key);
        let _guard = lock.lock().await;
        // The manifest blob key is the meta key with `.meta.json` → `.json`
        // (what `manifest_key` builds); stripping only `.meta.json` would check
        // `…/<ref>` and always miss, so the guard would skip every flush and the
        // sidecar would never be written (the stats would be silently lost).
        let manifest_key = format!(
            "{}.json",
            meta_key.strip_suffix(".meta.json").unwrap_or(&meta_key)
        );
        // Deleted-manifest guard: never resurrect a gone manifest's stats.
        if state.storage.stat(&manifest_key).await.is_none() {
            continue;
        }
        let mut stats = read_cumulative_stats(&state.storage, &meta_key).await;
        stats.downloads += delta.downloads;
        stats.last_pulled = stats.last_pulled.max(delta.last_pulled);
        let stats_key = manifest_stats_key(&meta_key);
        if let Ok(json) = serde_json::to_vec(&stats) {
            if let Err(e) = state.storage.put(&stats_key, &json).await {
                tracing::warn!(key = %stats_key, error = %e, "pull-stats sidecar write failed");
                crate::metrics::CACHE_WRITE_ERRORS
                    .with_label_values(&["docker", "stats"])
                    .inc();
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A file under `manifests/` stores a tag only if its name is a valid tag and not a sidecar.
    #[test]
    fn tag_from_manifest_file_accepts_only_tags() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let long = "a".repeat(129);
        let longest = "a".repeat(128);
        let cases: Vec<(String, Option<&str>)> = vec![
            ("1.0.0.json".into(), Some("1.0.0")),
            ("latest.json".into(), Some("latest")),
            ("v1.2.3-rc.1.json".into(), Some("v1.2.3-rc.1")),
            ("a.meta.b.json".into(), Some("a.meta.b")),
            (format!("{longest}.json"), Some(longest.as_str())),
            ("1.0.0.stats.json".into(), None),
            ("1.0.0.STATS.json".into(), None),
            ("1.0.0.meta.json".into(), None),
            ("x.meta.json".into(), None),
            (format!("{digest}.json"), None),
            (format!("{digest}.meta.json"), None),
            (format!("{digest}.stats.json"), None),
            (".json".into(), None),
            ("".into(), None),
            (format!("{long}.json"), None),
            ("latest".into(), None),
            ("-dash.json".into(), None),
            ("a..b.json".into(), None),
            ("a b.json".into(), None),
        ];
        for (file, want) in &cases {
            assert_eq!(tag_from_manifest_file(file), *want, "{file:?}");
        }
    }

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
            pushed_digest: None,
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
        let _lock = crate::test_env::env_lock();
        // Without env var set, should return default
        let max = max_upload_sessions();
        assert!(max > 0);
        assert_eq!(max, DEFAULT_MAX_UPLOAD_SESSIONS);
    }

    #[tokio::test]
    async fn test_cancel_upload_frees_session_and_temp() {
        use crate::test_helpers::{create_test_context, send};

        let ctx = create_test_context();
        let resp = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let location = resp.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string();

        let temp_path = {
            let sessions = ctx.state.upload_sessions.read();
            assert_eq!(sessions.len(), 1);
            sessions.values().next().unwrap().temp_path.clone()
        };
        assert!(temp_path.exists());

        let resp = send(&ctx.app, Method::DELETE, &location, Body::empty()).await;
        assert_eq!(
            resp.status(),
            StatusCode::NO_CONTENT,
            "cancel must be honoured, not 405 — a refused cancel holds a session slot until SESSION_TTL"
        );
        assert_eq!(ctx.state.upload_sessions.read().len(), 0);
        assert!(!temp_path.exists(), "cancel must reclaim the temp file");

        // Cancelling twice is a 404, not a panic or a second free.
        let resp = send(&ctx.app, Method::DELETE, &location, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_upload_session_limit_returns_oci_429() {
        // The handler reads the limit from env while the request runs, so the lock is
        // held across the whole request; a runtime of its own keeps that off an `.await`.
        let _lock = crate::test_env::env_lock();
        use crate::test_helpers::{body_bytes, create_test_context, send};

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Pre-fill the session map to the ceiling — no env mutation, so this is
            // safe under parallel tests.
            let ctx = create_test_context();
            {
                let mut sessions = ctx.state.upload_sessions.write();
                for i in 0..max_upload_sessions() {
                    sessions.insert(
                        format!("fill-{i}"),
                        UploadSession {
                            temp_path: std::env::temp_dir().join(format!("fill-{i}")),
                            size: 0,
                            name: "alpine".to_string(),
                            created_at: std::time::Instant::now(),
                        },
                    );
                }
            }
            let resp = send(
                &ctx.app,
                Method::POST,
                "/v2/alpine/blobs/uploads/",
                Body::empty(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                resp.headers()[header::CONTENT_TYPE].to_str().unwrap(),
                "application/json"
            );
            assert!(
                resp.headers().contains_key(header::RETRY_AFTER),
                "429 must carry Retry-After so clients back off"
            );
            let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
            assert_eq!(body["errors"][0]["code"], "TOOMANYREQUESTS");
            assert_eq!(
                body["errors"][0]["detail"]["limit"],
                max_upload_sessions() as u64
            );
        });
    }

    #[test]
    fn test_max_session_size_default() {
        let _lock = crate::test_env::env_lock();
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
    use crate::test_helpers::{
        body_bytes, create_test_context, create_test_context_with_config, send,
    };
    use axum::body::Body;
    use axum::http::{header, Method, StatusCode};
    use sha2::Digest;

    #[tokio::test]
    async fn test_docker_namespace_scope_enforced() {
        use crate::auth::NamespaceAuthority;
        use crate::config::ScopeEnforcement;
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
            Body::empty(),
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
            Body::empty(),
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
            Body::empty(),
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

    /// A cold miss is "not found" only when an upstream said so: a manifest or blob whose
    /// every upstream failed is 502. One upstream answering "not found" decides 404 while
    /// another is down. Docker Hub answers a single-segment name (`alpine`) with a 4xx and
    /// serves it as `library/alpine`, so that 4xx does not make the image missing while
    /// `library/alpine` failed.
    #[tokio::test]
    async fn a_cold_miss_is_404_only_when_an_upstream_said_not_found() {
        use crate::config::DockerUpstream;
        use wiremock::matchers::{method, path_regex};
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
        let hub_down = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("^/v2/library/"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&hub_down)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&hub_down)
            .await;
        let refused = "http://127.0.0.1:9".to_string();
        let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"layer")));
        let manifest = "/v2/myorg/app/manifests/1.0".to_string();
        let layer = format!("/v2/myorg/app/blobs/{blob}");
        let official = "/v2/alpine/manifests/3".to_string();
        let official_layer = format!("/v2/alpine/blobs/{blob}");

        for (upstreams, uri, want) in [
            (vec![down.uri()], &manifest, StatusCode::BAD_GATEWAY),
            (vec![refused.clone()], &manifest, StatusCode::BAD_GATEWAY),
            (vec![missing.uri()], &manifest, StatusCode::NOT_FOUND),
            (
                vec![down.uri(), missing.uri()],
                &manifest,
                StatusCode::NOT_FOUND,
            ),
            (vec![down.uri()], &layer, StatusCode::BAD_GATEWAY),
            (vec![refused.clone()], &layer, StatusCode::BAD_GATEWAY),
            (vec![missing.uri()], &layer, StatusCode::NOT_FOUND),
            (
                vec![down.uri(), missing.uri()],
                &layer,
                StatusCode::NOT_FOUND,
            ),
            (vec![hub_down.uri()], &official, StatusCode::BAD_GATEWAY),
            (vec![missing.uri()], &official, StatusCode::NOT_FOUND),
            (
                vec![hub_down.uri()],
                &official_layer,
                StatusCode::BAD_GATEWAY,
            ),
            (vec![missing.uri()], &official_layer, StatusCode::NOT_FOUND),
        ] {
            let entries = upstreams.clone();
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.docker.upstreams = entries
                    .into_iter()
                    .map(|url| DockerUpstream {
                        url,
                        auth: None,
                        namespace: None,
                        prefix: None,
                    })
                    .collect();
            });
            let resp = send(&ctx.app, Method::GET, uri, Body::empty()).await;
            assert_eq!(resp.status(), want, "{uri} {upstreams:?}");
        }
        assert!(!down.received_requests().await.unwrap().is_empty());
        assert!(!missing.received_requests().await.unwrap().is_empty());
        let hub = hub_down.received_requests().await.unwrap();
        assert!(hub
            .iter()
            .any(|r| r.url.path().starts_with("/v2/library/alpine/")));
    }

    /// A locally pushed manifest is authoritative: with global pull-through upstreams
    /// configured, GET must serve it without revalidating against upstream — an unreachable
    /// upstream must neither 404 the tag (serve_stale = false) nor stale-mark it.
    #[tokio::test]
    async fn test_hosted_manifest_skips_upstream_revalidation() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.serve_stale = false;
            cfg.docker.upstreams = vec![DockerUpstream {
                url: "http://127.0.0.1:1".into(),
                auth: None,
                namespace: None,
                prefix: None,
            }];
        });

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

        seed_zero_config(&ctx.state, "hosted-img").await;
        let put_resp = send(
            &ctx.app,
            Method::PUT,
            "/v2/hosted-img/manifests/v1",
            Body::from(manifest_bytes.clone()),
        )
        .await;
        assert_eq!(put_resp.status(), StatusCode::CREATED);

        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/hosted-img/manifests/v1",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("x-nora-stale").is_none(),
            "hosted manifest must not be served via the stale-while-error path"
        );
        let body = body_bytes(resp).await;
        assert_eq!(body.as_ref(), manifest_bytes.as_slice());
    }

    #[test]
    fn push_record_is_a_record_naming_a_digest() {
        let meta = |digest: Option<&str>| {
            serde_json::to_vec(&super::ImageMetadata {
                push_timestamp: 7,
                pushed_digest: digest.map(str::to_string),
                ..Default::default()
            })
            .unwrap()
        };
        let sha256 = format!("sha256:{}", "a".repeat(64));
        let sha512 = format!("sha512:{}", "b".repeat(128));
        assert_eq!(
            super::push_record(&meta(Some(&sha256))).map(|m| m.push_timestamp),
            Some(7)
        );
        assert!(super::push_record(&meta(Some(&sha512))).is_some());
        for not_a_record in [
            meta(None),
            meta(Some("")),
            meta(Some("md5:abc")),
            meta(Some("SHA256:abc")),
            b"not json".to_vec(),
        ] {
            assert!(
                super::push_record(&not_a_record).is_none(),
                "{}",
                String::from_utf8_lossy(&not_a_record)
            );
        }
    }

    #[test]
    fn content_has_digest_holds_digests_and_passes_tags() {
        use sha2::Digest;
        let body = b"manifest";
        let s256 = format!("sha256:{}", hex::encode(sha2::Sha256::digest(body)));
        let s512 = format!("sha512:{}", hex::encode(sha2::Sha512::digest(body)));
        assert!(super::content_has_digest(&s256, body));
        assert!(super::content_has_digest(&s512, body));
        assert!(!super::content_has_digest(&s256, b"other"));
        assert!(!super::content_has_digest(&s512, b"other"));
        assert!(!super::content_has_digest(
            &s256.to_uppercase().replace("SHA256", "sha256"),
            body
        ));
        assert!(!super::content_has_digest("sha256:", body));
        // The whole digest is compared: a reference that matches only in part, at any position,
        // is another digest.
        let hex = s256.strip_prefix("sha256:").unwrap();
        for i in 0..hex.len() {
            let mut other: Vec<u8> = hex.as_bytes().to_vec();
            other[i] = if other[i] == b'0' { b'1' } else { b'0' };
            let other = format!("sha256:{}", String::from_utf8(other).unwrap());
            assert!(!super::content_has_digest(&other, body), "position {i}");
        }
        assert!(!super::content_has_digest(
            &format!("sha256:{}", &hex[..12]),
            body
        ));
        assert!(!super::content_has_digest(&format!("{s256}0"), body));
        assert!(super::content_has_digest("latest", b"anything"));
        assert!(super::content_has_digest("v1.0", b""));
    }

    /// A manifest requested by digest is content-addressed: bytes from an upstream that hash to
    /// another digest are neither served under the requested one nor cached there — on every way
    /// an upstream is asked: the name as requested, the `library/` name of an official image, the
    /// next upstream after a miss, and an upstream addressed by its prefix.
    #[tokio::test]
    async fn a_manifest_by_digest_is_served_only_if_it_has_that_digest() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;
        use sha2::Digest;
        use wiremock::matchers::{any, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let wanted = b"{\"schemaVersion\":2,\"layers\":[]}".to_vec();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&wanted)));
        let other = b"{\"schemaVersion\":2,\"layers\":[],\"x\":1}".to_vec();
        let manifest = |body: &[u8]| {
            ResponseTemplate::new(200)
                .insert_header(
                    "content-type",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
                .set_body_bytes(body.to_vec())
        };
        let upstream = |url: String, prefix: Option<&str>| DockerUpstream {
            url,
            auth: None,
            namespace: None,
            prefix: prefix.map(str::to_string),
        };
        // (case, upstream answer for the asked name, request path, whether the answer is honest)
        for (case, honest) in [
            ("one upstream", false),
            ("library name", false),
            ("next upstream", false),
            ("prefixed upstream", false),
            ("one upstream", true),
            ("library name", true),
        ] {
            let body = if honest { &wanted } else { &other };
            let first = MockServer::start().await;
            let second = MockServer::start().await;
            let (upstreams, request) = match case {
                "one upstream" => {
                    Mock::given(any())
                        .respond_with(manifest(body))
                        .mount(&first)
                        .await;
                    (
                        vec![upstream(first.uri(), None)],
                        format!("/v2/corp/app/manifests/{digest}"),
                    )
                }
                "library name" => {
                    Mock::given(path(format!("/v2/library/nginx/manifests/{digest}")))
                        .respond_with(manifest(body))
                        .mount(&first)
                        .await;
                    Mock::given(any())
                        .respond_with(ResponseTemplate::new(404))
                        .mount(&first)
                        .await;
                    (
                        vec![upstream(first.uri(), None)],
                        format!("/v2/nginx/manifests/{digest}"),
                    )
                }
                "next upstream" => {
                    Mock::given(any())
                        .respond_with(ResponseTemplate::new(404))
                        .mount(&first)
                        .await;
                    Mock::given(any())
                        .respond_with(manifest(body))
                        .mount(&second)
                        .await;
                    (
                        vec![upstream(first.uri(), None), upstream(second.uri(), None)],
                        format!("/v2/corp/app/manifests/{digest}"),
                    )
                }
                _ => {
                    Mock::given(any())
                        .respond_with(manifest(body))
                        .mount(&first)
                        .await;
                    (
                        vec![upstream(first.uri(), Some("hub"))],
                        format!("/v2/hub/corp/app/manifests/{digest}"),
                    )
                }
            };
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.docker.upstreams = upstreams;
            });
            let resp = send(&ctx.app, Method::GET, &request, Body::empty()).await;
            let status = resp.status();
            let served = body_bytes(resp).await;
            if honest {
                assert_eq!(status, StatusCode::OK, "{case}: honest answer refused");
                assert_eq!(served.as_ref(), wanted.as_slice(), "{case}");
                continue;
            }
            assert_ne!(
                served.as_ref(),
                other.as_slice(),
                "{case}: served bytes of another digest ({status})"
            );
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let cached: Vec<String> = ctx
                .state
                .storage
                .list("docker/")
                .await
                .unwrap()
                .into_iter()
                .filter(|k| k.contains(&digest))
                .collect();
            assert!(
                cached.is_empty(),
                "{case}: cached under the digest: {cached:?}"
            );
        }
    }

    /// A copy stored under a digest reference that hashes to another digest (cached before the
    /// fetch checked it) is not that manifest: it is not served, and an honest upstream answer
    /// replaces it; with no upstream it is a missing manifest.
    #[tokio::test]
    async fn a_stored_copy_by_digest_is_served_only_if_it_has_that_digest() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;
        use sha2::Digest;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let wanted = b"{\"schemaVersion\":2,\"layers\":[]}".to_vec();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&wanted)));
        let other = b"{\"schemaVersion\":2,\"layers\":[],\"x\":1}".to_vec();
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "content-type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .set_body_bytes(wanted.clone()),
            )
            .mount(&server)
            .await;
        let upstream = DockerUpstream {
            url: server.uri(),
            auth: None,
            namespace: None,
            prefix: None,
        };
        let ns = upstream.resolved_namespace();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.docker.upstreams = vec![upstream];
        });
        let proxied = super::manifest_key(Some(&ns), "corp/app", &digest);
        ctx.state.storage.put(&proxied, &other).await.unwrap();
        let request = format!("/v2/corp/app/manifests/{digest}");
        let resp = send(&ctx.app, Method::GET, &request, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await.as_ref(), wanted.as_slice());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        // Err while the background write replaces the file counts as "not yet".
        while ctx.state.storage.get(&proxied).await.ok().as_deref() != Some(wanted.as_slice()) {
            assert!(
                std::time::Instant::now() < deadline,
                "the other digest's bytes stayed under the digest"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let hosted = create_test_context_with_config(|cfg| cfg.docker.upstreams = Vec::new());
        hosted
            .state
            .storage
            .put(&super::manifest_key(None, "corp/app", &digest), &other)
            .await
            .unwrap();
        let resp = send(&hosted.app, Method::GET, &request, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A manifest pushed by digest is that digest's content: other bytes are refused with OCI
    /// DIGEST_INVALID and nothing is stored.
    #[tokio::test]
    async fn a_manifest_pushed_by_digest_must_have_that_digest() {
        use sha2::Digest;
        let ctx = crate::test_helpers::create_test_context_with_config(|_| {});
        let pushed = table_manifest(PUSHED_CFG);
        seed_zero_config(&ctx.state, "corp/app").await;
        let other = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(table_manifest(UPSTREAM_CFG)))
        );
        let resp = send(
            &ctx.app,
            Method::PUT,
            &format!("/v2/corp/app/manifests/{other}"),
            Body::from(pushed.clone()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
        assert!(body.contains("DIGEST_INVALID"), "{body}");
        let stored: Vec<String> = ctx
            .state
            .storage
            .list("docker/corp/app/manifests/")
            .await
            .unwrap();
        assert!(stored.is_empty(), "stored: {stored:?}");

        let own = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&pushed)));
        let resp = send(
            &ctx.app,
            Method::PUT,
            &format!("/v2/corp/app/manifests/{own}"),
            Body::from(pushed),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    /// COMPAT.md: pushing to a name that would otherwise proxy pins that tag to the pushed copy.
    /// Also when the tag was pulled through the proxy before the push.
    #[tokio::test]
    async fn a_push_pins_a_tag_that_was_pulled_through_the_proxy() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let manifest = |config_digest: &str| {
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "config": {
                    "mediaType": "application/vnd.docker.container.image.v1+json",
                    "size": 0,
                    "digest": config_digest
                },
                "layers": []
            }))
            .unwrap()
        };
        let upstream_manifest =
            manifest("sha256:1111111111111111111111111111111111111111111111111111111111111111");
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "content-type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .set_body_bytes(upstream_manifest.clone()),
            )
            .mount(&server)
            .await;
        let uri = server.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: uri,
                auth: None,
                namespace: None,
                prefix: None,
            }];
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/corp/app/manifests/1.0",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_bytes(resp).await.as_ref(),
            upstream_manifest.as_slice()
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let pushed =
            manifest("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        seed_zero_config(&ctx.state, "corp/app").await;
        let put = send(
            &ctx.app,
            Method::PUT,
            "/v2/corp/app/manifests/1.0",
            Body::from(pushed.clone()),
        )
        .await;
        assert_eq!(put.status(), StatusCode::CREATED);

        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/corp/app/manifests/1.0",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_bytes(resp).await.as_ref(),
            pushed.as_slice(),
            "the pushed manifest answers its tag"
        );
    }

    /// Decision table for a pushed tag: helpers.
    fn table_manifest(config_digest: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": config_digest
            },
            "layers": []
        }))
        .unwrap()
    }

    const PUSHED_CFG: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const UPSTREAM_CFG: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    /// An upstream serving the same tag with its own manifest, and a context pointing at it.
    async fn table_context() -> (
        wiremock::MockServer,
        crate::test_helpers::TestContext,
        String,
    ) {
        use crate::config::DockerUpstream;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "content-type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .set_body_bytes(table_manifest(UPSTREAM_CFG)),
            )
            .mount(&server)
            .await;
        let upstream = DockerUpstream {
            url: server.uri(),
            auth: None,
            namespace: None,
            prefix: None,
        };
        let ns = upstream.resolved_namespace();
        let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
            cfg.docker.upstreams = vec![upstream];
        });
        (server, ctx, ns)
    }

    async fn table_push(ctx: &crate::test_helpers::TestContext) -> Vec<u8> {
        let pushed = table_manifest(PUSHED_CFG);
        seed_zero_config(&ctx.state, "corp/app").await;
        let put = send(
            &ctx.app,
            Method::PUT,
            "/v2/corp/app/manifests/1.0",
            Body::from(pushed.clone()),
        )
        .await;
        assert_eq!(put.status(), StatusCode::CREATED);
        pushed
    }

    async fn table_get(ctx: &crate::test_helpers::TestContext) -> Vec<u8> {
        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/corp/app/manifests/1.0",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        body_bytes(resp).await.to_vec()
    }

    /// Row 7: a push removes the proxied copy of its tag and the copy's metadata.
    #[tokio::test]
    async fn row7_a_push_removes_the_proxied_copy_of_its_tag() {
        let (_server, ctx, ns) = table_context().await;
        assert_eq!(table_get(&ctx).await, table_manifest(UPSTREAM_CFG));
        let proxied = super::manifest_key(Some(&ns), "corp/app", "1.0");
        let proxied_meta = super::manifest_meta_key(Some(&ns), "corp/app", "1.0");
        // The proxied copy is cached off the request path; its metadata is the task's last write.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while ctx.state.storage.stat(&proxied).await.is_none()
            || ctx.state.storage.stat(&proxied_meta).await.is_none()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "proxied copy and its metadata cached"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        table_push(&ctx).await;
        assert!(
            ctx.state.storage.stat(&proxied).await.is_none(),
            "proxied copy left beside the push"
        );
        assert!(
            ctx.state.storage.stat(&proxied_meta).await.is_none(),
            "proxied copy's metadata left beside the push"
        );
    }

    /// Row 1, cost: a pull of a pushed tag reads its push record once (it answers the tag and dates
    /// it for curation) and the pushed manifest — two reads. Reading the bare metadata a second time,
    /// or the namespaced metadata a push makes moot, costs every pull of a pushed image a round trip.
    #[tokio::test]
    async fn row1_a_pull_of_a_pushed_tag_reads_its_metadata_once() {
        use crate::config::DockerUpstream;
        let (storage, ops) = crate::test_helpers::op_counting_storage();
        let upstream = DockerUpstream {
            url: "http://127.0.0.1:9".to_string(),
            auth: None,
            namespace: None,
            prefix: None,
        };
        let ns = upstream.resolved_namespace();
        let ctx =
            crate::test_helpers::create_test_context_with_storage_and_config(storage, move |cfg| {
                cfg.docker.upstreams = vec![upstream];
            });
        assert_ne!(
            super::manifest_key(Some(&ns), "corp/app", "1.0"),
            super::manifest_key(None, "corp/app", "1.0")
        );
        let pushed = table_push(&ctx).await;
        ops.reset();
        assert_eq!(table_get(&ctx).await, pushed);
        assert_eq!(
            ops.snapshot().get("get").copied(),
            Some(2),
            "{:?}",
            ops.snapshot()
        );
    }

    /// Cost: a pull by digest of a proxied copy reads its metadata and the manifest — two reads.
    /// The bare metadata is read up front only where the push record answers (a tag), never on
    /// every pull.
    #[tokio::test]
    async fn a_pull_by_digest_of_a_proxied_copy_reads_two_documents() {
        use crate::config::DockerUpstream;
        use sha2::Digest;
        let (storage, ops) = crate::test_helpers::op_counting_storage();
        let upstream = DockerUpstream {
            url: "http://127.0.0.1:9".to_string(),
            auth: None,
            namespace: None,
            prefix: None,
        };
        let ns = upstream.resolved_namespace();
        let ctx =
            crate::test_helpers::create_test_context_with_storage_and_config(storage, move |cfg| {
                cfg.docker.upstreams = vec![upstream];
            });
        let proxied = table_manifest(UPSTREAM_CFG);
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&proxied)));
        let meta = super::ImageMetadata {
            push_timestamp: 100,
            ..Default::default()
        };
        ctx.state
            .storage
            .put(
                &super::manifest_key(Some(&ns), "corp/app", &digest),
                &proxied,
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                &super::manifest_meta_key(Some(&ns), "corp/app", &digest),
                &serde_json::to_vec(&meta).unwrap(),
            )
            .await
            .unwrap();
        ops.reset();
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/v2/corp/app/manifests/{digest}"),
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await.to_vec(), proxied);
        assert_eq!(
            ops.snapshot().get("get").copied(),
            Some(2),
            "{:?}",
            ops.snapshot()
        );
    }

    /// The sidecar publish date follows its decision table on every combination of the two metadata
    /// documents (dated, undated, with a push record, absent, unreadable), with and without a
    /// namespace, both when the request already holds the bare metadata and when the date reads it.
    #[tokio::test]
    async fn a_publish_date_follows_its_table_with_the_bare_metadata_read_once() {
        use std::sync::Arc;
        #[derive(Clone, Copy, Debug, PartialEq)]
        enum Doc {
            Absent,
            Dated,
            // Present but without a date: a namespaced one still wins over the bare one.
            Undated,
            // Dated, with a push record: here only a dated document.
            Pushed,
            // A push record without a date: here only an undated document.
            PushedUndated,
            Unreadable,
        }
        let (name, reference) = ("date-img", "v1");
        let mut seen = std::collections::BTreeSet::new();
        for ns in [Some("docker.io"), None] {
            let ns_key = super::manifest_meta_key(ns, name, reference);
            let bare_key = super::manifest_meta_key(None, name, reference);
            let docs = [
                Doc::Absent,
                Doc::Dated,
                Doc::Undated,
                Doc::Pushed,
                Doc::PushedUndated,
                Doc::Unreadable,
            ];
            for ns_doc in docs {
                for bare_doc in docs {
                    if ns_key == bare_key && ns_doc != Doc::Absent {
                        continue;
                    }
                    let dir = tempfile::TempDir::new().unwrap();
                    let path = dir.path().to_str().unwrap().to_string();
                    let writer = crate::storage::Storage::from_backend(Arc::new(
                        crate::storage::LocalStorage::new(&path),
                    ));
                    for (key, doc, ts) in [(&ns_key, ns_doc, 100u64), (&bare_key, bare_doc, 200)] {
                        if doc != Doc::Absent {
                            let meta = super::ImageMetadata {
                                push_timestamp: if matches!(doc, Doc::Undated | Doc::PushedUndated)
                                {
                                    0
                                } else {
                                    ts
                                },
                                pushed_digest: matches!(doc, Doc::Pushed | Doc::PushedUndated)
                                    .then(|| format!("sha256:{}", "a".repeat(64))),
                                ..Default::default()
                            };
                            writer
                                .put(key, &serde_json::to_vec(&meta).unwrap())
                                .await
                                .unwrap();
                        }
                    }
                    let fail_prefix = match (
                        ns_doc == Doc::Unreadable && ns_key != bare_key,
                        bare_doc == Doc::Unreadable,
                    ) {
                        (true, true) => "docker/".to_string(),
                        (true, false) => ns_key.clone(),
                        (false, true) => bare_key.clone(),
                        (false, false) => "\u{0}none".to_string(),
                    };
                    let storage =
                        crate::storage::Storage::from_backend(Arc::new(FailingPrefixBackend {
                            inner: crate::storage::LocalStorage::new(&path),
                            fail_prefix,
                        }));
                    let unread = super::extract_docker_publish_date(
                        &storage,
                        name,
                        reference,
                        false,
                        ns,
                        &mut super::BareMeta::Unread,
                    )
                    .await;
                    let mut once = super::BareMeta::Read(
                        super::read_bare_meta(&storage, name, reference).await,
                    );
                    let read = super::extract_docker_publish_date(
                        &storage, name, reference, false, ns, &mut once,
                    )
                    .await;
                    // The decision table: the namespaced document decides when it exists (a date, or none when
                    // it has no date or cannot be read), and the bare one only when it does not. A push record
                    // in a document changes nothing here: a tag a push answers is dated before this is asked.
                    let date =
                        |doc: Doc, ts: i64| matches!(doc, Doc::Dated | Doc::Pushed).then_some(ts);
                    let expected = if ns_key != bare_key && ns_doc != Doc::Absent {
                        date(ns_doc, 100)
                    } else {
                        date(bare_doc, 200)
                    };
                    let case = format!("ns {ns:?}, namespaced {ns_doc:?}, bare {bare_doc:?}");
                    assert_eq!(unread, expected, "unread: {case}");
                    assert_eq!(read, expected, "read once: {case}");
                    seen.insert(format!("{unread:?}"));
                }
            }
        }
        // The grid reaches every answer: the namespaced date, the bare one, and none.
        assert_eq!(seen.len(), 3, "{seen:?}");
    }

    /// A backend that, the first time `trigger` is read, applies `writes` before answering: a
    /// concurrent push whose writes land while the request reads that document.
    struct WriteOnReadBackend {
        inner: crate::storage::LocalStorage,
        trigger: String,
        writes: std::sync::Mutex<Option<Vec<(String, Vec<u8>)>>>,
    }

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for WriteOnReadBackend {
        async fn put(
            &self,
            key: &str,
            data: &[u8],
            sha256: &str,
            annotations: &nora_registry::annotations::Annotations,
        ) -> crate::storage::Result<()> {
            self.inner.put(key, data, sha256, annotations).await
        }
        async fn get(
            &self,
            key: &str,
        ) -> crate::storage::Result<(axum::body::Bytes, crate::storage::Recorded)> {
            if key == self.trigger {
                let pending = self.writes.lock().unwrap().take();
                for (k, v) in pending.unwrap_or_default() {
                    use sha2::Digest;
                    let sha = hex::encode(sha2::Sha256::digest(&v));
                    self.inner
                        .put(
                            &k,
                            &v,
                            &sha,
                            &nora_registry::annotations::Annotations::default(),
                        )
                        .await
                        .unwrap();
                }
            }
            self.inner.get(key).await
        }
        async fn recorded(&self, key: &str) -> crate::storage::Recorded {
            self.inner.recorded(key).await
        }
        async fn delete(&self, key: &str) -> crate::storage::Result<()> {
            self.inner.delete(key).await
        }
        async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
            self.inner.list(prefix).await
        }
        async fn stat(&self, key: &str) -> Option<crate::storage::FileMeta> {
            self.inner.stat(key).await
        }
        async fn health_check(&self) -> bool {
            true
        }
        async fn total_size(&self) -> u64 {
            self.inner.total_size().await
        }
        async fn copy(
            &self,
            src: &str,
            dst: &str,
            sha256: Option<&str>,
        ) -> crate::storage::Result<()> {
            self.inner.copy(src, dst, sha256).await
        }
        async fn put_from_path(
            &self,
            key: &str,
            src: &std::path::Path,
            sha256: Option<&str>,
            annotations: &nora_registry::annotations::Annotations,
        ) -> crate::storage::Result<()> {
            self.inner
                .put_from_path(key, src, sha256, annotations)
                .await
        }
        async fn get_reader(
            &self,
            key: &str,
        ) -> crate::storage::Result<(
            u64,
            crate::storage::Recorded,
            std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
        )> {
            self.inner.get_reader(key).await
        }
        fn backend_name(&self) -> &'static str {
            "write-on-read"
        }
    }

    /// Rows 7b and R3, through curation (`min_release_age` 7d): a tag a push answers is dated by its
    /// record, whatever its proxied copy's metadata says; a record without its manifest dates
    /// nothing — the tag is dated by its proxied copy, which answers it. The answer's status is the
    /// oracle: 200 for an old date, 403 for a fresh one.
    #[tokio::test]
    async fn row7b_curation_dates_a_tag_by_the_push_that_answers_it() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old = now - 30 * 86_400;
        // (push record date, bare manifest kept, proxied copy's date, expected status)
        let rows = [
            (old, true, now, StatusCode::OK),
            (now, true, old, StatusCode::FORBIDDEN),
            (old, false, now, StatusCode::FORBIDDEN),
            (now, false, old, StatusCode::OK),
        ];
        for (pushed_at, manifest_kept, proxied_at, expected) in rows {
            use crate::config::DockerUpstream;
            use wiremock::matchers::any;
            use wiremock::{Mock, MockServer, ResponseTemplate};
            let server = MockServer::start().await;
            Mock::given(any())
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header(
                            "content-type",
                            "application/vnd.docker.distribution.manifest.v2+json",
                        )
                        .set_body_bytes(table_manifest(UPSTREAM_CFG)),
                )
                .mount(&server)
                .await;
            let upstream = DockerUpstream {
                url: server.uri(),
                auth: None,
                namespace: None,
                prefix: None,
            };
            let ns = upstream.resolved_namespace();
            let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
                cfg.docker.upstreams = vec![upstream];
                cfg.curation.mode = crate::config::CurationMode::Enforce;
                cfg.curation.min_release_age = Some("7d".to_string());
            });
            let pushed = table_manifest(PUSHED_CFG);
            use sha2::Digest;
            let record = super::ImageMetadata {
                push_timestamp: pushed_at,
                pushed_digest: Some(format!(
                    "sha256:{}",
                    hex::encode(sha2::Sha256::digest(&pushed))
                )),
                ..Default::default()
            };
            let proxied_meta = super::ImageMetadata {
                push_timestamp: proxied_at,
                ..Default::default()
            };
            let storage = &ctx.state.storage;
            storage
                .put(
                    &super::manifest_meta_key(None, "corp/app", "1.0"),
                    &serde_json::to_vec(&record).unwrap(),
                )
                .await
                .unwrap();
            if manifest_kept {
                storage
                    .put(&super::manifest_key(None, "corp/app", "1.0"), &pushed)
                    .await
                    .unwrap();
            }
            storage
                .put(
                    &super::manifest_key(Some(&ns), "corp/app", "1.0"),
                    &table_manifest(UPSTREAM_CFG),
                )
                .await
                .unwrap();
            storage
                .put(
                    &super::manifest_meta_key(Some(&ns), "corp/app", "1.0"),
                    &serde_json::to_vec(&proxied_meta).unwrap(),
                )
                .await
                .unwrap();
            let resp = send(
                &ctx.app,
                Method::GET,
                "/v2/corp/app/manifests/1.0",
                Body::empty(),
            )
            .await;
            assert_eq!(
                resp.status(),
                expected,
                "pushed {pushed_at}, manifest kept {manifest_kept}, proxied {proxied_at}"
            );
        }
    }

    /// Row R3: a push record left without its bare manifest (a delete interrupted between the two)
    /// answers nothing; the tag goes on as if it had no record — here its proxied copy answers.
    #[tokio::test]
    async fn row_r3_a_record_without_its_manifest_hands_the_tag_on() {
        let (_server, ctx, ns) = table_context().await;
        table_push(&ctx).await;
        ctx.state
            .storage
            .put(
                &super::manifest_key(Some(&ns), "corp/app", "1.0"),
                &table_manifest(UPSTREAM_CFG),
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .delete(&super::manifest_key(None, "corp/app", "1.0"))
            .await
            .unwrap();
        assert!(ctx
            .state
            .storage
            .stat(&super::manifest_meta_key(None, "corp/app", "1.0"))
            .await
            .is_some());
        assert_eq!(table_get(&ctx).await, table_manifest(UPSTREAM_CFG));
    }

    /// Row R2, race: a pushed tag with a proxied copy beside it, re-pushed (its bare manifest, then
    /// its record; the proxied copy not yet removed) between the pull's read of the push record and
    /// its read of the manifest. The record still names the old digest, the bare bytes are the new
    /// push: the tag is the push's, so the new bytes answer — never the proxied copy.
    #[tokio::test]
    async fn row_r2_a_re_push_between_the_record_and_the_manifest_answers_the_new_push() {
        use sha2::Digest;
        use std::sync::Arc;
        let (_server, ctx, ns) = table_context().await;
        table_push(&ctx).await;
        ctx.state
            .storage
            .put(
                &super::manifest_key(Some(&ns), "corp/app", "1.0"),
                &table_manifest(UPSTREAM_CFG),
            )
            .await
            .unwrap();
        let repushed = table_manifest(
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        );
        let meta = super::ImageMetadata {
            push_timestamp: 1,
            pushed_digest: Some(format!(
                "sha256:{}",
                hex::encode(sha2::Sha256::digest(&repushed))
            )),
            ..Default::default()
        };
        let mut racy = ctx.state.clone();
        racy.storage = crate::storage::Storage::from_backend(Arc::new(WriteOnReadBackend {
            inner: crate::storage::LocalStorage::new(ctx._tempdir.path().to_str().unwrap()),
            trigger: super::manifest_key(None, "corp/app", "1.0"),
            writes: std::sync::Mutex::new(Some(vec![
                (
                    super::manifest_key(None, "corp/app", "1.0"),
                    repushed.clone(),
                ),
                (
                    super::manifest_meta_key(None, "corp/app", "1.0"),
                    serde_json::to_vec(&meta).unwrap(),
                ),
            ])),
        }));
        let resp = get_manifest_via_dispatch(&racy, "corp/app/manifests/1.0").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let got = body_bytes(resp).await.to_vec();
        assert!(
            got != table_manifest(UPSTREAM_CFG),
            "the proxied copy answered a pushed tag"
        );
        assert_eq!(got, repushed);
    }

    /// Row 1, race: a proxied copy written after the push (a fetch that was in flight) does not
    /// take the tag back.
    #[tokio::test]
    async fn row1_a_proxied_copy_written_after_the_push_does_not_win() {
        let (_server, ctx, ns) = table_context().await;
        let pushed = table_push(&ctx).await;
        let proxied = super::manifest_key(Some(&ns), "corp/app", "1.0");
        ctx.state
            .storage
            .put(&proxied, &table_manifest(UPSTREAM_CFG))
            .await
            .unwrap();
        assert_eq!(table_get(&ctx).await, pushed);
        let head = send(
            &ctx.app,
            Method::HEAD,
            "/v2/corp/app/manifests/1.0",
            Body::empty(),
        )
        .await;
        use sha2::Digest;
        let want = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&pushed)));
        assert_eq!(
            head.headers()
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            want
        );
    }

    /// Row 1, failed reads: with a proxied copy beside a push, a storage error reading the push
    /// record or the pushed manifest is a 500 — never the proxied copy.
    #[tokio::test]
    async fn row1_a_failed_read_of_the_push_is_a_500_not_the_proxied_copy() {
        use std::sync::Arc;
        for failing in [
            "docker/corp/app/manifests/1.0.meta.json",
            "docker/corp/app/manifests/1.0.json",
        ] {
            let (_server, ctx, ns) = table_context().await;
            table_push(&ctx).await;
            ctx.state
                .storage
                .put(
                    &super::manifest_key(Some(&ns), "corp/app", "1.0"),
                    &table_manifest(UPSTREAM_CFG),
                )
                .await
                .unwrap();
            let mut flaky = ctx.state.clone();
            flaky.storage = crate::storage::Storage::from_backend(Arc::new(FailingPrefixBackend {
                inner: crate::storage::LocalStorage::new(ctx._tempdir.path().to_str().unwrap()),
                fail_prefix: failing.to_string(),
            }));
            let resp = get_manifest_via_dispatch(&flaky, "corp/app/manifests/1.0").await;
            assert_eq!(
                resp.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "{failing} unreadable"
            );
        }
    }

    /// Row 5.3: a delete of a pushed tag whose push record cannot be read answers 500 and removes
    /// nothing — the tag, its metadata and the pushed manifest under its digest stay, as a pull of
    /// the tag answers 500. Control: with the record readable the same delete answers 202.
    #[tokio::test]
    async fn row5_a_delete_that_cannot_read_the_push_record_removes_nothing() {
        use sha2::Digest;
        use std::sync::Arc;
        for failing in [true, false] {
            let (_server, ctx, ns) = table_context().await;
            let pushed = table_push(&ctx).await;
            let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&pushed)));
            let mut state = ctx.state.clone();
            if failing {
                state.storage =
                    crate::storage::Storage::from_backend(Arc::new(FailingPrefixBackend {
                        inner: crate::storage::LocalStorage::new(
                            ctx._tempdir.path().to_str().unwrap(),
                        ),
                        fail_prefix: "docker/corp/app/manifests/1.0.meta.json".to_string(),
                    }));
            }
            let resp = {
                use axum::extract::{Path, State};
                use axum::http::Uri;
                use axum::Extension;
                super::docker_v2_dispatch(
                    State(state),
                    Method::DELETE,
                    Path("corp/app/manifests/1.0".to_string()),
                    Extension(crate::auth::NamespaceAuthority::Unrestricted),
                    "/v2/corp/app/manifests/1.0".parse::<Uri>().unwrap(),
                    axum::http::HeaderMap::new(),
                    Body::empty(),
                )
                .await
            };
            let kept = [
                super::manifest_key(None, "corp/app", "1.0"),
                super::manifest_meta_key(None, "corp/app", "1.0"),
                super::manifest_key(None, "corp/app", &digest),
            ];
            if failing {
                assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
                for key in &kept {
                    assert!(ctx.state.storage.stat(key).await.is_some(), "{key} removed");
                }
            } else {
                assert_eq!(resp.status(), StatusCode::ACCEPTED);
                for key in &kept {
                    assert!(ctx.state.storage.stat(key).await.is_none(), "{key} left");
                }
            }
            let _ = ns;
        }
    }

    /// Row 5.4: a delete by digest whose tags cannot all be read (here the push record of the tag
    /// that answers with it) answers 500 and removes nothing; with the record readable it removes
    /// the tag with the manifest (#658).
    #[tokio::test]
    async fn row5_a_delete_by_digest_that_cannot_read_a_tag_removes_nothing() {
        use sha2::Digest;
        use std::sync::Arc;
        // The tag's push record unreadable, the bare listing unreadable, the namespaced listing
        // unreadable, nothing failing.
        for case in 0..4 {
            let (_server, ctx, ns) = table_context().await;
            let fail_prefix = match case {
                0 => Some("docker/corp/app/manifests/1.0.meta.json".to_string()),
                1 => Some("docker/corp/app/manifests/".to_string()),
                2 => Some(format!("docker/{ns}/corp/app/manifests/")),
                _ => None,
            };
            let failing = fail_prefix.is_some();
            let pushed = table_push(&ctx).await;
            let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&pushed)));
            let mut state = ctx.state.clone();
            if let Some(fail_prefix) = fail_prefix {
                state.storage =
                    crate::storage::Storage::from_backend(Arc::new(FailingPrefixBackend {
                        inner: crate::storage::LocalStorage::new(
                            ctx._tempdir.path().to_str().unwrap(),
                        ),
                        fail_prefix,
                    }));
            }
            let path = format!("corp/app/manifests/{digest}");
            let resp = {
                use axum::extract::{Path, State};
                use axum::http::Uri;
                use axum::Extension;
                super::docker_v2_dispatch(
                    State(state),
                    Method::DELETE,
                    Path(path.clone()),
                    Extension(crate::auth::NamespaceAuthority::Unrestricted),
                    format!("/v2/{path}").parse::<Uri>().unwrap(),
                    axum::http::HeaderMap::new(),
                    Body::empty(),
                )
                .await
            };
            let tag = super::manifest_key(None, "corp/app", "1.0");
            let by_digest = super::manifest_key(None, "corp/app", &digest);
            if failing {
                assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
                assert!(ctx.state.storage.stat(&tag).await.is_some());
                assert!(ctx.state.storage.stat(&by_digest).await.is_some());
            } else {
                assert_eq!(resp.status(), StatusCode::ACCEPTED);
                assert!(ctx.state.storage.stat(&tag).await.is_none());
                assert!(ctx.state.storage.stat(&by_digest).await.is_none());
            }
        }
    }

    /// A push by digest with other bytes is refused also where an upstream is configured (the
    /// name then has an upstream namespace).
    #[tokio::test]
    async fn a_push_by_digest_with_other_bytes_is_refused_beside_an_upstream() {
        use sha2::Digest;
        let (_server, ctx, ns) = table_context().await;
        seed_zero_config(&ctx.state, "corp/app").await;
        let pushed = table_manifest(PUSHED_CFG);
        let other = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(table_manifest(UPSTREAM_CFG)))
        );
        let resp = send(
            &ctx.app,
            Method::PUT,
            &format!("/v2/corp/app/manifests/{other}"),
            Body::from(pushed),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        for key in [
            super::manifest_key(None, "corp/app", &other),
            super::manifest_key(Some(&ns), "corp/app", &other),
        ] {
            assert!(
                ctx.state.storage.stat(&key).await.is_none(),
                "{key} written"
            );
        }
    }

    /// Deleting a pushed manifest by its digest takes its tag back to the upstream, also when a
    /// proxied copy of the tag was written after the push: the tag resolves as a read does.
    #[tokio::test]
    async fn a_delete_by_digest_of_a_push_gives_the_tag_back_to_the_upstream() {
        use sha2::Digest;
        let (_server, ctx, ns) = table_context().await;
        let pushed = table_push(&ctx).await;
        ctx.state
            .storage
            .put(
                &super::manifest_key(Some(&ns), "corp/app", "1.0"),
                &table_manifest(UPSTREAM_CFG),
            )
            .await
            .unwrap();
        assert_eq!(table_get(&ctx).await, pushed);
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&pushed)));
        let resp = send(
            &ctx.app,
            Method::DELETE,
            &format!("/v2/corp/app/manifests/{digest}"),
            Body::empty(),
        )
        .await;
        assert!(resp.status().is_success(), "{}", resp.status());
        assert_eq!(table_get(&ctx).await, table_manifest(UPSTREAM_CFG));
        assert!(ctx
            .state
            .storage
            .stat(&super::manifest_key(None, "corp/app", "1.0"))
            .await
            .is_none());
    }

    /// Row 3: a bare manifest without the push record (pushed before 1.4.0, or a flat proxy
    /// cache before #349) beside a proxied copy keeps today's answer: the proxied copy.
    #[tokio::test]
    async fn row3_a_bare_manifest_without_a_record_keeps_todays_answer() {
        let (_server, ctx, ns) = table_context().await;
        let old = table_manifest(PUSHED_CFG);
        ctx.state
            .storage
            .put("docker/corp/app/manifests/1.0.json", &old)
            .await
            .unwrap();
        let meta = serde_json::to_vec(&super::ImageMetadata::default()).unwrap();
        ctx.state
            .storage
            .put("docker/corp/app/manifests/1.0.meta.json", &meta)
            .await
            .unwrap();
        let proxied = super::manifest_key(Some(&ns), "corp/app", "1.0");
        ctx.state
            .storage
            .put(&proxied, &table_manifest(UPSTREAM_CFG))
            .await
            .unwrap();
        assert_eq!(table_get(&ctx).await, table_manifest(UPSTREAM_CFG));
    }

    /// Row 1a: a bare manifest other than the bytes its push record names is a re-push in progress
    /// (the bare key is written only by a push): the tag is still the push's, and those bytes answer
    /// it — never the proxied copy beside it.
    #[tokio::test]
    async fn row1a_a_record_for_other_bytes_still_answers_with_the_bare_manifest() {
        let (_server, ctx, ns) = table_context().await;
        table_push(&ctx).await;
        ctx.state
            .storage
            .put(
                "docker/corp/app/manifests/1.0.json",
                &table_manifest(UPSTREAM_CFG.replace('1', "2").as_str()),
            )
            .await
            .unwrap();
        let proxied = super::manifest_key(Some(&ns), "corp/app", "1.0");
        ctx.state
            .storage
            .put(&proxied, &table_manifest(UPSTREAM_CFG))
            .await
            .unwrap();
        assert_eq!(
            table_get(&ctx).await,
            table_manifest(UPSTREAM_CFG.replace('1', "2").as_str())
        );
    }

    /// A deleted push gives the tag back to the upstream.
    #[tokio::test]
    async fn a_deleted_push_gives_the_tag_back_to_the_upstream() {
        let (_server, ctx, _ns) = table_context().await;
        table_push(&ctx).await;
        let del = send(
            &ctx.app,
            Method::DELETE,
            "/v2/corp/app/manifests/1.0",
            Body::empty(),
        )
        .await;
        assert!(del.status().is_success(), "{}", del.status());
        assert_eq!(table_get(&ctx).await, table_manifest(UPSTREAM_CFG));
    }

    /// A pull of a locally pushed image counts against that image. With an upstream configured
    /// every name resolves to the upstream's namespace, but a hosted manifest is served from its
    /// bare key, and its pull statistics go to the pushed manifest's own metadata — by tag and
    /// by digest — with nothing written under the namespace.
    #[tokio::test]
    async fn a_hosted_pull_counts_against_the_pushed_image() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: "http://127.0.0.1:1".into(),
                auth: None,
                namespace: Some("docker.io".into()),
                prefix: None,
            }];
        });
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
        let digest = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(&manifest_bytes))
        );
        seed_zero_config(&ctx.state, "hosted-img").await;
        let put = send(
            &ctx.app,
            Method::PUT,
            "/v2/hosted-img/manifests/v1",
            Body::from(manifest_bytes),
        )
        .await;
        assert_eq!(put.status(), StatusCode::CREATED);
        let pushed_at = |state: crate::AppState| async move {
            super::extract_docker_publish_date(
                &state.storage,
                "hosted-img",
                "v1",
                false,
                Some("docker.io"),
                &mut super::BareMeta::Unread,
            )
            .await
        };
        let date = pushed_at(ctx.state.clone()).await;
        assert!(date.is_some(), "a pushed image has a publish date");

        for uri in [
            "/v2/hosted-img/manifests/v1".to_string(),
            "/v2/hosted-img/manifests/v1".to_string(),
            format!("/v2/hosted-img/manifests/{digest}"),
        ] {
            let resp = send(&ctx.app, Method::GET, &uri, Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        }

        // #1114: pull stats live in the in-memory accumulator (flushed to a
        // .stats.json sidecar), read via current_pull_stats. record() runs
        // synchronously on the GET path, so the counts are already visible.
        let downloads = |key: String| {
            let state = ctx.state.clone();
            async move { Some(super::current_pull_stats(&state, &key).await.downloads) }
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let by_tag = downloads("docker/hosted-img/manifests/v1.meta.json".into()).await;
            let by_digest =
                downloads(format!("docker/hosted-img/manifests/{digest}.meta.json")).await;
            if by_tag == Some(2) && by_digest == Some(1) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "pushed image's own metadata: by tag {by_tag:?}, by digest {by_digest:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let elsewhere = ctx.state.storage.list("docker/docker.io/").await.unwrap();
        assert!(
            elsewhere.is_empty(),
            "written under the namespace: {elsewhere:?}"
        );
        // Curation still reads the push date after the pulls.
        assert_eq!(pushed_at(ctx.state.clone()).await, date);
    }

    /// #1114: a manifest pull must NOT rewrite its `.meta.json`. Pull statistics
    /// (downloads, last_pulled) are accumulated off the request path and flushed in
    /// batches to a separate sidecar, so the integrity-relevant `.meta.json` that a
    /// concurrent request reads (`extract_docker_publish_date`) is never rewritten by
    /// a pull — the source of the false INTEGRITY VIOLATION on healthy data (33-41
    /// per 100 GETs on 1.3.5). RED before V3: `update_metadata_on_pull` rewrites the
    /// `.meta.json` on every GET (downloads += 1, last_pulled = now).
    #[tokio::test]
    async fn a_pull_does_not_rewrite_the_manifest_meta_json() {
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
        seed_zero_config(&ctx.state, "stable-img").await;
        let put = send(
            &ctx.app,
            Method::PUT,
            "/v2/stable-img/manifests/v1",
            Body::from(manifest_bytes),
        )
        .await;
        assert_eq!(put.status(), StatusCode::CREATED);

        let meta_key = "docker/stable-img/manifests/v1.meta.json";
        let before = ctx
            .state
            .storage
            .get(meta_key)
            .await
            .expect("meta written at push");

        for _ in 0..5 {
            let resp = send(
                &ctx.app,
                Method::GET,
                "/v2/stable-img/manifests/v1",
                Body::empty(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        // Give any off-request-path stats work time to land before asserting.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let after = ctx
            .state
            .storage
            .get(meta_key)
            .await
            .expect("meta still present");
        assert_eq!(
            before, after,
            "a pull rewrote the manifest .meta.json (stats must go to the off-path sidecar, not the integrity meta)"
        );
    }

    /// #1114: the same holds under the real trigger — a herd of parallel pulls
    /// of one manifest (the docker proxy's thundering herd). On 1.3.5 each pull's
    /// off-path stats write raced the others and the request-path publish-date read,
    /// logging INTEGRITY VIOLATION on healthy data (19 even from one client pulling
    /// back-to-back). A batched off-path sidecar leaves `.meta.json` byte-identical
    /// no matter how many concurrent pulls land.
    #[tokio::test]
    async fn concurrent_pulls_do_not_rewrite_the_manifest_meta_json() {
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
        seed_zero_config(&ctx.state, "herd-img").await;
        let put = send(
            &ctx.app,
            Method::PUT,
            "/v2/herd-img/manifests/v1",
            Body::from(manifest_bytes),
        )
        .await;
        assert_eq!(put.status(), StatusCode::CREATED);

        let meta_key = "docker/herd-img/manifests/v1.meta.json";
        let before = ctx
            .state
            .storage
            .get(meta_key)
            .await
            .expect("meta written at push");

        let mut handles = Vec::new();
        for _ in 0..12 {
            let app = ctx.app.clone();
            handles.push(tokio::spawn(async move {
                send(
                    &app,
                    Method::GET,
                    "/v2/herd-img/manifests/v1",
                    Body::empty(),
                )
                .await
                .status()
            }));
        }
        for h in handles {
            assert_eq!(h.await.unwrap(), StatusCode::OK);
        }
        // Let any off-request-path stats work settle before asserting.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let after = ctx
            .state
            .storage
            .get(meta_key)
            .await
            .expect("meta still present");
        assert_eq!(
            before, after,
            "concurrent pulls rewrote the manifest .meta.json"
        );
    }

    /// #1114 unit: the pull-stats accumulator counts, peeks the un-flushed
    /// delta, keeps last_pulled as the max seen, and drains to empty.
    #[test]
    fn pull_stats_accumulator_counts_peeks_and_drains() {
        let acc = super::PullStatsAccumulator::default();
        acc.record("k1", 100);
        acc.record("k1", 200);
        acc.record("k2", 150);
        assert_eq!(
            acc.peek("k1"),
            super::PullDelta {
                downloads: 2,
                last_pulled: 200
            }
        );
        assert_eq!(
            acc.peek("k2"),
            super::PullDelta {
                downloads: 1,
                last_pulled: 150
            }
        );
        assert_eq!(acc.peek("absent"), super::PullDelta::default());

        let mut drained = acc.drain();
        drained.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            drained,
            vec![
                (
                    "k1".to_string(),
                    super::PullDelta {
                        downloads: 2,
                        last_pulled: 200
                    }
                ),
                (
                    "k2".to_string(),
                    super::PullDelta {
                        downloads: 1,
                        last_pulled: 150
                    }
                ),
            ]
        );
        assert_eq!(acc.peek("k1"), super::PullDelta::default());
        assert!(acc.drain().is_empty());

        // last_pulled is the max seen, never regressed by a later-but-smaller now.
        acc.record("k1", 50);
        acc.record("k1", 40);
        assert_eq!(
            acc.peek("k1"),
            super::PullDelta {
                downloads: 2,
                last_pulled: 50
            }
        );
    }

    /// Minimal hosted manifest for the flush tests: push `stable-img:v1`, return
    /// its meta key. Mirrors the push the other V3 tests use.
    async fn push_stable_img(ctx: &crate::test_helpers::TestContext) -> &'static str {
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
        seed_zero_config(&ctx.state, "stable-img").await;
        let put = send(
            &ctx.app,
            Method::PUT,
            "/v2/stable-img/manifests/v1",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;
        assert_eq!(put.status(), StatusCode::CREATED);
        "docker/stable-img/manifests/v1.meta.json"
    }

    /// #1114 (M5): the flush LOOP persists on an interval tick, not only on
    /// shutdown. Without the tick flush a crash loses every count since start,
    /// not "at most one interval" as the soft-state contract promises. A short
    /// interval drives a real tick; the assert is taken before any cancellation,
    /// so a loop that flushes only on shutdown fails it.
    #[tokio::test]
    async fn a_flush_loop_tick_persists_the_sidecar_before_shutdown() {
        let ctx = create_test_context();
        let meta_key = push_stable_img(&ctx).await;
        ctx.state.pull_stats.record(meta_key, 100);
        let handle = tokio::spawn(super::pull_stats_flush_loop(
            ctx.state.clone(),
            std::time::Duration::from_millis(10),
        ));
        let stats_key = "docker/stable-img/manifests/v1.stats.json";
        let mut persisted = false;
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if ctx.state.storage.get(stats_key).await.is_ok() {
                persisted = true;
                break;
            }
        }
        ctx.state.cancel_token.cancel();
        let _ = handle.await;
        assert!(
            persisted,
            "a tick must flush the sidecar before any shutdown (the loss bound depends on it)"
        );
    }

    /// #1114 positive control: a flush actually PERSISTS the stats to the
    /// `.stats.json` sidecar for a live manifest (the guard must find the
    /// manifest at `…/v1.json`, not `…/v1`). This is the control that was
    /// missing — without it the flush guard was vacuous and the stats were
    /// silently dropped. RED if the flush never writes the sidecar.
    #[tokio::test]
    async fn a_flush_persists_the_pull_stats_sidecar() {
        let ctx = create_test_context();
        let meta_key = push_stable_img(&ctx).await;
        let stats_key = "docker/stable-img/manifests/v1.stats.json";

        for _ in 0..3 {
            let r = send(
                &ctx.app,
                Method::GET,
                "/v2/stable-img/manifests/v1",
                Body::empty(),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        // Batched: nothing in the sidecar until a flush runs.
        assert!(
            ctx.state.storage.get(stats_key).await.is_err(),
            "sidecar must not exist before a flush"
        );

        super::flush_pull_stats(&ctx.state).await;

        let raw = ctx
            .state
            .storage
            .get(stats_key)
            .await
            .expect("flush must persist the .stats.json sidecar");
        let sidecar: super::StatsSidecar = serde_json::from_slice(&raw).unwrap();
        assert_eq!(sidecar.downloads, 3, "three pulls persisted");
        assert!(sidecar.last_pulled > 0, "last_pulled persisted");
        // current_pull_stats equals the flushed value (accumulator drained).
        assert_eq!(
            super::current_pull_stats(&ctx.state, meta_key)
                .await
                .downloads,
            3
        );
    }

    /// (M8, M12): the read path SUMS the flushed count and the pending delta;
    /// a later flush ADVANCES last_pulled past the flushed value.
    #[tokio::test]
    async fn read_sums_pending_and_flush_advances_last_pulled() {
        let ctx = create_test_context();
        let meta_key = push_stable_img(&ctx).await;
        ctx.state.pull_stats.record(meta_key, 100);
        ctx.state.pull_stats.record(meta_key, 100);
        super::flush_pull_stats(&ctx.state).await;
        ctx.state.pull_stats.record(meta_key, 200);
        assert_eq!(
            super::current_pull_stats(&ctx.state, meta_key)
                .await
                .downloads,
            3
        );
        super::flush_pull_stats(&ctx.state).await;
        let raw = ctx
            .state
            .storage
            .get("docker/stable-img/manifests/v1.stats.json")
            .await
            .unwrap();
        let s: super::StatsSidecar = serde_json::from_slice(&raw).unwrap();
        assert_eq!((s.downloads, s.last_pulled), (3, 200));
    }

    /// #1114: legacy counts in a pre-V3 `.meta.json` are migrated into the
    /// sidecar on the first flush — not lost, and not re-migrated (doubled) on
    /// later flushes (the sidecar becomes authoritative once written).
    #[tokio::test]
    async fn flush_migrates_legacy_meta_counts_once() {
        let ctx = create_test_context();
        let meta_key = push_stable_img(&ctx).await;
        let stats_key = "docker/stable-img/manifests/v1.stats.json";

        // Seed a pre-V3 .meta.json carrying 5 downloads.
        let mut m: super::ImageMetadata =
            serde_json::from_slice(&ctx.state.storage.get(meta_key).await.unwrap()).unwrap();
        m.downloads = 5;
        m.last_pulled = 1_000;
        ctx.state
            .storage
            .put(meta_key, &serde_json::to_vec(&m).unwrap())
            .await
            .unwrap();

        let pull = || async {
            let r = send(
                &ctx.app,
                Method::GET,
                "/v2/stable-img/manifests/v1",
                Body::empty(),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK);
        };

        pull().await;
        super::flush_pull_stats(&ctx.state).await;
        let read = |k: &'static str| {
            let st = ctx.state.storage.clone();
            async move {
                serde_json::from_slice::<super::StatsSidecar>(&st.get(k).await.unwrap()).unwrap()
            }
        };
        assert_eq!(
            read(stats_key).await.downloads,
            6,
            "legacy 5 migrated + 1 new, not lost"
        );

        pull().await;
        super::flush_pull_stats(&ctx.state).await;
        assert_eq!(
            read(stats_key).await.downloads,
            7,
            "second flush adds 1 to the sidecar, does not re-migrate the legacy 5"
        );
    }

    /// A pull leaves the push date curation reads where it was, even when the
    /// pull comes long after the push (the date is seeded in the past, so a pull that
    /// rewrote it cannot match by landing in the same second).
    #[tokio::test]
    async fn a_later_pull_keeps_the_push_date() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: "http://127.0.0.1:1".into(),
                auth: None,
                namespace: Some("docker.io".into()),
                prefix: None,
            }];
        });
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
        seed_zero_config(&ctx.state, "aged-img").await;
        let put = send(
            &ctx.app,
            Method::PUT,
            "/v2/aged-img/manifests/v1",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;
        assert_eq!(put.status(), StatusCode::CREATED);
        let meta_key = "docker/aged-img/manifests/v1.meta.json";
        let mut meta: super::ImageMetadata =
            serde_json::from_slice(&ctx.state.storage.get(meta_key).await.unwrap()).unwrap();
        meta.push_timestamp = 1_000_000;
        ctx.state
            .storage
            .put(meta_key, &serde_json::to_vec(&meta).unwrap())
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/aged-img/manifests/v1",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let downloads = Some(
                super::current_pull_stats(&ctx.state, meta_key)
                    .await
                    .downloads,
            );
            if downloads == Some(1) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "downloads {downloads:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let date = super::extract_docker_publish_date(
            &ctx.state.storage,
            "aged-img",
            "v1",
            false,
            Some("docker.io"),
            &mut super::BareMeta::Unread,
        )
        .await;
        assert_eq!(date, Some(1_000_000));
    }

    /// Control for the test above: a proxied copy, served from its namespaced key, keeps
    /// counting against that copy's metadata, not against a bare (hosted) key.
    #[tokio::test]
    async fn a_proxied_pull_counts_against_the_proxied_copy() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: "http://127.0.0.1:1".into(),
                auth: None,
                namespace: Some("docker.io".into()),
                prefix: None,
            }];
        });
        let manifest = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa"},"layers":[]}"#;
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(manifest)));
        let key = super::manifest_key(Some("docker.io"), "library/proxied", &digest);
        ctx.state.storage.put(&key, manifest).await.unwrap();

        let uri = format!("/v2/library/proxied/manifests/{digest}");
        for _ in 0..2 {
            let resp = send(&ctx.app, Method::GET, &uri, Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let meta_key = super::manifest_meta_key(Some("docker.io"), "library/proxied", &digest);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let downloads = Some(
                super::current_pull_stats(&ctx.state, &meta_key)
                    .await
                    .downloads,
            );
            if downloads == Some(2) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "proxied copy's metadata: {downloads:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let bare = super::manifest_meta_key(None, "library/proxied", &digest);
        assert!(ctx.state.storage.stat(&bare).await.is_none(), "{bare}");
    }

    /// Provenance invariant that #868's hosted/proxied inference depends on: a local push
    /// writes the BARE manifest key (`docker/{name}/manifests/{ref}.json`, no namespace
    /// segment). `get_manifest` reads a bare-key hit as a hosted (locally pushed) manifest —
    /// served authoritatively, no upstream revalidation. If `put_manifest` ever wrote a
    /// namespaced key, hosted and proxied manifests would become indistinguishable and a
    /// proxied tag could be served stale forever — so this must fail loudly.
    #[tokio::test]
    async fn test_local_push_writes_bare_manifest_key() {
        let ctx = create_test_context();
        seed_zero_config(&ctx.state, "prov-img").await;

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
            "/v2/prov-img/manifests/v1",
            Body::from(manifest_bytes),
        )
        .await;
        assert_eq!(put_resp.status(), StatusCode::CREATED);

        // The bare tag key — what get_manifest treats as the hosted/legacy key — is populated.
        assert!(
            ctx.state
                .storage
                .get("docker/prov-img/manifests/v1.json")
                .await
                .is_ok(),
            "local push must write the bare manifest key (hosted provenance)"
        );
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

    /// A pull's statistics land in a `.stats.json` sidecar beside the tag's manifest (#1114).
    /// After the flush, tags/list and the UI must still show only the real tag — the sidecar is
    /// not a tag — and the pull count must still be read from it.
    #[tokio::test]
    async fn tags_list_hides_the_pull_stats_sidecar() {
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
        let put = send(
            &ctx.app,
            Method::PUT,
            "/v2/alpine/manifests/1.0.0",
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;
        assert_eq!(put.status(), StatusCode::CREATED);
        let pull = send(
            &ctx.app,
            Method::GET,
            "/v2/alpine/manifests/1.0.0",
            Body::empty(),
        )
        .await;
        assert_eq!(pull.status(), StatusCode::OK);
        super::flush_pull_stats(&ctx.state).await;
        let stats_key = "docker/alpine/manifests/1.0.0.stats.json";
        assert!(
            ctx.state.storage.stat(stats_key).await.is_some(),
            "control: the flush wrote the pull-stats sidecar"
        );

        let resp = send(&ctx.app, Method::GET, "/v2/alpine/tags/list", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(json["tags"], serde_json::json!(["1.0.0"]), "{json}");

        let detail = crate::ui::api::get_docker_detail(&ctx.state, "alpine").await;
        let names: Vec<_> = detail.tags.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["1.0.0"]);
        assert_eq!(detail.tags[0].downloads, 1, "the pull count is kept");
    }

    /// #932: tags/list must not include digest references (sha256:…).
    /// put_manifest stores both {tag}.json and {digest}.json — only tags
    /// belong in the OCI tags API response.
    #[tokio::test]
    async fn test_list_tags_excludes_digests() {
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
        seed_zero_config(&ctx.state, "nginx").await;
        // Push two tags — each also stores a digest copy
        for tag in ["stable", "mainline"] {
            send(
                &ctx.app,
                Method::PUT,
                &format!("/v2/nginx/manifests/{}", tag),
                Body::from(serde_json::to_vec(&manifest).unwrap()),
            )
            .await;
        }

        let resp = send(&ctx.app, Method::GET, "/v2/nginx/tags/list", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let tags = json["tags"].as_array().unwrap();
        // Must contain the real tags
        assert!(
            tags.iter().any(|t| t.as_str() == Some("stable")),
            "{tags:?}"
        );
        assert!(
            tags.iter().any(|t| t.as_str() == Some("mainline")),
            "{tags:?}"
        );
        // Must NOT contain any digest reference
        for tag in tags {
            let t = tag.as_str().unwrap_or("");
            assert!(
                !t.starts_with("sha256:") && !t.starts_with("sha512:"),
                "digest leaked into tags list: {}",
                t
            );
        }
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

    /// A delete removes the manifest on every backend. An object store answers a delete of an
    /// absent key with success, so a delete that falls back to the second copy only on "not
    /// found" never reaches it there: with the default upstream a pushed name gets a namespace,
    /// the push writes the bare key, and the delete removed the namespaced one (absent) only.
    #[tokio::test]
    async fn a_deleted_manifest_is_gone_on_local_and_object_storage() {
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
        for object in [false, true] {
            // The binary's default upstream, which the test context leaves out: with it a name
            // without a prefix gets the upstream's namespace, and the delete has two keys.
            let default_upstream = |cfg: &mut crate::config::Config| {
                cfg.docker.upstreams = crate::config::DockerConfig::default().upstreams
            };
            let ctx = if object {
                crate::test_helpers::create_test_context_with_storage_and_config(
                    crate::storage::Storage::from_backend(std::sync::Arc::new(
                        crate::storage::ObjectStorage::in_memory(),
                    )),
                    default_upstream,
                )
            } else {
                crate::test_helpers::create_test_context_with_config(default_upstream)
            };
            seed_zero_config(&ctx.state, "rc/app").await;
            for (tag, by) in [("v1", "digest"), ("v2", "tag")] {
                let body = serde_json::to_vec(&serde_json::json!({
                    "schemaVersion": 2,
                    "mediaType": manifest["mediaType"],
                    "config": manifest["config"],
                    "layers": [],
                    "annotations": { "tag": tag },
                }))
                .unwrap();
                let put = send(
                    &ctx.app,
                    Method::PUT,
                    &format!("/v2/rc/app/manifests/{tag}"),
                    Body::from(body),
                )
                .await;
                assert_eq!(put.status(), StatusCode::CREATED, "object={object} {tag}");
                let digest = put.headers()["docker-content-digest"]
                    .to_str()
                    .unwrap()
                    .to_string();
                let target = if by == "digest" {
                    digest.clone()
                } else {
                    tag.to_string()
                };
                let del = send(
                    &ctx.app,
                    Method::DELETE,
                    &format!("/v2/rc/app/manifests/{target}"),
                    Body::empty(),
                )
                .await;
                assert_eq!(
                    del.status(),
                    StatusCode::ACCEPTED,
                    "object={object} by {by}"
                );
                for reference in [digest.as_str(), tag] {
                    let get = send(
                        &ctx.app,
                        Method::GET,
                        &format!("/v2/rc/app/manifests/{reference}"),
                        Body::empty(),
                    )
                    .await;
                    assert_eq!(
                        get.status(),
                        StatusCode::NOT_FOUND,
                        "object={object}: {reference} still served after a delete by {by}"
                    );
                }
            }
        }
    }

    /// A delete by digest removes the namespaced copy and a pre-migration bare copy alike: a read
    /// falls back to the bare copy, so leaving it kept the manifest served (local and object).
    #[tokio::test]
    async fn a_delete_removes_both_copies_of_a_manifest() {
        let body = b"{\"schemaVersion\":2}".to_vec();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&body)));
        for object in [false, true] {
            let default_upstream = |cfg: &mut crate::config::Config| {
                cfg.docker.upstreams = crate::config::DockerConfig::default().upstreams
            };
            let ctx = if object {
                crate::test_helpers::create_test_context_with_storage_and_config(
                    crate::storage::Storage::from_backend(std::sync::Arc::new(
                        crate::storage::ObjectStorage::in_memory(),
                    )),
                    default_upstream,
                )
            } else {
                crate::test_helpers::create_test_context_with_config(default_upstream)
            };
            let c = super::canonicalize("rc/two", &ctx.state.config.docker);
            assert!(
                c.namespace.is_some(),
                "the default upstream gives the name a namespace"
            );
            for key in [
                super::manifest_key(c.namespace.as_deref(), &c.name, &digest),
                super::manifest_key(None, &c.name, &digest),
            ] {
                ctx.state.storage.put(&key, &body).await.unwrap();
            }
            let del = send(
                &ctx.app,
                Method::DELETE,
                &format!("/v2/rc/two/manifests/{digest}"),
                Body::empty(),
            )
            .await;
            assert_eq!(del.status(), StatusCode::ACCEPTED, "object={object}");
            let get = send(
                &ctx.app,
                Method::GET,
                &format!("/v2/rc/two/manifests/{digest}"),
                Body::empty(),
            )
            .await;
            assert_eq!(
                get.status(),
                StatusCode::NOT_FOUND,
                "object={object}: a copy is still served"
            );
        }
    }

    /// A tag named like another tag's sidecar (`v1.meta`, `v1.stats`) is refused on every manifest
    /// route: its key is that sidecar's key, so a push would overwrite `v1`'s metadata, a delete
    /// would remove it, and a read would serve it as a manifest.
    #[tokio::test]
    async fn a_tag_named_like_a_sidecar_cannot_reach_another_tags_metadata() {
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
        seed_zero_config(&ctx.state, "app").await;
        let body = serde_json::to_vec(&manifest).unwrap();
        let put = send(
            &ctx.app,
            Method::PUT,
            "/v2/app/manifests/v1",
            Body::from(body.clone()),
        )
        .await;
        assert_eq!(put.status(), StatusCode::CREATED);
        let meta_key = super::manifest_meta_key(None, "app", "v1");
        let meta_before = ctx.state.storage.get(&meta_key).await.unwrap();
        for tag in ["v1.meta", "v1.stats"] {
            let put = send(
                &ctx.app,
                Method::PUT,
                &format!("/v2/app/manifests/{tag}"),
                Body::from(body.clone()),
            )
            .await;
            assert_eq!(put.status(), StatusCode::BAD_REQUEST, "PUT {tag}");
            let get = send(
                &ctx.app,
                Method::GET,
                &format!("/v2/app/manifests/{tag}"),
                Body::empty(),
            )
            .await;
            assert_eq!(get.status(), StatusCode::BAD_REQUEST, "GET {tag}");
            let del = send(
                &ctx.app,
                Method::DELETE,
                &format!("/v2/app/manifests/{tag}"),
                Body::empty(),
            )
            .await;
            assert_eq!(del.status(), StatusCode::BAD_REQUEST, "DELETE {tag}");
        }
        assert_eq!(
            ctx.state.storage.get(&meta_key).await.unwrap(),
            meta_before,
            "v1's metadata changed"
        );
        let get = send(&ctx.app, Method::GET, "/v2/app/manifests/v1", Body::empty()).await;
        assert_eq!(get.status(), StatusCode::OK);
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

    /// #1154: an uploaded blob is pinned to the digest it was checked against, whichever form
    /// the upload took (monolithic PUT, chunked PATCH then PUT, single POST).
    #[tokio::test]
    async fn an_uploaded_blob_is_pinned_to_its_digest() {
        let ctx = create_test_context();
        let session = |ctx: &crate::test_helpers::TestContext| {
            let app = ctx.app.clone();
            async move {
                let resp = send(
                    &app,
                    Method::POST,
                    "/v2/alpine/blobs/uploads/",
                    Body::empty(),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::ACCEPTED);
                let location = resp.headers().get("location").unwrap().to_str().unwrap();
                location.rsplit('/').next().unwrap().to_string()
            }
        };
        let digest_of = |data: &[u8]| hex::encode(sha2::Sha256::digest(data));

        let monolithic = b"pinned monolithic blob";
        let uuid = session(&ctx).await;
        let url = format!(
            "/v2/alpine/blobs/uploads/{uuid}?digest=sha256:{}",
            digest_of(monolithic)
        );
        let resp = send(&ctx.app, Method::PUT, &url, Body::from(&monolithic[..])).await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let chunked = b"pinned chunked blob";
        let uuid = session(&ctx).await;
        let url = format!("/v2/alpine/blobs/uploads/{uuid}");
        let resp = send(&ctx.app, Method::PATCH, &url, Body::from(&chunked[..])).await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let url = format!("{url}?digest=sha256:{}", digest_of(chunked));
        let resp = send(&ctx.app, Method::PUT, &url, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let single = b"pinned single-post blob";
        let url = format!(
            "/v2/alpine/blobs/uploads/?digest=sha256:{}",
            digest_of(single)
        );
        let resp = send(&ctx.app, Method::POST, &url, Body::from(&single[..])).await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        for data in [&monolithic[..], &chunked[..], &single[..]] {
            let hex = digest_of(data);
            let key = format!("docker/alpine/blobs/sha256:{hex}");
            assert_eq!(ctx.state.storage.pin(&key).await, Some(hex), "{key}");
        }
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
    async fn test_docker_cross_repo_blob_mount() {
        let ctx = create_test_context();
        let blob_data = b"cross-repo mounted layer";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

        let resp = send(
            &ctx.app,
            Method::POST,
            &format!("/v2/srcrepo/blobs/uploads/?digest={}", digest),
            Body::from(&blob_data[..]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let mount_url = format!("/v2/dstrepo/blobs/uploads/?mount={}&from=srcrepo", digest);
        let resp = send(&ctx.app, Method::POST, &mount_url, Body::empty()).await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a blob the source repo holds must mount without an upload"
        );
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("/v2/dstrepo/blobs/{}", digest)
        );
        assert_eq!(
            resp.headers()
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            digest
        );

        let get = send(
            &ctx.app,
            Method::GET,
            &format!("/v2/dstrepo/blobs/{}", digest),
            Body::empty(),
        )
        .await;
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(&body_bytes(get).await[..], &blob_data[..]);

        // Already in the destination: answered from the destination copy, so a
        // source that holds nothing still yields 201.
        let resp = send(
            &ctx.app,
            Method::POST,
            &format!("/v2/dstrepo/blobs/uploads/?mount={}&from=otherrepo", digest),
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_docker_mount_unknown_blob_falls_back_to_upload() {
        let ctx = create_test_context();
        let digest = format!("sha256:{}", "b".repeat(64));

        let resp = send(
            &ctx.app,
            Method::POST,
            &format!("/v2/dstrepo/blobs/uploads/?mount={}&from=srcrepo", digest),
            Body::empty(),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "an unmountable blob must degrade to a normal upload session"
        );
        assert!(resp.headers().contains_key("docker-upload-uuid"));
    }

    #[tokio::test]
    async fn test_docker_mount_invalid_source_repo_falls_back_to_upload() {
        let ctx = create_test_context();
        let blob_data = b"blob behind an unusable source name";
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));
        let resp = send(
            &ctx.app,
            Method::POST,
            &format!("/v2/srcrepo/blobs/uploads/?digest={}", digest),
            Body::from(&blob_data[..]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = send(
            &ctx.app,
            Method::POST,
            &format!("/v2/dstrepo/blobs/uploads/?mount={}&from=SRCREPO", digest),
            Body::empty(),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "an invalid source repository must degrade to an upload session, not 4xx"
        );
        assert!(resp.headers().contains_key("docker-upload-uuid"));
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

    // --- #817: blob-upload memory/disk bounds (streaming) ---

    #[tokio::test]
    async fn test_monolithic_upload_over_cap_rejected_fast() {
        // A monolithic PUT whose Content-Length exceeds the effective cap is
        // rejected up front (413), before any body is read.
        let ctx = create_test_context_with_config(|c| c.server.body_limit_mb = 1); // 1 MiB
        let blob = vec![0u8; 2 * 1024 * 1024]; // 2 MiB > cap
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
        let resp = send(
            &ctx.app,
            Method::POST,
            &format!("/v2/alpine/blobs/uploads/?digest={}", digest),
            Body::from(blob),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_monolithic_upload_over_cap_streamed_rejected() {
        // The incremental cap must bound a STREAMING body with no Content-Length
        // — DefaultBodyLimit does not apply to a Body extractor (#817). Without
        // the in-loop guard this would write unbounded bytes to disk.
        let ctx = create_test_context_with_config(|c| c.server.body_limit_mb = 1); // 1 MiB
        let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = (0..4)
            .map(|_| Ok(axum::body::Bytes::from(vec![0u8; 512 * 1024])))
            .collect(); // 2 MiB total, streamed
        let body = Body::from_stream(futures::stream::iter(chunks));
        let digest = format!("sha256:{}", "0".repeat(64)); // irrelevant — rejected before verify
        let resp = send(
            &ctx.app,
            Method::POST,
            &format!("/v2/alpine/blobs/uploads/?digest={}", digest),
            body,
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "streamed body over cap must 413 via the incremental guard, not OOM"
        );
    }

    #[tokio::test]
    async fn test_patch_over_cap_rejected() {
        // Chunked PATCH accumulating past the cap → 413.
        let ctx = create_test_context_with_config(|c| c.server.body_limit_mb = 1); // 1 MiB
        let post = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        assert_eq!(post.status(), StatusCode::ACCEPTED);
        let loc = post
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let uuid = loc.rsplit('/').next().unwrap();
        let big = vec![0u8; 2 * 1024 * 1024]; // 2 MiB > cap
        let resp = send(
            &ctx.app,
            Method::PATCH,
            &format!("/v2/alpine/blobs/uploads/{}", uuid),
            Body::from(big),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_manifest_over_cap_rejected() {
        // Manifests stay bounded: a body over MAX_MANIFEST_BYTES → 413, not OOM
        // (the streaming Body dispatcher bounds the collect explicitly, #817).
        let ctx = create_test_context();
        let huge = vec![b'{'; super::MAX_MANIFEST_BYTES + 1]; // just over 4 MiB
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/v2/alpine/manifests/latest",
            Body::from(huge),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_streaming_upload_multiframe_ok() {
        // A multi-frame streamed blob (no Content-Length) is assembled and
        // digest-verified correctly — the streaming path is not tiny-body-only.
        let ctx = create_test_context();
        let blob = vec![7u8; 1024 * 1024]; // 1 MiB
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
        let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = blob
            .chunks(64 * 1024)
            .map(|c| Ok(axum::body::Bytes::copy_from_slice(c)))
            .collect();
        let body = Body::from_stream(futures::stream::iter(chunks));
        let resp = send(
            &ctx.app,
            Method::POST,
            &format!("/v2/alpine/blobs/uploads/?digest={}", digest),
            body,
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "multi-frame streamed blob must store and verify"
        );
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

        // A client holding the whole blob resumes with `bytes=<size>-`: 416, not a
        // full re-download (#657, matches the reference `distribution` registry).
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri(format!("/v2/rng/blobs/{}", digest))
            .header(header::RANGE, format!("bytes={}-", blob.len()))
            .body(Body::empty())
            .unwrap();
        let resp = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes */{}", blob.len())
        );

        // A malformed range is ignored: full 200 (RFC 9110 §14.2).
        let req = axum::http::Request::builder()
            .method(Method::GET)
            .uri(format!("/v2/rng/blobs/{}", digest))
            .header(header::RANGE, "kilobytes=1-2")
            .body(Body::empty())
            .unwrap();
        let resp = ctx.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
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
            &mut super::BareMeta::Unread,
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
            &mut super::BareMeta::Unread,
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
            &mut super::BareMeta::Unread,
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

        // The headers go out as soon as upstream answers (the digest is only known at
        // the end of the spool), so a mismatch cannot be a 502 any more: the body aborts
        // instead of ending as a clean 200, and the poisoned bytes are never cached.
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
        assert!(
            body.is_err(),
            "a poisoned blob must not stream to a clean end"
        );
        // Poisoned blob must NOT have been cached under the docker blob key
        // (computed via the same canonicalize/blob_key path the handler uses).
        let c = super::canonicalize("library/test", &ctx.state.config.docker);
        let key = super::blob_key(c.namespace.as_deref(), &c.name, &requested_digest);
        // The spool task finishes after the response; give it a moment to clean up.
        let proxy_tmp =
            std::path::Path::new(&ctx.state.config.storage.path).join("tmp/docker-proxy");
        let leftover = || {
            std::fs::read_dir(&proxy_tmp)
                .map(|rd| rd.filter_map(|e| e.ok()).count())
                .unwrap_or(0)
        };
        let started = std::time::Instant::now();
        while leftover() > 0 && started.elapsed() < std::time::Duration::from_secs(5) {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            ctx.state.storage.get(&key).await.is_err(),
            "poisoned blob must not be cached"
        );
        // TempFileGuard must have cleaned up — no leftover proxy temp files.
        assert_eq!(
            leftover(),
            0,
            "temp files must be cleaned up after rejection"
        );
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

        // The verified blob is cached under the docker blob key (computed via the same
        // canonicalize/blob_key path the handler uses) once the detached spool stores it,
        // which completes just after the response body.
        let c = super::canonicalize("library/ok", &ctx.state.config.docker);
        let key = super::blob_key(c.namespace.as_deref(), &c.name, &digest);
        let started = std::time::Instant::now();
        while ctx.state.storage.get(&key).await.is_err()
            && started.elapsed() < std::time::Duration::from_secs(5)
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            ctx.state.storage.get(&key).await.is_ok(),
            "verified blob must be cached"
        );
    }

    /// Storage backend that delegates to local storage but fails `get`/`get_reader`
    /// with a transient (non-`NotFound`) error for keys under a given prefix —
    /// models an object-store blip on the namespaced key while the legacy key
    /// stays readable.
    struct FailingPrefixBackend {
        inner: crate::storage::LocalStorage,
        fail_prefix: String,
    }

    #[async_trait::async_trait]
    impl crate::storage::StorageBackend for FailingPrefixBackend {
        async fn put(
            &self,
            key: &str,
            data: &[u8],
            sha256: &str,
            annotations: &nora_registry::annotations::Annotations,
        ) -> crate::storage::Result<()> {
            self.inner.put(key, data, sha256, annotations).await
        }
        async fn get(
            &self,
            key: &str,
        ) -> crate::storage::Result<(axum::body::Bytes, crate::storage::Recorded)> {
            if key.starts_with(&self.fail_prefix) {
                return Err(crate::storage::StorageError::Network("injected".into()));
            }
            self.inner.get(key).await
        }
        async fn recorded(&self, key: &str) -> crate::storage::Recorded {
            self.inner.recorded(key).await
        }
        async fn delete(&self, key: &str) -> crate::storage::Result<()> {
            self.inner.delete(key).await
        }
        async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
            if prefix.starts_with(&self.fail_prefix) {
                return Err(crate::storage::StorageError::Network("injected".into()));
            }
            self.inner.list(prefix).await
        }
        async fn stat(&self, key: &str) -> Option<crate::storage::FileMeta> {
            self.inner.stat(key).await
        }
        async fn health_check(&self) -> bool {
            true
        }
        async fn total_size(&self) -> u64 {
            self.inner.total_size().await
        }
        fn backend_name(&self) -> &'static str {
            "failing-prefix-test"
        }
        async fn copy(
            &self,
            src: &str,
            dst: &str,
            sha256: Option<&str>,
        ) -> crate::storage::Result<()> {
            self.inner.copy(src, dst, sha256).await
        }
        async fn put_from_path(
            &self,
            key: &str,
            src: &std::path::Path,
            sha256: Option<&str>,
            annotations: &nora_registry::annotations::Annotations,
        ) -> crate::storage::Result<()> {
            self.inner
                .put_from_path(key, src, sha256, annotations)
                .await
        }
        async fn get_reader(
            &self,
            key: &str,
        ) -> crate::storage::Result<(
            u64,
            crate::storage::Recorded,
            std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
        )> {
            if key.starts_with(&self.fail_prefix) {
                return Err(crate::storage::StorageError::Network("injected".into()));
            }
            self.inner.get_reader(key).await
        }
    }

    fn unreachable_upstream() -> crate::config::DockerUpstream {
        crate::config::DockerUpstream {
            // Reserved port on localhost — connect fails fast, no real network.
            url: "http://127.0.0.1:9".to_string(),
            auth: None,
            namespace: None,
            prefix: None,
        }
    }

    async fn get_manifest_via_dispatch(
        state: &crate::AppState,
        path: &str,
    ) -> axum::response::Response {
        use axum::extract::{Path, State};
        use axum::http::Uri;
        use axum::Extension;
        super::docker_v2_dispatch(
            State(state.clone()),
            Method::GET,
            Path(path.to_string()),
            Extension(crate::auth::NamespaceAuthority::Unrestricted),
            format!("/v2/{path}").parse::<Uri>().unwrap(),
            axum::http::HeaderMap::new(),
            Body::empty(),
        )
        .await
    }

    /// A transient storage error on the namespaced manifest key must fail closed
    /// (500) — NOT silently serve the legacy (flat-key) copy. The two keys can
    /// hold different bytes (proxied-current vs pre-migration), so an
    /// error-driven fallback makes tag resolution flip per request with backend
    /// weather. Drives the real `get_manifest` read via `docker_v2_dispatch`.
    #[tokio::test]
    async fn manifest_get_fails_closed_on_transient_storage_error() {
        use std::sync::Arc;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![unreachable_upstream()];
        });

        // Legacy (flat) copy exists and is readable.
        ctx.state
            .storage
            .put("docker/app/manifests/latest.json", b"{\"legacy\":true}")
            .await
            .unwrap();

        // Same files, but the namespaced key errors transiently. Namespace for
        // an http://127.0.0.1:9 upstream is "127.0.0.1".
        let mut flaky = ctx.state.clone();
        flaky.storage = crate::storage::Storage::from_backend(Arc::new(FailingPrefixBackend {
            inner: crate::storage::LocalStorage::new(ctx._tempdir.path().to_str().unwrap()),
            fail_prefix: "docker/127.0.0.1/".to_string(),
        }));

        let resp = get_manifest_via_dispatch(&flaky, "app/manifests/latest").await;
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "transient error on the namespaced key must fail closed, not fall back"
        );
    }

    /// The legacy-key fallback still works for the case it exists for: the
    /// namespaced key is genuinely absent (`NotFound`) and a flat-key hosted
    /// copy exists. Served as locally authoritative — no upstream round trip,
    /// so no `x-nora-stale` even though the configured upstream is unreachable.
    #[tokio::test]
    async fn manifest_get_serves_hosted_legacy_on_ns_not_found() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![unreachable_upstream()];
        });

        ctx.state
            .storage
            .put("docker/app/manifests/latest.json", b"{\"legacy\":true}")
            .await
            .unwrap();

        let resp = get_manifest_via_dispatch(&ctx.state, "app/manifests/latest").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("x-nora-stale").is_none(),
            "hosted copy is authoritative — must not be served via the stale path"
        );
        let body = body_bytes(resp).await;
        assert_eq!(body.as_ref(), b"{\"legacy\":true}");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod index_cost_tests {
    //! Tag and catalog listings must cost the same storage round-trips for 1 and 100 entries.
    use crate::test_helpers::{create_test_context_with_storage, op_counting_storage, send};
    use axum::body::Body;
    use axum::http::{Method, StatusCode};

    async fn tags_list_ops(n: usize) -> (usize, String) {
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        for i in 0..n {
            let key = format!("docker/costimg/manifests/tag-{i}.json");
            ctx.state.storage.put(&key, b"{}").await.unwrap();
        }
        ops.reset();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/costimg/tags/list",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "tags/list with {n} tags");
        (ops.total(), format!("{:?}", ops.snapshot()))
    }

    async fn catalog_ops(n: usize) -> (usize, String) {
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        for i in 0..n {
            let key = format!("docker/costrepo-{i}/manifests/latest.json");
            ctx.state.storage.put(&key, b"{}").await.unwrap();
        }
        ops.reset();
        let resp = send(&ctx.app, Method::GET, "/v2/_catalog", Body::empty()).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "_catalog with {n} repositories"
        );
        (ops.total(), format!("{:?}", ops.snapshot()))
    }

    #[tokio::test]
    async fn docker_tags_list_cost_is_independent_of_tag_count() {
        let (small, small_ops) = tags_list_ops(1).await;
        let (large, large_ops) = tags_list_ops(100).await;
        assert_eq!(
            small, large,
            "tags/list must cost the same storage round-trips for 1 and 100 tags: {small_ops} vs {large_ops}"
        );
    }

    #[tokio::test]
    async fn docker_catalog_cost_is_independent_of_repository_count() {
        let (small, small_ops) = catalog_ops(1).await;
        let (large, large_ops) = catalog_ops(100).await;
        assert_eq!(
            small, large,
            "_catalog must cost the same storage round-trips for 1 and 100 repositories: {small_ops} vs {large_ops}"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod stream_spool_tests {
    //! A proxied blob is served while it is still being spooled from upstream.
    use super::{blob_key, canonicalize};
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
    use axum::body::{Body, Bytes};
    use axum::http::{header, Method, StatusCode};
    use axum::response::Response;
    use axum::Router;
    use futures::StreamExt;
    use sha2::Digest;
    use std::sync::Arc;
    use std::time::Duration;

    /// Upstream that answers its headers at once and trickles the body in `chunks`
    /// pieces `delay` apart, so a test can tell "headers before the body" from
    /// "headers after the whole blob".
    async fn slow_blob_upstream(blob: Vec<u8>, chunks: usize, delay: Duration) -> String {
        slow_blob_upstream_framed(blob, chunks, delay, true).await
    }

    /// `declare_length = false` answers chunked, with no `Content-Length`.
    async fn slow_blob_upstream_framed(
        blob: Vec<u8>,
        chunks: usize,
        delay: Duration,
        declare_length: bool,
    ) -> String {
        use axum::routing::get;
        let blob = Arc::new(blob);
        let app = Router::new().route(
            "/v2/{*rest}",
            get(move || {
                let blob = blob.clone();
                async move {
                    let piece = blob.len().div_ceil(chunks).max(1);
                    let pieces: Vec<Bytes> =
                        blob.chunks(piece).map(Bytes::copy_from_slice).collect();
                    let body = futures::stream::iter(pieces).then(move |p| async move {
                        tokio::time::sleep(delay).await;
                        Ok::<_, std::io::Error>(p)
                    });
                    let mut builder = Response::builder().status(StatusCode::OK);
                    if declare_length {
                        builder = builder.header(header::CONTENT_LENGTH, blob.len());
                    }
                    builder.body(Body::from_stream(body)).unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn slow_upstream_ctx(upstream: String) -> TestContext {
        use crate::config::DockerUpstream;
        create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: upstream,
                auth: None,
                namespace: None,
                prefix: None,
            }];
        })
    }

    async fn wait_until(
        deadline: Duration,
        mut ready: impl FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>,
    ) -> bool {
        let started = std::time::Instant::now();
        while started.elapsed() < deadline {
            if ready().await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    fn proxy_temp_count(ctx: &TestContext) -> usize {
        let proxy_tmp =
            std::path::Path::new(&ctx.state.config.storage.path).join("tmp/docker-proxy");
        std::fs::read_dir(&proxy_tmp)
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0)
    }

    /// A cache miss answers with the upstream headers before the blob is on disk and
    /// streams the body as the spool grows; the blob is cached once the spool ends.
    #[tokio::test]
    async fn test_docker_proxy_blob_streams_while_spooling() {
        let blob: Vec<u8> = (0..(4 * 256 * 1024 + 17))
            .map(|i| (i % 251) as u8)
            .collect();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
        let delay = Duration::from_millis(250);
        let upstream = slow_blob_upstream(blob.clone(), 4, delay).await;
        let ctx = slow_upstream_ctx(upstream);

        let started = std::time::Instant::now();
        let response = send(
            &ctx.app,
            Method::GET,
            &format!("/v2/library/test/blobs/{digest}"),
            Body::empty(),
        )
        .await;
        let headers_after = started.elapsed();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH].to_str().unwrap(),
            blob.len().to_string()
        );
        assert_eq!(response.headers()["docker-content-digest"], digest.as_str());
        // The whole body takes 4 × delay to arrive from upstream; the headers must not.
        assert!(
            headers_after < delay * 2,
            "headers arrived only after {headers_after:?}, i.e. after the spool"
        );

        let body = body_bytes(response).await;
        assert_eq!(body.len(), blob.len());
        assert_eq!(body.as_ref(), &blob[..]);
        assert!(
            started.elapsed() >= delay * 4,
            "the body cannot be complete before upstream sent it"
        );

        let c = canonicalize("library/test", &ctx.state.config.docker);
        let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
        let storage = ctx.state.storage.clone();
        let k = key.clone();
        assert!(
            wait_until(Duration::from_secs(5), move || {
                let storage = storage.clone();
                let k = k.clone();
                Box::pin(async move { storage.get(&k).await.is_ok() })
            })
            .await,
            "blob must be cached after the spool completes"
        );
        assert_eq!(
            ctx.state.storage.get(&key).await.unwrap().as_ref(),
            &blob[..]
        );
        assert_eq!(
            proxy_temp_count(&ctx),
            0,
            "spool file must be gone once stored"
        );
    }

    /// A client that drops the response mid-fill (containerd retrying a slow pull from
    /// scratch) must not discard the fill: the spool keeps going and the blob is cached.
    #[tokio::test]
    async fn test_docker_proxy_blob_fill_survives_client_disconnect() {
        let blob: Vec<u8> = (0..(2 * 256 * 1024 + 5)).map(|i| (i % 253) as u8).collect();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
        let upstream = slow_blob_upstream(blob.clone(), 4, Duration::from_millis(150)).await;
        let ctx = slow_upstream_ctx(upstream);

        let response = send(
            &ctx.app,
            Method::GET,
            &format!("/v2/library/test/blobs/{digest}"),
            Body::empty(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        drop(response);

        let c = canonicalize("library/test", &ctx.state.config.docker);
        let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
        let storage = ctx.state.storage.clone();
        let k = key.clone();
        assert!(
            wait_until(Duration::from_secs(5), move || {
                let storage = storage.clone();
                let k = k.clone();
                Box::pin(async move { storage.get(&k).await.is_ok() })
            })
            .await,
            "the fill must complete without a client"
        );
        assert_eq!(
            ctx.state.storage.get(&key).await.unwrap().as_ref(),
            &blob[..]
        );
        assert_eq!(proxy_temp_count(&ctx), 0);
    }

    /// Over real HTTP framing a poisoned upstream must not yield a complete body: hyper
    /// stops reading a `Content-Length` body once the declared bytes are out, so the last
    /// byte is withheld until the spool has verified the digest.
    #[tokio::test]
    async fn test_docker_proxy_blob_mismatch_aborts_framed_body() {
        let real = b"the real layer bytes".to_vec();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&real)));
        let poisoned = b"poisoned bytes of same len".to_vec();
        assert_ne!(real, poisoned);
        let upstream = slow_blob_upstream(poisoned, 2, Duration::from_millis(50)).await;
        let ctx = slow_upstream_ctx(upstream);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = ctx.app.clone();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let response = reqwest::Client::new()
            .get(format!("http://{addr}/v2/library/test/blobs/{digest}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert!(
            response.bytes().await.is_err(),
            "a poisoned blob must not arrive as a complete body"
        );

        let c = canonicalize("library/test", &ctx.state.config.docker);
        let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
        let started = std::time::Instant::now();
        while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            ctx.state.storage.get(&key).await.is_err(),
            "poisoned blob must not be cached"
        );
        assert_eq!(proxy_temp_count(&ctx), 0);
    }

    async fn follower_over(
        bytes: &[u8],
        status: super::SpoolStatus,
    ) -> (
        std::pin::Pin<Box<dyn futures::Stream<Item = std::io::Result<Bytes>> + Send>>,
        tokio::sync::watch::Sender<super::SpoolStatus>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("spool");
        tokio::fs::write(&path, bytes).await.unwrap();
        let file = tokio::fs::File::open(&path).await.unwrap();
        let (tx, rx) = tokio::sync::watch::channel(status);
        (
            Box::pin(super::spool_follower(file, rx, 0, Duration::from_secs(60))),
            tx,
            dir,
        )
    }

    /// A spool that reports nothing past the stall ceiling fails the read instead of
    /// holding the response forever.
    #[tokio::test]
    async fn spool_follower_fails_past_the_stall_ceiling() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("spool");
        tokio::fs::write(&path, b"abc").await.unwrap();
        let file = tokio::fs::File::open(&path).await.unwrap();
        let (_tx, rx) = tokio::sync::watch::channel(super::SpoolStatus {
            written: 3,
            done: None,
        });
        let mut follower = Box::pin(super::spool_follower(
            file,
            rx,
            0,
            Duration::from_millis(100),
        ));
        // Two bytes are released (one held back), then nothing more ever comes.
        let first = tokio::time::timeout(Duration::from_secs(1), follower.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(first.as_ref(), b"ab");
        let stalled = tokio::time::timeout(Duration::from_secs(2), follower.next())
            .await
            .expect("the ceiling ends the wait")
            .expect("an item, not a clean end");
        assert!(stalled.is_err(), "a silent spool must fail the read");
    }

    /// The follower withholds the last flushed byte until the spool reports a verified
    /// end, so a `Content-Length` body can never complete on unverified bytes.
    #[tokio::test]
    async fn spool_follower_withholds_last_byte_until_done() {
        let data = b"0123456789";
        let pending = super::SpoolStatus {
            written: data.len() as u64,
            done: None,
        };
        let (mut follower, tx, _dir) = follower_over(data, pending).await;

        let first = follower.next().await.unwrap().unwrap();
        assert_eq!(first.as_ref(), &data[..data.len() - 1]);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), follower.next())
                .await
                .is_err(),
            "the last byte must not be released while the spool is unverified"
        );

        tx.send_modify(|s| s.done = Some(Ok(())));
        let last = follower.next().await.unwrap().unwrap();
        assert_eq!(last.as_ref(), &data[data.len() - 1..]);
        assert!(
            follower.next().await.is_none(),
            "EOF after the verified last byte"
        );
    }

    /// A spool that ends in failure turns into a read error before the last byte.
    #[tokio::test]
    async fn spool_follower_errors_on_failed_spool() {
        let data = b"0123456789";
        let pending = super::SpoolStatus {
            written: data.len() as u64,
            done: None,
        };
        let (mut follower, tx, _dir) = follower_over(data, pending).await;
        let first = follower.next().await.unwrap().unwrap();
        assert_eq!(first.len(), data.len() - 1);

        tx.send_modify(|s| s.done = Some(Err("SHA-256 mismatch".to_string())));
        let err = follower.next().await.unwrap().unwrap_err();
        assert!(err.to_string().contains("SHA-256 mismatch"), "{err}");
    }

    /// Bytes flushed between a short read and the status check are picked up without
    /// waiting for a further update.
    #[tokio::test]
    async fn spool_follower_reads_bytes_published_before_it_waited() {
        let data = b"abcdef";
        let empty = super::SpoolStatus {
            written: 0,
            done: None,
        };
        let (mut follower, tx, _dir) = follower_over(data, empty).await;
        let pending = tokio::time::timeout(Duration::from_millis(100), follower.next());
        assert!(
            pending.await.is_err(),
            "nothing is released before any flush"
        );
        tx.send_modify(|s| s.written = data.len() as u64);
        let chunk = tokio::time::timeout(Duration::from_secs(1), follower.next())
            .await
            .expect("published bytes must be delivered")
            .unwrap()
            .unwrap();
        assert_eq!(chunk.as_ref(), &data[..data.len() - 1]);
    }

    async fn serve_ctx(ctx: &TestContext) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = ctx.app.clone();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        addr
    }

    /// An upstream that answers chunked (no `Content-Length`) streams and caches the same
    /// way; the response is chunked too and ends only after the verified last byte.
    #[tokio::test]
    async fn test_docker_proxy_blob_chunked_upstream_streams_and_caches() {
        let blob: Vec<u8> = (0..(300 * 1024 + 3)).map(|i| (i % 249) as u8).collect();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
        let upstream =
            slow_blob_upstream_framed(blob.clone(), 3, Duration::from_millis(100), false).await;
        let ctx = slow_upstream_ctx(upstream);
        let addr = serve_ctx(&ctx).await;

        let response = reqwest::Client::new()
            .get(format!("http://{addr}/v2/library/test/blobs/{digest}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert!(response.headers().get(header::CONTENT_LENGTH).is_none());
        assert_eq!(response.bytes().await.unwrap().as_ref(), &blob[..]);

        let c = canonicalize("library/test", &ctx.state.config.docker);
        let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
        let storage = ctx.state.storage.clone();
        let k = key.clone();
        assert!(
            wait_until(Duration::from_secs(5), move || {
                let storage = storage.clone();
                let k = k.clone();
                Box::pin(async move { storage.get(&k).await.is_ok() })
            })
            .await
        );
    }

    /// `Content-Length: 0` from upstream for a non-empty digest must not complete as a
    /// clean 200: hyper would finish the response from the headers alone, so an empty
    /// body is never declared and the verdict still gates the end of the body.
    #[tokio::test]
    async fn test_docker_proxy_blob_empty_poisoned_body_aborts() {
        let real = b"not empty".to_vec();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&real)));
        let upstream = slow_blob_upstream(Vec::new(), 1, Duration::from_millis(20)).await;
        let ctx = slow_upstream_ctx(upstream);
        let addr = serve_ctx(&ctx).await;

        let response = reqwest::Client::new()
            .get(format!("http://{addr}/v2/library/test/blobs/{digest}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert!(
            response.bytes().await.is_err(),
            "an empty poisoned body must not complete cleanly"
        );
        let c = canonicalize("library/test", &ctx.state.config.docker);
        let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
        let started = std::time::Instant::now();
        while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ctx.state.storage.get(&key).await.is_err());
    }

    /// Quarantine in enforce mode still holds a digest this mirror has never seen: the
    /// streaming path answers 403 before any byte, and the fill still completes and lands
    /// in the cache with the digest recorded, so the hold expires on schedule.
    #[tokio::test]
    async fn test_docker_proxy_blob_new_digest_held_on_streaming_path() {
        use crate::config::DockerUpstream;
        use crate::digest_quarantine::{QuarantineMode, QuarantineStatus};
        let blob: Vec<u8> = (0..(64 * 1024 + 9)).map(|i| (i % 247) as u8).collect();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
        let upstream = slow_blob_upstream(blob.clone(), 2, Duration::from_millis(50)).await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: upstream,
                auth: None,
                namespace: None,
                prefix: None,
            }];
            cfg.curation.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("1h".to_string());
        });

        let response = send(
            &ctx.app,
            Method::GET,
            &format!("/v2/library/test/blobs/{digest}"),
            Body::empty(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a new digest is held"
        );

        let c = canonicalize("library/test", &ctx.state.config.docker);
        let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
        let storage = ctx.state.storage.clone();
        let k = key.clone();
        assert!(
            wait_until(Duration::from_secs(5), move || {
                let storage = storage.clone();
                let k = k.clone();
                Box::pin(async move { storage.get(&k).await.is_ok() })
            })
            .await,
            "the held fill still completes into the cache"
        );
        assert!(
            matches!(
                ctx.state.digest_store.check("docker", &digest, 3600),
                QuarantineStatus::Pending { .. }
            ),
            "first-seen is recorded once the fetch verified"
        );
        let again = send(
            &ctx.app,
            Method::GET,
            &format!("/v2/library/test/blobs/{digest}"),
            Body::empty(),
        )
        .await;
        assert_eq!(
            again.status(),
            StatusCode::FORBIDDEN,
            "still held from the cache"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod upstream_resume_tests {
    //! A multi-GB layer must survive a slow or flaky upstream link: `proxy_timeout` bounds
    //! the wait for upstream headers, not the body, and a body cut mid-stream is resumed
    //! with `Range` instead of being fetched again from byte zero.
    use super::{blob_key, canonicalize};
    use crate::test_helpers::{
        body_bytes, create_test_context_with_config, send, send_with_headers, TestContext,
    };
    use axum::body::{Body, Bytes};
    use axum::http::{header, HeaderMap, Method, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::Router;
    use futures::StreamExt;
    use sha2::Digest;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// How the scripted upstream answers one blob GET.
    #[derive(Clone, Copy)]
    pub(super) struct Plan {
        /// Answer `Range: bytes=N-` with 206; `false` ignores it and sends the whole blob.
        pub(super) honor_range: bool,
        /// Drop the connection after this many body bytes of this response.
        pub(super) cut_after: Option<usize>,
        /// Body piece size and the pause before each piece.
        pub(super) piece: usize,
        pub(super) delay: Duration,
        /// Pause before the response headers.
        pub(super) header_delay: Duration,
    }

    impl Plan {
        pub(super) fn fast() -> Self {
            Plan {
                honor_range: true,
                cut_after: None,
                piece: 64 * 1024,
                delay: Duration::ZERO,
                header_delay: Duration::ZERO,
            }
        }
        pub(super) fn cut(after: usize) -> Self {
            Plan {
                cut_after: Some(after),
                ..Plan::fast()
            }
        }
    }

    /// Upstream that answers blob GETs by `plans[hit]` (the last plan repeats) and records
    /// the `Range` header of every request. With `bearer = Some(t)` a blob GET without
    /// `Authorization: Bearer t` gets a 401 challenge pointing at its own `/token`.
    pub(super) struct ScriptedUpstream {
        pub(super) url: String,
        pub(super) hits: Arc<AtomicUsize>,
        ranges: tokio::sync::mpsc::UnboundedReceiver<Option<String>>,
        server: tokio::task::JoinHandle<()>,
    }

    impl ScriptedUpstream {
        /// `Range` headers of the blob GETs so far, in arrival order.
        fn ranges(&mut self) -> Vec<Option<String>> {
            std::iter::from_fn(|| self.ranges.try_recv().ok()).collect()
        }
    }

    impl Drop for ScriptedUpstream {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    pub(super) async fn scripted_upstream(
        blob: Vec<u8>,
        plans: Vec<Plan>,
        bearer: Option<&'static str>,
    ) -> ScriptedUpstream {
        use axum::routing::get;
        let blob = Arc::new(blob);
        let hits = Arc::new(AtomicUsize::new(0));
        let (ranges_tx, ranges) = tokio::sync::mpsc::unbounded_channel();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let realm = format!("{url}/token");
        let (h, r) = (hits.clone(), ranges_tx);
        let app = Router::new()
            .route(
                "/token",
                get(move || async move {
                    axum::Json(serde_json::json!({ "token": bearer.unwrap_or("") }))
                }),
            )
            .route(
                "/v2/{*rest}",
                get(move |headers: HeaderMap| {
                    let (blob, plans, hits, ranges, realm) = (
                        blob.clone(),
                        plans.clone(),
                        h.clone(),
                        r.clone(),
                        realm.clone(),
                    );
                    async move {
                        if let Some(token) = bearer {
                            let auth = headers
                                .get(header::AUTHORIZATION)
                                .and_then(|v| v.to_str().ok());
                            if auth != Some(format!("Bearer {token}").as_str()) {
                                return Response::builder()
                                    .status(StatusCode::UNAUTHORIZED)
                                    .header(
                                        header::WWW_AUTHENTICATE,
                                        format!("Bearer realm=\"{realm}\",service=\"test\""),
                                    )
                                    .body(Body::empty())
                                    .unwrap();
                            }
                        }
                        let hit = hits.fetch_add(1, Ordering::SeqCst);
                        let plan = plans[hit.min(plans.len() - 1)];
                        let range = headers
                            .get(header::RANGE)
                            .and_then(|v| v.to_str().ok())
                            .map(String::from);
                        let _ = ranges.send(range.clone());
                        tokio::time::sleep(plan.header_delay).await;
                        let from = range
                            .as_deref()
                            .filter(|_| plan.honor_range)
                            .and_then(|r| r.strip_prefix("bytes="))
                            .and_then(|r| r.strip_suffix('-'))
                            .and_then(|n| n.parse::<usize>().ok());
                        let len = blob.len();
                        let mut builder = Response::builder();
                        let start = match from {
                            Some(n) => {
                                builder = builder.status(StatusCode::PARTIAL_CONTENT).header(
                                    header::CONTENT_RANGE,
                                    format!("bytes {n}-{}/{len}", len - 1),
                                );
                                n
                            }
                            None => {
                                builder = builder.status(StatusCode::OK);
                                0
                            }
                        };
                        let body = blob[start..].to_vec();
                        let send_len = plan.cut_after.map_or(body.len(), |c| c.min(body.len()));
                        let mut pieces: Vec<std::io::Result<Bytes>> = body[..send_len]
                            .chunks(plan.piece.max(1))
                            .map(|p| Ok(Bytes::copy_from_slice(p)))
                            .collect();
                        if plan.cut_after.is_some() {
                            pieces.push(Err(std::io::Error::other("connection cut")));
                        }
                        let delay = plan.delay;
                        let stream = futures::stream::iter(pieces).then(move |p| async move {
                            tokio::time::sleep(delay).await;
                            p
                        });
                        builder
                            .header(header::CONTENT_LENGTH, len - start)
                            .body(Body::from_stream(stream))
                            .unwrap()
                    }
                }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        ScriptedUpstream {
            url,
            hits,
            ranges,
            server,
        }
    }

    pub(super) fn ctx_for(upstream: &ScriptedUpstream, proxy_timeout: u64) -> TestContext {
        use crate::config::DockerUpstream;
        let url = upstream.url.clone();
        create_test_context_with_config(move |cfg| {
            cfg.docker.proxy_timeout = proxy_timeout;
            cfg.docker.upstreams = vec![DockerUpstream {
                url,
                auth: None,
                namespace: None,
                prefix: None,
            }];
        })
    }

    pub(super) fn layer(len: usize) -> (Vec<u8>, String) {
        let blob: Vec<u8> = (0..len).map(|i| (i % 241) as u8).collect();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
        (blob, digest)
    }

    /// Waits (bounded) for the spool task to store the blob; `true` once it is cached.
    pub(super) async fn cached(ctx: &TestContext, digest: &str) -> bool {
        let c = canonicalize("library/test", &ctx.state.config.docker);
        let key = blob_key(c.namespace.as_deref(), &c.name, digest);
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(10) {
            if ctx.state.storage.get(&key).await.is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    pub(super) fn proxy_temp_count(ctx: &TestContext) -> usize {
        let proxy_tmp =
            std::path::Path::new(&ctx.state.config.storage.path).join("tmp/docker-proxy");
        std::fs::read_dir(&proxy_tmp)
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0)
    }

    pub(super) async fn pull(ctx: &TestContext, digest: &str) -> Response<Body> {
        send(
            &ctx.app,
            Method::GET,
            &format!("/v2/library/test/blobs/{digest}"),
            Body::empty(),
        )
        .await
    }

    /// Maxim's 3.5 GB ollama layer, scaled down: the body takes longer than
    /// `proxy_timeout`, but it keeps flowing, so it must arrive whole in one upstream
    /// request — the per-chunk `read_timeout` is what guards a stalled body.
    #[tokio::test]
    async fn slow_body_is_not_cut_by_proxy_timeout() {
        let (blob, digest) = layer(8 * 16 * 1024);
        let upstream = scripted_upstream(
            blob.clone(),
            vec![Plan {
                piece: 16 * 1024,
                delay: Duration::from_millis(250),
                ..Plan::fast()
            }],
            None,
        )
        .await;
        let ctx = ctx_for(&upstream, 1);

        let response = pull(&ctx, &digest).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
        assert_eq!(
            body.expect("a body that outlives proxy_timeout must still complete")
                .as_ref(),
            &blob[..]
        );
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 1, "one upstream GET");
        assert!(cached(&ctx, &digest).await, "blob must be cached");
    }

    /// Headers that never come are still bounded by `proxy_timeout` (not worse than
    /// before): the pull fails over instead of hanging, with 502 — the upstream failed,
    /// it did not say the blob is missing.
    #[tokio::test]
    async fn missing_headers_are_bounded_by_proxy_timeout() {
        let (blob, digest) = layer(1024);
        let upstream = scripted_upstream(
            blob,
            vec![Plan {
                header_delay: Duration::from_secs(5),
                ..Plan::fast()
            }],
            None,
        )
        .await;
        let ctx = ctx_for(&upstream, 1);

        let started = std::time::Instant::now();
        let response = pull(&ctx, &digest).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "headers wait took {:?}, proxy_timeout is 1s",
            started.elapsed()
        );
    }

    /// A body cut mid-stream is resumed from the byte already on disk with
    /// `Range: bytes=N-`: the client sees one clean body, upstream sends each byte once.
    #[tokio::test]
    async fn cut_body_resumes_with_range() {
        let (blob, digest) = layer(256 * 1024 + 7);
        let half = blob.len() / 2;
        let mut upstream =
            scripted_upstream(blob.clone(), vec![Plan::cut(half), Plan::fast()], None).await;
        let ctx = ctx_for(&upstream, 5);

        let response = pull(&ctx, &digest).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
        assert_eq!(
            body.expect("a resumed fill must stream to a clean end")
                .as_ref(),
            &blob[..]
        );
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 2);
        let ranges = upstream.ranges();
        assert_eq!(ranges[0], None, "first GET is a plain GET");
        assert_eq!(
            ranges[1].as_deref(),
            Some(format!("bytes={half}-").as_str()),
            "resume asks only for the missing tail"
        );
        assert!(cached(&ctx, &digest).await, "resumed blob must be cached");
        assert_eq!(proxy_temp_count(&ctx), 0);
    }

    /// An upstream that ignores `Range` on the resume and answers 200 with the whole
    /// blob: the bytes already on disk are skipped, the result is still exact.
    #[tokio::test]
    async fn resume_skips_prefix_when_upstream_ignores_range() {
        let (blob, digest) = layer(256 * 1024 + 3);
        let half = blob.len() / 2;
        let whole = Plan {
            honor_range: false,
            ..Plan::fast()
        };
        let upstream = scripted_upstream(blob.clone(), vec![Plan::cut(half), whole], None).await;
        let ctx = ctx_for(&upstream, 5);

        let response = pull(&ctx, &digest).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
        assert_eq!(body.expect("clean end").as_ref(), &blob[..]);
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 2);
        assert!(cached(&ctx, &digest).await);
    }

    /// Docker Hub's bearer tokens outlive neither every layer nor every resume: the
    /// resume request carries the (cached or re-fetched) bearer token, not bare auth.
    #[tokio::test]
    async fn resume_carries_bearer_token() {
        let (blob, digest) = layer(128 * 1024 + 1);
        let upstream = scripted_upstream(
            blob.clone(),
            vec![Plan::cut(blob.len() / 3), Plan::fast()],
            Some("tok"),
        )
        .await;
        let ctx = ctx_for(&upstream, 5);

        let response = pull(&ctx, &digest).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
        assert_eq!(body.expect("clean end").as_ref(), &blob[..]);
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 2);
    }

    /// An upstream that keeps dropping the connection without progress exhausts the
    /// resume budget: the response aborts, nothing is cached, the spool is removed.
    #[tokio::test]
    async fn resume_gives_up_without_progress() {
        let (blob, digest) = layer(64 * 1024);
        let upstream =
            scripted_upstream(blob.clone(), vec![Plan::cut(1024), Plan::cut(0)], None).await;
        let ctx = ctx_for(&upstream, 5);

        let response = pull(&ctx, &digest).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
        assert!(
            body.is_err(),
            "a fill that never completes must not end clean"
        );
        let hits = upstream.hits.load(Ordering::SeqCst);
        assert!(
            hits >= 2,
            "a cut body is resumed at least once (hits = {hits})"
        );
        assert!(hits <= 10, "the resume budget is bounded (hits = {hits})");
        let started = std::time::Instant::now();
        while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(10) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(proxy_temp_count(&ctx), 0, "spool removed");
        let c = canonicalize("library/test", &ctx.state.config.docker);
        let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
        assert!(ctx.state.storage.get(&key).await.is_err(), "not cached");
    }

    /// A resume that upstream refuses (its token is no longer accepted, and the token
    /// server is down) is an auth problem, not the registry being down: exhausting the
    /// resume budget on it must not open the registry's circuit breaker, the way a 4xx
    /// or a failed token fetch on the initial open does not (#606).
    #[tokio::test]
    async fn refused_resume_does_not_trip_breaker() {
        use crate::config::DockerUpstream;
        use axum::routing::get;
        let (blob, digest) = layer(96 * 1024);
        let blob = Arc::new(blob);
        let token_calls = Arc::new(AtomicUsize::new(0));
        let blob_hits = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let realm = format!("{url}/token");
        let tc = token_calls.clone();
        let (b, h) = (blob.clone(), blob_hits.clone());
        // One token, once; the blob GET accepts it once and sends a third of the blob.
        // Every later GET is challenged again, and the token server is down by then.
        let app = Router::new()
            .route(
                "/token",
                get(move || {
                    let tc = tc.clone();
                    async move {
                        if tc.fetch_add(1, Ordering::SeqCst) == 0 {
                            axum::Json(serde_json::json!({ "token": "t1" })).into_response()
                        } else {
                            StatusCode::SERVICE_UNAVAILABLE.into_response()
                        }
                    }
                }),
            )
            .route(
                "/v2/{*rest}",
                get(move |headers: HeaderMap| {
                    let (blob, hits, realm) = (b.clone(), h.clone(), realm.clone());
                    async move {
                        let authed = headers
                            .get(header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            == Some("Bearer t1");
                        if !authed || hits.fetch_add(1, Ordering::SeqCst) > 0 {
                            return Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .header(
                                    header::WWW_AUTHENTICATE,
                                    format!("Bearer realm=\"{realm}\",service=\"test\""),
                                )
                                .body(Body::empty())
                                .unwrap();
                        }
                        let third = blob.len() / 3;
                        let pieces: Vec<std::io::Result<Bytes>> = vec![
                            Ok(Bytes::copy_from_slice(&blob[..third])),
                            Err(std::io::Error::other("connection cut")),
                        ];
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_LENGTH, blob.len())
                            .body(Body::from_stream(futures::stream::iter(pieces).then(
                                |p| async move {
                                    // headers must reach the client before the cut
                                    tokio::time::sleep(Duration::from_millis(50)).await;
                                    p
                                },
                            )))
                            .unwrap()
                    }
                }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let upstream_url = url.clone();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 1;
            cfg.docker.proxy_timeout = 5;
            cfg.docker.upstreams = vec![DockerUpstream {
                url: upstream_url,
                auth: None,
                namespace: None,
                prefix: None,
            }];
        });

        let response = pull(&ctx, &digest).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
        assert!(body.is_err(), "the fill cannot complete without a token");
        assert!(
            blob_hits.load(Ordering::SeqCst) >= 2,
            "the cut body must have been resumed"
        );
        // The spool records its outcome after the body aborts; wait for it to finish.
        let started = std::time::Instant::now();
        while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(10) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let cb_key = crate::circuit_breaker::upstream_key("docker", &url);
        assert!(
            ctx.state.circuit_breaker.check(&cb_key).is_ok(),
            "a refused resume must not open the registry's breaker"
        );
        server.abort();
    }

    /// containerd resumes a broken pull with `Range: bytes=N-`. On a cache miss that
    /// range is answered 206 from the spool, not 200 from byte zero (which ends in
    /// "failed to discard to offset").
    #[tokio::test]
    async fn client_range_on_cache_miss_is_partial_content() {
        let (blob, digest) = layer(200 * 1024 + 9);
        let upstream = scripted_upstream(blob.clone(), vec![Plan::fast()], None).await;
        let ctx = ctx_for(&upstream, 5);
        let from = 70_000usize;

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            &format!("/v2/library/test/blobs/{digest}"),
            vec![("range", &format!("bytes={from}-"))],
            Body::empty(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response.headers()[header::CONTENT_RANGE].to_str().unwrap(),
            format!("bytes {from}-{}/{}", blob.len() - 1, blob.len())
        );
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH].to_str().unwrap(),
            (blob.len() - from).to_string()
        );
        let body = body_bytes(response).await;
        assert_eq!(body.as_ref(), &blob[from..]);
        assert!(
            cached(&ctx, &digest).await,
            "the whole blob is still cached"
        );
    }

    /// A resume only continues from a 206 whose `Content-Range` names the byte asked for;
    /// anything malformed is refused rather than spliced in at the wrong offset.
    #[test]
    fn parse_content_range_accepts_only_well_formed_spans() {
        use super::parse_content_range;
        assert_eq!(
            parse_content_range("bytes 100-199/200"),
            Some((100, Some(200)))
        );
        assert_eq!(parse_content_range("bytes 0-0/1"), Some((0, Some(1))));
        assert_eq!(parse_content_range("bytes 5-9/*"), Some((5, None)));
        assert_eq!(parse_content_range("bytes 10-5/20"), None, "inverted span");
        assert_eq!(
            parse_content_range("bytes 0-200/200"),
            None,
            "end past size"
        );
        assert_eq!(parse_content_range("bytes */200"), None, "unsatisfied form");
        assert_eq!(parse_content_range("items 0-1/2"), None, "not bytes");
        assert_eq!(parse_content_range("bytes x-1/2"), None);
        assert_eq!(parse_content_range(""), None);
    }

    /// A range that starts past the end of a blob known only from upstream headers is
    /// a 416, like the cache-hit path.
    #[tokio::test]
    async fn client_range_past_end_on_cache_miss_is_416() {
        let (blob, digest) = layer(4096);
        let upstream = scripted_upstream(blob.clone(), vec![Plan::fast()], None).await;
        let ctx = ctx_for(&upstream, 5);

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            &format!("/v2/library/test/blobs/{digest}"),
            vec![("range", &format!("bytes={}-", blob.len()))],
            Body::empty(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            response.headers()[header::CONTENT_RANGE].to_str().unwrap(),
            format!("bytes */{}", blob.len())
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod blob_single_flight_tests {
    //! One upstream fetch per cold blob, shared by every client that asks while it fills
    //! (#1003): concurrent pulls, a client that arrives mid-fill, a ranged resume. A failed
    //! or poisoned fill never strands a client, and joining a fill never skips the joiner's
    //! own per-request checks.
    use super::upstream_resume_tests::{
        cached, ctx_for, layer, proxy_temp_count, pull, scripted_upstream, Plan,
    };
    use super::{blob_key, canonicalize};
    use crate::test_helpers::send_with_headers;
    use axum::body::Body;
    use axum::http::{header, Method, StatusCode};
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    /// A body that takes ~1.6 s to arrive, long enough for later clients to find it filling.
    fn slow() -> Plan {
        Plan {
            piece: 16 * 1024,
            delay: Duration::from_millis(100),
            ..Plan::fast()
        }
    }

    async fn body_of(response: axum::response::Response) -> Result<Vec<u8>, axum::Error> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .map(|b| b.to_vec())
    }

    /// N cold pulls of one layer at once → one upstream GET, every client gets the blob.
    #[tokio::test]
    async fn concurrent_cold_pulls_share_one_upstream_fetch() {
        let (blob, digest) = layer(256 * 1024);
        let upstream = scripted_upstream(blob.clone(), vec![slow()], None).await;
        let ctx = ctx_for(&upstream, 5);
        let joined_before = crate::metrics::PROXY_COALESCED_TOTAL
            .with_label_values(&["docker"])
            .get();

        let pulls: Vec<_> = (0..8)
            .map(|_| {
                let app = ctx.app.clone();
                let digest = digest.clone();
                let handle = tokio::spawn(async move {
                    let response = crate::test_helpers::send(
                        &app,
                        Method::GET,
                        &format!("/v2/library/test/blobs/{digest}"),
                        Body::empty(),
                    )
                    .await;
                    (response.status(), body_of(response).await)
                });
                handle
            })
            .collect();
        for pull in pulls {
            let (status, body) = pull.await.unwrap();
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body.expect("clean body"), blob);
        }
        assert_eq!(
            upstream.hits.load(Ordering::SeqCst),
            1,
            "8 concurrent pulls of one cold layer must cost one upstream fetch"
        );
        assert!(
            crate::metrics::PROXY_COALESCED_TOTAL
                .with_label_values(&["docker"])
                .get()
                >= joined_before + 7,
            "the 7 clients that joined are counted"
        );
        assert!(cached(&ctx, &digest).await);
    }

    /// A client that asks after the first one already has its headers (a containerd
    /// retry, a second node) joins the running fill instead of starting another one.
    #[tokio::test]
    async fn late_client_joins_running_fill() {
        let (blob, digest) = layer(256 * 1024);
        let upstream = scripted_upstream(blob.clone(), vec![slow()], None).await;
        let ctx = ctx_for(&upstream, 5);

        let first = pull(&ctx, &digest).await;
        assert_eq!(first.status(), StatusCode::OK);
        let first = tokio::spawn(body_of(first));
        tokio::time::sleep(Duration::from_millis(400)).await;

        let second = pull(&ctx, &digest).await;
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(body_of(second).await.expect("clean body"), blob);
        assert_eq!(first.await.unwrap().expect("clean body"), blob);
        assert_eq!(
            upstream.hits.load(Ordering::SeqCst),
            1,
            "joined, not refetched"
        );
    }

    /// containerd resuming a broken pull mid-fill: its `Range` is served 206 from the
    /// shared fill, still without a second upstream fetch.
    #[tokio::test]
    async fn late_ranged_client_gets_206_from_shared_fill() {
        let (blob, digest) = layer(256 * 1024);
        let upstream = scripted_upstream(blob.clone(), vec![slow()], None).await;
        let ctx = ctx_for(&upstream, 5);

        let first = pull(&ctx, &digest).await;
        let first = tokio::spawn(body_of(first));
        tokio::time::sleep(Duration::from_millis(400)).await;

        let from = 100_000usize;
        let ranged = send_with_headers(
            &ctx.app,
            Method::GET,
            &format!("/v2/library/test/blobs/{digest}"),
            vec![("range", &format!("bytes={from}-"))],
            Body::empty(),
        )
        .await;
        assert_eq!(ranged.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            ranged.headers()[header::CONTENT_RANGE].to_str().unwrap(),
            format!("bytes {from}-{}/{}", blob.len() - 1, blob.len())
        );
        assert_eq!(body_of(ranged).await.expect("clean body"), &blob[from..]);
        assert_eq!(first.await.unwrap().expect("clean body"), blob);
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
    }

    /// A poisoned upstream shared by three clients: one upstream fetch, every client's
    /// body aborts (the last byte waits for the digest verdict), nothing is cached.
    #[tokio::test]
    async fn poisoned_fill_aborts_every_joined_client() {
        let (_, digest) = layer(128 * 1024);
        let (poison, _) = layer(128 * 1024 + 1);
        let upstream = scripted_upstream(poison, vec![slow()], None).await;
        let ctx = ctx_for(&upstream, 5);

        let first = tokio::spawn(body_of(pull(&ctx, &digest).await));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let second = tokio::spawn(body_of(pull(&ctx, &digest).await));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let third = body_of(pull(&ctx, &digest).await).await;
        assert!(third.is_err(), "a poisoned fill must not end clean");
        assert!(second.await.unwrap().is_err());
        assert!(first.await.unwrap().is_err());
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
        let started = std::time::Instant::now();
        while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(10) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let c = canonicalize("library/test", &ctx.state.config.docker);
        let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
        assert!(ctx.state.storage.get(&key).await.is_err(), "not cached");
    }

    /// A fill that fails releases its slot: the next pull starts a fresh fetch and
    /// succeeds (fail-open — no client waits on a dead fill).
    #[tokio::test]
    async fn failed_fill_releases_slot_for_the_next_pull() {
        let (blob, digest) = layer(64 * 1024);
        // hit 0 cuts, hits 1..=5 are the resume budget, hit 6 serves
        let mut plans = vec![Plan::cut(1024)];
        plans.extend(std::iter::repeat_n(Plan::cut(0), 5));
        plans.push(Plan::fast());
        let upstream = scripted_upstream(blob.clone(), plans, None).await;
        let ctx = ctx_for(&upstream, 5);

        assert!(body_of(pull(&ctx, &digest).await).await.is_err());
        let started = std::time::Instant::now();
        while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(20) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let again = pull(&ctx, &digest).await;
        assert_eq!(again.status(), StatusCode::OK);
        assert_eq!(body_of(again).await.expect("clean body"), blob);
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 7);
    }

    /// Joining a fill never skips the joiner's own curation: with the name blocked, a
    /// client carrying the bypass token starts the fill and a client without it is still
    /// refused while that fill runs.
    #[tokio::test]
    async fn joiner_is_curated_on_its_own_request() {
        use crate::config::{CurationMode, DockerUpstream};
        use crate::secrets::ProtectedString;
        let (blob, digest) = layer(256 * 1024);
        let upstream = scripted_upstream(blob.clone(), vec![slow()], None).await;
        let dir = tempfile::TempDir::new().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "docker", "name": "library/test", "version": "*", "reason": "blocked"}]}"#,
        )
        .unwrap();
        let (bl, url) = (
            blocklist.to_str().unwrap().to_string(),
            upstream.url.clone(),
        );
        let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl);
            cfg.curation.bypass_token = Some(ProtectedString::from("let-me-in"));
            cfg.docker.upstreams = vec![DockerUpstream {
                url,
                auth: None,
                namespace: None,
                prefix: None,
            }];
        });
        let path = format!("/v2/library/test/blobs/{digest}");

        let leader = send_with_headers(
            &ctx.app,
            Method::GET,
            &path,
            vec![("x-nora-bypass-token", "let-me-in")],
            Body::empty(),
        )
        .await;
        assert_eq!(leader.status(), StatusCode::OK);
        let leader = tokio::spawn(body_of(leader));
        tokio::time::sleep(Duration::from_millis(400)).await;

        let joiner = pull(&ctx, &digest).await;
        assert_eq!(
            joiner.status(),
            StatusCode::FORBIDDEN,
            "a running fill must not serve a client its own curation refuses"
        );
        assert_eq!(leader.await.unwrap().expect("clean body"), blob);
    }

    /// Clients trickling in across the whole fill — the shape of a node pool rolling one
    /// image — still cost a single upstream fetch.
    #[tokio::test]
    async fn staggered_clients_share_one_upstream_fetch() {
        let (blob, digest) = layer(256 * 1024);
        let upstream = scripted_upstream(blob.clone(), vec![slow()], None).await;
        let ctx = ctx_for(&upstream, 5);
        let mut pulls = Vec::new();
        for _ in 0..20 {
            let (app, digest) = (ctx.app.clone(), digest.clone());
            let handle = tokio::spawn(async move {
                let response = crate::test_helpers::send(
                    &app,
                    Method::GET,
                    &format!("/v2/library/test/blobs/{digest}"),
                    Body::empty(),
                )
                .await;
                body_of(response).await
            });
            pulls.push(handle);
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        for pull in pulls {
            assert_eq!(pull.await.unwrap().expect("clean body"), blob);
        }
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
    }

    /// A request can land on a fill whose spool has already moved into storage (the
    /// lease is released just after the move): it is served from storage, not failed and
    /// not refetched. A failed fill with nothing stored hands back to the caller (`None`).
    #[tokio::test]
    async fn follower_of_a_moved_spool_is_served_from_storage() {
        let (blob, digest) = layer(32 * 1024);
        let upstream = scripted_upstream(blob.clone(), vec![Plan::fast()], None).await;
        let ctx = ctx_for(&upstream, 5);
        let c = canonicalize("library/test", &ctx.state.config.docker);
        let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
        let legacy_key = blob_key(None, &c.name, &digest);
        let share = |ok: bool| {
            let done = if ok {
                Ok(())
            } else {
                Err("fill failed".to_string())
            };
            let (tx, status) = tokio::sync::watch::channel(super::SpoolStatus {
                written: blob.len() as u64,
                done: Some(done),
            });
            std::mem::forget(tx);
            super::SpoolShare {
                path: std::path::PathBuf::from("/nonexistent/spool-moved-into-storage"),
                status,
                content_length: Some(blob.len() as u64),
            }
        };
        let target = super::BlobTarget {
            name: &c.name,
            upstream_name: "library/test",
            digest: &digest,
            key: &key,
            legacy_key: &legacy_key,
            upstream_url: &upstream.url,
        };
        let headers = axum::http::HeaderMap::new();

        let failed = super::follow_fill(&ctx.state, share(false), &target, &headers).await;
        assert!(
            failed.is_none(),
            "a failed fill with nothing stored hands back"
        );

        ctx.state.storage.put(&key, &blob).await.unwrap();
        let response = super::follow_fill(&ctx.state, share(true), &target, &headers)
            .await
            .expect("served from storage");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await.unwrap(), blob);
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 0, "no refetch");
    }

    /// Once the fill is stored, a later pull is a plain cache hit.
    #[tokio::test]
    async fn pull_after_store_is_a_cache_hit() {
        let (blob, digest) = layer(64 * 1024);
        let upstream = scripted_upstream(blob.clone(), vec![Plan::fast()], None).await;
        let ctx = ctx_for(&upstream, 5);
        assert_eq!(body_of(pull(&ctx, &digest).await).await.unwrap(), blob);
        assert!(cached(&ctx, &digest).await);
        assert_eq!(body_of(pull(&ctx, &digest).await).await.unwrap(), blob);
        assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod breaker_probe_tests {
    //! Every exit of a Docker upstream fetch that took a circuit-breaker probe reports
    //! it back, so a half-open breaker never waits out the #585 stall recovery behind a
    //! probe nobody returned. A refused token is the registry answering (alive), and a
    //! failed local spool write says nothing against the upstream (alive, not a failure).
    use super::{
        fetch_blob_from_upstream, fetch_manifest_from_upstream, open_blob_from_upstream,
        spool_upstream_blob, SpoolFile, SpoolStatus,
    };
    use crate::circuit_breaker::{upstream_key, CircuitBreakerRegistry, ProbeToken};
    use crate::config::CircuitBreakerConfig;
    use crate::registry::docker_auth::DockerAuth;
    use crate::registry::TempFileGuard;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const NAME: &str = "library/alpine";
    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    /// A breaker whose next `check` for `upstream` is the half-open probe. Reset is 1 h,
    /// so the #585 stall recovery cannot hand the slot back during a test.
    fn half_open_cb(upstream: &str) -> (CircuitBreakerRegistry, String) {
        let cb = CircuitBreakerRegistry::new(CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            reset_timeout: 3600,
            overrides: std::collections::HashMap::new(),
        });
        let key = upstream_key("docker", upstream);
        cb.record_failure(&key, ProbeToken::BACKGROUND);
        cb.expire_open_for_test(&key);
        (cb, key)
    }

    fn status(cb: &CircuitBreakerRegistry, key: &str) -> &'static str {
        let snapshot = cb.health_snapshot("docker").unwrap();
        assert!(cb.keys().iter().any(|k| k == key));
        snapshot.status
    }

    /// An upstream whose blob and manifest endpoints answer 401 with a bearer challenge,
    /// and whose token endpoint fails: the token server gives no token.
    async fn upstream_without_token() -> wiremock::MockServer {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let challenge = format!("Bearer realm=\"{}/token\",service=\"test\"", server.uri());
        Mock::given(method("GET"))
            .and(path_regex(r"^/v2/.*/(blobs|manifests)/"))
            .respond_with(ResponseTemplate::new(401).insert_header("www-authenticate", challenge))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn blob_open_without_token_returns_the_probe_as_alive() {
        let server = upstream_without_token().await;
        let (cb, key) = half_open_cb(&server.uri());
        let auth = DockerAuth::default();
        let opened = open_blob_from_upstream(
            &reqwest::Client::new(),
            &server.uri(),
            NAME,
            DIGEST,
            &auth,
            5,
            None,
            &cb,
        )
        .await;
        assert!(opened.is_err(), "no token, no blob");
        assert_eq!(
            status(&cb, &key),
            "closed",
            "the registry answered (401): the probe proves it alive"
        );
    }

    #[tokio::test]
    async fn manifest_without_token_returns_the_probe_as_alive() {
        let server = upstream_without_token().await;
        let (cb, key) = half_open_cb(&server.uri());
        let auth = DockerAuth::default();
        let fetched = fetch_manifest_from_upstream(
            &reqwest::Client::new(),
            &server.uri(),
            NAME,
            "latest",
            &auth,
            5,
            None,
            &cb,
        )
        .await;
        assert!(fetched.is_err(), "no token, no manifest");
        assert_eq!(
            status(&cb, &key),
            "closed",
            "the registry answered (401): the probe proves it alive"
        );
    }

    /// Open the blob as the half-open probe against an upstream that sends `pieces` (a
    /// pause before each), then spool it into a handle that cannot be written (opened
    /// read-only), so the local write fails while the upstream is healthy.
    async fn spool_into_unwritable(
        pieces: &[&[u8]],
        progress: bool,
    ) -> (CircuitBreakerRegistry, String) {
        let total: usize = pieces.iter().map(|p| p.len()).sum();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let (cb, key) = half_open_cb(&upstream);
        let serve_once = async {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 4096];
            let _ = sock.read(&mut req).await;
            let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {total}\r\n\r\n");
            let _ = sock.write_all(head.as_bytes()).await;
            for piece in pieces {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = sock.write_all(piece).await;
                let _ = sock.flush().await;
            }
            // Hold the connection until the client is done with it.
            let _ = sock.read(&mut req).await;
        };
        let fill = async {
            let auth = DockerAuth::default();
            let blob = open_blob_from_upstream(
                &reqwest::Client::new(),
                &upstream,
                NAME,
                DIGEST,
                &auth,
                5,
                None,
                &cb,
            )
            .await
            .unwrap();
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("spool");
            std::fs::write(&path, b"").unwrap();
            let spool = SpoolFile {
                path: path.clone(),
                file: tokio::fs::File::open(&path).await.unwrap(),
                guard: TempFileGuard::new(path),
            };
            let (tx, _rx) = tokio::sync::watch::channel(SpoolStatus::default());
            let outcome = spool_upstream_blob(blob, spool, 5, &cb, progress.then_some(&tx)).await;
            assert!(outcome.is_err(), "the spool write must fail");
        };
        tokio::join!(serve_once, fill);
        (cb, key)
    }

    #[tokio::test]
    async fn spool_write_error_returns_the_probe_as_alive() {
        let (cb, key) = spool_into_unwritable(&[b"first-chunk", b"second-chunk"], false).await;
        assert_eq!(
            status(&cb, &key),
            "closed",
            "a failed local write is not the upstream's failure"
        );
    }

    #[tokio::test]
    async fn spool_progress_flush_error_returns_the_probe_as_alive() {
        let (cb, key) = spool_into_unwritable(&[b"only-chunk"], true).await;
        assert_eq!(
            status(&cb, &key),
            "closed",
            "a failed local flush is not the upstream's failure"
        );
    }

    #[tokio::test]
    async fn spool_final_flush_error_returns_the_probe_as_alive() {
        let (cb, key) = spool_into_unwritable(&[b"only-chunk"], false).await;
        assert_eq!(
            status(&cb, &key),
            "closed",
            "a failed local flush is not the upstream's failure"
        );
    }

    /// The spool file is local: when it cannot be created, no probe may have been taken
    /// yet and the upstream is not asked at all.
    #[tokio::test]
    async fn fetch_blob_without_a_spool_takes_no_probe() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"blob".to_vec()))
            .expect(0)
            .mount(&server)
            .await;
        let (cb, key) = half_open_cb(&server.uri());
        let missing = tempfile::TempDir::new().unwrap().path().join("no-such-dir");
        let auth = DockerAuth::default();
        let fetched = fetch_blob_from_upstream(
            &reqwest::Client::new(),
            &server.uri(),
            NAME,
            DIGEST,
            &auth,
            5,
            5,
            None,
            &cb,
            &missing,
        )
        .await;
        assert!(fetched.is_err(), "no spool, no fetch");
        assert!(
            cb.check(&key).is_ok(),
            "no probe may be held: the next request must be allowed to probe"
        );
    }
}

#[cfg(test)]
mod upstream_failure_cases {
    use crate::config::DockerUpstream;
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use sha2::Digest;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// one upstream asked under `alpine` (fails) and `library/alpine` (4xx): it failed
    /// under one name, so it did not say "not found" — 502 for manifest and blob.
    #[tokio::test]
    async fn failed_under_plain_name_404_under_library_is_502() {
        let flip = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("^/v2/library/"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&flip)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&flip)
            .await;
        let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"layer")));
        for uri in [
            "/v2/alpine/manifests/3".to_string(),
            format!("/v2/alpine/blobs/{blob}"),
        ] {
            let url = flip.uri();
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.docker.upstreams = vec![DockerUpstream {
                    url,
                    auth: None,
                    namespace: None,
                    prefix: None,
                }];
            });
            let resp = send(&ctx.app, Method::GET, &uri, Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "{uri}");
        }
        let asked = flip.received_requests().await.unwrap();
        assert!(asked
            .iter()
            .any(|r| r.url.path().starts_with("/v2/library/alpine/")));
    }
}

#[cfg(test)]
mod upstream_failure_edge_cases {
    use crate::config::DockerUpstream;
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use sha2::Digest;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Any 4xx is an answer — an upstream answering 400 for a manifest or a
    /// blob said "not here", so 404, not 502.
    #[tokio::test]
    async fn upstream_400_is_404() {
        let bad = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&bad)
            .await;
        let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"layer")));
        for uri in [
            "/v2/myorg/app/manifests/1.0".to_string(),
            format!("/v2/myorg/app/blobs/{blob}"),
        ] {
            let url = bad.uri();
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.docker.upstreams = vec![DockerUpstream {
                    url,
                    auth: None,
                    namespace: None,
                    prefix: None,
                }];
            });
            let resp = send(&ctx.app, Method::GET, &uri, Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
        }
    }
}

/// A hosted pull's statistics and a re-push write the same metadata file: the pull's write
/// is held after its read, a re-push lands, then the held write is released — the push date
/// curation reads must be the re-push's, not the first push's.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod hosted_pull_stats_and_re_push {
    use crate::storage::{FileMeta, ObjectStorage, Result, StorageBackend};
    use crate::Storage;
    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::sync::Notify;

    struct HeldPut {
        inner: ObjectStorage,
        key: String,
        armed: AtomicBool,
        reached: Arc<Notify>,
        release: Arc<Notify>,
    }

    #[async_trait::async_trait]
    impl StorageBackend for HeldPut {
        async fn put(
            &self,
            key: &str,
            data: &[u8],
            sha256: &str,
            annotations: &nora_registry::annotations::Annotations,
        ) -> Result<()> {
            if key == self.key && self.armed.swap(false, Ordering::SeqCst) {
                self.reached.notify_one();
                self.release.notified().await;
            }
            self.inner.put(key, data, sha256, annotations).await
        }
        async fn get(&self, key: &str) -> Result<(Bytes, crate::storage::Recorded)> {
            self.inner.get(key).await
        }
        async fn recorded(&self, key: &str) -> crate::storage::Recorded {
            self.inner.recorded(key).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>> {
            self.inner.list(prefix).await
        }
        async fn stat(&self, key: &str) -> Option<FileMeta> {
            self.inner.stat(key).await
        }
        async fn health_check(&self) -> bool {
            true
        }
        async fn total_size(&self) -> u64 {
            0
        }
        fn backend_name(&self) -> &'static str {
            "held-put"
        }
        async fn put_from_path(
            &self,
            key: &str,
            src: &std::path::Path,
            sha256: Option<&str>,
            annotations: &nora_registry::annotations::Annotations,
        ) -> Result<()> {
            self.inner
                .put_from_path(key, src, sha256, annotations)
                .await
        }
        async fn copy(&self, src: &str, dst: &str, sha256: Option<&str>) -> Result<()> {
            self.inner.copy(src, dst, sha256).await
        }
        async fn get_reader(
            &self,
            key: &str,
        ) -> Result<(
            u64,
            crate::storage::Recorded,
            std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
        )> {
            self.inner.get_reader(key).await
        }
    }

    /// Push long ago, then (optionally) a pull whose statistics write is held, a re-push,
    /// release. Returns the push date curation reads afterwards.
    async fn push_date_after_re_push(with_pull: bool) -> i64 {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: "http://127.0.0.1:1".into(),
                auth: None,
                namespace: Some("docker.io".into()),
                prefix: None,
            }];
        });
        let meta_key = "docker/race-img/manifests/v1.meta.json";
        let reached = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let backend = Arc::new(HeldPut {
            inner: ObjectStorage::in_memory(),
            key: meta_key.to_string(),
            armed: AtomicBool::new(false),
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        });
        let mut state = ctx.state.clone();
        state.storage = Storage::from_backend(backend.clone());

        let manifest = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "config": {
                    "mediaType": "application/vnd.docker.container.image.v1+json",
                    "size": 0,
                    "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                },
                "layers": []
            }))
            .unwrap(),
        );
        state
            .storage
            .put(
                "docker/race-img/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000",
                b"x",
            )
            .await
            .unwrap();
        let push = |state: crate::AppState, body: Bytes| async move {
            super::put_manifest(
                State(state),
                Path(("race-img".to_string(), "v1".to_string())),
                body,
            )
            .await
            .status()
        };
        assert_eq!(
            push(state.clone(), manifest.clone()).await,
            StatusCode::CREATED
        );
        // The first push was long ago.
        let mut meta: super::ImageMetadata =
            serde_json::from_slice(&state.storage.get(meta_key).await.unwrap()).unwrap();
        meta.push_timestamp = 1_000_000;
        state
            .storage
            .put(meta_key, &serde_json::to_vec(&meta).unwrap())
            .await
            .unwrap();

        if with_pull {
            // V3: the pull records in-memory and never writes .meta.json, so it
            // cannot clobber the publish date curation reads.
            let pull = super::get_manifest(
                State(state.clone()),
                axum::http::HeaderMap::new(),
                Path(("race-img".to_string(), "v1".to_string())),
            )
            .await;
            assert_eq!(pull.status(), StatusCode::OK);
        }

        // A re-push sets the new date; a flush then touches only the .stats.json sidecar.
        let repush = push(state.clone(), manifest.clone()).await;
        assert_eq!(repush, StatusCode::CREATED);
        super::flush_pull_stats(&state).await;

        super::extract_docker_publish_date(
            &state.storage,
            "race-img",
            "v1",
            false,
            Some("docker.io"),
            &mut super::BareMeta::Unread,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_re_push_during_a_pull_keeps_the_re_push_date() {
        let date = push_date_after_re_push(true).await;
        assert!(
            date > 1_000_000,
            "curation reads the first push's date after a re-push: {date}"
        );
    }

    /// Control: without a pull the re-push's date is what curation reads.
    #[tokio::test]
    async fn control_a_re_push_alone_sets_the_push_date() {
        assert!(push_date_after_re_push(false).await > 1_000_000);
    }

    /// A delete while a pull's statistics write is held: once both are done, no metadata of
    /// the deleted manifest is left behind (the pull's write must not land after the delete).
    #[tokio::test]
    async fn a_delete_during_a_pull_leaves_no_metadata() {
        use crate::config::DockerUpstream;
        use crate::test_helpers::create_test_context_with_config;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: "http://127.0.0.1:1".into(),
                auth: None,
                namespace: Some("docker.io".into()),
                prefix: None,
            }];
        });
        let meta_key = "docker/race-img/manifests/v1.meta.json";
        let reached = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let backend = Arc::new(HeldPut {
            inner: ObjectStorage::in_memory(),
            key: meta_key.to_string(),
            armed: AtomicBool::new(false),
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        });
        let mut state = ctx.state.clone();
        state.storage = Storage::from_backend(backend.clone());
        state
            .storage
            .put(
                "docker/race-img/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000",
                b"x",
            )
            .await
            .unwrap();
        let manifest = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "config": {
                    "mediaType": "application/vnd.docker.container.image.v1+json",
                    "size": 0,
                    "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                },
                "layers": []
            }))
            .unwrap(),
        );
        let pushed = super::put_manifest(
            State(state.clone()),
            Path(("race-img".to_string(), "v1".to_string())),
            manifest,
        )
        .await;
        assert_eq!(pushed.status(), StatusCode::CREATED);

        // V3: the pull records in-memory (no storage write); the manifest is then
        // deleted; a later flush must honour the deleted-manifest guard and
        // resurrect neither the .meta.json nor the .stats.json. The held-put arming
        // (backend.armed / reached / release) is left unused — the pull no longer
        // writes, so there is nothing to hold.
        let pull = super::get_manifest(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Path(("race-img".to_string(), "v1".to_string())),
        )
        .await;
        assert_eq!(pull.status(), StatusCode::OK);

        let delete = super::delete_manifest(
            State(state.clone()),
            Path(("race-img".to_string(), "v1".to_string())),
        )
        .await;
        assert_eq!(delete.status(), StatusCode::ACCEPTED);
        super::flush_pull_stats(&state).await;
        // The flush never writes .meta.json: the metadata the delete removed stays
        // removed. On this backend (in-memory + an upstream namespace) the bare
        // manifest survives the delete through a separate pre-existing gap, so the
        // flush legitimately persists the .stats.json sidecar (the manifest is
        // still stored); the no-resurrect guard for a truly-gone manifest is
        // covered on the local backend by delete_during_pull and
        // a_pull_stats_task_after_the_delete_leaves_no_metadata.
        assert!(
            state.storage.stat(meta_key).await.is_none(),
            "the deleted manifest's .meta.json was written back by the flush"
        );
    }
}

/// Every writer and deleter of a manifest's metadata takes the lock a hosted pull's statistics
/// take: a delete by tag or by digest, a re-push, the legacy key, a mixed-case tag. Each test holds
/// one side between its read and its write while the other runs.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod hosted_pull_stats_every_writer_takes_the_lock {
    use crate::config::DockerUpstream;
    use crate::storage::{FileMeta, ObjectStorage, Result, StorageBackend};
    use crate::Storage;
    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;

    const BLOB: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    /// Holds the next put and/or the next delete of one key until released.
    struct Held {
        inner: Arc<dyn StorageBackend>,
        key: String,
        hold_put: AtomicBool,
        put_reached: Notify,
        put_release: Notify,
        hold_delete: AtomicBool,
        del_reached: Notify,
        del_release: Notify,
    }

    #[async_trait::async_trait]
    impl StorageBackend for Held {
        async fn put(
            &self,
            key: &str,
            data: &[u8],
            sha256: &str,
            annotations: &nora_registry::annotations::Annotations,
        ) -> Result<()> {
            if key == self.key && self.hold_put.swap(false, Ordering::SeqCst) {
                self.put_reached.notify_one();
                self.put_release.notified().await;
            }
            self.inner.put(key, data, sha256, annotations).await
        }
        async fn get(&self, key: &str) -> Result<(Bytes, crate::storage::Recorded)> {
            self.inner.get(key).await
        }
        async fn recorded(&self, key: &str) -> crate::storage::Recorded {
            self.inner.recorded(key).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            if key == self.key && self.hold_delete.swap(false, Ordering::SeqCst) {
                self.del_reached.notify_one();
                self.del_release.notified().await;
            }
            self.inner.delete(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>> {
            self.inner.list(prefix).await
        }
        async fn stat(&self, key: &str) -> Option<FileMeta> {
            self.inner.stat(key).await
        }
        async fn health_check(&self) -> bool {
            true
        }
        async fn total_size(&self) -> u64 {
            0
        }
        fn backend_name(&self) -> &'static str {
            "held"
        }
        async fn put_from_path(
            &self,
            key: &str,
            src: &std::path::Path,
            sha256: Option<&str>,
            annotations: &nora_registry::annotations::Annotations,
        ) -> Result<()> {
            self.inner
                .put_from_path(key, src, sha256, annotations)
                .await
        }
        async fn copy(&self, src: &str, dst: &str, sha256: Option<&str>) -> Result<()> {
            self.inner.copy(src, dst, sha256).await
        }
        async fn get_reader(
            &self,
            key: &str,
        ) -> Result<(
            u64,
            crate::storage::Recorded,
            std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
        )> {
            self.inner.get_reader(key).await
        }
    }

    struct Fx {
        _ctx: crate::test_helpers::TestContext,
        _dir: Option<tempfile::TempDir>,
        state: crate::AppState,
        held: Arc<Held>,
        manifest: Bytes,
        digest: String,
    }

    /// Upstream with namespace docker.io configured (so a hosted pull is a bare-key hit);
    /// `local` = LocalStorage (delete of a missing key is NotFound) instead of in-memory.
    async fn fx(local: bool, held_key: impl Fn(&str) -> String) -> Fx {
        use crate::test_helpers::create_test_context_with_config;
        use sha2::Digest as _;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: "http://127.0.0.1:1".into(),
                auth: None,
                namespace: Some("docker.io".into()),
                prefix: None,
            }];
        });
        let manifest = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "config": {
                    "mediaType": "application/vnd.docker.container.image.v1+json",
                    "size": 0,
                    "digest": BLOB
                },
                "layers": []
            }))
            .unwrap(),
        );
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&manifest)));
        let (dir, inner): (Option<tempfile::TempDir>, Arc<dyn StorageBackend>) = if local {
            let d = tempfile::tempdir().unwrap();
            let s = crate::storage::LocalStorage::new(d.path().to_str().unwrap());
            (Some(d), Arc::new(s))
        } else {
            (None, Arc::new(ObjectStorage::in_memory()))
        };
        let held = Arc::new(Held {
            inner,
            key: held_key(&digest),
            hold_put: AtomicBool::new(false),
            put_reached: Notify::new(),
            put_release: Notify::new(),
            hold_delete: AtomicBool::new(false),
            del_reached: Notify::new(),
            del_release: Notify::new(),
        });
        let mut state = ctx.state.clone();
        state.storage = Storage::from_backend(held.clone());
        state
            .storage
            .put(&format!("docker/race-img/blobs/{BLOB}"), b"x")
            .await
            .unwrap();
        Fx {
            _ctx: ctx,
            _dir: dir,
            state,
            held,
            manifest,
            digest,
        }
    }

    async fn push(state: crate::AppState, tag: String, body: Bytes) -> StatusCode {
        super::put_manifest(State(state), Path(("race-img".to_string(), tag)), body)
            .await
            .status()
    }

    async fn pull(state: &crate::AppState, reference: &str) {
        let r = super::get_manifest(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Path(("race-img".to_string(), reference.to_string())),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
    }

    async fn reached(n: &Notify, what: &str) {
        // CANCEL-SAFETY: a timed-out wait drops only the notification future; expect fails.
        tokio::time::timeout(Duration::from_secs(5), n.notified())
            .await
            .expect(what);
    }

    async fn set_push_ts(state: &crate::AppState, key: &str, ts: u64) {
        let mut m: super::ImageMetadata =
            serde_json::from_slice(&state.storage.get(key).await.unwrap()).unwrap();
        m.push_timestamp = ts;
        state
            .storage
            .put(key, &serde_json::to_vec(&m).unwrap())
            .await
            .unwrap();
    }

    async fn date(state: &crate::AppState, reference: &str) -> Option<i64> {
        super::extract_docker_publish_date(
            &state.storage,
            "race-img",
            reference,
            false,
            Some("docker.io"),
            &mut super::BareMeta::Unread,
        )
        .await
    }

    /// Pull (stats write held) ‖ delete `delete_ref`; the held key must be gone afterwards.
    async fn delete_during_pull(f: &Fx, pull_ref: &str, delete_ref: &str) {
        let key = f.held.key.clone();
        assert_eq!(
            push(f.state.clone(), "v1".into(), f.manifest.clone()).await,
            StatusCode::CREATED
        );
        assert!(f.state.storage.stat(&key).await.is_some());
        // V3: the pull records in-memory (no storage write); the manifest is then
        // deleted; a later flush must honour the deleted-manifest guard and
        // resurrect neither the .meta.json nor the .stats.json of a gone manifest.
        pull(&f.state, pull_ref).await;
        let del = super::delete_manifest(
            State(f.state.clone()),
            Path(("race-img".to_string(), delete_ref.to_string())),
        )
        .await;
        assert_eq!(del.status(), StatusCode::ACCEPTED);
        super::flush_pull_stats(&f.state).await;
        assert!(
            f.state.storage.stat(&key).await.is_none(),
            "metadata {key} of the deleted manifest was written back"
        );
        assert!(
            f.state
                .storage
                .stat(&super::manifest_stats_key(&key))
                .await
                .is_none(),
            "the stats sidecar of the deleted manifest was written back"
        );
    }

    /// M02: pull by digest ‖ delete by tag — the digest's metadata must not survive.
    #[tokio::test]
    async fn a_delete_by_tag_during_a_digest_pull_leaves_no_metadata() {
        let f = fx(false, |d| {
            format!("docker/race-img/manifests/{d}.meta.json")
        })
        .await;
        let d = f.digest.clone();
        delete_during_pull(&f, &d, "v1").await;
    }

    /// M03: pull by tag ‖ delete by digest (tag dropped via delete_tags_for_digest).
    #[tokio::test]
    async fn a_delete_by_digest_during_a_tag_pull_leaves_no_tag_metadata() {
        let f = fx(false, |_| "docker/race-img/manifests/v1.meta.json".into()).await;
        let d = f.digest.clone();
        delete_during_pull(&f, "v1", &d).await;
    }

    /// M06: LocalStorage — delete by tag takes the legacy-key branch.
    #[tokio::test]
    async fn a_delete_during_a_pull_on_local_storage_leaves_no_metadata() {
        let f = fx(true, |_| "docker/race-img/manifests/v1.meta.json".into()).await;
        delete_during_pull(&f, "v1", "v1").await;
    }

    /// Pull of `pull_ref` (stats write held) ‖ re-push of `tag`; date for `pull_ref` must be the re-push's.
    async fn re_push_during_pull(f: &Fx, tag: &str, pull_ref: &str) {
        let key = f.held.key.clone();
        assert_eq!(
            push(f.state.clone(), tag.into(), f.manifest.clone()).await,
            StatusCode::CREATED
        );
        set_push_ts(&f.state, &key, 1_000_000).await;
        // V3: the pull records in-memory and never writes .meta.json, so it cannot
        // clobber the publish date. A re-push sets the new date; a later flush
        // touches only the .stats.json sidecar, never the publish timestamp.
        pull(&f.state, pull_ref).await;
        assert_eq!(
            push(f.state.clone(), tag.into(), f.manifest.clone()).await,
            StatusCode::CREATED
        );
        super::flush_pull_stats(&f.state).await;
        let got = date(&f.state, pull_ref).await.unwrap();
        assert!(
            got > 1_000_000,
            "stale first-push date after re-push: {got}"
        );
    }

    /// M04: pull by digest ‖ re-push — the digest's metadata keeps the re-push date.
    #[tokio::test]
    async fn a_re_push_during_a_digest_pull_keeps_the_re_push_date() {
        let f = fx(false, |d| {
            format!("docker/race-img/manifests/{d}.meta.json")
        })
        .await;
        let d = f.digest.clone();
        re_push_during_pull(&f, "v1", &d).await;
    }

    /// M08: a tag with upper-case letters — same race, lock key must be the exact meta key.
    #[tokio::test]
    async fn a_re_push_during_a_pull_of_a_mixed_case_tag_keeps_the_re_push_date() {
        let f = fx(false, |_| "docker/race-img/manifests/V1.meta.json".into()).await;
        re_push_during_pull(&f, "V1", "V1").await;
    }

    /// A pull's statistics task that starts while the delete is in flight must not read the old
    /// metadata and write it back (that would hand the deleted push's date to curation of the
    /// same reference): it waits for the delete's lock and then finds the manifest gone.
    #[tokio::test]
    async fn a_delete_holds_the_lock_until_the_metadata_is_gone() {
        // Local storage: on an object backend with an upstream namespace the delete leaves the
        // hosted manifest in place (a separate, older defect), and the task rightly counts it.
        let f = fx(true, |_| "docker/race-img/manifests/v1.meta.json".into()).await;
        let key = f.held.key.clone();
        assert_eq!(
            push(f.state.clone(), "v1".into(), f.manifest.clone()).await,
            StatusCode::CREATED
        );
        set_push_ts(&f.state, &key, 1_000_000).await;
        f.held.hold_delete.store(true, Ordering::SeqCst);
        let del = tokio::spawn(super::delete_manifest(
            State(f.state.clone()),
            Path(("race-img".to_string(), "v1".to_string())),
        ));
        reached(&f.held.del_reached, "metadata delete not reached").await;
        // V3: a pull recorded now; its flush races the in-flight delete. The flush
        // waits on the publish lock the delete holds, then finds the manifest gone
        // and drops the delta — the sidecar must not resurrect the deleted manifest.
        f.state.pull_stats.record(&key, 1_700_000_000);
        let stats = {
            let st = f.state.clone();
            tokio::spawn(async move {
                super::flush_pull_stats(&st).await;
            })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        f.held.del_release.notify_one();
        assert_eq!(del.await.unwrap().status(), StatusCode::ACCEPTED);
        stats.await.unwrap();
        assert!(
            f.state.storage.stat(&key).await.is_none(),
            "the deleted manifest's metadata is back"
        );
        assert!(
            f.state
                .storage
                .stat(&super::manifest_stats_key(&key))
                .await
                .is_none(),
            "a flush resurrected the deleted manifest's stats sidecar"
        );
        assert_eq!(
            date(&f.state, "v1").await,
            None,
            "a deleted push's date survived the delete"
        );
    }
}

/// A pull's statistics are recorded only while the manifest it was served from is stored: the
/// statistics task runs at any later point, and after a delete it must not bring the deleted
/// manifest's metadata back.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod hosted_pull_stats_after_a_delete {
    use crate::config::DockerUpstream;
    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;

    const BLOB: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn ctx() -> crate::test_helpers::TestContext {
        crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                url: "http://127.0.0.1:1".into(),
                auth: None,
                namespace: Some("docker.io".into()),
                prefix: None,
            }];
        })
    }

    async fn push_v1(state: &crate::AppState) {
        state
            .storage
            .put(&format!("docker/race-img/blobs/{BLOB}"), b"x")
            .await
            .unwrap();
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "config": {
                    "mediaType": "application/vnd.docker.container.image.v1+json",
                    "size": 0,
                    "digest": BLOB
                },
                "layers": []
            }))
            .unwrap(),
        );
        let r = super::put_manifest(
            State(state.clone()),
            Path(("race-img".to_string(), "v1".to_string())),
            body,
        )
        .await;
        assert_eq!(r.status(), StatusCode::CREATED);
    }

    // The pull was served (manifest read, statistics task spawned), then the delete ran first.
    #[tokio::test]
    async fn a_pull_stats_task_after_the_delete_leaves_no_metadata() {
        let ctx = ctx();
        let state = ctx.state.clone();
        push_v1(&state).await;
        let key = "docker/race-img/manifests/v1.meta.json".to_string();
        let del = super::delete_manifest(
            State(state.clone()),
            Path(("race-img".to_string(), "v1".to_string())),
        )
        .await;
        assert_eq!(del.status(), StatusCode::ACCEPTED);
        // V3: a late pull records into the in-memory accumulator; the flush's
        // deleted-manifest guard must drop it — neither .meta.json nor the
        // .stats.json sidecar may reappear for a manifest that was deleted.
        state.pull_stats.record(&key, 1_700_000_000);
        super::flush_pull_stats(&state).await;
        assert!(
            state.storage.stat(&key).await.is_none(),
            "the deleted manifest's metadata was re-created by a late pull flush"
        );
        assert!(
            state
                .storage
                .stat(&super::manifest_stats_key(&key))
                .await
                .is_none(),
            "the deleted manifest's stats sidecar was created by a late pull flush"
        );
    }
}

/// A manifest and its metadata keep one order: a manifest is written and deleted under its lock
/// and its metadata under the metadata lock taken after it; a manifest goes before its metadata; a
/// pull's statistics take only the metadata lock and write only while the manifest is stored.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod manifest_before_metadata_one_lock_order {
    use crate::config::DockerUpstream;
    use crate::storage::{FileMeta, ObjectStorage, Result, StorageBackend};
    use crate::Storage;
    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;

    const BLOB: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const PUT: u8 = 1;
    const DELETE: u8 = 2;
    const STAT: u8 = 3;
    const TAG_MANIFEST: &str = "docker/race-img/manifests/v1.json";
    const TAG_META: &str = "docker/race-img/manifests/v1.meta.json";

    /// Holds the next armed operation (put / delete / stat-after-result) on one key.
    struct Held {
        inner: Arc<dyn StorageBackend>,
        key: std::sync::Mutex<String>,
        op: AtomicU8,
        reached: Notify,
        release: Notify,
    }

    impl Held {
        fn arm(&self, op: u8, key: &str) {
            *self.key.lock().unwrap() = key.to_string();
            self.op.store(op, Ordering::SeqCst);
        }
        async fn gate(&self, op: u8, key: &str) {
            let same = { *self.key.lock().unwrap() == key };
            if same
                && self
                    .op
                    .compare_exchange(op, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                self.reached.notify_one();
                self.release.notified().await;
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for Held {
        async fn put(
            &self,
            key: &str,
            data: &[u8],
            sha256: &str,
            annotations: &nora_registry::annotations::Annotations,
        ) -> Result<()> {
            self.gate(PUT, key).await;
            self.inner.put(key, data, sha256, annotations).await
        }
        async fn get(&self, key: &str) -> Result<(Bytes, crate::storage::Recorded)> {
            self.inner.get(key).await
        }
        async fn recorded(&self, key: &str) -> crate::storage::Recorded {
            self.inner.recorded(key).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.gate(DELETE, key).await;
            self.inner.delete(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>> {
            self.inner.list(prefix).await
        }
        async fn stat(&self, key: &str) -> Option<FileMeta> {
            // The answer is taken first; the hold sits between the answer and its use.
            let r = self.inner.stat(key).await;
            self.gate(STAT, key).await;
            r
        }
        async fn health_check(&self) -> bool {
            true
        }
        async fn total_size(&self) -> u64 {
            0
        }
        fn backend_name(&self) -> &'static str {
            "held-r2"
        }
        async fn put_from_path(
            &self,
            key: &str,
            src: &std::path::Path,
            sha256: Option<&str>,
            annotations: &nora_registry::annotations::Annotations,
        ) -> Result<()> {
            self.inner
                .put_from_path(key, src, sha256, annotations)
                .await
        }
        async fn copy(&self, src: &str, dst: &str, sha256: Option<&str>) -> Result<()> {
            self.inner.copy(src, dst, sha256).await
        }
        async fn get_reader(
            &self,
            key: &str,
        ) -> Result<(
            u64,
            crate::storage::Recorded,
            std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
        )> {
            self.inner.get_reader(key).await
        }
    }

    struct Fx {
        _ctx: crate::test_helpers::TestContext,
        _dir: Option<tempfile::TempDir>,
        state: crate::AppState,
        held: Arc<Held>,
        manifest: Bytes,
        digest: String,
    }

    /// `upstream_ns`: an upstream with namespace docker.io (hosted = bare-key hit) vs none;
    /// `local`: LocalStorage instead of in-memory.
    async fn fx(upstream_ns: bool, local: bool) -> Fx {
        use sha2::Digest as _;
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = if upstream_ns {
                vec![DockerUpstream {
                    url: "http://127.0.0.1:1".into(),
                    auth: None,
                    namespace: Some("docker.io".into()),
                    prefix: None,
                }]
            } else {
                vec![]
            };
        });
        let manifest = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "config": {
                    "mediaType": "application/vnd.docker.container.image.v1+json",
                    "size": 0,
                    "digest": BLOB
                },
                "layers": []
            }))
            .unwrap(),
        );
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&manifest)));
        let (dir, inner): (Option<tempfile::TempDir>, Arc<dyn StorageBackend>) = if local {
            let d = tempfile::tempdir().unwrap();
            let s = crate::storage::LocalStorage::new(d.path().to_str().unwrap());
            (Some(d), Arc::new(s))
        } else {
            (None, Arc::new(ObjectStorage::in_memory()))
        };
        let held = Arc::new(Held {
            inner,
            key: std::sync::Mutex::new(String::new()),
            op: AtomicU8::new(0),
            reached: Notify::new(),
            release: Notify::new(),
        });
        let mut state = ctx.state.clone();
        state.storage = Storage::from_backend(held.clone());
        state
            .storage
            .put(&format!("docker/race-img/blobs/{BLOB}"), b"x")
            .await
            .unwrap();
        assert_eq!(
            push(state.clone(), manifest.clone()).await,
            StatusCode::CREATED
        );
        Fx {
            _ctx: ctx,
            _dir: dir,
            state,
            held,
            manifest,
            digest,
        }
    }

    async fn push(state: crate::AppState, body: Bytes) -> StatusCode {
        super::put_manifest(
            State(state),
            Path(("race-img".to_string(), "v1".to_string())),
            body,
        )
        .await
        .status()
    }

    async fn delete(state: crate::AppState, reference: String) -> StatusCode {
        super::delete_manifest(State(state), Path(("race-img".to_string(), reference)))
            .await
            .status()
    }

    async fn pull(state: &crate::AppState, reference: &str) {
        let r = super::get_manifest(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Path(("race-img".to_string(), reference.to_string())),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
    }

    async fn reached(n: &Notify, what: &str) {
        // CANCEL-SAFETY: a timed-out wait drops only the notification future; expect fails.
        tokio::time::timeout(Duration::from_secs(5), n.notified())
            .await
            .expect(what);
    }

    async fn finishes<T>(h: tokio::task::JoinHandle<T>, what: &str) -> T {
        // CANCEL-SAFETY: on timeout the handle is dropped (task detached) and the test fails.
        tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .expect(what)
            .unwrap()
    }

    async fn downloads(state: &crate::AppState, key: &str) -> Option<u64> {
        Some(super::current_pull_stats(state, key).await.downloads)
    }

    /// The delete is held at `held_manifest`'s removal; a pull of `pull_ref` is served and its
    /// statistics task completes meanwhile. Once the delete is done, `meta_key` must be gone.
    async fn pull_while_manifest_delete_held(
        f: &Fx,
        held_manifest: &str,
        pull_ref: &str,
        delete_ref: &str,
        meta_key: &str,
    ) {
        f.held.arm(DELETE, held_manifest);
        let del = tokio::spawn(delete(f.state.clone(), delete_ref.to_string()));
        reached(&f.held.reached, "manifest delete not reached").await;
        pull(&f.state, pull_ref).await;
        // CANCEL-SAFETY: the poll loop holds nothing across its awaits; timeout fails the test.
        tokio::time::timeout(Duration::from_secs(5), async {
            while downloads(&f.state, meta_key).await != Some(1) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("pull statistics not recorded while the manifest was still stored");
        f.held.release.notify_one();
        assert_eq!(finishes(del, "delete hung").await, StatusCode::ACCEPTED);
        assert!(
            f.state.storage.stat(held_manifest).await.is_none(),
            "manifest {held_manifest} still stored"
        );
        assert!(
            f.state.storage.stat(meta_key).await.is_none(),
            "metadata {meta_key} outlived its deleted manifest"
        );
    }

    /// delete by tag, no upstream (Ok arm): a pull during the delete leaves no tag metadata.
    #[tokio::test]
    async fn a_pull_during_a_tag_delete_leaves_no_tag_metadata() {
        let f = fx(false, false).await;
        pull_while_manifest_delete_held(&f, TAG_MANIFEST, "v1", "v1", TAG_META).await;
    }

    /// upstream namespace + local storage (legacy arm deletes the hosted manifest).
    #[tokio::test]
    async fn a_pull_during_a_legacy_key_delete_leaves_no_metadata() {
        let f = fx(true, true).await;
        pull_while_manifest_delete_held(&f, TAG_MANIFEST, "v1", "v1", TAG_META).await;
    }

    /// delete by digest drops the tag (delete_tags_for_digest) while a tag pull is served.
    #[tokio::test]
    async fn a_tag_pull_during_a_digest_delete_leaves_no_tag_metadata() {
        let f = fx(false, false).await;
        let d = f.digest.clone();
        pull_while_manifest_delete_held(&f, TAG_MANIFEST, "v1", &d, TAG_META).await;
    }

    /// delete by tag drops the digest copy while a digest pull is served.
    #[tokio::test]
    async fn a_digest_pull_during_a_tag_delete_leaves_no_digest_metadata() {
        let f = fx(false, false).await;
        let d = f.digest.clone();
        let dm = format!("docker/race-img/manifests/{d}.json");
        let dmeta = format!("docker/race-img/manifests/{d}.meta.json");
        pull_while_manifest_delete_held(&f, &dm, &d, "v1", &dmeta).await;
    }

    // ---- pull-stats sidecar: regression fixtures ----

    /// (M1, M2): a FLUSH must not rewrite .meta.json either — not to mirror
    /// the counts, not to clear migrated legacy counts.
    #[tokio::test]
    async fn flush_never_rewrites_the_meta_json() {
        let f = fx(false, true).await;
        let mut m: super::ImageMetadata =
            serde_json::from_slice(&f.state.storage.get(TAG_META).await.unwrap()).unwrap();
        m.downloads = 5;
        m.last_pulled = 1_000;
        f.state
            .storage
            .put(TAG_META, &serde_json::to_vec(&m).unwrap())
            .await
            .unwrap();
        let before = f.state.storage.get(TAG_META).await.unwrap();
        for _ in 0..2 {
            pull(&f.state, "v1").await;
            super::flush_pull_stats(&f.state).await;
        }
        assert_eq!(
            downloads(&f.state, TAG_META).await,
            Some(7),
            "control: the flush ran and migrated"
        );
        assert_eq!(
            f.state.storage.get(TAG_META).await.unwrap(),
            before,
            "a flush rewrote .meta.json"
        );
    }

    /// the flush's existence answer is held; a whole delete runs; on
    /// release the flush must not resurrect the deleted manifest's stats sidecar.
    #[tokio::test]
    async fn delete_while_the_flush_check_is_held_leaves_no_stats() {
        let f = fx(false, true).await;
        pull(&f.state, "v1").await;
        f.held.arm(STAT, TAG_MANIFEST);
        let flush = {
            let st = f.state.clone();
            tokio::spawn(async move { super::flush_pull_stats(&st).await })
        };
        reached(&f.held.reached, "flush existence check not reached").await;
        let del = tokio::spawn(delete(f.state.clone(), "v1".into()));
        tokio::time::sleep(Duration::from_millis(300)).await;
        f.held.release.notify_one();
        finishes(flush, "flush hung").await;
        assert_eq!(finishes(del, "delete hung").await, StatusCode::ACCEPTED);
        assert!(f.state.storage.stat(TAG_MANIFEST).await.is_none());
        assert!(
            f.state
                .storage
                .stat(&super::manifest_stats_key(TAG_META))
                .await
                .is_none(),
            "the flush resurrected the deleted manifest's stats sidecar"
        );
    }

    /// a delete removes an ALREADY-FLUSHED sidecar; a re-push of the
    /// same tag starts from zero, not from the deleted manifest's count.
    #[tokio::test]
    async fn delete_drops_the_flushed_stats_sidecar() {
        let f = fx(false, true).await;
        pull(&f.state, "v1").await;
        super::flush_pull_stats(&f.state).await;
        let sk = super::manifest_stats_key(TAG_META);
        assert!(
            f.state.storage.stat(&sk).await.is_some(),
            "control: flushed"
        );
        assert_eq!(
            delete(f.state.clone(), "v1".into()).await,
            StatusCode::ACCEPTED
        );
        assert!(
            f.state.storage.stat(&sk).await.is_none(),
            "the deleted manifest's stats sidecar survived the delete"
        );
        assert_eq!(
            push(f.state.clone(), f.manifest.clone()).await,
            StatusCode::CREATED
        );
        assert_eq!(downloads(&f.state, TAG_META).await, Some(0));
    }

    /// A delete that lands before a flush leaves no metadata and no stats sidecar:
    /// the flush re-checks the manifest under the publish lock and skips a gone
    /// one. This is the SEQUENTIAL case; the concurrent race — the flush's
    /// existence answer held across a whole delete — is covered by
    /// `delete_while_the_flush_check_is_held_leaves_no_stats`.
    #[tokio::test]
    async fn a_delete_between_the_stats_check_and_its_write_leaves_no_metadata() {
        let f = fx(false, false).await;
        // V3: the pull records in-memory; the flush's existence check and its
        // sidecar write are both under the per-key publish lock (a delete takes the
        // same lock), so a delete cannot slip between the check and the write. After
        // a delete, a flush resurrects neither the metadata nor the stats sidecar.
        pull(&f.state, "v1").await;
        assert_eq!(
            delete(f.state.clone(), "v1".into()).await,
            StatusCode::ACCEPTED
        );
        super::flush_pull_stats(&f.state).await;
        assert!(f.state.storage.stat(TAG_MANIFEST).await.is_none());
        assert!(
            f.state.storage.stat(TAG_META).await.is_none(),
            "the deleted manifest's metadata was created after the delete"
        );
        assert!(
            f.state
                .storage
                .stat(&super::manifest_stats_key(TAG_META))
                .await
                .is_none(),
            "the deleted manifest's stats sidecar was created after the delete"
        );
    }

    /// lock order manifest -> metadata. Pull stats hold the metadata lock; a re-push and a
    /// delete of the same tag queue up; both must finish once the pull's write is released.
    #[tokio::test]
    async fn push_and_delete_during_a_pull_do_not_deadlock() {
        let f = fx(false, false).await;
        // V3: the pull records in-memory; the flush, a re-push, and a delete all
        // take the per-key publish lock, so they serialize without a lock-order
        // deadlock. Run them concurrently and require all three to finish.
        pull(&f.state, "v1").await;
        let flush = {
            let st = f.state.clone();
            tokio::spawn(async move { super::flush_pull_stats(&st).await })
        };
        let rp = tokio::spawn(push(f.state.clone(), f.manifest.clone()));
        let del = tokio::spawn(delete(f.state.clone(), "v1".into()));
        finishes(flush, "flush hung (lock-order deadlock)").await;
        assert_eq!(
            finishes(rp, "re-push hung (lock-order deadlock)").await,
            StatusCode::CREATED
        );
        assert_eq!(
            finishes(del, "delete hung (lock-order deadlock)").await,
            StatusCode::ACCEPTED
        );
    }

    /// the pull's statistics take only the metadata lock — a pull during a re-push (held at
    /// its manifest write) must not leave the push waiting forever.
    #[tokio::test]
    async fn a_pull_during_a_re_push_does_not_deadlock() {
        let f = fx(false, false).await;
        f.held.arm(PUT, TAG_MANIFEST);
        let rp = tokio::spawn(push(f.state.clone(), f.manifest.clone()));
        reached(&f.held.reached, "re-push manifest write not reached").await;
        pull(&f.state, "v1").await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        f.held.release.notify_one();
        assert_eq!(
            finishes(rp, "re-push hung (lock-order deadlock)").await,
            StatusCode::CREATED
        );
    }

    /// a push writes all of its metadata while it still holds the manifest lock — a delete
    /// that arrives mid-push runs after it, and leaves no metadata of the deleted manifest.
    #[tokio::test]
    async fn a_delete_during_a_push_leaves_no_metadata() {
        let f = fx(false, false).await;
        let dm = format!("docker/race-img/manifests/{}.json", f.digest);
        let dmeta = format!("docker/race-img/manifests/{}.meta.json", f.digest);
        f.held.arm(PUT, TAG_META);
        let rp = tokio::spawn(push(f.state.clone(), f.manifest.clone()));
        reached(&f.held.reached, "push metadata write not reached").await;
        let del = tokio::spawn(delete(f.state.clone(), "v1".into()));
        tokio::time::sleep(Duration::from_millis(300)).await;
        f.held.release.notify_one();
        assert_eq!(finishes(rp, "push hung").await, StatusCode::CREATED);
        assert_eq!(finishes(del, "delete hung").await, StatusCode::ACCEPTED);
        tokio::time::sleep(Duration::from_millis(100)).await;
        for (m, meta) in [(TAG_MANIFEST, TAG_META), (dm.as_str(), dmeta.as_str())] {
            if f.state.storage.stat(m).await.is_none() {
                assert!(
                    f.state.storage.stat(meta).await.is_none(),
                    "metadata {meta} outlived its deleted manifest"
                );
            }
        }
    }
}

/// Only the metadata section builds a manifest metadata key: `manifest_meta_key` is called, and
/// `.meta.json` written, in no other production function — so every write and delete of a
/// manifest's metadata goes through the helpers that keep the order "manifest, then metadata,
/// manifest lock before metadata lock". A white list, not a list of forbidden forms, which
/// would miss the next form.
#[cfg(test)]
mod only_the_metadata_section_builds_metadata_keys {
    /// The functions that may build a metadata key: its definition, the three helpers, and the
    /// reader of a push date.
    const ALLOWED: [&str; 9] = [
        "manifest_meta_key",
        "write_manifest_meta",
        "delete_manifest_and_meta",
        // A push's record and the proxied copy a push takes its tag back from (variant A).
        "read_bare_meta",
        "delete_proxied_tag",
        "extract_docker_publish_date",
        // #1114: pull stats are keyed off the manifest meta key and derive the
        // .stats.json sidecar key from it.
        "serve_cached_manifest",
        "manifest_stats_key",
        "flush_pull_stats",
    ];

    /// The function a line belongs to: the last `fn name` header above it.
    fn fn_name(line: &str) -> Option<&str> {
        let at = line.find("fn ")?;
        let before = &line[..at];
        if !before.trim().is_empty()
            && ![
                "pub",
                "pub(crate)",
                "async",
                "pub async",
                "pub(crate) async",
            ]
            .contains(&before.trim())
        {
            return None;
        }
        let rest = &line[at + 3..];
        let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
        Some(&rest[..end])
    }

    /// Every line of the production part that builds a metadata key outside the white list, and
    /// every top-level line after the first test module that is not part of a test module.
    fn violations(src: &str) -> Vec<String> {
        let cut = src
            .find("\n#[cfg(test)]\n")
            .expect("docker.rs has test modules");
        let (production, tests) = src.split_at(cut);
        let mut found = Vec::new();
        let mut current: Option<&str> = None;
        for (i, line) in production.lines().enumerate() {
            if let Some(name) = fn_name(line) {
                current = Some(name);
            }
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            let builds = (line.contains("manifest_meta_key")
                && fn_name(line) != Some("manifest_meta_key"))
                || line.contains(".meta.json");
            if builds && !current.is_some_and(|f| ALLOWED.contains(&f)) {
                found.push(format!(
                    "line {}: {} (in {:?})",
                    i + 1,
                    line.trim(),
                    current
                ));
            }
        }
        // After the first test module only test modules follow.
        let mut attrs_have_cfg_test = false;
        for line in tests.lines() {
            if line.is_empty()
                || line.starts_with(' ')
                || line.starts_with('\t')
                || line.starts_with('}')
            {
                continue;
            }
            if line.starts_with("//") {
                continue;
            }
            if line.starts_with("#[") {
                attrs_have_cfg_test |= line.starts_with("#[cfg(test)]");
                continue;
            }
            if line.starts_with("mod ") && attrs_have_cfg_test {
                attrs_have_cfg_test = false;
                continue;
            }
            found.push(format!("production item after the tests: {line}"));
        }
        found
    }

    #[test]
    fn only_the_metadata_section_builds_metadata_keys() {
        let src = include_str!("docker.rs");
        assert_eq!(violations(src), Vec::<String>::new());
    }

    // Controls: a metadata key built in another function, or a production function after the
    // tests, is caught; a comment that mentions `.meta.json` is not.
    #[test]
    fn the_white_list_catches_a_key_built_elsewhere() {
        let src = include_str!("docker.rs");
        let cut = src.find("\n#[cfg(test)]\n").unwrap();
        let mut built_elsewhere = src.to_string();
        built_elsewhere.insert_str(
            cut,
            "\nasync fn stray(state: &AppState) {\n    let _ = state.storage.delete(&manifest_meta_key(None, \"a\", \"b\")).await;\n}\n",
        );
        assert_eq!(violations(&built_elsewhere).len(), 1);
        let mut literal = src.to_string();
        literal.insert_str(
            cut,
            "\nfn stray() -> &'static str {\n    \"docker/a/manifests/b.meta.json\"\n}\n",
        );
        assert_eq!(violations(&literal).len(), 1);
        let mut after_tests = src.to_string();
        after_tests.push_str("\nasync fn late(state: &AppState) {\n    let _ = state;\n}\n");
        assert_eq!(violations(&after_tests).len(), 1);
        // The function itself handed to another name, too.
        let mut alias = src.to_string();
        alias.insert_str(
            cut,
            "\nfn stray() {\n    let key = manifest_meta_key;\n    let _ = key;\n}\n",
        );
        assert_eq!(violations(&alias).len(), 1);
        let mut comment = src.to_string();
        comment.insert_str(
            cut,
            "\nfn quiet() {\n    // the .meta.json sidecar is written elsewhere\n}\n",
        );
        assert_eq!(violations(&comment), Vec::<String>::new());
    }
}
