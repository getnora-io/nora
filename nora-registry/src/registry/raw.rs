// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, NamespaceAuthority};
use crate::registry::{
    content_length, method_not_allowed, sha256_of_file, stream_body_to_file, StreamOutcome,
    TempFileGuard,
};
use crate::validation::validate_storage_key;
use crate::AppState;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Router,
};

/// Build the storage key for a Raw artifact at request-relative `path`.
///
/// Single source of truth for the `raw/<path>` layout so the handlers here and
/// `nora import` (review R7, contract `import-key-format-equals-handler-key-format`)
/// produce byte-identical keys that GC/retention/UI browse walk as strings.
pub(crate) fn storage_key(path: &str) -> String {
    format!("raw/{path}")
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/raw/-/reindex", post(reindex)).route(
        "/raw/{*path}",
        get(download)
            .put(upload)
            .delete(delete_file)
            .head(check_exists)
            .fallback(|| async { method_not_allowed("GET, PUT, DELETE, HEAD") }),
    )
}

/// Invalidate the raw index so it rebuilds on next read.
/// Useful after uploading files directly to S3/storage bypassing the API.
async fn reindex(State(state): State<AppState>) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.repo_index.invalidate("raw");
    tracing::info!("raw index invalidated via API");
    StatusCode::OK.into_response()
}

async fn download(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let key = storage_key(&path);
    if validate_storage_key(&key).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // mtime fallback — Raw is always hosted (no proxy)
    let publish_date = crate::curation::extract_mtime_as_publish_date(&state.storage, &key).await;

    // Curation check — raw files are treated as name=path, no version. #733: raw is hosted-only
    // (no upstream), so an internal-namespace file is operator-owned — skip curation and serve the
    // local copy below; a missing one 404s naturally (nothing is ever proxied).
    if !crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Raw,
        &path,
    ) {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Raw,
            &path,
            None,
            publish_date,
        ) {
            return response;
        }
    }

    // Conditional GET — If-None-Match
    if let Some(inm) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(stored_hash) = state.storage.get_pin_hash(&key) {
            let etag_val = format!("\"{}\"", stored_hash);
            if inm.trim() == etag_val || inm.trim() == "*" {
                return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag_val)]).into_response();
            }
        }
    }

    // Streamed serve with STREAMING integrity verification. The buffered
    // `get_verified` gate would hold the whole object in memory — unusable for
    // multi-GB artifacts — so raw hashes the stream as it is served and
    // compares against the recorded pin at EOF. On a mismatch the body is
    // aborted BEFORE its final frame: the client observes a connection error /
    // Content-Length shortfall instead of a completed corrupt download —
    // fail-closed, in streaming form. A key with no pin (object-store backend)
    // is served without a cryptographic check, exactly like the buffered
    // gate's `Unpinned` arm.
    let pin = state.storage.get_pin_hash(&key);
    match state.storage.get_reader(&key).await {
        Ok((len, reader)) => {
            state.metrics.record_download("raw");
            state.activity.push(ActivityEntry::new(
                ActionType::Pull,
                path,
                crate::registry_type::RegistryType::Raw,
                "LOCAL",
            ));
            state
                .audit
                .log(AuditEntry::new("pull", "api", "", "raw", ""));

            let content_type = guess_content_type(&key);
            let mut builder = axum::http::Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_LENGTH, len.to_string())
                .header(header::CACHE_CONTROL, &state.config.raw.cache_control);
            if let Some(ref hash) = pin {
                builder = builder.header(header::ETAG, format!("\"{}\"", hash));
            }
            builder
                .body(axum::body::Body::from_stream(verify_while_streaming(
                    reader,
                    pin,
                    key.clone(),
                )))
                .expect("valid response")
                .into_response()
        }
        Err(crate::storage::StorageError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, key = %key, "Failed to read raw artifact");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Frame stream that hashes every frame and, when an integrity pin is
/// present, withholds the FINAL frame until the digest has been checked at
/// EOF — a mismatch aborts the body one frame short of completion, so a
/// tampered object can never arrive at the client as a complete download.
/// (The streaming counterpart of the buffered `get_verified` gate; see the
/// serve site above.)
struct VerifyingStream {
    frames:
        tokio_util::io::ReaderStream<std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>>,
    /// Expected pin + running hash; `None` = unpinned key, no check.
    hashing: Option<(String, sha2::Sha256)>,
    key: String,
    /// One-frame holdback buffer (only used while `hashing` is active).
    held: Option<axum::body::Bytes>,
    done: bool,
}

impl futures::Stream for VerifyingStream {
    type Item = Result<axum::body::Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use sha2::Digest;
        use std::task::Poll;

        loop {
            if self.done {
                return Poll::Ready(None);
            }
            match std::pin::Pin::new(&mut self.frames).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => {
                    if let Some((_, hasher)) = self.hashing.as_mut() {
                        hasher.update(&chunk);
                        // Holdback applies only when a pin will be checked.
                        match self.held.replace(chunk) {
                            Some(prev) => return Poll::Ready(Some(Ok(prev))),
                            None => continue, // primed the holdback, read on
                        }
                    }
                    return Poll::Ready(Some(Ok(chunk)));
                }
                Poll::Ready(Some(Err(e))) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    self.done = true;
                    if let Some((expected, hasher)) = self.hashing.take() {
                        let computed = hex::encode(hasher.finalize());
                        if computed != expected {
                            tracing::error!(
                                key = %self.key,
                                expected = %expected,
                                computed = %computed,
                                "SECURITY: integrity pin mismatch on streamed read — aborting body"
                            );
                            return Poll::Ready(Some(Err(std::io::Error::other(
                                "integrity pin mismatch",
                            ))));
                        }
                    }
                    return match self.held.take() {
                        Some(last) => Poll::Ready(Some(Ok(last))),
                        None => Poll::Ready(None),
                    };
                }
            }
        }
    }
}

fn verify_while_streaming(
    reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    pin: Option<String>,
    key: String,
) -> VerifyingStream {
    use sha2::Digest;
    VerifyingStream {
        frames: tokio_util::io::ReaderStream::with_capacity(reader, 256 * 1024),
        hashing: pin.map(|p| (p, sha2::Sha256::new())),
        key,
        held: None,
        done: false,
    }
}

async fn upload(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Extension(authority): Extension<NamespaceAuthority>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let key = storage_key(&path);
    if validate_storage_key(&key).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Enforce OIDC namespace_scope on the artifact coordinate (#583).
    if enforce_namespace_scope(&authority, &path).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }

    if !path.is_ascii() {
        return (
            StatusCode::BAD_REQUEST,
            "Path must contain only ASCII characters",
        )
            .into_response();
    }

    let too_large = || {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "File too large. Max size: {} bytes",
                state.config.raw.max_file_size
            ),
        )
            .into_response()
    };
    // Fast-reject an oversized declared length before reading any body bytes.
    if content_length(&headers).is_some_and(|len| len > state.config.raw.max_file_size) {
        return too_large();
    }

    // Stream the body to a temp file on the storage filesystem — the body is
    // never held in memory, so uploads are bounded by disk, not RAM, and the
    // local backend's put_from_path commits by rename (no copy). The size cap
    // is enforced incrementally as frames arrive. Streamed BEFORE taking the
    // publish lock so a slow client cannot hold the key's lock for the
    // duration of a multi-GB transfer.
    let temp_dir = raw_upload_temp_dir(&state.config.storage.path);
    let temp_path = temp_dir.join(uuid::Uuid::new_v4().to_string());
    let mut temp_guard = TempFileGuard::new(temp_path.clone());
    let mut file = match tokio::fs::File::create(&temp_path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create raw upload temp file");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    match stream_body_to_file(body, &mut file, state.config.raw.max_file_size).await {
        StreamOutcome::Ok(_) => {}
        StreamOutcome::TooLarge => return too_large(),
        StreamOutcome::ClientGone => {
            return (StatusCode::BAD_REQUEST, "Request body stream ended early").into_response()
        }
        StreamOutcome::Io(e) => {
            tracing::error!(error = %e, "Failed to write raw upload temp file");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    drop(file);
    // Hash the streamed file for the integrity pin (drives the ETag flows).
    let sha256 = match sha256_of_file(&temp_path).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "Failed to hash raw upload temp file");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string());
    let if_match = headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string());

    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;

    let file_exists = state.storage.stat(&key).await.is_some();

    match (file_exists, if_none_match.as_deref(), if_match.as_deref()) {
        // No conditional headers, file exists → 409 (backward compat)
        (true, None, None) => {
            return (
                StatusCode::CONFLICT,
                format!("File already exists: {}", path),
            )
                .into_response();
        }

        // No conditional headers, file doesn't exist → create
        (false, None, None) => {
            // fall through to create
        }

        // If-None-Match: * → create only if not exists
        (true, Some("*"), _) => {
            return (StatusCode::PRECONDITION_FAILED, "Resource already exists").into_response();
        }
        (false, Some("*"), _) => {
            // fall through to create
        }

        // If-None-Match with a specific ETag value (not useful for PUT, but handle gracefully)
        (_, Some(_), None) => {
            // Non-* If-None-Match on PUT: not meaningful per RFC 9110, reject
            return (
                StatusCode::BAD_REQUEST,
                "If-None-Match on PUT only supports * value",
            )
                .into_response();
        }

        // If-Match: * → update only if resource exists
        (true, _, Some("*")) => {
            return do_overwrite(&state, &key, &path, &temp_path, &sha256, &mut temp_guard).await;
        }
        (false, _, Some("*")) => {
            return (StatusCode::PRECONDITION_FAILED, "Resource does not exist").into_response();
        }

        // If-Match: "<etag>" → update only if ETag matches
        (true, _, Some(etag)) => {
            let stored_hash = state.storage.get_pin_hash(&key);
            match stored_hash {
                Some(hash) => {
                    let expected = format!("\"{}\"", hash);
                    if etag == expected {
                        return do_overwrite(
                            &state,
                            &key,
                            &path,
                            &temp_path,
                            &sha256,
                            &mut temp_guard,
                        )
                        .await;
                    }
                    return (StatusCode::PRECONDITION_FAILED, "ETag mismatch").into_response();
                }
                None => {
                    // No pin hash available (e.g. S3 backend) — cannot verify
                    return (
                        StatusCode::PRECONDITION_FAILED,
                        "ETag not available for this resource",
                    )
                        .into_response();
                }
            }
        }
        (false, _, Some(_)) => {
            return (StatusCode::PRECONDITION_FAILED, "Resource does not exist").into_response();
        }
    }

    // Create new file — commit the streamed temp (rename on the local backend).
    match state
        .storage
        .put_from_path(&key, &temp_path, Some(&sha256))
        .await
    {
        Ok(()) => {
            temp_guard.disarm();
            state.metrics.record_upload("raw");
            state
                .audit
                .log(AuditEntry::new("push", "api", &path, "raw", ""));
            state.activity.push(ActivityEntry::new(
                ActionType::Push,
                path,
                crate::registry_type::RegistryType::Raw,
                "LOCAL",
            ));
            state.repo_index.invalidate("raw");
            StatusCode::CREATED.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, key = %key, "Failed to store raw artifact");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Overwrite an existing file (conditional PUT with `If-Match`).
async fn do_overwrite(
    state: &AppState,
    key: &str,
    path: &str,
    temp_path: &std::path::Path,
    sha256: &str,
    temp_guard: &mut TempFileGuard,
) -> Response {
    // put_from_path overwrites in place on both backends, avoiding the 404
    // window that delete-then-put created for concurrent readers.
    match state
        .storage
        .put_from_path(key, temp_path, Some(sha256))
        .await
    {
        Ok(()) => {
            temp_guard.disarm();
            state.metrics.record_upload("raw");
            state.activity.push(ActivityEntry::new(
                ActionType::Push,
                path.to_string(),
                crate::registry_type::RegistryType::Raw,
                "LOCAL",
            ));
            state
                .audit
                .log(AuditEntry::new("overwrite", "api", path, "raw", ""));
            state.repo_index.invalidate("raw");
            StatusCode::OK.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, key = %key, "Failed to store raw artifact");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn delete_file(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Extension(authority): Extension<NamespaceAuthority>,
) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let key = storage_key(&path);
    if validate_storage_key(&key).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Enforce OIDC namespace_scope on the artifact coordinate (#583).
    if enforce_namespace_scope(&authority, &path).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    match state.storage.delete(&key).await {
        Ok(()) => {
            state
                .audit
                .log(AuditEntry::new("delete", "api", &path, "raw", ""));
            state.repo_index.invalidate("raw");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(crate::storage::StorageError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, key = %key, "Failed to delete raw artifact");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn check_exists(State(state): State<AppState>, Path(path): Path<String>) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let key = storage_key(&path);
    if validate_storage_key(&key).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state.storage.stat(&key).await {
        Some(meta) => {
            let mut builder = axum::http::Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_LENGTH, meta.size.to_string())
                .header(header::CONTENT_TYPE, guess_content_type(&key))
                .header(header::CACHE_CONTROL, &state.config.raw.cache_control);
            if let Some(hash) = state.storage.get_pin_hash(&key) {
                builder = builder.header(header::ETAG, format!("\"{}\"", hash));
            }
            if meta.modified > 0 {
                builder = builder.header(header::LAST_MODIFIED, format_http_date(meta.modified));
            }
            builder
                .body(axum::body::Body::empty())
                .expect("valid response")
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Temp directory for streamed raw uploads, created on demand. Lives inside
/// the storage path so the local backend's commit is a same-filesystem rename.
fn raw_upload_temp_dir(data_dir: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(data_dir).join("tmp/raw-uploads");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::error!(path = %dir.display(), error = %e, "failed to create raw upload temp directory");
    }
    dir
}

/// Format a Unix timestamp as an HTTP-date (RFC 7231 §7.1.1.1).
fn format_http_date(timestamp: u64) -> String {
    use chrono::{TimeZone, Utc};
    let dt = Utc.timestamp_opt(timestamp as i64, 0).single();
    match dt {
        Some(dt) => dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        None => String::new(),
    }
}

fn guess_content_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext.to_lowercase().as_str() {
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "yaml" | "yml" => "application/x-yaml",
        "toml" => "application/toml",
        "tar" => "application/x-tar",
        "gz" | "gzip" => "application/gzip",
        "zip" => "application/zip",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guess_content_type_json() {
        assert_eq!(guess_content_type("config.json"), "application/json");
    }

    #[test]
    fn test_guess_content_type_xml() {
        assert_eq!(guess_content_type("data.xml"), "application/xml");
    }

    #[test]
    fn test_guess_content_type_html() {
        assert_eq!(guess_content_type("index.html"), "text/html");
        assert_eq!(guess_content_type("page.htm"), "text/html");
    }

    #[test]
    fn test_guess_content_type_css() {
        assert_eq!(guess_content_type("style.css"), "text/css");
    }

    #[test]
    fn test_guess_content_type_js() {
        assert_eq!(guess_content_type("app.js"), "application/javascript");
    }

    #[test]
    fn test_guess_content_type_text() {
        assert_eq!(guess_content_type("readme.txt"), "text/plain");
    }

    #[test]
    fn test_guess_content_type_markdown() {
        assert_eq!(guess_content_type("README.md"), "text/markdown");
    }

    #[test]
    fn test_guess_content_type_yaml() {
        assert_eq!(guess_content_type("config.yaml"), "application/x-yaml");
        assert_eq!(guess_content_type("config.yml"), "application/x-yaml");
    }

    #[test]
    fn test_guess_content_type_toml() {
        assert_eq!(guess_content_type("Cargo.toml"), "application/toml");
    }

    #[test]
    fn test_guess_content_type_archives() {
        assert_eq!(guess_content_type("data.tar"), "application/x-tar");
        assert_eq!(guess_content_type("data.gz"), "application/gzip");
        assert_eq!(guess_content_type("data.gzip"), "application/gzip");
        assert_eq!(guess_content_type("data.zip"), "application/zip");
    }

    #[test]
    fn test_guess_content_type_images() {
        assert_eq!(guess_content_type("logo.png"), "image/png");
        assert_eq!(guess_content_type("photo.jpg"), "image/jpeg");
        assert_eq!(guess_content_type("photo.jpeg"), "image/jpeg");
        assert_eq!(guess_content_type("anim.gif"), "image/gif");
        assert_eq!(guess_content_type("icon.svg"), "image/svg+xml");
    }

    #[test]
    fn test_guess_content_type_special() {
        assert_eq!(guess_content_type("doc.pdf"), "application/pdf");
        assert_eq!(guess_content_type("module.wasm"), "application/wasm");
    }

    #[test]
    fn test_guess_content_type_unknown() {
        assert_eq!(guess_content_type("binary.bin"), "application/octet-stream");
        assert_eq!(guess_content_type("noext"), "application/octet-stream");
    }

    #[test]
    fn test_guess_content_type_case_insensitive() {
        assert_eq!(guess_content_type("FILE.JSON"), "application/json");
        assert_eq!(guess_content_type("IMAGE.PNG"), "image/png");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::storage::{Storage, StorageError};
    use crate::test_helpers::{
        body_bytes, create_test_context, create_test_context_with_raw_disabled, send,
        send_with_headers,
    };
    use axum::http::{Method, StatusCode};

    fn scoped(mode: crate::config::ScopeEnforcement) -> crate::auth::NamespaceAuthority {
        crate::auth::NamespaceAuthority::from_oidc_scope("ci", &["myorg/**".to_string()], mode)
    }

    #[tokio::test]
    async fn test_raw_namespace_scope_enforced() {
        use crate::config::ScopeEnforcement;
        use axum::body::Body;
        use axum::extract::{Path, State};
        use axum::Extension;

        let ctx = create_test_context();

        // Out of scope -> 403, and nothing is written.
        let resp = super::upload(
            State(ctx.state.clone()),
            Path("other/secret.txt".to_string()),
            Extension(scoped(ScopeEnforcement::Enforce)),
            axum::http::HeaderMap::new(),
            Body::from(&b"x"[..]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(ctx.state.storage.get("raw/other/secret.txt").await.is_err());

        // In scope -> created.
        let resp = super::upload(
            State(ctx.state.clone()),
            Path("myorg/app/file.txt".to_string()),
            Extension(scoped(ScopeEnforcement::Enforce)),
            axum::http::HeaderMap::new(),
            Body::from(&b"x"[..]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // DELETE out of scope -> 403.
        let resp = super::delete_file(
            State(ctx.state.clone()),
            Path("other/secret.txt".to_string()),
            Extension(scoped(ScopeEnforcement::Enforce)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Audit mode allows an out-of-scope write (only logs/counts).
        let resp = super::upload(
            State(ctx.state.clone()),
            Path("elsewhere/a.txt".to_string()),
            Extension(scoped(ScopeEnforcement::Audit)),
            axum::http::HeaderMap::new(),
            Body::from(&b"x"[..]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_raw_put_get_roundtrip() {
        let ctx = create_test_context();
        let put_resp = send(&ctx.app, Method::PUT, "/raw/test.txt", b"hello".to_vec()).await;
        assert_eq!(put_resp.status(), StatusCode::CREATED);

        let get_resp = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = body_bytes(get_resp).await;
        assert_eq!(&body[..], b"hello");
    }

    #[tokio::test]
    async fn test_raw_head() {
        let ctx = create_test_context();
        send(
            &ctx.app,
            Method::PUT,
            "/raw/test.txt",
            b"hello world".to_vec(),
        )
        .await;

        let head_resp = send(&ctx.app, Method::HEAD, "/raw/test.txt", "").await;
        assert_eq!(head_resp.status(), StatusCode::OK);
        let cl = head_resp.headers().get("content-length").unwrap();
        assert_eq!(cl.to_str().unwrap(), "11");
    }

    #[tokio::test]
    async fn test_raw_delete() {
        let ctx = create_test_context();
        send(&ctx.app, Method::PUT, "/raw/test.txt", b"data".to_vec()).await;

        let del = send(&ctx.app, Method::DELETE, "/raw/test.txt", "").await;
        assert_eq!(del.status(), StatusCode::NO_CONTENT);

        let get = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
        assert_eq!(get.status(), StatusCode::NOT_FOUND);
    }

    /// Uploads stream to disk: a multi-megabyte body (many frames) round-trips,
    /// records an integrity pin (ETag present), and leaves no temp file behind.
    #[tokio::test]
    async fn test_raw_streamed_upload_roundtrip_and_temp_hygiene() {
        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.raw.max_file_size = 16 * 1024 * 1024
        });
        // ~3.2MB of non-repeating bytes — crosses many body frames.
        let body: Vec<u8> = (0..800_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let put = send(&ctx.app, Method::PUT, "/raw/big.bin", body.clone()).await;
        assert_eq!(put.status(), StatusCode::CREATED);

        let get = send(&ctx.app, Method::GET, "/raw/big.bin", "").await;
        assert_eq!(get.status(), StatusCode::OK);
        assert!(
            get.headers().get("etag").is_some(),
            "pin must survive streaming"
        );
        let got = body_bytes(get).await;
        assert_eq!(got.len(), body.len());
        assert_eq!(&got[..], &body[..]);

        let tmp = std::path::Path::new(&ctx.state.config.storage.path).join("tmp/raw-uploads");
        let leftovers = std::fs::read_dir(&tmp).map(|d| d.count()).unwrap_or(0);
        assert_eq!(
            leftovers, 0,
            "temp file must be consumed by the commit rename"
        );
    }

    /// The size cap rejects mid-stream (413), stores nothing, leaks no temp.
    #[tokio::test]
    async fn test_raw_streamed_upload_too_large_rejected_midstream() {
        let ctx = create_test_context(); // 1 MB cap
        let body = vec![0u8; 2 * 1024 * 1024];
        let put = send(&ctx.app, Method::PUT, "/raw/big.bin", body).await;
        assert_eq!(put.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(ctx.state.storage.stat("raw/big.bin").await.is_none());
        let tmp = std::path::Path::new(&ctx.state.config.storage.path).join("tmp/raw-uploads");
        let leftovers = std::fs::read_dir(&tmp).map(|d| d.count()).unwrap_or(0);
        assert_eq!(leftovers, 0, "aborted stream must not leak its temp file");
    }

    /// A tampered object must never arrive complete: the streamed read hashes
    /// while serving and aborts the body before its final frame on a pin
    /// mismatch — the client sees a broken transfer, not a corrupt file.
    #[tokio::test]
    async fn test_raw_streamed_read_aborts_on_tamper() {
        let ctx = create_test_context();
        let body = vec![7u8; 300_000];
        let put = send(&ctx.app, Method::PUT, "/raw/pinned.bin", body.clone()).await;
        assert_eq!(put.status(), StatusCode::CREATED);

        // Corrupt the object behind the pin store's back.
        let on_disk = std::path::Path::new(&ctx.state.config.storage.path).join("raw/pinned.bin");
        let mut tampered = std::fs::read(&on_disk).unwrap();
        tampered[150_000] ^= 0xFF;
        std::fs::write(&on_disk, &tampered).unwrap();

        let resp = send(&ctx.app, Method::GET, "/raw/pinned.bin", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "status is already committed when streaming"
        );
        let collected = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
        match collected {
            Err(_) => {} // body errored mid-stream — the fail-closed signal
            Ok(bytes) => assert!(
                bytes.len() < body.len(),
                "tampered object must not arrive complete ({} of {} bytes)",
                bytes.len(),
                body.len()
            ),
        }
    }

    /// An oversized declared Content-Length is rejected before the body is read.
    #[tokio::test]
    async fn test_raw_content_length_fast_reject() {
        let ctx = create_test_context();
        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/big.bin",
            vec![("content-length", "99999999")],
            vec![0u8; 8],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_raw_not_found() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::GET, "/raw/missing.txt", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_raw_immutable_overwrite_rejected() {
        let ctx = create_test_context();
        let put1 = send(
            &ctx.app,
            Method::PUT,
            "/raw/immutable.txt",
            b"first".to_vec(),
        )
        .await;
        assert_eq!(put1.status(), StatusCode::CREATED);

        let put2 = send(
            &ctx.app,
            Method::PUT,
            "/raw/immutable.txt",
            b"second".to_vec(),
        )
        .await;
        assert_eq!(put2.status(), StatusCode::CONFLICT);

        // Verify original content preserved
        let get = send(&ctx.app, Method::GET, "/raw/immutable.txt", "").await;
        assert_eq!(get.status(), StatusCode::OK);
        let body = body_bytes(get).await;
        assert_eq!(&body[..], b"first");
    }

    #[tokio::test]
    async fn test_raw_content_type_json() {
        let ctx = create_test_context();
        send(&ctx.app, Method::PUT, "/raw/file.json", b"{}".to_vec()).await;

        let resp = send(&ctx.app, Method::GET, "/raw/file.json", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get("content-type").unwrap();
        assert_eq!(ct.to_str().unwrap(), "application/json");
    }

    #[tokio::test]
    async fn test_raw_payload_too_large() {
        let ctx = create_test_context();
        let big = vec![0u8; 2 * 1024 * 1024]; // 2 MB > 1 MB limit
        let resp = send(&ctx.app, Method::PUT, "/raw/large.bin", big).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_raw_disabled() {
        let ctx = create_test_context_with_raw_disabled();
        let get = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
        assert_eq!(get.status(), StatusCode::NOT_FOUND);
        let put = send(&ctx.app, Method::PUT, "/raw/test.txt", b"data".to_vec()).await;
        assert_eq!(put.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_raw_reindex_endpoint() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::POST, "/raw/-/reindex", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_raw_reindex_disabled() {
        let ctx = create_test_context_with_raw_disabled();
        let resp = send(&ctx.app, Method::POST, "/raw/-/reindex", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_raw_curation_blocks_download() {
        use crate::config::CurationMode;

        // Create a blocklist file
        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist_path,
            r#"{"version": 1, "rules": [{"registry": "raw", "name": "secret*", "version": "*", "reason": "blocked"}]}"#,
        ).unwrap();

        let bp = blocklist_path.to_str().unwrap().to_string();
        let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bp);
        });

        // Upload a file first (upload is not curated)
        let put = send(&ctx.app, Method::PUT, "/raw/secret.txt", b"data".to_vec()).await;
        assert_eq!(put.status(), StatusCode::CREATED);

        // Download should be blocked by curation
        let get = send(&ctx.app, Method::GET, "/raw/secret.txt", "").await;
        assert_eq!(get.status(), StatusCode::FORBIDDEN);

        // Non-matching file should pass
        let put2 = send(&ctx.app, Method::PUT, "/raw/public.txt", b"ok".to_vec()).await;
        assert_eq!(put2.status(), StatusCode::CREATED);
        let get2 = send(&ctx.app, Method::GET, "/raw/public.txt", "").await;
        assert_eq!(get2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_upload_path_traversal_rejected() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_str().unwrap());

        let result = storage.put("raw/../../../etc/passwd", b"pwned").await;
        assert!(result.is_err(), "path traversal key must be rejected");
        match result {
            Err(StorageError::Validation(v)) => {
                assert_eq!(format!("{}", v), "Path traversal detected");
            }
            other => panic!("expected Validation(PathTraversal), got {:?}", other),
        }
    }

    // --- RFC 9110 conditional request tests ---

    #[tokio::test]
    async fn test_raw_head_returns_etag() {
        let ctx = create_test_context();
        send(&ctx.app, Method::PUT, "/raw/etag.txt", b"hello".to_vec()).await;

        // The ETag is the hash-pin, recorded fire-and-forget after PUT. Wait for
        // it to land so HEAD deterministically sees the ETag — otherwise the
        // pin task can be starved under a full parallel suite and the header is
        // absent (#603). Polls (fast path = immediate), no fixed sleep.
        for _ in 0..200 {
            if ctx.state.storage.get_pin_hash("raw/etag.txt").is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let head = send(&ctx.app, Method::HEAD, "/raw/etag.txt", "").await;
        assert_eq!(head.status(), StatusCode::OK);
        let etag = head.headers().get("etag").expect("HEAD must return ETag");
        let val = etag.to_str().unwrap();
        assert!(
            val.starts_with('"') && val.ends_with('"'),
            "ETag must be quoted"
        );
        assert!(val.len() > 2, "ETag must contain a hash");
    }

    #[tokio::test]
    async fn test_raw_head_returns_last_modified() {
        let ctx = create_test_context();
        send(&ctx.app, Method::PUT, "/raw/lm.txt", b"hello".to_vec()).await;

        let head = send(&ctx.app, Method::HEAD, "/raw/lm.txt", "").await;
        assert_eq!(head.status(), StatusCode::OK);
        let lm = head
            .headers()
            .get("last-modified")
            .expect("HEAD must return Last-Modified");
        let val = lm.to_str().unwrap();
        assert!(val.contains("GMT"), "Last-Modified must be HTTP-date");
    }

    #[tokio::test]
    async fn test_raw_put_if_none_match_star_creates() {
        let ctx = create_test_context();
        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/new.txt",
            vec![("if-none-match", "*")],
            b"content".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_raw_put_if_none_match_star_rejects_existing() {
        let ctx = create_test_context();
        send(&ctx.app, Method::PUT, "/raw/exists.txt", b"v1".to_vec()).await;

        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/exists.txt",
            vec![("if-none-match", "*")],
            b"v2".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn test_raw_put_if_match_etag_overwrites() {
        let ctx = create_test_context();
        send(&ctx.app, Method::PUT, "/raw/up.txt", b"v1".to_vec()).await;

        // Get the ETag
        let head = send(&ctx.app, Method::HEAD, "/raw/up.txt", "").await;
        let etag = head
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/up.txt",
            vec![("if-match", &etag)],
            b"v2".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_raw_put_if_match_etag_wrong_rejects() {
        let ctx = create_test_context();
        send(&ctx.app, Method::PUT, "/raw/wrong.txt", b"v1".to_vec()).await;

        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/wrong.txt",
            vec![(
                "if-match",
                "\"0000000000000000000000000000000000000000000000000000000000000000\"",
            )],
            b"v2".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn test_raw_put_if_match_star_overwrites_existing() {
        let ctx = create_test_context();
        send(&ctx.app, Method::PUT, "/raw/star.txt", b"v1".to_vec()).await;

        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/star.txt",
            vec![("if-match", "*")],
            b"v2".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_raw_put_if_match_star_rejects_missing() {
        let ctx = create_test_context();
        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/ghost.txt",
            vec![("if-match", "*")],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn test_raw_put_no_headers_still_409() {
        let ctx = create_test_context();
        let put1 = send(&ctx.app, Method::PUT, "/raw/compat.txt", b"v1".to_vec()).await;
        assert_eq!(put1.status(), StatusCode::CREATED);

        let put2 = send(&ctx.app, Method::PUT, "/raw/compat.txt", b"v2".to_vec()).await;
        assert_eq!(put2.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_raw_get_if_none_match_returns_304() {
        let ctx = create_test_context();
        send(&ctx.app, Method::PUT, "/raw/cached.txt", b"hello".to_vec()).await;

        // Get the ETag
        let head = send(&ctx.app, Method::HEAD, "/raw/cached.txt", "").await;
        let etag = head
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/cached.txt",
            vec![("if-none-match", &etag)],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn test_raw_overwrite_updates_content() {
        let ctx = create_test_context();
        send(
            &ctx.app,
            Method::PUT,
            "/raw/update.txt",
            b"original".to_vec(),
        )
        .await;

        // Get ETag for conditional overwrite
        let head = send(&ctx.app, Method::HEAD, "/raw/update.txt", "").await;
        let etag = head
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Overwrite
        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/update.txt",
            vec![("if-match", &etag)],
            b"updated".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify new content
        let get = send(&ctx.app, Method::GET, "/raw/update.txt", "").await;
        assert_eq!(get.status(), StatusCode::OK);
        let body = body_bytes(get).await;
        assert_eq!(&body[..], b"updated");
    }

    #[tokio::test]
    async fn test_raw_cache_control_default() {
        let ctx = create_test_context();
        send(&ctx.app, Method::PUT, "/raw/cc.txt", b"data".to_vec()).await;

        let get = send(&ctx.app, Method::GET, "/raw/cc.txt", "").await;
        assert_eq!(get.status(), StatusCode::OK);
        let cc = get
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cc, "no-cache");
    }
}
