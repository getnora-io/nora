// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::method_not_allowed;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
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
async fn reindex(State(state): State<Arc<AppState>>) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.repo_index.invalidate("raw");
    tracing::info!("raw index invalidated via API");
    StatusCode::OK.into_response()
}

async fn download(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let key = format!("raw/{}", path);

    // mtime fallback — Raw is always hosted (no proxy)
    let publish_date = crate::curation::extract_mtime_as_publish_date(&state.storage, &key).await;

    // Curation check — raw files are treated as name=path, no version
    if let Some(response) = crate::curation::check_download(
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::Raw,
        &path,
        None,
        publish_date,
    ) {
        return response;
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

    match state.storage.get(&key).await {
        Ok(data) => {
            state.metrics.record_download("raw");
            state
                .activity
                .push(ActivityEntry::new(ActionType::Pull, path, "raw", "LOCAL"));
            state
                .audit
                .log(AuditEntry::new("pull", "api", "", "raw", ""));

            // Guess content type from extension
            let content_type = guess_content_type(&key);
            let mut builder = axum::http::Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CACHE_CONTROL, &state.config.raw.cache_control);
            if let Some(hash) = state.storage.get_pin_hash(&key) {
                builder = builder.header(header::ETAG, format!("\"{}\"", hash));
            }
            builder
                .body(axum::body::Body::from(data))
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

async fn upload(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    if !path.is_ascii() {
        return (
            StatusCode::BAD_REQUEST,
            "Path must contain only ASCII characters",
        )
            .into_response();
    }

    // Check file size limit
    if body.len() as u64 > state.config.raw.max_file_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "File too large. Max size: {} bytes",
                state.config.raw.max_file_size
            ),
        )
            .into_response();
    }

    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string());
    let if_match = headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string());

    let key = format!("raw/{}", path);

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
            return do_overwrite(&state, &key, &path, &body).await;
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
                        return do_overwrite(&state, &key, &path, &body).await;
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

    // Create new file
    match state.storage.put(&key, &body).await {
        Ok(()) => {
            state.metrics.record_upload("raw");
            state
                .audit
                .log(AuditEntry::new("push", "api", &path, "raw", ""));
            state
                .activity
                .push(ActivityEntry::new(ActionType::Push, path, "raw", "LOCAL"));
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
async fn do_overwrite(state: &Arc<AppState>, key: &str, path: &str, body: &[u8]) -> Response {
    // Delete old, write new (within publish_lock — atomic from NORA's perspective)
    if let Err(e) = state.storage.delete(key).await {
        tracing::error!(error = %e, key = %key, "Failed to delete raw artifact before overwrite");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    match state.storage.put(key, body).await {
        Ok(()) => {
            state.metrics.record_upload("raw");
            state.activity.push(ActivityEntry::new(
                ActionType::Push,
                path.to_string(),
                "raw",
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

async fn delete_file(State(state): State<Arc<AppState>>, Path(path): Path<String>) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let key = format!("raw/{}", path);
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

async fn check_exists(State(state): State<Arc<AppState>>, Path(path): Path<String>) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let key = format!("raw/{}", path);
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
