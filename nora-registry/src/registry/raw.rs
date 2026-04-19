// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/raw/{*path}",
        get(download)
            .put(upload)
            .delete(delete_file)
            .head(check_exists),
    )
}

async fn download(State(state): State<Arc<AppState>>, Path(path): Path<String>) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let key = format!("raw/{}", path);
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
            (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], data).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn upload(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    body: Bytes,
) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
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

    let key = format!("raw/{}", path);

    // Immutable: reject overwrite of existing files
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;

    if state.storage.stat(&key).await.is_some() {
        return (
            StatusCode::CONFLICT,
            format!("File already exists: {}", path),
        )
            .into_response();
    }

    match state.storage.put(&key, &body).await {
        Ok(()) => {
            state.metrics.record_upload("raw");
            state
                .activity
                .push(ActivityEntry::new(ActionType::Push, path, "raw", "LOCAL"));
            state
                .audit
                .log(AuditEntry::new("push", "api", "", "raw", ""));
            StatusCode::CREATED.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn delete_file(State(state): State<Arc<AppState>>, Path(path): Path<String>) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let key = format!("raw/{}", path);
    match state.storage.delete(&key).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(crate::storage::StorageError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn check_exists(State(state): State<Arc<AppState>>, Path(path): Path<String>) -> Response {
    if !state.config.raw.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    let key = format!("raw/{}", path);
    match state.storage.stat(&key).await {
        Some(meta) => (
            StatusCode::OK,
            [
                (header::CONTENT_LENGTH, meta.size.to_string()),
                (header::CONTENT_TYPE, guess_content_type(&key).to_string()),
            ],
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
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
}
