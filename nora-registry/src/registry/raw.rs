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
    use crate::storage::{Storage, StorageError};

    #[tokio::test]
    async fn test_download_nonexistent_returns_not_found() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_str().unwrap());

        let result = storage.get("raw/does-not-exist.tar.gz").await;
        assert!(
            matches!(result, Err(StorageError::NotFound)),
            "expected NotFound, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_upload_path_traversal_rejected() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_str().unwrap());

        // The Storage wrapper calls validate_storage_key which rejects ".."
        let result = storage.put("raw/../../../etc/passwd", b"pwned").await;
        assert!(result.is_err(), "path traversal key must be rejected");
        // Specifically it should be a Validation error
        match result {
            Err(StorageError::Validation(v)) => {
                assert_eq!(format!("{}", v), "Path traversal detected");
            }
            other => panic!("expected Validation(PathTraversal), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_delete_nonexistent_returns_not_found() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_str().unwrap());

        let result = storage.delete("raw/ghost-file.bin").await;
        assert!(
            matches!(result, Err(StorageError::NotFound)),
            "delete of nonexistent key should return NotFound, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_head_nonexistent_returns_none() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_str().unwrap());

        let meta = storage.stat("raw/nothing-here").await;
        assert!(meta.is_none(), "stat on nonexistent key must return None");
    }

    #[tokio::test]
    async fn test_raw_disabled_storage_still_works_but_handler_would_404() {
        // When raw.enabled=false the HTTP handler returns 404 before touching storage.
        // Here we verify at the storage level that the key namespace still works
        // (the 404 is an HTTP-layer concern).
        // We also confirm that a valid raw key round-trips correctly.
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::new_local(temp_dir.path().to_str().unwrap());

        storage.put("raw/test-file.txt", b"hello").await.unwrap();
        let data = storage.get("raw/test-file.txt").await.unwrap();
        assert_eq!(&*data, b"hello");
    }

    #[tokio::test]
    async fn test_guess_content_type() {
        // Test the content type guessing function
        assert_eq!(super::guess_content_type("file.json"), "application/json");
        assert_eq!(super::guess_content_type("file.tar"), "application/x-tar");
        assert_eq!(super::guess_content_type("file.gz"), "application/gzip");
        assert_eq!(
            super::guess_content_type("file.unknown"),
            "application/octet-stream"
        );
        assert_eq!(
            super::guess_content_type("file"),
            "application/octet-stream"
        );
        assert_eq!(super::guess_content_type("file.PDF"), "application/pdf");
        assert_eq!(super::guess_content_type("file.YAML"), "application/x-yaml");
    }
}
