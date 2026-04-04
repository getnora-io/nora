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
