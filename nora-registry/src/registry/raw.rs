// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
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
