// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::validation::validate_storage_key;
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/cargo/api/v1/crates/{crate_name}", get(get_metadata))
        .route(
            "/cargo/api/v1/crates/{crate_name}/{version}/download",
            get(download),
        )
}

async fn get_metadata(
    State(state): State<Arc<AppState>>,
    Path(crate_name): Path<String>,
) -> Response {
    // Validate input to prevent path traversal
    if validate_storage_key(&crate_name).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let key = format!("cargo/{}/metadata.json", crate_name);
    match state.storage.get(&key).await {
        Ok(data) => (StatusCode::OK, data).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn download(
    State(state): State<Arc<AppState>>,
    Path((crate_name, version)): Path<(String, String)>,
) -> Response {
    // Validate inputs to prevent path traversal
    if validate_storage_key(&crate_name).is_err() || validate_storage_key(&version).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let key = format!(
        "cargo/{}/{}/{}-{}.crate",
        crate_name, version, crate_name, version
    );
    match state.storage.get(&key).await {
        Ok(data) => {
            state.metrics.record_download("cargo");
            state.metrics.record_cache_hit();
            state.activity.push(ActivityEntry::new(
                ActionType::Pull,
                format!("{}@{}", crate_name, version),
                "cargo",
                "LOCAL",
            ));
            state
                .audit
                .log(AuditEntry::new("pull", "api", "", "cargo", ""));
            (StatusCode::OK, data).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
