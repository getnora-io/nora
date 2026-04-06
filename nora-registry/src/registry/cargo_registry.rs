// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::proxy_fetch;
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
    if validate_storage_key(&crate_name).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let key = format!("cargo/{}/metadata.json", crate_name);

    if let Ok(data) = state.storage.get(&key).await {
        return (StatusCode::OK, data).into_response();
    }

    // Proxy fetch metadata from upstream
    let proxy_url = match &state.config.cargo.proxy {
        Some(url) => url.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let url = format!(
        "{}/api/v1/crates/{}",
        proxy_url.trim_end_matches('/'),
        crate_name
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        state.config.cargo.proxy_timeout,
        state.config.cargo.proxy_auth.as_deref(),
    )
    .await
    {
        Ok(data) => {
            let storage = state.storage.clone();
            let key_clone = key.clone();
            let data_clone = data.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &data_clone).await;
            });
            (StatusCode::OK, data).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn download(
    State(state): State<Arc<AppState>>,
    Path((crate_name, version)): Path<(String, String)>,
) -> Response {
    if validate_storage_key(&crate_name).is_err() || validate_storage_key(&version).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let key = format!(
        "cargo/{}/{}/{}-{}.crate",
        crate_name, version, crate_name, version
    );

    // Try local storage first
    if let Ok(data) = state.storage.get(&key).await {
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
        return (StatusCode::OK, data).into_response();
    }

    // Proxy fetch from upstream
    let proxy_url = match &state.config.cargo.proxy {
        Some(url) => url.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let url = format!(
        "{}/api/v1/crates/{}/{}/download",
        proxy_url.trim_end_matches('/'),
        crate_name,
        version
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        state.config.cargo.proxy_timeout,
        state.config.cargo.proxy_auth.as_deref(),
    )
    .await
    {
        Ok(data) => {
            // Cache in background
            let storage = state.storage.clone();
            let key_clone = key.clone();
            let data_clone = data.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &data_clone).await;
            });
            state.metrics.record_download("cargo");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::Pull,
                format!("{}@{}", crate_name, version),
                "cargo",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "cargo", ""));
            (StatusCode::OK, data).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_cargo_metadata_not_found() {
        let ctx = create_test_context();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/nonexistent",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_cargo_metadata_from_storage() {
        let ctx = create_test_context();
        let meta = r#"{"name":"test-crate","versions":[]}"#;
        ctx.state
            .storage
            .put("cargo/test-crate/metadata.json", meta.as_bytes())
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/cargo/api/v1/crates/test-crate", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], meta.as_bytes());
    }

    #[tokio::test]
    async fn test_cargo_download_not_found() {
        let ctx = create_test_context();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/missing/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_cargo_download_from_storage() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("cargo/my-crate/1.2.3/my-crate-1.2.3.crate", b"crate-data")
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/my-crate/1.2.3/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"crate-data");
    }
}
