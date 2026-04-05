// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use serde::Serialize;
use std::sync::Arc;

use crate::AppState;

#[derive(Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub storage: StorageHealth,
    pub registries: RegistriesHealth,
}

#[derive(Serialize)]
pub struct StorageHealth {
    pub backend: String,
    pub reachable: bool,
    pub endpoint: String,
    pub total_size_bytes: u64,
}

#[derive(Serialize)]
pub struct RegistriesHealth {
    pub docker: String,
    pub maven: String,
    pub npm: String,
    pub cargo: String,
    pub pypi: String,
    pub go: String,
    pub raw: String,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
}

async fn health_check(State(state): State<Arc<AppState>>) -> (StatusCode, Json<HealthStatus>) {
    let storage_reachable = check_storage_reachable(&state).await;
    let total_size = state.storage.total_size().await;

    let status = if storage_reachable {
        "healthy"
    } else {
        "unhealthy"
    };

    let uptime = state.start_time.elapsed().as_secs();

    let health = HealthStatus {
        status: status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        storage: StorageHealth {
            backend: state.storage.backend_name().to_string(),
            reachable: storage_reachable,
            endpoint: match state.storage.backend_name() {
                "s3" => state.config.storage.s3_url.clone(),
                _ => state.config.storage.path.clone(),
            },
            total_size_bytes: total_size,
        },
        registries: RegistriesHealth {
            docker: "ok".to_string(),
            maven: "ok".to_string(),
            npm: "ok".to_string(),
            cargo: "ok".to_string(),
            pypi: "ok".to_string(),
            go: "ok".to_string(),
            raw: "ok".to_string(),
        },
    };

    let status_code = if storage_reachable {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(health))
}

async fn readiness_check(State(state): State<Arc<AppState>>) -> StatusCode {
    if check_storage_reachable(&state).await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn check_storage_reachable(state: &AppState) -> bool {
    state.storage.health_check().await
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_health_returns_200() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(body_str.contains("healthy"));
    }

    #[tokio::test]
    async fn test_health_json_has_version() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("version").is_some());
    }

    #[tokio::test]
    async fn test_health_json_has_storage_size() {
        let ctx = create_test_context();

        // Put some data to have non-zero size
        ctx.state
            .storage
            .put("test/artifact", b"hello world")
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let storage = json.get("storage").unwrap();
        let size = storage.get("total_size_bytes").unwrap().as_u64().unwrap();
        assert!(
            size > 0,
            "total_size_bytes should be > 0 after storing data"
        );
    }

    #[tokio::test]
    async fn test_health_empty_storage_size_zero() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let size = json["storage"]["total_size_bytes"].as_u64().unwrap();
        assert_eq!(size, 0, "empty storage should report 0 bytes");
    }

    #[tokio::test]
    async fn test_ready_returns_200() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/ready", "").await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
