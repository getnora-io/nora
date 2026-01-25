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
}

#[derive(Serialize)]
pub struct RegistriesHealth {
    pub docker: String,
    pub maven: String,
    pub npm: String,
    pub cargo: String,
    pub pypi: String,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
}

async fn health_check(State(state): State<Arc<AppState>>) -> (StatusCode, Json<HealthStatus>) {
    let storage_reachable = check_storage_reachable(&state).await;

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
        },
        registries: RegistriesHealth {
            docker: "ok".to_string(),
            maven: "ok".to_string(),
            npm: "ok".to_string(),
            cargo: "ok".to_string(),
            pypi: "ok".to_string(),
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
