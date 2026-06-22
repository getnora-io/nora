// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use serde::Serialize;
use std::collections::HashMap;
use utoipa::ToSchema;

use crate::circuit_breaker::UpstreamHealth;
use crate::AppState;

#[derive(Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub storage: StorageHealth,
    pub registries: HashMap<String, String>,
    /// Per-upstream circuit-breaker state, keyed by registry name. Surfaced so
    /// operators without Prometheus/Grafana can see which upstreams are
    /// reachable. Read from cached in-memory state only — the `/health` path
    /// never performs a live upstream probe (#468).
    pub upstreams: HashMap<String, UpstreamHealth>,
}

#[derive(Serialize, ToSchema)]
pub struct StorageHealth {
    pub backend: String,
    pub reachable: bool,
    pub total_size_bytes: u64,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
}

async fn health_check(State(state): State<AppState>) -> (StatusCode, Json<HealthStatus>) {
    let storage_reachable = check_storage_reachable(&state).await;
    let total_size = state.storage.total_size().await;

    let status = if storage_reachable {
        "healthy"
    } else {
        "unhealthy"
    };

    let uptime = state.start_time.elapsed().as_secs();

    // Build registries map from enabled registries
    let mut registries = HashMap::new();
    for reg in state.enabled_registries.iter() {
        registries.insert(reg.as_str().to_string(), "ok".to_string());
    }

    let upstreams = build_upstreams(&state);

    let health = HealthStatus {
        status: status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        storage: StorageHealth {
            backend: state.storage.backend_name().to_string(),
            reachable: storage_reachable,
            total_size_bytes: total_size,
        },
        registries,
        upstreams,
    };

    let status_code = if storage_reachable {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(health))
}

async fn readiness_check(State(state): State<AppState>) -> StatusCode {
    if check_storage_reachable(&state).await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn check_storage_reachable(state: &AppState) -> bool {
    state.storage.health_check().await
}

/// Build the per-upstream circuit-breaker view for the `/health` response.
///
/// One entry per enabled registry, keyed by registry name. The state is read
/// from the circuit breaker's cached in-memory snapshot — this never performs a
/// live upstream probe, so `/health` stays fast and non-blocking (#468).
///
/// A registry with no recorded breaker yet (no proxy traffic since startup, or
/// the breaker is keyed differently — e.g. Docker keys per upstream URL)
/// defaults to a healthy `closed` state. When the circuit-breaker feature is
/// disabled (the default), every entry reports `disabled`.
fn build_upstreams(state: &AppState) -> HashMap<String, UpstreamHealth> {
    let cb_enabled = state.circuit_breaker.is_enabled();
    let mut upstreams = HashMap::new();
    for reg in state.enabled_registries.iter() {
        let key = reg.as_str();
        let entry = if !cb_enabled {
            UpstreamHealth {
                status: "disabled",
                failure_count: 0,
                last_failure_seconds_ago: None,
            }
        } else {
            state
                .circuit_breaker
                .health_snapshot(key)
                .unwrap_or(UpstreamHealth {
                    status: "closed",
                    failure_count: 0,
                    last_failure_seconds_ago: None,
                })
        };
        upstreams.insert(key.to_string(), entry);
    }
    upstreams
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::test_helpers::{
        body_bytes, create_test_context, create_test_context_with_config, send,
    };
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

    #[tokio::test]
    async fn test_health_registries_dynamic() {
        // Default context has all 7 v1 registries enabled
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let registries = json.get("registries").unwrap().as_object().unwrap();
        assert!(registries.contains_key("docker"));
        assert!(registries.contains_key("maven"));
        assert!(registries.contains_key("npm"));
        assert!(registries.contains_key("cargo"));
        assert!(registries.contains_key("pypi"));
        assert!(registries.contains_key("go"));
        assert!(registries.contains_key("raw"));
    }

    #[tokio::test]
    async fn test_health_disabled_registry_absent() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.enabled = false;
        });
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let registries = json.get("registries").unwrap().as_object().unwrap();
        assert!(
            !registries.contains_key("docker"),
            "disabled docker should not appear in health"
        );
        // Others should still be present
        assert!(registries.contains_key("maven"));
    }

    /// #468: `/health` exposes an `upstreams` section, one entry per enabled
    /// registry. With the circuit breaker off (the default) every entry is
    /// reported as `disabled` rather than omitted.
    #[tokio::test]
    async fn test_health_upstreams_present_disabled_by_default() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let upstreams = json
            .get("upstreams")
            .expect("health response must have an upstreams section")
            .as_object()
            .unwrap();
        assert!(upstreams.contains_key("npm"));
        assert_eq!(
            upstreams["npm"]["status"], "disabled",
            "breaker off by default → upstream status should be 'disabled'"
        );
        assert_eq!(upstreams["npm"]["failure_count"], 0);
    }

    /// #468: when the circuit breaker is enabled and has not yet seen traffic,
    /// an upstream defaults to the healthy `closed` state.
    #[tokio::test]
    async fn test_health_upstreams_closed_when_enabled_no_traffic() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.circuit_breaker.enabled = true;
        });
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let upstreams = json.get("upstreams").unwrap().as_object().unwrap();
        assert_eq!(upstreams["pypi"]["status"], "closed");
    }

    /// #468: a tripped breaker surfaces as `open` with the failure count, read
    /// from cached state (no live probe in the request path).
    #[tokio::test]
    async fn test_health_upstreams_open_breaker_surfaced() {
        use crate::circuit_breaker::ProbeToken;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 2;
            cfg.circuit_breaker.reset_timeout = 3600;
        });

        // Trip the npm breaker into Open via the cached state directly.
        ctx.state
            .circuit_breaker
            .record_failure("npm", ProbeToken::BACKGROUND);
        ctx.state
            .circuit_breaker
            .record_failure("npm", ProbeToken::BACKGROUND);

        let response = send(&ctx.app, Method::GET, "/health", "").await;
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let npm = &json.get("upstreams").unwrap()["npm"];
        assert_eq!(npm["status"], "open", "tripped breaker should report open");
        assert_eq!(npm["failure_count"], 2);
        // pypi never failed → still closed
        assert_eq!(json["upstreams"]["pypi"]["status"], "closed");
    }
}
