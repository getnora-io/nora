// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use axum::{extract::State, http::StatusCode, response::Json, routing::get, Router};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
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

/// When the maintenance loop (token flush, upload-session expiry, storage gauges) last
/// started a tick, read by `/health` (R2-49). A panic in the shipped build no longer ends
/// the process, so a loop that dies or hangs would otherwise leave a process that answers
/// probes but never flushes tokens again; a silence longer than `max_silence` fails the
/// liveness probe so the orchestrator restarts it.
pub struct MaintenanceHeartbeat {
    origin: tokio::time::Instant,
    /// Milliseconds from `origin` to the start of the last tick.
    last_beat_ms: AtomicU64,
    max_silence: Duration,
}

impl MaintenanceHeartbeat {
    /// A heartbeat that counts as a beat now, and is stalled after `max_silence` without one.
    pub fn new(max_silence: Duration) -> Self {
        Self {
            origin: tokio::time::Instant::now(),
            last_beat_ms: AtomicU64::new(0),
            max_silence,
        }
    }

    /// Record the start of a tick.
    pub fn beat(&self) {
        let ms = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_beat_ms.store(ms, Ordering::Relaxed);
    }

    /// Time since the last tick started.
    pub fn silent_for(&self) -> Duration {
        let now = self.origin.elapsed();
        now.saturating_sub(Duration::from_millis(
            self.last_beat_ms.load(Ordering::Relaxed),
        ))
    }

    /// Whether the loop has been silent for longer than it may be.
    pub fn stalled(&self) -> bool {
        self.silent_for() > self.max_silence
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
}

async fn health_check(State(state): State<AppState>) -> (StatusCode, Json<HealthStatus>) {
    // Read when the probe arrives, before the storage checks below take their time.
    let maintenance_stalled = state.maintenance.stalled();
    let storage_reachable = check_storage_reachable(&state).await;
    let total_size = state.storage.total_size().await;

    let status = if maintenance_stalled {
        "unhealthy"
    } else if storage_reachable {
        "healthy"
    } else {
        "degraded"
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

    // /health is a liveness signal — the process is up and serving. Storage
    // reachability is informational (`status: degraded`); gating liveness or the LB
    // on it turns a storage blip into a restart loop / full 502 outage for every
    // route, storage-backed or not (#869). Readiness (`/ready`) is the storage gate.
    // A maintenance loop silent too long (R2-49) is the process's own fault, which a
    // restart clears: that one fails liveness.
    if maintenance_stalled {
        tracing::warn!(
            silent_secs = state.maintenance.silent_for().as_secs(),
            "maintenance loop stalled, failing liveness"
        );
        return (StatusCode::SERVICE_UNAVAILABLE, Json(health));
    }
    (StatusCode::OK, Json(health))
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
/// live upstream probe, so `/health` stays fast and non-blocking (#468). A
/// registry keyed per upstream (Docker, PyPI) reports its worst upstream.
///
/// A registry with no recorded breaker yet (no proxy traffic since startup)
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
    use super::MaintenanceHeartbeat;
    use crate::test_helpers::{
        body_bytes, create_test_context, create_test_context_with_config, send,
    };
    use axum::http::{Method, StatusCode};
    use axum::Router;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn test_health_returns_200() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(body_str.contains("healthy"));
    }

    /// A maintenance loop that stopped ticking fails liveness (R2-49): `/health` answers 503
    /// once the loop has been silent longer than it may be, and 200 again after a tick.
    #[tokio::test]
    async fn health_is_503_while_the_maintenance_loop_is_silent_too_long() {
        let silence = Duration::from_secs(2);
        let ctx = create_test_context();
        let mut state = ctx.state.clone();
        state.maintenance = Arc::new(MaintenanceHeartbeat::new(silence));
        let app = Router::new()
            .merge(super::routes())
            .with_state(state.clone());

        state.maintenance.beat();
        let response = send(&app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);

        tokio::time::sleep(silence + Duration::from_millis(500)).await;
        let response = send(&app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["status"], "unhealthy");

        state.maintenance.beat();
        let response = send(&app, Method::GET, "/health", "").await;
        assert_eq!(response.status(), StatusCode::OK);
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

    /// Storage unreachable → `/health` stays 200 (liveness = process up) and reports
    /// `degraded`; `/ready` is the storage gate and goes 503 (#869).
    #[cfg(unix)]
    #[tokio::test]
    async fn test_health_200_degraded_when_storage_unreachable() {
        use std::os::unix::fs::PermissionsExt;
        let ctx = create_test_context();
        let dir = ctx._tempdir.path();
        let mut perms = std::fs::metadata(dir).unwrap().permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(dir, perms).unwrap();

        let health = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(health.status(), StatusCode::OK);
        let body = body_bytes(health).await;
        assert!(std::str::from_utf8(&body).unwrap().contains("degraded"));

        let ready = send(&ctx.app, Method::GET, "/ready", "").await;
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Restore write permission so TempDir::drop can clean up.
        let mut perms = std::fs::metadata(dir).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(dir, perms).unwrap();
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
            cfg.npm.proxy = Some("http://127.0.0.1:1".into());
        });

        // Trip the breaker of the configured npm upstream into Open via the cached
        // state directly: npm keys its breaker per upstream, and `/health` reports
        // the worst one under the format name.
        let key = crate::circuit_breaker::upstream_key("npm", "http://127.0.0.1:1");
        ctx.state
            .circuit_breaker
            .record_failure(&key, ProbeToken::BACKGROUND);
        ctx.state
            .circuit_breaker
            .record_failure(&key, ProbeToken::BACKGROUND);

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
