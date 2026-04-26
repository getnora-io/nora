// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

//! Shared test infrastructure for integration tests.
//!
//! Provides `TestContext` that builds a full axum Router backed by a
//! tempdir-based local storage with all upstream proxies disabled.

#![allow(clippy::unwrap_used)] // tests may use .unwrap() freely

use axum::{body::Body, extract::DefaultBodyLimit, http::Request, middleware, Router};
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;

use crate::activity_log::ActivityLog;
use crate::audit::AuditLog;
use crate::auth::HtpasswdAuth;
use crate::config::*;
use crate::dashboard_metrics::DashboardMetrics;
use crate::registry;
use crate::repo_index::RepoIndex;
use crate::storage::Storage;
use crate::tokens::TokenStore;
use crate::AppState;

use parking_lot::RwLock;

/// Everything a test needs: tempdir (must stay alive), shared state, and the router.
pub struct TestContext {
    pub state: Arc<AppState>,
    pub app: Router,
    pub _tempdir: TempDir,
}

/// Build a test context with auth **disabled** and all proxies off.
pub fn create_test_context() -> TestContext {
    build_context(false, &[], false, |_| {})
}

/// Build a test context with auth **enabled** (bcrypt cost=4 for speed).
pub fn create_test_context_with_auth(users: &[(&str, &str)]) -> TestContext {
    build_context(true, users, false, |_| {})
}

/// Build a test context with auth + anonymous_read.
pub fn create_test_context_with_anonymous_read(users: &[(&str, &str)]) -> TestContext {
    build_context(true, users, true, |_| {})
}

/// Build a test context with raw storage **disabled**.
pub fn create_test_context_with_raw_disabled() -> TestContext {
    build_context(false, &[], false, |cfg| cfg.raw.enabled = false)
}

fn build_context(
    auth_enabled: bool,
    users: &[(&str, &str)],
    anonymous_read: bool,
    customize: impl FnOnce(&mut Config),
) -> TestContext {
    let tempdir = TempDir::new().expect("failed to create tempdir");
    let storage_path = tempdir.path().to_str().unwrap().to_string();

    let mut config = Config {
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: 0,
            public_url: None,
            body_limit_mb: 2048,
        },
        storage: StorageConfig {
            mode: StorageMode::Local,
            path: storage_path.clone(),
            s3_url: String::new(),
            bucket: String::new(),
            s3_access_key: None,
            s3_secret_key: None,
            s3_region: String::new(),
        },
        maven: MavenConfig {
            proxies: vec![],
            proxy_timeout: 5,
            checksum_verify: true,
            immutable_releases: true,
        },
        npm: NpmConfig {
            proxy: None,
            proxy_auth: None,
            proxy_timeout: 5,
            metadata_ttl: 0,
        },
        pypi: PypiConfig {
            proxy: None,
            proxy_auth: None,
            proxy_timeout: 5,
        },
        go: GoConfig {
            proxy: None,
            proxy_auth: None,
            proxy_timeout: 5,
            proxy_timeout_zip: 30,
            max_zip_size: 10_485_760,
        },
        cargo: CargoConfig {
            proxy: None,
            proxy_auth: None,
            proxy_timeout: 5,
        },
        docker: DockerConfig {
            proxy_timeout: 5,
            upstreams: vec![],
        },
        raw: RawConfig {
            enabled: true,
            max_file_size: 1_048_576, // 1 MB
        },
        auth: AuthConfig {
            enabled: auth_enabled,
            anonymous_read,
            htpasswd_file: String::new(),
            token_storage: tempdir.path().join("tokens").to_str().unwrap().to_string(),
        },
        rate_limit: RateLimitConfig {
            enabled: false,
            ..RateLimitConfig::default()
        },
        secrets: SecretsConfig::default(),
        gc: crate::config::GcConfig::default(),
        retention: crate::config::RetentionConfig::default(),
    };

    // Apply any custom config tweaks
    customize(&mut config);

    let storage = Storage::new_local(&storage_path);

    let auth = if auth_enabled && !users.is_empty() {
        let htpasswd_path = tempdir.path().join("users.htpasswd");
        let mut content = String::new();
        for (username, password) in users {
            let hash = bcrypt::hash(password, 4).expect("bcrypt hash");
            content.push_str(&format!("{}:{}\n", username, hash));
        }
        std::fs::write(&htpasswd_path, &content).expect("write htpasswd");
        config.auth.htpasswd_file = htpasswd_path.to_str().unwrap().to_string();
        HtpasswdAuth::from_file(&htpasswd_path)
    } else {
        None
    };

    let tokens = if auth_enabled {
        Some(TokenStore::new(tempdir.path().join("tokens").as_path()))
    } else {
        None
    };

    let docker_auth = registry::DockerAuth::new(config.docker.proxy_timeout);

    let state = Arc::new(AppState {
        storage,
        config,
        start_time: Instant::now(),
        auth,
        tokens,
        metrics: DashboardMetrics::new(),
        activity: ActivityLog::new(50),
        audit: AuditLog::new(&storage_path),
        docker_auth,
        repo_index: RepoIndex::new(),
        http_client: reqwest::Client::new(),
        upload_sessions: Arc::new(RwLock::new(HashMap::new())),
        publish_locks: parking_lot::Mutex::new(HashMap::new()),
    });

    // Build router identical to run_server() but without TcpListener / rate-limiting
    let registry_routes = Router::new()
        .merge(registry::docker_routes())
        .merge(registry::maven_routes())
        .merge(registry::npm_routes())
        .merge(registry::cargo_routes())
        .merge(registry::pypi_routes())
        .merge(registry::raw_routes())
        .merge(registry::go_routes());

    let public_routes = Router::new().merge(crate::health::routes());

    let app_routes = Router::new()
        .merge(crate::auth::token_routes())
        .merge(crate::ui::routes())
        .merge(registry_routes);

    let app = Router::new()
        .merge(public_routes)
        .merge(app_routes)
        .layer(DefaultBodyLimit::max(
            state.config.server.body_limit_mb * 1024 * 1024,
        ))
        .layer(middleware::from_fn(
            crate::request_id::request_id_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::auth_middleware,
        ))
        .with_state(state.clone());

    TestContext {
        state,
        app,
        _tempdir: tempdir,
    }
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Send a request through the router and return the response.
pub async fn send(
    app: &Router,
    method: axum::http::Method,
    uri: &str,
    body: impl Into<Body>,
) -> axum::http::Response<Body> {
    use tower::ServiceExt;

    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(body.into())
        .unwrap();

    app.clone().oneshot(request).await.unwrap()
}

/// Send a request with custom headers.
pub async fn send_with_headers(
    app: &Router,
    method: axum::http::Method,
    uri: &str,
    headers: Vec<(&str, &str)>,
    body: impl Into<Body>,
) -> axum::http::Response<Body> {
    use tower::ServiceExt;

    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    let request = builder.body(body.into()).unwrap();

    app.clone().oneshot(request).await.unwrap()
}

/// Read the full response body into bytes.
pub async fn body_bytes(response: axum::http::Response<Body>) -> axum::body::Bytes {
    response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes()
}
