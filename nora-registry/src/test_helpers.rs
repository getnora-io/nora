// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Shared test infrastructure for integration tests.
//!
//! Provides `TestContext` that builds a full axum Router backed by a
//! tempdir-based local storage with all upstream proxies disabled.

#![allow(clippy::unwrap_used)] // tests may use .unwrap() freely

use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit},
    http::Request,
    middleware, Router,
};
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;

use crate::activity_log::ActivityLog;
use crate::audit::AuditLog;
use crate::auth::HtpasswdAuth;
use crate::config::*;
use crate::curation::CurationEngine;
use crate::dashboard_metrics::DashboardMetrics;
use crate::registry;
use crate::repo_index::RepoIndex;
use crate::storage::Storage;
use crate::tokens::TokenStore;
use crate::AppState;

use parking_lot::RwLock;

/// Everything a test needs: tempdir (must stay alive), shared state, and the router.
pub struct TestContext {
    pub state: AppState,
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

/// Build a test context with auth + `docker_anon_pull` (general
/// `anonymous_read` left OFF, to prove Docker is governed by its own switch).
pub fn create_test_context_with_docker_anon_pull(users: &[(&str, &str)]) -> TestContext {
    build_context(true, users, false, |cfg| {
        cfg.auth.docker_anon_pull = true;
    })
}

/// Build a test context with raw storage **disabled**.
pub fn create_test_context_with_raw_disabled() -> TestContext {
    build_context(false, &[], false, |cfg| cfg.raw.enabled = false)
}

/// Build a test context with custom config tweaks.
pub fn create_test_context_with_config(customize: impl FnOnce(&mut Config)) -> TestContext {
    build_context(false, &[], false, customize)
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
            proxy_coalesce: true,
            // Permissive test fixture: trust upstream dates so existing handler
            // tests exercise the upstream-date path (prod default is false/secure;
            // the trust=false path has its own dedicated tests).
            trust_upstream_dates: true,
        },
        storage: StorageConfig {
            mode: StorageMode::Local,
            path: storage_path.clone(),
            s3_url: String::new(),
            bucket: String::new(),
            s3_access_key: None,
            s3_secret_key: None,
            s3_region: String::new(),
            s3_virtual_hosted: false,
        },
        maven: MavenConfig {
            enabled: true,
            proxies: vec![],
            proxy_timeout: 5,
            checksum_verify: true,
            immutable_releases: true,
            metadata_ttl: 300,
        },
        npm: NpmConfig {
            enabled: true,
            proxy: None,
            proxy_auth: None,
            proxy_timeout: 5,
            metadata_ttl: -1,
            serve_stale: true,
            revalidate: true,
        },
        pypi: PypiConfig {
            enabled: true,
            proxy: None,
            proxy_auth: None,
            proxies: Vec::new(),
            proxy_timeout: 5,
        },
        go: GoConfig {
            enabled: true,
            proxy: None,
            proxy_auth: None,
            proxy_timeout: 5,
            proxy_timeout_zip: 30,
            max_zip_size: 10_485_760,
            metadata_ttl: 300,
        },
        cargo: CargoConfig {
            enabled: true,
            proxy: None,
            proxy_auth: None,
            proxy_timeout: 5,
            metadata_ttl: 300,
        },
        docker: DockerConfig {
            enabled: true,
            proxy_timeout: 5,
            read_timeout: 60,
            metadata_ttl: -1,
            serve_stale: true,
            default_action: crate::config::DefaultAction::Allow,
            upstreams: vec![],
        },
        raw: RawConfig {
            enabled: true,
            max_file_size: 1_048_576, // 1 MB
            cache_control: "no-cache".to_string(),
        },
        gems: GemsConfig::default(),
        terraform: TerraformConfig::default(),
        ansible: AnsibleConfig::default(),
        nuget: NugetConfig::default(),
        pub_dart: crate::config::PubDartConfig::default(),
        conan: crate::config::ConanConfig::default(),
        auth: AuthConfig {
            enabled: auth_enabled,
            anonymous_read,
            docker_anon_pull: false,
            htpasswd_file: String::new(),
            token_storage: tempdir.path().join("tokens").to_str().unwrap().to_string(),
            token_cache_ttl: 300,
            trusted_proxies: crate::config::TrustedProxies::default_loopback(),
            oidc: crate::config::OidcConfig::default(),
            admin_users: Vec::new(),
        },
        rate_limit: RateLimitConfig {
            enabled: false,
            ..RateLimitConfig::default()
        },
        secrets: SecretsConfig::default(),
        gc: crate::config::GcConfig::default(),
        retention: crate::config::RetentionConfig::default(),
        curation: CurationConfig::default(),
        circuit_breaker: crate::config::CircuitBreakerConfig::default(),
        tls: crate::config::TlsConfig::default(),
        audit: crate::config::AuditConfig::default(),
        registries: None,
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

    let docker_auth =
        registry::DockerAuth::new(reqwest::Client::new(), config.docker.proxy_timeout);

    // Build curation engine before consuming config (mirroring main.rs)
    let mut curation_engine = CurationEngine::new(config.curation.clone());
    if let Some(ref path) = config.curation.blocklist_path {
        if let Ok(filter) = crate::curation::BlocklistFilter::from_file(path) {
            curation_engine.add_filter(Box::new(filter));
        }
    }
    if let Some(ref path) = config.curation.allowlist_path {
        if let Ok(filter) =
            crate::curation::AllowlistFilter::from_file(path, config.curation.require_integrity)
        {
            curation_engine.add_filter(Box::new(filter));
        }
    }
    if !config.curation.internal_namespaces.is_empty() {
        let ns_filter =
            crate::curation::NamespaceFilter::new(config.curation.internal_namespaces.clone());
        curation_engine.set_namespace_filter(Box::new(ns_filter));
    }

    let enabled_registries = config.enabled_registries();
    let cb_config = config.circuit_breaker.clone();

    let bypass_token = config.curation.bypass_token.clone();
    let reloadable = Arc::new(arc_swap::ArcSwap::from_pointee(crate::ReloadableConfig {
        curation_engine,
        bypass_token,
    }));

    let leak_finders = crate::metrics::LeakFinders::new(config.upstream_hostnames());

    let enabled_registries = Arc::new(enabled_registries);
    let state = AppState {
        storage,
        config: Arc::new(config),
        enabled_registries: enabled_registries.clone(),
        start_time: Instant::now(),
        startup_duration_ms: 0,
        auth: auth.map(Arc::new),
        tokens,
        metrics: Arc::new(DashboardMetrics::new()),
        activity: Arc::new(ActivityLog::new(50)),
        audit: Arc::new(AuditLog::new(&storage_path, crate::audit::AuditMode::Off)),
        docker_auth: Arc::new(docker_auth),
        repo_index: Arc::new(RepoIndex::new()),
        http_client: reqwest::Client::new(),
        upload_sessions: Arc::new(RwLock::new(HashMap::new())),
        publish_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        reloadable,
        auth_failures: Arc::new(crate::auth::AuthFailureTracker::new(5, 900)),
        oidc: None,
        circuit_breaker: Arc::new(crate::circuit_breaker::CircuitBreakerRegistry::new(
            cb_config,
        )),
        proxy_coalesce: crate::proxy_coalesce::InflightMap::new(),
        digest_store: Arc::new(crate::digest_quarantine::DigestStore::empty(&storage_path)),
        leak_finders,
        cancel_token: tokio_util::sync::CancellationToken::new(),
    };

    // Build router identical to run_server() but without TcpListener / rate-limiting
    // Dynamic route merging based on enabled registries
    let mut registry_routes = Router::new();
    for reg in enabled_registries.iter() {
        match reg {
            crate::registry_type::RegistryType::Docker => {
                registry_routes = registry_routes.merge(registry::docker_routes());
            }
            crate::registry_type::RegistryType::Maven => {
                registry_routes = registry_routes.merge(registry::maven_routes());
            }
            crate::registry_type::RegistryType::Npm => {
                registry_routes = registry_routes.merge(registry::npm_routes());
            }
            crate::registry_type::RegistryType::Cargo => {
                registry_routes = registry_routes.merge(registry::cargo_routes());
            }
            crate::registry_type::RegistryType::PyPI => {
                registry_routes = registry_routes.merge(registry::pypi_routes());
            }
            crate::registry_type::RegistryType::Raw => {
                registry_routes = registry_routes.merge(registry::raw_routes());
            }
            crate::registry_type::RegistryType::Go => {
                registry_routes = registry_routes.merge(registry::go_routes());
            }
            crate::registry_type::RegistryType::Gems => {
                registry_routes = registry_routes.merge(registry::gems_routes());
            }
            crate::registry_type::RegistryType::Terraform => {
                registry_routes = registry_routes.merge(registry::terraform_routes());
            }
            crate::registry_type::RegistryType::Ansible => {
                registry_routes = registry_routes.merge(registry::ansible_routes());
            }
            crate::registry_type::RegistryType::Nuget => {
                registry_routes = registry_routes.merge(registry::nuget_routes());
            }
            crate::registry_type::RegistryType::PubDart => {
                registry_routes = registry_routes.merge(registry::pub_dart_routes());
            }
            crate::registry_type::RegistryType::Conan => {
                registry_routes = registry_routes.merge(registry::conan_routes());
            }
        }
    }

    let public_routes = Router::new().merge(crate::health::routes());

    let app_routes = Router::new()
        .merge(crate::auth::token_routes())
        .merge(crate::ui::routes())
        .merge(registry_routes);

    let app = Router::new()
        .merge(public_routes)
        .merge(app_routes)
        .merge(crate::admin::routes())
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

    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(body.into())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));

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
    let mut request = builder.body(body.into()).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));

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
