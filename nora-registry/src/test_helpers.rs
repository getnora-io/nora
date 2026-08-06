// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Shared test infrastructure for integration tests.
//!
//! Provides `TestContext` that builds a full axum Router backed by a
//! tempdir-based local storage with all upstream proxies disabled.

#![allow(clippy::unwrap_used)] // tests may use .unwrap() freely

use async_trait::async_trait;
use axum::body::Bytes;
use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit},
    http::Request,
    middleware, Router,
};
use http_body_util::BodyExt;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;
use tokio::io::AsyncRead;

use crate::activity_log::ActivityLog;
use crate::audit::AuditLog;
use crate::auth::HtpasswdAuth;
use crate::config::*;
use crate::curation::CurationEngine;
use crate::dashboard_metrics::DashboardMetrics;
use crate::registry;
use crate::repo_index::RepoIndex;
use crate::storage::{FileMeta, Storage, StorageBackend, StorageError};
use crate::tokens::TokenStore;
use crate::AppState;

use parking_lot::RwLock;

/// Test-only storage wrapper for exercising fail-closed behavior without
/// teaching production backends about synthetic failures.
pub struct FaultInjectBackend {
    inner: Storage,
    get_failures: HashSet<String>,
    put_failures: HashSet<String>,
    put_after_failures: HashSet<String>,
    create_failures: HashSet<String>,
    create_after_failures: HashSet<String>,
    delete_failures: HashSet<String>,
    delete_after_failures: HashSet<String>,
    stat_none: HashSet<String>,
    list_omissions: HashSet<String>,
    delete_attempts: Arc<parking_lot::Mutex<Vec<String>>>,
    get_attempts: Arc<parking_lot::Mutex<Vec<String>>>,
    list_attempts: Arc<parking_lot::Mutex<Vec<String>>>,
    write_attempts: Arc<parking_lot::Mutex<Vec<String>>>,
}

impl FaultInjectBackend {
    pub fn new(inner: Storage) -> Self {
        Self {
            inner,
            get_failures: HashSet::new(),
            put_failures: HashSet::new(),
            put_after_failures: HashSet::new(),
            create_failures: HashSet::new(),
            create_after_failures: HashSet::new(),
            delete_failures: HashSet::new(),
            delete_after_failures: HashSet::new(),
            stat_none: HashSet::new(),
            list_omissions: HashSet::new(),
            delete_attempts: Arc::new(parking_lot::Mutex::new(Vec::new())),
            get_attempts: Arc::new(parking_lot::Mutex::new(Vec::new())),
            list_attempts: Arc::new(parking_lot::Mutex::new(Vec::new())),
            write_attempts: Arc::new(parking_lot::Mutex::new(Vec::new())),
        }
    }

    pub fn fail_get(mut self, key: impl Into<String>) -> Self {
        self.get_failures.insert(key.into());
        self
    }

    pub fn fail_put(mut self, key: impl Into<String>) -> Self {
        self.put_failures.insert(key.into());
        self
    }

    pub fn fail_put_after(mut self, key: impl Into<String>) -> Self {
        self.put_after_failures.insert(key.into());
        self
    }

    pub fn fail_create(mut self, key: impl Into<String>) -> Self {
        self.create_failures.insert(key.into());
        self
    }

    pub fn fail_create_after(mut self, key: impl Into<String>) -> Self {
        self.create_after_failures.insert(key.into());
        self
    }

    pub fn fail_delete(mut self, key: impl Into<String>) -> Self {
        self.delete_failures.insert(key.into());
        self
    }

    pub fn fail_delete_after(mut self, key: impl Into<String>) -> Self {
        self.delete_after_failures.insert(key.into());
        self
    }

    #[allow(dead_code)] // consumed by binary-only cleanup tests, not lib test target
    pub fn stat_none(mut self, key: impl Into<String>) -> Self {
        self.stat_none.insert(key.into());
        self
    }

    /// Simulate an eventually-consistent object-store LIST that omits an
    /// existing exact key while GET continues to return it.
    pub fn omit_from_list(mut self, key: impl Into<String>) -> Self {
        self.list_omissions.insert(key.into());
        self
    }

    pub fn delete_attempts(&self) -> Arc<parking_lot::Mutex<Vec<String>>> {
        Arc::clone(&self.delete_attempts)
    }

    pub fn get_attempts(&self) -> Arc<parking_lot::Mutex<Vec<String>>> {
        Arc::clone(&self.get_attempts)
    }

    pub fn list_attempts(&self) -> Arc<parking_lot::Mutex<Vec<String>>> {
        Arc::clone(&self.list_attempts)
    }

    pub fn write_attempts(&self) -> Arc<parking_lot::Mutex<Vec<String>>> {
        Arc::clone(&self.write_attempts)
    }
}

#[async_trait]
impl StorageBackend for FaultInjectBackend {
    async fn put(&self, key: &str, data: &[u8]) -> crate::storage::Result<()> {
        self.write_attempts.lock().push(format!("put:{key}"));
        if self.put_failures.contains(key) {
            return Err(StorageError::Network("injected put failure".to_string()));
        }
        let result = self.inner.put(key, data).await;
        if result.is_ok() && self.put_after_failures.contains(key) {
            return Err(StorageError::Network(
                "injected post-commit put failure".to_string(),
            ));
        }
        result
    }

    async fn put_if_absent(&self, key: &str, data: &[u8]) -> crate::storage::Result<()> {
        self.write_attempts.lock().push(format!("create:{key}"));
        if self.create_failures.contains(key) {
            return Err(StorageError::Network("injected create failure".to_string()));
        }
        let result = self.inner.put_if_absent(key, data).await;
        if result.is_ok() && self.create_after_failures.contains(key) {
            return Err(StorageError::Network(
                "injected post-commit create failure".to_string(),
            ));
        }
        result
    }

    async fn get(&self, key: &str) -> crate::storage::Result<Bytes> {
        self.get_attempts.lock().push(key.to_string());
        if self.get_failures.contains(key) {
            return Err(StorageError::Network("injected get failure".to_string()));
        }
        self.inner.get(key).await
    }

    async fn delete(&self, key: &str) -> crate::storage::Result<()> {
        self.delete_attempts.lock().push(key.to_string());
        if self.delete_failures.contains(key) {
            return Err(StorageError::Network("injected delete failure".to_string()));
        }
        let result = self.inner.delete(key).await;
        if result.is_ok() && self.delete_after_failures.contains(key) {
            return Err(StorageError::Network(
                "injected post-commit delete failure".to_string(),
            ));
        }
        result
    }

    async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
        self.list_attempts.lock().push(prefix.to_string());
        let mut entries = self.inner.list(prefix).await?;
        entries.retain(|key| !self.list_omissions.contains(key));
        Ok(entries)
    }

    async fn stat(&self, key: &str) -> Option<FileMeta> {
        if self.stat_none.contains(key) {
            return None;
        }
        self.inner.stat(key).await
    }

    async fn list_with_meta(
        &self,
        prefix: &str,
    ) -> crate::storage::Result<Vec<(String, FileMeta)>> {
        let mut entries = self.inner.list_with_meta(prefix).await?;
        entries
            .retain(|(key, _)| !self.stat_none.contains(key) && !self.list_omissions.contains(key));
        Ok(entries)
    }

    async fn health_check(&self) -> bool {
        self.inner.health_check().await
    }

    async fn total_size(&self) -> u64 {
        self.inner.total_size().await
    }

    fn backend_name(&self) -> &'static str {
        "fault-inject"
    }

    async fn refresh_total_size(&self) {
        self.inner.refresh_total_size_cache().await;
    }

    async fn put_from_path(&self, key: &str, src: &Path) -> crate::storage::Result<()> {
        self.inner.put_from_path(key, src, None).await
    }

    async fn get_reader(
        &self,
        key: &str,
    ) -> crate::storage::Result<(u64, Pin<Box<dyn AsyncRead + Send + Unpin>>)> {
        self.inner.get_reader(key).await
    }
}

/// Everything a test needs: tempdir (must stay alive), shared state, and the router.
pub struct TestContext {
    pub state: AppState,
    pub app: Router,
    pub _tempdir: TempDir,
    /// Holds the signing key outside the storage root, so storage-size
    /// assertions see only artifact bytes.
    pub _signing_dir: TempDir,
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

/// Build a test context with auth + anonymous_read and custom registry config.
pub fn create_test_context_with_anonymous_read_config(
    users: &[(&str, &str)],
    customize: impl FnOnce(&mut Config),
) -> TestContext {
    build_context(true, users, true, customize)
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
            gcs_service_account_path: None,
            gcs_base_url: None,
        },
        maven: MavenConfig {
            enabled: true,
            proxies: vec![],
            proxy_timeout: 5,
            immutable_releases: true,
            metadata_ttl: 300,
            repositories: Vec::new(),
            default_repository: None,
        },
        npm: NpmConfig {
            enabled: true,
            proxy: None,
            proxy_auth: None,
            proxy_timeout: 5,
            metadata_ttl: -1,
            serve_stale: true,
            revalidate: true,
            repositories: Vec::new(),
            default_repository: None,
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
        rpm: crate::config::RpmConfig {
            enabled: true,
            ..crate::config::RpmConfig::default()
        },
        deb: crate::config::DebConfig {
            enabled: true,
            ..crate::config::DebConfig::default()
        },
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
            public_web_ui: false,
            public_metrics: true,
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
        signing: crate::config::SigningConfig::default(),
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
    let signing_dir = TempDir::new().expect("signing tempdir");
    let signer = if config.signing.enabled {
        Some(Arc::new(
            crate::signing::RepoSigner::load_or_generate(&signing_dir.path().join("signing.key"))
                .expect("test signing key"),
        ))
    } else {
        None
    };
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
        no_redirect_http_client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test no-redirect HTTP client"),
        upload_sessions: Arc::new(RwLock::new(HashMap::new())),
        publish_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        maven_negative_cache: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        reloadable,
        auth_failures: Arc::new(crate::auth::AuthFailureTracker::new(5, 900)),
        oidc: None,
        circuit_breaker: Arc::new(crate::circuit_breaker::CircuitBreakerRegistry::new(
            cb_config,
        )),
        proxy_coalesce: crate::proxy_coalesce::InflightMap::new(),
        digest_store: Arc::new(crate::digest_quarantine::DigestStore::empty(&storage_path)),
        signer,
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
            crate::registry_type::RegistryType::Rpm => {
                registry_routes = registry_routes.merge(registry::rpm_routes());
            }
            crate::registry_type::RegistryType::Deb => {
                registry_routes = registry_routes.merge(registry::deb_routes());
            }
        }
    }
    if enabled_registries.contains(&crate::registry_type::RegistryType::Maven)
        || enabled_registries.contains(&crate::registry_type::RegistryType::Npm)
    {
        registry_routes = registry_routes.merge(registry::named_repository_routes());
    }

    let public_routes = Router::new()
        .merge(crate::health::routes())
        .merge(crate::metrics::routes());

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
        _signing_dir: signing_dir,
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

/// Build a minimal, protocol-valid npm publish body for integration tests.
///
/// Keeping this in the shared test harness lets cross-router tests seed hosted
/// state through the public publish contract instead of reconstructing Nora's
/// private storage layout.
pub fn npm_publish_payload(package: &str, version: &str, tag: &str) -> Vec<u8> {
    use base64::Engine as _;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let encoder = GzEncoder::new(Vec::new(), Compression::fast());
    let mut archive = tar::Builder::new(encoder);
    let package_json = serde_json::to_vec(&serde_json::json!({
        "name": package,
        "version": version,
    }))
    .unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_size(package_json.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, "package/package.json", package_json.as_slice())
        .unwrap();
    let tarball = archive.into_inner().unwrap().finish().unwrap();
    let package_basename = package.split('/').next_back().unwrap_or(package);
    let filename = format!("{package_basename}-{version}.tgz");

    serde_json::to_vec(&serde_json::json!({
        "name": package,
        "versions": {
            (version): {
                "name": package,
                "version": version,
                "dist": {},
            },
        },
        "_attachments": {
            (filename): {
                "data": base64::engine::general_purpose::STANDARD.encode(&tarball),
                "length": tarball.len(),
            },
        },
        "dist-tags": {(tag): version},
    }))
    .unwrap()
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
