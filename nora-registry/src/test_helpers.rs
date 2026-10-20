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
    Router,
};
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Build a test context over a caller-supplied backend, so handler tests can
/// run against an object store instead of the local filesystem.
pub fn create_test_context_with_storage(storage: Storage) -> TestContext {
    build_context_with(false, &[], false, |_| {}, Some(storage))
}

/// Build a test context with custom config tweaks.
pub fn create_test_context_with_config(customize: impl FnOnce(&mut Config)) -> TestContext {
    build_context(false, &[], false, customize)
}

/// Build a test context over a caller-supplied backend **and** custom config tweaks —
/// what a proxy-path test needs when it also has to observe backend round-trips.
pub fn create_test_context_with_storage_and_config(
    storage: Storage,
    customize: impl FnOnce(&mut Config),
) -> TestContext {
    build_context_with(false, &[], false, customize, Some(storage))
}

/// Build a test context with auth + anonymous_read + custom config tweaks.
/// Auth required for every request (no anonymous read), plus a custom config.
pub fn create_test_context_with_auth_and_config(
    users: &[(&str, &str)],
    customize: impl FnOnce(&mut Config),
) -> TestContext {
    build_context(true, users, false, customize)
}

pub fn create_test_context_with_anonymous_read_and_config(
    users: &[(&str, &str)],
    customize: impl FnOnce(&mut Config),
) -> TestContext {
    build_context(true, users, true, customize)
}

fn build_context(
    auth_enabled: bool,
    users: &[(&str, &str)],
    anonymous_read: bool,
    customize: impl FnOnce(&mut Config),
) -> TestContext {
    build_context_with(auth_enabled, users, anonymous_read, customize, None)
}

/// A context whose outbound HTTP clients send every request through the forward proxy at
/// `egress_proxy` (an [`EgressRecorder`]): whatever host a handler asks, the proxy sees it.
pub fn create_test_context_with_egress_proxy(
    egress_proxy: &str,
    customize: impl FnOnce(&mut Config),
) -> TestContext {
    build_context_full(false, &[], false, customize, None, Some(egress_proxy))
}

fn build_context_with(
    auth_enabled: bool,
    users: &[(&str, &str)],
    anonymous_read: bool,
    customize: impl FnOnce(&mut Config),
    storage: Option<Storage>,
) -> TestContext {
    build_context_full(
        auth_enabled,
        users,
        anonymous_read,
        customize,
        storage,
        None,
    )
}

fn build_context_full(
    auth_enabled: bool,
    users: &[(&str, &str)],
    anonymous_read: bool,
    customize: impl FnOnce(&mut Config),
    storage: Option<Storage>,
    egress_proxy: Option<&str>,
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
            shutdown_timeout: 15,
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
            checksum_verify: true,
            immutable_releases: true,
            metadata_ttl: 300,
        },
        npm: NpmConfig {
            enabled: true,
            proxy: None,
            proxy_auth: None,
            proxies: Vec::new(),
            proxy_timeout: 5,
            metadata_ttl: -1,
            serve_stale: true,
            revalidate: true,
            import_embedded: Vec::new(),
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
            import_embedded: Vec::new(),
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
        cpan: crate::config::CpanConfig::default(),
        hf: crate::config::HfConfig::default(),
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
        // Off unless a test opts in (`cfg.audit.mode = AuditMode::File`); the state
        // below builds its audit log from this mode, as main.rs does.
        audit: crate::config::AuditConfig {
            mode: crate::audit::AuditMode::Off,
        },
        registries: None,
        signing: crate::config::SigningConfig::default(),
    };

    // Apply any custom config tweaks
    customize(&mut config);

    let storage = storage.unwrap_or_else(|| Storage::new_local(&storage_path));

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

    // The curation engine is the one the server builds (main.rs `build_curation_engine`), so a
    // test sees exactly the filters production installs. A list that does not parse fails the
    // test in every mode: main.rs refuses it only in enforce, and a test that silently runs
    // without its list checks nothing.
    if let Some(ref path) = config.curation.blocklist_path {
        crate::curation::BlocklistFilter::from_file(path)
            .unwrap_or_else(|e| panic!("test blocklist {path}: {e}"));
    }
    if let Some(ref path) = config.curation.allowlist_path {
        crate::curation::AllowlistFilter::from_file(path, config.curation.require_integrity)
            .unwrap_or_else(|e| panic!("test allowlist {path}: {e}"));
    }
    let curation_engine = crate::build_curation_engine(&config)
        .unwrap_or_else(|e| panic!("test curation engine: {e}"));

    let enabled_registries = config.enabled_registries();
    let cb_config = config.circuit_breaker.clone();
    let audit_mode = config.audit.mode.clone();

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
    let (http_client, http_client_no_redirect) = match egress_proxy {
        Some(url) => {
            let proxy = || reqwest::Proxy::all(url).expect("egress proxy url");
            (
                // No idle connections: every request opens its own, so the recorder sees each one.
                reqwest::Client::builder()
                    .proxy(proxy())
                    .pool_max_idle_per_host(0)
                    .build()
                    .expect("egress client"),
                reqwest::Client::builder()
                    .proxy(proxy())
                    .pool_max_idle_per_host(0)
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .expect("egress client"),
            )
        }
        None => (
            reqwest::Client::new(),
            crate::build_no_redirect_client(&config.tls),
        ),
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
        audit: Arc::new(AuditLog::new(&storage_path, audit_mode)),
        docker_auth: Arc::new(docker_auth),
        repo_index: Arc::new(RepoIndex::new()),
        http_client,
        http_client_no_redirect,
        hf_canonical_ids: Arc::default(),
        upload_sessions: Arc::new(RwLock::new(HashMap::new())),
        publish_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        reloadable,
        auth_failures: Arc::new(crate::auth::AuthFailureTracker::new(5, 900)),
        oidc: None,
        circuit_breaker: Arc::new(crate::circuit_breaker::CircuitBreakerRegistry::new(
            cb_config,
        )),
        proxy_coalesce: crate::proxy_coalesce::InflightMap::new(),
        blob_flights: crate::proxy_coalesce::InflightMap::new(),
        digest_store: Arc::new(crate::digest_quarantine::DigestStore::empty(&storage_path)),
        signer,
        leak_finders,
        cancel_token: tokio_util::sync::CancellationToken::new(),
        pull_stats: std::sync::Arc::new(crate::registry::docker::PullStatsAccumulator::default()),
    };

    // Build router identical to run_server() but without TcpListener / rate-limiting
    // Dynamic route merging based on enabled registries
    // The server's own assembly of the registry routes (main.rs `registry_routes`).
    let registry_routes = crate::registry_routes(&enabled_registries);

    let public_routes = Router::new()
        .merge(crate::health::routes())
        .merge(crate::metrics::routes());

    let app_routes = Router::new()
        .merge(crate::auth::token_routes())
        .merge(crate::ui::routes())
        .merge(registry_routes);

    let routes = Router::new()
        .merge(public_routes)
        .merge(app_routes)
        .merge(crate::admin::routes())
        .layer(DefaultBodyLimit::max(
            state.config.server.body_limit_mb * 1024 * 1024,
        ));
    // The server's own request layers (auth, request id, audit, …), so tests run its order.
    let app = crate::request_layers(routes, &state).with_state(state.clone());

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

/// Read the full response body into bytes.
pub async fn body_bytes(response: axum::http::Response<Body>) -> axum::body::Bytes {
    response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes()
}

// ── Storage round-trip counting ─────────────────────────────────────────────

/// Backend methods an [`OpCountingBackend`] counts, in reporting order.
const COUNTED_METHODS: [&str; 11] = [
    "put",
    "get",
    "pin",
    "delete",
    "list",
    "stat",
    "list_with_meta",
    "put_from_path",
    "copy",
    "get_reader",
    "get_range",
];

/// Per-method count of backend round-trips observed by an [`OpCountingBackend`].
///
/// The counters are atomics: backend methods run in async code, where a blocking
/// lock does not belong.
#[derive(Default)]
pub struct OpCounts {
    counts: [AtomicUsize; COUNTED_METHODS.len()],
}

impl OpCounts {
    fn hit(&self, method: &'static str) {
        let slot = COUNTED_METHODS
            .iter()
            .position(|counted| *counted == method)
            .expect("every counted backend method is listed in COUNTED_METHODS");
        self.counts[slot].fetch_add(1, Ordering::Relaxed);
    }

    /// Forget everything counted so far. Call it after seeding, right before the
    /// request under test.
    pub fn reset(&self) {
        for count in &self.counts {
            count.store(0, Ordering::Relaxed);
        }
    }

    /// Round-trips counted since the last [`reset`](Self::reset).
    pub fn total(&self) -> usize {
        self.counts
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .sum()
    }

    /// Per-method counts since the last reset, leaving out methods that were not
    /// called, for assertion messages.
    pub fn snapshot(&self) -> std::collections::BTreeMap<&'static str, usize> {
        COUNTED_METHODS
            .iter()
            .zip(&self.counts)
            .map(|(method, count)| (*method, count.load(Ordering::Relaxed)))
            .filter(|(_, calls)| *calls > 0)
            .collect()
    }
}

/// Storage backend that counts every round-trip and delegates to an in-memory
/// object store.
///
/// Each counted call is one request on S3/GCS, so the count is what a handler
/// costs against a real object store. `list_with_meta` and `get_range` forward to
/// the object store's own implementations (one LIST, one ranged GET) rather than
/// the trait defaults, so the counts match production.
pub struct OpCountingBackend {
    inner: crate::storage::ObjectStorage,
    counts: Arc<OpCounts>,
}

/// An in-memory object-store [`Storage`] whose backend round-trips are counted.
///
/// Used by the index-cost tests: an index or metadata response must cost the same
/// number of round-trips whether it lists 1 item or 100.
pub fn op_counting_storage() -> (Storage, Arc<OpCounts>) {
    let counts = Arc::new(OpCounts::default());
    let backend = OpCountingBackend {
        inner: crate::storage::ObjectStorage::in_memory(),
        counts: Arc::clone(&counts),
    };
    (Storage::from_backend(Arc::new(backend)), counts)
}

#[async_trait::async_trait]
impl crate::storage::StorageBackend for OpCountingBackend {
    async fn put(&self, key: &str, data: &[u8], sha256: &str) -> crate::storage::Result<()> {
        self.counts.hit("put");
        self.inner.put(key, data, sha256).await
    }

    async fn get(&self, key: &str) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
        self.counts.hit("get");
        self.inner.get(key).await
    }

    async fn pin(&self, key: &str) -> Option<String> {
        self.counts.hit("pin");
        self.inner.pin(key).await
    }

    async fn delete(&self, key: &str) -> crate::storage::Result<()> {
        self.counts.hit("delete");
        self.inner.delete(key).await
    }

    async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
        self.counts.hit("list");
        self.inner.list(prefix).await
    }

    async fn stat(&self, key: &str) -> Option<crate::storage::FileMeta> {
        self.counts.hit("stat");
        self.inner.stat(key).await
    }

    async fn list_with_meta(
        &self,
        prefix: &str,
    ) -> crate::storage::Result<Vec<(String, crate::storage::FileMeta)>> {
        self.counts.hit("list_with_meta");
        self.inner.list_with_meta(prefix).await
    }

    async fn health_check(&self) -> bool {
        self.inner.health_check().await
    }

    async fn total_size(&self) -> u64 {
        self.inner.total_size().await
    }

    fn backend_name(&self) -> &'static str {
        self.inner.backend_name()
    }

    async fn refresh_total_size(&self) {
        self.inner.refresh_total_size().await
    }

    async fn put_from_path(
        &self,
        key: &str,
        src: &std::path::Path,
        sha256: Option<&str>,
    ) -> crate::storage::Result<()> {
        self.counts.hit("put_from_path");
        self.inner.put_from_path(key, src, sha256).await
    }

    async fn copy(&self, src: &str, dst: &str, sha256: Option<&str>) -> crate::storage::Result<()> {
        self.counts.hit("copy");
        self.inner.copy(src, dst, sha256).await
    }

    async fn get_reader(
        &self,
        key: &str,
    ) -> crate::storage::Result<(
        u64,
        Option<String>,
        std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    )> {
        self.counts.hit("get_reader");
        self.inner.get_reader(key).await
    }

    async fn get_range(
        &self,
        key: &str,
        start: u64,
        end: u64,
    ) -> crate::storage::Result<(
        u64,
        Option<String>,
        std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    )> {
        self.counts.hit("get_range");
        self.inner.get_range(key, start, end).await
    }
}

// ── Per-registry artifact counts, each read from its real source ────────────

/// The three per-registry artifact counts an operator can read for one store.
#[derive(Debug, PartialEq, Eq)]
pub struct ArtifactCounts {
    /// Dashboard card: `/api/ui/dashboard` → `registry_stats[].artifact_count`
    /// (the HTML dashboard renders the same `build_dashboard_response`).
    pub dashboard: usize,
    /// `/api/ui/stats` → the registry's field.
    pub stats: usize,
    /// `nora_artifacts_total{registry}`: the 60 s tick in `main.rs` sets the gauge
    /// verbatim from `repo_index.counts()`, read here after the two endpoints above
    /// rebuilt the index. Read directly rather than through the process-global
    /// gauge, which parallel tests would race on.
    pub metric: usize,
}

/// Read [`ArtifactCounts`] for `registry` through the router and the shared index.
pub async fn artifact_counts(ctx: &TestContext, registry: &str) -> ArtifactCounts {
    use axum::http::{Method, StatusCode};

    let resp = send(&ctx.app, Method::GET, "/api/ui/dashboard", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let dashboard: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let card = dashboard["registry_stats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|card| card["name"] == registry)
        .unwrap_or_else(|| panic!("no dashboard card for {registry}: {dashboard}"));
    let dashboard = card["artifact_count"].as_u64().unwrap() as usize;

    let resp = send(&ctx.app, Method::GET, "/api/ui/stats", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let stats: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let stats = stats[registry].as_u64().unwrap() as usize;

    let rt = crate::registry_type::RegistryType::from_str_opt(registry).unwrap();
    let metric = ctx.state.repo_index.counts().get(&rt).copied().unwrap_or(0);

    ArtifactCounts {
        dashboard,
        stats,
        metric,
    }
}

/// The path of every request an upstream mock has received, in order.
pub async fn upstream_paths(upstream: &wiremock::MockServer) -> Vec<String> {
    upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect()
}

/// A curation blocklist file refusing every version of `name` in `registry`. Keep the
/// directory alive while a context uses the path.
pub fn blocklist_file(registry: &str, name: &str) -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("blocklist.json");
    std::fs::write(
        &path,
        format!(r#"{{"version": 1, "rules": [{{"registry": "{registry}", "name": "{name}", "version": "*", "reason": "malware"}}]}}"#),
    )
    .unwrap();
    (dir, path.to_string_lossy().into_owned())
}

/// Readers of a source file for white-list teeth: which functions hold a call, and the body of a
/// function. They read production code only — everything before the first test module.
pub mod source_reader {
    /// Production code: everything before the first `#[cfg(test)]` at the start of a line.
    pub fn production(source: &str) -> &str {
        &source[..source.find("\n#[cfg(test)]").unwrap_or(source.len())]
    }

    /// The name a top-level function's signature line declares (`fn`, `async fn`, `pub fn`,
    /// `pub(crate) async fn`, …), if the line is one.
    fn declares(line: &str) -> Option<&str> {
        let mut rest = line;
        for prefix in ["pub(crate) ", "pub "] {
            rest = rest.strip_prefix(prefix).unwrap_or(rest);
        }
        rest = rest.strip_prefix("async ").unwrap_or(rest);
        let rest = rest.strip_prefix("fn ")?;
        Some(&rest[..rest.find(['(', '<']).unwrap_or(rest.len())])
    }

    /// The body of the top-level function `name`, from its signature to its closing brace.
    pub fn body<'a>(source: &'a str, name: &str) -> Option<&'a str> {
        let mut offset = 0;
        for line in source.split_inclusive('\n') {
            if declares(line) == Some(name) {
                let end = source[offset..].find("\n}\n").map(|end| offset + end)?;
                return Some(&source[offset..end]);
            }
            offset += line.len();
        }
        None
    }

    /// The top-level functions whose bodies contain `needle`, a call on the signature's own line
    /// included; `fn needle(` itself is no call.
    pub fn holders(source: &str, needle: &str) -> Vec<String> {
        let mut found = Vec::new();
        let mut current = String::new();
        for line in source.lines() {
            if let Some(name) = declares(line) {
                current = name.to_string();
            }
            // An occurrence that names the function being declared (`fn needle(`) is not a call.
            if line
                .match_indices(needle)
                .any(|(at, _)| !line[..at].ends_with("fn "))
            {
                found.push(current.clone());
            }
        }
        found.sort();
        found.dedup();
        found
    }
}

/// A forward proxy that answers every request 403 and records its first line — `CONNECT host:443`
/// for https, the absolute URL for http. A context built with
/// [`create_test_context_with_egress_proxy`] sends all its outbound requests here, so an empty
/// record proves nothing left NORA, whatever host a handler meant to ask. Connections are answered
/// one at a time; the accepting task ends when the recorder is dropped.
pub struct EgressRecorder {
    pub url: String,
    seen: Arc<tokio::sync::Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl EgressRecorder {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind egress recorder");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("recorder address")
        );
        let seen: Arc<tokio::sync::Mutex<Vec<String>>> = Arc::default();
        let record = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let line = Self::answer(socket).await;
                record.lock().await.push(line);
            }
        });
        Self { url, seen, task }
    }

    /// Read a request head (up to 2 s), answer 403, and return its first line.
    async fn answer(mut socket: tokio::net::TcpStream) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        let read = async {
            while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16384 {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
        };
        // CANCEL-SAFETY: on timeout the partial head is still recorded; the socket is dropped.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), read).await;
        let _ = socket
            .write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n")
            .await;
        String::from_utf8_lossy(&head)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// The first line of every request the recorder received so far.
    pub async fn seen(&self) -> Vec<String> {
        self.seen.lock().await.clone()
    }
}

impl Drop for EgressRecorder {
    fn drop(&mut self) {
        self.task.abort();
    }
}
