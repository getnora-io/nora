// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]
#![warn(clippy::large_stack_frames, clippy::large_futures)]
// Test code is linted under `--all-targets` but is not held to the production
// restriction/style lints (see lib.rs for rationale). Scoped to `cfg(test)`.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::redundant_clone,
        clippy::int_plus_one,
        clippy::field_reassign_with_default,
        clippy::unnecessary_get_then_check,
        clippy::single_match,
        clippy::redundant_field_names,
        clippy::len_zero,
        clippy::items_after_test_module
    )
)]

// musl's mallocng serializes every allocation on one global lock, which collapses into kernel
// futex contention under many async workers; mimalloc's per-thread heaps avoid it. Feature
// `mimalloc` is on by default; `--no-default-features` falls back to the system allocator.
// Declaring the static needs no unsafe here (the GlobalAlloc impl lives in the crate), so
// `#![forbid(unsafe_code)]` still holds.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod activity_log;
mod admin;
mod audit;
mod auth;
mod backup;
mod cache_ttl;
mod circuit_breaker;
mod cleanup;
mod config;
mod curation;
mod dashboard_metrics;
mod digest_quarantine;
mod docker_key_migration;
mod gc;
mod hash_pin_store;
mod health;
mod import;
mod log_redact;
mod metrics;
mod migrate;
mod mirror;
mod openapi;
mod proxy_coalesce;
mod rate_limit;
mod registry;
mod registry_type;
mod repo_index;
mod request_id;
mod retention;
mod secrets;
mod signing;
mod storage;
mod tokens;
mod ui;
mod validation;

#[cfg(test)]
mod test_env;
#[cfg(test)]
mod test_helpers;

use arc_swap::ArcSwap;
use axum::{body::Bytes, extract::DefaultBodyLimit, http::HeaderValue, middleware, Router};
use clap::{Parser, Subcommand};
use log_redact::RedactUserinfo;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use activity_log::ActivityLog;
use audit::AuditLog;
use auth::HtpasswdAuth;
use config::{Config, CurationMode, StorageMode, TlsConfig};
use dashboard_metrics::DashboardMetrics;
use registry_type::RegistryType;
use repo_index::RepoIndex;
use secrets::{expose_opt, ProtectedString};
pub use storage::Storage;
use tokens::TokenStore;

use futures::FutureExt;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};

#[derive(Parser)]
#[command(name = "nora", version, about = "Multi-protocol artifact registry")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the registry server (default)
    Serve,
    /// Backup all artifacts to a tar.gz file
    Backup {
        /// Output file path (e.g., backup.tar.gz)
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Restore artifacts from a backup file
    Restore {
        /// Input backup file path
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Garbage collect orphaned blobs and checksum sidecars
    Gc {
        /// Actually delete orphans (default: dry-run only)
        #[arg(long, default_value = "false")]
        apply: bool,
    },
    /// Show retention plan (dry-run)
    RetentionPlan,
    /// Apply retention policies (delete old versions)
    RetentionApply {
        /// Confirm deletion (required to actually delete)
        #[arg(long)]
        yes: bool,
    },
    /// Migrate artifacts between storage backends
    Migrate {
        /// Source storage: local or s3
        #[arg(long)]
        from: String,
        /// Destination storage: local or s3
        #[arg(long)]
        to: String,
        /// Dry run - show what would be migrated without copying
        #[arg(long, default_value = "false")]
        dry_run: bool,
    },
    /// Pre-fetch dependencies through NORA proxy cache
    Mirror {
        #[command(subcommand)]
        format: mirror::MirrorFormat,
        /// NORA registry URL
        #[arg(long, default_value = "http://localhost:4000", global = true)]
        registry: String,
        /// Max concurrent downloads
        #[arg(long, default_value = "8", global = true)]
        concurrency: usize,
        /// Output results as JSON (for CI pipelines)
        #[arg(long, global = true)]
        json: bool,
    },
    /// Import artifacts from an external registry (Artifactory / Nexus) into NORA (#599)
    Import {
        #[command(subcommand)]
        action: import::ImportCommand,
    },
    /// Curation tools: validate files, explain decisions
    Curation {
        #[command(subcommand)]
        action: CurationCommand,
    },
    /// Migrate legacy Docker storage keys to namespaced format
    MigrateDockerKeys {
        /// Dry run — show what would be migrated without modifying storage
        #[arg(long, default_value = "false")]
        dry_run: bool,
    },
    /// Recover an artifact whose hash pin no longer matches its bytes (#601).
    ///
    /// Updates the pin to `--expected` only if the on-disk bytes already hash
    /// to it. If the disk is genuinely corrupt (does not match), it refuses —
    /// re-pin cannot heal corruption; restore from backup first.
    RePin {
        /// Storage key, e.g. `raw/myorg/app-1.0.0.bin`
        key: String,
        /// The SHA-256 (64-char hex) the operator knows to be canonical for
        /// this key — from a CI manifest, upstream checksum, or lockfile.
        #[arg(long)]
        expected: String,
        /// Apply the change. Without this, prints what would change (dry run).
        #[arg(long)]
        yes: bool,
    },
    /// Check a running NORA server's health endpoint (for Docker HEALTHCHECK).
    ///
    /// Reads `NORA_HOST`/`NORA_PORT` the same way the server does, probes
    /// `GET /health`, and exits 0 on a 2xx response, 1 otherwise. Needs no
    /// external tools (curl/wget) and no hardcoded address.
    Healthcheck {
        /// Request timeout in seconds.
        #[arg(long, default_value = "5")]
        timeout_secs: u64,
    },
}

#[derive(Subcommand)]
enum CurationCommand {
    /// Validate blocklist/allowlist JSON files
    Validate {
        /// Path to the JSON file to validate
        file: PathBuf,
    },
    /// Explain curation decision for a specific package
    Explain {
        /// Package in format "registry:name@version" (e.g., "cargo:serde@1.0.0")
        package: String,
    },
}

/// Per-key publish locks — shared between AppState and GC to serialize
/// metadata read-modify-write operations on the same artifact.
///
/// # Lock ordering
///
/// `cleanup_lock` → `publish_lock`. Never acquire `cleanup_lock` while
/// holding a `publish_lock` (handlers never touch `cleanup_lock`).
pub type PublishLocks = Arc<parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>;

/// One GC pass of the scheduler. A pass that removed anything marks every repository index
/// stale, so the dashboard, `/api/ui/stats` and the artifact gauges show the store and not
/// what it held before the pass; a write marks its own registry the same way.
async fn gc_pass(
    storage: &Storage,
    publish_locks: &PublishLocks,
    repo_index: &RepoIndex,
    dry_run: bool,
    grace_secs: u64,
    npm_is_proxy: bool,
    proxy_cache_max_bytes: u64,
) -> gc::GcResult {
    let result = gc::run_gc(
        storage,
        publish_locks,
        dry_run,
        grace_secs,
        npm_is_proxy,
        proxy_cache_max_bytes,
    )
    .await;
    if !dry_run && result.removed_anything() {
        repo_index.invalidate_all();
    }
    result
}

/// The line the GC scheduler logs when a pass ends. Files evicted by
/// `[gc] proxy_cache_max_bytes` are counted apart from the orphans: they are neither in
/// `deleted` nor in its `bytes_freed`.
fn gc_done_line(result: &gc::GcResult, dry_run: bool) -> String {
    let eviction = &result.proxy_cache_eviction;
    if dry_run {
        // A dry pass deletes nothing: its counts are what a real pass would take.
        return format!(
            "GC scheduler: dry run in {:.1}s — {} orphans ({} bytes would be freed), {} would be evicted from the proxy cache ({} bytes), {} metadata phantoms, {} skipped (grace)",
            result.duration_secs,
            result.orphaned,
            result.bytes_freed,
            eviction.evicted_files,
            eviction.bytes_freed,
            result.metadata_phantoms_removed,
            result.skipped_recent
        );
    }
    format!(
        "GC scheduler: done in {:.1}s — {} orphans ({} deleted, {} bytes freed), {} evicted from the proxy cache ({} bytes freed), {} metadata phantoms, {} skipped (grace)",
        result.duration_secs,
        result.orphaned,
        result.deleted,
        result.bytes_freed,
        eviction.evicted_files,
        eviction.bytes_freed,
        result.metadata_phantoms_removed,
        result.skipped_recent
    )
}

/// One retention pass of the scheduler; a pass that deleted keys marks every repository
/// index stale, as `gc_pass` does. A pass that found versions to delete leaves one audit
/// entry: `retention-apply` when it deleted them, `retention-dry-run` when `dry_run` only
/// planned it, so the trail never records a deletion that did not happen.
async fn retention_pass(
    storage: &Storage,
    publish_locks: &PublishLocks,
    repo_index: &RepoIndex,
    signer: Option<&signing::RepoSigner>,
    rules: &[config::RetentionRule],
    dry_run: bool,
    audit: &AuditLog,
) -> retention::RetentionResult {
    let result = retention::run_retention(storage, publish_locks, signer, rules, dry_run).await;
    if !dry_run && result.deleted_keys > 0 {
        repo_index.invalidate_all();
    }
    if result.planned > 0 {
        audit.log(audit::AuditEntry::new(
            if dry_run {
                "retention-dry-run"
            } else {
                "retention-apply"
            },
            "scheduler",
            &format!("{} versions", result.planned),
            "*",
            &if dry_run {
                // Nothing was deleted: the bytes are what an applied pass would free.
                format!(
                    "would_free_bytes={} duration={:.1}s",
                    result.bytes_freed, result.duration_secs
                )
            } else {
                format!(
                    "keys={} bytes_freed={} duration={:.1}s",
                    result.deleted_keys, result.bytes_freed, result.duration_secs
                )
            },
        ));
    }
    result
}

/// Set `nora_artifacts_total` and the per-registry `nora_storage_bytes` from the
/// repository index, first rebuilding each enabled registry's index that a restart, a
/// write or a cleanup pass marked stale — the read `/api/ui/stats` does. An index nothing
/// touched since its last rebuild is served from memory without a storage round-trip; a
/// stale one costs one listing of its registry, at most once per call.
async fn refresh_artifact_gauges(
    repo_index: &RepoIndex,
    storage: &Storage,
    enabled: &HashSet<RegistryType>,
) {
    for rt in enabled {
        let _ = repo_index.get(rt.as_str(), storage).await;
    }
    for (rt, count) in repo_index.counts() {
        metrics::ARTIFACTS_TOTAL
            .with_label_values(&[rt.as_str()])
            .set(count as i64);
    }
    for (rt, bytes) in repo_index.sizes() {
        metrics::STORAGE_BYTES
            .with_label_values(&[rt.as_str()])
            .set(bytes as i64);
    }
}

/// Get or create a per-key publish lock for TOCTOU protection.
///
/// Used by both `AppState::publish_lock()` and GC metadata cleanup to ensure
/// all metadata writes to the same key are serialized.
pub fn acquire_publish_lock(locks: &PublishLocks, key: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut map = locks.lock();
    map.entry(key.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Curation-related config that can be hot-reloaded via SIGHUP.
pub struct ReloadableConfig {
    pub curation_engine: curation::CurationEngine,
    pub bypass_token: Option<ProtectedString>,
}

#[derive(Clone)]
pub struct AppState {
    pub storage: Storage,
    pub config: Arc<Config>,
    pub enabled_registries: Arc<HashSet<RegistryType>>,
    pub start_time: Instant,
    pub startup_duration_ms: u64,
    pub auth: Option<Arc<HtpasswdAuth>>,
    pub tokens: Option<TokenStore>,
    pub metrics: Arc<DashboardMetrics>,
    pub activity: Arc<ActivityLog>,
    pub audit: Arc<AuditLog>,
    pub docker_auth: Arc<registry::DockerAuth>,
    pub repo_index: Arc<RepoIndex>,
    pub http_client: reqwest::Client,
    /// The same client, except that it never follows a redirect: for a format whose answer
    /// depends on what each hop said (hf: the commit rides on the Hub's redirect).
    pub http_client_no_redirect: reqwest::Client,
    /// Canonical repo ids the Hugging Face upstream named, for curation of aliases (#579).
    pub hf_canonical_ids: Arc<registry::hf::CanonicalIds>,
    pub upload_sessions: Arc<RwLock<HashMap<String, registry::docker::UploadSession>>>,
    /// Per-key publish locks for TOCTOU protection (immutable releases)
    publish_locks: PublishLocks,
    /// Hot-reloadable curation config (swapped atomically on SIGHUP).
    pub reloadable: Arc<ArcSwap<ReloadableConfig>>,
    /// Per-IP failed auth attempt tracker for brute-force protection
    pub auth_failures: Arc<auth::AuthFailureTracker>,
    /// OIDC validator for workload identity (CI/CD)
    pub oidc: Option<Arc<auth::OidcValidator>>,
    pub(crate) circuit_breaker: Arc<circuit_breaker::CircuitBreakerRegistry>,
    /// Single-flight coalescer for the proxy cache-miss path: collapses a
    /// thundering herd of concurrent requests for the same key into one
    /// upstream fetch (#595). In-memory and rebuildable (empty after restart).
    pub(crate) proxy_coalesce: proxy_coalesce::InflightMap<Bytes>,
    /// Docker blob fills in flight, shared by every request for the blob (#1003).
    pub(crate) blob_flights: proxy_coalesce::InflightMap<registry::docker::SpoolShare>,
    pub digest_store: Arc<digest_quarantine::DigestStore>,
    /// Repository index signer (rpm/deb). `None` = indexes are unsigned.
    pub signer: Option<Arc<signing::RepoSigner>>,
    /// Pre-compiled upstream hostname searchers for leak detection (#386)
    pub leak_finders: metrics::LeakFinders,
    /// Shared shutdown signal so on-demand background tasks (e.g. the admin
    /// reindex warm-up) stop promptly on SIGTERM/SIGINT (#306).
    pub cancel_token: tokio_util::sync::CancellationToken,
    /// Off-request-path docker pull-stats accumulator (#1114): a manifest GET
    /// bumps the per-key counter here; a background task flushes it in batches
    /// to a `.stats.json` sidecar, so `.meta.json` is never rewritten by a pull.
    /// In-memory, rebuildable-empty after a restart.
    pub(crate) pull_stats: Arc<registry::docker::PullStatsAccumulator>,
}

impl AppState {
    /// Load a snapshot of the current curation engine (lock-free read via ArcSwap).
    pub fn curation(&self) -> arc_swap::Guard<Arc<ReloadableConfig>> {
        self.reloadable.load()
    }

    /// Shorthand for the curation bypass token from the reloadable config.
    pub fn bypass_token(&self) -> Option<String> {
        self.reloadable
            .load()
            .bypass_token
            .as_ref()
            .map(|s| s.expose().to_string())
    }

    /// Get or create a per-key publish lock for TOCTOU protection.
    pub fn publish_lock(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        acquire_publish_lock(&self.publish_locks, key)
    }

    /// Background-cache proxy data and invalidate the registry index.
    ///
    /// Use for ALL proxy caching instead of manual `tokio::spawn` + `storage.put`.
    /// Guarantees that `repo_index.invalidate()` is called AFTER the write completes,
    /// avoiding the race condition where invalidation fires before the file lands on S3.
    pub fn spawn_cache(&self, registry: &'static str, key: String, data: Bytes) {
        let storage = self.storage.clone();
        let repo_index = Arc::clone(&self.repo_index);
        tokio::spawn(
            std::panic::AssertUnwindSafe(async move {
                if storage.put(&key, &data).await.is_ok() {
                    repo_index.invalidate(registry);
                }
            })
            .catch_unwind()
            .map(|r| {
                if let Err(e) = r {
                    tracing::error!(panic = ?e, "background cache task panicked");
                }
            }),
        );
    }

    /// Like [`spawn_cache`], but skips the write if the key already exists (immutable artifacts).
    pub fn spawn_cache_immutable(&self, registry: &'static str, key: String, data: Bytes) {
        let storage = self.storage.clone();
        let repo_index = Arc::clone(&self.repo_index);
        tokio::spawn(
            std::panic::AssertUnwindSafe(async move {
                if storage.stat(&key).await.is_none() && storage.put(&key, &data).await.is_ok() {
                    repo_index.invalidate(registry);
                }
            })
            .catch_unwind()
            .map(|r| {
                if let Err(e) = r {
                    tracing::error!(panic = ?e, "background cache task panicked");
                }
            }),
        );
    }
}

/// Mask credentials in a proxy URL for safe logging.
///
/// `http://user:pass@proxy:3128` → `http://***@proxy:3128`
fn sanitize_proxy_url(url: &str) -> String {
    // Try to find userinfo (anything before @ in authority)
    if let Some(at_pos) = url.find('@') {
        // Find the scheme separator
        let scheme_end = url.find("://").map(|p| p + 3).unwrap_or(0);
        if at_pos > scheme_end {
            return format!("{}***@{}", &url[..scheme_end], &url[at_pos + 1..]);
        }
    }
    url.to_string()
}

/// Log detected outbound proxy configuration from environment variables.
fn log_outbound_proxy() {
    let vars = [
        "ALL_PROXY",
        "all_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ];
    for var in &vars {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                info!(var = %var, proxy = %sanitize_proxy_url(&val), "Outbound proxy detected from environment");
                break;
            }
        }
    }
    let no_proxy = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    if !no_proxy.is_empty() {
        info!(no_proxy = %no_proxy, "NO_PROXY exclusions configured");
    }
}

/// User-Agent sent by all outbound HTTP clients. Compile-time `&'static str`
/// via `concat!`/`env!` — no per-call heap allocation.
const USER_AGENT: &str = concat!("nora/", env!("CARGO_PKG_VERSION"));

/// Build HTTP client with optional custom CA certificate support.
///
/// When `timeout` is `Some`, a default request timeout is set on the client
/// (used by `nora mirror` for long-running downloads). When `no_proxy` is true
/// the client ignores any `HTTP(S)_PROXY` env — required for loopback probes
/// (the healthcheck) that must reach the local server directly, not via an
/// upstream proxy. `redirect` is reqwest's own default (`Policy::default()`) for
/// every client but the one in [`build_no_redirect_client`].
fn build_http_client(
    tls: &TlsConfig,
    timeout: Option<std::time::Duration>,
    no_proxy: bool,
    redirect: reqwest::redirect::Policy,
) -> reqwest::Client {
    let mut builder = reqwest::ClientBuilder::new()
        .user_agent(USER_AGENT)
        .redirect(redirect);

    if let Some(t) = timeout {
        builder = builder.timeout(t);
    }

    if no_proxy {
        builder = builder.no_proxy();
    }

    if let Some(ref ca_path) = tls.ca_cert {
        match std::fs::read(ca_path) {
            Ok(pem) => match reqwest::tls::Certificate::from_pem(&pem) {
                Ok(cert) => {
                    builder = builder.add_root_certificate(cert);
                    info!(path = %ca_path, "Custom CA certificate loaded");
                }
                Err(e) => {
                    error!(path = %ca_path, error = %e, "Failed to parse CA certificate");
                    panic!("Cannot start with invalid CA certificate: {}", ca_path);
                }
            },
            Err(e) => {
                error!(path = %ca_path, error = %e, "Failed to read CA certificate file");
                panic!(
                    "Cannot start: CA certificate file not readable: {}",
                    ca_path
                );
            }
        }
    }

    builder.build().expect("Failed to build HTTP client")
}

/// The client that never follows a redirect, for a format whose answer depends on what each
/// hop said (hf: the commit rides on the Hub's redirect). Built by [`build_http_client`]
/// (custom CA, user agent, proxy settings); the test context builds it here too, so the
/// tests run against the very client the server uses.
pub(crate) fn build_no_redirect_client(tls: &TlsConfig) -> reqwest::Client {
    build_http_client(tls, None, false, reqwest::redirect::Policy::none())
}

/// Build the `/health` probe URL from the configured listen host. Wildcard
/// binds are probed over loopback — you cannot connect *to* `0.0.0.0` / `::`.
/// Both wildcards probe `127.0.0.1`: a `::` server is dual-stack (or falls back
/// to `0.0.0.0`), so IPv4 loopback reaches it in every case, whereas `::1` would
/// miss the fallback.
fn healthcheck_url(host: &str, port: u16) -> String {
    let h = match host {
        "0.0.0.0" | "::" | "[::]" => "127.0.0.1",
        other => other,
    };
    // Bracket a bare IPv6 literal for the URL authority.
    if h.contains(':') && !h.starts_with('[') {
        format!("http://[{h}]:{port}/health")
    } else {
        format!("http://{h}:{port}/health")
    }
}

/// Probe a running server's `/health` and map the result to a process exit
/// code: 0 if it returns 2xx (server up), 1 otherwise. Backs the `healthcheck`
/// subcommand so Docker HEALTHCHECK needs no curl/wget and no hardcoded address.
async fn run_healthcheck(timeout_secs: u64) -> i32 {
    // Read the listen host/port the same way the server does (env vars), without
    // loading or validating the full config — a probe must not abort on a missing
    // NORA_PUBLIC_URL or any other server-only requirement.
    let host = std::env::var("NORA_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("NORA_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(4000);
    let url = healthcheck_url(&host, port);
    // Reuse the central HTTP client builder, but with no_proxy: a loopback probe
    // must reach the local server directly, never through an upstream HTTP proxy
    // (which would 502 the local address when HTTP_PROXY is set).
    let client = build_http_client(
        &TlsConfig::default(),
        Some(std::time::Duration::from_secs(timeout_secs)),
        true,
        reqwest::redirect::Policy::default(),
    );
    match client.get(&url).send().await {
        // /health returns 200 when healthy, 503 when storage is unreachable.
        Ok(resp) if resp.status().is_success() => 0,
        Ok(resp) => {
            eprintln!("healthcheck: {url} -> HTTP {}", resp.status());
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {url} -> {e}");
            1
        }
    }
}

/// The request layers inside metrics, shared by the server and the test router so the
/// tests run the order the server runs (#542). Innermost first: curation_refusal (audit)
/// → request_id → leak_detection → rewrite_ui_base_path → auth. auth runs first of these;
/// the audit layer sits inside it so it knows who was refused, and request_id runs before
/// the handler so the ID is available to it.
/// Response security headers applied to every route, outermost. `nosniff`,
/// `DENY` framing and the referrer policy are uniform and override whatever a
/// handler set. The Content-Security-Policy is added only when a handler set
/// none (`if_not_present`): the UI's permissive policy (it needs `unsafe-inline`)
/// is the default, but the raw download handler sets its own `sandbox` policy on
/// user-uploaded bytes and that stricter one must survive. Kept in one function
/// so the server and its test run the same layering.
pub(crate) fn apply_security_headers<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    use tower_http::set_header::SetResponseHeaderLayer;
    router
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'"),
        ))
}

pub(crate) fn request_layers(router: Router<AppState>, state: &AppState) -> Router<AppState> {
    router
        .layer(middleware::from_fn_with_state(
            state.clone(),
            audit::curation_refusal_middleware,
        ))
        .layer(middleware::from_fn(request_id::request_id_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            metrics::leak_detection_middleware,
        ))
        // Prefix the UI's root-absolute self-links + redirects with the public_url
        // path so the UI works under a sub-path behind a proxy. No-op when unset;
        // only buffers text/html (UI pages), so blob streams pass through untouched.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            ui::rewrite_ui_base_path,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
}

#[cfg(test)]
mod middleware_stack_tests {
    /// The server applies the audit layer once — in `request_layers`, which the test router
    /// shares, so router tests see where the server runs it. A second copy (say outside
    /// auth) would record each refusal twice, once as `anonymous`; a missing or commented-out
    /// layer is caught by the audit tests themselves. Comments are skipped, and the needle is
    /// built at run time so this test's own text does not count.
    #[test]
    fn the_audit_layer_is_applied_once() {
        let code: String = include_str!("main.rs")
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let needle = ["curation_refusal", "_middleware"].concat();
        assert!(
            code.matches(&needle).count() <= 1,
            "{needle} applied more than once"
        );
    }
}

#[cfg(test)]
mod security_header_tests {
    use super::apply_security_headers;
    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn header_of(app: &Router, path: &str, name: &str) -> Option<String> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
    }

    // A handler that sets its own CSP (the raw download handler, `sandbox`) keeps it; a handler
    // that sets none gets the permissive UI default. The default must not override a stricter
    // handler policy, or raw's user-uploaded bytes would run under the UI's `unsafe-inline`.
    #[tokio::test]
    async fn a_handler_csp_survives_the_default() {
        let app = apply_security_headers(
            Router::<()>::new()
                .route(
                    "/raw-like",
                    get(|| async { ([(header::CONTENT_SECURITY_POLICY, "sandbox")], "bytes") }),
                )
                .route("/ui-like", get(|| async { "page" })),
        );
        assert_eq!(
            header_of(&app, "/raw-like", "content-security-policy").await,
            Some("sandbox".to_string())
        );
        let default = header_of(&app, "/ui-like", "content-security-policy")
            .await
            .expect("a route without its own CSP gets the default");
        assert!(
            default.contains("script-src 'self' 'unsafe-inline'"),
            "default UI CSP expected, got {default}"
        );
        // nosniff is uniform and overrides, on both.
        for path in ["/raw-like", "/ui-like"] {
            assert_eq!(
                header_of(&app, path, "x-content-type-options").await,
                Some("nosniff".to_string())
            );
        }
    }
}

#[cfg(test)]
mod healthcheck_tests {
    use super::healthcheck_url;

    #[test]
    fn wildcard_hosts_probe_loopback() {
        assert_eq!(
            healthcheck_url("0.0.0.0", 4000),
            "http://127.0.0.1:4000/health"
        );
        // Both wildcards probe IPv4 loopback (reaches dual-stack and the
        // 0.0.0.0 fallback alike).
        assert_eq!(healthcheck_url("::", 4000), "http://127.0.0.1:4000/health");
        assert_eq!(
            healthcheck_url("[::]", 4000),
            "http://127.0.0.1:4000/health"
        );
    }

    #[test]
    fn specific_hosts_pass_through_with_ipv6_bracketing() {
        assert_eq!(
            healthcheck_url("127.0.0.1", 8080),
            "http://127.0.0.1:8080/health"
        );
        assert_eq!(
            healthcheck_url("example.com", 80),
            "http://example.com:80/health"
        );
        assert_eq!(healthcheck_url("::1", 4000), "http://[::1]:4000/health");
        assert_eq!(
            healthcheck_url("[2001:db8::1]", 4000),
            "http://[2001:db8::1]:4000/health"
        );
    }
}

/// Bind the server's TCP listener, preferring dual-stack for the IPv6 wildcard.
///
/// For `::` we create the socket explicitly and clear `IPV6_V6ONLY`, so the
/// listener accepts both IPv4 and IPv6 regardless of the host's `bindv6only`
/// sysctl (#574). If IPv6 is unavailable, we fall back to `0.0.0.0` (IPv4-only)
/// rather than failing to start. Any other host (specific IP or name) binds
/// normally.
async fn bind_listener(host: &str, port: u16) -> std::io::Result<tokio::net::TcpListener> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    if host == "::" || host == "0:0:0:0:0:0:0:0" {
        let v6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
        match bind_v6_dual_stack(v6) {
            Ok(listener) => return Ok(listener),
            Err(e) => {
                warn!(
                    error = %e,
                    "dual-stack bind on [::] failed; falling back to 0.0.0.0 (IPv4-only)"
                );
                let v4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
                return tokio::net::TcpListener::bind(v4).await;
            }
        }
    }
    tokio::net::TcpListener::bind((host, port)).await
}

/// Create a dual-stack (`IPV6_V6ONLY = false`) IPv6 listener via `socket2`,
/// returning it as a non-blocking `tokio` listener.
fn bind_v6_dual_stack(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Socket, Type};

    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod shutdown_drain_tests {
    //! Graceful shutdown drains in-flight requests for at most the shutdown timeout
    //! (#1016): a client that stops reading can no longer hold the process past it.
    use super::{serve_with_drain, ServeEnd};
    use axum::body::{Body, Bytes};
    use axum::routing::get;
    use axum::Router;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A body that never ends, in 64 KiB pieces.
    async fn endless() -> Body {
        let piece = Bytes::from(vec![7u8; 64 * 1024]);
        Body::from_stream(futures::stream::repeat_with(move || {
            Ok::<_, std::io::Error>(piece.clone())
        }))
    }

    /// Three pieces 100 ms apart: a download that finishes on its own.
    async fn short() -> Body {
        use futures::StreamExt;
        Body::from_stream(futures::stream::iter(0..3u8).then(|i| async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok::<_, std::io::Error>(Bytes::from(vec![i; 1024]))
        }))
    }

    async fn start(
        drain: Duration,
    ) -> (
        std::net::SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<std::io::Result<ServeEnd>>,
    ) {
        let app = Router::new()
            .route("/endless", get(endless))
            .route("/short", get(short));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_with_drain(
            listener,
            app,
            async move {
                let _ = rx.await;
            },
            drain,
        ));
        (addr, tx, server)
    }

    /// A client reads the start of an endless body and then stops reading, keeping the
    /// connection open (dockerd after a failed layer). After the signal, serving ends
    /// at the deadline instead of waiting on that connection forever.
    #[tokio::test]
    async fn stalled_client_cannot_hold_shutdown_past_the_deadline() {
        let drain = Duration::from_millis(300);
        let (addr, stop, server) = start(drain).await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /endless HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut head = [0u8; 4096];
        let _ = client.read(&mut head).await.unwrap(); // started, then never read again

        let signalled = Instant::now();
        stop.send(()).unwrap();
        let end = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("serving must end at the drain deadline, not wait on the stalled client")
            .unwrap()
            .unwrap();
        assert_eq!(end, ServeEnd::DeadlinePassed);
        assert!(
            signalled.elapsed() >= drain,
            "in-flight requests get the whole drain window"
        );
        drop(client);
    }

    /// A download already in flight when the signal comes, and short enough to finish
    /// within the deadline, completes whole; serving ends as drained.
    #[tokio::test]
    async fn in_flight_download_finishes_within_the_deadline() {
        let (addr, stop, server) = start(Duration::from_secs(5)).await;
        let download = tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
            client
                .write_all(b"GET /short HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut all = Vec::new();
            client.read_to_end(&mut all).await.unwrap();
            all
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.send(()).unwrap();
        let end = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(end, ServeEnd::Drained);
        let response = download.await.unwrap();
        let body_bytes = response.iter().filter(|b| matches!(b, 0..=2)).count();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert!(body_bytes >= 3 * 1024, "the whole body arrived");
    }
}

#[cfg(test)]
mod bind_tests {
    use super::bind_listener;

    #[tokio::test]
    async fn dual_stack_listener_accepts_ipv4() {
        // A "::" bind must accept IPv4 clients — via dual-stack, or via the
        // 0.0.0.0 fallback when IPv6 is unavailable. Guards against an IPv4
        // regression from defaulting the container bind to "::".
        let listener = bind_listener("::", 0).await.expect("bind ::");
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("IPv4 loopback connects to a :: listener");
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging (JSON for server, plain for CLI commands)
    let is_server = matches!(cli.command, None | Some(Commands::Serve));
    let _log_guard = init_logging(is_server);

    // Healthcheck is a client-side probe (Docker HEALTHCHECK) — handle it before
    // loading the full server config, which it does not need and which can abort
    // (e.g. NORA_PUBLIC_URL is required on a 0.0.0.0 bind).
    if let Some(Commands::Healthcheck { timeout_secs }) = &cli.command {
        std::process::exit(run_healthcheck(*timeout_secs).await);
    }

    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            // A clean, non-retried stop: the units list EXIT_CONFIG in
            // RestartPreventExitStatus= (#1025).
            error!(error = %e, "Cannot start with this configuration");
            eprintln!("nora: {e}");
            std::process::exit(config::EXIT_CONFIG);
        }
    };

    // Initialize storage based on mode
    let storage = match config.storage.mode {
        StorageMode::Local => {
            if is_server {
                info!(path = %config.storage.path, "Using local storage");
            }
            Storage::new_local(&config.storage.path)
        }
        StorageMode::S3 => {
            if is_server {
                info!(
                    s3_url = %config.storage.s3_url,
                    bucket = %config.storage.bucket,
                    region = %config.storage.s3_region,
                    has_credentials = config.storage.s3_access_key.is_some(),
                    virtual_hosted = config.storage.s3_virtual_hosted,
                    "Using S3 storage"
                );
            }
            Storage::new_s3(
                &config.storage.s3_url,
                &config.storage.bucket,
                &config.storage.s3_region,
                expose_opt(&config.storage.s3_access_key),
                expose_opt(&config.storage.s3_secret_key),
                config.storage.s3_virtual_hosted,
            )
        }
        StorageMode::Gcs => {
            if is_server {
                info!(
                    bucket = %config.storage.bucket,
                    has_service_account = config.storage.gcs_service_account_path.is_some(),
                    base_url = %config.storage.gcs_base_url.as_deref().unwrap_or("https://storage.googleapis.com"),
                    "Using Google Cloud Storage"
                );
            }
            Storage::new_gcs(
                &config.storage.bucket,
                config.storage.gcs_service_account_path.as_deref(),
                config.storage.gcs_base_url.as_deref(),
            )
        }
    };

    // Dispatch to command
    match cli.command {
        None | Some(Commands::Serve) => {
            run_server(config, storage).await;
        }
        Some(Commands::Backup { output }) => {
            if let Err(e) = backup::create_backup(&storage, &output).await {
                error!("Backup failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Restore { input }) => {
            if let Err(e) = backup::restore_backup(&storage, &input).await {
                error!("Restore failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Gc { apply }) => {
            let dry_run = !apply;
            let cli_publish_locks: PublishLocks = Arc::new(parking_lot::Mutex::new(HashMap::new()));
            // Grace applies to manual GC too: `nora gc --apply` is often run while
            // traffic is live, when in-flight pushes are most likely (#584).
            let result = gc::run_gc(
                &storage,
                &cli_publish_locks,
                dry_run,
                config.gc.grace_secs,
                !config.npm.upstream_urls().is_empty(),
                config.gc.proxy_cache_max_bytes,
            )
            .await;
            println!("GC Summary{}:", if dry_run { " (dry-run)" } else { "" });
            println!("  Candidates:       {}", result.total_candidates);
            println!("  Orphaned:          {}", result.orphaned);
            println!("  Deleted:           {}", result.deleted);
            println!("  Bytes freed:       {}", result.bytes_freed);
            if result.docker_mark_failed {
                println!("  Docker sweep:      skipped (manifest graph incomplete; all Docker objects kept)");
            }
            if result.skipped_recent > 0 {
                println!(
                    "  Skipped (grace):   {} (younger than {}s — likely in-flight uploads)",
                    result.skipped_recent, config.gc.grace_secs
                );
            }
            if result.stat_failures > 0 {
                println!(
                    "  Stat failures:     {} (kept, age unknown — GC may be unable to reclaim space)",
                    result.stat_failures
                );
            }
            println!("  Duration:          {:.1}s", result.duration_secs);
            if dry_run && !result.orphan_keys.is_empty() {
                println!("\nOrphan keys:");
                for key in &result.orphan_keys {
                    println!("  {}", key);
                }
                println!("\nRun with --apply to delete orphans.");
            }
            if result.proxy_cache_eviction.evicted_files > 0
                || result.proxy_cache_eviction.total_bytes > 0
            {
                let e = &result.proxy_cache_eviction;
                println!(
                    "  Proxy cache:       {} bytes total, {} files evicted, {} bytes freed",
                    e.total_bytes, e.evicted_files, e.bytes_freed
                );
            }
            if !result.uncovered.is_empty() {
                let parts: Vec<String> = result
                    .uncovered
                    .iter()
                    .map(|(name, count)| format!("{} ({} files)", name, count))
                    .collect();
                println!("\nNote: GC does not scan: {}", parts.join(", "));
            }
            if result.docker_mark_failed {
                std::process::exit(1);
            }
        }
        Some(Commands::RetentionPlan) => {
            let cli_publish_locks: PublishLocks = Arc::new(parking_lot::Mutex::new(HashMap::new()));
            // Dry-run: plans only, no deletions and no index regeneration —
            // no signer needed.
            let result = retention::run_retention(
                &storage,
                &cli_publish_locks,
                None,
                &config.retention.rules,
                true,
            )
            .await;
            println!("Retention Plan (dry-run):");
            println!("  Versions to delete: {}", result.planned);
            println!("  Bytes to free:      {}", result.bytes_freed);
            for (group, plans) in &result.plans {
                for plan in plans {
                    println!(
                        "  {} / {} — {} ({})",
                        group, plan.version_name, plan.reason, plan.size
                    );
                }
            }
            if result.planned == 0 {
                println!("\nNothing to delete.");
            } else {
                println!("\nRun `nora retention-apply` to execute.");
            }
            print_retention_coverage(&storage, &config.retention.rules).await;
        }
        Some(Commands::RetentionApply { yes }) => {
            let cli_publish_locks: PublishLocks = Arc::new(parking_lot::Mutex::new(HashMap::new()));
            if !yes {
                // Show plan first, require --yes to execute
                let result = retention::run_retention(
                    &storage,
                    &cli_publish_locks,
                    None,
                    &config.retention.rules,
                    true,
                )
                .await;
                println!("Retention Plan:");
                println!("  Versions to delete: {}", result.planned);
                println!("  Bytes to free:      {}", result.bytes_freed);
                for (group, plans) in &result.plans {
                    for plan in plans {
                        println!(
                            "  {} / {} — {} ({})",
                            group, plan.version_name, plan.reason, plan.size
                        );
                    }
                }
                if result.planned > 0 {
                    println!(
                        "\nThis will delete {} versions. Run with --yes to confirm.",
                        result.planned
                    );
                } else {
                    println!("\nNothing to delete.");
                }
                print_retention_coverage(&storage, &config.retention.rules).await;
            } else {
                // Real deletions rebuild rpm/deb indexes — sign them with the
                // same key the server would, or clients start failing
                // verification after a CLI retention pass.
                let signer = build_signer(&config, &config.enabled_registries());
                let result = retention::run_retention(
                    &storage,
                    &cli_publish_locks,
                    signer.as_deref(),
                    &config.retention.rules,
                    false,
                )
                .await;
                println!("Retention Applied:");
                println!("  Versions deleted:   {}", result.planned);
                println!("  Keys deleted:       {}", result.deleted_keys);
                println!("  Bytes freed:        {}", result.bytes_freed);
                if result.planned > 0 {
                    let audit = AuditLog::new(&config.storage.path, config.audit.mode.clone());
                    audit.log(audit::AuditEntry::new(
                        "retention-apply",
                        "cli",
                        &format!("{} versions", result.planned),
                        "*",
                        &format!(
                            "keys={} bytes_freed={} duration={:.1}s",
                            result.deleted_keys, result.bytes_freed, result.duration_secs
                        ),
                    ));
                    audit.shutdown().await;
                }
                print_retention_coverage(&storage, &config.retention.rules).await;
            }
        }
        Some(Commands::Mirror {
            format,
            registry,
            concurrency,
            json,
        }) => {
            let client = build_http_client(
                &config.tls,
                Some(std::time::Duration::from_secs(300)),
                false,
                reqwest::redirect::Policy::default(),
            );
            if let Err(e) = mirror::run_mirror(format, &registry, concurrency, json, &client).await
            {
                error!("Mirror failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Migrate { from, to, dry_run }) => {
            let source = match from.as_str() {
                "local" => Storage::new_local(&config.storage.path),
                "s3" => Storage::new_s3(
                    &config.storage.s3_url,
                    &config.storage.bucket,
                    &config.storage.s3_region,
                    expose_opt(&config.storage.s3_access_key),
                    expose_opt(&config.storage.s3_secret_key),
                    config.storage.s3_virtual_hosted,
                ),
                "gcs" => Storage::new_gcs(
                    &config.storage.bucket,
                    config.storage.gcs_service_account_path.as_deref(),
                    config.storage.gcs_base_url.as_deref(),
                ),
                _ => {
                    error!("Invalid source: '{}'. Use 'local', 's3', or 'gcs'", from);
                    std::process::exit(1);
                }
            };

            let dest = match to.as_str() {
                "local" => Storage::new_local(&config.storage.path),
                "s3" => Storage::new_s3(
                    &config.storage.s3_url,
                    &config.storage.bucket,
                    &config.storage.s3_region,
                    expose_opt(&config.storage.s3_access_key),
                    expose_opt(&config.storage.s3_secret_key),
                    config.storage.s3_virtual_hosted,
                ),
                "gcs" => Storage::new_gcs(
                    &config.storage.bucket,
                    config.storage.gcs_service_account_path.as_deref(),
                    config.storage.gcs_base_url.as_deref(),
                ),
                _ => {
                    error!("Invalid destination: '{}'. Use 'local', 's3', or 'gcs'", to);
                    std::process::exit(1);
                }
            };

            if from == to {
                error!("Source and destination cannot be the same");
                std::process::exit(1);
            }

            let options = migrate::MigrateOptions { dry_run };

            if let Err(e) = migrate::migrate(&source, &dest, options).await {
                error!("Migration failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Curation { action }) => match action {
            CurationCommand::Validate { file } => {
                run_curation_validate(&file);
            }
            CurationCommand::Explain { package } => {
                run_curation_explain(&config, &package);
            }
        },
        Some(Commands::Import { action }) => {
            if let Err(e) = import::run(action, &storage, &config).await {
                error!("Import failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::MigrateDockerKeys { dry_run }) => {
            let namespace = config
                .docker
                .upstreams
                .first()
                .map(|u| u.resolved_namespace())
                .unwrap_or_else(|| "docker.io".to_string());

            if config.docker.upstreams.len() > 1 {
                warn!(
                    namespace = %namespace,
                    upstream_count = config.docker.upstreams.len(),
                    "Multiple Docker upstreams configured; using first upstream namespace for migration"
                );
            }

            match docker_key_migration::migrate_docker_keys(
                &storage,
                &namespace,
                docker_key_migration::MigrateDockerKeysOptions { dry_run },
            )
            .await
            {
                Ok(stats) => {
                    if stats.failed > 0 {
                        error!("{} keys failed to migrate", stats.failed);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    error!("Docker key migration failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::RePin { key, expected, yes }) => {
            let expected = expected.to_ascii_lowercase();
            if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
                error!("--expected must be a 64-character hex SHA-256");
                std::process::exit(2);
            }
            match storage.repin(&key, &expected, yes).await {
                Ok(storage::RepinOutcome::DiskMismatch { disk, expected }) => {
                    error!(
                        key = %key,
                        on_disk = %disk,
                        expected = %expected,
                        "re-pin refused: on-disk bytes do not match --expected — the artifact is corrupt. Restore it from backup, then re-pin."
                    );
                    std::process::exit(1);
                }
                Ok(storage::RepinOutcome::AlreadyPinned { hash }) => {
                    println!("Pin already matches {hash} — nothing to do.");
                }
                Ok(storage::RepinOutcome::WouldUpdate { old, new }) => {
                    println!(
                        "Would re-pin {key}:\n  old: {}\n  new: {new}\nRe-run with --yes to apply.",
                        old.as_deref().unwrap_or("(none)")
                    );
                }
                Ok(storage::RepinOutcome::Updated { old, new }) => {
                    // Loud audit trail — re-pin is a privileged integrity override.
                    warn!(
                        key = %key,
                        old = ?old,
                        new = %new,
                        "INTEGRITY RE-PIN: hash pin updated by operator (#601)"
                    );
                    println!(
                        "Re-pinned {key}:\n  old: {}\n  new: {new}",
                        old.as_deref().unwrap_or("(none)")
                    );
                }
                Err(e) => {
                    error!(key = %key, "re-pin failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        // Handled before storage init by the early dispatch above; the process
        // has already exited by the time control would reach here.
        Some(Commands::Healthcheck { .. }) => unreachable!(),
    }
}

/// Build the repository index signer (#128). `None` disables signing:
/// explicitly via config, when no signing-capable registry (rpm/deb) is
/// enabled, or on S3 storage without a configured `signing.key_path` (warned
/// — there is no local data directory to keep a generated key in). A present
/// but unreadable/corrupt key is fatal: silently serving unsigned (or with a
/// silently rotated key) would break every client pinning the public key.
fn build_signer(
    config: &config::Config,
    enabled: &std::collections::HashSet<RegistryType>,
) -> Option<Arc<signing::RepoSigner>> {
    if !enabled.contains(&RegistryType::Rpm) && !enabled.contains(&RegistryType::Deb) {
        return None;
    }
    if !config.signing.enabled {
        info!("repository index signing disabled by config");
        return None;
    }
    let path = if !config.signing.key_path.is_empty() {
        std::path::PathBuf::from(&config.signing.key_path)
    } else if config.storage.mode == config::StorageMode::Local {
        std::path::Path::new(&config.storage.path).join(".signing/nora.key")
    } else {
        tracing::warn!(
            "repository index signing disabled: storage is not local and signing.key_path \
             is not set (NORA_SIGNING_KEY_PATH)"
        );
        return None;
    };
    match signing::RepoSigner::load_or_generate(&path) {
        Ok(signer) => {
            info!(
                fingerprint = %signer.fingerprint(),
                path = %path.display(),
                "repository index signing enabled"
            );
            if signer.was_generated() && config.storage.mode != config::StorageMode::Local {
                tracing::warn!(
                    path = %path.display(),
                    "signing key was GENERATED on this boot while artifacts live in an \
                     object store — if this path is per-pod/ephemeral, every replica or \
                     reschedule mints a new identity and clients fail verification. \
                     Provision one key and mount it read-only on every replica."
                );
            }
            Some(Arc::new(signer))
        }
        Err(e) => {
            eprintln!("Fatal: repository index signing key error: {e}");
            std::process::exit(1);
        }
    }
}

fn run_curation_validate(file: &Path) {
    let content = match std::fs::read_to_string(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: Cannot read '{}': {}", file.display(), e);
            std::process::exit(1);
        }
    };

    // Try as blocklist first
    if let Ok(parsed) = serde_json::from_str::<curation::BlocklistFile>(&content) {
        if parsed.version != 1 {
            eprintln!(
                "ERROR: Unsupported blocklist version {} (expected 1)",
                parsed.version
            );
            std::process::exit(1);
        }
        println!("OK: Valid blocklist — {} rules", parsed.rules.len());
        for (i, rule) in parsed.rules.iter().enumerate() {
            println!(
                "  [{}] {}/{}@{} — {}",
                i + 1,
                rule.registry,
                rule.name,
                rule.version,
                rule.reason
            );
        }
        return;
    }

    // Try as allowlist
    if let Ok(parsed) = serde_json::from_str::<curation::AllowlistFile>(&content) {
        if parsed.version != 1 {
            eprintln!(
                "ERROR: Unsupported allowlist version {} (expected 1)",
                parsed.version
            );
            std::process::exit(1);
        }
        let with_integrity = parsed
            .entries
            .iter()
            .filter(|e| e.integrity.is_some())
            .count();
        println!(
            "OK: Valid allowlist — {} entries ({} with integrity)",
            parsed.entries.len(),
            with_integrity
        );
        for (i, entry) in parsed.entries.iter().enumerate() {
            let integrity_flag = if entry.integrity.is_some() {
                " [hash]"
            } else {
                ""
            };
            println!(
                "  [{}] {}/{}@{}{}",
                i + 1,
                entry.registry,
                entry.name,
                entry.version,
                integrity_flag
            );
        }
        return;
    }

    eprintln!(
        "ERROR: '{}' is not a valid blocklist or allowlist JSON",
        file.display()
    );
    eprintln!("  Expected {{ \"version\": 1, \"rules\": [...] }} or {{ \"version\": 1, \"entries\": [...] }}");
    std::process::exit(1);
}

/// The parts of a `registry:name@version` curation-explain spec.
#[derive(Debug, PartialEq)]
enum ExplainSpec {
    Parsed {
        registry: RegistryType,
        name: String,
        version: Option<String>,
    },
    NoColon,
    UnknownRegistry(String),
}

/// Parse a `registry:name@version` spec (the command a refusal's hint names) back
/// into its parts. The version follows the LAST `@`, except: an `@` that starts
/// the name opens an npm scope (`npm:@scope/pkg`), and a `raw` name carries no
/// version — its path may itself contain `@` (`raw:dir/a@b.txt`), so the whole
/// remainder is the name. Pure, so a table test pins every registry's convention
/// and the round-trip of the hint `explain_command` builds (#1099).
fn parse_explain_spec(spec: &str) -> ExplainSpec {
    let Some((registry_str, rest)) = spec.split_once(':') else {
        return ExplainSpec::NoColon;
    };
    let Some(registry) = RegistryType::from_str_opt(registry_str) else {
        return ExplainSpec::UnknownRegistry(registry_str.to_string());
    };
    let (name, version) = if registry == RegistryType::Raw {
        // A raw name is a path and carries no version; it may itself contain '@'.
        (rest.to_string(), None)
    } else {
        match rest.rfind('@') {
            Some(at) if at > 0 => (rest[..at].to_string(), Some(rest[at + 1..].to_string())),
            _ => (rest.to_string(), None),
        }
    };
    ExplainSpec::Parsed {
        registry,
        name,
        version,
    }
}

fn run_curation_explain(config: &Config, package_spec: &str) {
    let (registry, name, version) = match parse_explain_spec(package_spec) {
        ExplainSpec::Parsed {
            registry,
            name,
            version,
        } => (registry, name, version),
        ExplainSpec::NoColon => {
            eprintln!("ERROR: Expected format 'registry:name@version' (e.g., 'cargo:serde@1.0.0')");
            std::process::exit(1);
        }
        ExplainSpec::UnknownRegistry(registry_str) => {
            eprintln!(
                "ERROR: Unknown registry '{}'. Use: {}",
                registry_str,
                RegistryType::all()
                    .iter()
                    .map(|r| r.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            std::process::exit(1);
        }
    };

    // Build engine with configured filters
    let mut engine = curation::CurationEngine::new(config.curation.clone());

    if let Some(ref path) = config.curation.blocklist_path {
        match curation::BlocklistFilter::from_file(path) {
            Ok(filter) => {
                println!("Blocklist: {} ({} rules)", path, filter.rule_count());
                engine.add_filter(Box::new(filter));
            }
            Err(e) => println!("Blocklist: {} (ERROR: {})", path, e),
        }
    } else {
        println!("Blocklist: not configured");
    }

    if let Some(ref path) = config.curation.allowlist_path {
        match curation::AllowlistFilter::from_file(path, config.curation.require_integrity) {
            Ok(filter) => {
                println!("Allowlist: {} ({} entries)", path, filter.entry_count());
                engine.add_filter(Box::new(filter));
            }
            Err(e) => println!("Allowlist: {} (ERROR: {})", path, e),
        }
    } else {
        println!("Allowlist: not configured");
    }

    if !config.curation.internal_namespaces.is_empty() {
        let ns_filter = curation::NamespaceFilter::new(config.curation.internal_namespaces.clone());
        println!("Namespaces: {} patterns", ns_filter.pattern_count());
        engine.set_namespace_filter(Box::new(ns_filter));
    } else {
        println!("Namespaces: not configured");
    }

    let (min_age, problems) = curation::MinReleaseAgeFilter::from_config(&config.curation);
    for problem in &problems {
        println!("Min-release-age: ERROR: {}", problem);
    }
    match min_age {
        Some(filter) => {
            match filter.global_only() {
                Some((secs, value)) => println!("Min-release-age: {} ({}s)", value, secs),
                None => println!("Min-release-age: {}", filter.summary()),
            }
            engine.add_filter(Box::new(filter));
        }
        None if problems.is_empty() => println!("Min-release-age: not configured"),
        None => {}
    }

    println!("Mode: {}", config.curation.mode);
    println!("---");

    let request = curation::FilterRequest {
        registry,
        upstream: None,
        name: name.clone(),
        version: curation::RequestVersion::named(version.as_deref()),
        integrity: None,
        bypass: false,
        publish_date: None,
    };

    let result = engine.evaluate(&request);
    println!(
        "Package: {}:{}@{}",
        registry.as_str(),
        name,
        version.as_deref().unwrap_or("*")
    );
    println!("Decision: {:?}", result.decision);
    println!(
        "Decided by: {}",
        result.decided_by.as_deref().unwrap_or("(default)")
    );
    if result.audited {
        println!("Mode: AUDIT (would block but logs only)");
    }
}

#[cfg(test)]
mod explain_spec_tests {
    use super::*;

    #[test]
    fn parse_explain_spec_recovers_each_registrys_at_convention() {
        let cases: &[(&str, RegistryType, &str, Option<&str>)] = &[
            (
                "cargo:serde@1.0.0",
                RegistryType::Cargo,
                "serde",
                Some("1.0.0"),
            ),
            (
                "npm:is-number@7.0.0",
                RegistryType::Npm,
                "is-number",
                Some("7.0.0"),
            ),
            // an '@' that starts the name opens an npm scope, not a version
            (
                "npm:@scope/pkg@1.0.0",
                RegistryType::Npm,
                "@scope/pkg",
                Some("1.0.0"),
            ),
            ("npm:@scope/pkg", RegistryType::Npm, "@scope/pkg", None),
            (
                "docker:library/nginx@sha256:abc",
                RegistryType::Docker,
                "library/nginx",
                Some("sha256:abc"),
            ),
            // #1099 D1: a raw path with '@' and no version must NOT split on the '@'
            // — otherwise the hint explains a different package than the one refused.
            ("raw:dir/a@b.txt", RegistryType::Raw, "dir/a@b.txt", None),
            ("raw:path/to/file", RegistryType::Raw, "path/to/file", None),
            ("gems:rails", RegistryType::Gems, "rails", None),
        ];
        for (spec, reg, name, ver) in cases {
            match parse_explain_spec(spec) {
                ExplainSpec::Parsed {
                    registry,
                    name: n,
                    version: v,
                } => assert_eq!(
                    (registry, n.as_str(), v.as_deref()),
                    (*reg, *name, *ver),
                    "spec={spec}"
                ),
                other => panic!("spec={spec}: expected Parsed, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_explain_spec_flags_malformed_specs() {
        assert_eq!(parse_explain_spec("no-colon-here"), ExplainSpec::NoColon);
        match parse_explain_spec("bogusreg:thing") {
            ExplainSpec::UnknownRegistry(r) => assert_eq!(r, "bogusreg"),
            other => panic!("expected UnknownRegistry, got {other:?}"),
        }
    }

    /// Reverse of `shell_word`: a single-quoted token back to its contents, a bare
    /// token unchanged — what a shell does before `nora curation explain` runs.
    fn shell_unquote(word: &str) -> String {
        match word.strip_prefix('\'').and_then(|w| w.strip_suffix('\'')) {
            Some(inner) => inner.replace(r"'\''", "'"),
            None => word.to_string(),
        }
    }

    /// #1099: the hint explains the package it NAMES, and its spec is
    /// one shell word so pasting it is safe. For each registry over a corpus —
    /// single-letter names (`@` at index 1), npm scopes, raw paths with `@`, and
    /// shell metacharacters in the name AND in the version — the spec the shell
    /// hands back parses to the same registry/name/version, and the spec is one
    /// shell word (bare safe chars, or a single-quoted token).
    #[test]
    fn explain_command_round_trips_and_is_one_shell_word() {
        let cases: &[(RegistryType, &str, Option<&str>)] = &[
            (RegistryType::Npm, "q", Some("1.5.1")), // single-letter: '@' at index 1 (H3)
            (RegistryType::Npm, "@scope/pkg", Some("1.0.0")),
            (RegistryType::Cargo, "serde", Some("1.0.0")),
            (
                RegistryType::Docker,
                "library/nginx",
                Some("sha256:0123abcd"),
            ),
            (RegistryType::Raw, "dir/a@b.txt", None), // raw path with '@', no version
            (RegistryType::Raw, "dir/my file.txt", None),
            (RegistryType::Npm, "is-number", Some("7.0.0$(touch x)")), // metachar version (H9)
            (RegistryType::Npm, "is-number", Some("7.0.0;id")),
            (RegistryType::Raw, "a`id`b", None), // metachar name
        ];
        for &(rt, name, version) in cases {
            let hint = crate::curation::explain_command(rt.as_str(), name, version);
            let spec = hint
                .strip_prefix("nora curation explain ")
                .expect("hint shape");
            // One shell word: bare safe chars, or a single-quoted token. A version
            // with a metacharacter must land INSIDE the quotes (H9), not after.
            let bare_safe = !spec.is_empty()
                && spec
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./_-".contains(c));
            let quoted = spec.len() >= 2 && spec.starts_with('\'') && spec.ends_with('\'');
            assert!(
                bare_safe || quoted,
                "spec is not one shell word: {spec:?} ({}:{name})",
                rt.as_str()
            );
            match parse_explain_spec(&shell_unquote(spec)) {
                ExplainSpec::Parsed {
                    registry,
                    name: n,
                    version: v,
                } => assert_eq!(
                    (registry, n.as_str(), v.as_deref()),
                    (rt, name, version),
                    "round-trip for {}:{name}",
                    rt.as_str()
                ),
                other => panic!("{}:{name}: expected Parsed, got {other:?}", rt.as_str()),
            }
        }
    }
}

/// Initialize tracing subscriber with stdout + optional file output.
///
/// When `NORA_LOG_FILE` is set, logs are duplicated to the specified file path
/// using a non-blocking writer. The file layer uses the same format and level
/// filter as stdout. Returns a guard that must be held for the process lifetime
/// to ensure the non-blocking writer flushes on shutdown.
fn init_logging(json_format: bool) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Optional file output via NORA_LOG_FILE
    let file_writer = match std::env::var("NORA_LOG_FILE") {
        Ok(path) if !path.is_empty() => open_log_file(&path),
        _ => None,
    };

    match (json_format, file_writer) {
        (true, Some((non_blocking, guard))) => {
            let file_filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_writer(RedactUserinfo(std::io::stdout)),
                )
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_writer(RedactUserinfo(non_blocking))
                        .with_filter(file_filter),
                )
                .init();
            Some(guard)
        }
        (true, None) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_writer(RedactUserinfo(std::io::stdout)),
                )
                .init();
            None
        }
        (false, Some((non_blocking, guard))) => {
            let file_filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .with_target(false)
                        .with_writer(RedactUserinfo(std::io::stdout)),
                )
                .with(
                    fmt::layer()
                        .with_target(false)
                        .with_writer(RedactUserinfo(non_blocking))
                        .with_filter(file_filter),
                )
                .init();
            Some(guard)
        }
        (false, None) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .with_target(false)
                        .with_writer(RedactUserinfo(std::io::stdout)),
                )
                .init();
            None
        }
    }
}

/// Open a log file for non-blocking writes. Creates parent directories as needed.
fn open_log_file(
    path: &str,
) -> Option<(
    tracing_appender::non_blocking::NonBlocking,
    tracing_appender::non_blocking::WorkerGuard,
)> {
    let file_path = std::path::Path::new(path);

    // Create parent directories if needed
    if let Some(parent) = file_path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "WARNING: cannot create log directory {}: {e}",
                    parent.display()
                );
                return None;
            }
        }
    }

    let file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("WARNING: cannot open log file {}: {e}", file_path.display());
            return None;
        }
    };

    let (non_blocking, guard) = tracing_appender::non_blocking(file);
    eprintln!("Log file: {path}");
    Some((non_blocking, guard))
}

/// Auth routes behind the auth and general limiters, registry routes behind the upload limiter,
/// each limiter built for its quota. Returns the quotas the built limiters enforce, read back
/// from them, for the startup log.
fn rate_limited_routes<S: Clone + Send + Sync + 'static>(
    auth_routes: Router<S>,
    registry_routes: Router<S>,
    quotas: &rate_limit::LimiterQuotas,
    trusted_proxies: config::TrustedProxies,
) -> (Router<S>, rate_limit::LimiterQuotas) {
    let (auth_limiter, auth) = rate_limit::auth_rate_limiter(quotas.auth, trusted_proxies.clone());
    let (upload_limiter, upload) =
        rate_limit::upload_rate_limiter(quotas.upload, trusted_proxies.clone());
    let (general_limiter, general) =
        rate_limit::general_rate_limiter(quotas.general, trusted_proxies);

    // Auth routes: auth_limiter (strict 1rps) + general_limiter
    let auth_routes = auth_routes.layer(auth_limiter).layer(general_limiter);
    // Registry routes: upload_limiter only (200rps/500burst)
    // No general_limiter — avoids double-limiting that causes 429
    // during cache warming (dotnet restore with many packages)
    let limited_registry = registry_routes.layer(upload_limiter);

    let enforced = rate_limit::LimiterQuotas {
        auth,
        upload,
        general,
    };
    (
        Router::new().merge(auth_routes).merge(limited_registry),
        enforced,
    )
}

#[cfg(test)]
mod rate_limited_routes_tests {
    use super::*;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    async fn statuses(app: &Router, path: &str, count: usize) -> Vec<u16> {
        let mut out = Vec::new();
        for _ in 0..count {
            let mut req = axum::http::Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(SocketAddr::from((
                    [127, 0, 0, 1],
                    4000,
                ))));
            out.push(app.clone().oneshot(req).await.unwrap().status().as_u16());
        }
        out
    }

    // Registry routes are limited by the upload_* settings and only by
    // them; auth routes by auth_* and general_*. Bursts differ (auth 1, upload 2, general 3), one
    // request a second, so the first refusal tells which limiter answered.
    #[tokio::test]
    async fn registry_routes_use_the_upload_limiter_only() {
        let rl = config::RateLimitConfig {
            enabled: true,
            auth_rps: 1,
            auth_burst: 1,
            upload_rps: 1,
            upload_burst: 2,
            general_rps: 1,
            general_burst: 3,
        };
        let auth = Router::new().route("/api/tokens", axum::routing::get(|| async { "ok" }));
        let registry = Router::new().route("/v2/", axum::routing::get(|| async { "ok" }));
        let quotas = rate_limit::limiter_quotas(&rl);
        let (app, enforced) = rate_limited_routes(
            auth,
            registry,
            &quotas,
            config::TrustedProxies::default_loopback(),
        );
        assert_eq!(enforced, quotas);
        assert_eq!(
            statuses(&app, "/v2/", 4).await,
            vec![200, 200, 429, 429],
            "registry"
        );
        assert_eq!(
            statuses(&app, "/api/tokens", 2).await,
            vec![200, 429],
            "auth"
        );

        // The general limiter stricter than the upload one must not reach registry routes.
        let rl = config::RateLimitConfig {
            auth_burst: 2,
            upload_burst: 3,
            general_burst: 1,
            ..rl
        };
        let auth = Router::new().route("/api/tokens", axum::routing::get(|| async { "ok" }));
        let registry = Router::new().route("/v2/", axum::routing::get(|| async { "ok" }));
        let quotas = rate_limit::limiter_quotas(&rl);
        let (app, enforced) = rate_limited_routes(
            auth,
            registry,
            &quotas,
            config::TrustedProxies::default_loopback(),
        );
        assert_eq!(enforced, quotas);
        assert_eq!(
            statuses(&app, "/v2/", 4).await,
            vec![200, 200, 200, 429],
            "registry"
        );
        assert_eq!(
            statuses(&app, "/api/tokens", 2).await,
            vec![200, 429],
            "auth"
        );
    }

    // Whatever the rates, the routes are built with the quotas they are given, each from its
    // own setting: rates far apart and far above 1000/s, bursts above u16::MAX.
    #[test]
    fn the_routes_enforce_the_quotas_they_are_given() {
        for (auth, upload, general) in [
            (1_500_000, 5_000_000, 3),
            ((1 << 32) + 200, 7, u64::MAX),
            (999, 1_000_001, 600),
        ] {
            let rl = config::RateLimitConfig {
                enabled: true,
                auth_rps: auth,
                auth_burst: 70_000,
                upload_rps: upload,
                upload_burst: 100_000,
                general_rps: general,
                general_burst: 65_536,
            };
            let quotas = rate_limit::limiter_quotas(&rl);
            let (_, enforced) = rate_limited_routes::<()>(
                Router::new(),
                Router::new(),
                &quotas,
                config::TrustedProxies::default_loopback(),
            );
            assert_eq!(enforced, quotas, "{auth} {upload} {general}");
        }
    }
}

async fn run_server(mut config: Config, storage: Storage) {
    let start_time = Instant::now();

    // Log rate limiting configuration
    info!(
        enabled = config.rate_limit.enabled,
        auth_rps = config.rate_limit.auth_rps,
        auth_burst = config.rate_limit.auth_burst,
        upload_rps = config.rate_limit.upload_rps,
        upload_burst = config.rate_limit.upload_burst,
        general_rps = config.rate_limit.general_rps,
        general_burst = config.rate_limit.general_burst,
        "Rate limiting configured"
    );

    // Load auth if enabled
    let auth = if config.auth.enabled {
        let path = Path::new(&config.auth.htpasswd_file);
        match HtpasswdAuth::from_file(path) {
            Some(auth) => {
                info!(users = auth.list_users().len(), "Auth enabled");
                Some(auth)
            }
            None if config.auth.oidc.is_active() => {
                // #996 — OIDC-only is the intended setup; a missing htpasswd is
                // not a misconfiguration, so log at info rather than a warning
                // that trains operators to ignore auth warnings. Basic still
                // takes API tokens as the password (#1094).
                info!(
                    oidc_providers = config.auth.oidc.providers.len(),
                    "No htpasswd (OIDC-only): Basic auth accepts API tokens only"
                );
                None
            }
            None => {
                warn!(file = %config.auth.htpasswd_file, "Auth enabled but htpasswd file not found or empty");
                None
            }
        }
    } else {
        warn!("Authentication is DISABLED — all endpoints are publicly accessible. Set [auth] enabled=true for production.");
        None
    };

    // #590: a loopback bind without NORA_PUBLIC_URL makes the registry service index
    // advertise unreachable URLs to clients behind a reverse proxy. Warn (not fatal —
    // local-only use is the default and valid). A public_url that itself points at
    // loopback is caught separately by config validation.
    if config.server.public_url.is_none() && Config::is_loopback_host(&config.server.host) {
        warn!(
            "server.host is loopback ('{}') and NORA_PUBLIC_URL is not set — behind a reverse \
             proxy the service index (/nuget/v3/index.json and others) will advertise \
             unreachable http://{}:{} URLs to remote clients. Set \
             NORA_PUBLIC_URL=https://registry.example.com if proxied; ignore this if NORA is \
             only used locally.",
            config.server.host, config.server.host, config.server.port
        );
    }

    // Initialize token store if auth is enabled
    let tokens = if config.auth.enabled {
        let token_path = Path::new(&config.auth.token_storage);
        // Fail fast: with auth enabled a token store that cannot create/write its
        // directory is unusable. Surface it at boot with the resolved path instead
        // of swallowing the mkdir error and failing later with a bare ENOENT on the
        // first POST /api/tokens (#816). Under a systemd sandbox a relative
        // token_storage resolves outside ReadWritePaths and is not writable.
        if let Err(e) = std::fs::create_dir_all(token_path) {
            error!(
                path = %config.auth.token_storage,
                error = %e,
                "Cannot create token storage directory — auth is enabled but tokens cannot be \
                 persisted. Set NORA_AUTH_TOKEN_STORAGE to a writable absolute path (e.g. \
                 /var/lib/nora/tokens, inside the service's ReadWritePaths)."
            );
            std::process::exit(1);
        }
        info!(path = %config.auth.token_storage, "Token storage initialized");
        Some(TokenStore::with_cache_ttl(
            token_path,
            std::time::Duration::from_secs(config.auth.token_cache_ttl),
        ))
    } else {
        None
    };

    let storage_path = config.storage.path.clone();
    let rate_limit_enabled = config.rate_limit.enabled;

    // Warn about plaintext credentials in config.toml
    config.warn_plaintext_credentials();

    let http_client = build_http_client(
        &config.tls,
        None,
        false,
        reqwest::redirect::Policy::default(),
    );
    let http_client_no_redirect = build_no_redirect_client(&config.tls);
    log_outbound_proxy();

    // Initialize Docker auth with shared HTTP client (includes custom CA certs)
    let docker_auth = registry::DockerAuth::new(http_client.clone(), config.docker.proxy_timeout);

    // Discover NuGet search endpoints from upstream service index
    if config.nuget.enabled {
        registry::nuget::discover_search_endpoints(&http_client, &mut config.nuget).await;
    }

    // Build curation engine (shared helper, also used by SIGHUP reload).
    // Fail-closed: in enforce mode an unparsable filter aborts boot rather
    // than starting in a silent allow-all state (#586) — with EXIT_CONFIG, a
    // clean stop the units do not restart into, as for any other configuration
    // NORA cannot start with (#1025).
    let curation_engine = match build_curation_engine(&config) {
        Ok(engine) => engine,
        Err(e) => {
            error!(error = %e, "Cannot start in enforce mode");
            eprintln!("nora: cannot start in enforce mode: {e}");
            std::process::exit(config::EXIT_CONFIG);
        }
    };
    if curation_engine.is_active() {
        info!(
            mode = %config.curation.mode,
            "Curation layer active"
        );
    }

    // Determine enabled registries from config
    let enabled_registries = config.enabled_registries();

    // Back-propagate the resolved set into the per-registry `enabled` flags so
    // hosted handlers (rpm/deb/raw) that re-check `config.<reg>.enabled` agree
    // with route mounting. Without this, an enable-set from
    // NORA_REGISTRIES_ENABLE / [registries].enable mounts the routes but leaves
    // the flags at their defaults, so rpm/deb 404. (#856)
    config.apply_enabled_registries(&enabled_registries);

    // Make the enabled set available to the UI sidebar so its nav lists exactly
    // the enabled registries (matching the dashboard body). Set once, immutable.
    ui::components::set_enabled_registries(enabled_registries.clone());

    // Registry routes — only merge enabled registries
    let mut registry_routes = Router::new();
    for reg in &enabled_registries {
        match reg {
            RegistryType::Docker => {
                registry_routes = registry_routes.merge(registry::docker_routes())
            }
            RegistryType::Maven => {
                registry_routes = registry_routes.merge(registry::maven_routes())
            }
            RegistryType::Npm => registry_routes = registry_routes.merge(registry::npm_routes()),
            RegistryType::Cargo => {
                registry_routes = registry_routes.merge(registry::cargo_routes())
            }
            RegistryType::PyPI => registry_routes = registry_routes.merge(registry::pypi_routes()),
            RegistryType::Raw => registry_routes = registry_routes.merge(registry::raw_routes()),
            RegistryType::Go => registry_routes = registry_routes.merge(registry::go_routes()),
            RegistryType::Gems => registry_routes = registry_routes.merge(registry::gems_routes()),
            RegistryType::Terraform => {
                registry_routes = registry_routes.merge(registry::terraform_routes())
            }
            RegistryType::Ansible => {
                registry_routes = registry_routes.merge(registry::ansible_routes())
            }
            RegistryType::Nuget => {
                registry_routes = registry_routes
                    .merge(registry::nuget_routes())
                    .merge(registry::nuget_alias_routes())
            }
            RegistryType::PubDart => {
                registry_routes = registry_routes.merge(registry::pub_dart_routes())
            }
            RegistryType::Conan => {
                registry_routes = registry_routes.merge(registry::conan_routes())
            }
            RegistryType::Rpm => registry_routes = registry_routes.merge(registry::rpm_routes()),
            RegistryType::Deb => registry_routes = registry_routes.merge(registry::deb_routes()),
            RegistryType::Cpan => registry_routes = registry_routes.merge(registry::cpan_routes()),
            RegistryType::HuggingFace => {
                tracing::info!(
                    "Hugging Face proxy enabled: public models only (datasets answer 501), \
                     files over plain HTTP (Xet is never proxied)"
                );
                registry_routes = registry_routes.merge(registry::hf_routes())
            }
        }
    }

    // Routes WITHOUT rate limiting (health, metrics, UI)
    let public_routes = Router::new()
        .merge(health::routes())
        .merge(metrics::routes())
        .merge(ui::routes())
        .merge(openapi::routes());

    let app_routes = if rate_limit_enabled {
        let (routes, enforced) = rate_limited_routes(
            auth::token_routes(),
            registry_routes,
            &rate_limit::limiter_quotas(&config.rate_limit),
            config.auth.trusted_proxies.clone(),
        );
        // What the built limiters enforce, read back from them: any narrowing between the
        // configuration and the limiters shows here, next to "Rate limiting configured".
        info!(
            auth_rps = enforced.auth.per_second(),
            auth_burst = enforced.auth.burst,
            upload_rps = enforced.upload.per_second(),
            upload_burst = enforced.upload.burst,
            general_rps = enforced.general.per_second(),
            general_burst = enforced.general.burst,
            "Rate limits enforced"
        );
        routes
    } else {
        info!("Rate limiting DISABLED");
        Router::new()
            .merge(auth::token_routes())
            .merge(registry_routes)
    };

    let startup_duration_ms = start_time.elapsed().as_millis() as u64;

    let cb_config = config.circuit_breaker.clone();
    let audit_mode = config.audit.mode.clone();

    // Initialize digest quarantine store. Load the durable on-disk store whenever
    // ANY quarantine is effectively active — global OR a per-registry override
    // (e.g. docker-only [curation.docker] quarantine). Gating on the global field
    // alone built an empty() store for per-registry-only configs, so after a
    // restart a still-young cached digest read as `New` and was served early —
    // a fail-open the check-only cache-serve gate cannot catch (#765). The
    // predicate is the same one config validation uses, so they cannot diverge.
    let digest_store = if config.any_quarantine_active() {
        Arc::new(digest_quarantine::DigestStore::load(&storage_path))
    } else {
        Arc::new(digest_quarantine::DigestStore::empty(&storage_path))
    };

    let oidc_validator = if config.auth.oidc.enabled {
        Some(auth::OidcValidator::new(
            config.auth.oidc.clone(),
            http_client.clone(),
        ))
    } else {
        None
    };

    let bypass_token = config.curation.bypass_token.clone();
    let reloadable = Arc::new(ArcSwap::from_pointee(ReloadableConfig {
        curation_engine,
        bypass_token,
    }));

    let leak_finders = metrics::LeakFinders::new(config.upstream_hostnames());

    let enabled_registries = Arc::new(enabled_registries);
    // Cancellation token for graceful shutdown of background tasks (#306). Created
    // before AppState so on-demand handlers (admin reindex warm-up) can observe it.
    let cancel_token = tokio_util::sync::CancellationToken::new();
    let signer = build_signer(&config, &enabled_registries);

    let state = AppState {
        storage,
        config: Arc::new(config),
        enabled_registries,
        start_time,
        startup_duration_ms,
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
        auth_failures: Arc::new(auth::AuthFailureTracker::new(5, 900)),
        oidc: oidc_validator.map(Arc::new),
        circuit_breaker: Arc::new(circuit_breaker::CircuitBreakerRegistry::new(cb_config)),
        proxy_coalesce: proxy_coalesce::InflightMap::new(),
        blob_flights: proxy_coalesce::InflightMap::new(),
        digest_store,
        signer,
        leak_finders,
        cancel_token: cancel_token.clone(),
        pull_stats: Arc::new(registry::docker::PullStatsAccumulator::default()),
    };

    // Initialize circuit breaker gauge to 0 (Closed) for every breaker key (#441)
    let breaker_keys = circuit_breaker::initial_gauge_keys(&state.config);
    let breaker_keys: Vec<&str> = breaker_keys.iter().map(String::as_str).collect();
    state.circuit_breaker.init_gauges(&breaker_keys);

    // Shared lock: nothing that calls storage.delete may run concurrently.
    // The periodic cleanup cycle takes it once per cycle and runs every due
    // pass under it; it also serializes future manual/admin cleanup entry
    // points against that cycle.
    let cleanup_lock = Arc::new(tokio::sync::Mutex::new(()));

    let mut scheduler_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // #1114: fold accumulated docker pull counts into their .stats.json sidecars
    // every PULL_STATS_FLUSH_INTERVAL and once more on shutdown. Pushed to the
    // scheduler handles so the final flush completes within the shutdown drain,
    // keeping the stats loss to at most one interval only on a hard crash.
    scheduler_handles.push(tokio::spawn(registry::docker::pull_stats_flush_loop(
        state.clone(),
        registry::docker::PULL_STATS_FLUSH_INTERVAL,
    )));

    // Retention is pushed first: it deletes expired versions, creating the
    // orphans the GC pass then sweeps in the same cycle.
    let mut cleanup_passes: Vec<cleanup::CleanupPass> = Vec::new();

    if state.config.retention.enabled && !state.config.retention.rules.is_empty() {
        let storage = state.storage.clone();
        let publish_locks = state.publish_locks.clone();
        let signer = state.signer.clone();
        let rules = state.config.retention.rules.clone();
        let dry_run = state.config.retention.dry_run;
        let audit = state.audit.clone();
        let repo_index = state.repo_index.clone();
        cleanup_passes.push(cleanup::CleanupPass {
            name: "retention",
            interval: std::time::Duration::from_secs(state.config.retention.interval),
            run: Box::new(move || {
                let storage = storage.clone();
                let publish_locks = publish_locks.clone();
                let signer = signer.clone();
                let rules = rules.clone();
                let audit = audit.clone();
                let repo_index = repo_index.clone();
                async move {
                    info!(
                        dry_run = dry_run,
                        "Retention scheduler: starting periodic run"
                    );
                    let result = retention_pass(
                        &storage,
                        &publish_locks,
                        &repo_index,
                        signer.as_deref(),
                        &rules,
                        dry_run,
                        &audit,
                    )
                    .await;
                    info!(
                        "Retention scheduler: done in {:.1}s — {} versions, {} keys, {} bytes freed",
                        result.duration_secs, result.planned, result.deleted_keys, result.bytes_freed
                    );
                }
                .boxed()
            }),
        });
        info!(
            interval_secs = state.config.retention.interval,
            rules = state.config.retention.rules.len(),
            dry_run = state.config.retention.dry_run,
            "Retention scheduler started"
        );
    }

    if state.config.gc.enabled {
        let storage = state.storage.clone();
        let publish_locks = state.publish_locks.clone();
        let dry_run = state.config.gc.dry_run;
        let grace_secs = state.config.gc.grace_secs;
        let npm_is_proxy = !state.config.npm.upstream_urls().is_empty();
        let proxy_cache_max_bytes = state.config.gc.proxy_cache_max_bytes;
        let repo_index = state.repo_index.clone();
        cleanup_passes.push(cleanup::CleanupPass {
            name: "gc",
            interval: std::time::Duration::from_secs(state.config.gc.interval),
            run: Box::new(move || {
                let storage = storage.clone();
                let publish_locks = publish_locks.clone();
                let repo_index = repo_index.clone();
                async move {
                    info!("GC scheduler: starting periodic run");
                    let result = gc_pass(
                        &storage,
                        &publish_locks,
                        &repo_index,
                        dry_run,
                        grace_secs,
                        npm_is_proxy,
                        proxy_cache_max_bytes,
                    )
                    .await;
                    info!("{}", gc_done_line(&result, dry_run));
                }
                .boxed()
            }),
        });
        info!(
            interval_secs = state.config.gc.interval,
            dry_run = state.config.gc.dry_run,
            "GC scheduler started"
        );
    }

    if !cleanup_passes.is_empty() {
        scheduler_handles.push(cleanup::spawn_cleanup_scheduler(
            cleanup_passes,
            cleanup_lock,
            cancel_token.clone(),
        ));
    }

    let app = Router::new()
        .merge(public_routes)
        .merge(app_routes)
        // Admin control-plane routes — gated admin-only by auth_middleware
        // (auth::is_admin_path); abuse is bounded by the in-handler reindex
        // debounce rather than the optional HTTP rate limiter.
        .merge(admin::routes())
        .layer(DefaultBodyLimit::max(
            state.config.server.body_limit_mb * 1024 * 1024,
        ));
    let app = apply_security_headers(app);
    // Middleware layer order — LOAD-BEARING, do not reorder (#542).
    //
    // In axum, last .layer() = outermost (runs first). Execution order:
    //   reject_null_bytes → metrics → [request_layers: auth → rewrite_ui_base_path
    //   → leak_detection → request_id → curation_refusal (audit)] → handler
    //
    // reject_null_bytes MUST be outermost to block null-byte path attacks
    // before any processing occurs.
    // metrics MUST be next-outermost so it counts ALL responses including
    // auth rejections (401/403/429) in nora_http_requests_total.
    // The layers inside metrics are built by `request_layers`, which the test
    // router uses too, so the tests run the order the server runs.
    let app = request_layers(app, &state)
        .layer(middleware::from_fn(metrics::metrics_middleware))
        .layer(middleware::from_fn(
            validation::reject_null_bytes_middleware,
        ))
        .with_state(state.clone());

    // Open this instance's staging directory, removing what dead instances (SIGKILL,
    // OOM, power cut) left in theirs.
    state.storage.prepare().await;

    // Clean up stale Docker temp files from previous runs (#530, #580).
    if state.config.docker.enabled {
        registry::docker::cleanup_upload_temp_dir(&state.config.storage.path);
        registry::docker::cleanup_proxy_temp_dir(&state.config.storage.path);
    }
    // ...and streamed raw uploads a crash cut off mid-request.
    if state.config.raw.enabled {
        registry::raw::cleanup_upload_temp_dir(&state.config.storage.path);
    }
    // ...and Hugging Face cache fills a crash cut off mid-file.
    if state.config.hf.enabled {
        registry::hf::cleanup_fill_temp_dir(&state.config.storage.path);
    }

    let listener = bind_listener(&state.config.server.host, state.config.server.port)
        .await
        .expect("Failed to bind");
    // Report the address actually bound (reflects any IPv6 -> IPv4 fallback).
    let addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| state.config.server.bind_addr());

    info!(
        address = %addr,
        version = env!("CARGO_PKG_VERSION"),
        storage = state.storage.backend_name(),
        auth_enabled = state.auth.is_some(),
        body_limit_mb = state.config.server.body_limit_mb,
        "Nora started"
    );

    // Log enabled registries and their mount points
    let enabled_names: Vec<String> = state
        .enabled_registries
        .iter()
        .map(|r| format!("{} ({})", r.display_name(), r.mount_point()))
        .collect();
    info!(
        registries = ?enabled_names,
        count = state.enabled_registries.len(),
        "Enabled registries"
    );

    info!(
        health = "/health",
        ready = "/ready",
        metrics = "/metrics",
        ui = "/ui/",
        api_docs = "/api-docs",
        "System endpoints"
    );

    // Background task: flush token last_used + periodic maintenance every 30 seconds
    let metrics_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        let mut tick_count: u64 = 0;
        loop {
            interval.tick().await;
            tick_count += 1;
            if let Some(ref token_store) = metrics_state.tokens {
                token_store.flush_last_used().await;
            }
            registry::docker::cleanup_expired_sessions(&metrics_state.upload_sessions);
            metrics_state.auth_failures.cleanup();

            // Every 60s (odd ticks — the interval's first tick fires immediately, so the
            // boot pass runs right away: object-store reachability (#869) and the storage
            // gauge are populated before the first readiness probe, not 30s in).
            if !tick_count.is_multiple_of(2) {
                metrics_state.storage.refresh_total_size_cache().await;
                metrics::STORAGE_BYTES
                    .with_label_values(&["total"])
                    .set(metrics_state.storage.total_size().await as i64);
                // Per-registry artifact counts + logical bytes from the index, plus
                // process uptime (#446). The "total" storage_bytes label above is the
                // full physical footprint; per-registry is summed artifact size.
                // A panic in an index builder must not end this loop: it also flushes
                // tokens and expires upload sessions.
                let gauges = std::panic::AssertUnwindSafe(refresh_artifact_gauges(
                    &metrics_state.repo_index,
                    &metrics_state.storage,
                    &metrics_state.enabled_registries,
                ))
                .catch_unwind()
                .await;
                if let Err(e) = gauges {
                    tracing::error!(panic = ?e, "artifact gauge refresh panicked");
                }
                metrics::UPTIME_SECONDS.set(metrics_state.start_time.elapsed().as_secs() as i64);
            }

            // Every 5 minutes (tick_count % 10 == 0): evict unused publish locks
            // + clean up stale proxy and upload temp files (#580)
            if tick_count.is_multiple_of(10) {
                let mut locks = metrics_state.publish_locks.lock();
                locks.retain(|_, arc| Arc::strong_count(arc) > 1);
                let storage_path = metrics_state.config.storage.path.clone();
                tokio::task::spawn_blocking(move || {
                    registry::docker::cleanup_proxy_temp_dir(&storage_path);
                    registry::hf::cleanup_fill_temp_dir(&storage_path);
                    // Reclaim upload temp files orphaned by a storage-write failure
                    // without waiting for a restart. cleanup_expired_sessions only
                    // frees temps still tracked by a live (expired) session, so an
                    // orphan whose session entry is already gone would otherwise
                    // survive on disk until the next boot. Age-guarded by SESSION_TTL,
                    // so in-progress uploads are never reaped.
                    registry::docker::cleanup_upload_temp_dir(&storage_path);
                    registry::raw::cleanup_upload_temp_dir(&storage_path);
                });
            }
        }
    });

    // SIGHUP handler: hot-reload curation policy
    #[cfg(unix)]
    {
        let reload_state = state.clone();
        tokio::spawn(async move {
            let mut sighup = signal::unix::signal(signal::unix::SignalKind::hangup())
                .expect("Failed to install SIGHUP handler");
            loop {
                sighup.recv().await;
                info!("SIGHUP received — reloading curation policy");
                match reload_curation(&reload_state) {
                    Ok(()) => info!("Curation policy reloaded successfully"),
                    Err(e) => {
                        error!(error = %e, "Curation policy reload failed, keeping previous config")
                    }
                }
            }
        });
    }

    // Graceful shutdown on SIGTERM/SIGINT, draining for at most `shutdown_timeout` (#1016)
    let drain = std::time::Duration::from_secs(state.config.server.shutdown_timeout);
    match serve_with_drain(listener, app, shutdown_signal(), drain)
        .await
        .expect("Server error")
    {
        ServeEnd::Drained => {}
        ServeEnd::DeadlinePassed => warn!(
            shutdown_timeout_secs = state.config.server.shutdown_timeout,
            "Connections still open after the shutdown timeout are closed; finishing shutdown"
        ),
    }

    // Signal background schedulers to stop and wait for them (#306)
    cancel_token.cancel();
    if !scheduler_handles.is_empty() {
        info!("Waiting for background schedulers to finish (10s timeout)...");
        let join_all = futures::future::join_all(scheduler_handles);
        // CANCEL-SAFETY: timeout wraps join_all of scheduler handles. On timeout,
        // the JoinHandles are dropped which cancels the spawned tasks — this is
        // intentional since we're shutting down and don't need their results.
        if tokio::time::timeout(std::time::Duration::from_secs(10), join_all)
            .await
            .is_err()
        {
            warn!("Background schedulers did not finish within 10s, proceeding with shutdown");
        }
    }

    // Drain audit log — AFTER schedulers finish so their final entries are captured (#543)
    state.audit.shutdown().await;

    // Flush token last_used timestamps to disk
    if let Some(ref token_store) = state.tokens {
        token_store.flush_last_used().await;
    }

    info!(
        uptime_seconds = state.start_time.elapsed().as_secs(),
        "Nora shutdown complete"
    );
}

/// How serving ended after the shutdown signal.
#[derive(Debug, PartialEq, Eq)]
enum ServeEnd {
    /// Every in-flight request finished within the drain window.
    Drained,
    /// The drain window passed with connections still open.
    DeadlinePassed,
}

/// Serve `app` until `shutdown` resolves, then give in-flight requests `drain` to finish.
///
/// axum's graceful shutdown stops accepting at once but then waits for every open
/// connection with no limit, so a client that stops reading a response holds it
/// forever. Connections still open when the window passes are not awaited any more:
/// their tasks end when the runtime shuts down at process exit, after the shutdown
/// steps (schedulers, audit drain, token flush) have run.
async fn serve_with_drain<F>(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: F,
    drain: std::time::Duration,
) -> std::io::Result<ServeEnd>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let signalled = Arc::new(tokio::sync::Notify::new());
    let notify = Arc::clone(&signalled);
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.await;
        // A stored permit: the wait below sees it even if it starts afterwards.
        notify.notify_one();
    });
    let server = std::future::IntoFuture::into_future(server);
    tokio::pin!(server);
    // CANCEL-SAFETY: both arms only poll; the server future stays pinned here and is
    // polled again below, `notified()` holds nothing.
    tokio::select! {
        served = &mut server => {
            served?;
            return Ok(ServeEnd::Drained);
        }
        () = signalled.notified() => {}
    }
    // CANCEL-SAFETY: on timeout the server future is dropped; that only stops waiting
    // for the open connections, whose tasks are owned by the runtime.
    match tokio::time::timeout(drain, &mut server).await {
        Ok(served) => {
            served?;
            Ok(ServeEnd::Drained)
        }
        Err(_) => Ok(ServeEnd::DeadlinePassed),
    }
}

/// Wait for shutdown signal (SIGTERM or SIGINT)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    // CANCEL-SAFETY: Both futures (ctrl_c and terminate) are signal listeners
    // with no intermediate state. Dropping either loses nothing — the process
    // is about to shut down regardless.
    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT, starting graceful shutdown...");
        }
        _ = terminate => {
            info!("Received SIGTERM, starting graceful shutdown...");
        }
    }
}

/// Reload curation policy from disk (triggered by SIGHUP).
///
/// Re-reads config.toml, rebuilds the CurationEngine with new filters,
/// and atomically swaps the old config via ArcSwap.
/// Storage, auth, port, and other settings are NOT reloaded — only curation.
fn reload_curation(state: &AppState) -> Result<(), String> {
    let config = Config::try_load()?;

    // Fail-closed: `build_curation_engine` returns Err in enforce mode if any
    // filter no longer parses, so a broken allowlist surfaces here and the
    // `?` short-circuits BEFORE the `store` below — the previous (working)
    // engine is kept and never swapped for an allow-all one (#586).
    let engine = build_curation_engine(&config)?;

    state.reloadable.store(Arc::new(ReloadableConfig {
        curation_engine: engine,
        bypass_token: config.curation.bypass_token,
    }));

    Ok(())
}

/// Build a CurationEngine from the given config (used at startup and reload).
///
/// Fail-closed in enforce mode: if a configured filter fails to parse, this
/// returns `Err` instead of silently dropping it. Dropping a deny-by-default
/// allowlist would turn the engine into allow-all, so callers must refuse to
/// boot (startup) or refuse to swap (SIGHUP reload) — see #586. The file is
/// parsed exactly once here, so there is no validate-then-rebuild TOCTOU
/// window: the same parse that is checked is the one that is installed.
///
/// In audit/off mode a parse error is logged and the filter dropped (the
/// engine is advisory there), so this never returns `Err`.
fn build_curation_engine(config: &Config) -> Result<curation::CurationEngine, String> {
    let enforce = config.curation.mode == CurationMode::Enforce;
    let mut engine = curation::CurationEngine::new(config.curation.clone());

    // Load blocklist filter if configured
    if let Some(ref path) = config.curation.blocklist_path {
        match curation::BlocklistFilter::from_file(path) {
            Ok(filter) => {
                let count = filter.rule_count();
                engine.add_filter(Box::new(filter));
                info!(path = %path, rules = count, "Blocklist filter loaded");
            }
            Err(e) if enforce => return Err(format!("invalid blocklist {path}: {e}")),
            Err(e) => error!(path = %path, error = %e, "Failed to load blocklist"),
        }
    }

    // Load allowlist filter if configured
    if let Some(ref path) = config.curation.allowlist_path {
        match curation::AllowlistFilter::from_file(path, config.curation.require_integrity) {
            Ok(filter) => {
                let count = filter.entry_count();
                engine.add_filter(Box::new(filter));
                info!(path = %path, entries = count, "Allowlist filter loaded");
            }
            Err(e) if enforce => return Err(format!("invalid allowlist {path}: {e}")),
            Err(e) => error!(path = %path, error = %e, "Failed to load allowlist"),
        }
    }

    // Load namespace isolation filter if configured
    if !config.curation.internal_namespaces.is_empty() {
        let ns_filter = curation::NamespaceFilter::new(config.curation.internal_namespaces.clone());
        let count = ns_filter.pattern_count();
        engine.set_namespace_filter(Box::new(ns_filter));
        info!(patterns = count, "Namespace isolation filter loaded");
    }

    // Load the min-release-age filter if the global value or any per-registry one
    // is set: a per-registry value applies on its own (#1098).
    let (min_age, problems) = curation::MinReleaseAgeFilter::from_config(&config.curation);
    if enforce && !problems.is_empty() {
        return Err(format!("invalid min_release_age: {}", problems.join("; ")));
    }
    for problem in &problems {
        error!(problem = %problem, "Invalid min_release_age");
    }
    if let Some(filter) = min_age {
        match filter.global_only() {
            Some((secs, value)) => {
                info!(min_age = %value, seconds = secs, "Min-release-age filter loaded")
            }
            None => info!(min_age = %filter.summary(), "Min-release-age filter loaded"),
        }
        engine.add_filter(Box::new(filter));
    }

    Ok(engine)
}

/// Print note about registries that have data but no retention rules configured.
async fn print_retention_coverage(storage: &Storage, rules: &[config::RetentionRule]) {
    let covered: HashSet<&str> = rules.iter().map(|r| r.registry.as_str()).collect();
    if covered.contains("*") {
        return;
    }
    let all_registries = RegistryType::all()
        .iter()
        .map(|r| r.as_str())
        .collect::<Vec<_>>();
    let mut uncovered = Vec::new();
    for name in &all_registries {
        if !covered.contains(name) {
            let count = storage
                .list(&format!("{}/", name))
                .await
                .unwrap_or_default()
                .len();
            if count > 0 {
                uncovered.push(format!("{} ({} files)", name, count));
            }
        }
    }
    if !uncovered.is_empty() {
        println!("\nNote: No retention rules for: {}", uncovered.join(", "));
    }
}

#[cfg(test)]
mod log_file_tests {
    use super::open_log_file;

    #[test]
    fn open_log_file_creates_parent_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("nested").join("dir").join("nora.log");
        let result = open_log_file(path.to_str().unwrap());
        assert!(result.is_some(), "should open file with nested dirs");
        assert!(path.exists(), "log file should be created");
    }

    #[test]
    fn open_log_file_invalid_path() {
        let result = open_log_file("/nonexistent-root-82371/nora.log");
        assert!(result.is_none(), "should return None for invalid path");
    }

    #[test]
    fn open_log_file_appends() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("nora.log");
        std::fs::write(&path, "existing\n").unwrap();
        let result = open_log_file(path.to_str().unwrap());
        assert!(result.is_some());
        // Drop the writer to flush
        drop(result);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.starts_with("existing\n"),
            "should preserve existing content"
        );
    }

    #[test]
    fn open_log_file_empty_path() {
        // open_log_file is called only when path is non-empty,
        // but test defensively
        let result = open_log_file("");
        // Empty path will fail to open
        assert!(result.is_none());
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::sanitize_proxy_url;

    #[test]
    fn sanitize_with_credentials() {
        assert_eq!(
            sanitize_proxy_url("http://user:p%40ss@proxy:3128"),
            "http://***@proxy:3128"
        );
    }

    #[test]
    fn sanitize_user_only() {
        assert_eq!(
            sanitize_proxy_url("http://admin@proxy:3128"),
            "http://***@proxy:3128"
        );
    }

    #[test]
    fn sanitize_no_credentials() {
        assert_eq!(sanitize_proxy_url("http://proxy:3128"), "http://proxy:3128");
    }

    #[test]
    fn sanitize_socks5() {
        assert_eq!(
            sanitize_proxy_url("socks5://user:pass@proxy:1080"),
            "socks5://***@proxy:1080"
        );
    }

    #[test]
    fn sanitize_empty() {
        assert_eq!(sanitize_proxy_url(""), "");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod curation_reload_tests {
    use super::build_curation_engine;
    use crate::config::{Config, CurationConfig, CurationMode};

    fn config_with_allowlist(mode: CurationMode, allowlist_path: String) -> Config {
        Config {
            curation: CurationConfig {
                mode,
                allowlist_path: Some(allowlist_path),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Regression for #586: a SIGHUP reload must NOT swap to an allow-all engine
    /// when the allowlist no longer parses. `reload_curation()` gates its
    /// `ArcSwap::store` on `build_curation_engine(&config)?`, so this is the
    /// exact function the production reload path runs: in enforce mode a
    /// malformed allowlist must return `Err` (so `?` short-circuits before the
    /// swap and the previous engine survives), not a silently-dropped,
    /// deny-by-default-defeating filter.
    #[test]
    fn enforce_rejects_malformed_allowlist() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, b"{ not valid json").unwrap();

        let config = config_with_allowlist(CurationMode::Enforce, path.to_str().unwrap().into());
        let result = build_curation_engine(&config);
        assert!(
            result.is_err(),
            "enforce mode must reject a malformed allowlist, got an engine"
        );
    }

    /// A well-formed allowlist still builds, and the filter is actually
    /// installed (engine active) — the fix must not reject valid reloads.
    #[test]
    fn enforce_accepts_valid_allowlist() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, br#"{"version": 1, "entries": []}"#).unwrap();

        let config = config_with_allowlist(CurationMode::Enforce, path.to_str().unwrap().into());
        let engine = build_curation_engine(&config).expect("valid allowlist must build");
        assert!(engine.is_active(), "allowlist filter must be installed");
    }

    /// Audit/off mode stays lenient (matches boot behavior): a broken file
    /// there is logged and dropped, never blocking the build, since the engine
    /// is advisory.
    #[test]
    fn non_enforce_is_lenient_on_malformed_allowlist() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, b"garbage").unwrap();

        let config = config_with_allowlist(CurationMode::Off, path.to_str().unwrap().into());
        assert!(build_curation_engine(&config).is_ok());
    }

    /// Ages given in seconds, keyed by registry: what the engine decides for a
    /// release of that age.
    fn blocked(config: &Config, registry: crate::curation::RegistryType, age_secs: i64) -> bool {
        use crate::curation::{Decision, FilterRequest, RequestVersion};
        let engine = build_curation_engine(config).expect("engine builds");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let result = engine.evaluate(&FilterRequest {
            registry,
            upstream: None,
            name: "pkg".to_string(),
            version: RequestVersion::named(Some("1.0.0")),
            integrity: None,
            bypass: false,
            publish_date: Some(now - age_secs),
        });
        match result.decision {
            Decision::Block { rule, .. } => {
                assert_eq!(rule, "min-release-age");
                true
            }
            _ => false,
        }
    }

    fn enforce() -> Config {
        Config {
            curation: CurationConfig {
                mode: CurationMode::Enforce,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// #1098: a per-registry minimum age without a global one is applied to its
    /// registry, and only to it.
    #[test]
    fn a_per_registry_min_release_age_alone_is_applied_to_its_registry() {
        use crate::curation::RegistryType;
        let mut config = enforce();
        config.curation.npm.min_release_age = Some("3d".to_string());
        assert!(blocked(&config, RegistryType::Npm, 3_600));
        assert!(!blocked(&config, RegistryType::Npm, 4 * 86_400));
        for other in [RegistryType::PyPI, RegistryType::Cargo, RegistryType::Raw] {
            assert!(!blocked(&config, other, 3_600), "{other}");
        }
    }

    /// With a global value, an override applies to its registry and the global
    /// value to the others — every registry that has an override, cpan included.
    #[test]
    fn an_override_applies_to_its_registry_and_the_global_value_to_the_others() {
        use crate::curation::RegistryType;
        let mut config = enforce();
        config.curation.min_release_age = Some("1h".to_string());
        config.curation.npm.min_release_age = Some("3d".to_string());
        config.curation.cpan.min_release_age = Some("3d".to_string());
        config.curation.pypi.min_release_age = Some("1d".to_string());
        let two_hours = 2 * 3_600;
        assert!(blocked(&config, RegistryType::Npm, two_hours));
        assert!(blocked(&config, RegistryType::Cpan, two_hours));
        assert!(blocked(&config, RegistryType::PyPI, two_hours));
        assert!(!blocked(&config, RegistryType::PyPI, 2 * 86_400));
        assert!(!blocked(&config, RegistryType::Cargo, two_hours));
        assert!(blocked(&config, RegistryType::Cargo, 1_800));
    }

    /// In enforce mode an unparsable per-registry value refuses the build and
    /// names the value, as an unparsable global one does — it is never dropped.
    #[test]
    fn enforce_rejects_an_unparsable_per_registry_min_release_age() {
        // With a global value and without one: the per-registry value is read either way.
        for global in [Some("7d"), None] {
            let mut config = enforce();
            config.curation.min_release_age = global.map(str::to_string);
            config.curation.npm.min_release_age = Some("3x".to_string());
            let err = build_curation_engine(&config).err().unwrap_or_else(|| {
                panic!("global {global:?}: an unparsable value must refuse the build")
            });
            assert!(err.contains("curation.npm.min_release_age"), "{err}");
            assert!(err.contains("3x"), "{err}");
        }
    }
}

/// the production stack is `request_layers` plus exactly metrics and
/// reject_null_bytes outside it (white list), and the test router builds its layers only
/// through `request_layers`. Needles are built at run time so this text does not match.
#[cfg(test)]
mod middleware_stack_whitelist {
    fn squash(s: &str) -> String {
        s.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .flat_map(|l| l.chars())
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    #[test]
    fn the_server_stack_is_request_layers_plus_metrics_and_null_bytes() {
        let code = squash(include_str!("main.rs"));
        let fn_start = ["async", "fnrun_server("].concat();
        let body = &code[code.find(&fn_start).expect("run_server")..];
        let start = ["letapp=request_layers", "(app,&state)"].concat();
        let at = body
            .find(&start)
            .expect("run_server must build its stack with request_layers");
        let tail = &body[at..];
        let end = tail.find(".with_state(state.clone());").unwrap();
        let expected = [
            "letapp=request_layers(app,&state)",
            ".layer(middleware::from_fn(metrics::metrics_middleware))",
            ".layer(middleware::from_fn(validation::reject_null_bytes_middleware,))",
        ]
        .concat();
        assert_eq!(&tail[..end], expected);
    }

    #[test]
    fn the_test_router_builds_its_layers_only_through_request_layers() {
        let code = squash(include_str!("test_helpers.rs"));
        assert!(code.contains(&["crate::request_layers", "(routes,&state)"].concat()));
        assert_eq!(code.matches(&["from_fn", ""].concat()).count(), 0);
        assert_eq!(
            code.matches(&[".layer", "("].concat()).count(),
            1,
            "only DefaultBodyLimit"
        );
    }
}

#[cfg(test)]
mod cleanup_pass_tests {
    //! A scheduled GC or retention pass that takes files out of the store marks the
    //! repository indexes stale: the dashboard counts what is there after the pass.
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn locks() -> PublishLocks {
        Arc::new(parking_lot::Mutex::new(HashMap::new()))
    }

    /// `n` proxy-cached rpm files of 100 bytes, the first one the oldest.
    async fn rpm_cache(data: &Path, n: u32) -> Storage {
        let storage = Storage::new_local(data.to_str().unwrap());
        for i in 0..n {
            let key = format!("rpm/repo/Packages/{i}-1.0.rpm");
            storage.put(&key, &[0u8; 100]).await.unwrap();
            std::fs::File::options()
                .write(true)
                .open(data.join(&key))
                .unwrap()
                .set_modified(UNIX_EPOCH + Duration::from_secs(1_000_000 + u64::from(i) * 1000))
                .unwrap();
        }
        storage
    }

    async fn counted(index: &RepoIndex, storage: &Storage, registry: &str) -> usize {
        index
            .get(registry, storage)
            .await
            .iter()
            .map(|r| r.versions)
            .sum()
    }

    #[tokio::test]
    async fn a_gc_pass_that_evicts_marks_the_index_stale() {
        let dir = tempfile::tempdir().unwrap();
        let storage = rpm_cache(dir.path(), 5).await;
        let index = RepoIndex::new();
        assert_eq!(counted(&index, &storage, "rpm").await, 5);
        let result = gc_pass(&storage, &locks(), &index, false, 0, false, 300).await;
        assert_eq!(result.proxy_cache_eviction.evicted_files, 2);
        assert_eq!(counted(&index, &storage, "rpm").await, 3);
    }

    #[tokio::test]
    async fn a_dry_gc_pass_leaves_the_store_and_its_counts() {
        let dir = tempfile::tempdir().unwrap();
        let storage = rpm_cache(dir.path(), 5).await;
        let index = RepoIndex::new();
        assert_eq!(counted(&index, &storage, "rpm").await, 5);
        let result = gc_pass(&storage, &locks(), &index, true, 0, false, 300).await;
        assert_eq!(
            result.proxy_cache_eviction.evicted_files, 2,
            "what would go"
        );
        assert!(storage.get("rpm/repo/Packages/0-1.0.rpm").await.is_ok());
        assert_eq!(counted(&index, &storage, "rpm").await, 5);
    }

    #[tokio::test]
    async fn a_retention_pass_that_deletes_marks_the_index_stale() {
        let dir = tempfile::tempdir().unwrap();
        let (storage, rules) = go_versions(dir.path()).await;
        let index = RepoIndex::new();
        let before = counted(&index, &storage, "go").await;
        assert!(before >= 3, "{before}");
        let audit = AuditLog::new(dir.path().to_str().unwrap(), audit::AuditMode::Off);
        let result = retention_pass(&storage, &locks(), &index, None, &rules, false, &audit).await;
        assert_eq!(result.planned, 2);
        let after = counted(&index, &storage, "go").await;
        assert_eq!(
            after,
            before / 3,
            "one version of three left: {before} -> {after}"
        );
    }

    /// Three go module versions and a `keep_last = 1` rule: a pass finds two to delete.
    async fn go_versions(data: &Path) -> (Storage, Vec<config::RetentionRule>) {
        let storage = Storage::new_local(data.to_str().unwrap());
        for ver in ["v1.0.0", "v2.0.0", "v3.0.0"] {
            for ext in ["info", "mod", "zip"] {
                let key = format!("go/github.com/user/repo/@v/{ver}.{ext}");
                storage.put(&key, b"x").await.unwrap();
            }
        }
        let rules = vec![config::RetentionRule {
            registry: "go".to_string(),
            name_glob: None,
            keep_last: Some(1),
            older_than_days: None,
            include_tags: Vec::new(),
            exclude_tags: Vec::new(),
        }];
        (storage, rules)
    }

    /// The actions a retention pass wrote to `audit.jsonl` under `audit_dir`.
    async fn audited_actions(
        storage: &Storage,
        rules: &[config::RetentionRule],
        dry_run: bool,
        audit_dir: &Path,
    ) -> Vec<String> {
        let audit = AuditLog::new(audit_dir.to_str().unwrap(), audit::AuditMode::File);
        let result = retention_pass(
            storage,
            &locks(),
            &RepoIndex::new(),
            None,
            rules,
            dry_run,
            &audit,
        )
        .await;
        assert_eq!(result.planned, 2, "two of three versions are due");
        let path = audit.path().clone();
        audit.shutdown().await;
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| {
                let entry: serde_json::Value = serde_json::from_str(line).unwrap();
                format!(
                    "{} {}",
                    entry["action"].as_str().unwrap(),
                    entry["detail"].as_str().unwrap()
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn a_dry_retention_pass_is_not_audited_as_applied() {
        let data = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let (storage, rules) = go_versions(data.path()).await;
        let actions = audited_actions(&storage, &rules, true, audit_dir.path()).await;
        assert_eq!(actions.len(), 1, "{actions:?}");
        assert!(
            actions[0].starts_with("retention-dry-run would_free_bytes="),
            "{actions:?}"
        );
        assert!(
            !actions[0].contains("bytes_freed") && !actions[0].contains("keys="),
            "{actions:?}"
        );
        assert!(
            storage
                .get("go/github.com/user/repo/@v/v1.0.0.zip")
                .await
                .is_ok(),
            "a dry run deletes nothing"
        );
    }

    #[tokio::test]
    async fn an_applied_retention_pass_is_audited_as_applied() {
        let data = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let (storage, rules) = go_versions(data.path()).await;
        let actions = audited_actions(&storage, &rules, false, audit_dir.path()).await;
        assert_eq!(actions.len(), 1, "{actions:?}");
        assert!(
            actions[0].starts_with("retention-apply keys=6 bytes_freed="),
            "{actions:?}"
        );
        assert!(storage
            .get("go/github.com/user/repo/@v/v1.0.0.zip")
            .await
            .is_err());
    }

    #[test]
    fn the_gc_done_line_names_the_proxy_cache_evictions_apart_from_the_orphans() {
        let result = gc::GcResult {
            total_candidates: 10,
            orphaned: 3,
            deleted: 2,
            bytes_freed: 700,
            orphan_keys: Vec::new(),
            duration_secs: 0.5,
            uncovered: Vec::new(),
            metadata_phantoms_removed: 1,
            skipped_recent: 1,
            stat_failures: 0,
            docker_mark_failed: false,
            proxy_cache_eviction: gc::ProxyCacheEviction {
                total_bytes: 9_000,
                evicted_files: 5,
                bytes_freed: 4_096,
            },
        };
        let line = gc_done_line(&result, false);
        assert!(
            line.contains("3 orphans (2 deleted, 700 bytes freed)"),
            "{line}"
        );
        assert!(
            line.contains("5 evicted from the proxy cache (4096 bytes freed)"),
            "{line}"
        );
        // A dry pass freed nothing: the line says what an applied pass would.
        let dry = gc_done_line(&result, true);
        assert!(dry.contains("dry run"), "{dry}");
        assert!(dry.contains("700 bytes would be freed"), "{dry}");
        assert!(
            dry.contains("5 would be evicted from the proxy cache (4096 bytes)"),
            "{dry}"
        );
        assert!(
            !dry.contains("deleted") && !dry.contains("bytes freed"),
            "{dry}"
        );
    }

    fn artifacts_gauge(rt: RegistryType) -> i64 {
        metrics::ARTIFACTS_TOTAL
            .with_label_values(&[rt.as_str()])
            .get()
    }

    fn bytes_gauge(rt: RegistryType) -> i64 {
        metrics::STORAGE_BYTES
            .with_label_values(&[rt.as_str()])
            .get()
    }

    /// The only test that sets the per-registry gauges: they are process-wide.
    #[tokio::test]
    async fn the_artifact_gauges_follow_the_store_without_a_read_of_the_ui() {
        let (storage, ops) = test_helpers::op_counting_storage();
        // Five proxy-cached rpm repositories of one 100-byte file each, and go data
        // of a registry that is not enabled.
        for i in 0..5 {
            storage
                .put(&format!("rpm/repo{i}/Packages/{i}-1.0.rpm"), &[0u8; 100])
                .await
                .unwrap();
        }
        storage
            .put("go/github.com/user/repo/@v/v1.0.0.zip", b"x")
            .await
            .unwrap();
        let enabled: HashSet<RegistryType> = [RegistryType::Rpm].into_iter().collect();
        // A fresh process: nothing has read the index yet.
        let index = RepoIndex::new();

        ops.reset();
        refresh_artifact_gauges(&index, &storage, &enabled).await;
        assert_eq!(
            artifacts_gauge(RegistryType::Rpm),
            5,
            "first tick after a restart"
        );
        assert_eq!(bytes_gauge(RegistryType::Rpm), 500);
        assert_eq!(
            ops.snapshot(),
            [("list_with_meta", 1)].into_iter().collect(),
            "one listing, of the enabled registry only"
        );

        ops.reset();
        refresh_artifact_gauges(&index, &storage, &enabled).await;
        assert_eq!(
            ops.total(),
            0,
            "nothing changed: no storage round-trip, {:?}",
            ops.snapshot()
        );
        assert_eq!(artifacts_gauge(RegistryType::Rpm), 5);

        // A write marks its registry stale, as every handler does.
        storage
            .put("rpm/repo5/Packages/5-1.0.rpm", &[0u8; 100])
            .await
            .unwrap();
        index.invalidate("rpm");
        refresh_artifact_gauges(&index, &storage, &enabled).await;
        assert_eq!(
            artifacts_gauge(RegistryType::Rpm),
            6,
            "the tick after a write"
        );
        assert_eq!(bytes_gauge(RegistryType::Rpm), 600);

        // A GC pass evicts the proxy cache down to 300 bytes.
        let result = gc_pass(&storage, &locks(), &index, false, 0, false, 300).await;
        assert_eq!(result.proxy_cache_eviction.evicted_files, 3);
        refresh_artifact_gauges(&index, &storage, &enabled).await;
        assert_eq!(
            artifacts_gauge(RegistryType::Rpm),
            3,
            "the tick after a GC pass"
        );
        assert_eq!(bytes_gauge(RegistryType::Rpm), 300);
    }
}
