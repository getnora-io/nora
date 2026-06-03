// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]
#![warn(clippy::large_stack_frames, clippy::large_futures)]
mod activity_log;
mod audit;
mod auth;
mod backup;
mod cache_ttl;
mod circuit_breaker;
mod config;
mod curation;
mod dashboard_metrics;
mod digest_quarantine;
mod docker_key_migration;
mod gc;
mod hash_pin_store;
mod health;
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
mod storage;
mod tokens;
mod ui;
mod validation;

#[cfg(test)]
mod test_helpers;

use arc_swap::ArcSwap;
use axum::{body::Bytes, extract::DefaultBodyLimit, http::HeaderValue, middleware, Router};
use clap::{Parser, Subcommand};
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
    pub digest_store: Arc<digest_quarantine::DigestStore>,
    /// Pre-compiled upstream hostname searchers for leak detection (#386)
    pub leak_finders: metrics::LeakFinders,
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

/// Build HTTP client with optional custom CA certificate support.
///
/// When `timeout` is `Some`, a default request timeout is set on the client
/// (used by `nora mirror` for long-running downloads).
fn build_http_client(tls: &TlsConfig, timeout: Option<std::time::Duration>) -> reqwest::Client {
    let mut builder =
        reqwest::ClientBuilder::new().user_agent(format!("nora/{}", env!("CARGO_PKG_VERSION")));

    if let Some(t) = timeout {
        builder = builder.timeout(t);
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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging (JSON for server, plain for CLI commands)
    let is_server = matches!(cli.command, None | Some(Commands::Serve));
    let _log_guard = init_logging(is_server);

    let config = Config::load();

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
                    "Using S3 storage"
                );
            }
            Storage::new_s3(
                &config.storage.s3_url,
                &config.storage.bucket,
                &config.storage.s3_region,
                expose_opt(&config.storage.s3_access_key),
                expose_opt(&config.storage.s3_secret_key),
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
            let result =
                gc::run_gc(&storage, &cli_publish_locks, dry_run, config.gc.grace_secs).await;
            println!("GC Summary{}:", if dry_run { " (dry-run)" } else { "" });
            println!("  Candidates:       {}", result.total_candidates);
            println!("  Orphaned:          {}", result.orphaned);
            println!("  Deleted:           {}", result.deleted);
            println!("  Bytes freed:       {}", result.bytes_freed);
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
            if !result.uncovered.is_empty() {
                let parts: Vec<String> = result
                    .uncovered
                    .iter()
                    .map(|(name, count)| format!("{} ({} files)", name, count))
                    .collect();
                println!("\nNote: GC does not scan: {}", parts.join(", "));
            }
        }
        Some(Commands::RetentionPlan) => {
            let cli_publish_locks: PublishLocks = Arc::new(parking_lot::Mutex::new(HashMap::new()));
            let result = retention::run_retention(
                &storage,
                &cli_publish_locks,
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
                let result = retention::run_retention(
                    &storage,
                    &cli_publish_locks,
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
            let client = build_http_client(&config.tls, Some(std::time::Duration::from_secs(300)));
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
                ),
                _ => {
                    error!("Invalid source: '{}'. Use 'local' or 's3'", from);
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
                ),
                _ => {
                    error!("Invalid destination: '{}'. Use 'local' or 's3'", to);
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
    }
}

/// Load per-registry min_release_age overrides from CurationConfig into the filter.
fn load_registry_overrides(
    filter: &mut curation::MinReleaseAgeFilter,
    curation_config: &config::CurationConfig,
) {
    let registry_overrides: &[(RegistryType, &config::RegistryCurationOverride)] = &[
        (RegistryType::Npm, &curation_config.npm),
        (RegistryType::PyPI, &curation_config.pypi),
        (RegistryType::Cargo, &curation_config.cargo),
        (RegistryType::Go, &curation_config.go),
        (RegistryType::Docker, &curation_config.docker),
        (RegistryType::Maven, &curation_config.maven),
        (RegistryType::Gems, &curation_config.gems),
        (RegistryType::Terraform, &curation_config.terraform),
        (RegistryType::Ansible, &curation_config.ansible),
        (RegistryType::Nuget, &curation_config.nuget),
        (RegistryType::PubDart, &curation_config.pub_dart),
        (RegistryType::Conan, &curation_config.conan),
    ];

    for (registry, override_cfg) in registry_overrides {
        if let Some(ref age_str) = override_cfg.min_release_age {
            match curation::parse_duration(age_str) {
                Ok(secs) => {
                    filter.add_override(*registry, secs, age_str.clone());
                    tracing::info!(
                        registry = %registry,
                        min_age = %age_str,
                        seconds = secs,
                        "Per-registry min-release-age override loaded"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        registry = %registry,
                        value = %age_str,
                        error = %e,
                        "Invalid per-registry min_release_age"
                    );
                }
            }
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

fn run_curation_explain(config: &Config, package_spec: &str) {
    // Parse "registry:name@version"
    let (registry_str, rest) = match package_spec.split_once(':') {
        Some(parts) => parts,
        None => {
            eprintln!("ERROR: Expected format 'registry:name@version' (e.g., 'cargo:serde@1.0.0')");
            std::process::exit(1);
        }
    };

    let (name, version) = match rest.split_once('@') {
        Some((n, v)) => (n.to_string(), Some(v.to_string())),
        None => (rest.to_string(), None),
    };

    let registry = match RegistryType::from_str_opt(registry_str) {
        Some(rt) => rt,
        None => {
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

    if let Some(ref age_str) = config.curation.min_release_age {
        match curation::parse_duration(age_str) {
            Ok(secs) => {
                let mut filter = curation::MinReleaseAgeFilter::new(secs, age_str);
                load_registry_overrides(&mut filter, &config.curation);
                println!("Min-release-age: {} ({}s)", age_str, secs);
                engine.add_filter(Box::new(filter));
            }
            Err(e) => println!("Min-release-age: {} (ERROR: {})", age_str, e),
        }
    } else {
        println!("Min-release-age: not configured");
    }

    println!("Mode: {}", config.curation.mode);
    println!("---");

    let request = curation::FilterRequest {
        registry,
        upstream: None,
        name: name.clone(),
        version: version.clone(),
        integrity: None,
        bypass: false,
        publish_date: None,
    };

    let result = engine.evaluate(&request);
    println!(
        "Package: {}:{}@{}",
        registry_str,
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
                .with(fmt::layer().json().with_target(true))
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .with_writer(non_blocking)
                        .with_filter(file_filter),
                )
                .init();
            Some(guard)
        }
        (true, None) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json().with_target(true))
                .init();
            None
        }
        (false, Some((non_blocking, guard))) => {
            let file_filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_target(false))
                .with(
                    fmt::layer()
                        .with_target(false)
                        .with_writer(non_blocking)
                        .with_filter(file_filter),
                )
                .init();
            Some(guard)
        }
        (false, None) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_target(false))
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
        info!(path = %config.auth.token_storage, "Token storage initialized");
        Some(TokenStore::new(token_path))
    } else {
        None
    };

    let storage_path = config.storage.path.clone();
    let rate_limit_enabled = config.rate_limit.enabled;

    // Warn about plaintext credentials in config.toml
    config.warn_plaintext_credentials();

    let http_client = build_http_client(&config.tls, None);
    log_outbound_proxy();

    // Initialize Docker auth with shared HTTP client (includes custom CA certs)
    let docker_auth = registry::DockerAuth::new(http_client.clone(), config.docker.proxy_timeout);

    // Discover NuGet search endpoints from upstream service index
    if config.nuget.enabled {
        registry::nuget::discover_search_endpoints(&http_client, &mut config.nuget).await;
    }

    // Build curation engine (shared helper, also used by SIGHUP reload).
    // Fail-closed: in enforce mode an unparsable filter aborts boot rather
    // than starting in a silent allow-all state (#586).
    let curation_engine = build_curation_engine(&config)
        .unwrap_or_else(|e| panic!("Cannot start in enforce mode: {e}"));
    if curation_engine.is_active() {
        info!(
            mode = %config.curation.mode,
            "Curation layer active"
        );
    }

    // Determine enabled registries from config
    let enabled_registries = config.enabled_registries();

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
        }
    }

    // Routes WITHOUT rate limiting (health, metrics, UI)
    let public_routes = Router::new()
        .merge(health::routes())
        .merge(metrics::routes())
        .merge(ui::routes())
        .merge(openapi::routes());

    let app_routes = if rate_limit_enabled {
        // Create rate limiters before moving config to state
        let auth_limiter =
            rate_limit::auth_rate_limiter(&config.rate_limit, config.auth.trusted_proxies.clone());
        let upload_limiter = rate_limit::upload_rate_limiter(&config.rate_limit);
        let general_limiter = rate_limit::general_rate_limiter(&config.rate_limit);

        // Auth routes: auth_limiter (strict 1rps) + general_limiter
        let auth_routes = auth::token_routes()
            .layer(auth_limiter)
            .layer(general_limiter);
        // Registry routes: upload_limiter only (200rps/500burst)
        // No general_limiter — avoids double-limiting that causes 429
        // during cache warming (dotnet restore with many packages)
        let limited_registry = registry_routes.layer(upload_limiter);

        Router::new().merge(auth_routes).merge(limited_registry)
    } else {
        info!("Rate limiting DISABLED");
        Router::new()
            .merge(auth::token_routes())
            .merge(registry_routes)
    };

    let startup_duration_ms = start_time.elapsed().as_millis() as u64;

    let cb_config = config.circuit_breaker.clone();
    let audit_mode = config.audit.mode.clone();

    // Initialize digest quarantine store
    let digest_store = if config.curation.quarantine.is_some() {
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
    let state = AppState {
        storage,
        config: Arc::new(config),
        enabled_registries,
        start_time,
        startup_duration_ms,
        auth: auth.map(Arc::new),
        tokens,
        metrics: Arc::new(DashboardMetrics::with_persistence(&storage_path)),
        activity: Arc::new(ActivityLog::new(50)),
        audit: Arc::new(AuditLog::new(&storage_path, audit_mode)),
        docker_auth: Arc::new(docker_auth),
        repo_index: Arc::new(RepoIndex::new()),
        http_client,
        upload_sessions: Arc::new(RwLock::new(HashMap::new())),
        publish_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        reloadable,
        auth_failures: Arc::new(auth::AuthFailureTracker::new(5, 900)),
        oidc: oidc_validator.map(Arc::new),
        circuit_breaker: Arc::new(circuit_breaker::CircuitBreakerRegistry::new(cb_config)),
        proxy_coalesce: proxy_coalesce::InflightMap::new(),
        digest_store,
        leak_finders,
    };

    // Initialize circuit breaker gauge to 0 (Closed) for all registries (#441)
    let registry_names: Vec<&str> = RegistryType::all().iter().map(|rt| rt.as_str()).collect();
    state.circuit_breaker.init_gauges(&registry_names);

    // Shared lock: GC and Retention must not run concurrently (both call storage.delete)
    let cleanup_lock = Arc::new(tokio::sync::Mutex::new(()));

    // Cancellation token for graceful shutdown of background schedulers (#306)
    let cancel_token = tokio_util::sync::CancellationToken::new();
    let mut scheduler_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // Spawn background GC scheduler if enabled
    if state.config.gc.enabled {
        let handle = gc::spawn_gc_scheduler(
            state.storage.clone(),
            state.publish_locks.clone(),
            state.config.gc.interval,
            state.config.gc.dry_run,
            state.config.gc.grace_secs,
            cleanup_lock.clone(),
            cancel_token.clone(),
        );
        scheduler_handles.push(handle);
        info!(
            interval_secs = state.config.gc.interval,
            dry_run = state.config.gc.dry_run,
            "GC scheduler started"
        );
    }

    // Spawn background retention scheduler if enabled
    if state.config.retention.enabled && !state.config.retention.rules.is_empty() {
        let handle = retention::spawn_retention_scheduler(
            state.storage.clone(),
            state.publish_locks.clone(),
            state.config.retention.rules.clone(),
            state.config.retention.interval,
            state.config.retention.dry_run,
            Some(state.audit.clone()),
            cleanup_lock.clone(),
            cancel_token.clone(),
        );
        scheduler_handles.push(handle);
        info!(
            interval_secs = state.config.retention.interval,
            rules = state.config.retention.rules.len(),
            dry_run = state.config.retention.dry_run,
            "Retention scheduler started"
        );
    }

    let app = Router::new()
        .merge(public_routes)
        .merge(app_routes)
        .layer(DefaultBodyLimit::max(
            state.config.server.body_limit_mb * 1024 * 1024,
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            axum::http::header::HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            axum::http::header::HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            axum::http::header::HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            axum::http::header::HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'"),
        ))
        // Middleware layer order — LOAD-BEARING, do not reorder (#542).
        //
        // In axum, last .layer() = outermost (runs first). Execution order:
        //   reject_null_bytes → metrics → auth → leak_detection → request_id → handler
        //
        // reject_null_bytes MUST be outermost to block null-byte path attacks
        // before any processing occurs.
        // metrics MUST be next-outermost so it counts ALL responses including
        // auth rejections (401/403/429) in nora_http_requests_total.
        // request_id is innermost so the ID is available to handlers.
        .layer(middleware::from_fn(request_id::request_id_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            metrics::leak_detection_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .layer(middleware::from_fn(metrics::metrics_middleware))
        .layer(middleware::from_fn(validation::reject_null_bytes_middleware))
        .with_state(state.clone());

    // Clean up stale Docker temp files from previous runs (#530, #580).
    if state.config.docker.enabled {
        registry::docker::cleanup_upload_temp_dir(&state.config.storage.path);
        registry::docker::cleanup_proxy_temp_dir(&state.config.storage.path);
    }

    let addr = state.config.server.bind_addr();
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");

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

    // Background task: persist metrics and flush token last_used every 30 seconds
    let metrics_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        let mut tick_count: u64 = 0;
        loop {
            interval.tick().await;
            tick_count += 1;
            metrics_state.metrics.save().await;
            if let Some(ref token_store) = metrics_state.tokens {
                token_store.flush_last_used().await;
            }
            registry::docker::cleanup_expired_sessions(&metrics_state.upload_sessions);
            metrics_state.auth_failures.cleanup();

            // Every 60s (every other tick): refresh S3 total_size cache + storage gauge
            if tick_count.is_multiple_of(2) {
                metrics_state.storage.refresh_total_size_cache().await;
                metrics::STORAGE_BYTES
                    .with_label_values(&["total"])
                    .set(metrics_state.storage.total_size().await as i64);
            }

            // Every 5 minutes (tick_count % 10 == 0): evict unused publish locks
            // + clean up stale proxy temp files (#580)
            if tick_count.is_multiple_of(10) {
                let mut locks = metrics_state.publish_locks.lock();
                locks.retain(|_, arc| Arc::strong_count(arc) > 1);
                let storage_path = metrics_state.config.storage.path.clone();
                tokio::task::spawn_blocking(move || {
                    registry::docker::cleanup_proxy_temp_dir(&storage_path);
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

    // Graceful shutdown on SIGTERM/SIGINT
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("Server error");

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

    // Save metrics on shutdown
    state.metrics.save().await;

    // Flush token last_used timestamps to disk
    if let Some(ref token_store) = state.tokens {
        token_store.flush_last_used().await;
    }

    info!(
        uptime_seconds = state.start_time.elapsed().as_secs(),
        "Nora shutdown complete"
    );
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

    // Load min-release-age filter if configured
    if let Some(ref age_str) = config.curation.min_release_age {
        match curation::parse_duration(age_str) {
            Ok(secs) => {
                let mut filter = curation::MinReleaseAgeFilter::new(secs, age_str);
                load_registry_overrides(&mut filter, &config.curation);
                engine.add_filter(Box::new(filter));
                info!(min_age = %age_str, seconds = secs, "Min-release-age filter loaded");
            }
            Err(e) if enforce => return Err(format!("invalid min_release_age {age_str}: {e}")),
            Err(e) => error!(value = %age_str, error = %e, "Invalid min_release_age"),
        }
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
}
