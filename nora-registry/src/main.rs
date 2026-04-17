// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT
#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]
mod activity_log;
mod audit;
mod auth;
mod backup;
mod config;
mod dashboard_metrics;
mod error;
mod gc;
mod health;
mod metrics;
mod migrate;
mod mirror;
mod openapi;
mod rate_limit;
mod registry;
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

use axum::{extract::DefaultBodyLimit, http::HeaderValue, middleware, Router};
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
use config::{Config, StorageMode};
use dashboard_metrics::DashboardMetrics;
use repo_index::RepoIndex;
pub use storage::Storage;
use tokens::TokenStore;

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
}

pub struct AppState {
    pub storage: Storage,
    pub config: Config,
    pub start_time: Instant,
    pub auth: Option<HtpasswdAuth>,
    pub tokens: Option<TokenStore>,
    pub metrics: DashboardMetrics,
    pub activity: ActivityLog,
    pub audit: AuditLog,
    pub docker_auth: registry::DockerAuth,
    pub repo_index: RepoIndex,
    pub http_client: reqwest::Client,
    pub upload_sessions: Arc<RwLock<HashMap<String, registry::docker::UploadSession>>>,
    /// Per-key publish locks for TOCTOU protection (immutable releases)
    publish_locks: parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl AppState {
    /// Get or create a per-key publish lock for TOCTOU protection.
    pub fn publish_lock(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.publish_locks.lock();
        locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging (JSON for server, plain for CLI commands)
    let is_server = matches!(cli.command, None | Some(Commands::Serve));
    init_logging(is_server);

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
                config.storage.s3_access_key.as_deref(),
                config.storage.s3_secret_key.as_deref(),
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
            let result = gc::run_gc(&storage, dry_run).await;
            println!("GC Summary{}:", if dry_run { " (dry-run)" } else { "" });
            println!("  Candidates:       {}", result.total_candidates);
            println!("  Orphaned:          {}", result.orphaned);
            println!("  Deleted:           {}", result.deleted);
            println!("  Bytes freed:       {}", result.bytes_freed);
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
            let result = retention::run_retention(&storage, &config.retention.rules, true).await;
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
            if !yes {
                // Show plan first, require --yes to execute
                let result =
                    retention::run_retention(&storage, &config.retention.rules, true).await;
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
                let result =
                    retention::run_retention(&storage, &config.retention.rules, false).await;
                println!("Retention Applied:");
                println!("  Versions deleted:   {}", result.planned);
                println!("  Keys deleted:       {}", result.deleted_keys);
                println!("  Bytes freed:        {}", result.bytes_freed);
                if result.planned > 0 {
                    let audit = AuditLog::new(&config.storage.path);
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
            if let Err(e) = mirror::run_mirror(format, &registry, concurrency, json).await {
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
                    config.storage.s3_access_key.as_deref(),
                    config.storage.s3_secret_key.as_deref(),
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
                    config.storage.s3_access_key.as_deref(),
                    config.storage.s3_secret_key.as_deref(),
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
    }
}

fn init_logging(json_format: bool) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if json_format {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json().with_target(true))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().with_target(false))
            .init();
    }
}

async fn run_server(config: Config, storage: Storage) {
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

    // Initialize secrets provider
    let secrets_provider = match secrets::create_secrets_provider(&config.secrets) {
        Ok(provider) => {
            info!(
                provider = provider.provider_name(),
                clear_env = config.secrets.clear_env,
                "Secrets provider initialized"
            );
            Some(provider)
        }
        Err(e) => {
            warn!(error = %e, "Failed to initialize secrets provider, using defaults");
            None
        }
    };

    // Store secrets provider for future use (S3 credentials, etc.)
    let _secrets = secrets_provider;

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
        None
    };

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

    // Initialize Docker auth with proxy timeout
    let docker_auth = registry::DockerAuth::new(config.docker.proxy_timeout);

    let http_client = reqwest::Client::new();

    // Registry routes (shared between rate-limited and non-limited paths)
    let registry_routes = Router::new()
        .merge(registry::docker_routes())
        .merge(registry::maven_routes())
        .merge(registry::npm_routes())
        .merge(registry::cargo_routes())
        .merge(registry::pypi_routes())
        .merge(registry::raw_routes())
        .merge(registry::go_routes());

    // Routes WITHOUT rate limiting (health, metrics, UI)
    let public_routes = Router::new()
        .merge(health::routes())
        .merge(metrics::routes())
        .merge(ui::routes())
        .merge(openapi::routes());

    let app_routes = if rate_limit_enabled {
        // Create rate limiters before moving config to state
        let auth_limiter = rate_limit::auth_rate_limiter(&config.rate_limit);
        let upload_limiter = rate_limit::upload_rate_limiter(&config.rate_limit);
        let general_limiter = rate_limit::general_rate_limiter(&config.rate_limit);

        let auth_routes = auth::token_routes().layer(auth_limiter);
        let limited_registry = registry_routes.layer(upload_limiter);

        Router::new()
            .merge(auth_routes)
            .merge(limited_registry)
            .layer(general_limiter)
    } else {
        info!("Rate limiting DISABLED");
        Router::new()
            .merge(auth::token_routes())
            .merge(registry_routes)
    };

    let state = Arc::new(AppState {
        storage,
        config,
        start_time,
        auth,
        tokens,
        metrics: DashboardMetrics::with_persistence(&storage_path),
        activity: ActivityLog::new(50),
        audit: AuditLog::new(&storage_path),
        docker_auth,
        repo_index: RepoIndex::new(),
        http_client,
        upload_sessions: Arc::new(RwLock::new(HashMap::new())),
        publish_locks: parking_lot::Mutex::new(HashMap::new()),
    });

    // Spawn background GC scheduler if enabled
    if state.config.gc.enabled {
        gc::spawn_gc_scheduler(
            state.storage.clone(),
            state.config.gc.interval,
            state.config.gc.dry_run,
        );
        info!(
            interval_secs = state.config.gc.interval,
            dry_run = state.config.gc.dry_run,
            "GC scheduler started"
        );
    }

    // Spawn background retention scheduler if enabled
    if state.config.retention.enabled && !state.config.retention.rules.is_empty() {
        retention::spawn_retention_scheduler(
            state.storage.clone(),
            state.config.retention.rules.clone(),
            state.config.retention.interval,
            Some(std::sync::Arc::new(audit::AuditLog::new(&storage_path))),
        );
        info!(
            interval_secs = state.config.retention.interval,
            rules = state.config.retention.rules.len(),
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
            HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'"),
        ))
        .layer(middleware::from_fn(request_id::request_id_middleware))
        .layer(middleware::from_fn(metrics::metrics_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .with_state(state.clone());

    let addr = format!("{}:{}", state.config.server.host, state.config.server.port);
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

    info!(
        health = "/health",
        ready = "/ready",
        metrics = "/metrics",
        ui = "/ui/",
        api_docs = "/api-docs",
        docker = "/v2/",
        maven = "/maven2/",
        npm = "/npm/",
        cargo = "/cargo/",
        pypi = "/simple/",
        go = "/go/",
        raw = "/raw/",
        "Available endpoints"
    );

    // Background task: persist metrics and flush token last_used every 30 seconds
    let metrics_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            metrics_state.metrics.save().await;
            if let Some(ref token_store) = metrics_state.tokens {
                token_store.flush_last_used().await;
            }
            registry::docker::cleanup_expired_sessions(&metrics_state.upload_sessions);
        }
    });

    // Graceful shutdown on SIGTERM/SIGINT
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("Server error");

    // Save metrics on shutdown
    state.metrics.save().await;

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

    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT, starting graceful shutdown...");
        }
        _ = terminate => {
            info!("Received SIGTERM, starting graceful shutdown...");
        }
    }
}

/// Print note about registries that have data but no retention rules configured.
async fn print_retention_coverage(storage: &Storage, rules: &[config::RetentionRule]) {
    let covered: HashSet<&str> = rules.iter().map(|r| r.registry.as_str()).collect();
    if covered.contains("*") {
        return;
    }
    let all_registries = ["docker", "maven", "npm", "pypi", "cargo", "go", "raw"];
    let mut uncovered = Vec::new();
    for name in &all_registries {
        if !covered.contains(name) {
            let count = storage.list(&format!("{}/", name)).await.len();
            if count > 0 {
                uncovered.push(format!("{} ({} files)", name, count));
            }
        }
    }
    if !uncovered.is_empty() {
        println!("\nNote: No retention rules for: {}", uncovered.join(", "));
    }
}
