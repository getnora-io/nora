// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

mod activity_log;
mod auth;
mod backup;
mod config;
mod dashboard_metrics;
mod error;
mod health;
mod metrics;
mod migrate;
mod openapi;
mod rate_limit;
mod registry;
mod repo_index;
mod request_id;
mod secrets;
mod storage;
mod tokens;
mod ui;
mod validation;

use axum::{extract::DefaultBodyLimit, middleware, Router};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use activity_log::ActivityLog;
use auth::HtpasswdAuth;
use config::{Config, StorageMode};
use dashboard_metrics::DashboardMetrics;
use repo_index::RepoIndex;
pub use storage::Storage;
use tokens::TokenStore;

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
}

pub struct AppState {
    pub storage: Storage,
    pub config: Config,
    pub start_time: Instant,
    pub auth: Option<HtpasswdAuth>,
    pub tokens: Option<TokenStore>,
    pub metrics: DashboardMetrics,
    pub activity: ActivityLog,
    pub docker_auth: registry::DockerAuth,
    pub repo_index: RepoIndex,
    pub http_client: reqwest::Client,
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

    // Create rate limiters before moving config to state
    let auth_limiter = rate_limit::auth_rate_limiter(&config.rate_limit);
    let upload_limiter = rate_limit::upload_rate_limiter(&config.rate_limit);
    let general_limiter = rate_limit::general_rate_limiter(&config.rate_limit);

    // Initialize Docker auth with proxy timeout
    let docker_auth = registry::DockerAuth::new(config.docker.proxy_timeout);

    let http_client = reqwest::Client::new();

    let state = Arc::new(AppState {
        storage,
        config,
        start_time,
        auth,
        tokens,
        metrics: DashboardMetrics::new(),
        activity: ActivityLog::new(50),
        docker_auth,
        repo_index: RepoIndex::new(),
        http_client,
    });

    // Token routes with strict rate limiting (brute-force protection)
    let auth_routes = auth::token_routes().layer(auth_limiter);

    // Registry routes with upload rate limiting
    let registry_routes = Router::new()
        .merge(registry::docker_routes())
        .merge(registry::maven_routes())
        .merge(registry::npm_routes())
        .merge(registry::cargo_routes())
        .merge(registry::pypi_routes())
        .merge(registry::raw_routes())
        .layer(upload_limiter);

    // Routes WITHOUT rate limiting (health, metrics, UI)
    let public_routes = Router::new()
        .merge(health::routes())
        .merge(metrics::routes())
        .merge(ui::routes())
        .merge(openapi::routes());

    // Routes WITH rate limiting
    let rate_limited_routes = Router::new()
        .merge(auth_routes)
        .merge(registry_routes)
        .layer(general_limiter);

    let app = Router::new()
        .merge(public_routes)
        .merge(rate_limited_routes)
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024)) // 100MB default body limit
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
        raw = "/raw/",
        "Available endpoints"
    );

    // Graceful shutdown on SIGTERM/SIGINT
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("Server error");

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
