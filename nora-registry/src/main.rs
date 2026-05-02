// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]
mod activity_log;
mod audit;
mod auth;
mod backup;
mod config;
mod curation;
mod dashboard_metrics;
mod error;
mod gc;
mod hash_pin_store;
mod health;
mod metrics;
mod migrate;
mod mirror;
mod openapi;
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
use config::{Config, CurationMode, StorageMode};
use dashboard_metrics::DashboardMetrics;
use registry_type::RegistryType;
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
    /// Curation tools: validate files, explain decisions
    Curation {
        #[command(subcommand)]
        action: CurationCommand,
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

pub struct AppState {
    pub storage: Storage,
    pub config: Config,
    pub enabled_registries: HashSet<RegistryType>,
    pub start_time: Instant,
    pub startup_duration_ms: u64,
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
    pub curation: curation::CurationEngine,
    /// Per-IP failed auth attempt tracker for brute-force protection
    pub auth_failures: auth::AuthFailureTracker,
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
        Some(Commands::Curation { action }) => match action {
            CurationCommand::Validate { file } => {
                run_curation_validate(&file);
            }
            CurationCommand::Explain { package } => {
                run_curation_explain(&config, &package);
            }
        },
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

    // Initialize curation engine
    let mut curation_engine = curation::CurationEngine::new(config.curation.clone());
    if curation_engine.is_active() {
        info!(
            mode = %config.curation.mode,
            "Curation layer active"
        );
    }

    // Load blocklist filter if configured
    if let Some(ref path) = config.curation.blocklist_path {
        match curation::BlocklistFilter::from_file(path) {
            Ok(filter) => {
                let count = filter.rule_count();
                curation_engine.add_filter(Box::new(filter));
                info!(path = %path, rules = count, "Blocklist filter loaded");
            }
            Err(e) => {
                error!(path = %path, error = %e, "Failed to load blocklist");
                if config.curation.mode == CurationMode::Enforce {
                    panic!("Cannot start in enforce mode with invalid blocklist");
                }
            }
        }
    }

    // Load allowlist filter if configured (after blocklist — blocklist wins on overlap)
    if let Some(ref path) = config.curation.allowlist_path {
        match curation::AllowlistFilter::from_file(path, config.curation.require_integrity) {
            Ok(filter) => {
                let count = filter.entry_count();
                curation_engine.add_filter(Box::new(filter));
                info!(path = %path, entries = count, "Allowlist filter loaded");
            }
            Err(e) => {
                error!(path = %path, error = %e, "Failed to load allowlist");
                if config.curation.mode == CurationMode::Enforce {
                    panic!("Cannot start in enforce mode with invalid allowlist");
                }
            }
        }
    }

    // Load namespace isolation filter if configured (always active, even in mode=Off)
    if !config.curation.internal_namespaces.is_empty() {
        let ns_filter = curation::NamespaceFilter::new(config.curation.internal_namespaces.clone());
        let count = ns_filter.pattern_count();
        curation_engine.set_namespace_filter(Box::new(ns_filter));
        info!(patterns = count, "Namespace isolation filter loaded");
    }

    // Load min-release-age filter if configured
    if let Some(ref age_str) = config.curation.min_release_age {
        match curation::parse_duration(age_str) {
            Ok(secs) => {
                let mut filter = curation::MinReleaseAgeFilter::new(secs, age_str);
                load_registry_overrides(&mut filter, &config.curation);
                curation_engine.add_filter(Box::new(filter));
                info!(min_age = %age_str, seconds = secs, "Min-release-age filter loaded");
            }
            Err(e) => {
                error!(value = %age_str, error = %e, "Invalid min_release_age");
                if config.curation.mode == CurationMode::Enforce {
                    panic!(
                        "Cannot start in enforce mode with invalid min_release_age: {}",
                        e
                    );
                }
            }
        }
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
                registry_routes = registry_routes.merge(registry::nuget_routes())
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

    let startup_duration_ms = start_time.elapsed().as_millis() as u64;

    let state = Arc::new(AppState {
        storage,
        config,
        enabled_registries,
        start_time,
        startup_duration_ms,
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
        curation: curation_engine,
        auth_failures: auth::AuthFailureTracker::new(5, 900),
    });

    // Shared lock: GC and Retention must not run concurrently (both call storage.delete)
    let cleanup_lock = Arc::new(tokio::sync::Mutex::new(()));

    // Spawn background GC scheduler if enabled
    if state.config.gc.enabled {
        gc::spawn_gc_scheduler(
            state.storage.clone(),
            state.config.gc.interval,
            state.config.gc.dry_run,
            cleanup_lock.clone(),
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
            state.config.retention.dry_run,
            Some(std::sync::Arc::new(audit::AuditLog::new(&storage_path))),
            cleanup_lock.clone(),
        );
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

            // Every 60s (every other tick): refresh S3 total_size cache
            if tick_count.is_multiple_of(2) {
                metrics_state.storage.refresh_total_size_cache().await;
            }

            // Every 5 minutes (tick_count % 10 == 0): evict unused publish locks
            if tick_count.is_multiple_of(10) {
                let mut locks = metrics_state.publish_locks.lock();
                locks.retain(|_, arc| Arc::strong_count(arc) > 1);
            }
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
    let all_registries = RegistryType::all_v1()
        .iter()
        .map(|r| r.as_str())
        .collect::<Vec<_>>();
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
