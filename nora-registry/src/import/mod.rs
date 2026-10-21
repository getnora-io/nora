//! `nora import` — pull artifacts from an external registry (Artifactory / Nexus)
//! into NORA's storage. Stateless, filesystem-resumable, single static binary (#599).
//!
//! Migration-only: this module never serves requests. It touches the rest of
//! NORA only through three deliberate seams — the [`StorageBackend`](crate::storage)
//! trait, the [`CurationEngine`](crate::curation), and each format handler's
//! `pub(crate)` **storage-key builder** (`registry::{maven,raw}::storage_key`) —
//! never registry protocol logic. The key-builder seam is load-bearing (review
//! R7): reusing the handler's own key function is what keeps imported keys
//! byte-identical to served keys, so GC/retention/UI browse see them. The
//! transfer step ([`transfer`]) reuses the crash-safe *core* of the proxy blob
//! path — a `TempFileGuard` RAII + incremental Sha256, streamed to a temp file
//! with a per-read stall timeout (client `read_timeout`, not a total cap) — plus
//! the concurrency + reporting shape from `mirror/`.
//!
//! Load-bearing invariants (see #599 + the plan-stage review; contracts):
//! - **verify-before-commit, fail-closed**: a source→local checksum mismatch, or
//!   an unverifiable artifact, leaves *nothing* in storage (the storage backend
//!   is never called) — review R8, contract `import-checksum-fail-closed`.
//! - **curation not bypassed**: commit runs the FULL `CurationEngine::evaluate`
//!   (not `verify_integrity_by_hash`, which is integrity-only), honoring
//!   audit-mode semantics — review R1, contract `import-curation-full-chain`.
//! - **durable commit**: the temp file is `sync_all()`'d before the atomic
//!   rename (the same-fs rename branch relies on the caller having fsync'd) —
//!   review R4, contract `import-durable-commit`.
//! - **no job/state DB**: resume is an authoritative on-disk `.done`/journal
//!   oracle + a content-addressed fast-path (ADR-2) — review R5, contract
//!   `import-resume-journal-authoritative`.
//! - **every written key passes `validate_storage_key`** and is built by the
//!   same key-functions the format handlers use — review R7, contract
//!   `import-key-format-equals-handler-key-format`.
//! - **SSRF guard** on the source URL and every redirect hop (DNS-pinned) —
//!   review R2, contract `import-ssrf-per-redirect-hop`.

use async_trait::async_trait;
use axum::body::Bytes;
use futures::stream::BoxStream;

pub mod http;
pub mod layout;
pub mod permissions;
pub mod resume;
pub mod source;
pub mod transfer;

/// Import error. STRING-backed for the scaffold (matches the `migrate.rs`
/// sibling); TODO(#599) upgrade to a `thiserror` `ImportError` enum so the
/// fail-closed call sites can distinguish checksum-mismatch / curation-block /
/// ssrf-reject / source-http as they land.
pub type Result<T> = std::result::Result<T, String>;

/// A repository discovered on the source registry.
#[derive(Debug, Clone)]
pub struct RepoRef {
    pub name: String,
    /// Source-reported format (e.g. `maven2`, `npm`, `docker`, `yum`, `raw`).
    /// Normalized to a [`RegistryType`](crate::registry_type) in `layout`.
    pub format: String,
}

/// One artifact (file) on the source registry, with whatever checksums the
/// source advertised. `sha256`/`sha1` are kept separate: older Nexus Maven
/// artifacts advertise only sha1, and each advertised digest is verified
/// against the same-algorithm local digest before commit.
#[derive(Debug, Clone)]
pub struct ArtifactRef {
    pub repo: String,
    pub path: String,
    pub name: String,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
}

/// A migration source. Implementors are **forward-only cursors** so a source's
/// native pagination (Artifactory offset, Nexus opaque continuation token)
/// never leaks and resume never re-walks completed pages (avoids O(n²)).
/// Lives outside `registry/`; must not touch storage directly.
#[async_trait]
pub trait SourceRegistry: Send + Sync {
    /// Enumerate repositories on the source.
    async fn list_repositories(&self) -> Result<Vec<RepoRef>>;

    /// Forward-only cursor over a repo's artifacts. The adapter threads its
    /// native pagination token internally.
    fn artifacts<'a>(&'a self, repo: &'a str) -> BoxStream<'a, Result<ArtifactRef>>;

    /// Stream an artifact's body — never buffered whole in memory (peak = O(chunk)).
    async fn download_stream(
        &self,
        artifact: &ArtifactRef,
    ) -> Result<BoxStream<'static, Result<Bytes>>>;

    /// Connectivity smoke check for `assess`. Default: a successful repository
    /// listing (YAGNI, per review — adapters need not implement a trivial
    /// health check; override for a lighter endpoint).
    async fn ping(&self) -> Result<()> {
        self.list_repositories().await.map(|_| ())
    }
}

/// Which external registry to import from.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum SourceKind {
    Artifactory,
    Nexus,
}

/// `nora import {assess,run}`.
#[derive(Debug, clap::Subcommand)]
pub enum ImportCommand {
    /// Read-only: per-repo compatibility table + connectivity/SSRF/auth smoke
    /// test. Writes nothing, sets no markers.
    Assess(AssessArgs),
    /// Pull repos + artifacts into NORA storage (verify-before-commit, resumable).
    ///
    /// npm: each tarball is imported with the version document a publish writes, and that
    /// document names the tarball under the public URL in effect when the import runs. Run the
    /// import with the public URL the server uses (NORA_PUBLIC_URL, or `public_url` under
    /// `[server]` in the same config): without one the bind address is written, and clients
    /// cannot fetch the tarballs.
    ///
    /// PyPI and NuGet: a project or package imported from a repository of the source is NORA's
    /// own from then on. Its index, registration and files are served from what the import
    /// stored, and no upstream is asked for its name — a version NORA does not hold is not found.
    /// Only distribution files (.whl, .tar.gz, .zip, .egg) and .nupkg files are imported; a
    /// .nupkg must hold one .nuspec naming the id and version of its file name.
    ///
    /// Upgrading from 1.4.1 or older: an npm repository those releases imported holds tarballs
    /// without version documents, and NORA does not serve them as published packages; a PyPI or
    /// NuGet repository they imported holds nothing, every file of it skipped. A re-run skips a
    /// repository it finished, so first delete that repository's `<repo>__<hash>.done` and
    /// `<repo>__<hash>.progress` from the source's directory under `<storage path>/.nora-import/`,
    /// then run the import again: on local storage it writes the missing npm documents beside the
    /// tarballs already stored; on S3 it transfers the tarballs again; PyPI and NuGet files are
    /// transferred.
    Run(RunArgs),
}

#[derive(Debug, clap::Args)]
pub struct AssessArgs {
    #[arg(long, value_enum)]
    pub source: SourceKind,
    /// Source registry base URL.
    #[arg(long)]
    pub url: String,
    /// Repo glob(s); default = all repositories.
    #[arg(long)]
    pub repos: Vec<String>,
}

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    #[arg(long, value_enum)]
    pub source: SourceKind,
    /// Source registry base URL.
    #[arg(long)]
    pub url: String,
    /// Repo glob(s); default = all repositories.
    #[arg(long)]
    pub repos: Vec<String>,
    /// Stream + hash + verify every artifact but commit nothing (rehearsal).
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
    /// Max concurrent downloads.
    #[arg(long, default_value_t = 8)]
    pub concurrency: usize,
    /// Emit the result summary as JSON (for CI).
    #[arg(long, default_value_t = false)]
    pub json: bool,
    /// Best-effort permission mapping to NORA's file-first auth (Artifactory
    /// only; errors loudly on Nexus, which exposes no permission API). Emits an
    /// inert proposal for human ratification, not live credentials, by default.
    #[arg(long, default_value_t = false)]
    pub with_permissions: bool,
    /// Permit the permission proposal to suggest a role above `Read`
    /// (Write/Admin→Write). Without this, over-Read grants are listed in the
    /// widen set but proposed as `Read` (review R3, no silent privilege widening).
    #[arg(long, default_value_t = false)]
    pub grant_write: bool,
    /// Allow loopback/link-local/RFC1918/cloud-metadata source URLs (SSRF opt-out).
    #[arg(long, default_value_t = false)]
    pub allow_private_cidrs: bool,
    /// Import sha1-only artifacts (marked weak provenance). Off by default:
    /// SHA-1 is collision-broken, so a source-advertised sha1 certifies transport
    /// integrity only, not tamper-evidence (review R8).
    #[arg(long, default_value_t = false)]
    pub allow_sha1: bool,
}

/// Import outcome — same shape family as [`mirror::MirrorResult`](crate::mirror).
#[derive(Debug, Default, serde::Serialize)]
pub struct ImportResult {
    pub total: usize,
    pub imported: usize,
    pub skipped: usize,
    pub failed: usize,
    pub bytes: u64,
}

impl ImportResult {
    fn merge(&mut self, other: &ImportResult) {
        self.total += other.total;
        self.imported += other.imported;
        self.skipped += other.skipped;
        self.failed += other.failed;
        self.bytes += other.bytes;
    }
}

/// Connection timeout: fail fast if the source is unreachable.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Per-read stall timeout — NOT a total timeout, so a progressing TB download is
/// never aborted mid-stream (review R5).
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
/// Env var carrying `user:pass` source credentials (never a CLI flag, so it stays
/// out of shell history; never logged).
const AUTH_ENV: &str = "NORA_IMPORT_AUTH";

/// Entry point dispatched from `Commands::Import` in `main.rs`.
pub async fn run(
    cmd: ImportCommand,
    storage: &crate::storage::Storage,
    config: &crate::config::Config,
) -> Result<()> {
    match cmd {
        ImportCommand::Assess(args) => assess(args, config).await,
        ImportCommand::Run(args) => run_import(args, storage, config).await,
    }
}

/// Read `user:pass` credentials from the environment (never a CLI flag, so it
/// stays out of shell history). The value is only ever handed to
/// `basic_auth_header` at the reqwest call site — never logged, and error text is
/// built from a redacted URL, not the credential.
fn read_auth() -> Option<String> {
    std::env::var(AUTH_ENV).ok().filter(|s| !s.is_empty())
}

/// `nora import assess` — read-only per-repo compatibility table plus a
/// connectivity/SSRF/auth smoke test. Writes nothing, sets no markers.
async fn assess(args: AssessArgs, config: &crate::config::Config) -> Result<()> {
    // Default-deny SSRF on the operator URL (assess has no opt-out flag).
    http::precheck_url(&args.url, false)?;
    let client = http::build_import_client(&config.tls, CONNECT_TIMEOUT, READ_TIMEOUT, false)?;
    let host = http::redact_url(&args.url);
    let source = source::build_source(args.source, &args.url, client, read_auth(), false)?;

    // Connectivity/SSRF/auth smoke: a repo listing (also the default `ping`).
    source
        .ping()
        .await
        .map_err(|e| format!("connectivity/auth smoke test failed: {e}"))?;
    let repos = filter_repos(source.list_repositories().await?, &args.repos);

    println!("nora import assess — source: {host}");
    println!("{:<32} {:<12} {:<12} notes", "REPO", "FORMAT", "COMPAT");
    let mut full = 0usize;
    let mut partial = 0usize;
    let mut unsupported = 0usize;
    for repo in &repos {
        let (compat, note) = match layout::normalize_format(&repo.format) {
            Some(rt) => {
                let c = layout::compat(rt);
                match c {
                    layout::Compat::Full => full += 1,
                    layout::Compat::Partial => partial += 1,
                    layout::Compat::Unsupported => unsupported += 1,
                }
                let note = match (c, rt) {
                    (layout::Compat::Full, _) => "",
                    (_, crate::registry_type::RegistryType::PyPI) => {
                        "distribution files only; served as hosted, never asked of an upstream"
                    }
                    (_, crate::registry_type::RegistryType::Nuget) => {
                        ".nupkg only; served as hosted, never asked of an upstream"
                    }
                    (layout::Compat::Partial, _) => "tarballs only; metadata regenerated",
                    (layout::Compat::Unsupported, _) => "no NORA import layout — will be skipped",
                };
                (format!("{c:?}"), note)
            }
            None => {
                unsupported += 1;
                (
                    "Unsupported".to_string(),
                    "unknown source format — will be skipped",
                )
            }
        };
        println!(
            "{:<32} {:<12} {:<12} {}",
            truncate(&repo.name, 31),
            truncate(&repo.format, 11),
            compat,
            note
        );
    }
    println!(
        "\n{} repo(s): {full} full, {partial} partial, {unsupported} unsupported",
        repos.len()
    );

    // R3: permission import is Artifactory-only — flag Nexus before a run.
    if matches!(args.source, SourceKind::Nexus) {
        println!("\nNOTE: --with-permissions is unsupported for Nexus (no permission API).");
    }
    Ok(())
}

/// `nora import run` — the full pull pipeline (stream → verify → curate → commit),
/// filesystem-resumable and memory-bounded.
async fn run_import(
    args: RunArgs,
    storage: &crate::storage::Storage,
    config: &crate::config::Config,
) -> Result<()> {
    // Fail-closed BEFORE any bytes move (review R3): Nexus + --with-permissions.
    if args.with_permissions {
        permissions::ensure_supported(args.source)?;
    }
    http::precheck_url(&args.url, args.allow_private_cidrs)?;
    let client = http::build_import_client(
        &config.tls,
        CONNECT_TIMEOUT,
        READ_TIMEOUT,
        args.allow_private_cidrs,
    )?;
    let host = http::redact_url(&args.url);
    let auth = read_auth();

    let on_s3 = storage.backend_name() == "s3";

    let curation = crate::build_curation_engine(config)?;
    let source = source::build_source(
        args.source,
        &args.url,
        client.clone(),
        auth.clone(),
        args.allow_private_cidrs,
    )?;

    // Resume + temp state are LOCAL filesystem (ADR-2), co-located with the
    // storage root so the local-backend commit is a same-fs atomic rename.
    let state_root = std::path::PathBuf::from(&config.storage.path);
    let temp_dir = state_root.join(".nora-import").join("tmp");
    let resume = resume::ResumeStore::open(&state_root, &args.url).await?;

    let public_base = config.server.public_base_url();
    let opts = transfer::TransferOpts {
        dry_run: args.dry_run,
        allow_sha1: args.allow_sha1,
        public_base: &public_base,
    };

    let repos = filter_repos(source.list_repositories().await?, &args.repos);
    let mut result = ImportResult::default();
    for repo in &repos {
        if resume.is_repo_done(&repo.name) {
            tracing::info!(repo = %repo.name, "skipping repo (.done marker)");
            continue;
        }
        let Some(rt) = layout::normalize_format(&repo.format) else {
            tracing::info!(repo = %repo.name, format = %repo.format, "skipping repo (unsupported source format)");
            continue;
        };
        // Per-repo isolation: a repo that fails to even start (e.g. journal open
        // error) is logged and counted, never aborting the remaining repos of a
        // multi-day migration (review: single-error-aborts-job).
        match import_repo(
            source.as_ref(),
            repo,
            rt,
            &host,
            storage,
            &curation,
            &temp_dir,
            &resume,
            opts,
            args.concurrency,
            on_s3,
        )
        .await
        {
            Ok(repo_res) => result.merge(&repo_res),
            Err(e) => {
                tracing::error!(repo = %repo.name, error = %e, "repo import failed — continuing with remaining repos");
                result.failed += 1;
            }
        }
    }

    // Permission proposal (Artifactory only; inert — review R3).
    if args.with_permissions {
        emit_permissions_proposal(&args, client, auth, &host, &state_root).await?;
    }

    report_result(&result, args.dry_run, args.json);
    Ok(())
}

/// Import a single repo with bounded concurrency and strict resume ordering.
#[allow(clippy::too_many_arguments)]
async fn import_repo(
    source: &dyn SourceRegistry,
    repo: &RepoRef,
    rt: crate::registry_type::RegistryType,
    host: &str,
    storage: &crate::storage::Storage,
    curation: &crate::curation::CurationEngine,
    temp_dir: &std::path::Path,
    resume: &resume::ResumeStore,
    opts: transfer::TransferOpts<'_>,
    concurrency: usize,
    on_s3: bool,
) -> Result<ImportResult> {
    use futures::StreamExt;

    let mut journal = resume.open_journal(&repo.name).await?;
    // Read-only snapshot of the prior-run committed set for skip decisions; the
    // journal append writer stays the single owner (no borrow contention).
    let prior = std::sync::Arc::new(journal.snapshot());
    let mut result = ImportResult::default();
    // A journal/marker write error is per-repo, NOT job-fatal: the artifact is
    // already committed (idempotent re-import next run), so we log it and withhold
    // the repo's `.done` marker rather than `?`-aborting a multi-day migration on
    // one transient ENOSPC/EIO (review: single-fsync-error-aborts-job).
    let mut journal_ok = true;

    // Per-artifact classification. `buffer_unordered` runs up to `concurrency`
    // transfers on THIS task (I/O-bound → no need for spawn/Send), so one failed
    // artifact resolves to `failed += 1` and never cancels siblings (review R9/SRE#6).
    let mut stream = source
        .artifacts(&repo.name)
        .map(|art_res| {
            let prior = prior.clone();
            async move {
                let art = match art_res {
                    Ok(a) => a,
                    Err(e) => return Item::StreamErr(e),
                };
                let key = match layout::map_artifact(rt, &art) {
                    layout::Mapping::Key(k) => k,
                    layout::Mapping::Skip(r) => return Item::Skip(r.to_string()),
                    layout::Mapping::Reject(r) => return Item::Reject(r),
                };
                // Authoritative resume: prior-run journal (in-memory, no I/O).
                if prior.contains(&key) {
                    return Item::ResumeSkip;
                }
                // Fast-path only on local (per-object HEAD on S3 = $$ + latency, R5). Not for a
                // PyPI file or a .nupkg: what is stored under the key may be what an upstream
                // served under the name before the import made it NORA's own, and only a transfer
                // stores the source's verified bytes and writes every record beside them.
                let hosted_records = matches!(
                    rt,
                    crate::registry_type::RegistryType::PyPI
                        | crate::registry_type::RegistryType::Nuget
                );
                if !on_s3 && !hosted_records && storage.stat(&key).await.is_some() {
                    // An npm tarball an earlier import committed without its version document
                    // (before 1.4.2, or a failed document write) is published now.
                    if rt == crate::registry_type::RegistryType::Npm && !opts.dry_run {
                        if let Err(e) =
                            transfer::publish_stored_npm_tarball(storage, &key, opts.public_base)
                                .await
                        {
                            return Item::Done {
                                key,
                                outcome: transfer::Outcome::Failed {
                                    reason: format!("{}: {e}", art.path),
                                },
                            };
                        }
                    }
                    return Item::CasSkip { key };
                }
                let cname = curation_name(rt, &art, &key);
                let outcome = transfer::transfer_artifact(
                    source, &art, &key, rt, &cname, host, storage, curation, temp_dir, opts,
                )
                .await;
                Item::Done { key, outcome }
            }
        })
        .buffer_unordered(concurrency.max(1));

    while let Some(item) = stream.next().await {
        result.total += 1;
        match item {
            Item::Skip(reason) => {
                tracing::debug!(repo = %repo.name, %reason, "artifact skipped");
                result.skipped += 1;
            }
            Item::Reject(reason) => {
                tracing::warn!(repo = %repo.name, %reason, "artifact rejected");
                result.failed += 1;
            }
            Item::StreamErr(e) => {
                tracing::error!(repo = %repo.name, error = %e, "source cursor error");
                result.failed += 1;
            }
            Item::ResumeSkip => result.skipped += 1,
            Item::CasSkip { key } => {
                result.skipped += 1;
                if !opts.dry_run {
                    // Record so future runs skip via the (cheap) journal, not stat.
                    if let Err(e) = journal.record(&key, "cas-present").await {
                        tracing::error!(repo = %repo.name, error = %e, "journal write failed");
                        journal_ok = false;
                    }
                }
            }
            Item::Done { key, outcome } => match outcome {
                transfer::Outcome::Imported { bytes, sha256 } => {
                    result.imported += 1;
                    result.bytes += bytes;
                    // Strict ordering: commit already returned Ok; journal+fsync
                    // happens here, before the cursor advances (review R5/SRE#4).
                    if !opts.dry_run {
                        if let Err(e) = journal.record(&key, &sha256).await {
                            tracing::error!(repo = %repo.name, error = %e, "journal write failed");
                            journal_ok = false;
                        }
                    }
                }
                transfer::Outcome::Skipped { reason } => {
                    tracing::info!(repo = %repo.name, %reason, "artifact not imported");
                    result.skipped += 1;
                }
                transfer::Outcome::Failed { reason } => {
                    tracing::warn!(repo = %repo.name, %reason, "artifact failed");
                    result.failed += 1;
                }
            },
        }
    }

    if let Err(e) = journal.sync().await {
        tracing::error!(repo = %repo.name, error = %e, "journal final fsync failed");
        journal_ok = false;
    }
    // `.done` only after the whole cursor drained AND the final fsync, and only if
    // nothing failed AND the journal is intact — a failed artifact or a lost
    // journal line must be retried on the next run. A marker-write failure is
    // logged but not fatal (the repo simply re-scans next run).
    if !opts.dry_run && result.failed == 0 && journal_ok {
        if let Err(e) = resume.mark_repo_done(&repo.name).await {
            tracing::error!(repo = %repo.name, error = %e, "failed to write .done marker (repo will re-scan next run)");
        }
    }
    Ok(result)
}

/// Per-artifact classification produced concurrently, folded sequentially.
enum Item {
    Skip(String),
    Reject(String),
    StreamErr(String),
    ResumeSkip,
    CasSkip {
        key: String,
    },
    Done {
        key: String,
        outcome: transfer::Outcome,
    },
}

/// Best-effort curation "name" per format (namespace-isolation and blocklist
/// rules key on it). For npm the package name, for PyPI the project and for NuGet the id the
/// handler checks; otherwise the repo-relative path.
fn curation_name(rt: crate::registry_type::RegistryType, art: &ArtifactRef, key: &str) -> String {
    let segment = |at: usize| key.split('/').nth(at).unwrap_or(&art.path).to_string();
    match rt {
        crate::registry_type::RegistryType::Npm => art
            .path
            .split("/-/")
            .next()
            .unwrap_or(&art.path)
            .to_string(),
        // `pypi/<project>/<file>`
        crate::registry_type::RegistryType::PyPI => segment(1),
        // `nuget/flatcontainer/<id>/<version>/<file>`
        crate::registry_type::RegistryType::Nuget => segment(2),
        _ => art.path.clone(),
    }
}

/// Fetch + map + write the inert Artifactory permission proposal (review R3).
async fn emit_permissions_proposal(
    args: &RunArgs,
    client: reqwest::Client,
    auth: Option<String>,
    host: &str,
    state_root: &std::path::Path,
) -> Result<()> {
    let http = source::SourceHttp {
        client,
        base: args.url.trim_end_matches('/').to_string(),
        auth,
        allow_private: args.allow_private_cidrs,
    };
    let principals = permissions::fetch_artifactory_principals(&http).await?;
    let report = permissions::map_to_proposal(
        host,
        &principals,
        permissions::PermOpts {
            grant_write: args.grant_write,
        },
    );
    let path = permissions::write_report(&report, state_root).await?;
    println!(
        "Permission proposal (INERT — review before applying): {}",
        path.display()
    );
    Ok(())
}

/// Keep only repos matching one of `globs` (empty = all). Globs support a
/// trailing `*` prefix match plus exact match.
fn filter_repos(repos: Vec<RepoRef>, globs: &[String]) -> Vec<RepoRef> {
    if globs.is_empty() {
        return repos;
    }
    repos
        .into_iter()
        .filter(|r| globs.iter().any(|g| glob_match(g, &r.name)))
        .collect()
}

fn glob_match(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

fn report_result(r: &ImportResult, dry_run: bool, json: bool) {
    if json {
        // ImportResult derives Serialize; a bad serialize is not import-fatal.
        match serde_json::to_string(r) {
            Ok(s) => println!("{s}"),
            Err(e) => tracing::error!(error = %e, "failed to serialize import result"),
        }
        return;
    }
    let mode = if dry_run {
        " (dry-run — nothing committed)"
    } else {
        ""
    };
    println!(
        "import complete{mode}: {} imported, {} skipped, {} failed, {} bytes ({} total)",
        r.imported, r.skipped, r.failed, r.bytes, r.total
    );
}

fn truncate(s: &str, max: usize) -> String {
    // Truncate by CHARS, not bytes: `repo.name`/`repo.format` are source-controlled
    // and may contain multibyte UTF-8 (Cyrillic/CJK/emoji). A byte slice on a
    // non-char-boundary would panic and crash the read-only `assess` table.
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod integration_tests {
    //! End-to-end acceptance tests against mock Artifactory/Nexus (wiremock) into
    //! a real local Storage — the #599 acceptance criteria. These exercise the
    //! REAL call-path (adapter → transfer → curation → storage → resume), not
    //! isolated helpers (pipeline PM-4).

    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct Harness {
        storage: crate::storage::Storage,
        curation: crate::curation::CurationEngine,
        temp_dir: std::path::PathBuf,
        resume: resume::ResumeStore,
        _tmp: tempfile::TempDir,
    }

    async fn harness(source_host: &str) -> Harness {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let storage = crate::storage::Storage::new_local(root.to_str().unwrap());
        let curation =
            crate::curation::CurationEngine::new(crate::config::CurationConfig::default());
        let temp_dir = root.join(".nora-import").join("tmp");
        let resume = resume::ResumeStore::open(&root, source_host).await.unwrap();
        Harness {
            storage,
            curation,
            temp_dir,
            resume,
            _tmp: tmp,
        }
    }

    /// Guarded client that can reach a loopback mock (allow_private=true).
    fn loopback_client() -> reqwest::Client {
        http::build_import_client(
            &crate::config::TlsConfig::default(),
            CONNECT_TIMEOUT,
            READ_TIMEOUT,
            true,
        )
        .unwrap()
    }

    fn opts(dry_run: bool) -> transfer::TransferOpts<'static> {
        transfer::TransferOpts {
            dry_run,
            allow_sha1: false,
            public_base: "http://nora.example",
        }
    }

    /// Mount Artifactory `/api/repositories` + one AQL page + a blob download.
    /// Returns (sha256_advertised).
    async fn mount_artifactory(server: &MockServer, body: &[u8], advertised_sha: &str) {
        mount_artifactory_checksums(server, body, advertised_sha, "").await;
    }

    async fn mount_artifactory_checksums(
        server: &MockServer,
        body: &[u8],
        sha256: &str,
        sha1: &str,
    ) {
        Mock::given(method("GET"))
            .and(path("/api/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"key": "libs-release-local", "type": "LOCAL", "packageType": "maven"}
            ])))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/search/aql"))
            .and(body_string_contains("offset(0)"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "repo": "libs-release-local",
                    "path": "com/example/foo/1.0",
                    "name": "foo-1.0.jar",
                    "size": body.len(),
                    "sha256": sha256,
                    "actual_sha1": sha1
                }]
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/libs-release-local/com/example/foo/1.0/foo-1.0.jar"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(server)
            .await;
    }

    #[test]
    fn truncate_is_char_boundary_safe_on_multibyte_names() {
        // A source repo named in Cyrillic longer than the column width must NOT
        // panic (byte-slice on a non-char-boundary) — it would crash `assess`.
        let name = "репозиторий-релизов-длинное-имя"; // 31 Cyrillic chars, 2 bytes each
        let t = truncate(name, 10);
        assert!(t.chars().count() <= 10);
        assert!(t.ends_with('…'));
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("🚀🚀🚀🚀🚀", 3), "🚀🚀…"); // emoji (4-byte) boundaries
    }

    const MAVEN_KEY: &str = "maven/com/example/foo/1.0/foo-1.0.jar";

    #[tokio::test]
    async fn artifactory_import_commits_pins_and_resumes() {
        let body = b"hello world artifact payload";
        let sha = hex::encode(Sha256::digest(body));
        let server = MockServer::start().await;
        mount_artifactory(&server, body, &sha).await;

        let h = harness("art-e2e").await;
        let source = source::build_source(
            SourceKind::Artifactory,
            &server.uri(),
            loopback_client(),
            None,
            true,
        )
        .unwrap();
        let repos = source.list_repositories().await.unwrap();
        assert_eq!(repos.len(), 1);
        let rt = layout::normalize_format(&repos[0].format).unwrap();

        let res = import_repo(
            source.as_ref(),
            &repos[0],
            rt,
            "art",
            &h.storage,
            &h.curation,
            &h.temp_dir,
            &h.resume,
            opts(false),
            4,
            false,
        )
        .await
        .unwrap();

        assert_eq!(res.imported, 1, "one artifact imported");
        assert_eq!(res.failed, 0);
        // Committed under the handler-format key, with the pin recorded (local).
        assert!(
            h.storage.stat(MAVEN_KEY).await.is_some(),
            "artifact at handler key"
        );
        assert_eq!(h.storage.get(MAVEN_KEY).await.unwrap().as_ref(), body);
        assert_eq!(
            h.storage.pin(MAVEN_KEY).await.as_deref(),
            Some(sha.as_str())
        );
        // Repo marked done; rerun is idempotent (resume skip, no re-download).
        assert!(h.resume.is_repo_done("libs-release-local"));
        let res2 = import_repo(
            source.as_ref(),
            &repos[0],
            rt,
            "art",
            &h.storage,
            &h.curation,
            &h.temp_dir,
            &h.resume,
            opts(false),
            4,
            false,
        )
        .await
        .unwrap();
        assert_eq!(res2.imported, 0, "rerun imports nothing");
        assert!(res2.skipped >= 1, "rerun skips via journal");
    }

    #[tokio::test]
    async fn corrupt_stream_commits_nothing() {
        // Advertise a sha256 that does NOT match the delivered bytes.
        let body = b"the real bytes";
        let wrong_sha = hex::encode(Sha256::digest(b"different bytes"));
        let server = MockServer::start().await;
        mount_artifactory(&server, body, &wrong_sha).await;

        let h = harness("art-corrupt").await;
        let source = source::build_source(
            SourceKind::Artifactory,
            &server.uri(),
            loopback_client(),
            None,
            true,
        )
        .unwrap();
        let repos = source.list_repositories().await.unwrap();
        let rt = layout::normalize_format(&repos[0].format).unwrap();

        let res = import_repo(
            source.as_ref(),
            &repos[0],
            rt,
            "art",
            &h.storage,
            &h.curation,
            &h.temp_dir,
            &h.resume,
            opts(false),
            4,
            false,
        )
        .await
        .unwrap();

        assert_eq!(res.imported, 0);
        assert_eq!(res.failed, 1, "checksum mismatch → failed");
        // Fail-closed: nothing in storage, repo NOT marked done (so it retries).
        assert!(
            h.storage.stat(MAVEN_KEY).await.is_none(),
            "nothing committed on mismatch"
        );
        assert!(!h.resume.is_repo_done("libs-release-local"));
    }

    #[tokio::test]
    async fn dry_run_verifies_but_commits_nothing() {
        let body = b"rehearsal payload";
        let sha = hex::encode(Sha256::digest(body));
        let server = MockServer::start().await;
        mount_artifactory(&server, body, &sha).await;

        let h = harness("art-dry").await;
        let source = source::build_source(
            SourceKind::Artifactory,
            &server.uri(),
            loopback_client(),
            None,
            true,
        )
        .unwrap();
        let repos = source.list_repositories().await.unwrap();
        let rt = layout::normalize_format(&repos[0].format).unwrap();

        let res = import_repo(
            source.as_ref(),
            &repos[0],
            rt,
            "art",
            &h.storage,
            &h.curation,
            &h.temp_dir,
            &h.resume,
            opts(true),
            4,
            false,
        )
        .await
        .unwrap();

        assert_eq!(res.imported, 1, "dry-run counts a would-import");
        assert!(
            h.storage.stat(MAVEN_KEY).await.is_none(),
            "dry-run commits nothing"
        );
        assert!(
            !h.resume.is_repo_done("libs-release-local"),
            "dry-run sets no marker"
        );
    }

    #[tokio::test]
    async fn nexus_import_flattens_components_to_assets() {
        let body = b"nexus artifact bytes";
        let sha = hex::encode(Sha256::digest(body));
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/service/rest/v1/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"name": "maven-releases", "format": "maven2", "type": "hosted"}
            ])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/service/rest/v1/components"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{
                    "assets": [{
                        "path": "com/acme/lib/2.0/lib-2.0.jar",
                        "checksum": {"sha1": "unused", "sha256": sha},
                        "fileSize": body.len()
                    }]
                }],
                "continuationToken": null
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/repository/maven-releases/com/acme/lib/2.0/lib-2.0.jar",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(&server)
            .await;

        let h = harness("nexus-e2e").await;
        let source = source::build_source(
            SourceKind::Nexus,
            &server.uri(),
            loopback_client(),
            None,
            true,
        )
        .unwrap();
        let repos = source.list_repositories().await.unwrap();
        assert_eq!(repos.len(), 1);
        let rt = layout::normalize_format(&repos[0].format).unwrap();
        assert_eq!(rt, crate::registry_type::RegistryType::Maven); // maven2 → Maven

        let res = import_repo(
            source.as_ref(),
            &repos[0],
            rt,
            "nexus",
            &h.storage,
            &h.curation,
            &h.temp_dir,
            &h.resume,
            opts(false),
            4,
            false,
        )
        .await
        .unwrap();

        assert_eq!(res.imported, 1);
        let key = "maven/com/acme/lib/2.0/lib-2.0.jar";
        assert!(h.storage.stat(key).await.is_some());
        assert_eq!(h.storage.get(key).await.unwrap().as_ref(), body);
    }

    #[tokio::test]
    async fn ssrf_resolver_blocks_loopback_hostname() {
        // A mock server on loopback; a guarded client (default-deny) must refuse
        // to resolve `localhost` → 127.0.0.1/::1, while the opt-out client reaches it.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ping"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let port = server.address().port();

        let guarded = http::build_import_client(
            &crate::config::TlsConfig::default(),
            CONNECT_TIMEOUT,
            READ_TIMEOUT,
            false, // default-deny
        )
        .unwrap();
        let blocked = guarded
            .get(format!("http://localhost:{port}/ping"))
            .send()
            .await;
        assert!(
            blocked.is_err(),
            "guarded client must block localhost→loopback"
        );

        let allowed = loopback_client()
            .get(format!("http://localhost:{port}/ping"))
            .send()
            .await;
        assert!(allowed.is_ok(), "opt-out client reaches loopback mock");
    }

    #[tokio::test]
    async fn sha1_only_artifact_is_gated_by_allow_sha1() {
        let body = b"old maven artifact with only sha1";
        let sha1 = hex::encode(sha1::Sha1::digest(body));
        let server = MockServer::start().await;
        mount_artifactory_checksums(&server, body, "", &sha1).await; // sha256 absent

        // Without --allow-sha1: sha1-only artifact is SKIPPED (fail-closed), not imported.
        let h = harness("art-sha1-off").await;
        let source = source::build_source(
            SourceKind::Artifactory,
            &server.uri(),
            loopback_client(),
            None,
            true,
        )
        .unwrap();
        let repos = source.list_repositories().await.unwrap();
        let rt = layout::normalize_format(&repos[0].format).unwrap();
        let res = import_repo(
            source.as_ref(),
            &repos[0],
            rt,
            "art",
            &h.storage,
            &h.curation,
            &h.temp_dir,
            &h.resume,
            transfer::TransferOpts {
                dry_run: false,
                allow_sha1: false,
                public_base: "http://nora.example",
            },
            4,
            false,
        )
        .await
        .unwrap();
        assert_eq!(res.imported, 0);
        assert_eq!(res.skipped, 1, "sha1-only skipped without --allow-sha1");
        assert!(h.storage.stat(MAVEN_KEY).await.is_none());

        // With --allow-sha1: the sha1 is verified and the artifact imports.
        let h2 = harness("art-sha1-on").await;
        let source2 = source::build_source(
            SourceKind::Artifactory,
            &server.uri(),
            loopback_client(),
            None,
            true,
        )
        .unwrap();
        let res2 = import_repo(
            source2.as_ref(),
            &repos[0],
            rt,
            "art",
            &h2.storage,
            &h2.curation,
            &h2.temp_dir,
            &h2.resume,
            transfer::TransferOpts {
                dry_run: false,
                allow_sha1: true,
                public_base: "http://nora.example",
            },
            4,
            false,
        )
        .await
        .unwrap();
        assert_eq!(res2.imported, 1, "sha1-only imports with --allow-sha1");
        assert!(h2.storage.stat(MAVEN_KEY).await.is_some());
    }

    #[tokio::test]
    async fn artifactory_404_falls_back_to_download_uri() {
        // Direct download 404 → read storage-info → fetch the returned downloadUri.
        let body = b"artifact served via storage-info downloadUri";
        let sha = hex::encode(Sha256::digest(body));
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"key": "libs-release-local", "type": "LOCAL", "packageType": "maven"}
            ])))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/search/aql"))
            .and(body_string_contains("offset(0)"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "repo": "libs-release-local", "path": "com/example/foo/1.0",
                    "name": "foo-1.0.jar", "size": body.len(), "sha256": sha, "actual_sha1": ""
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/libs-release-local/com/example/foo/1.0/foo-1.0.jar"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let download_uri = format!("{}/dl/foo-1.0.jar", server.uri());
        Mock::given(method("GET"))
            .and(path(
                "/api/storage/libs-release-local/com/example/foo/1.0/foo-1.0.jar",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "downloadUri": download_uri })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/dl/foo-1.0.jar"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
            .mount(&server)
            .await;

        let h = harness("art-404-fallback").await;
        let source = source::build_source(
            SourceKind::Artifactory,
            &server.uri(),
            loopback_client(),
            None,
            true,
        )
        .unwrap();
        let repos = source.list_repositories().await.unwrap();
        let rt = layout::normalize_format(&repos[0].format).unwrap();
        let res = import_repo(
            source.as_ref(),
            &repos[0],
            rt,
            "art",
            &h.storage,
            &h.curation,
            &h.temp_dir,
            &h.resume,
            opts(false),
            4,
            false,
        )
        .await
        .unwrap();
        assert_eq!(res.imported, 1, "404 → downloadUri fallback imports");
        assert_eq!(h.storage.get(MAVEN_KEY).await.unwrap().as_ref(), body);
    }

    #[tokio::test]
    async fn artifactory_retries_transient_503() {
        // First call 503 (retryable) → backoff → retry → 200: exercises send_with_retry.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/repositories"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"key": "r", "type": "LOCAL", "packageType": "maven"}
            ])))
            .mount(&server)
            .await;
        let source = source::build_source(
            SourceKind::Artifactory,
            &server.uri(),
            loopback_client(),
            None,
            true,
        )
        .unwrap();
        let repos = source.list_repositories().await.unwrap();
        assert_eq!(repos.len(), 1, "retried past transient 503");
    }

    #[tokio::test]
    async fn artifactory_http_error_surfaces() {
        // 403 is non-retryable → the adapter surfaces an error (not a silent empty).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/repositories"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let source = source::build_source(
            SourceKind::Artifactory,
            &server.uri(),
            loopback_client(),
            None,
            true,
        )
        .unwrap();
        assert!(source.list_repositories().await.is_err());
    }

    // ---- import_repo via an in-process FakeSource ----
    // The wiremock e2e tests above exercise the real HTTP adapters, but the
    // coverage engine attributes only the in-process path, so these drive
    // `import_repo`'s every Item arm without a live server.

    struct FakeSource {
        arts: Vec<(String, Vec<u8>)>,
        stream_err: bool,
    }

    #[async_trait]
    impl SourceRegistry for FakeSource {
        async fn list_repositories(&self) -> Result<Vec<RepoRef>> {
            Ok(vec![RepoRef {
                name: "r".into(),
                format: "maven".into(),
            }])
        }
        fn artifacts<'a>(&'a self, _repo: &'a str) -> BoxStream<'a, Result<ArtifactRef>> {
            use futures::StreamExt;
            let items: Vec<Result<ArtifactRef>> = if self.stream_err {
                vec![Err("cursor error".to_string())]
            } else {
                self.arts
                    .iter()
                    .map(|(p, b)| {
                        Ok(ArtifactRef {
                            repo: "r".into(),
                            path: p.clone(),
                            name: p.rsplit('/').next().unwrap_or(p).to_string(),
                            size: Some(b.len() as u64),
                            sha256: Some(hex::encode(Sha256::digest(b))),
                            sha1: None,
                        })
                    })
                    .collect()
            };
            futures::stream::iter(items).boxed()
        }
        async fn download_stream(
            &self,
            artifact: &ArtifactRef,
        ) -> Result<BoxStream<'static, Result<Bytes>>> {
            use futures::StreamExt;
            let body = self
                .arts
                .iter()
                .find(|(p, _)| *p == artifact.path)
                .map(|(_, b)| b.clone())
                .unwrap_or_default();
            Ok(futures::stream::once(async move { Ok(Bytes::from(body)) }).boxed())
        }
    }

    /// `nora import run --help` tells an operator what an npm import depends on: the public URL the
    /// version documents are written under, and how to publish an import made by 1.4.1 or older.
    #[test]
    fn run_help_names_the_public_url_and_the_upgrade_path() {
        use clap::Subcommand;
        let mut import = ImportCommand::augment_subcommands(clap::Command::new("import"));
        let help = import
            .find_subcommand_mut("run")
            .unwrap()
            .render_long_help()
            .to_string();
        for needle in [
            "NORA_PUBLIC_URL",
            ".nora-import",
            "<repo>__<hash>.done",
            "<repo>__<hash>.progress",
            "1.4.1",
            "PyPI or NuGet repository",
        ] {
            assert!(help.contains(needle), "{needle} missing from:\n{help}");
        }
    }

    /// An npm tarball as `npm pack` writes one: `package/package.json` and a file.
    fn npm_tgz(manifest: &serde_json::Value) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (path, data) in [
            ("package/package.json", manifest.to_string().into_bytes()),
            ("package/index.js", b"module.exports = 1;".to_vec()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, path, &data[..]).unwrap();
        }
        let tar = tar.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        gz.finish().unwrap()
    }

    /// An npm tarball `nora import` commits is a published version — its packument and
    /// tarball are served from NORA's own keys, and the upstream is never asked for the name.
    #[tokio::test]
    async fn an_imported_npm_tarball_is_served_as_published_without_an_upstream() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use base64::Engine;

        let upstream = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "name": "c73pkg",
                "description": "FROM-PUBLIC-UPSTREAM",
                "versions": {},
            })))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.server.public_url = Some("http://nora.example".to_string());
        });
        let tgz = npm_tgz(&json!({
            "name": "c73pkg",
            "version": "1.0.0",
            "description": "INTERNAL-ARTIFACTORY",
            "dependencies": { "left-pad": "^1.0.0" },
        }));
        let src = FakeSource {
            arts: vec![("c73pkg/-/c73pkg-1.0.0.tgz".into(), tgz.clone())],
            stream_err: false,
        };
        let state = tempfile::tempdir().unwrap();
        let resume = resume::ResumeStore::open(state.path(), "host")
            .await
            .unwrap();
        let curation =
            crate::curation::CurationEngine::new(crate::config::CurationConfig::default());
        let repo = RepoRef {
            name: "r".into(),
            format: "npm".into(),
        };
        let res = import_repo(
            &src,
            &repo,
            crate::registry_type::RegistryType::Npm,
            "host",
            &ctx.state.storage,
            &curation,
            &state.path().join("tmp"),
            &resume,
            opts(false),
            1,
            false,
        )
        .await
        .unwrap();
        assert_eq!((res.imported, res.failed), (1, 0), "{res:?}");

        let resp = send(&ctx.app, Method::GET, "/npm/c73pkg", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let version = &doc["versions"]["1.0.0"];
        assert_eq!(version["description"], "INTERNAL-ARTIFACTORY", "{doc}");
        assert_eq!(version["dependencies"]["left-pad"], "^1.0.0");
        assert_eq!(
            version["dist"]["tarball"],
            "http://nora.example/npm/c73pkg/-/c73pkg-1.0.0.tgz"
        );
        assert_eq!(
            version["dist"]["shasum"],
            hex::encode(<sha1::Sha1 as Digest>::digest(&tgz))
        );
        assert_eq!(
            version["dist"]["integrity"],
            format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD
                    .encode(<sha2::Sha512 as Digest>::digest(&tgz))
            )
        );
        assert_eq!(doc["dist-tags"]["latest"], "1.0.0");
        let tarball = send(&ctx.app, Method::GET, "/npm/c73pkg/-/c73pkg-1.0.0.tgz", "").await;
        assert_eq!(tarball.status(), StatusCode::OK);
        assert_eq!(&body_bytes(tarball).await[..], &tgz[..]);
        let asked: Vec<String> = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert!(
            asked.is_empty(),
            "upstream asked for an imported package: {asked:?}"
        );
    }

    async fn import_npm(
        storage: &crate::storage::Storage,
        arts: Vec<(String, Vec<u8>)>,
        state: &std::path::Path,
    ) -> ImportResult {
        let src = FakeSource {
            arts,
            stream_err: false,
        };
        let resume = resume::ResumeStore::open(state, "host").await.unwrap();
        let curation =
            crate::curation::CurationEngine::new(crate::config::CurationConfig::default());
        let repo = RepoRef {
            name: "r".into(),
            format: "npm".into(),
        };
        import_repo(
            &src,
            &repo,
            crate::registry_type::RegistryType::Npm,
            "host",
            storage,
            &curation,
            &state.join("tmp"),
            &resume,
            opts(false),
            1,
            false,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn an_npm_tarball_that_does_not_name_its_key_is_not_imported() {
        let h = harness("npm-mismatch").await;
        let state = tempfile::tempdir().unwrap();
        let other = npm_tgz(&json!({ "name": "other", "version": "1.0.0" }));
        let older = npm_tgz(&json!({ "name": "pkg", "version": "0.9.0" }));
        let bare = {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(
                &mut gz,
                &tar::Builder::new(Vec::new()).into_inner().unwrap(),
            )
            .unwrap();
            gz.finish().unwrap()
        };
        let res = import_npm(
            &h.storage,
            vec![
                ("pkg/-/pkg-1.0.0.tgz".into(), other),
                ("pkg/-/pkg-1.0.1.tgz".into(), older),
                ("pkg/-/pkg-1.0.2.tgz".into(), bare),
            ],
            state.path(),
        )
        .await;
        assert_eq!((res.imported, res.failed), (0, 3), "{res:?}");
        assert_eq!(h.storage.list("npm/").await.unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_tarball_an_earlier_import_committed_alone_is_published_by_the_next_run() {
        let h = harness("npm-upgrade").await;
        let tgz = npm_tgz(&json!({ "name": "pkg", "version": "1.0.0" }));
        // What an import before 1.4.2 left: the tarball, no version document.
        h.storage
            .put("npm/pkg/tarballs/pkg-1.0.0.tgz", &tgz)
            .await
            .unwrap();
        let state = tempfile::tempdir().unwrap();
        let res = import_npm(
            &h.storage,
            vec![("pkg/-/pkg-1.0.0.tgz".into(), tgz)],
            state.path(),
        )
        .await;
        assert_eq!((res.skipped, res.failed), (1, 0), "{res:?}");
        let doc: serde_json::Value =
            serde_json::from_slice(&h.storage.get("npm/pkg/versions/1.0.0.json").await.unwrap())
                .unwrap();
        assert_eq!(
            doc["dist"]["tarball"],
            "http://nora.example/npm/pkg/-/pkg-1.0.0.tgz"
        );
    }

    /// Import `arts` from one source repository of `format` into `storage`.
    async fn import_as(
        storage: &crate::storage::Storage,
        rt: crate::registry_type::RegistryType,
        format: &str,
        arts: Vec<(String, Vec<u8>)>,
        state: &std::path::Path,
    ) -> ImportResult {
        let src = FakeSource {
            arts,
            stream_err: false,
        };
        let resume = resume::ResumeStore::open(state, "host").await.unwrap();
        let curation =
            crate::curation::CurationEngine::new(crate::config::CurationConfig::default());
        let repo = RepoRef {
            name: "r".into(),
            format: format.into(),
        };
        import_repo(
            &src,
            &repo,
            rt,
            "host",
            storage,
            &curation,
            &state.join("tmp"),
            &resume,
            opts(false),
            4,
            false,
        )
        .await
        .unwrap()
    }

    /// The request paths a mock upstream received.
    async fn asked(upstream: &MockServer) -> Vec<String> {
        upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    /// A zip archive of `entries`, each stored or deflated, as `dotnet pack` and wheel builders
    /// write them.
    fn zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let (mut out, mut central) = (Vec::new(), Vec::new());
        for (name, data, deflate) in entries {
            let mut crc = flate2::Crc::new();
            crc.update(data);
            let body = if *deflate {
                let mut enc =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                std::io::Write::write_all(&mut enc, data).unwrap();
                enc.finish().unwrap()
            } else {
                data.to_vec()
            };
            let method: u16 = if *deflate { 8 } else { 0 };
            let offset = out.len() as u32;
            let mut common = Vec::new();
            common.extend_from_slice(&20u16.to_le_bytes()); // version needed
            common.extend_from_slice(&0u16.to_le_bytes()); // flags
            common.extend_from_slice(&method.to_le_bytes());
            common.extend_from_slice(&[0; 4]); // time, date
            common.extend_from_slice(&crc.sum().to_le_bytes());
            common.extend_from_slice(&(body.len() as u32).to_le_bytes());
            common.extend_from_slice(&(data.len() as u32).to_le_bytes());
            common.extend_from_slice(&(name.len() as u16).to_le_bytes());
            common.extend_from_slice(&0u16.to_le_bytes()); // extra length
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&common);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&body);
            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central.extend_from_slice(&common);
            central.extend_from_slice(&[0; 10]); // comment length, disk, attributes
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let (cd_offset, cd_size) = (out.len() as u32, central.len() as u32);
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0; 4]); // disk numbers
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment length
        out
    }

    /// A .nupkg of `id` at `version` whose .nuspec depends on Newtonsoft.Json for net8.0.
    fn nupkg(id: &str, version: &str) -> Vec<u8> {
        let nuspec = format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>{id}</id>
    <version>{version}</version>
    <authors>INTERNAL-ARTIFACTORY</authors>
    <description>INTERNAL-ARTIFACTORY &amp; more</description>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="13.0.1" exclude="Build,Analyzers" />
      </group>
    </dependencies>
  </metadata>
</package>"#
        );
        zip(&[
            ("[Content_Types].xml", b"<Types/>", false),
            (&format!("{id}.nuspec"), nuspec.as_bytes(), true),
            ("lib/net8.0/x.txt", b"x", true),
        ])
    }

    /// A PyPI file imported from a hosted repository is NORA's own: the index lists it with its
    /// digest, the file is served, and neither the index, its dates nor a file NORA does not
    /// hold are asked of an upstream. A name nothing imported still goes to the upstream.
    #[tokio::test]
    async fn an_imported_pypi_project_is_served_as_hosted_without_an_upstream() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};

        let upstream = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<a href="/files/corppkg-9.9.9-py3-none-any.whl">corppkg-9.9.9-py3-none-any.whl</a>"#,
            ))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.enabled = true;
            cfg.pypi.proxy = Some(format!("{uri}/simple/"));
            cfg.server.trust_upstream_dates = true;
        });
        let wheel = zip(&[("corppkg/__init__.py", b"", true)]);
        let sdist = b"sdist bytes".to_vec();
        // What an upstream served under the name before the import, cached under the same key.
        ctx.state
            .storage
            .put("pypi/corppkg/corppkg-1.0.0-py3-none-any.whl", b"squatted")
            .await
            .unwrap();
        let state = tempfile::tempdir().unwrap();
        let res = import_as(
            &ctx.state.storage,
            crate::registry_type::RegistryType::PyPI,
            "pypi",
            vec![
                (
                    "corppkg/1.0.0/corppkg-1.0.0-py3-none-any.whl".into(),
                    wheel.clone(),
                ),
                ("packages/CorpPkg/1.0.0/CorpPkg-1.0.0.tar.gz".into(), sdist),
                (
                    "corppkg/1.0.0/corppkg-1.0.0.tar.gz.asc".into(),
                    b"sig".to_vec(),
                ),
            ],
            state.path(),
        )
        .await;
        assert_eq!(
            (res.imported, res.skipped, res.failed),
            (2, 1, 0),
            "{res:?}"
        );

        let index = send(&ctx.app, Method::GET, "/simple/corppkg/", "").await;
        assert_eq!(index.status(), StatusCode::OK);
        let html = String::from_utf8(body_bytes(index).await.to_vec()).unwrap();
        let wheel_sha = hex::encode(Sha256::digest(&wheel));
        assert!(
            html.contains(&format!(
                "/simple/corppkg/corppkg-1.0.0-py3-none-any.whl#sha256={wheel_sha}"
            )),
            "{html}"
        );
        assert!(html.contains("CorpPkg-1.0.0.tar.gz#sha256="), "{html}");
        assert!(!html.contains("9.9.9"), "{html}");
        let json = crate::test_helpers::send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/corppkg/",
            vec![("accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;
        assert_eq!(json.status(), StatusCode::OK);
        let file = send(
            &ctx.app,
            Method::GET,
            "/simple/corppkg/corppkg-1.0.0-py3-none-any.whl",
            "",
        )
        .await;
        assert_eq!(file.status(), StatusCode::OK);
        assert_eq!(&body_bytes(file).await[..], &wheel[..]);
        let other = send(
            &ctx.app,
            Method::GET,
            "/simple/corppkg/corppkg-9.9.9-py3-none-any.whl",
            "",
        )
        .await;
        assert_eq!(other.status(), StatusCode::NOT_FOUND);
        assert_eq!(asked(&upstream).await, Vec::<String>::new());

        // Control: a project nothing imported is still the upstream's.
        send(&ctx.app, Method::GET, "/simple/requests/", "").await;
        assert_eq!(
            asked(&upstream).await,
            vec!["/simple/requests/".to_string()]
        );
    }

    /// A .nupkg imported from a hosted repository is NORA's own: the flat container lists and
    /// serves it with its .nuspec, the registration names it with the dependencies its .nuspec
    /// declares, and no upstream is asked for the id — nor for a version NORA does not hold.
    /// An id nothing imported still goes to the upstream.
    #[tokio::test]
    async fn an_imported_nupkg_is_served_as_hosted_without_an_upstream() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};

        let upstream = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "versions": ["9.9.9"] })),
            )
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.server.public_url = Some("http://nora.example".to_string());
            cfg.server.trust_upstream_dates = true;
        });
        let one = nupkg("Corp.Lib", "1.0");
        let two = nupkg("Corp.Lib", "2.0.0-Beta.1");
        // What an upstream served under the id before the import: a version and its list.
        for (key, data) in [
            (
                "nuget/flatcontainer/corp.lib/9.9.9/corp.lib.9.9.9.nupkg",
                &b"squatted"[..],
            ),
            (
                "nuget/flatcontainer/corp.lib/index.json",
                br#"{"versions":["9.9.9"]}"#,
            ),
        ] {
            ctx.state.storage.put(key, data).await.unwrap();
        }
        let state = tempfile::tempdir().unwrap();
        let res = import_as(
            &ctx.state.storage,
            crate::registry_type::RegistryType::Nuget,
            "nuget",
            vec![
                ("Corp.Lib/Corp.Lib.1.0.nupkg".into(), one.clone()),
                ("Corp.Lib.2.0.0-Beta.1.nupkg".into(), two),
            ],
            state.path(),
        )
        .await;
        assert_eq!((res.imported, res.failed), (2, 0), "{res:?}");

        let flat = "/nuget/v3/flatcontainer/corp.lib";
        let index = send(&ctx.app, Method::GET, &format!("{flat}/index.json"), "").await;
        assert_eq!(index.status(), StatusCode::OK);
        let versions: serde_json::Value = serde_json::from_slice(&body_bytes(index).await).unwrap();
        assert_eq!(versions, json!({ "versions": ["1.0.0", "2.0.0-beta.1"] }));
        let package = send(
            &ctx.app,
            Method::GET,
            &format!("{flat}/1.0.0/corp.lib.1.0.0.nupkg"),
            "",
        )
        .await;
        assert_eq!(package.status(), StatusCode::OK);
        assert_eq!(&body_bytes(package).await[..], &one[..]);
        let nuspec = send(
            &ctx.app,
            Method::GET,
            &format!("{flat}/1.0.0/corp.lib.nuspec"),
            "",
        )
        .await;
        assert_eq!(nuspec.status(), StatusCode::OK);
        let nuspec = String::from_utf8(body_bytes(nuspec).await.to_vec()).unwrap();
        assert!(nuspec.contains("<id>Corp.Lib</id>"), "{nuspec}");

        let registration = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/corp.lib/index.json",
            "",
        )
        .await;
        assert_eq!(registration.status(), StatusCode::OK);
        let gzip = registration
            .headers()
            .get("content-encoding")
            .is_some_and(|v| v == "gzip");
        let raw = body_bytes(registration).await;
        let mut text = Vec::new();
        if gzip {
            std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&raw[..]), &mut text)
                .unwrap();
        } else {
            text = raw.to_vec();
        }
        let doc: serde_json::Value = serde_json::from_slice(&text).unwrap();
        let leaves = doc["items"][0]["items"].as_array().unwrap();
        assert_eq!(leaves.len(), 2, "{doc}");
        let entry = &leaves[0]["catalogEntry"];
        assert_eq!(entry["id"], "Corp.Lib", "{doc}");
        assert_eq!(entry["version"], "1.0.0");
        assert_eq!(entry["description"], "INTERNAL-ARTIFACTORY & more");
        assert_eq!(
            entry["packageContent"],
            "http://nora.example/nuget/v3/flatcontainer/corp.lib/1.0.0/corp.lib.1.0.0.nupkg"
        );
        let group = &entry["dependencyGroups"][0];
        assert_eq!(group["targetFramework"], "net8.0", "{doc}");
        assert_eq!(group["dependencies"][0]["id"], "Newtonsoft.Json");
        assert_eq!(group["dependencies"][0]["range"], "13.0.1");
        assert_eq!(leaves[1]["catalogEntry"]["version"], "2.0.0-Beta.1");

        let squatted = send(
            &ctx.app,
            Method::GET,
            &format!("{flat}/9.9.9/corp.lib.9.9.9.nupkg"),
            "",
        )
        .await;
        assert_eq!(squatted.status(), StatusCode::NOT_FOUND);
        // A hosted version whose package is gone is not found, and not asked of the upstream.
        ctx.state
            .storage
            .delete("nuget/flatcontainer/corp.lib/2.0.0-beta.1/corp.lib.2.0.0-beta.1.nupkg")
            .await
            .unwrap();
        let gone = send(
            &ctx.app,
            Method::GET,
            &format!("{flat}/2.0.0-beta.1/corp.lib.2.0.0-beta.1.nupkg"),
            "",
        )
        .await;
        assert_eq!(gone.status(), StatusCode::NOT_FOUND);
        // The registration lists every version inline: there is no page to ask an upstream for.
        let page = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/corp.lib/page/1.0.0/2.0.0.json",
            "",
        )
        .await;
        assert_eq!(page.status(), StatusCode::NOT_FOUND);
        assert_eq!(asked(&upstream).await, Vec::<String>::new());

        // Control: an id nothing imported is still the upstream's.
        send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/other.lib/index.json",
            "",
        )
        .await;
        assert_eq!(
            asked(&upstream).await,
            vec!["/v3-flatcontainer/other.lib/index.json".to_string()]
        );
    }

    /// A .nupkg is imported only when it is a package of the id and version its key names: one
    /// whose .nuspec names another id or version, or that is no zip with a .nuspec, leaves
    /// nothing behind.
    #[tokio::test]
    async fn a_nupkg_that_does_not_name_its_key_is_not_imported() {
        let h = harness("nuget-mismatch").await;
        let state = tempfile::tempdir().unwrap();
        let res = import_as(
            &h.storage,
            crate::registry_type::RegistryType::Nuget,
            "nuget",
            vec![
                ("Pkg/Pkg.1.0.0.nupkg".into(), nupkg("Other", "1.0.0")),
                ("Pkg/Pkg.1.0.1.nupkg".into(), nupkg("Pkg", "1.0.0")),
                ("Pkg/Pkg.1.0.2.nupkg".into(), b"not a zip".to_vec()),
                (
                    "Pkg/Pkg.1.0.3.nupkg".into(),
                    zip(&[("lib/x.txt", b"x", false)]),
                ),
                ("Pkg/Pkg.1.0.4.nupkg".into(), {
                    // The .nuspec's bytes do not match the CRC-32 the archive records.
                    let mut package = zip(&[(
                        "Pkg.nuspec",
                        b"<package><metadata><id>Pkg</id><version>1.0.4</version><description>abcde</description></metadata></package>",
                        false,
                    )]);
                    let at = package.windows(5).position(|w| w == b"abcde").unwrap();
                    package[at] = b'X';
                    package
                }),
                (
                    "Pkg/Pkg.1.0.5.nupkg".into(),
                    zip(&[
                        ("Pkg.nuspec", b"<package/>", false),
                        ("pkg.NUSPEC", b"<package/>", false),
                    ]),
                ),
            ],
            state.path(),
        )
        .await;
        assert_eq!((res.imported, res.failed), (0, 6), "{res:?}");
        assert_eq!(
            h.storage.list("nuget/").await.unwrap(),
            Vec::<String>::new()
        );
    }

    /// What makes a name hosted is read before an upstream is asked for it: a store that cannot
    /// answer leaves the request unanswered (503), and the name is not handed to the upstream.
    #[tokio::test]
    async fn a_store_that_cannot_tell_a_name_is_hosted_does_not_hand_it_upstream() {
        use crate::test_helpers::{
            create_test_context_with_storage_and_config, outage_storage, send,
        };
        use axum::http::{Method, StatusCode};

        let upstream = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "versions": [] })))
            .mount(&upstream)
            .await;
        let (storage, outage) = outage_storage();
        let state = tempfile::tempdir().unwrap();
        let res = import_as(
            &storage,
            crate::registry_type::RegistryType::PyPI,
            "pypi",
            vec![("corppkg/1.0/corppkg-1.0.tar.gz".into(), b"s".to_vec())],
            state.path(),
        )
        .await;
        assert_eq!(res.imported, 1, "{res:?}");
        let res = import_as(
            &storage,
            crate::registry_type::RegistryType::Nuget,
            "nuget",
            vec![("Corp.Lib.1.0.0.nupkg".into(), nupkg("Corp.Lib", "1.0.0"))],
            state.path(),
        )
        .await;
        assert_eq!(res.imported, 1, "{res:?}");
        let uri = upstream.uri();
        let ctx = create_test_context_with_storage_and_config(storage, move |cfg| {
            cfg.pypi.enabled = true;
            cfg.pypi.proxy = Some(format!("{uri}/simple/"));
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
        });
        outage.begin();
        for path in [
            "/simple/corppkg/",
            "/simple/corppkg/corppkg-2.0.tar.gz",
            "/nuget/v3/flatcontainer/corp.lib/index.json",
            "/nuget/v3/flatcontainer/corp.lib/2.0.0/corp.lib.2.0.0.nupkg",
            "/nuget/v3/registration/corp.lib/index.json",
        ] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        }
        assert_eq!(asked(&upstream).await, Vec::<String>::new());
    }

    /// A second run over a finished import transfers nothing and leaves the store as it was.
    #[tokio::test]
    async fn a_pypi_and_nuget_import_runs_again_without_a_change() {
        let h = harness("rerun").await;
        let state = tempfile::tempdir().unwrap();
        let wheel = vec![(
            "corppkg/1.0.0/corppkg-1.0.0-py3-none-any.whl".to_string(),
            b"w".to_vec(),
        )];
        let package = vec![(
            "Corp.Lib/Corp.Lib.1.0.0.nupkg".to_string(),
            nupkg("Corp.Lib", "1.0.0"),
        )];
        let pypi = crate::registry_type::RegistryType::PyPI;
        let nuget = crate::registry_type::RegistryType::Nuget;
        let first = import_as(&h.storage, pypi, "pypi", wheel.clone(), state.path()).await;
        assert_eq!((first.imported, first.failed), (1, 0), "{first:?}");
        let first = import_as(&h.storage, nuget, "nuget", package.clone(), state.path()).await;
        assert_eq!((first.imported, first.failed), (1, 0), "{first:?}");
        let mut stored = h.storage.list("").await.unwrap();
        stored.sort();
        let again = import_as(&h.storage, pypi, "pypi", wheel, state.path()).await;
        assert_eq!((again.imported, again.skipped), (0, 1), "{again:?}");
        let again = import_as(&h.storage, nuget, "nuget", package, state.path()).await;
        assert_eq!((again.imported, again.skipped), (0, 1), "{again:?}");
        let mut after = h.storage.list("").await.unwrap();
        after.sort();
        assert_eq!(stored, after);
    }

    fn rr() -> RepoRef {
        RepoRef {
            name: "r".into(),
            format: "maven".into(),
        }
    }

    async fn run_repo(
        src: &FakeSource,
        rt: crate::registry_type::RegistryType,
        h: &Harness,
        dry: bool,
    ) -> ImportResult {
        import_repo(
            src,
            &rr(),
            rt,
            "host",
            &h.storage,
            &h.curation,
            &h.temp_dir,
            &h.resume,
            opts(dry),
            4,
            false,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn import_repo_commits_multiple_and_resumes() {
        let h = harness("ir-multi").await;
        let src = FakeSource {
            arts: vec![
                ("com/a/1.0/a-1.0.jar".into(), b"artifact a".to_vec()),
                ("com/b/2.0/b-2.0.jar".into(), b"artifact b longer".to_vec()),
            ],
            stream_err: false,
        };
        let res = run_repo(&src, crate::registry_type::RegistryType::Maven, &h, false).await;
        assert_eq!(res.imported, 2);
        assert_eq!(res.failed, 0);
        assert!(h.storage.stat("maven/com/a/1.0/a-1.0.jar").await.is_some());
        assert!(h.resume.is_repo_done("r"));
        let res2 = run_repo(&src, crate::registry_type::RegistryType::Maven, &h, false).await;
        assert_eq!(res2.imported, 0);
        assert!(res2.skipped >= 2);
    }

    #[tokio::test]
    async fn import_repo_stream_error_fails_and_withholds_done() {
        let h = harness("ir-err").await;
        let src = FakeSource {
            arts: vec![],
            stream_err: true,
        };
        let res = run_repo(&src, crate::registry_type::RegistryType::Maven, &h, false).await;
        assert!(res.failed >= 1);
        assert!(!h.resume.is_repo_done("r"));
    }

    #[tokio::test]
    async fn import_repo_rejects_traversal_path() {
        let h = harness("ir-rej").await;
        let src = FakeSource {
            arts: vec![("../../etc/passwd".into(), b"x".to_vec())],
            stream_err: false,
        };
        let res = run_repo(&src, crate::registry_type::RegistryType::Maven, &h, false).await;
        assert_eq!(res.failed, 1);
        assert_eq!(res.imported, 0);
    }

    #[tokio::test]
    async fn import_repo_skips_unsupported_layout() {
        let h = harness("ir-skip").await;
        let src = FakeSource {
            arts: vec![("some-package".into(), b"x".to_vec())],
            stream_err: false,
        };
        let res = run_repo(&src, crate::registry_type::RegistryType::Npm, &h, false).await;
        assert_eq!(res.skipped, 1);
        assert_eq!(res.imported, 0);
    }

    #[tokio::test]
    async fn import_repo_dry_run_counts_without_commit_or_marker() {
        let h = harness("ir-dry").await;
        let src = FakeSource {
            arts: vec![("com/a/1.0/a.jar".into(), b"body".to_vec())],
            stream_err: false,
        };
        let res = run_repo(&src, crate::registry_type::RegistryType::Maven, &h, true).await;
        assert_eq!(res.imported, 1);
        assert!(h.storage.stat("maven/com/a/1.0/a.jar").await.is_none());
        assert!(!h.resume.is_repo_done("r"));
    }

    #[tokio::test]
    async fn import_repo_cas_skips_present_without_journal() {
        let h = harness("ir-cas").await;
        let src = FakeSource {
            arts: vec![("com/a/1.0/a.jar".into(), b"body".to_vec())],
            stream_err: false,
        };
        // First run commits + journals the artifact.
        let first = run_repo(&src, crate::registry_type::RegistryType::Maven, &h, false).await;
        assert_eq!(first.imported, 1);
        // A FRESH resume store (empty journal) over the SAME storage → the CAS
        // fast-path (storage.stat present) skips without re-downloading.
        let fresh = resume::ResumeStore::open(h._tmp.path(), "ir-cas-fresh")
            .await
            .unwrap();
        let res = import_repo(
            &src,
            &rr(),
            crate::registry_type::RegistryType::Maven,
            "host",
            &h.storage,
            &h.curation,
            &h.temp_dir,
            &fresh,
            opts(false),
            4,
            false,
        )
        .await
        .unwrap();
        assert_eq!(res.imported, 0);
        assert!(res.skipped >= 1);
    }

    // ---- pure helpers ----

    #[test]
    fn glob_match_prefix_and_exact() {
        assert!(glob_match("libs-*", "libs-release"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "other"));
        assert!(!glob_match("libs-*", "app"));
    }

    #[test]
    fn filter_repos_honors_globs() {
        let repos = vec![
            RepoRef {
                name: "libs-release".into(),
                format: "maven".into(),
            },
            RepoRef {
                name: "npm-local".into(),
                format: "npm".into(),
            },
        ];
        assert_eq!(filter_repos(repos.clone(), &[]).len(), 2);
        assert_eq!(filter_repos(repos.clone(), &["libs-*".into()]).len(), 1);
        assert_eq!(filter_repos(repos, &["nope".into()]).len(), 0);
    }

    #[test]
    fn curation_name_derives_npm_package_else_path() {
        let npm = ArtifactRef {
            repo: "r".into(),
            path: "@scope/pkg/-/pkg-1.0.0.tgz".into(),
            name: "x".into(),
            size: None,
            sha256: None,
            sha1: None,
        };
        assert_eq!(
            curation_name(
                crate::registry_type::RegistryType::Npm,
                &npm,
                "npm/@scope/pkg/tarballs/pkg-1.0.0.tgz"
            ),
            "@scope/pkg"
        );
        let maven = ArtifactRef {
            repo: "r".into(),
            path: "com/x/1.0/x.jar".into(),
            name: "x".into(),
            size: None,
            sha256: None,
            sha1: None,
        };
        assert_eq!(
            curation_name(
                crate::registry_type::RegistryType::Maven,
                &maven,
                "maven/com/x/1.0/x.jar"
            ),
            "com/x/1.0/x.jar"
        );
        // PyPI and NuGet rules key on the project and the id the handlers check.
        assert_eq!(
            curation_name(
                crate::registry_type::RegistryType::PyPI,
                &maven,
                "pypi/corppkg/CorpPkg-1.0.0.tar.gz"
            ),
            "corppkg"
        );
        assert_eq!(
            curation_name(
                crate::registry_type::RegistryType::Nuget,
                &maven,
                "nuget/flatcontainer/corp.lib/1.0.0/corp.lib.1.0.0.nupkg"
            ),
            "corp.lib"
        );
    }

    #[test]
    fn import_result_merge_sums_fields() {
        let mut a = ImportResult::default();
        a.merge(&ImportResult {
            total: 2,
            imported: 1,
            skipped: 1,
            failed: 0,
            bytes: 100,
        });
        a.merge(&ImportResult {
            total: 3,
            imported: 2,
            skipped: 0,
            failed: 1,
            bytes: 50,
        });
        assert_eq!(a.total, 5);
        assert_eq!(a.imported, 3);
        assert_eq!(a.skipped, 1);
        assert_eq!(a.failed, 1);
        assert_eq!(a.bytes, 150);
    }

    #[test]
    fn report_result_json_and_human_branches() {
        let r = ImportResult {
            total: 3,
            imported: 2,
            skipped: 1,
            failed: 0,
            bytes: 42,
        };
        report_result(&r, false, true); // json
        report_result(&r, true, false); // human dry-run
        report_result(&r, false, false); // human normal
    }
}
