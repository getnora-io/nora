// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Structured audit log — append-only JSONL output.
//!
//! Records who/when/what for every registry write operation.
//! Output modes (NORA_AUDIT_LOG):
//!   - `file`   — write to {storage_path}/audit.jsonl (default)
//!   - `stdout`  — write JSONL to stderr (12-factor compatible)
//!   - `both`   — write to file AND stderr
//!   - `off`    — disable audit logging
//!
//! Uses a bounded mpsc channel with a single writer task (#543) to avoid
//! per-entry `spawn_blocking` + Mutex contention under load.

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Channel bound for audit entries. Under normal load, entries are drained
/// faster than they arrive. The bound provides backpressure under extreme
/// load — entries exceeding this are dropped with a warning (#543).
const AUDIT_CHANNEL_BOUND: usize = 10_000;

/// Audit output mode.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditMode {
    #[default]
    File,
    Stdout,
    Both,
    Off,
}

impl std::fmt::Display for AuditMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File => write!(f, "file"),
            Self::Stdout => write!(f, "stdout"),
            Self::Both => write!(f, "both"),
            Self::Off => write!(f, "off"),
        }
    }
}

impl std::str::FromStr for AuditMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "file" => Ok(Self::File),
            "stdout" | "stderr" => Ok(Self::Stdout),
            "both" => Ok(Self::Both),
            "off" | "none" | "false" | "0" => Ok(Self::Off),
            other => Err(format!(
                "unknown audit mode {:?} — valid values: file, stdout, both, off",
                other
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub ts: DateTime<Utc>,
    pub action: String,
    pub actor: String,
    pub artifact: String,
    pub registry: String,
    pub detail: String,
}

impl AuditEntry {
    /// The entry of a token mint, the same on every route that mints: `actor`
    /// minted for `owner` (artifact) through `route` (registry: `api`, `ui`,
    /// `admin`) a token of `role` living `ttl_secs`, as granted. Never the
    /// token itself.
    pub fn token_mint(
        actor: &str,
        route: &str,
        owner: &str,
        role: &dyn std::fmt::Display,
        ttl_secs: u64,
    ) -> Self {
        Self::new(
            "token_mint",
            actor,
            owner,
            route,
            &format!("role={role} ttl_secs={ttl_secs}"),
        )
    }

    pub fn new(action: &str, actor: &str, artifact: &str, registry: &str, detail: &str) -> Self {
        Self {
            ts: Utc::now(),
            action: action.to_string(),
            actor: actor.to_string(),
            artifact: artifact.to_string(),
            registry: registry.to_string(),
            detail: detail.to_string(),
        }
    }
}

pub struct AuditLog {
    path: PathBuf,
    mode: AuditMode,
    /// Channel sender, wrapped in Mutex<Option<>> so `shutdown()` can take it
    /// through `&self` (needed because AuditLog is behind Arc in AppState).
    sender: Mutex<Option<mpsc::Sender<AuditEntry>>>,
    /// Handle to the background writer task, used for graceful shutdown.
    writer_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl AuditLog {
    pub fn new(storage_path: &str, mode: AuditMode) -> Self {
        let path = PathBuf::from(storage_path).join("audit.jsonl");

        if mode == AuditMode::Off {
            info!("Audit log disabled (mode=off)");
            return Self {
                path,
                mode,
                sender: Mutex::new(None),
                writer_handle: Mutex::new(None),
            };
        }

        // Open file handle if needed
        let file = if mode == AuditMode::File || mode == AuditMode::Both {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(f) => {
                    info!(path = %path.display(), mode = ?mode, "Audit log initialized");
                    Some(f)
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to open audit log file");
                    None
                }
            }
        } else {
            info!(mode = ?mode, "Audit log initialized (stderr only)");
            None
        };

        let (tx, rx) = mpsc::channel(AUDIT_CHANNEL_BOUND);

        debug_assert!(
            mode != AuditMode::Off,
            "channel should not be created when mode is Off"
        );

        let writer_mode = mode.clone();
        let handle = tokio::task::spawn_blocking(move || {
            Self::writer_loop(rx, file, writer_mode);
        });

        Self {
            path,
            mode,
            sender: Mutex::new(Some(tx)),
            writer_handle: Mutex::new(Some(handle)),
        }
    }

    /// Background writer loop — receives entries from the channel and writes
    /// them to file/stderr. Runs until the channel is closed (all senders dropped).
    fn writer_loop(
        mut rx: mpsc::Receiver<AuditEntry>,
        mut file: Option<fs::File>,
        mode: AuditMode,
    ) {
        // blocking_recv() blocks the current thread until an entry arrives
        // or the channel is closed. This is correct because we're inside
        // spawn_blocking.
        while let Some(entry) = rx.blocking_recv() {
            Self::write_entry(&entry, &mut file, &mode);
        }

        // Channel closed — drain any remaining buffered entries
        while let Ok(entry) = rx.try_recv() {
            Self::write_entry(&entry, &mut file, &mode);
        }

        // Final flush on shutdown
        if let Some(ref mut f) = file {
            if let Err(e) = f.flush() {
                tracing::error!(error = %e, "Audit log final flush failed");
            }
        }
    }

    /// Write a single audit entry to file and/or stderr.
    fn write_entry(entry: &AuditEntry, file: &mut Option<fs::File>, mode: &AuditMode) {
        let json = match serde_json::to_string(entry) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "Audit log serialization failed");
                return;
            }
        };

        if *mode == AuditMode::File || *mode == AuditMode::Both {
            if let Some(ref mut f) = file {
                if let Err(e) = writeln!(f, "{}", json) {
                    tracing::error!(error = %e, "Audit log write failed");
                }
                if let Err(e) = f.flush() {
                    tracing::error!(error = %e, "Audit log flush failed");
                }
            }
        }

        if *mode == AuditMode::Stdout || *mode == AuditMode::Both {
            eprintln!("{}", json);
        }
    }

    /// Send an audit entry to the background writer (#543).
    ///
    /// Infallible: if the channel is full (extreme backpressure), the entry
    /// is dropped with a warning. If the channel is closed (shutdown), the
    /// entry is silently discarded.
    pub fn log(&self, entry: AuditEntry) {
        if self.mode == AuditMode::Off {
            return;
        }

        if let Some(ref sender) = *self.sender.lock() {
            if let Err(mpsc::error::TrySendError::Full(_)) = sender.try_send(entry) {
                warn!("Audit log channel full — entry dropped (backpressure)");
            }
            // TrySendError::Closed is silently ignored — happens during shutdown
        }
    }

    /// Graceful shutdown: close the channel and wait for the writer to drain.
    ///
    /// Must be called AFTER all background schedulers have finished (#543),
    /// so their final audit entries are captured.
    pub async fn shutdown(&self) {
        // Drop the sender to close the channel
        self.sender.lock().take();

        // Take the handle out of the mutex BEFORE awaiting (avoid holding
        // MutexGuard across .await)
        let handle = self.writer_handle.lock().take();

        // Wait for the writer task to finish draining
        if let Some(handle) = handle {
            if let Err(e) = handle.await {
                tracing::error!(error = %e, "Audit log writer task panicked");
            }
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn mode(&self) -> &AuditMode {
        &self.mode
    }
}

/// Records each download curation refused: a refusal leaves its handler as a
/// `CurationRefusal` response extension, and this layer — inside auth, so it knows the
/// caller — writes one `curation_block` entry for it. One layer covers every refusal site
/// (`check_download`, `check_namespace_isolation`, `verify_integrity`) instead of each
/// taking the audit log and the caller.
pub async fn curation_refusal_middleware(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let actor = request
        .extensions()
        .get::<crate::auth::AuthenticatedUser>()
        .map_or_else(|| "anonymous".to_string(), |user| user.0.clone());
    let response = next.run(request).await;
    if let Some(refusal) = response
        .extensions()
        .get::<crate::curation::CurationRefusal>()
    {
        state.audit.log(AuditEntry::new(
            "curation_block",
            &actor,
            &format!(
                "{}@{}",
                refusal.package,
                refusal.version.as_deref().unwrap_or("*")
            ),
            &refusal.registry,
            &format!("{}: {}", refusal.rule, refusal.reason),
        ));
    }
    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_audit_entry_new() {
        let entry = AuditEntry::new(
            "push",
            "admin",
            "nginx:latest",
            "docker",
            "uploaded manifest",
        );
        assert_eq!(entry.action, "push");
        assert_eq!(entry.actor, "admin");
        assert_eq!(entry.artifact, "nginx:latest");
        assert_eq!(entry.registry, "docker");
        assert_eq!(entry.detail, "uploaded manifest");
    }

    #[test]
    fn test_audit_log_new_and_path() {
        // AuditLog::new() spawns a tokio task, so we need a runtime
        let rt = tokio::runtime::Runtime::new().unwrap();
        let tmp = TempDir::new().unwrap();
        let log =
            rt.block_on(async { AuditLog::new(tmp.path().to_str().unwrap(), AuditMode::File) });
        assert!(log.path().ends_with("audit.jsonl"));
    }

    #[tokio::test]
    async fn test_audit_log_write_entry() {
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::new(tmp.path().to_str().unwrap(), AuditMode::File);

        let entry = AuditEntry::new("pull", "user1", "lodash", "npm", "downloaded");
        log.log(entry);

        // Wait for writer to process by shutting down (drains channel)
        let path = log.path().clone();
        log.shutdown().await;

        let content = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(content.contains(r#""action":"pull""#));
        assert!(content.contains(r#""actor":"user1""#));
        assert!(content.contains(r#""artifact":"lodash""#));
    }

    #[tokio::test]
    async fn test_audit_log_multiple_entries() {
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::new(tmp.path().to_str().unwrap(), AuditMode::File);

        log.log(AuditEntry::new("push", "admin", "a", "docker", ""));
        log.log(AuditEntry::new("pull", "user", "b", "npm", ""));
        log.log(AuditEntry::new("delete", "admin", "c", "maven", ""));

        let path = log.path().clone();
        log.shutdown().await;

        let content = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(content.lines().count(), 3);
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry::new("push", "ci", "app:v1", "docker", "ci build");
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains(r#""action":"push""#));
        assert!(json.contains(r#""ts":""#));
    }

    #[test]
    fn test_audit_mode_from_str() {
        assert_eq!("stdout".parse::<AuditMode>().unwrap(), AuditMode::Stdout);
        assert_eq!("stderr".parse::<AuditMode>().unwrap(), AuditMode::Stdout);
        assert_eq!("both".parse::<AuditMode>().unwrap(), AuditMode::Both);
        assert_eq!("off".parse::<AuditMode>().unwrap(), AuditMode::Off);
        assert_eq!("none".parse::<AuditMode>().unwrap(), AuditMode::Off);
        assert_eq!("false".parse::<AuditMode>().unwrap(), AuditMode::Off);
        assert_eq!("0".parse::<AuditMode>().unwrap(), AuditMode::Off);
        assert_eq!("file".parse::<AuditMode>().unwrap(), AuditMode::File);
    }

    #[test]
    fn test_audit_mode_rejects_invalid() {
        assert!("anything".parse::<AuditMode>().is_err());
        assert!("flie".parse::<AuditMode>().is_err());
        assert!("".parse::<AuditMode>().is_err());
        let err = "typo".parse::<AuditMode>().unwrap_err();
        assert!(
            err.contains("file"),
            "error should list valid values: {err}"
        );
    }

    #[test]
    fn test_audit_mode_display_roundtrip() {
        for mode in [
            AuditMode::File,
            AuditMode::Stdout,
            AuditMode::Both,
            AuditMode::Off,
        ] {
            let s = mode.to_string();
            let parsed: AuditMode = s.parse().unwrap();
            assert_eq!(mode, parsed);
        }
    }

    #[tokio::test]
    async fn test_audit_log_off_mode() {
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::new(tmp.path().to_str().unwrap(), AuditMode::Off);
        assert_eq!(log.mode(), &AuditMode::Off);
        // Should not panic even when logging to Off mode
        log.log(AuditEntry::new("test", "test", "test", "test", "test"));
    }
}

/// A download refused by curation leaves one entry in `audit.jsonl` (who / what /
/// registry / rule), as push, delete, proxy_fetch, cache_hit and pull do. The test context opts into the file audit log the way an
/// operator does (`NORA_AUDIT_LOG=file`) and requests go through the whole router,
/// so the test holds wherever the entry is written — handler or middleware.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod curation_refusal_audit_tests {
    use super::*;
    use crate::test_helpers::{create_test_context_with_config, send, TestContext};
    use axum::http::{Method, StatusCode};
    use tempfile::TempDir;

    const CPAN_AUTHOR: &str = "/cpan/authors/id/A/AU/AUTHOR";

    /// Curation in enforce mode with both refusal kinds: a blocklist rule for raw
    /// (hosted) and an allowlist for CPAN (proxy). The four files are seeded straight
    /// into storage, so the audit log starts empty. The policy directory is returned
    /// to keep it alive.
    async fn audited_context() -> (TestContext, TempDir) {
        let policy = TempDir::new().unwrap();
        let blocklist = policy.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "raw", "name": "secret*", "version": "*", "reason": "blocked"}]}"#,
        )
        .unwrap();
        let allowlist = policy.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            r#"{"version": 1, "entries": [{"registry": "cpan", "name": "Foo-Bar", "version": "1.0"}]}"#,
        )
        .unwrap();
        let blocklist = blocklist.to_string_lossy().into_owned();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.audit.mode = AuditMode::File;
            cfg.cpan.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
            cfg.curation.allowlist_path = Some(allowlist);
        });
        for key in [
            "raw/secret.txt",
            "raw/public.txt",
            "cpan/authors/id/A/AU/AUTHOR/Foo-Bar-1.0.tar.gz",
            "cpan/authors/id/A/AU/AUTHOR/Other-Dist-2.0.tar.gz",
        ] {
            ctx.state.storage.put(key, b"data").await.unwrap();
        }
        (ctx, policy)
    }

    /// Drain the writer and parse every line of `audit.jsonl`.
    async fn written_entries(audit: &AuditLog) -> Vec<serde_json::Value> {
        let path = audit.path().clone();
        audit.shutdown().await;
        std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn blocked_downloads() -> u64 {
        crate::metrics::CURATION_DECISIONS_TOTAL
            .with_label_values(&["block"])
            .get()
    }

    #[tokio::test]
    async fn a_refused_download_leaves_one_audit_entry() {
        let (ctx, _policy) = audited_context().await;
        let blocks_before = blocked_downloads();

        // A blocklisted raw file, and a CPAN distribution the allowlist misses.
        let refusals = [
            (
                "raw",
                "/raw/secret.txt".to_string(),
                "secret.txt",
                "blocklist",
            ),
            (
                "cpan",
                format!("{CPAN_AUTHOR}/Other-Dist-2.0.tar.gz"),
                "Other-Dist",
                "allowlist",
            ),
        ];
        for (_, uri, _, rule) in &refusals {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(resp.headers()["x-nora-decision"], "blocked", "{uri}");
            assert_eq!(resp.headers()["x-nora-rule"], *rule, "{uri}");
        }
        // The block counter moved (other tests only ever add to it) ...
        assert!(
            blocked_downloads() >= blocks_before + 2,
            "nora_curation_decisions_total{{decision=\"block\"}} must count both refusals"
        );

        // ... and each refusal must be in the audit trail, once.
        let entries = written_entries(&ctx.state.audit).await;
        let per_registry: Vec<(&str, usize)> = refusals
            .iter()
            .map(|(registry, ..)| {
                let hits = entries.iter().filter(|e| e["registry"] == *registry);
                (*registry, hits.count())
            })
            .collect();
        assert_eq!(
            per_registry,
            [("raw", 1), ("cpan", 1)],
            "each download refused by curation must leave one audit entry; \
             audit.jsonl = {entries:?}"
        );
        for (registry, _, artifact, rule) in &refusals {
            let entry = entries.iter().find(|e| e["registry"] == *registry).unwrap();
            assert!(
                !entry["actor"].as_str().unwrap_or("").is_empty(),
                "who: {entry}"
            );
            assert!(
                entry["artifact"].as_str().unwrap_or("").contains(artifact),
                "what: {entry}"
            );
            assert!(entry.to_string().contains(rule), "rule: {entry}");
        }
    }

    /// Each entry names the refusal exactly as the client was told it: action
    /// `curation_block`, the caller (`anonymous`, or the user who signed in), the
    /// artifact as `package@version` and the detail as `rule: reason` from the 403 body —
    /// for a blocklist hit and for a namespace-isolation refusal alike.
    #[tokio::test]
    async fn a_refusal_entry_names_the_caller_artifact_and_rule() {
        let policy = TempDir::new().unwrap();
        let blocklist = policy.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "raw", "name": "secret*", "version": "*", "reason": "blocked"}]}"#,
        )
        .unwrap();
        let blocklist = blocklist.to_string_lossy().into_owned();
        // Every request signs in: with `anonymous_read` a read is served as `anonymous`
        // whatever credentials it carries, so the caller could not be told apart.
        let ctx = crate::test_helpers::create_test_context_with_auth_and_config(
            &[("alice", "pw"), ("bob", "pw")],
            move |cfg| {
                cfg.audit.mode = AuditMode::File;
                cfg.curation.mode = crate::config::CurationMode::Enforce;
                cfg.curation.blocklist_path = Some(blocklist);
                cfg.curation.internal_namespaces = vec!["internal-*".to_string()];
            },
        );
        ctx.state
            .storage
            .put("raw/secret.txt", b"data")
            .await
            .unwrap();

        // base64("alice:pw"), base64("bob:pw")
        let alice = || vec![("authorization", "Basic YWxpY2U6cHc=")];
        let bob = || vec![("authorization", "Basic Ym9iOnB3")];
        let mut expected = Vec::new();
        for (uri, headers, actor) in [
            ("/raw/secret.txt", alice(), "alice"),
            ("/raw/secret.txt", bob(), "bob"),
            ("/simple/internal-secret/", alice(), "alice"),
        ] {
            let resp =
                crate::test_helpers::send_with_headers(&ctx.app, Method::GET, uri, headers, "")
                    .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
            let body: serde_json::Value =
                serde_json::from_slice(&crate::test_helpers::body_bytes(resp).await).unwrap();
            let c = &body["context"];
            expected.push(serde_json::json!({
                "action": "curation_block",
                "actor": actor,
                "artifact": format!("{}@{}", c["package"].as_str().unwrap(), c["version"].as_str().unwrap()),
                "registry": c["registry"],
                "detail": format!("{}: {}", c["rule"].as_str().unwrap(), c["reason"].as_str().unwrap()),
            }));
        }
        let entries: Vec<serde_json::Value> = written_entries(&ctx.state.audit)
            .await
            .into_iter()
            .filter(|e| e["action"] == "curation_block")
            .map(|mut e| {
                e.as_object_mut().unwrap().remove("ts");
                e
            })
            .collect();
        assert_eq!(entries, expected);
    }

    /// Control for the test above: the same context and policy, with downloads that
    /// curation allows — each leaves its one existing audit entry, so the harness
    /// captures what these routes write.
    #[tokio::test]
    async fn allowed_downloads_keep_their_audit_entries() {
        let (ctx, _policy) = audited_context().await;

        let resp = send(&ctx.app, Method::GET, "/raw/public.txt", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let uri = format!("{CPAN_AUTHOR}/Foo-Bar-1.0.tar.gz");
        let resp = send(&ctx.app, Method::GET, &uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK);

        let entries = written_entries(&ctx.state.audit).await;
        let actions: Vec<(&str, &str)> = entries
            .iter()
            .map(|e| {
                (
                    e["registry"].as_str().unwrap(),
                    e["action"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(actions, [("raw", "pull"), ("cpan", "cache_hit")]);
    }
}

/// Every refusal kind — an allowlist miss with a known version, an integrity mismatch, a
/// blocklist hit on a nested raw path with a reason in Cyrillic and with a line break (which
/// no header can carry) — leaves exactly the entry the 403 body describes.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod curation_refusal_audit_kinds {
    use super::*;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use tempfile::TempDir;

    #[tokio::test]
    async fn each_refusal_kind_is_recorded_as_its_body_says() {
        let policy = TempDir::new().unwrap();
        let blocklist = policy.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "raw", "name": "dir/secret.txt", "version": "*", "reason": "заблокировано\nполитикой"}]}"#,
        )
        .unwrap();
        let allowlist = policy.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            r#"{"version": 1, "entries": [{"registry": "cpan", "name": "Foo-Bar", "version": "1.0", "integrity": "sha256:0000000000000000000000000000000000000000000000000000000000000000", "integrity_source": "manual"}]}"#,
        )
        .unwrap();
        let blocklist = blocklist.to_string_lossy().into_owned();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.audit.mode = AuditMode::File;
            cfg.cpan.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
            cfg.curation.allowlist_path = Some(allowlist);
        });
        for key in [
            "raw/dir/secret.txt",
            "cpan/authors/id/A/AU/AUTHOR/Foo-Bar-1.0.tar.gz",
            "cpan/authors/id/A/AU/AUTHOR/Other-Dist-2.0.tar.gz",
        ] {
            ctx.state.storage.put(key, b"data").await.unwrap();
        }
        let mut expected = Vec::new();
        for uri in [
            "/raw/dir/secret.txt",
            "/cpan/authors/id/A/AU/AUTHOR/Foo-Bar-1.0.tar.gz",
            "/cpan/authors/id/A/AU/AUTHOR/Other-Dist-2.0.tar.gz",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
            let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
            let c = &body["context"];
            expected.push(serde_json::json!({
                "action": "curation_block",
                "actor": "anonymous",
                "artifact": format!("{}@{}", c["package"].as_str().unwrap(), c["version"].as_str().unwrap()),
                "registry": c["registry"],
                "detail": format!("{}: {}", c["rule"].as_str().unwrap(), c["reason"].as_str().unwrap()),
            }));
        }
        let path = ctx.state.audit.path().clone();
        ctx.state.audit.shutdown().await;
        let entries: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|e| e["action"] == "curation_block")
            .map(|mut e| {
                e.as_object_mut().unwrap().remove("ts");
                e
            })
            .collect();
        assert_eq!(entries, expected);
        // The cases must keep covering a known version, a nested path, integrity and non-ASCII.
        let text = serde_json::to_string(&expected).unwrap();
        for needle in [
            "Other-Dist@2.0",
            "dir/secret.txt@*",
            "integrity",
            "заблокировано",
        ] {
            assert!(text.contains(needle), "lost {needle}: {text}");
        }
    }
}

/// the docker blob path refuses through two sites the other tests do not
/// reach — `check_download` in the blob handler and `verify_integrity_by_hash` for a stored
/// blob. Each refusal must leave exactly the entry its 403 body describes.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod curation_refusal_audit_docker {
    use super::*;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use tempfile::TempDir;

    #[tokio::test]
    async fn docker_blob_refusals_are_recorded() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let policy = TempDir::new().unwrap();
        let blocklist = policy.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "docker", "name": "blocked*", "version": "*", "reason": "blocked"}]}"#,
        )
        .unwrap();
        let allowlist = policy.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            format!(
                r#"{{"version": 1, "entries": [{{"registry": "docker", "name": "alpine", "version": "{digest}", "integrity": "sha256:{}", "integrity_source": "manual"}}]}}"#,
                "0".repeat(64)
            ),
        )
        .unwrap();
        let blocklist = blocklist.to_string_lossy().into_owned();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.audit.mode = AuditMode::File;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
            cfg.curation.allowlist_path = Some(allowlist);
        });
        ctx.state
            .storage
            .put(&format!("docker/alpine/blobs/{digest}"), b"data")
            .await
            .unwrap();
        let mut expected = Vec::new();
        for uri in [
            format!("/v2/blocked/blobs/{digest}"),
            format!("/v2/alpine/blobs/{digest}"),
        ] {
            let resp = send(&ctx.app, Method::GET, &uri, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
            let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
            let c = &body["context"];
            expected.push(serde_json::json!({
                "action": "curation_block",
                "actor": "anonymous",
                "artifact": format!("{}@{}", c["package"].as_str().unwrap(), c["version"].as_str().unwrap()),
                "registry": c["registry"],
                "detail": format!("{}: {}", c["rule"].as_str().unwrap(), c["reason"].as_str().unwrap()),
            }));
        }
        let text = serde_json::to_string(&expected).unwrap();
        assert!(
            text.contains("allowlist:integrity"),
            "integrity case lost: {text}"
        );
        let path = ctx.state.audit.path().clone();
        ctx.state.audit.shutdown().await;
        let entries: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|e| e["action"] == "curation_block")
            .map(|mut e| {
                e.as_object_mut().unwrap().remove("ts");
                e
            })
            .collect();
        assert_eq!(entries, expected);
    }
}
