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
