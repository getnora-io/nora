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

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

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
    writer: Arc<Mutex<Option<fs::File>>>,
    mode: AuditMode,
}

impl AuditLog {
    pub fn new(storage_path: &str, mode: AuditMode) -> Self {
        if mode == AuditMode::Off {
            info!("Audit log disabled (mode=off)");
            return Self {
                path: PathBuf::from(storage_path).join("audit.jsonl"),
                writer: Arc::new(Mutex::new(None)),
                mode,
            };
        }

        let path = PathBuf::from(storage_path).join("audit.jsonl");
        let writer = if mode == AuditMode::File || mode == AuditMode::Both {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(f) => {
                    info!(path = %path.display(), mode = ?mode, "Audit log initialized");
                    Arc::new(Mutex::new(Some(f)))
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to open audit log file");
                    Arc::new(Mutex::new(None))
                }
            }
        } else {
            info!(mode = ?mode, "Audit log initialized (stderr only)");
            Arc::new(Mutex::new(None))
        };

        Self { path, writer, mode }
    }

    pub fn log(&self, entry: AuditEntry) {
        if self.mode == AuditMode::Off {
            return;
        }

        let writer = Arc::clone(&self.writer);
        let mode = self.mode.clone();
        tokio::task::spawn_blocking(move || {
            let json = match serde_json::to_string(&entry) {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!(error = %e, "Audit log serialization failed");
                    return;
                }
            };

            // Write to file if mode is file or both
            if mode == AuditMode::File || mode == AuditMode::Both {
                if let Some(ref mut file) = *writer.lock() {
                    if let Err(e) = writeln!(file, "{}", json) {
                        tracing::error!(error = %e, "Audit log write failed");
                    }
                    if let Err(e) = file.flush() {
                        tracing::error!(error = %e, "Audit log flush failed");
                    }
                }
            }

            // Write to stderr if mode is stdout or both
            if mode == AuditMode::Stdout || mode == AuditMode::Both {
                eprintln!("{}", json);
            }
        });
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
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::new(tmp.path().to_str().unwrap(), AuditMode::File);
        assert!(log.path().ends_with("audit.jsonl"));
    }

    #[tokio::test]
    async fn test_audit_log_write_entry() {
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::new(tmp.path().to_str().unwrap(), AuditMode::File);

        let entry = AuditEntry::new("pull", "user1", "lodash", "npm", "downloaded");
        log.log(entry);

        // spawn_blocking is fire-and-forget; retry until flushed (max 1s)
        let path = log.path().clone();
        let mut content = String::new();
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            content = std::fs::read_to_string(&path).unwrap_or_default();
            if content.contains(r#""action":"pull""#) {
                break;
            }
        }

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

        // Retry until all 3 entries flushed (max 1s)
        let path = log.path().clone();
        let mut line_count = 0;
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if let Ok(content) = std::fs::read_to_string(&path) {
                line_count = content.lines().count();
                if line_count >= 3 {
                    break;
                }
            }
        }

        assert_eq!(line_count, 3);
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

    #[test]
    fn test_audit_log_off_mode() {
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::new(tmp.path().to_str().unwrap(), AuditMode::Off);
        assert_eq!(log.mode(), &AuditMode::Off);
    }
}
