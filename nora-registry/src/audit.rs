// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Persistent audit log — append-only JSONL file
//!
//! Records who/when/what for every registry operation.
//! File: {storage_path}/audit.jsonl

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

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
}

impl AuditLog {
    pub fn new(storage_path: &str) -> Self {
        let path = PathBuf::from(storage_path).join("audit.jsonl");
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let writer = match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(f) => {
                info!(path = %path.display(), "Audit log initialized");
                Arc::new(Mutex::new(Some(f)))
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to open audit log, auditing disabled");
                Arc::new(Mutex::new(None))
            }
        };
        Self { path, writer }
    }

    pub fn log(&self, entry: AuditEntry) {
        let writer = Arc::clone(&self.writer);
        tokio::task::spawn_blocking(move || {
            if let Some(ref mut file) = *writer.lock() {
                if let Ok(json) = serde_json::to_string(&entry) {
                    let _ = writeln!(file, "{}", json);
                    let _ = file.flush();
                }
            }
        });
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
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
        let log = AuditLog::new(tmp.path().to_str().unwrap());
        assert!(log.path().ends_with("audit.jsonl"));
    }

    #[tokio::test]
    async fn test_audit_log_write_entry() {
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::new(tmp.path().to_str().unwrap());

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
        let log = AuditLog::new(tmp.path().to_str().unwrap());

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
}
