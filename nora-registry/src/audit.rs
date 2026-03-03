// Copyright (c) 2026 Volkov Pavel | DevITWay
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
    writer: Mutex<Option<fs::File>>,
}

impl AuditLog {
    pub fn new(storage_path: &str) -> Self {
        let path = PathBuf::from(storage_path).join("audit.jsonl");
        let writer = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(f) => {
                info!(path = %path.display(), "Audit log initialized");
                Mutex::new(Some(f))
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to open audit log, auditing disabled");
                Mutex::new(None)
            }
        };
        Self { path, writer }
    }

    pub fn log(&self, entry: AuditEntry) {
        if let Some(ref mut file) = *self.writer.lock() {
            if let Ok(json) = serde_json::to_string(&entry) {
                let _ = writeln!(file, "{}", json);
                let _ = file.flush();
            }
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}
