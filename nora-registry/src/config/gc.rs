// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Garbage collection configuration.

use serde::{Deserialize, Serialize};
use std::env;

/// Garbage collection configuration.
///
/// # Environment Variables
/// - `NORA_GC_ENABLED` — enable/disable background GC (default: false)
/// - `NORA_GC_INTERVAL` — interval in seconds between GC runs (default: 86400)
/// - `NORA_GC_DRY_RUN` — if true, only report orphans without deleting (default: false)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_gc_interval")]
    pub interval: u64,
    #[serde(default)]
    pub dry_run: bool,
    /// Don't delete an orphan whose backing file is younger than this many
    /// seconds. Protects blobs from an in-flight push whose referencing
    /// manifest has not been written yet (write-vs-GC race, #584). Set to 0
    /// only during a read-only maintenance window with no concurrent writes.
    #[serde(default = "default_gc_grace")]
    pub grace_secs: u64,
}

fn default_gc_interval() -> u64 {
    86400 // 24 hours
}

fn default_gc_grace() -> u64 {
    // 7 days — matches docker-distribution's reference default. Must exceed the
    // slowest expected blob→manifest gap (large/resumed pushes of multi-GB
    // images over slow links). Lowering it risks the #584 race for heavy
    // pushes; the only cost of a high value is deferred orphan reclaim.
    604_800
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: 86400,
            dry_run: false,
            grace_secs: default_gc_grace(),
        }
    }
}

impl GcConfig {
    /// Apply environment variable overrides for GC config.
    pub(super) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_GC_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_GC_INTERVAL") {
            super::parse_env_warn("NORA_GC_INTERVAL", &val, &mut self.interval);
        }
        if let Ok(val) = env::var("NORA_GC_DRY_RUN") {
            self.dry_run = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_GC_GRACE") {
            super::parse_env_warn("NORA_GC_GRACE", &val, &mut self.grace_secs);
        }
    }
}
