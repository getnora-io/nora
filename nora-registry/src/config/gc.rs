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
}

fn default_gc_interval() -> u64 {
    86400 // 24 hours
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: 86400,
            dry_run: false,
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
    }
}
