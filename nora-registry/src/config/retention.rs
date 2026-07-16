// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Retention policy configuration.

use serde::{Deserialize, Serialize};
use std::env;

/// A single retention rule applied to a registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionRule {
    /// Registry name (e.g., "docker", "maven", "npm", "pypi", "cargo") or "*" for all
    pub registry: String,
    /// Optional glob matched against the group name within the registry
    /// (e.g. `myrepo/*` for one rpm/deb repository, `archive/*` for one raw
    /// top-level prefix). Absent = rule applies to every group in the
    /// registry. First matching rule wins, so put specific rules first.
    #[serde(default)]
    pub name_glob: Option<String>,
    /// Keep the N most recent versions
    #[serde(default)]
    pub keep_last: Option<u32>,
    /// Only delete versions older than N days
    #[serde(default)]
    pub older_than_days: Option<u32>,
    /// Glob patterns that protect versions from deletion
    #[serde(default)]
    pub exclude_tags: Vec<String>,
}

/// Retention policies configuration.
///
/// # Environment Variables
/// - `NORA_RETENTION_ENABLED` — enable/disable background retention (default: false)
/// - `NORA_RETENTION_INTERVAL` — interval in seconds between runs (default: 86400)
/// - `NORA_RETENTION_DRY_RUN` — if true, only report what would be deleted (default: false)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Enable background retention scheduler
    #[serde(default)]
    pub enabled: bool,
    /// Interval in seconds between retention runs (default: 86400 = 24h)
    #[serde(default = "default_retention_interval")]
    pub interval: u64,
    /// If true, only log what would be deleted without actually deleting (default: false)
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub rules: Vec<RetentionRule>,
}

fn default_retention_interval() -> u64 {
    86400 // 24 hours
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: 86400,
            dry_run: false,
            rules: Vec::new(),
        }
    }
}

impl RetentionConfig {
    /// Apply environment variable overrides for retention config.
    pub(super) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_RETENTION_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_RETENTION_INTERVAL") {
            super::parse_env_warn("NORA_RETENTION_INTERVAL", &val, &mut self.interval);
        }
        if let Ok(val) = env::var("NORA_RETENTION_DRY_RUN") {
            self.dry_run = val.to_lowercase() == "true" || val == "1";
        }
    }
}
