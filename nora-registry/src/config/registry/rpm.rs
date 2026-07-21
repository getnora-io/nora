// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use super::RepoProxyEntry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpmConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_rpm_max_file_size")]
    pub max_file_size: u64,
    /// Changelog entries per package kept in other.xml (createrepo_c default: 10).
    #[serde(default = "default_rpm_changelog_limit")]
    pub changelog_limit: usize,
    /// Pull-through repos: local repo name → upstream yum repo URL. A repo
    /// listed here is read-only (no publish/delete/reindex); upstream metadata
    /// is served verbatim under `metadata_ttl`, packages are cached forever.
    #[serde(default)]
    pub proxies: BTreeMap<String, RepoProxyEntry>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    /// Staleness window (seconds) for upstream metadata (everything that is
    /// not a `.rpm`/`.drpm`); a non-positive value revalidates every pull.
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
}

fn default_rpm_max_file_size() -> u64 {
    1_073_741_824 // 1GiB — kernel/driver RPMs routinely exceed 100MB
}

fn default_rpm_changelog_limit() -> usize {
    10
}

impl Default for RpmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_file_size: default_rpm_max_file_size(),
            changelog_limit: default_rpm_changelog_limit(),
            proxies: BTreeMap::new(),
            proxy_timeout: 30,
            metadata_ttl: 300,
        }
    }
}

impl RpmConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_RPM_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_RPM_MAX_FILE_SIZE") {
            super::super::parse_env_warn("NORA_RPM_MAX_FILE_SIZE", &val, &mut self.max_file_size);
        }
        if let Ok(val) = env::var("NORA_RPM_CHANGELOG_LIMIT") {
            super::super::parse_env_warn(
                "NORA_RPM_CHANGELOG_LIMIT",
                &val,
                &mut self.changelog_limit,
            );
        }
        if let Ok(val) = env::var("NORA_RPM_PROXIES") {
            self.proxies = super::parse_repo_proxies_env(&val);
        }
        if let Ok(val) = env::var("NORA_RPM_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_RPM_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_RPM_METADATA_TTL") {
            super::super::parse_env_warn("NORA_RPM_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
    }
}
