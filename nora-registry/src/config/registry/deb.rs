// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use super::RepoProxyEntry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_deb_max_file_size")]
    pub max_file_size: u64,
    /// Pull-through repos: local repo name → upstream apt repo URL. A repo
    /// listed here is read-only (no publish/delete/reindex); upstream metadata
    /// is served verbatim under `metadata_ttl`, packages are cached forever.
    #[serde(default)]
    pub proxies: BTreeMap<String, RepoProxyEntry>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    /// Staleness window (seconds) for upstream metadata (everything that is
    /// not a `.deb`/`.udeb`); a non-positive value revalidates every pull.
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
}

fn default_deb_max_file_size() -> u64 {
    1_073_741_824 // 1GiB — matches rpm; large firmware/driver debs exist
}

impl Default for DebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_file_size: default_deb_max_file_size(),
            proxies: BTreeMap::new(),
            proxy_timeout: 30,
            metadata_ttl: 300,
        }
    }
}

impl DebConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_DEB_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_DEB_MAX_FILE_SIZE") {
            super::super::parse_env_warn("NORA_DEB_MAX_FILE_SIZE", &val, &mut self.max_file_size);
        }
        if let Ok(val) = env::var("NORA_DEB_PROXIES") {
            self.proxies = super::parse_repo_proxies_env(&val);
        }
        if let Ok(val) = env::var("NORA_DEB_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_DEB_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_DEB_METADATA_TTL") {
            super::super::parse_env_warn("NORA_DEB_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
    }
}
