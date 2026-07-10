// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
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
    }
}
