// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_deb_max_file_size")]
    pub max_file_size: u64,
}

fn default_deb_max_file_size() -> u64 {
    1_073_741_824 // 1GiB — matches rpm; large firmware/driver debs exist
}

impl Default for DebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_file_size: default_deb_max_file_size(),
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
    }
}
