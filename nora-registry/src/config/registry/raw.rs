// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawConfig {
    #[serde(default = "default_raw_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,
    #[serde(default = "default_raw_cache_control")]
    pub cache_control: String,
}

fn default_raw_enabled() -> bool {
    true
}

fn default_max_file_size() -> u64 {
    104_857_600 // 100MB
}

fn default_raw_cache_control() -> String {
    "no-cache".to_string()
}

impl Default for RawConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_file_size: 104_857_600,
            cache_control: default_raw_cache_control(),
        }
    }
}

impl RawConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_RAW_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_RAW_MAX_FILE_SIZE") {
            super::super::parse_env_warn("NORA_RAW_MAX_FILE_SIZE", &val, &mut self.max_file_size);
        }
        if let Ok(val) = env::var("NORA_RAW_CACHE_CONTROL") {
            self.cache_control = val;
        }
    }
}
