// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoConfig {
    #[serde(default = "super::super::default_true")]
    pub enabled: bool,
    #[serde(default = "default_go_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "default_go_zip_timeout")]
    pub proxy_timeout_zip: u64,
    #[serde(default = "default_go_max_zip_size")]
    pub max_zip_size: u64,
}

fn default_go_proxy() -> Option<String> {
    Some("https://proxy.golang.org".to_string())
}

pub(in crate::config) fn default_go_zip_timeout() -> u64 {
    120
}

fn default_go_max_zip_size() -> u64 {
    104_857_600 // 100MB
}

impl Default for GoConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: default_go_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            proxy_timeout_zip: 120,
            max_zip_size: 104_857_600,
        }
    }
}

impl GoConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_GO_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_GO_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_GO_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_GO_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_GO_PROXY_TIMEOUT_ZIP") {
            if let Ok(timeout) = val.parse() {
                self.proxy_timeout_zip = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_GO_MAX_ZIP_SIZE") {
            if let Ok(size) = val.parse() {
                self.max_zip_size = size;
            }
        }
    }
}
