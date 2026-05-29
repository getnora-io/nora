// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConanConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_conan_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "super::go::default_go_zip_timeout")]
    pub proxy_timeout_dl: u64,
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
}

fn default_conan_proxy() -> Option<String> {
    Some("https://center2.conan.io".to_string())
}

impl Default for ConanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_conan_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            proxy_timeout_dl: 120,
            metadata_ttl: 300,
        }
    }
}

impl ConanConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_CONAN_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_CONAN_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CONAN_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_CONAN_PROXY_TIMEOUT") {
            if let Ok(timeout) = val.parse() {
                self.proxy_timeout = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_CONAN_PROXY_TIMEOUT_DL") {
            if let Ok(timeout) = val.parse() {
                self.proxy_timeout_dl = timeout;
            }
        }
        if let Ok(val) = env::var("NORA_CONAN_METADATA_TTL") {
            if let Ok(ttl) = val.parse() {
                self.metadata_ttl = ttl;
            }
        }
    }
}
