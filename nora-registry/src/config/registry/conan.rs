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
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
    /// Revalidate stale metadata with a conditional request (`If-None-Match` /
    /// `If-Modified-Since`) instead of always re-downloading the full body.
    /// Fail-open: any error falls back to a full fetch. Note: ConanCenter
    /// (center2.conan.io) does not emit HTTP validators, so a 304 only occurs
    /// behind a validator-adding CDN / Artifactory; otherwise this degrades to a
    /// full fetch — never worse than before.
    #[serde(default = "super::super::default_true")]
    pub revalidate: bool,
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
            serve_stale: true,
            revalidate: true,
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
            super::super::parse_env_warn("NORA_CONAN_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_CONAN_PROXY_TIMEOUT_DL") {
            super::super::parse_env_warn(
                "NORA_CONAN_PROXY_TIMEOUT_DL",
                &val,
                &mut self.proxy_timeout_dl,
            );
        }
        if let Ok(val) = env::var("NORA_CONAN_METADATA_TTL") {
            super::super::parse_env_warn("NORA_CONAN_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_CONAN_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_CONAN_REVALIDATE") {
            self.revalidate = !matches!(val.as_str(), "false" | "0");
        }
    }
}
