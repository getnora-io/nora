// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerraformConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(
        default = "default_terraform_proxy",
        deserialize_with = "super::super::deserialize_upstream"
    )]
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
    /// Seconds a metadata request waits for the upstream when a stored copy is there to serve
    /// stale (`proxy_timeout`, if lower): when the upstream has not answered by then, the copy
    /// is. It stays below the 10 s Terraform waits for each mirror request, so an upstream that
    /// does not answer leaves `terraform init` on a warm cache working (#1230). A request with
    /// no stored copy to fall back to waits the full `proxy_timeout`.
    #[serde(default = "default_tf_revalidate_timeout")]
    pub revalidate_timeout: u64,
}

fn default_terraform_proxy() -> Option<String> {
    Some("https://registry.terraform.io".to_string())
}

/// 5 s: half the 10 s Terraform 1.9.8 waits for a network mirror request (measured, #1230).
fn default_tf_revalidate_timeout() -> u64 {
    5
}

impl Default for TerraformConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_terraform_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            proxy_timeout_dl: 120,
            metadata_ttl: 300,
            serve_stale: true,
            revalidate_timeout: default_tf_revalidate_timeout(),
        }
    }
}

impl TerraformConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_TF_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_TF_PROXY") {
            self.proxy = super::super::upstream_setting(val);
        }
        if let Ok(val) = env::var("NORA_TF_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_TF_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_TF_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_TF_PROXY_TIMEOUT_DL") {
            super::super::parse_env_warn(
                "NORA_TF_PROXY_TIMEOUT_DL",
                &val,
                &mut self.proxy_timeout_dl,
            );
        }
        if let Ok(val) = env::var("NORA_TF_METADATA_TTL") {
            super::super::parse_env_warn("NORA_TF_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_TF_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_TF_REVALIDATE_TIMEOUT") {
            super::super::parse_env_warn(
                "NORA_TF_REVALIDATE_TIMEOUT",
                &val,
                &mut self.revalidate_timeout,
            );
        }
    }
}
