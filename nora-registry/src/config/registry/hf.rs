// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::env;

/// Hugging Face Hub pull-through proxy (`[hf]`), off by default while the format is built.
///
/// Only the upstream is configurable. There is deliberately no `proxy_auth`: a server-side
/// token would let the cache hand gated repositories to every NORA user, so the first
/// release proxies public repositories only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HfConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_hf_proxy")]
    pub proxy: Option<String>,
}

fn default_hf_proxy() -> Option<String> {
    Some("https://huggingface.co".to_string())
}

impl Default for HfConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_hf_proxy(),
        }
    }
}

impl HfConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_HF_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_HF_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
    }
}
