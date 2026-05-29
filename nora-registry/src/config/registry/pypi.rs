// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PypiConfig {
    #[serde(default = "super::super::default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
}

impl Default for PypiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: Some("https://pypi.org/simple/".to_string()),
            proxy_auth: None,
            proxy_timeout: 30,
        }
    }
}

impl PypiConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_PYPI_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_PYPI_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_PYPI_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_PYPI_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_PYPI_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
    }
}
