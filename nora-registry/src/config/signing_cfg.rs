// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Repository index signing configuration (#128).

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SigningConfig {
    /// Sign rpm/deb repository indexes. On by default: with local storage a
    /// key is generated at first boot; signed and unsigned clients both keep
    /// working (unsigned clients simply don't fetch the signatures).
    #[serde(default = "default_signing_enabled")]
    pub enabled: bool,
    /// Path of the armored OpenPGP secret key. Empty = derive
    /// `<storage.path>/.signing/nora.key` for local storage; required for S3
    /// (there is no local data directory to derive from).
    #[serde(default)]
    pub key_path: String,
}

fn default_signing_enabled() -> bool {
    true
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            key_path: String::new(),
        }
    }
}

impl SigningConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_SIGNING_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_SIGNING_KEY_PATH") {
            self.key_path = val;
        }
    }
}
