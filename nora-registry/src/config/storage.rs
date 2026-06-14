// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Storage backend configuration.

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StorageMode {
    #[default]
    Local,
    S3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default)]
    pub mode: StorageMode,
    #[serde(default = "default_storage_path")]
    pub path: String,
    #[serde(default = "default_s3_url")]
    pub s3_url: String,
    #[serde(default = "default_bucket")]
    pub bucket: String,
    /// S3 access key (optional, uses anonymous access if not set)
    #[serde(default, skip_serializing)]
    pub s3_access_key: Option<ProtectedString>,
    /// S3 secret key (optional, uses anonymous access if not set)
    #[serde(default, skip_serializing)]
    pub s3_secret_key: Option<ProtectedString>,
    /// S3 region (default: us-east-1)
    #[serde(default = "default_s3_region")]
    pub s3_region: String,
}

pub(super) fn default_s3_region() -> String {
    "us-east-1".to_string()
}

pub(super) fn default_storage_path() -> String {
    "data/storage".to_string()
}

pub(super) fn default_s3_url() -> String {
    "http://127.0.0.1:9000".to_string()
}

pub(super) fn default_bucket() -> String {
    "registry".to_string()
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            mode: StorageMode::Local,
            path: default_storage_path(),
            s3_url: default_s3_url(),
            bucket: default_bucket(),
            s3_access_key: None,
            s3_secret_key: None,
            s3_region: default_s3_region(),
        }
    }
}

impl StorageConfig {
    /// Apply environment variable overrides for storage config.
    ///
    /// Returns `Err` if `NORA_STORAGE_MODE` has an unrecognized value — fail-closed (#562).
    pub(super) fn apply_env_overrides(&mut self) -> Result<(), String> {
        if let Ok(val) = env::var("NORA_STORAGE_MODE") {
            self.mode = match val.to_lowercase().as_str() {
                "local" | "filesystem" => StorageMode::Local,
                "s3" => StorageMode::S3,
                other => {
                    return Err(format!(
                        "NORA_STORAGE_MODE={:?} is invalid — valid values: local, s3",
                        other
                    ))
                }
            };
        }
        if let Ok(val) = env::var("NORA_STORAGE_PATH") {
            self.path = val;
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_URL") {
            self.s3_url = val;
        }
        if let Ok(val) = env::var("NORA_STORAGE_BUCKET") {
            self.bucket = val;
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_ACCESS_KEY") {
            self.s3_access_key = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_SECRET_KEY") {
            self.s3_secret_key = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_STORAGE_S3_REGION") {
            self.s3_region = val;
        }

        Ok(())
    }
}
