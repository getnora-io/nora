// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Rate limiting configuration.

use serde::{Deserialize, Serialize};
use std::env;

/// Rate limiting configuration
///
/// Controls request rate limits for different endpoint types.
///
/// # Example
/// ```toml
/// [rate_limit]
/// auth_rps = 1
/// auth_burst = 5
/// upload_rps = 200
/// upload_burst = 500
/// general_rps = 100
/// general_burst = 200
/// ```
///
/// # Environment Variables
/// - `NORA_RATE_LIMIT_AUTH_RPS` - Auth requests per second
/// - `NORA_RATE_LIMIT_AUTH_BURST` - Auth burst size
/// - `NORA_RATE_LIMIT_UPLOAD_RPS` - Upload requests per second
/// - `NORA_RATE_LIMIT_UPLOAD_BURST` - Upload burst size
/// - `NORA_RATE_LIMIT_GENERAL_RPS` - General requests per second
/// - `NORA_RATE_LIMIT_GENERAL_BURST` - General burst size
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting (default: true). Set `NORA_RATE_LIMIT_ENABLED=false` to disable.
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,
    #[serde(default = "default_auth_rps")]
    pub auth_rps: u64,
    #[serde(default = "default_auth_burst")]
    pub auth_burst: u32,
    #[serde(default = "default_upload_rps")]
    pub upload_rps: u64,
    #[serde(default = "default_upload_burst")]
    pub upload_burst: u32,
    #[serde(default = "default_general_rps")]
    pub general_rps: u64,
    #[serde(default = "default_general_burst")]
    pub general_burst: u32,
}

fn default_rate_limit_enabled() -> bool {
    true
}
fn default_auth_rps() -> u64 {
    1
}
fn default_auth_burst() -> u32 {
    5
}
fn default_upload_rps() -> u64 {
    200
}
fn default_upload_burst() -> u32 {
    500
}
fn default_general_rps() -> u64 {
    100
}
fn default_general_burst() -> u32 {
    200
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            auth_rps: default_auth_rps(),
            auth_burst: default_auth_burst(),
            upload_rps: default_upload_rps(),
            upload_burst: default_upload_burst(),
            general_rps: default_general_rps(),
            general_burst: default_general_burst(),
        }
    }
}

impl RateLimitConfig {
    /// Apply environment variable overrides for rate limit config.
    pub(super) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_RATE_LIMIT_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_RATE_LIMIT_AUTH_RPS") {
            if let Ok(v) = val.parse::<u64>() {
                self.auth_rps = v;
            }
        }
        if let Ok(val) = env::var("NORA_RATE_LIMIT_AUTH_BURST") {
            if let Ok(v) = val.parse::<u32>() {
                self.auth_burst = v;
            }
        }
        if let Ok(val) = env::var("NORA_RATE_LIMIT_UPLOAD_RPS") {
            if let Ok(v) = val.parse::<u64>() {
                self.upload_rps = v;
            }
        }
        if let Ok(val) = env::var("NORA_RATE_LIMIT_UPLOAD_BURST") {
            if let Ok(v) = val.parse::<u32>() {
                self.upload_burst = v;
            }
        }
        if let Ok(val) = env::var("NORA_RATE_LIMIT_GENERAL_RPS") {
            if let Ok(v) = val.parse::<u64>() {
                self.general_rps = v;
            }
        }
        if let Ok(val) = env::var("NORA_RATE_LIMIT_GENERAL_BURST") {
            if let Ok(v) = val.parse::<u32>() {
                self.general_burst = v;
            }
        }
    }
}
