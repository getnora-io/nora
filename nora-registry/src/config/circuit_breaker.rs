// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Circuit breaker configuration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;

fn default_cb_enabled() -> bool {
    false
}
fn default_cb_threshold() -> u32 {
    5
}
fn default_cb_reset_timeout() -> u64 {
    30
}

/// Upstream proxy circuit breaker configuration.
///
/// Experimental — disabled by default. When enabled, tracks per-registry
/// upstream failures and fails fast (503) when a registry is known to be down.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Enable circuit breaker (default: false)
    #[serde(default = "default_cb_enabled")]
    pub enabled: bool,
    /// Number of consecutive failures before opening the circuit (default: 5)
    #[serde(default = "default_cb_threshold")]
    pub failure_threshold: u32,
    /// Seconds to wait before probing a failed upstream (default: 30)
    #[serde(default = "default_cb_reset_timeout")]
    pub reset_timeout: u64,
    /// Per-registry overrides keyed by circuit breaker key (e.g. "docker:https://registry-1.docker.io").
    #[serde(default)]
    pub overrides: HashMap<String, CircuitBreakerOverride>,
}

/// Per-registry circuit breaker threshold overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerOverride {
    pub failure_threshold: Option<u32>,
    pub reset_timeout: Option<u64>,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: default_cb_enabled(),
            failure_threshold: default_cb_threshold(),
            reset_timeout: default_cb_reset_timeout(),
            overrides: HashMap::new(),
        }
    }
}

impl CircuitBreakerConfig {
    /// Apply environment variable overrides for circuit breaker config.
    pub(super) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_CB_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_CB_THRESHOLD") {
            super::parse_env_warn("NORA_CB_THRESHOLD", &val, &mut self.failure_threshold);
        }
        if let Ok(val) = env::var("NORA_CB_RESET_TIMEOUT") {
            super::parse_env_warn("NORA_CB_RESET_TIMEOUT", &val, &mut self.reset_timeout);
        }
    }
}
