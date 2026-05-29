// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Audit log configuration.
//!
//! Named `audit_cfg` to avoid collision with `crate::audit` module.

use serde::{Deserialize, Serialize};
use std::env;

/// Audit log configuration.
///
/// Controls where audit events are written:
/// - `file`   — write to {storage_path}/audit.jsonl (default)
/// - `stdout` — write JSONL to stderr (12-factor compatible)
/// - `both`   — write to file AND stderr
/// - `off`    — disable audit logging
///
/// ENV: `NORA_AUDIT_LOG=file|stdout|both|off`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default)]
    pub mode: crate::audit::AuditMode,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            mode: crate::audit::AuditMode::File,
        }
    }
}

impl AuditConfig {
    /// Apply environment variable overrides for audit config.
    pub(super) fn apply_env_overrides(&mut self) -> Result<(), String> {
        if let Ok(val) = env::var("NORA_AUDIT_LOG") {
            self.mode = val
                .parse::<crate::audit::AuditMode>()
                .map_err(|e| format!("NORA_AUDIT_LOG={:?}: {}", val, e))?;
        }
        Ok(())
    }
}
