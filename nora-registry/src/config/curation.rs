// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Curation layer configuration.

use crate::digest_quarantine::QuarantineMode;
use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

/// Curation operating mode.
///
/// - `off` — curation disabled, all requests pass through (default)
/// - `audit` — evaluate filters and log decisions, but never block
/// - `enforce` — evaluate filters and block requests that match a deny rule
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CurationMode {
    #[default]
    Off,
    Audit,
    Enforce,
}

impl std::fmt::Display for CurationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CurationMode::Off => write!(f, "off"),
            CurationMode::Audit => write!(f, "audit"),
            CurationMode::Enforce => write!(f, "enforce"),
        }
    }
}

impl std::str::FromStr for CurationMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "audit" => Ok(Self::Audit),
            "enforce" => Ok(Self::Enforce),
            other => Err(format!(
                "unknown curation mode {:?} — valid values: off, audit, enforce",
                other
            )),
        }
    }
}

/// Behavior when a curation filter returns an error or panics.
///
/// - `closed` — treat as blocked (fail-safe, default)
/// - `open` — treat as allowed (fail-open)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CurationOnFailure {
    #[default]
    Closed,
    Open,
}

/// Curation layer configuration.
///
/// # Environment Variables
/// - `NORA_CURATION_MODE` — off/audit/enforce (default: off)
/// - `NORA_CURATION_ON_FAILURE` — closed/open (default: closed)
/// - `NORA_CURATION_ALLOWLIST_PATH` — path to allowlist JSON file
/// - `NORA_CURATION_BLOCKLIST_PATH` — path to blocklist JSON file
/// - `NORA_CURATION_BYPASS_TOKEN` — token to bypass curation checks
/// - `NORA_CURATION_REQUIRE_INTEGRITY` — require integrity metadata (default: false)
/// - `NORA_CURATION_INTERNAL_NS` — comma-separated glob patterns
/// - `NORA_CURATION_MIN_RELEASE_AGE` — minimum release age (e.g., "7d", "24h", "1w")
/// - `NORA_CURATION_QUARANTINE` — quarantine mode: off/observe/enforce (default: off)
/// - `NORA_CURATION_QUARANTINE_TTL` — quarantine hold duration (e.g., "14d", "24h")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurationConfig {
    #[serde(default)]
    pub mode: CurationMode,
    #[serde(default)]
    pub on_failure: CurationOnFailure,
    #[serde(default)]
    pub allowlist_path: Option<String>,
    #[serde(default)]
    pub blocklist_path: Option<String>,
    /// Token to bypass curation. Should only be set via env var, not config file.
    #[serde(default, skip_serializing)]
    pub bypass_token: Option<ProtectedString>,
    #[serde(default)]
    pub require_integrity: bool,
    /// Glob patterns for internal namespaces that must never be proxied upstream.
    /// Always active regardless of curation mode (security boundary).
    #[serde(default)]
    pub internal_namespaces: Vec<String>,
    /// Minimum release age before a package is allowed (e.g., "7d", "24h", "1w").
    /// Packages published less than this duration ago are blocked.
    #[serde(default)]
    pub min_release_age: Option<String>,
    /// Digest quarantine mode: "off" (default), "observe", or "enforce".
    /// Tracks first-seen timestamps for proxy-fetched content digests.
    /// Invalid values are rejected at config parse time (ADR-8: security never silently disabled).
    #[serde(default)]
    pub quarantine: Option<QuarantineMode>,
    /// How long new digests are held in quarantine (e.g., "14d", "24h", "1w").
    #[serde(default)]
    pub quarantine_ttl: Option<String>,
    /// Per-registry curation overrides. Overrides `min_release_age` per registry.
    #[serde(default)]
    pub npm: RegistryCurationOverride,
    #[serde(default)]
    pub pypi: RegistryCurationOverride,
    #[serde(default)]
    pub cargo: RegistryCurationOverride,
    #[serde(default)]
    pub go: RegistryCurationOverride,
    #[serde(default)]
    pub docker: RegistryCurationOverride,
    #[serde(default)]
    pub maven: RegistryCurationOverride,
    #[serde(default)]
    pub gems: RegistryCurationOverride,
    #[serde(default)]
    pub terraform: RegistryCurationOverride,
    #[serde(default)]
    pub ansible: RegistryCurationOverride,
    #[serde(default)]
    pub nuget: RegistryCurationOverride,
    #[serde(rename = "pub", default)]
    pub pub_dart: RegistryCurationOverride,
    #[serde(default)]
    pub conan: RegistryCurationOverride,
}

/// Per-registry curation override (used within `[curation.{registry}]`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryCurationOverride {
    /// Override min_release_age for this specific registry.
    #[serde(default)]
    pub min_release_age: Option<String>,
    /// Override quarantine mode for this specific registry.
    #[serde(default)]
    pub quarantine: Option<QuarantineMode>,
    /// Override quarantine TTL for this specific registry.
    #[serde(default)]
    pub quarantine_ttl: Option<String>,
}

impl Default for CurationConfig {
    fn default() -> Self {
        Self {
            mode: CurationMode::Off,
            on_failure: CurationOnFailure::Closed,
            allowlist_path: None,
            blocklist_path: None,
            bypass_token: None,
            require_integrity: false,
            internal_namespaces: Vec::new(),
            min_release_age: None,
            quarantine: None,
            quarantine_ttl: None,
            npm: RegistryCurationOverride::default(),
            pypi: RegistryCurationOverride::default(),
            cargo: RegistryCurationOverride::default(),
            go: RegistryCurationOverride::default(),
            docker: RegistryCurationOverride::default(),
            maven: RegistryCurationOverride::default(),
            gems: RegistryCurationOverride::default(),
            terraform: RegistryCurationOverride::default(),
            ansible: RegistryCurationOverride::default(),
            nuget: RegistryCurationOverride::default(),
            pub_dart: RegistryCurationOverride::default(),
            conan: RegistryCurationOverride::default(),
        }
    }
}

impl CurationConfig {
    /// Apply environment variable overrides for curation config.
    pub(super) fn apply_env_overrides(&mut self) -> Result<(), String> {
        if let Ok(val) = env::var("NORA_CURATION_MODE") {
            self.mode = val
                .parse::<CurationMode>()
                .map_err(|e| format!("NORA_CURATION_MODE={:?}: {}", val, e))?;
        }
        if let Ok(val) = env::var("NORA_CURATION_ON_FAILURE") {
            self.on_failure = match val.to_lowercase().as_str() {
                "open" => CurationOnFailure::Open,
                _ => CurationOnFailure::Closed,
            };
        }
        if let Ok(val) = env::var("NORA_CURATION_ALLOWLIST_PATH") {
            self.allowlist_path = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CURATION_BLOCKLIST_PATH") {
            self.blocklist_path = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CURATION_BYPASS_TOKEN") {
            self.bypass_token = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_CURATION_REQUIRE_INTEGRITY") {
            self.require_integrity = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_CURATION_INTERNAL_NS") {
            self.internal_namespaces = if val.is_empty() {
                Vec::new()
            } else {
                val.split(',').map(|s| s.trim().to_string()).collect()
            };
        }
        if let Ok(val) = env::var("NORA_CURATION_MIN_RELEASE_AGE") {
            self.min_release_age = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_CURATION_QUARANTINE") {
            self.quarantine = if val.is_empty() {
                None
            } else {
                Some(
                    val.parse::<QuarantineMode>()
                        .map_err(|e| format!("NORA_CURATION_QUARANTINE={:?}: {}", val, e))?,
                )
            };
        }
        if let Ok(val) = env::var("NORA_CURATION_QUARANTINE_TTL") {
            self.quarantine_ttl = if val.is_empty() { None } else { Some(val) };
        }

        // Per-registry curation overrides
        for (env_suffix, field) in [
            ("NPM", &mut self.npm),
            ("PYPI", &mut self.pypi),
            ("CARGO", &mut self.cargo),
            ("GO", &mut self.go),
            ("DOCKER", &mut self.docker),
            ("MAVEN", &mut self.maven),
            ("GEMS", &mut self.gems),
            ("TERRAFORM", &mut self.terraform),
            ("ANSIBLE", &mut self.ansible),
            ("NUGET", &mut self.nuget),
            ("PUB", &mut self.pub_dart),
            ("CONAN", &mut self.conan),
        ] {
            if let Ok(val) = env::var(format!("NORA_CURATION_{}_MIN_RELEASE_AGE", env_suffix)) {
                field.min_release_age = if val.is_empty() { None } else { Some(val) };
            }
            if let Ok(val) = env::var(format!("NORA_CURATION_{}_QUARANTINE", env_suffix)) {
                field.quarantine = if val.is_empty() {
                    None
                } else {
                    Some(val.parse::<QuarantineMode>().map_err(|e| {
                        format!("NORA_CURATION_{}_QUARANTINE={:?}: {}", env_suffix, val, e)
                    })?)
                };
            }
            if let Ok(val) = env::var(format!("NORA_CURATION_{}_QUARANTINE_TTL", env_suffix)) {
                field.quarantine_ttl = if val.is_empty() { None } else { Some(val) };
            }
        }

        Ok(())
    }
}
