// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Declarative registry selection via `[registries]` TOML section.

use crate::registry_type::RegistryType;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Top-level `[registries]` section for declarative registry selection.
///
/// # Example
/// ```toml
/// [registries]
/// enable = ["docker", "npm", "pypi"]
///
/// # Or enable all except some:
/// # enable = ["all", "-maven"]
///
/// # Or enable everything:
/// # enable = "all"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistriesSection {
    #[serde(default)]
    pub enable: Option<EnableSpec>,
}

/// What registries to enable — a single string or list of strings.
///
/// Supports:
/// - `"all"` — all 13 registries
/// - `"docker"` — single registry
/// - `["docker", "npm", "pypi"]` — explicit list
/// - `["all", "-maven"]` — all except maven
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum EnableSpec {
    /// Single string: `enable = "all"` or `enable = "docker"`
    Single(String),
    /// List of strings: `enable = ["docker", "npm"]`
    List(Vec<String>),
}

impl EnableSpec {
    /// Parse from comma-separated env var string.
    /// E.g. `"docker,npm,pypi"` or `"all,-maven"`.
    pub fn from_env_str(s: &str) -> Self {
        let items: Vec<String> = s
            .split(',')
            .map(|item| item.trim().to_lowercase())
            .filter(|item| !item.is_empty())
            .collect();
        match items.len() {
            1 => {
                // Safety: we just checked len() == 1
                let item = items.into_iter().next().unwrap_or_default();
                EnableSpec::Single(item)
            }
            _ => EnableSpec::List(items),
        }
    }

    /// Resolve the spec into a concrete set of RegistryTypes.
    ///
    /// Rules:
    /// - `"all"` → all 13 registries
    /// - `"-name"` → exclusion (only valid when `"all"` is present)
    /// - `"name"` → inclusion
    /// - Unknown name → Err
    /// - Empty result → Err
    pub fn resolve(&self) -> Result<HashSet<RegistryType>, String> {
        let items = match self {
            EnableSpec::Single(s) => vec![s.clone()],
            EnableSpec::List(v) => v.clone(),
        };

        if items.is_empty() {
            return Err("registries.enable must not be empty".to_string());
        }

        let has_all = items.iter().any(|s| s == "all");
        let exclusions: Vec<&str> = items
            .iter()
            .filter(|s| s.starts_with('-'))
            .map(|s| s.as_str())
            .collect();
        let inclusions: Vec<&str> = items
            .iter()
            .filter(|s| *s != "all" && !s.starts_with('-'))
            .map(|s| s.as_str())
            .collect();

        // Exclusions without "all" is an error
        if !exclusions.is_empty() && !has_all {
            return Err(format!(
                "exclusion entries ({}) require \"all\" in the list",
                exclusions.join(", ")
            ));
        }

        // "all" with inclusions is ambiguous
        if has_all && !inclusions.is_empty() {
            return Err(format!(
                "\"all\" cannot be combined with inclusions ({}); use \"all\" with exclusions like \"-maven\"",
                inclusions.join(", ")
            ));
        }

        if has_all {
            // Start with all, then remove exclusions
            let mut set: HashSet<RegistryType> = RegistryType::all().iter().copied().collect();
            for ex in &exclusions {
                let name = &ex[1..]; // strip leading '-'
                match RegistryType::from_str_opt(name) {
                    Some(rt) => {
                        set.remove(&rt);
                    }
                    None => {
                        return Err(format!("unknown registry in exclusion: \"{}\"", ex));
                    }
                }
            }
            if set.is_empty() {
                return Err("all registries excluded — at least one must be enabled".to_string());
            }
            Ok(set)
        } else {
            // Explicit inclusion list
            let mut set = HashSet::new();
            for name in &inclusions {
                match RegistryType::from_str_opt(name) {
                    Some(rt) => {
                        set.insert(rt);
                    }
                    None => {
                        return Err(format!("unknown registry: \"{}\"", name));
                    }
                }
            }
            if set.is_empty() {
                return Err("registries.enable must not be empty".to_string());
            }
            Ok(set)
        }
    }
}
