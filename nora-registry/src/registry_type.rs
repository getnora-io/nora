// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Shared registry type enum used across config, curation, metrics, and UI.

use serde::Serialize;
use std::fmt;

/// All supported registry formats.
///
/// This is the single source of truth for registry types. Other modules
/// (curation, config, metrics, UI) reference this enum.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize)]
pub enum RegistryType {
    Docker,
    Maven,
    Npm,
    Cargo,
    #[serde(rename = "pypi")]
    PyPI,
    Go,
    Raw,
    // New formats (v0.7):
    #[serde(rename = "gems")]
    Gems,
    #[serde(rename = "terraform")]
    Terraform,
    #[serde(rename = "ansible")]
    Ansible,
    #[serde(rename = "nuget")]
    Nuget,
    #[serde(rename = "pub")]
    PubDart,
    #[serde(rename = "conan")]
    Conan,
}

impl RegistryType {
    /// Lowercase string identifier used in storage keys, metrics, and config.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Maven => "maven",
            Self::Npm => "npm",
            Self::Cargo => "cargo",
            Self::PyPI => "pypi",
            Self::Go => "go",
            Self::Raw => "raw",
            Self::Gems => "gems",
            Self::Terraform => "terraform",
            Self::Ansible => "ansible",
            Self::Nuget => "nuget",
            Self::PubDart => "pub",
            Self::Conan => "conan",
        }
    }

    /// URL mount point for this registry's routes.
    pub fn mount_point(&self) -> &'static str {
        match self {
            Self::Docker => "/v2/",
            Self::Maven => "/maven2/",
            Self::Npm => "/npm/",
            Self::Cargo => "/cargo/",
            Self::PyPI => "/simple/",
            Self::Go => "/go/",
            Self::Raw => "/raw/",
            Self::Gems => "/gems/",
            Self::Terraform => "/terraform/",
            Self::Ansible => "/ansible/",
            Self::Nuget => "/nuget/",
            Self::PubDart => "/pub/",
            Self::Conan => "/conan/",
        }
    }

    /// Display name for UI (capitalized).
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Docker => "Docker",
            Self::Maven => "Maven",
            Self::Npm => "npm",
            Self::Cargo => "Cargo",
            Self::PyPI => "PyPI",
            Self::Go => "Go",
            Self::Raw => "Raw",
            Self::Gems => "RubyGems",
            Self::Terraform => "Terraform",
            Self::Ansible => "Ansible",
            Self::Nuget => "NuGet",
            Self::PubDart => "Pub (Dart)",
            Self::Conan => "Conan",
        }
    }

    /// All registry types (original 7).
    pub fn all_v1() -> &'static [RegistryType] {
        &[
            Self::Docker,
            Self::Maven,
            Self::Npm,
            Self::Cargo,
            Self::PyPI,
            Self::Go,
            Self::Raw,
        ]
    }

    /// All registry types including new formats.
    pub fn all() -> &'static [RegistryType] {
        &[
            Self::Docker,
            Self::Maven,
            Self::Npm,
            Self::Cargo,
            Self::PyPI,
            Self::Go,
            Self::Raw,
            Self::Gems,
            Self::Terraform,
            Self::Ansible,
            Self::Nuget,
            Self::PubDart,
            Self::Conan,
        ]
    }

    /// Parse from string (case-insensitive).
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "docker" => Some(Self::Docker),
            "maven" => Some(Self::Maven),
            "npm" => Some(Self::Npm),
            "cargo" => Some(Self::Cargo),
            "pypi" => Some(Self::PyPI),
            "go" => Some(Self::Go),
            "raw" => Some(Self::Raw),
            "gems" | "rubygems" => Some(Self::Gems),
            "terraform" => Some(Self::Terraform),
            "ansible" => Some(Self::Ansible),
            "nuget" => Some(Self::Nuget),
            "pub" | "pub_dart" | "dart" => Some(Self::PubDart),
            "conan" => Some(Self::Conan),
            _ => None,
        }
    }
}

impl fmt::Display for RegistryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_str_roundtrip() {
        for rt in RegistryType::all() {
            let s = rt.as_str();
            let parsed = RegistryType::from_str_opt(s);
            assert_eq!(parsed, Some(*rt), "roundtrip failed for {}", s);
        }
    }

    #[test]
    fn test_mount_points_unique() {
        let mut seen = std::collections::HashSet::new();
        for rt in RegistryType::all() {
            assert!(
                seen.insert(rt.mount_point()),
                "duplicate mount point: {}",
                rt.mount_point()
            );
        }
    }

    #[test]
    fn test_display() {
        assert_eq!(RegistryType::Docker.to_string(), "docker");
        assert_eq!(RegistryType::PyPI.to_string(), "pypi");
        assert_eq!(RegistryType::Gems.to_string(), "gems");
        assert_eq!(RegistryType::Nuget.to_string(), "nuget");
    }

    #[test]
    fn test_from_str_case_insensitive() {
        assert_eq!(
            RegistryType::from_str_opt("DOCKER"),
            Some(RegistryType::Docker)
        );
        assert_eq!(
            RegistryType::from_str_opt("RubyGems"),
            Some(RegistryType::Gems)
        );
        assert_eq!(RegistryType::from_str_opt("unknown"), None);
    }

    #[test]
    fn test_all_contains_v1() {
        for rt in RegistryType::all_v1() {
            assert!(
                RegistryType::all().contains(rt),
                "{} in v1 but not in all",
                rt
            );
        }
    }
}
