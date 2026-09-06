// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Shared registry type enum used across config, curation, metrics, and UI.

use serde::Serialize;
use std::fmt;

/// Declares [`RegistryType`] and its intrinsic string forms from a SINGLE list, so that
/// adding a format is one line and `all()` can never drift from the enum: the variant,
/// its `as_str`, `mount_point` and `display_name` are generated together, and each
/// per-variant method is an exhaustive `match` (a new variant is a compile error until
/// handled). This is the single source of truth for registry formats (#369).
macro_rules! registry_types {
    ( $( $variant:ident => $as_str:literal, $mount:literal, $display:literal );+ $(;)? ) => {
        /// All supported registry formats.
        ///
        /// This is the single source of truth for registry types. Other modules
        /// (curation, config, metrics, UI) reference this enum. Declared via
        /// [`registry_types!`], so the enum and [`RegistryType::all`] are generated
        /// from one list and cannot desync.
        #[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize)]
        pub enum RegistryType {
            $( #[serde(rename = $as_str)] $variant ),+
        }

        impl RegistryType {
            /// Lowercase string identifier used in storage keys, metrics, and config.
            pub fn as_str(&self) -> &'static str {
                match self { $( Self::$variant => $as_str ),+ }
            }

            /// URL mount point for this registry's routes.
            pub fn mount_point(&self) -> &'static str {
                match self { $( Self::$variant => $mount ),+ }
            }

            /// Display name for UI (capitalized).
            pub fn display_name(&self) -> &'static str {
                match self { $( Self::$variant => $display ),+ }
            }

            /// Every registry type, in declaration order. Generated from the same list
            /// as the enum itself, so it can never silently omit a variant.
            pub fn all() -> &'static [RegistryType] {
                &[ $( Self::$variant ),+ ]
            }
        }
    };
}

registry_types! {
    Docker    => "docker",    "/v2/",        "Docker";
    Maven     => "maven",     "/maven2/",    "Maven";
    Npm       => "npm",       "/npm/",       "npm";
    Cargo     => "cargo",     "/cargo/",     "Cargo";
    PyPI      => "pypi",      "/simple/",    "PyPI";
    Go        => "go",        "/go/",        "Go";
    Raw       => "raw",       "/raw/",       "Raw";
    Gems      => "gems",      "/gems/",      "RubyGems";
    Terraform => "terraform", "/terraform/", "Terraform";
    Ansible   => "ansible",   "/ansible/",   "Ansible";
    Nuget     => "nuget",     "/nuget/",     "NuGet";
    PubDart   => "pub",       "/pub/",       "Pub (Dart)";
    Conan     => "conan",     "/conan/",     "Conan";
    Rpm       => "rpm",       "/rpm/",       "RPM";
    Deb       => "deb",       "/deb/",       "Debian";
}

impl RegistryType {
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

    /// Parse from string (case-insensitive), accepting common aliases. Kept hand-written
    /// because of the aliases; `test_as_str_roundtrip` guards that every variant's
    /// canonical `as_str` parses back.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "docker" => Some(Self::Docker),
            "maven" | "maven2" => Some(Self::Maven),
            "npm" => Some(Self::Npm),
            "cargo" => Some(Self::Cargo),
            "pypi" => Some(Self::PyPI),
            "go" => Some(Self::Go),
            "raw" => Some(Self::Raw),
            "gems" | "rubygems" => Some(Self::Gems),
            "terraform" => Some(Self::Terraform),
            "ansible" => Some(Self::Ansible),
            "nuget" | "chocolatey" | "choco" | "powershellgallery" | "pwsh" => Some(Self::Nuget),
            "pub" | "pub_dart" | "dart" => Some(Self::PubDart),
            "conan" => Some(Self::Conan),
            "rpm" | "yum" | "dnf" => Some(Self::Rpm),
            "deb" | "apt" | "debian" => Some(Self::Deb),
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
