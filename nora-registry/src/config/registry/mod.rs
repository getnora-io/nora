// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Per-registry configuration modules.

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};

/// Upstream for one proxied rpm/deb repository: the local repo name maps to a
/// single upstream repo URL (`[rpm.proxies] fedora = "https://…"`), unlike the
/// flat-namespace registries where every upstream serves the same coordinate
/// space. One upstream per repo — mirrors of the same distro repo lag each
/// other, and mixing them within a metadata-TTL window can serve a repomd.xml
/// whose referenced blobs come from a different sync generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RepoProxyEntry {
    Simple(String),
    Full(RepoProxy),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoProxy {
    pub url: String,
    #[serde(default, skip_serializing)]
    pub auth: Option<ProtectedString>,
}

impl RepoProxyEntry {
    pub fn url(&self) -> &str {
        match self {
            RepoProxyEntry::Simple(s) => s,
            RepoProxyEntry::Full(p) => &p.url,
        }
    }
    pub fn auth(&self) -> Option<&str> {
        match self {
            RepoProxyEntry::Simple(_) => None,
            RepoProxyEntry::Full(p) => crate::secrets::expose_opt(&p.auth),
        }
    }
}

/// Parse `repo=url|auth,repo2=url` env form shared by `NORA_RPM_PROXIES` /
/// `NORA_DEB_PROXIES`.
pub(in crate::config) fn parse_repo_proxies_env(
    val: &str,
) -> std::collections::BTreeMap<String, RepoProxyEntry> {
    val.split(',')
        .filter_map(|s| s.trim().split_once('='))
        .map(|(repo, rest)| {
            let entry = match rest.split_once('|') {
                Some((url, auth)) => RepoProxyEntry::Full(RepoProxy {
                    url: url.to_string(),
                    auth: Some(ProtectedString::from(auth)),
                }),
                None => RepoProxyEntry::Simple(rest.to_string()),
            };
            (repo.to_string(), entry)
        })
        .collect()
}

#[cfg(test)]
mod repo_proxy_tests {
    use super::*;

    #[test]
    fn parses_env_map_with_auth() {
        let map = parse_repo_proxies_env(
            "fedora=https://dl.fedoraproject.org/pub/fedora, epel=https://internal/epel|user:pass",
        );
        assert_eq!(map.len(), 2);
        assert_eq!(
            map["fedora"].url(),
            "https://dl.fedoraproject.org/pub/fedora"
        );
        assert!(map["fedora"].auth().is_none());
        assert_eq!(map["epel"].url(), "https://internal/epel");
        assert_eq!(map["epel"].auth(), Some("user:pass"));
    }

    #[test]
    fn skips_malformed_entries() {
        let map = parse_repo_proxies_env("no-equals-sign,ok=https://u");
        assert_eq!(map.len(), 1);
        assert_eq!(map["ok"].url(), "https://u");
    }
}

mod ansible;
mod cargo;
mod conan;
mod deb;
mod docker;
mod gems;
mod go;
mod maven;
mod npm;
mod nuget;
mod pub_dart;
mod pypi;
mod raw;
mod rpm;
mod terraform;

pub use self::ansible::AnsibleConfig;
pub use self::cargo::CargoConfig;
pub use self::conan::ConanConfig;
pub use self::deb::DebConfig;
// Re-export all Docker types including extract_docker_namespace (public API surface)
#[allow(unused_imports)]
pub use self::docker::{extract_docker_namespace, DefaultAction, DockerConfig, DockerUpstream};
pub use self::gems::GemsConfig;
pub use self::go::GoConfig;
#[allow(unused_imports)]
pub use self::maven::{MavenConfig, MavenProxy, MavenProxyEntry};
pub use self::npm::NpmConfig;
pub use self::nuget::NugetConfig;
pub use self::pub_dart::PubDartConfig;
pub use self::pypi::PypiConfig;
pub use self::raw::RawConfig;
pub use self::rpm::RpmConfig;
pub use self::terraform::TerraformConfig;
