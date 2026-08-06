// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavenConfig {
    #[serde(default = "super::super::default_true")]
    pub enabled: bool,
    #[serde(default = "default_maven_proxies")]
    pub proxies: Vec<MavenProxyEntry>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    /// Prevent overwriting released (non-SNAPSHOT) artifacts
    #[serde(default = "super::super::default_true")]
    pub immutable_releases: bool,
    /// Staleness window (seconds) for mutable metadata (maven-metadata.xml, SNAPSHOT); a
    /// non-positive value revalidates every pull. Release artifacts are always immutable.
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
    #[serde(default)]
    pub repositories: Vec<MavenRepository>,
    #[serde(default)]
    pub default_repository: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MavenVersionPolicy {
    Release,
    Snapshot,
    #[default]
    Mixed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MavenWritePolicy {
    Allow,
    #[default]
    AllowOnce,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum MavenRepository {
    Hosted {
        name: String,
        #[serde(default)]
        version_policy: MavenVersionPolicy,
        #[serde(default)]
        write_policy: MavenWritePolicy,
    },
    Proxy {
        name: String,
        url: String,
        #[serde(default, skip_serializing)]
        auth: Option<ProtectedString>,
        #[serde(default)]
        version_policy: MavenVersionPolicy,
        #[serde(default)]
        metadata_ttl: Option<i64>,
        #[serde(default = "default_negative_ttl")]
        negative_ttl: i64,
    },
    Group {
        name: String,
        members: Vec<String>,
    },
}

fn default_negative_ttl() -> i64 {
    1_440 * 60
}

impl MavenRepository {
    pub fn name(&self) -> &str {
        match self {
            Self::Hosted { name, .. } | Self::Proxy { name, .. } | Self::Group { name, .. } => name,
        }
    }
}

/// Maven upstream proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MavenProxyEntry {
    Simple(String),
    Full(MavenProxy),
}

/// Maven upstream proxy with optional auth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MavenProxy {
    pub url: String,
    #[serde(default, skip_serializing)]
    pub auth: Option<ProtectedString>,
}

impl MavenProxyEntry {
    pub fn url(&self) -> &str {
        match self {
            MavenProxyEntry::Simple(s) => s,
            MavenProxyEntry::Full(p) => &p.url,
        }
    }
    pub fn auth(&self) -> Option<&str> {
        use crate::secrets::expose_opt;
        match self {
            MavenProxyEntry::Simple(_) => None,
            MavenProxyEntry::Full(p) => expose_opt(&p.auth),
        }
    }
}

/// Default Maven upstream. Single source for the serde field-default and the
/// `Default` impl so a present-but-empty `[maven]` table keeps the upstream
/// instead of silently going local-only (the npm/pypi `#[serde(default)]`
/// divergence class — a bare default on a `Vec` yields an empty list).
fn default_maven_proxies() -> Vec<MavenProxyEntry> {
    vec![MavenProxyEntry::Simple(
        "https://repo1.maven.org/maven2".to_string(),
    )]
}

impl Default for MavenConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxies: default_maven_proxies(),
            proxy_timeout: 30,
            immutable_releases: true,
            metadata_ttl: 300,
            repositories: Vec::new(),
            default_repository: None,
        }
    }
}

impl MavenConfig {
    pub fn repository(&self, name: &str) -> Option<&MavenRepository> {
        self.repositories.iter().find(|repo| repo.name() == name)
    }

    pub fn has_proxy(&self) -> bool {
        !self.proxies.is_empty()
            || self
                .repositories
                .iter()
                .any(|repo| matches!(repo, MavenRepository::Proxy { .. }))
    }

    pub fn validate_repositories(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let mut names = HashSet::new();

        for repo in &self.repositories {
            let name = repo.name();
            if name.is_empty()
                || name == "."
                || name.contains("..")
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            {
                errors.push(format!(
                    "maven repository name {name:?} must contain only ASCII letters, digits, '.', '_' or '-'"
                ));
            } else if !names.insert(name.to_string()) {
                errors.push(format!("duplicate maven repository name {name:?}"));
            }

            match repo {
                MavenRepository::Proxy { url, .. } => match reqwest::Url::parse(url) {
                    Ok(parsed) if matches!(parsed.scheme(), "http" | "https") => {}
                    _ => errors.push(format!(
                        "maven proxy repository {name:?} has an invalid HTTP(S) URL"
                    )),
                },
                MavenRepository::Group { members, .. } if members.is_empty() => {
                    errors.push(format!(
                        "maven group repository {name:?} must have at least one member"
                    ));
                }
                _ => {}
            }
        }

        let by_name: HashMap<&str, &MavenRepository> = self
            .repositories
            .iter()
            .map(|repo| (repo.name(), repo))
            .collect();
        for repo in &self.repositories {
            if let MavenRepository::Group { name, members } = repo {
                let mut group_members = HashSet::new();
                for member in members {
                    if !group_members.insert(member) {
                        errors.push(format!(
                            "maven group repository {name:?} contains duplicate member {member:?}"
                        ));
                    }
                    match by_name.get(member.as_str()) {
                        None => errors.push(format!(
                            "maven group repository {name:?} references unknown member {member:?}"
                        )),
                        Some(MavenRepository::Group { .. }) => errors.push(format!(
                            "maven group repository {name:?} cannot contain group member {member:?}"
                        )),
                        Some(_) => {}
                    }
                }
            }
        }

        if let Some(default) = &self.default_repository {
            if !by_name.contains_key(default.as_str()) {
                errors.push(format!(
                    "maven.default_repository references unknown repository {default:?}"
                ));
            }
        } else if !self.repositories.is_empty() {
            errors.push(
                "maven.default_repository is required when named Maven repositories are configured"
                    .to_string(),
            );
        }
        errors
    }

    pub(in crate::config) fn apply_env_overrides(&mut self) -> Result<(), String> {
        if let Ok(val) = env::var("NORA_MAVEN_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_MAVEN_PROXIES") {
            self.proxies = val
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let parts: Vec<&str> = s.trim().splitn(2, '|').collect();
                    if parts.len() > 1 {
                        MavenProxyEntry::Full(MavenProxy {
                            url: parts[0].to_string(),
                            auth: Some(ProtectedString::from(parts[1])),
                        })
                    } else {
                        MavenProxyEntry::Simple(parts[0].to_string())
                    }
                })
                .collect();
        }
        if let Ok(val) = env::var("NORA_MAVEN_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_MAVEN_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_MAVEN_IMMUTABLE_RELEASES") {
            self.immutable_releases = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_MAVEN_METADATA_TTL") {
            super::super::parse_env_warn("NORA_MAVEN_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_MAVEN_REPOSITORIES_JSON") {
            self.repositories = serde_json::from_str(&val)
                .map_err(|error| format!("NORA_MAVEN_REPOSITORIES_JSON is invalid: {error}"))?;
        }
        if let Ok(val) = env::var("NORA_MAVEN_DEFAULT_REPOSITORY") {
            self.default_repository = if val.trim().is_empty() {
                None
            } else {
                Some(val)
            };
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosted(name: &str) -> MavenRepository {
        MavenRepository::Hosted {
            name: name.to_string(),
            version_policy: MavenVersionPolicy::Mixed,
            write_policy: MavenWritePolicy::AllowOnce,
        }
    }

    #[test]
    fn repository_names_reject_path_traversal_but_allow_single_dots() {
        for name in [".", "..", "repo..private"] {
            let config = MavenConfig {
                repositories: vec![hosted(name)],
                default_repository: Some(name.to_string()),
                ..MavenConfig::default()
            };
            assert!(!config.validate_repositories().is_empty(), "{name}");
        }
        let config = MavenConfig {
            repositories: vec![hosted("repo.private")],
            default_repository: Some("repo.private".to_string()),
            ..MavenConfig::default()
        };
        assert!(config.validate_repositories().is_empty());
    }

    #[test]
    fn named_repositories_require_a_default_alias_target() {
        let config = MavenConfig {
            repositories: vec![hosted("releases")],
            default_repository: None,
            ..MavenConfig::default()
        };
        assert!(config
            .validate_repositories()
            .iter()
            .any(|error| error.contains("default_repository is required")));
    }

    #[test]
    fn hosted_write_policy_defaults_to_allow_once_and_accepts_explicit_allow() {
        let default: MavenRepository = serde_json::from_str(
            r#"{"kind":"hosted","name":"releases","version_policy":"release"}"#,
        )
        .unwrap();
        assert!(matches!(
            default,
            MavenRepository::Hosted {
                write_policy: MavenWritePolicy::AllowOnce,
                ..
            }
        ));

        let allow: MavenRepository = serde_json::from_str(
            r#"{"kind":"hosted","name":"releases","version_policy":"release","write_policy":"allow"}"#,
        )
        .unwrap();
        assert!(matches!(
            allow,
            MavenRepository::Hosted {
                write_policy: MavenWritePolicy::Allow,
                ..
            }
        ));
    }
}
