// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmConfig {
    #[serde(default = "super::super::default_true")]
    pub enabled: bool,

    // Kept as the compatibility source for the `/npm` alias. New installations
    // should declare named repositories and a default_repository.
    #[serde(default = "default_npm_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
    #[serde(default = "super::super::default_true")]
    pub revalidate: bool,

    #[serde(default)]
    pub repositories: Vec<NpmRepository>,
    #[serde(default)]
    pub default_repository: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum NpmRepository {
    Hosted {
        name: String,
        #[serde(default)]
        write_policy: NpmWritePolicy,
    },
    Proxy {
        name: String,
        url: String,
        #[serde(default, skip_serializing)]
        auth: Option<ProtectedString>,
        #[serde(default)]
        metadata_ttl: Option<i64>,
        #[serde(default = "default_negative_ttl")]
        negative_ttl: i64,
    },
    Group {
        name: String,
        members: Vec<String>,
        writable_member: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmWritePolicy {
    Allow,
    #[default]
    AllowOnce,
    Deny,
}

impl NpmRepository {
    pub fn name(&self) -> &str {
        match self {
            Self::Hosted { name, .. } | Self::Proxy { name, .. } | Self::Group { name, .. } => name,
        }
    }
}

fn default_negative_ttl() -> i64 {
    300
}

/// Default npm upstream. This remains the source for the compatibility `/npm`
/// alias; named proxies carry their own URL.
fn default_npm_proxy() -> Option<String> {
    Some("https://registry.npmjs.org".to_string())
}

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: default_npm_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            metadata_ttl: 300,
            serve_stale: true,
            revalidate: true,
            repositories: Vec::new(),
            default_repository: None,
        }
    }
}

impl NpmConfig {
    pub fn repository(&self, name: &str) -> Option<&NpmRepository> {
        self.repositories.iter().find(|repo| repo.name() == name)
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
                    "npm repository name {name:?} must contain only ASCII letters, digits, '.', '_' or '-'"
                ));
            } else if !names.insert(name.to_string()) {
                errors.push(format!("duplicate npm repository name {name:?}"));
            }

            match repo {
                NpmRepository::Proxy { url, .. } => match reqwest::Url::parse(url) {
                    Ok(parsed) if matches!(parsed.scheme(), "http" | "https") => {}
                    _ => errors.push(format!(
                        "npm proxy repository {name:?} has an invalid HTTP(S) URL"
                    )),
                },
                NpmRepository::Group { members, .. } if members.is_empty() => errors.push(format!(
                    "npm group repository {name:?} must have at least one member"
                )),
                _ => {}
            }
        }

        let by_name: HashMap<&str, &NpmRepository> = self
            .repositories
            .iter()
            .map(|repo| (repo.name(), repo))
            .collect();
        for repo in &self.repositories {
            if let NpmRepository::Group {
                name,
                members,
                writable_member,
            } = repo
            {
                let mut group_members = HashSet::new();
                for member in members {
                    if !group_members.insert(member) {
                        errors.push(format!(
                            "npm group repository {name:?} contains duplicate member {member:?}"
                        ));
                    }
                    match by_name.get(member.as_str()) {
                        None => errors.push(format!(
                            "npm group repository {name:?} references unknown member {member:?}"
                        )),
                        Some(NpmRepository::Group { .. }) => errors.push(format!(
                            "npm group repository {name:?} cannot contain group member {member:?}"
                        )),
                        Some(_) => {}
                    }
                }
                if let Some(writable) = writable_member {
                    if !members.contains(writable) {
                        errors.push(format!(
                            "npm group repository {name:?} writable_member {writable:?} is not a group member"
                        ));
                    } else if !matches!(
                        by_name.get(writable.as_str()),
                        Some(NpmRepository::Hosted { .. })
                    ) {
                        errors.push(format!(
                            "npm group repository {name:?} writable_member {writable:?} must reference a hosted repository"
                        ));
                    }
                }
            }
        }

        if let Some(default) = &self.default_repository {
            if !by_name.contains_key(default.as_str()) {
                errors.push(format!(
                    "npm.default_repository references unknown repository {default:?}"
                ));
            }
        } else if !self.repositories.is_empty() {
            errors.push(
                "npm.default_repository is required when named npm repositories are configured"
                    .to_string(),
            );
        }

        errors
    }

    pub(in crate::config) fn apply_env_overrides(&mut self) -> Result<(), String> {
        if let Ok(val) = env::var("NORA_NPM_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_NPM_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_NPM_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_NPM_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_NPM_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_NPM_METADATA_TTL") {
            super::super::parse_env_warn("NORA_NPM_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_NPM_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_NPM_REVALIDATE") {
            self.revalidate = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_NPM_REPOSITORIES_JSON") {
            self.repositories = serde_json::from_str(&val)
                .map_err(|error| format!("NORA_NPM_REPOSITORIES_JSON is invalid: {error}"))?;
        }
        if let Ok(val) = env::var("NORA_NPM_DEFAULT_REPOSITORY") {
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

    #[test]
    fn named_repository_validation_accepts_hosted_proxy_group() {
        let config = NpmConfig {
            repositories: vec![
                NpmRepository::Hosted {
                    name: "npm-private".into(),
                    write_policy: NpmWritePolicy::AllowOnce,
                },
                NpmRepository::Proxy {
                    name: "npm-registry".into(),
                    url: "https://registry.npmjs.org".into(),
                    auth: None,
                    metadata_ttl: None,
                    negative_ttl: 300,
                },
                NpmRepository::Group {
                    name: "npm-group".into(),
                    members: vec!["npm-private".into(), "npm-registry".into()],
                    writable_member: Some("npm-private".into()),
                },
            ],
            default_repository: Some("npm-group".into()),
            ..NpmConfig::default()
        };
        assert!(config.validate_repositories().is_empty());
    }

    #[test]
    fn hosted_write_policy_defaults_to_allow_once_and_accepts_allow() {
        let default: NpmRepository =
            serde_json::from_str(r#"{"kind":"hosted","name":"private"}"#).unwrap();
        assert!(matches!(
            default,
            NpmRepository::Hosted {
                write_policy: NpmWritePolicy::AllowOnce,
                ..
            }
        ));

        let allow: NpmRepository =
            serde_json::from_str(r#"{"kind":"hosted","name":"private","write_policy":"allow"}"#)
                .unwrap();
        assert!(matches!(
            allow,
            NpmRepository::Hosted {
                write_policy: NpmWritePolicy::Allow,
                ..
            }
        ));
    }

    #[test]
    fn writable_member_must_be_a_hosted_group_member() {
        let config = NpmConfig {
            repositories: vec![
                NpmRepository::Proxy {
                    name: "proxy".into(),
                    url: "https://registry.npmjs.org".into(),
                    auth: None,
                    metadata_ttl: None,
                    negative_ttl: 300,
                },
                NpmRepository::Group {
                    name: "group".into(),
                    members: vec!["proxy".into()],
                    writable_member: Some("proxy".into()),
                },
            ],
            default_repository: Some("group".into()),
            ..NpmConfig::default()
        };
        assert!(config
            .validate_repositories()
            .iter()
            .any(|error| error.contains("must reference a hosted repository")));
    }

    #[test]
    fn repository_names_reject_path_traversal_but_allow_single_dots() {
        for name in [".", "..", "repo..private"] {
            let config = NpmConfig {
                repositories: vec![NpmRepository::Hosted {
                    name: name.to_string(),
                    write_policy: NpmWritePolicy::AllowOnce,
                }],
                default_repository: Some(name.to_string()),
                ..NpmConfig::default()
            };
            assert!(!config.validate_repositories().is_empty(), "{name}");
        }
        let config = NpmConfig {
            repositories: vec![NpmRepository::Hosted {
                name: "repo.private".to_string(),
                write_policy: NpmWritePolicy::AllowOnce,
            }],
            default_repository: Some("repo.private".to_string()),
            ..NpmConfig::default()
        };
        assert!(config.validate_repositories().is_empty());
    }

    #[test]
    fn named_repositories_require_a_default_alias_target() {
        let config = NpmConfig {
            repositories: vec![NpmRepository::Hosted {
                name: "packages".to_string(),
                write_policy: NpmWritePolicy::AllowOnce,
            }],
            default_repository: None,
            ..NpmConfig::default()
        };
        assert!(config
            .validate_repositories()
            .iter()
            .any(|error| error.contains("default_repository is required")));
    }
}
