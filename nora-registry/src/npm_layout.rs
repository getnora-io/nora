// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Parser for the authoritative named npm storage layout.
//!
//! Hosted packages and proxy cache entries deliberately share the
//! `npm/repositories/{repository}/` prefix. The literal package name `proxy`
//! is valid, so consumers must distinguish the two layouts by their complete
//! shape instead of treating every second path segment named `proxy` as cache.

use base64::Engine;
use sha2::Digest;
use std::collections::BTreeMap;

pub(crate) const HOSTED_PACKUMENT_RETIRED_V1: &[u8] = b"retired-v1";
pub(crate) const HOSTED_MAINTENANCE_SCHEMA_V1: u8 = 1;
pub(crate) const HOSTED_IMPORT_SESSION_SCHEMA_V1: u8 = 1;
pub(crate) const HOSTED_PUBLISH_PENDING_SCHEMA_V1: u8 = 1;
const HOSTED_MAINTENANCE_OPERATION_ID_DOMAIN: &[u8] =
    b"nora:npm:hosted-maintenance:operation-id:v1\0";

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostedPackumentPointer {
    pub(crate) generation: String,
    pub(crate) full_sha256: String,
    pub(crate) install_v1_sha256: String,
}

/// Exact package-wide journal for a bulk import. The version roster is
/// extended before any object for that version is written, so finalize can
/// prove completeness without relying on object-store LIST consistency.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostedImportSession {
    pub(crate) schema: u8,
    pub(crate) repository: String,
    pub(crate) package: String,
    pub(crate) packument_sha256: String,
    pub(crate) base: Option<HostedPackumentPointer>,
    pub(crate) versions: BTreeMap<String, String>,
}

/// A normal publish can derive its immutable target from the exact base and
/// retry payload. An import version is instead bound to its package-wide
/// import journal.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum HostedPublishPendingTarget {
    Publish {
        base: Option<HostedPackumentPointer>,
        target: HostedPackumentPointer,
    },
    Import {
        packument_sha256: String,
    },
}

/// Singleton exact-key transaction record. A deployment owns one package
/// mutation lock, so a package has at most one active version publish.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostedPublishPending {
    pub(crate) schema: u8,
    pub(crate) repository: String,
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) manifest_sha256: String,
    pub(crate) blob_sha512: String,
    pub(crate) target: HostedPublishPendingTarget,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum HostedMaintenanceTarget {
    Live { pointer: HostedPackumentPointer },
    Retired,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum HostedMaintenanceAction {
    DistTag {
        tag: String,
        value: Option<String>,
    },
    Deprecations {
        values: BTreeMap<String, Option<String>>,
    },
    Retention {
        snapshot_guard: String,
        removed_versions: BTreeMap<String, String>,
        expected_authority: BTreeMap<String, String>,
    },
}

/// Deterministic operation payload used to derive `operation_id` without a
/// self-reference. Every map in the schema is ordered so serde's struct field
/// order plus canonical map iteration produces stable bytes.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostedMaintenanceOperation {
    pub(crate) schema: u8,
    pub(crate) repository: String,
    pub(crate) package: String,
    pub(crate) base: HostedPackumentPointer,
    pub(crate) target: HostedMaintenanceTarget,
    pub(crate) action: HostedMaintenanceAction,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostedMaintenanceMarker {
    pub(crate) schema: u8,
    pub(crate) repository: String,
    pub(crate) package: String,
    pub(crate) operation_id: String,
    pub(crate) base: HostedPackumentPointer,
    pub(crate) target: HostedMaintenanceTarget,
    pub(crate) action: HostedMaintenanceAction,
}

impl HostedMaintenanceMarker {
    pub(crate) fn operation(&self) -> HostedMaintenanceOperation {
        HostedMaintenanceOperation {
            schema: self.schema,
            repository: self.repository.clone(),
            package: self.package.clone(),
            base: self.base.clone(),
            target: self.target.clone(),
            action: self.action.clone(),
        }
    }
}

pub(crate) fn hosted_maintenance_operation_id(
    operation: &HostedMaintenanceOperation,
) -> Result<String, serde_json::Error> {
    let encoded = serde_json::to_vec(operation)?;
    let mut digest = sha2::Sha256::new();
    digest.update(HOSTED_MAINTENANCE_OPERATION_ID_DOMAIN);
    digest.update(encoded);
    Ok(hex::encode(digest.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NpmObjectKind {
    HostedPackage,
    /// Rebuildable materialized hosted packument. Authoritative hosted state
    /// remains in the package/version/tag/deprecation objects.
    HostedPackumentCache,
    /// Mutable pointer to a complete immutable hosted packument generation.
    HostedPackumentCurrent,
    HostedPackumentRetired,
    /// Single immutable package-wide maintenance lease and recovery record.
    HostedMaintenanceActive,
    /// Immutable full hosted packument read model.
    HostedPackumentFull(String),
    /// Immutable abbreviated (`install-v1`) hosted packument read model.
    HostedPackumentInstallV1(String),
    /// Content-bound marker used while a package is imported in bulk.
    HostedImportPending,
    HostedImportEvidence {
        packument_sha256: String,
        version: String,
        manifest_sha256: String,
    },
    /// Immutable receipt for a completed package import.
    HostedImportReceipt(String),
    HostedVersion(String),
    HostedPublishPending(String),
    HostedPublishPendingIndex,
    HostedPublishComplete(String),
    HostedTarball(String),
    HostedBlob {
        algorithm: String,
        digest: String,
    },
    HostedDistTag(String),
    HostedDeprecation(String),
    ProxyPackument,
    ProxyTarball(String),
    ProxyNegative,
}

#[cfg(test)]
pub(crate) fn hosted_packument_cache_key(repository: &str, package: &str) -> String {
    format!("npm/repositories/{repository}/{package}/packument-cache.json")
}

pub(crate) fn hosted_package_key(repository: &str, package: &str) -> String {
    format!("npm/repositories/{repository}/{package}/pkg.json")
}

pub(crate) fn hosted_packuments_prefix(repository: &str, package: &str) -> String {
    format!("npm/repositories/{repository}/{package}/hosted-packuments/")
}

pub(crate) fn hosted_packument_current_key(repository: &str, package: &str) -> String {
    format!(
        "{}current.json",
        hosted_packuments_prefix(repository, package)
    )
}

pub(crate) fn hosted_maintenance_active_key(repository: &str, package: &str) -> String {
    format!("npm/repositories/{repository}/{package}/maintenance/active-v1.json")
}

pub(crate) fn hosted_packument_retired_key(repository: &str, package: &str) -> String {
    format!(
        "{}retired-v1",
        hosted_packuments_prefix(repository, package)
    )
}

pub(crate) fn hosted_packument_full_key(
    repository: &str,
    package: &str,
    generation: &str,
) -> String {
    format!(
        "{}{generation}/full.json",
        hosted_packuments_prefix(repository, package)
    )
}

pub(crate) fn hosted_packument_install_v1_key(
    repository: &str,
    package: &str,
    generation: &str,
) -> String {
    format!(
        "{}{generation}/install-v1.json",
        hosted_packuments_prefix(repository, package)
    )
}

pub(crate) fn hosted_import_pending_key(repository: &str, package: &str) -> String {
    format!("npm/repositories/{repository}/{package}/import/pending-v1")
}

pub(crate) fn hosted_publish_pending_index_key(repository: &str, package: &str) -> String {
    format!("npm/repositories/{repository}/{package}/publish-pending-index-v1")
}

pub(crate) fn hosted_import_receipt_key(
    repository: &str,
    package: &str,
    generation: &str,
) -> String {
    format!("npm/repositories/{repository}/{package}/import/receipts/{generation}.json")
}

pub(crate) fn hosted_import_evidence_key(
    repository: &str,
    package: &str,
    packument_sha256: &str,
    version: &str,
    manifest_sha256: &str,
) -> String {
    format!(
        "npm/repositories/{repository}/{package}/import/generations/{packument_sha256}/versions/{version}/{manifest_sha256}"
    )
}

pub(crate) fn hosted_blob_key_for_digest(repository: &str, package: &str, digest: &str) -> String {
    format!("npm/repositories/{repository}/{package}/blobs/sha512/{digest}.tgz")
}

pub(crate) fn hosted_blob_digest_from_manifest(manifest: &[u8]) -> Option<String> {
    let manifest = serde_json::from_slice::<serde_json::Value>(manifest).ok()?;
    let integrity = manifest.get("dist")?.get("integrity")?.as_str()?;
    integrity
        .split_ascii_whitespace()
        .filter_map(|candidate| candidate.strip_prefix("sha512-"))
        .find_map(|encoded| {
            let digest = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()?;
            (digest.len() == 64).then(|| hex::encode(digest))
        })
}

pub(crate) fn hosted_blob_key_from_manifest(
    repository: &str,
    package: &str,
    manifest: &[u8],
) -> Option<String> {
    hosted_blob_digest_from_manifest(manifest)
        .map(|digest| hosted_blob_key_for_digest(repository, package, &digest))
}

pub(crate) fn hosted_manifest_digest(manifest: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(manifest))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NpmObjectPath {
    pub repository: String,
    pub package: String,
    pub kind: NpmObjectKind,
}

/// Parse one object below `npm/repositories/`.
///
/// The proxy namespace is recognized only for a complete cache-object shape.
/// In particular, `.../{repo}/proxy/tarballs/proxy-1.0.0.tgz` is the hosted
/// package named `proxy`, while
/// `.../{repo}/proxy/tarballs/proxy/proxy-1.0.0.tgz` is a proxy-cache tarball.
pub(crate) fn parse_npm_object_key(key: &str) -> Option<NpmObjectPath> {
    let rest = key.strip_prefix("npm/repositories/")?;
    let parts: Vec<&str> = rest.split('/').collect();
    let repository = parts.first().copied().filter(|part| !part.is_empty())?;
    let tail = parts.get(1..)?;

    if tail.first() == Some(&"proxy") {
        match tail.get(1).copied() {
            Some("packuments") if tail.len() >= 3 => {
                let package = tail[2..].join("/");
                let package = package.strip_suffix(".json")?;
                if package.is_empty() {
                    return None;
                }
                return Some(NpmObjectPath {
                    repository: repository.to_string(),
                    package: package.to_string(),
                    kind: NpmObjectKind::ProxyPackument,
                });
            }
            Some("negative") if tail.len() >= 3 => {
                let package = tail[2..].join("/");
                if package.is_empty() {
                    return None;
                }
                return Some(NpmObjectPath {
                    repository: repository.to_string(),
                    package,
                    kind: NpmObjectKind::ProxyNegative,
                });
            }
            // A cached tarball always has both a package path and a filename
            // after `proxy/tarballs`. With only a filename this is the hosted
            // package whose literal name is `proxy`.
            Some("tarballs") if tail.len() >= 4 => {
                let package = tail[2..tail.len() - 1].join("/");
                let filename = tail.last()?.to_string();
                if package.is_empty() || filename.is_empty() {
                    return None;
                }
                return Some(NpmObjectPath {
                    repository: repository.to_string(),
                    package,
                    kind: NpmObjectKind::ProxyTarball(filename),
                });
            }
            _ => {}
        }
    }

    if tail.len() >= 2 && tail.last() == Some(&"pkg.json") {
        let package = tail[..tail.len() - 1].join("/");
        if package.is_empty() {
            return None;
        }
        return Some(NpmObjectPath {
            repository: repository.to_string(),
            package,
            kind: NpmObjectKind::HostedPackage,
        });
    }

    if tail.len() >= 2 && tail.last() == Some(&"packument-cache.json") {
        let package = tail[..tail.len() - 1].join("/");
        if package.is_empty() {
            return None;
        }
        return Some(NpmObjectPath {
            repository: repository.to_string(),
            package,
            kind: NpmObjectKind::HostedPackumentCache,
        });
    }

    if tail.len() >= 2 && tail.last() == Some(&"publish-pending-index-v1") {
        let package = tail[..tail.len() - 1].join("/");
        if package.is_empty() {
            return None;
        }
        return Some(NpmObjectPath {
            repository: repository.to_string(),
            package,
            kind: NpmObjectKind::HostedPublishPendingIndex,
        });
    }

    if tail.len() >= 3
        && tail[tail.len() - 2] == "hosted-packuments"
        && tail.last() == Some(&"current.json")
    {
        let package = tail[..tail.len() - 2].join("/");
        if package.is_empty() {
            return None;
        }
        return Some(NpmObjectPath {
            repository: repository.to_string(),
            package,
            kind: NpmObjectKind::HostedPackumentCurrent,
        });
    }

    if tail.len() >= 3
        && tail[tail.len() - 2] == "maintenance"
        && tail.last() == Some(&"active-v1.json")
    {
        let package = tail[..tail.len() - 2].join("/");
        if package.is_empty() {
            return None;
        }
        return Some(NpmObjectPath {
            repository: repository.to_string(),
            package,
            kind: NpmObjectKind::HostedMaintenanceActive,
        });
    }

    if tail.len() >= 3
        && tail[tail.len() - 2] == "hosted-packuments"
        && tail.last() == Some(&"retired-v1")
    {
        let package = tail[..tail.len() - 2].join("/");
        if package.is_empty() {
            return None;
        }
        return Some(NpmObjectPath {
            repository: repository.to_string(),
            package,
            kind: NpmObjectKind::HostedPackumentRetired,
        });
    }

    if let Some(marker) = tail.iter().rposition(|part| *part == "hosted-packuments") {
        if marker > 0 && marker + 3 == tail.len() {
            let package = tail[..marker].join("/");
            let generation = tail[marker + 1];
            let kind = match tail[marker + 2] {
                "full.json" => NpmObjectKind::HostedPackumentFull(generation.to_string()),
                "install-v1.json" => {
                    NpmObjectKind::HostedPackumentInstallV1(generation.to_string())
                }
                _ => return None,
            };
            if package.is_empty()
                || generation.len() != 64
                || !generation
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return None;
            }
            return Some(NpmObjectPath {
                repository: repository.to_string(),
                package,
                kind,
            });
        }
    }

    if tail.len() >= 3 && tail[tail.len() - 2] == "import" && tail.last() == Some(&"pending-v1") {
        let package = tail[..tail.len() - 2].join("/");
        if package.is_empty() {
            return None;
        }
        return Some(NpmObjectPath {
            repository: repository.to_string(),
            package,
            kind: NpmObjectKind::HostedImportPending,
        });
    }

    if let Some(marker) = tail.iter().rposition(|part| *part == "import") {
        if marker > 0
            && marker + 6 == tail.len()
            && tail[marker + 1] == "generations"
            && tail[marker + 3] == "versions"
        {
            let package = tail[..marker].join("/");
            let packument_sha256 = tail[marker + 2];
            let version = tail[marker + 4];
            let manifest_sha256 = tail[marker + 5];
            if package.is_empty()
                || version.is_empty()
                || version.contains('/')
                || ![packument_sha256, manifest_sha256].iter().all(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                })
            {
                return None;
            }
            return Some(NpmObjectPath {
                repository: repository.to_string(),
                package,
                kind: NpmObjectKind::HostedImportEvidence {
                    packument_sha256: packument_sha256.to_string(),
                    version: version.to_string(),
                    manifest_sha256: manifest_sha256.to_string(),
                },
            });
        }
        if marker > 0 && marker + 3 == tail.len() && tail[marker + 1] == "receipts" {
            let package = tail[..marker].join("/");
            let generation = tail[marker + 2].strip_suffix(".json")?;
            if package.is_empty()
                || generation.len() != 64
                || !generation
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return None;
            }
            return Some(NpmObjectPath {
                repository: repository.to_string(),
                package,
                kind: NpmObjectKind::HostedImportReceipt(generation.to_string()),
            });
        }
    }

    if let Some(marker) = tail.iter().rposition(|part| *part == "blobs") {
        if marker > 0
            && marker + 3 == tail.len()
            && tail[marker + 1] == "sha512"
            && tail[marker + 2].ends_with(".tgz")
        {
            let package = tail[..marker].join("/");
            let digest = tail[marker + 2].strip_suffix(".tgz")?;
            if !package.is_empty()
                && digest.len() == 128
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Some(NpmObjectPath {
                    repository: repository.to_string(),
                    package,
                    kind: NpmObjectKind::HostedBlob {
                        algorithm: "sha512".to_string(),
                        digest: digest.to_ascii_lowercase(),
                    },
                });
            }
        }
    }

    let marker = tail.iter().rposition(|part| {
        matches!(
            *part,
            "versions"
                | "publish-pending"
                | "publish-complete"
                | "tarballs"
                | "dist-tags"
                | "deprecations"
        )
    })?;
    if marker == 0 || marker + 2 != tail.len() {
        return None;
    }
    let package = tail[..marker].join("/");
    let object = tail[marker + 1];
    if package.is_empty() || object.is_empty() {
        return None;
    }
    let kind = match tail[marker] {
        "versions" => NpmObjectKind::HostedVersion(object.strip_suffix(".json")?.to_string()),
        "publish-pending" => NpmObjectKind::HostedPublishPending(object.to_string()),
        "publish-complete" => NpmObjectKind::HostedPublishComplete(object.to_string()),
        "tarballs" => NpmObjectKind::HostedTarball(object.to_string()),
        "dist-tags" => NpmObjectKind::HostedDistTag(object.to_string()),
        "deprecations" => NpmObjectKind::HostedDeprecation(object.to_string()),
        _ => return None,
    };
    Some(NpmObjectPath {
        repository: repository.to_string(),
        package,
        kind,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_hosted_package_named_proxy_from_proxy_cache() {
        let hosted =
            parse_npm_object_key("npm/repositories/npm-private/proxy/tarballs/proxy-1.0.0.tgz")
                .expect("hosted tarball");
        assert_eq!(hosted.repository, "npm-private");
        assert_eq!(hosted.package, "proxy");
        assert_eq!(
            hosted.kind,
            NpmObjectKind::HostedTarball("proxy-1.0.0.tgz".to_string())
        );

        let cached = parse_npm_object_key(
            "npm/repositories/npm-registry/proxy/tarballs/proxy/proxy-1.0.0.tgz",
        )
        .expect("proxy tarball");
        assert_eq!(cached.repository, "npm-registry");
        assert_eq!(cached.package, "proxy");
        assert_eq!(
            cached.kind,
            NpmObjectKind::ProxyTarball("proxy-1.0.0.tgz".to_string())
        );
    }

    #[test]
    fn parses_hosted_proxy_version_and_scoped_proxy_cache() {
        let version =
            parse_npm_object_key("npm/repositories/npm-private/proxy/versions/1.0.0.json")
                .expect("hosted version");
        assert_eq!(version.package, "proxy");
        assert_eq!(
            version.kind,
            NpmObjectKind::HostedVersion("1.0.0".to_string())
        );

        let cached = parse_npm_object_key(
            "npm/repositories/npm-registry/proxy/tarballs/@scope/pkg/pkg-1.0.0.tgz",
        )
        .expect("scoped cache tarball");
        assert_eq!(cached.package, "@scope/pkg");
        assert!(matches!(cached.kind, NpmObjectKind::ProxyTarball(_)));

        let marker =
            parse_npm_object_key("npm/repositories/npm-private/@scope/pkg/publish-complete/1.0.0")
                .expect("publish completion marker");
        assert_eq!(marker.package, "@scope/pkg");
        assert_eq!(
            marker.kind,
            NpmObjectKind::HostedPublishComplete("1.0.0".to_string())
        );

        let packument_cache =
            parse_npm_object_key("npm/repositories/npm-private/@scope/pkg/packument-cache.json")
                .expect("hosted packument cache");
        assert_eq!(packument_cache.package, "@scope/pkg");
        assert_eq!(packument_cache.kind, NpmObjectKind::HostedPackumentCache);

        let digest = "a".repeat(128);
        let blob = parse_npm_object_key(&format!(
            "npm/repositories/npm-private/@scope/pkg/blobs/sha512/{digest}.tgz"
        ))
        .expect("hosted content-addressed blob");
        assert_eq!(blob.package, "@scope/pkg");
        assert_eq!(
            blob.kind,
            NpmObjectKind::HostedBlob {
                algorithm: "sha512".to_string(),
                digest,
            }
        );
    }

    #[test]
    fn hosted_packument_layout_never_collides_with_package_named_proxy() {
        let digest = "a".repeat(64);
        let cases = [
            (
                hosted_packument_current_key("npm-private", "proxy"),
                NpmObjectKind::HostedPackumentCurrent,
            ),
            (
                hosted_packument_retired_key("npm-private", "proxy"),
                NpmObjectKind::HostedPackumentRetired,
            ),
            (
                hosted_packument_full_key("npm-private", "proxy", &digest),
                NpmObjectKind::HostedPackumentFull(digest.clone()),
            ),
            (
                hosted_packument_install_v1_key("npm-private", "proxy", &digest),
                NpmObjectKind::HostedPackumentInstallV1(digest.clone()),
            ),
            (
                hosted_maintenance_active_key("npm-private", "proxy"),
                NpmObjectKind::HostedMaintenanceActive,
            ),
        ];
        for (key, kind) in cases {
            let parsed = parse_npm_object_key(&key).expect("hosted read-model key");
            assert_eq!(parsed.repository, "npm-private");
            assert_eq!(parsed.package, "proxy");
            assert_eq!(parsed.kind, kind);
        }

        let cached =
            parse_npm_object_key("npm/repositories/npm-private/proxy/packuments/current.json")
                .expect("proxy cache packument");
        assert_eq!(cached.package, "current");
        assert_eq!(cached.kind, NpmObjectKind::ProxyPackument);
    }

    #[test]
    fn maintenance_operation_id_is_deterministic_and_content_bound() {
        let pointer = HostedPackumentPointer {
            generation: "a".repeat(64),
            full_sha256: "a".repeat(64),
            install_v1_sha256: "b".repeat(64),
        };
        let operation = HostedMaintenanceOperation {
            schema: HOSTED_MAINTENANCE_SCHEMA_V1,
            repository: "npm-private".to_string(),
            package: "@scope/pkg".to_string(),
            base: pointer.clone(),
            target: HostedMaintenanceTarget::Live {
                pointer: pointer.clone(),
            },
            action: HostedMaintenanceAction::DistTag {
                tag: "next".to_string(),
                value: Some("1.0.0".to_string()),
            },
        };
        let first = hosted_maintenance_operation_id(&operation).unwrap();
        let second = hosted_maintenance_operation_id(&operation).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);

        let mut changed = operation;
        changed.action = HostedMaintenanceAction::DistTag {
            tag: "next".to_string(),
            value: None,
        };
        assert_ne!(first, hosted_maintenance_operation_id(&changed).unwrap());
    }

    #[test]
    fn derives_hosted_blob_and_completion_digests_from_manifest() {
        let digest = [7u8; 64];
        let integrity = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
        let manifest = serde_json::to_vec(&serde_json::json!({
            "dist": {"integrity": integrity}
        }))
        .unwrap();
        let digest_hex = hex::encode(digest);
        assert_eq!(
            hosted_blob_digest_from_manifest(&manifest).as_deref(),
            Some(digest_hex.as_str())
        );
        assert_eq!(
            hosted_blob_key_from_manifest("repo", "@scope/pkg", &manifest).as_deref(),
            Some(
                format!("npm/repositories/repo/@scope/pkg/blobs/sha512/{digest_hex}.tgz").as_str()
            )
        );
        assert_eq!(hosted_manifest_digest(&manifest).len(), 64);
    }
}
