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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NpmObjectKind {
    HostedPackage,
    HostedVersion(String),
    HostedPublishComplete(String),
    HostedTarball(String),
    HostedBlob { algorithm: String, digest: String },
    HostedDistTag(String),
    HostedDeprecation(String),
    ProxyPackument,
    ProxyTarball(String),
    ProxyNegative,
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
            "versions" | "publish-complete" | "tarballs" | "dist-tags" | "deprecations"
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
