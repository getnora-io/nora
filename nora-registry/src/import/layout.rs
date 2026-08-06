//! Layout translation: source (Artifactory/Nexus) format + artifact → NORA
//! storage key (#599, review R7).
//!
//! The load-bearing rule (contract `import-key-format-equals-handler-key-format`):
//! import MUST write keys in the **same format the format's handler serves**, or
//! GC/retention/UI browse — which walk keys as strings (regression-map semantic
//! row) — will not see the import. For Maven and Raw (Full support) this module
//! calls the handler's own `storage_key` builder directly (the single source of
//! truth). The named npm registry cannot be imported as isolated tarballs:
//! its immutable version manifest is the visibility/commit point and its tags
//! and deprecations must be restored through the npm protocol. npm is therefore
//! intentionally unsupported here; the Nexus migration workflow publishes to
//! the named hosted repository and verifies through the group. Unsupported
//! formats are **skipped, not failed**.
//!
//! Every source string is tainted: a `repo`/`path` of `../../etc` must never
//! become a raw path. Traversal/empty segments are rejected pre-key-build
//! (defence-in-depth) and every emitted key additionally passes
//! `validate_storage_key`.

use super::ArtifactRef;
use crate::registry_type::RegistryType;
use crate::validation::validate_storage_key;

/// How well a source repo's format maps onto NORA hosted storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Compat {
    /// Every artifact maps 1:1 to a hosted key (Maven, Raw).
    Full,
    /// NORA does not host this format via import — all artifacts skipped.
    Unsupported,
}

/// Normalize a source-reported format string (Artifactory `maven`, Nexus
/// `maven2`/`raw`/`yum`, ...) to a NORA [`RegistryType`], reusing NORA's shared
/// alias table (`registry_type::from_str_opt`). `None` = NORA hosts no such
/// registry.
pub fn normalize_format(src_format: &str) -> Option<RegistryType> {
    RegistryType::from_str_opt(src_format)
}

/// Compatibility class for a normalized format — drives the `assess` table and
/// whether `run` attempts a key.
pub fn compat(rt: RegistryType) -> Compat {
    match rt {
        RegistryType::Maven | RegistryType::Raw => Compat::Full,
        _ => Compat::Unsupported,
    }
}

/// Outcome of mapping one source artifact to a NORA storage key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mapping {
    /// Import under this key (already passed `validate_storage_key`).
    Key(String),
    /// Recognized but intentionally not imported (cache-only metadata NORA
    /// regenerates, or a format NORA does not host) → count `skipped`.
    Skip(&'static str),
    /// Source-controlled path is unsafe/invalid (traversal, absolute, empty
    /// segment, bad key) → count `failed`; fail-closed, never emit a raw path.
    Reject(String),
}

/// Map `(format, artifact)` to a NORA key, reusing each handler's own key
/// builder so the import is byte-identical to what the handler serves.
pub fn map_artifact(rt: RegistryType, art: &ArtifactRef) -> Mapping {
    // Defence-in-depth: reject traversal/empty segments in the tainted source
    // strings BEFORE building a key. `validate_storage_key` allows `//` (empty
    // segments) and only catches `..`; we are stricter here so a crafted source
    // path cannot slip an empty/`.` segment into a control key.
    for (label, s) in [("repo", art.repo.as_str()), ("path", art.path.as_str())] {
        if let Some(bad) = first_unsafe_segment(s) {
            return Mapping::Reject(format!("unsafe {label} segment {bad:?} in {s:?}"));
        }
    }

    let key = match rt {
        // Maven coordinates are a global namespace in NORA (the source repo name
        // is dropped — a Maven client fetches `maven/<group>/<artifact>/...`).
        RegistryType::Maven => crate::registry::maven_storage_key(&art.path),
        // Raw has no global coordinate scheme, so fold the source repo into the
        // path to avoid cross-repo collisions; still a valid `raw/<...>` key the
        // Raw handler serves for request path `<repo>/<path>`.
        RegistryType::Raw => crate::registry::raw_storage_key(&join_repo(&art.repo, &art.path)),
        // A named npm tarball without its immutable version manifest is
        // deliberately invisible and will be collected as a pre-commit orphan.
        // Import npm through the protocol-aware Nexus migrator instead.
        RegistryType::Npm => {
            return Mapping::Skip("npm requires protocol migration into a named hosted repository")
        }
        _ => return Mapping::Skip("format not hosted by NORA import"),
    };

    match validate_storage_key(&key) {
        Ok(()) => Mapping::Key(key),
        Err(e) => Mapping::Reject(format!("invalid storage key {key:?}: {e}")),
    }
}

/// Join a source repo name and a repo-relative path into one relative path,
/// trimming stray separators (both are pre-validated by [`first_unsafe_segment`]).
fn join_repo(repo: &str, path: &str) -> String {
    let repo = repo.trim_matches('/');
    let path = path.trim_start_matches('/');
    if repo.is_empty() {
        path.to_string()
    } else {
        format!("{repo}/{path}")
    }
}

/// First segment of `path` that must never reach key construction from a tainted
/// source string (empty, `.`, `..`, backslash, or NUL). `None` = safe.
fn first_unsafe_segment(path: &str) -> Option<&str> {
    if path.is_empty() {
        return Some("");
    }
    path.split('/').find(|seg| {
        seg.is_empty() || *seg == "." || *seg == ".." || seg.contains('\\') || seg.contains('\0')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(repo: &str, path: &str) -> ArtifactRef {
        ArtifactRef {
            repo: repo.to_string(),
            path: path.to_string(),
            name: path.rsplit('/').next().unwrap_or(path).to_string(),
            size: None,
            sha256: None,
            sha1: None,
        }
    }

    #[test]
    fn normalize_covers_source_aliases() {
        assert_eq!(normalize_format("maven"), Some(RegistryType::Maven));
        assert_eq!(normalize_format("maven2"), Some(RegistryType::Maven)); // Nexus
        assert_eq!(normalize_format("raw"), Some(RegistryType::Raw));
        assert_eq!(normalize_format("npm"), Some(RegistryType::Npm));
        assert_eq!(normalize_format("yum"), Some(RegistryType::Rpm));
        assert_eq!(normalize_format("docker"), Some(RegistryType::Docker));
        assert_eq!(normalize_format("nonsense"), None);
    }

    #[test]
    fn compat_classes() {
        assert_eq!(compat(RegistryType::Maven), Compat::Full);
        assert_eq!(compat(RegistryType::Raw), Compat::Full);
        assert_eq!(compat(RegistryType::Npm), Compat::Unsupported);
        assert_eq!(compat(RegistryType::Cargo), Compat::Unsupported);
        assert_eq!(compat(RegistryType::Docker), Compat::Unsupported);
    }

    #[test]
    fn maven_key_matches_handler_and_drops_repo() {
        let a = art("libs-release-local", "com/example/foo/1.0/foo-1.0.jar");
        // Reuses the handler's builder; repo dropped (global Maven namespace).
        assert_eq!(
            map_artifact(RegistryType::Maven, &a),
            Mapping::Key("maven/com/example/foo/1.0/foo-1.0.jar".to_string())
        );
    }

    #[test]
    fn raw_key_matches_handler_and_folds_repo() {
        let a = art("configs", "app/prod/settings.yaml");
        assert_eq!(
            map_artifact(RegistryType::Raw, &a),
            Mapping::Key("raw/configs/app/prod/settings.yaml".to_string())
        );
    }

    #[test]
    fn npm_is_skipped_until_protocol_state_can_be_committed() {
        for path in [
            "left-pad/-/left-pad-1.3.0.tgz",
            "@babel/core/-/core-7.0.0.tgz",
            "left-pad",
        ] {
            match map_artifact(RegistryType::Npm, &art("npm-local", path)) {
                Mapping::Skip(reason) => assert!(reason.contains("protocol migration")),
                other => panic!("expected Skip, got {other:?}"),
            }
        }
    }

    #[test]
    fn npm_malformed_tarball_is_still_skipped_without_emitting_a_key() {
        for path in ["pkg/-/nested/file.tgz", "pkg/-/file.tgz"] {
            match map_artifact(RegistryType::Npm, &art("npm", path)) {
                Mapping::Skip(_) => {}
                other => panic!("expected Skip, got {other:?}"),
            }
        }
    }

    #[test]
    fn unsupported_format_is_skipped() {
        match map_artifact(
            RegistryType::Cargo,
            &art("crates", "some/crate-1.0.0.crate"),
        ) {
            Mapping::Skip(_) => {}
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn traversal_in_path_is_rejected() {
        for bad in [
            "../../etc/passwd",
            "a/../../b",
            "/abs/path",
            "a//b",
            "a/./b",
        ] {
            match map_artifact(RegistryType::Maven, &art("r", bad)) {
                Mapping::Reject(_) => {}
                other => panic!("expected Reject for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn traversal_in_repo_is_rejected() {
        match map_artifact(RegistryType::Raw, &art("../../etc", "file")) {
            Mapping::Reject(_) => {}
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn empty_path_is_rejected() {
        assert!(matches!(
            map_artifact(RegistryType::Maven, &art("r", "")),
            Mapping::Reject(_)
        ));
    }

    use proptest::prelude::*;

    proptest! {
        // Any path built from safe segments maps to a key that passes the real
        // storage validator — the import can never emit an invalid Maven key.
        #[test]
        fn maven_keys_always_validate(
            segs in prop::collection::vec("[a-zA-Z0-9._-]{1,12}", 1..6)
        ) {
            let path = segs.join("/");
            let a = art("repo", &path);
            match map_artifact(RegistryType::Maven, &a) {
                Mapping::Key(k) => {
                    prop_assert!(validate_storage_key(&k).is_ok());
                    prop_assert!(k.starts_with("maven/"));
                }
                // A segment could still be a lone "." — that's a legal Reject.
                Mapping::Reject(_) => {}
                Mapping::Skip(s) => prop_assert!(false, "unexpected skip: {s}"),
            }
        }
    }
}
