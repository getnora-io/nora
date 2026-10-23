//! Layout translation: source (Artifactory/Nexus) format + artifact → NORA
//! storage key (#599, review R7).
//!
//! The load-bearing rule (contract `import-key-format-equals-handler-key-format`):
//! import MUST write keys in the **same format the format's handler serves**, or
//! GC/retention/UI browse — which walk keys as strings (regression-map semantic
//! row) — will not see the import. For Maven and Raw (Full support) this module
//! calls the handler's own `storage_key` builder directly (the single source of
//! truth); for npm (Partial) it builds the tarball key and pins the exact handler
//! format with a regression test. PyPI and NuGet (Partial) take the key from their
//! handler's builder too: a distribution file under its project, a .nupkg under the
//! flat-container key a client asks for. Unsupported formats are **skipped, not failed**.
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
    /// Some assets map (e.g. npm tarballs); others are regenerated/skipped.
    Partial,
    /// NORA does not host this format via import — all artifacts skipped.
    Unsupported,
}

/// The layout `nora import` writes, recorded in the marker of every repository it finishes.
/// Layout 1 — releases up to 1.4.1, whose markers record none — skipped every PyPI and NuGet
/// file; layout 2 imports them.
pub const LAYOUT: u32 = 2;

/// The first layout that imported the files of a repository of format `rt`. A repository
/// finished under an earlier layout had its files skipped, not imported, and is walked again.
pub fn imported_since(rt: RegistryType) -> u32 {
    match rt {
        RegistryType::PyPI | RegistryType::Nuget => 2,
        RegistryType::Maven | RegistryType::Raw | RegistryType::Npm => 1,
        // Not imported by any layout: a finished repository of one is not walked again.
        RegistryType::Docker
        | RegistryType::Cargo
        | RegistryType::Go
        | RegistryType::Gems
        | RegistryType::Terraform
        | RegistryType::Ansible
        | RegistryType::PubDart
        | RegistryType::Conan
        | RegistryType::Rpm
        | RegistryType::Deb
        | RegistryType::Cpan
        | RegistryType::HuggingFace => 1,
    }
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
        RegistryType::Npm | RegistryType::PyPI | RegistryType::Nuget => Compat::Partial,
        RegistryType::Docker
        | RegistryType::Cargo
        | RegistryType::Go
        | RegistryType::Gems
        | RegistryType::Terraform
        | RegistryType::Ansible
        | RegistryType::PubDart
        | RegistryType::Conan
        | RegistryType::Rpm
        | RegistryType::Deb
        | RegistryType::Cpan
        | RegistryType::HuggingFace => Compat::Unsupported,
    }
}

/// What `assess` tells an operator about a repository of format `rt`.
pub fn note(rt: RegistryType) -> &'static str {
    match rt {
        RegistryType::Maven | RegistryType::Raw => "",
        RegistryType::Npm => "tarballs only; metadata regenerated",
        RegistryType::PyPI => {
            "distribution files only; served as hosted, never asked of an upstream"
        }
        RegistryType::Nuget => ".nupkg only; served as hosted, never asked of an upstream",
        RegistryType::Docker
        | RegistryType::Cargo
        | RegistryType::Go
        | RegistryType::Gems
        | RegistryType::Terraform
        | RegistryType::Ansible
        | RegistryType::PubDart
        | RegistryType::Conan
        | RegistryType::Rpm
        | RegistryType::Deb
        | RegistryType::Cpan
        | RegistryType::HuggingFace => "no NORA import layout — will be skipped",
    }
}

// ── What lies under a key ──────────────────────────────────────────────
//
// What `nora import` does with an artifact from what already lies under the key it built, before
// anything is downloaded. One rule, [`action`], for every format: a format without a decision
// does not compile, and the import looks under a key only through `super::under_key`.

/// What lies under an artifact's key, as far as the import looked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnderKey {
    /// The import did not look: on S3 a look is a request per object (review R5).
    NotLooked,
    /// Nothing.
    Nothing,
    /// An object the import can tell is its own ([`own_by`]): the record its format writes after
    /// it, or a pin to the very bytes the source advertises.
    Recorded,
    /// An object the import cannot tell is its own: what an import stored before its record was
    /// written, what an upstream served under the name, or an object of a format with no such
    /// mark.
    Unrecorded,
}

/// What the import does with an artifact before any transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    /// Transfer the source's artifact: download, verify, curate, and commit it with every record
    /// its format keeps beside it.
    Transfer,
    /// Leave what is there; the journal records the key.
    Skip,
}

/// What the import does with an artifact of format `rt` when `under` lies under its key.
///
/// - Maven: a coordinate is served from storage before any upstream, whoever stored it. An object
///   pinned to the source's bytes is left; any other may be what an upstream served under the
///   coordinate, and the source's artifact is transferred over it.
/// - Raw has no upstream: an object under the key is an upload or an earlier import, NORA's own,
///   and is left.
/// - npm: a tarball whose version document is there is published, and is left. One without it
///   may be what an upstream served under the name, and publishing it would make the upstream's
///   bytes the imported version: the source's tarball is transferred, and its document written.
/// - PyPI and NuGet: what is under the key may be what an upstream served before the import made
///   the name NORA's own, and only a transfer stores the source's verified bytes and writes every
///   record beside them.
/// - The other formats are not imported ([`map_artifact`] skips them first).
pub(super) fn action(rt: RegistryType, under: UnderKey) -> Action {
    use Action::{Skip, Transfer};
    use UnderKey::{NotLooked, Nothing, Recorded, Unrecorded};
    match rt {
        RegistryType::Raw => match under {
            NotLooked | Nothing => Transfer,
            Recorded | Unrecorded => Skip,
        },
        RegistryType::Maven | RegistryType::Npm => match under {
            NotLooked | Nothing | Unrecorded => Transfer,
            Recorded => Skip,
        },
        RegistryType::PyPI | RegistryType::Nuget => Transfer,
        RegistryType::Docker
        | RegistryType::Cargo
        | RegistryType::Go
        | RegistryType::Gems
        | RegistryType::Terraform
        | RegistryType::Ansible
        | RegistryType::PubDart
        | RegistryType::Conan
        | RegistryType::Rpm
        | RegistryType::Deb
        | RegistryType::Cpan
        | RegistryType::HuggingFace => Transfer,
    }
}

/// How the import tells that the object at an artifact's key is NORA's own and not what an
/// upstream served under the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Own {
    /// By a record the format writes after the object: an npm tarball's version document.
    Record(String),
    /// By the object's pin: the import commits an artifact pinned to the SHA-256 the source
    /// advertises, so an object pinned to that digest holds the source's bytes.
    Pin,
    /// It cannot tell.
    Unknown,
}

/// How the import tells that the object at `key` of format `rt` is its own ([`Own`]).
pub(super) fn own_by(rt: RegistryType, key: &str) -> Own {
    match rt {
        RegistryType::Npm => match crate::registry::npm::imported_version_key(key) {
            Some(record) => Own::Record(record),
            None => Own::Unknown,
        },
        RegistryType::Maven => Own::Pin,
        RegistryType::Raw
        | RegistryType::PyPI
        | RegistryType::Nuget
        | RegistryType::Docker
        | RegistryType::Cargo
        | RegistryType::Go
        | RegistryType::Gems
        | RegistryType::Terraform
        | RegistryType::Ansible
        | RegistryType::PubDart
        | RegistryType::Conan
        | RegistryType::Rpm
        | RegistryType::Deb
        | RegistryType::Cpan
        | RegistryType::HuggingFace => Own::Unknown,
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
        // npm: import tarballs only; the transfer writes each tarball's version document
        // from its package.json, and NORA assembles the packument from those.
        RegistryType::Npm => match npm_tarball_key(&art.path) {
            Some(k) => k,
            None => return Mapping::Skip("npm non-tarball asset (NORA assembles the packument)"),
        },
        // PyPI: distribution files only, under the project the file names; the index and the
        // digests are served from them.
        RegistryType::PyPI => match pypi_key(&art.path) {
            Ok(k) => k,
            Err(mapping) => return mapping,
        },
        // NuGet: .nupkg files only; the transfer stores each one's .nuspec and record beside it.
        RegistryType::Nuget => match nuget_key(&art.path) {
            Ok(k) => k,
            Err(mapping) => return mapping,
        },
        RegistryType::Docker
        | RegistryType::Cargo
        | RegistryType::Go
        | RegistryType::Gems
        | RegistryType::Terraform
        | RegistryType::Ansible
        | RegistryType::PubDart
        | RegistryType::Conan
        | RegistryType::Rpm
        | RegistryType::Deb
        | RegistryType::Cpan
        | RegistryType::HuggingFace => return Mapping::Skip("format not hosted by NORA import"),
    };

    match validate_storage_key(&key) {
        Ok(()) => Mapping::Key(key),
        Err(e) => Mapping::Reject(format!("invalid storage key {key:?}: {e}")),
    }
}

/// Build the npm tarball key `npm/<package>/tarballs/<file>` from a source asset
/// path (`<package>/-/<file>.tgz`, scoped `@scope/<pkg>/-/<file>.tgz`). Returns
/// `None` for non-tarball npm assets (package metadata: the transfer writes each
/// version's document from its tarball's package.json).
///
/// MUST match the tarball key the npm handler serves
/// (`registry/npm.rs`: `format!("npm/{}/tarballs/{}", package, file)`); pinned by
/// the `npm_key_matches_handler_format` test.
fn npm_tarball_key(path: &str) -> Option<String> {
    let (package, file) = path.split_once("/-/")?;
    if package.is_empty() || file.is_empty() || file.contains('/') {
        return None;
    }
    Some(format!("npm/{package}/tarballs/{file}"))
}

/// The key of a PyPI distribution file at source path `path`: `pypi/<project>/<file>`, the key
/// an upload of the file writes. A wheel or an egg names its project in its first `-` field; an
/// sdist's name may itself hold a `-`, so its project is the nearest directory of the source
/// path it is a file of (Artifactory `<project>/<version>/`, Nexus `packages/<project>/<version>/`),
/// else the name before its last `-`. Anything but a distribution file is skipped.
fn pypi_key(path: &str) -> Result<String, Mapping> {
    use nora_registry::pypi_files::{parse_pypi_version, pep503_normalize, served_extension};
    let (dirs, file) = path.rsplit_once('/').unwrap_or(("", path));
    let Some(ext) = served_extension(file) else {
        return Err(Mapping::Skip("PyPI asset that is no distribution file"));
    };
    if file.contains("..") {
        return Err(Mapping::Reject(format!(
            "PyPI file name {file:?} is not one NORA serves"
        )));
    }
    let stem = &file[..file.len() - ext.len()];
    let first_field = stem.split('-').next().unwrap_or_default();
    let last_split = stem
        .rsplit_once('-')
        .map(|(name, _)| name)
        .unwrap_or_default();
    let candidates: Vec<&str> = if ext == ".whl" || ext == ".egg" {
        vec![first_field]
    } else {
        dirs.rsplit('/').chain([last_split]).collect()
    };
    candidates
        .into_iter()
        .map(pep503_normalize)
        .find(|project| {
            !project.is_empty()
                && crate::validation::is_one_segment(project)
                && parse_pypi_version(project, file).is_some()
        })
        .map(|project| crate::registry::pypi_storage_key(&project, file))
        .ok_or_else(|| {
            Mapping::Reject(format!(
                "cannot tell the project and version of PyPI file {file:?}"
            ))
        })
}

/// The flat-container key of a .nupkg at source path `path`, from its file name
/// `<id>.<version>.nupkg`. An id may end in a number, so the directory the file is in decides
/// where the id ends when it names it (Artifactory `<id>/<id>.<version>.nupkg`); otherwise the
/// version is the shortest tail of dot-separated fields that is a NuGet version. The transfer
/// checks the package's .nuspec names the same id and version. Anything but a .nupkg is skipped.
fn nuget_key(path: &str) -> Result<String, Mapping> {
    let (dirs, file) = path.rsplit_once('/').unwrap_or(("", path));
    let Some(stem) = file
        .len()
        .checked_sub(".nupkg".len())
        .filter(|&at| file.is_char_boundary(at) && file[at..].eq_ignore_ascii_case(".nupkg"))
        .map(|at| &file[..at])
    else {
        return Err(Mapping::Skip("NuGet asset that is no .nupkg"));
    };
    let dir = dirs.rsplit('/').next().unwrap_or_default();
    let named_by_dir = (!dir.is_empty()
        && stem.len() > dir.len() + 1
        && stem.is_char_boundary(dir.len())
        && stem[..dir.len()].eq_ignore_ascii_case(dir)
        && stem.as_bytes()[dir.len()] == b'.')
        .then(|| (&stem[..dir.len()], &stem[dir.len() + 1..]));
    let key = named_by_dir
        .and_then(|(id, version)| crate::registry::nuget_package_key(id, version))
        .or_else(|| {
            stem.match_indices('.').find_map(|(at, _)| {
                crate::registry::nuget_package_key(&stem[..at], &stem[at + 1..])
            })
        });
    key.ok_or_else(|| {
        Mapping::Reject(format!(
            "cannot tell the id and version of NuGet package {file:?}"
        ))
    })
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

    /// Every format against every state of its key: what the import does. `upstream cache` is
    /// an object without a record, which is how an upstream's copy of the same version lies.
    #[test]
    fn what_the_import_does_with_what_lies_under_the_key() {
        use Action::{Skip, Transfer};
        use RegistryType as R;
        //            not looked (S3)  nothing    recorded   upstream cache / unrecorded
        let table: &[(RegistryType, [Action; 4])] = &[
            (R::Docker, [Transfer, Transfer, Transfer, Transfer]),
            (R::Maven, [Transfer, Transfer, Skip, Transfer]),
            (R::Npm, [Transfer, Transfer, Skip, Transfer]),
            (R::Cargo, [Transfer, Transfer, Transfer, Transfer]),
            (R::PyPI, [Transfer, Transfer, Transfer, Transfer]),
            (R::Go, [Transfer, Transfer, Transfer, Transfer]),
            (R::Raw, [Transfer, Transfer, Skip, Skip]),
            (R::Gems, [Transfer, Transfer, Transfer, Transfer]),
            (R::Terraform, [Transfer, Transfer, Transfer, Transfer]),
            (R::Ansible, [Transfer, Transfer, Transfer, Transfer]),
            (R::Nuget, [Transfer, Transfer, Transfer, Transfer]),
            (R::PubDart, [Transfer, Transfer, Transfer, Transfer]),
            (R::Conan, [Transfer, Transfer, Transfer, Transfer]),
            (R::Rpm, [Transfer, Transfer, Transfer, Transfer]),
            (R::Deb, [Transfer, Transfer, Transfer, Transfer]),
            (R::Cpan, [Transfer, Transfer, Transfer, Transfer]),
            (R::HuggingFace, [Transfer, Transfer, Transfer, Transfer]),
        ];
        let states = [
            UnderKey::NotLooked,
            UnderKey::Nothing,
            UnderKey::Recorded,
            UnderKey::Unrecorded,
        ];
        for (rt, row) in table {
            for (under, want) in states.into_iter().zip(row) {
                assert_eq!(action(*rt, under), *want, "{rt:?} with {under:?}");
            }
        }
        let rows: Vec<RegistryType> = table.iter().map(|(rt, _)| *rt).collect();
        assert_eq!(rows, RegistryType::all(), "a row for every format");
    }

    /// How the import tells its own object: an npm tarball by its version document, a Maven
    /// artifact by its pin; any other format it cannot tell.
    #[test]
    fn the_import_tells_its_own_npm_tarball_by_its_document_and_a_maven_artifact_by_its_pin() {
        assert_eq!(
            own_by(RegistryType::Npm, "npm/@scope/a/tarballs/a-1.0.0.tgz"),
            Own::Record("npm/@scope/a/versions/1.0.0.json".to_owned())
        );
        assert_eq!(own_by(RegistryType::Npm, "npm/a/a-1.0.0.tgz"), Own::Unknown);
        assert_eq!(
            own_by(RegistryType::Maven, "maven/com/a/1.0/a-1.0.jar"),
            Own::Pin
        );
        for rt in RegistryType::all() {
            if !matches!(rt, RegistryType::Npm | RegistryType::Maven) {
                assert_eq!(
                    own_by(*rt, "npm/a/tarballs/a-1.0.0.tgz"),
                    Own::Unknown,
                    "{rt:?}"
                );
            }
        }
    }

    #[test]
    fn compat_classes() {
        assert_eq!(compat(RegistryType::Maven), Compat::Full);
        assert_eq!(compat(RegistryType::Raw), Compat::Full);
        assert_eq!(compat(RegistryType::Npm), Compat::Partial);
        assert_eq!(compat(RegistryType::PyPI), Compat::Partial);
        assert_eq!(compat(RegistryType::Nuget), Compat::Partial);
        assert_eq!(compat(RegistryType::Cargo), Compat::Unsupported);
        assert_eq!(compat(RegistryType::Docker), Compat::Unsupported);
    }

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

    /// Every format: how it maps, the first layout that imported its files, and whether a
    /// source artifact of it is mapped to a key at all.
    #[test]
    fn every_format_has_its_import_decisions() {
        use Compat::{Full, Partial, Unsupported};
        use RegistryType as R;
        let table: &[(RegistryType, Compat, u32, bool)] = &[
            (R::Docker, Unsupported, 1, false),
            (R::Maven, Full, 1, true),
            (R::Npm, Partial, 1, true),
            (R::Cargo, Unsupported, 1, false),
            (R::PyPI, Partial, 2, true),
            (R::Go, Unsupported, 1, false),
            (R::Raw, Full, 1, true),
            (R::Gems, Unsupported, 1, false),
            (R::Terraform, Unsupported, 1, false),
            (R::Ansible, Unsupported, 1, false),
            (R::Nuget, Partial, 2, true),
            (R::PubDart, Unsupported, 1, false),
            (R::Conan, Unsupported, 1, false),
            (R::Rpm, Unsupported, 1, false),
            (R::Deb, Unsupported, 1, false),
            (R::Cpan, Unsupported, 1, false),
            (R::HuggingFace, Unsupported, 1, false),
        ];
        let rows: Vec<RegistryType> = table.iter().map(|row| row.0).collect();
        assert_eq!(rows, RegistryType::all(), "a row for every format");
        for &(rt, want, since, mapped) in table {
            assert_eq!(compat(rt), want, "{rt:?}");
            assert_eq!(imported_since(rt), since, "{rt:?}");
            assert_eq!(note(rt).is_empty(), want == Full, "{rt:?}");
            assert_eq!(
                note(rt) == "no NORA import layout — will be skipped",
                want == Unsupported,
                "{rt:?}"
            );
            // A path every mapped format reads as one of its files.
            let path = match rt {
                R::Npm => "a/-/a-1.0.0.tgz",
                R::PyPI => "a/1.0/a-1.0.tar.gz",
                R::Nuget => "A/A.1.0.0.nupkg",
                _ => "com/a/1.0/a-1.0.jar",
            };
            let art = super::super::ArtifactRef {
                repo: "r".into(),
                path: path.into(),
                name: "x".into(),
                size: None,
                sha256: None,
                sha1: None,
            };
            assert_eq!(
                matches!(map_artifact(rt, &art), Mapping::Key(_)),
                mapped,
                "{rt:?}: {:?}",
                map_artifact(rt, &art)
            );
        }
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
    fn npm_tarball_maps_scoped_and_unscoped() {
        assert_eq!(
            map_artifact(
                RegistryType::Npm,
                &art("npm-local", "left-pad/-/left-pad-1.3.0.tgz")
            ),
            Mapping::Key("npm/left-pad/tarballs/left-pad-1.3.0.tgz".to_string())
        );
        assert_eq!(
            map_artifact(
                RegistryType::Npm,
                &art("npm-local", "@babel/core/-/core-7.0.0.tgz")
            ),
            Mapping::Key("npm/@babel/core/tarballs/core-7.0.0.tgz".to_string())
        );
    }

    #[test]
    fn npm_key_matches_handler_format() {
        // Pins the coupling to registry/npm.rs (which inlines this literal at its
        // serve + upload sites). If the handler format changes, this must too.
        let handler_literal = format!("npm/{}/tarballs/{}", "left-pad", "left-pad-1.3.0.tgz");
        assert_eq!(
            npm_tarball_key("left-pad/-/left-pad-1.3.0.tgz"),
            Some(handler_literal)
        );
    }

    #[test]
    fn npm_non_tarball_is_skipped_not_failed() {
        // Package metadata document (no `/-/`) — NORA regenerates it.
        match map_artifact(RegistryType::Npm, &art("npm-local", "left-pad")) {
            Mapping::Skip(_) => {}
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn pypi_file_maps_to_the_key_an_upload_writes() {
        // A wheel names its project in its first field, wherever the source keeps it.
        assert_eq!(
            map_artifact(
                RegistryType::PyPI,
                &art("pypi-local", "corppkg/1.0.0/CorpPkg-1.0.0-py3-none-any.whl")
            ),
            Mapping::Key("pypi/corppkg/CorpPkg-1.0.0-py3-none-any.whl".to_string())
        );
        // An sdist's project is the directory of the source that names it.
        assert_eq!(
            map_artifact(
                RegistryType::PyPI,
                &art("pypi-hosted", "packages/my.pkg/2.0/my-pkg-2.0.tar.gz")
            ),
            Mapping::Key("pypi/my-pkg/my-pkg-2.0.tar.gz".to_string())
        );
        assert_eq!(
            map_artifact(RegistryType::PyPI, &art("r", "flat-1.0.zip")),
            Mapping::Key("pypi/flat/flat-1.0.zip".to_string())
        );
        // The key is the one the upload handler writes for the same project and file.
        assert_eq!(
            crate::registry::pypi_storage_key("corppkg", "CorpPkg-1.0.0-py3-none-any.whl"),
            "pypi/corppkg/CorpPkg-1.0.0-py3-none-any.whl"
        );
    }

    #[test]
    fn pypi_assets_that_are_no_distribution_are_skipped() {
        for path in [
            "corppkg/1.0.0/corppkg-1.0.0.tar.gz.asc",
            "corppkg/1.0.0/corppkg-1.0.0-py3-none-any.whl.metadata",
            "simple/corppkg/index.html",
        ] {
            assert!(
                matches!(
                    map_artifact(RegistryType::PyPI, &art("r", path)),
                    Mapping::Skip(_)
                ),
                "{path}"
            );
        }
        // A distribution file that names no version is refused, not skipped.
        assert!(matches!(
            map_artifact(RegistryType::PyPI, &art("r", "pkg/pkg.tar.gz")),
            Mapping::Reject(_)
        ));
    }

    #[test]
    fn nupkg_maps_to_the_flat_container_key_a_client_reads() {
        assert_eq!(
            map_artifact(
                RegistryType::Nuget,
                &art("nuget-local", "Corp.Lib/Corp.Lib.1.0.nupkg")
            ),
            Mapping::Key("nuget/flatcontainer/corp.lib/1.0.0/corp.lib.1.0.0.nupkg".to_string())
        );
        assert_eq!(
            map_artifact(
                RegistryType::Nuget,
                &art("nuget-local", "Foo.2D.Bar.01.2.3-RC.1+git.nupkg")
            ),
            Mapping::Key(
                "nuget/flatcontainer/foo.2d.bar/1.2.3-rc.1/foo.2d.bar.1.2.3-rc.1.nupkg".to_string()
            )
        );
        // The directory that names the id decides where an id ends in digits.
        assert_eq!(
            map_artifact(RegistryType::Nuget, &art("r", "Lib.2/Lib.2.1.0.0.nupkg")),
            Mapping::Key("nuget/flatcontainer/lib.2/1.0.0/lib.2.1.0.0.nupkg".to_string())
        );
        for skipped in ["Corp.Lib/Corp.Lib.1.0.0.snupkg", "Corp.Lib/Corp.Lib.nuspec"] {
            assert!(
                matches!(
                    map_artifact(RegistryType::Nuget, &art("r", skipped)),
                    Mapping::Skip(_)
                ),
                "{skipped}"
            );
        }
        assert!(matches!(
            map_artifact(RegistryType::Nuget, &art("r", "NoVersion.nupkg")),
            Mapping::Reject(_)
        ));
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
    fn npm_malformed_tarball_paths() {
        // Slash inside the file component → npm_tarball_key returns None → Skip.
        assert!(matches!(
            map_artifact(RegistryType::Npm, &art("npm", "pkg/-/nested/file.tgz")),
            Mapping::Skip(_)
        ));
        // A trailing empty segment is caught earlier as unsafe → Reject.
        assert!(matches!(
            map_artifact(RegistryType::Npm, &art("npm", "pkg/-/")),
            Mapping::Reject(_)
        ));
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
