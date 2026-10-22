// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! npm tarball file names: the version a tarball of a package names. Defined once here, for the
//! server (curation, retention, the npm handler) and for the fuzz targets alike.

/// Parse version from an npm tarball filename.
///
/// For scoped packages `@scope/name`, the tarball is `name-VERSION.tgz` on npmjs and
/// `@scope/name-VERSION.tgz` on GitLab's npm registry; both are accepted.
/// For regular packages `name`, the tarball is `name-VERSION.tgz`.
/// Font Awesome's registry puts the file under a version directory,
/// `VERSION/name-VERSION.tgz`; it is accepted when the directory names the version
/// the file does.
///
/// `None` makes the allowlist treat the request as metadata and let it through, so a
/// form this parser misses is a curation bypass, not a cosmetic miss.
pub fn parse_npm_tarball_version(package_name: &str, filename: &str) -> Option<String> {
    if let Some(version) = parse_npm_tarball_file(package_name, filename) {
        return Some(version);
    }
    let (dir, file) = filename.split_once('/')?;
    parse_npm_tarball_file(package_name, file).filter(|version| version == dir)
}

fn parse_npm_tarball_file(package_name: &str, filename: &str) -> Option<String> {
    let filename = filename.strip_suffix(".tgz")?;
    // For scoped packages like @scope/name, the npmjs tarball uses just the "name" part
    let name_part = if package_name.contains('/') {
        package_name.rsplit('/').next()?
    } else {
        package_name
    };
    let version = filename
        .strip_prefix(package_name)
        .or_else(|| filename.strip_prefix(name_part))?
        .strip_prefix('-')?;
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
}
