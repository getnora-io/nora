// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! `nora mirror deb` — warm a pull-through DEB repo for offline use.
//!
//! Enumerates the upstream package list THROUGH the NORA proxy (Release →
//! Packages → `Filename:` fields), so the metadata lands in the cache too,
//! then fetches every package path. After a full run, `apt` clients work with
//! the upstream unreachable.

use super::{decompress_index, fetch_repo_file, warm_repo_paths, MirrorResult};
use std::collections::BTreeSet;

#[allow(clippy::too_many_arguments)]
pub async fn run_deb_mirror(
    client: &reqwest::Client,
    registry: &str,
    repo: &str,
    dist: Option<&str>,
    components: Option<&[String]>,
    arches: Option<&[String]>,
    concurrency: usize,
) -> Result<MirrorResult, String> {
    let base = registry.trim_end_matches('/');

    // Package paths in Packages files are repo-root-relative for both layouts
    // (structured: pool/…; flat: ./…). The index files themselves are warmed
    // as a side effect of enumerating through the proxy.
    let mut paths: BTreeSet<String> = BTreeSet::new();

    if let Some(dist) = dist {
        let release_path = format!("dists/{dist}/Release");
        let release_raw = fetch_repo_file(client, base, "deb", repo, &release_path).await?;
        let release = String::from_utf8(release_raw).map_err(|e| format!("{release_path}: {e}"))?;
        // Warm the signed variants apt actually fetches first — best-effort,
        // an unsigned upstream has neither.
        for extra in [
            format!("dists/{dist}/InRelease"),
            format!("dists/{dist}/Release.gpg"),
        ] {
            let _ = fetch_repo_file(client, base, "deb", repo, &extra).await;
        }

        let all_components = release_list(&release, "Components:");
        let all_arches = release_list(&release, "Architectures:");
        let components = filter_or_all(components, all_components, "component")?;
        let arches = filter_or_all(arches, all_arches, "arch")?;

        for comp in &components {
            for arch in &arches {
                let dir = format!("dists/{dist}/{comp}/binary-{arch}");
                let packages = fetch_packages_index(client, base, repo, &dir).await?;
                paths.extend(package_filenames(&packages));
            }
        }
    } else {
        let packages = fetch_packages_index(client, base, repo, "").await?;
        let _ = fetch_repo_file(client, base, "deb", repo, "Release").await;
        paths.extend(package_filenames(&packages));
    }

    if paths.is_empty() {
        return Err("no packages found in Packages index (wrong repo/dist/filter?)".to_string());
    }

    let paths: Vec<String> = paths.into_iter().collect();
    println!(
        "Mirroring {} deb packages from repo '{repo}' via {registry}...",
        paths.len()
    );
    Ok(warm_repo_paths(client, base, "deb", repo, &paths, concurrency).await)
}

/// Fetch `{dir}/Packages.gz` falling back to `.xz` then plain `Packages`,
/// returning the decompressed text.
async fn fetch_packages_index(
    client: &reqwest::Client,
    base: &str,
    repo: &str,
    dir: &str,
) -> Result<String, String> {
    let prefix = if dir.is_empty() {
        String::new()
    } else {
        format!("{dir}/")
    };
    let mut last_err = String::new();
    for name in ["Packages.gz", "Packages.xz", "Packages"] {
        let path = format!("{prefix}{name}");
        match fetch_repo_file(client, base, "deb", repo, &path).await {
            Ok(raw) => return decompress_index(&path, raw),
            Err(e) => last_err = e,
        }
    }
    Err(format!("no Packages index under '{prefix}': {last_err}"))
}

/// `Filename:` fields of every paragraph, `./`-stripped (flat-repo form).
fn package_filenames(packages: &str) -> Vec<String> {
    packages
        .lines()
        .filter_map(|l| l.strip_prefix("Filename:"))
        .map(|v| v.trim().trim_start_matches("./").to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

/// Space-separated value list of a `Key:` line in a Release file.
fn release_list(release: &str, key: &str) -> Vec<String> {
    release
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .map(|v| v.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Intersect a user filter with what the Release file advertises; no filter
/// means everything advertised. Erroring on an empty result beats silently
/// mirroring nothing.
fn filter_or_all(
    requested: Option<&[String]>,
    available: Vec<String>,
    what: &str,
) -> Result<Vec<String>, String> {
    let result = match requested {
        None => available,
        Some(req) => req
            .iter()
            .filter(|r| available.is_empty() || available.contains(r))
            .cloned()
            .collect(),
    };
    if result.is_empty() {
        Err(format!(
            "no matching {what} (Release file advertises none of the requested values)"
        ))
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_filenames() {
        let packages = "Package: a\nFilename: pool/main/a/a_1.0_amd64.deb\nSize: 1\n\nPackage: b\nFilename: ./b_2.0_all.deb\n";
        assert_eq!(
            package_filenames(packages),
            vec!["pool/main/a/a_1.0_amd64.deb", "b_2.0_all.deb"]
        );
    }

    #[test]
    fn parses_release_lists() {
        let release =
            "Origin: Debian\nComponents: main contrib non-free\nArchitectures: amd64 arm64 all\n";
        assert_eq!(
            release_list(release, "Components:"),
            vec!["main", "contrib", "non-free"]
        );
        assert_eq!(
            release_list(release, "Architectures:"),
            vec!["amd64", "arm64", "all"]
        );
    }

    #[test]
    fn filter_intersects_with_release() {
        let available = vec!["main".to_string(), "contrib".to_string()];
        let req = vec!["main".to_string(), "bogus".to_string()];
        assert_eq!(
            filter_or_all(Some(&req), available.clone(), "component").unwrap(),
            vec!["main"]
        );
        assert_eq!(
            filter_or_all(None, available.clone(), "component").unwrap(),
            available
        );
        assert!(filter_or_all(Some(&["bogus".to_string()]), available, "component").is_err());
    }

    #[test]
    fn filter_trusts_request_when_release_lists_nothing() {
        let req = vec!["main".to_string()];
        assert_eq!(
            filter_or_all(Some(&req), Vec::new(), "component").unwrap(),
            vec!["main"]
        );
    }

    #[tokio::test]
    async fn mirror_warms_structured_repo() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let nora = MockServer::start().await;
        let release = "Components: main\nArchitectures: amd64\n";
        let packages =
            "Package: a\nFilename: pool/main/a/a_1.0_amd64.deb\n\nPackage: b\nFilename: pool/main/b/b_1.0_amd64.deb\n";
        for (p, body) in [
            ("/deb/debian/dists/bookworm/Release", release),
            (
                "/deb/debian/dists/bookworm/main/binary-amd64/Packages",
                packages,
            ),
            ("/deb/debian/pool/main/a/a_1.0_amd64.deb", "deb-a"),
            ("/deb/debian/pool/main/b/b_1.0_amd64.deb", "deb-b"),
        ] {
            Mock::given(method("GET"))
                .and(path(p))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .mount(&nora)
                .await;
        }
        // Packages.gz/.xz, InRelease, Release.gpg, HEAD probes → 404 (unmocked);
        // the index fetch falls back to plain Packages.

        let client = reqwest::Client::new();
        let result = run_deb_mirror(
            &client,
            &nora.uri(),
            "debian",
            Some("bookworm"),
            None,
            None,
            4,
        )
        .await
        .unwrap();

        assert_eq!(result.total, 2);
        assert_eq!(result.fetched, 2);
        assert_eq!(result.failed, 0);
    }
}
