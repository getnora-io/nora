// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! `nora mirror rpm` — warm a pull-through RPM repo for offline use.
//!
//! Enumerates the upstream package list THROUGH the NORA proxy (repomd.xml →
//! primary.xml → `<location href=…>`), so the metadata lands in the cache too,
//! then fetches every package path. After a full run, `dnf` clients work with
//! the upstream unreachable.

use super::{decompress_index, fetch_repo_file, warm_repo_paths, MirrorResult};

pub async fn run_rpm_mirror(
    client: &reqwest::Client,
    registry: &str,
    repo: &str,
    arches: Option<&[String]>,
    concurrency: usize,
) -> Result<MirrorResult, String> {
    let base = registry.trim_end_matches('/');

    let repomd = fetch_repo_file(client, base, "rpm", repo, "repodata/repomd.xml").await?;
    let repomd = String::from_utf8(repomd).map_err(|e| format!("repomd.xml: {e}"))?;

    // Warm the signature/key alongside repomd.xml — best-effort, an unsigned
    // upstream has neither.
    for extra in ["repodata/repomd.xml.asc", "repodata/repomd.xml.key"] {
        let _ = fetch_repo_file(client, base, "rpm", repo, extra).await;
    }

    let primary_href =
        primary_location(&repomd).ok_or("repomd.xml has no <data type=\"primary\"> location")?;
    let primary_raw = fetch_repo_file(client, base, "rpm", repo, &primary_href).await?;
    let primary = decompress_index(&primary_href, primary_raw)?;

    let mut paths = location_hrefs(&primary);
    if let Some(arches) = arches {
        let suffixes: Vec<String> = arches.iter().map(|a| format!(".{a}.rpm")).collect();
        paths.retain(|p| suffixes.iter().any(|s| p.ends_with(s.as_str())));
    }
    if paths.is_empty() {
        return Err("no packages found in primary.xml (wrong repo or arch filter?)".to_string());
    }

    // Warm the non-primary repodata blobs (filelists/other/…) so dnf finds
    // every file repomd.xml references.
    let repodata_extras: Vec<String> = location_hrefs(&repomd)
        .into_iter()
        .filter(|h| *h != primary_href)
        .collect();

    println!(
        "Mirroring {} rpm packages from repo '{repo}' via {registry}...",
        paths.len()
    );
    let meta = warm_repo_paths(client, base, "rpm", repo, &repodata_extras, concurrency).await;
    let mut result = warm_repo_paths(client, base, "rpm", repo, &paths, concurrency).await;
    result.total += meta.total;
    result.fetched += meta.fetched;
    result.failed += meta.failed;
    result.bytes += meta.bytes;
    Ok(result)
}

/// `href` attribute of the `<location …/>` inside `<data type="primary">`.
fn primary_location(repomd: &str) -> Option<String> {
    let start = repomd.find("<data type=\"primary\">")?;
    let block = &repomd[start..];
    let end = block.find("</data>").unwrap_or(block.len());
    location_hrefs(&block[..end]).into_iter().next()
}

/// All `href` attributes of `<location …>` elements, in document order.
/// Hand-rolled scan: repodata XML is machine-generated (createrepo_c and our
/// own generator) with attribute-quoted hrefs — no XML dependency needed.
fn location_hrefs(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find("<location") {
        rest = &rest[pos..];
        let tag_end = match rest.find('>') {
            Some(e) => e,
            None => break,
        };
        let tag = &rest[..tag_end];
        if let Some(href_start) = tag.find("href=\"") {
            let val = &tag[href_start + 6..];
            if let Some(href_end) = val.find('"') {
                out.push(val[..href_end].to_string());
            }
        }
        rest = &rest[tag_end..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPOMD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <location href="repodata/abc123-primary.xml.gz"/>
  </data>
  <data type="filelists">
    <location href="repodata/def456-filelists.xml.gz"/>
  </data>
  <data type="primary_db">
    <location href="repodata/ffff-primary.sqlite.bz2"/>
  </data>
</repomd>"#;

    #[test]
    fn primary_location_ignores_primary_db() {
        assert_eq!(
            primary_location(REPOMD).as_deref(),
            Some("repodata/abc123-primary.xml.gz")
        );
    }

    #[test]
    fn location_hrefs_in_order() {
        assert_eq!(
            location_hrefs(REPOMD),
            vec![
                "repodata/abc123-primary.xml.gz",
                "repodata/def456-filelists.xml.gz",
                "repodata/ffff-primary.sqlite.bz2",
            ]
        );
    }

    #[test]
    fn location_hrefs_from_primary() {
        let primary = r#"<metadata packages="2">
<package type="rpm"><name>a</name>
  <location href="Packages/a/a-1.0-1.x86_64.rpm"/>
</package>
<package type="rpm"><name>b</name>
  <location href="Packages/b/b-2.0-1.noarch.rpm"/>
</package>
</metadata>"#;
        assert_eq!(
            location_hrefs(primary),
            vec![
                "Packages/a/a-1.0-1.x86_64.rpm",
                "Packages/b/b-2.0-1.noarch.rpm"
            ]
        );
    }

    #[test]
    fn no_primary_in_empty_repomd() {
        assert_eq!(primary_location("<repomd></repomd>"), None);
    }

    #[tokio::test]
    async fn mirror_warms_repodata_and_packages() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let nora = MockServer::start().await;
        let repomd = r#"<repomd>
  <data type="primary"><location href="repodata/primary.xml"/></data>
  <data type="filelists"><location href="repodata/filelists.xml"/></data>
</repomd>"#;
        let primary = r#"<metadata>
<package><location href="Packages/a-1.0-1.x86_64.rpm"/></package>
<package><location href="Packages/b-1.0-1.aarch64.rpm"/></package>
</metadata>"#;
        for (p, body) in [
            ("/rpm/fedora/repodata/repomd.xml", repomd),
            ("/rpm/fedora/repodata/primary.xml", primary),
            ("/rpm/fedora/repodata/filelists.xml", "<filelists/>"),
            ("/rpm/fedora/Packages/a-1.0-1.x86_64.rpm", "rpm-a"),
        ] {
            Mock::given(method("GET"))
                .and(path(p))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .mount(&nora)
                .await;
        }
        // HEAD (cache probe) and everything unmocked (.asc/.key warm) → 404.

        let client = reqwest::Client::new();
        let result = run_rpm_mirror(
            &client,
            &nora.uri(),
            "fedora",
            Some(&["x86_64".to_string()]),
            4,
        )
        .await
        .unwrap();

        // filelists.xml (repodata extra) + the one x86_64 package; the aarch64
        // package is filtered out.
        assert_eq!(result.total, 2);
        assert_eq!(result.fetched, 2);
        assert_eq!(result.failed, 0);
    }
}
