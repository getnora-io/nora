// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! `nora mirror pip`: the distribution files each pinned requirement resolves to, fetched through
//! NORA so that its store serves an offline `pip install` (#1183).
//!
//! NORA builds a project page from the upstream's page while it can reach it, and from the files
//! it stores when it cannot; an offline client therefore finds exactly the files the mirror made
//! NORA store. A pinned requirement (`name==version`) resolves to every file of that version —
//! each wheel and the sdist — since the platform and Python version of the client that installs
//! later are not known here.

use super::{create_progress_bar, drain, fetch_ok, FetchError, MirrorResult, MirrorTarget};
use futures::stream::{self, StreamExt};
use nora_registry::pypi_files::{parse_pypi_version, pep503_normalize};

/// PEP 691 JSON: NORA's project page as data, not HTML to scrape.
const PEP691_JSON: &str = "application/vnd.pypi.simple.v1+json";

/// Why a requirement leaves nothing an offline client can install.
#[derive(Debug, thiserror::Error)]
enum PipMiss {
    #[error("not pinned to one version (`==`): pin it (`pip freeze`, `pip-compile`) to mirror its files")]
    NotPinned,
    #[error("project page: {0}")]
    Page(FetchError),
    #[error("NORA lists no file of version {0}")]
    NoFiles(String),
    #[error("{file}: {source}")]
    File { file: String, source: FetchError },
}

#[derive(serde::Deserialize)]
struct ProjectPage {
    files: Vec<PageFile>,
}

#[derive(serde::Deserialize)]
struct PageFile {
    filename: String,
}

/// Fetch, through NORA at `base`, the files of every requirement in `targets`; a requirement is
/// fetched when all its files are, and failed (with a warning naming why) otherwise.
pub(super) async fn mirror_requirements(
    client: &reqwest::Client,
    base: &str,
    targets: &[MirrorTarget],
    concurrency: usize,
) -> MirrorResult {
    let pb = create_progress_bar(targets.len() as u64);
    let mut fetched = 0;
    let mut failed = 0;
    let mut bytes = 0u64;
    for target in targets {
        pb.set_message(format!("{}=={}", target.name, target.version));
        match mirror_requirement(client, base, target, concurrency).await {
            Ok(n) => {
                bytes += n;
                fetched += 1;
            }
            Err(miss) => {
                pb.suspend(|| eprintln!("  WARN: {} {} -> {miss}", target.name, target.version));
                failed += 1;
            }
        }
        pb.inc(1);
    }
    pb.finish_with_message("done");
    if fetched > 0 {
        eprintln!(
            "  NOTE: Only the listed requirements were mirrored, not their dependencies. For air-gapped\n        installs, list every dependency pinned: `pip freeze > requirements.txt` or `pip-compile`."
        );
    }
    MirrorResult {
        total: targets.len(),
        fetched,
        failed,
        bytes,
    }
}

/// The bytes of every file of one pinned requirement, fetched through NORA.
async fn mirror_requirement(
    client: &reqwest::Client,
    base: &str,
    target: &MirrorTarget,
    concurrency: usize,
) -> Result<u64, PipMiss> {
    let pin = crate::curation::pep440_key(&target.version).ok_or(PipMiss::NotPinned)?;
    let project = pep503_normalize(&target.name);
    let page = format!("{base}/simple/{project}/");
    let files = project_files(client, &page).await.map_err(PipMiss::Page)?;
    let wanted = files_of_version(&project, &pin, files);
    if wanted.is_empty() {
        return Err(PipMiss::NoFiles(target.version.clone()));
    }
    let page = &page;
    let results: Vec<(String, Result<u64, FetchError>)> = stream::iter(wanted)
        .map(|file| async move {
            let got = match fetch_ok(client, &format!("{page}{file}"), None).await {
                Ok(resp) => drain(resp).await,
                Err(e) => Err(e),
            };
            (file, got)
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;
    let mut total = 0u64;
    for (file, got) in results {
        total += got.map_err(|source| PipMiss::File { file, source })?;
    }
    Ok(total)
}

/// The file names NORA lists on a project page.
async fn project_files(client: &reqwest::Client, page: &str) -> Result<Vec<String>, FetchError> {
    let body = fetch_ok(client, page, Some(PEP691_JSON))
        .await?
        .bytes()
        .await?;
    let page: ProjectPage = serde_json::from_slice(&body)?;
    Ok(page.files.into_iter().map(|f| f.filename).collect())
}

/// The files of `project` whose version is `pin` (a PEP 440 key: `1.0`, `1.0.0` and `v1` are
/// one version), read from each name as the server and pip read it.
fn files_of_version(project: &str, pin: &str, files: Vec<String>) -> Vec<String> {
    files
        .into_iter()
        .filter(|file| {
            parse_pypi_version(project, file)
                .and_then(|v| crate::curation::pep440_key(&v))
                .is_some_and(|v| v == pin)
        })
        .collect()
}

/// The requirements of a requirements file (`pip freeze`, `pip-compile`, hand-written). A
/// requirement pinned to one version (`==` or `===`, without a wildcard) carries it; any other is
/// `latest`, which names no files. Continuation lines (`\`), comments, options (`-r`, `--hash`,
/// `--index-url`), extras and environment markers are not part of a name or a version.
pub(super) fn parse_requirements_txt(content: &str) -> Vec<MirrorTarget> {
    let mut logical = Vec::new();
    let mut line = String::new();
    for raw in content.lines() {
        match raw.strip_suffix('\\') {
            Some(continued) => {
                line.push_str(continued);
                line.push(' ');
            }
            None => {
                line.push_str(raw);
                logical.push(std::mem::take(&mut line));
            }
        }
    }
    if !line.is_empty() {
        logical.push(line);
    }
    logical
        .iter()
        .filter_map(|l| parse_requirement(l))
        .collect()
}

/// One logical line of a requirements file; `None` for a comment, a blank or an option line.
fn parse_requirement(line: &str) -> Option<MirrorTarget> {
    let line = line.trim_start();
    if line.starts_with('#') {
        return None;
    }
    // A comment starts at a `#` after whitespace; a marker at `;`.
    let line = match line
        .match_indices('#')
        .find(|(i, _)| line[..*i].ends_with([' ', '\t']))
    {
        Some((i, _)) => &line[..i],
        None => line,
    };
    let line = line.split(';').next().unwrap_or(line);
    // Per-requirement options (`--hash=…`) follow the requirement; whitespace inside it is
    // insignificant.
    let spec: String = line
        .split_whitespace()
        .take_while(|token| !token.starts_with("--"))
        .collect();
    if spec.is_empty() || spec.starts_with('-') {
        return None;
    }
    let name_len = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        .unwrap_or(spec.len());
    let name = &spec[..name_len];
    if name.is_empty() {
        return None;
    }
    let mut rest = &spec[name_len..];
    if rest.starts_with('[') {
        rest = rest.find(']').map_or("", |i| &rest[i + 1..]);
    }
    let specifiers: Vec<&str> = rest.split(',').filter(|s| !s.is_empty()).collect();
    let version = match specifiers.as_slice() {
        [one] => one
            .strip_prefix("===")
            .or_else(|| one.strip_prefix("=="))
            .filter(|v| !v.is_empty() && !v.contains('*')),
        _ => None,
    };
    Some(MirrorTarget {
        name: name.to_string(),
        version: version.unwrap_or("latest").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(content: &str) -> Vec<(String, String)> {
        parse_requirements_txt(content)
            .into_iter()
            .map(|t| (t.name, t.version))
            .collect()
    }

    fn pairs(want: &[(&str, &str)]) -> Vec<(String, String)> {
        want.iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_parse_requirements_txt() {
        let content = "flask==2.3.0\nrequests>=2.28.0\n# comment\nnumpy==1.24.3\n";
        assert_eq!(
            parsed(content),
            pairs(&[
                ("flask", "2.3.0"),
                ("requests", "latest"),
                ("numpy", "1.24.3")
            ])
        );
    }

    #[test]
    fn test_parse_requirements_txt_empty() {
        assert!(parse_requirements_txt("").is_empty());
    }

    #[test]
    fn test_parse_requirements_txt_comments_only() {
        assert!(parse_requirements_txt("# This is a comment\n# Another comment\n\n").is_empty());
    }

    #[test]
    fn test_parse_requirements_txt_flags() {
        let content = "-r other-requirements.txt\n-i https://pypi.org/simple\nflask==2.0\n";
        assert_eq!(parsed(content), pairs(&[("flask", "2.0")]));
    }

    /// A marker is not part of the version (PEP 508): `pkg5==1.0 ; python_version>='3.8'` is
    /// version `1.0`.
    #[test]
    fn test_parse_requirements_txt_version_specifiers() {
        let content =
            "pkg1>=1.0\npkg2<2.0\npkg3!=1.5\npkg4~=1.0\npkg5==1.0 ; python_version>='3.8'\n";
        assert_eq!(
            parsed(content),
            pairs(&[
                ("pkg1", "latest"),
                ("pkg2", "latest"),
                ("pkg3", "latest"),
                ("pkg4", "latest"),
                ("pkg5", "1.0"),
            ])
        );
    }

    #[test]
    fn test_parse_requirements_txt_inline_comments() {
        assert_eq!(
            parsed("flask==2.0  # web framework\n"),
            pairs(&[("flask", "2.0")])
        );
    }

    /// Only one exact version pins: a wildcard, a range or two specifiers do not; `===` does.
    #[test]
    fn only_one_exact_version_pins() {
        let content =
            "a==1.*\nb>=1.0,==1.5\nc===1.0\nd == 1.2\ne @ https://example.invalid/e.whl\nf\n";
        assert_eq!(
            parsed(content),
            pairs(&[
                ("a", "latest"),
                ("b", "latest"),
                ("c", "1.0"),
                ("d", "1.2"),
                ("e", "latest"),
                ("f", "latest"),
            ])
        );
    }

    /// The version a file name gives is compared as PEP 440 compares versions, and only files of
    /// the project count.
    #[test]
    fn files_of_a_version_are_matched_by_pep_440() {
        let files = [
            "demo-1.0-py3-none-any.whl",
            "demo-1.0.0.tar.gz",
            "Demo-1.0.zip",
            "demo-1.0.1.tar.gz",
            "demo-1.0rc1.tar.gz",
            "demo_other-1.0.tar.gz",
            "demo-1.0.exe",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(
            files_of_version("demo", "1", files),
            vec![
                "demo-1.0-py3-none-any.whl",
                "demo-1.0.0.tar.gz",
                "Demo-1.0.zip"
            ]
        );
    }
}
