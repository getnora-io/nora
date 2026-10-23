// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! What NORA does with the tarball link an npm upstream's packument names: whether the link is
//! the upstream's own, and for a download which URL is asked, with whose credential, or whether
//! anything is asked at all. Decisions over parsed URLs, without I/O, defined once here for the
//! server and the fuzz targets alike.

use reqwest::Url;

/// Whether `a` and `b` are one origin: scheme, host and port, a port left out being the
/// scheme's own.
pub fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

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

/// The tarball file a link on the upstream's origin names, as the link writes it and decoded.
#[derive(Debug, PartialEq, Eq)]
pub struct OriginFile {
    pub raw: String,
    pub decoded: String,
}

/// The file of `package` that `link` names on the upstream's own origin, outside its path —
/// where GitLab's instance-level endpoint, say, has each tarball under its project
/// (`…/api/v4/projects/<id>/packages/npm/<package>/-/<file>`). NORA serves it as
/// `<package>/-/<file>` and fetches it from exactly `link`, with the upstream's credential: the
/// origin is the upstream's, so the credential goes nowhere it does not already go.
///
/// Only a link that leaves nothing to interpretation counts: absolute, written as a URL parser
/// writes it (no dot segment, stray space or case the parser would change), http or https on
/// the upstream's origin ([`same_origin`]), without userinfo, query or fragment, its path ending
/// in this package's name as whole segments ([`holder_is`]), `/-/` and one of its tarball files
/// whose storage key `key_ok` accepts. `None` for anything else — the caller leaves it out.
pub fn origin_file(
    link: &str,
    upstream: &str,
    package: &str,
    key_ok: &dyn Fn(&str) -> bool,
) -> Option<OriginFile> {
    let target = Url::parse(link).ok()?;
    let upstream = Url::parse(upstream).ok()?;
    let web = |url: &Url| matches!(url.scheme(), "http" | "https");
    if target.as_str() != link
        || !web(&target)
        || !web(&upstream)
        || !target.username().is_empty()
        || target.password().is_some()
        || target.query().is_some()
        || target.fragment().is_some()
        || target.host_str().is_none()
        || !same_origin(&target, &upstream)
    {
        return None;
    }
    let (holder, raw) = target.path().split_once("/-/")?;
    if !holder_is(holder, package) {
        return None;
    }
    let decoded = decode(raw)?;
    parse_npm_tarball_version(package, &decoded)?;
    key_ok(&format!("npm/{package}/tarballs/{decoded}")).then(|| OriginFile {
        raw: raw.to_string(),
        decoded,
    })
}

fn decode(s: &str) -> Option<String> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .ok()
        .map(|s| s.into_owned())
}

/// Whether the path `holder` (as a URL writes it) ends in `package`'s name as whole segments:
/// the name's last segment, or for `@scope/name` its last two, decoded one by one — `%40` and
/// `%2F` may stand for `@` and `/` within the name, never for the `/` before it. So
/// `…/npm/@vendor/pkg`, `…/npm/@vendor%2Fpkg` and `…/npm/%40vendor/pkg` hold `@vendor/pkg`;
/// `…/npm/evil@vendor/pkg`, `…/npm/x%40vendor/pkg` and `…/x%2F@vendor/pkg` do not, and neither
/// does `…/npm/@vendor/pkg` hold `pkg`: the segment before the name is never a scope.
pub fn holder_is(holder: &str, package: &str) -> bool {
    let segments: Vec<&str> = holder.split('/').collect();
    let n = segments.len();
    let whole = |from: usize| -> Option<String> {
        let parts: Option<Vec<String>> = segments[from..].iter().map(|s| decode(s)).collect();
        Some(parts?.join("/"))
    };
    // A segment before the name, and not a scope: the holder is `/…/<name>`, never the name
    // alone or the name under another package's scope.
    let after_a_segment =
        |from: usize| from >= 1 && decode(segments[from - 1]).is_some_and(|d| !d.starts_with('@'));
    let one = n >= 2 && after_a_segment(n - 1) && whole(n - 1).as_deref() == Some(package);
    let two = n >= 3
        && package.starts_with('@')
        && after_a_segment(n - 2)
        && segments[n - 2..]
            .iter()
            .all(|s| decode(s).is_some_and(|d| !d.contains('/')))
        && whole(n - 2).as_deref() == Some(package);
    one || two
}

/// `link` with the userinfo of `upstream`'s URL, the credential an upstream may carry there (the
/// client sends it as Basic): a link on the upstream's origin goes nowhere new with it. A link
/// that already has userinfo (the upstream's own URL) is left as it is.
pub fn with_userinfo_of(link: &str, upstream: &str) -> Option<String> {
    let upstream = Url::parse(upstream).ok()?;
    let mut link = Url::parse(link).ok()?;
    if (upstream.username().is_empty() && upstream.password().is_none())
        || !link.username().is_empty()
        || link.password().is_some()
    {
        return Some(link.into());
    }
    link.set_username(upstream.username()).ok()?;
    link.set_password(upstream.password()).ok()?;
    Some(link.into())
}

/// What a download of an upstream tarball asks.
#[derive(Debug, PartialEq, Eq)]
pub enum TarballSource {
    /// Ask `asked`, which carries the upstream's userinfo if its URL has one, with the
    /// upstream's credential; `named` is what the download is recorded as. The credential goes
    /// as far as the upstream's origin: a redirect off it is followed without the credential.
    Ask { asked: String, named: String },
    /// The upstream's packument does not list this file for its version: nothing is asked.
    NotListed,
}

/// Where NORA downloads the tarball at `path` (`<package>/-/<file>`, or GitHub Packages'
/// `download/<package>/<version>/<sha1>`), given the link `listed` that the upstream's trusted
/// packument names for the version the path asks (`None`: it lists no such version).
///
/// - A link on the upstream's own origin ([`origin_file`]) naming this file: that link, with the
///   upstream's userinfo.
/// - A link on NORA (the packument as NORA caches it) or under the upstream (a copy cached
///   before links were moved onto NORA) naming exactly this path: `<upstream>/<path>`.
/// - Anything else — no such version, a link to another file or another place: nothing.
pub fn tarball_source(
    upstream: &str,
    nora_npm_base: &str,
    package: &str,
    path: &str,
    listed: Option<&str>,
    key_ok: &dyn Fn(&str) -> bool,
) -> TarballSource {
    let Some(link) = listed else {
        return TarballSource::NotListed;
    };
    if path.contains(['?', '#']) {
        return TarballSource::NotListed;
    }
    if let Some(found) = origin_file(link, upstream, package, key_ok) {
        let asks_this_file = path
            .split_once("/-/")
            .is_some_and(|(holder, file)| holder == package && file == found.decoded);
        return match with_userinfo_of(link, upstream).filter(|_| asks_this_file) {
            Some(asked) => TarballSource::Ask {
                asked,
                named: link.to_string(),
            },
            None => TarballSource::NotListed,
        };
    }
    if names_path_on(link, nora_npm_base, path) || names_path_under(link, upstream, path) {
        let at_upstream = format!("{}/{}", upstream.trim_end_matches('/'), path);
        return TarballSource::Ask {
            asked: at_upstream.clone(),
            named: at_upstream,
        };
    }
    TarballSource::NotListed
}

/// Whether `link`, read against NORA's npm base (a relative link included), is `<base>/<path>`.
fn names_path_on(link: &str, nora_npm_base: &str, path: &str) -> bool {
    let Ok(base) = Url::parse(&format!("{}/", nora_npm_base.trim_end_matches('/'))) else {
        return false;
    };
    let (Ok(target), Ok(expected)) = (base.join(link), base.join(path)) else {
        return false;
    };
    same_origin(&target, &base)
        && target.username().is_empty()
        && target.password().is_none()
        && target.query().is_none()
        && target.fragment().is_none()
        && decode(target.path()).is_some_and(|p| Some(p) == decode(expected.path()))
}

/// Whether `link` is the upstream's URL, under either scheme, followed by exactly `/<path>`.
fn names_path_under(link: &str, upstream: &str, path: &str) -> bool {
    upstream_url_forms(upstream.trim_end_matches('/'))
        .iter()
        .filter(|form| !form.is_empty())
        .any(|form| {
            link.strip_prefix(form.as_str())
                .filter(|rest| crate::upstream_url::ends(rest.as_bytes()))
                .and_then(decode)
                .is_some_and(|rest| rest == format!("/{path}"))
        })
}

/// The upstream's URL as configured, and the same host and path under the other scheme. A
/// registry reached over `https://` may name its tarballs `http://` (one behind a TLS terminator
/// writes the scheme it sees), and the other way round: both name the upstream, and a link left
/// under either sends the client past NORA.
pub fn upstream_url_forms(upstream_url: &str) -> Vec<String> {
    let twin = if let Some(rest) = upstream_url.strip_prefix("https://") {
        Some(format!("http://{rest}"))
    } else {
        upstream_url
            .strip_prefix("http://")
            .map(|rest| format!("https://{rest}"))
    };
    std::iter::once(upstream_url.to_string())
        .chain(twin)
        .collect()
}

/// The link the packument `doc` names for the tarball of `version`, if it lists that version.
pub fn listed_link(doc: &[u8], version: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Dist {
        tarball: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Version {
        dist: Option<Dist>,
    }
    #[derive(serde::Deserialize)]
    struct Document {
        versions: Option<std::collections::HashMap<String, Version>>,
    }
    serde_json::from_slice::<Document>(doc)
        .ok()?
        .versions?
        .remove(version)?
        .dist?
        .tarball
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const NORA: &str = "https://nora.example/npm";
    const PROJECT: &str = "/api/v4/projects/7/packages/npm";

    fn any_key(_: &str) -> bool {
        true
    }

    /// Every combination of the upstream (path or not, userinfo or not, port), the link's port,
    /// its holder, the package's scope and the file it names: the link is the upstream's own —
    /// asked as it is written, with the upstream's userinfo — exactly when it is on the
    /// upstream's origin written as a parser writes it, holds exactly this package and names
    /// this version's file. Anything else asks nothing.
    #[test]
    fn a_link_is_asked_only_when_it_is_the_upstreams_own() {
        let mut wrong = Vec::new();
        let mut rows = 0;
        for with_path in [true, false] {
            for userinfo in [false, true] {
                // (upstream port, link port, same origin as a parser writes it)
                for (up_port, link_port, same) in [
                    ("", "", true),
                    ("", ":443", false),
                    ("", ":9443", false),
                    (":8443", ":8443", true),
                    (":8443", "", false),
                    (":8443", ":9443", false),
                ] {
                    for scoped in [true, false] {
                        let package = if scoped { "@vendor/pkg" } else { "pkg" };
                        // (holder, holds exactly this package)
                        let holders: Vec<(String, bool)> = if scoped {
                            vec![
                                ("@vendor/pkg".into(), true),
                                ("%40vendor/pkg".into(), true),
                                ("@vendor%2Fpkg".into(), true),
                                ("evil@vendor/pkg".into(), false),
                                ("x%40vendor/pkg".into(), false),
                                ("x%2F@vendor/pkg".into(), false),
                                ("@other/pkg".into(), false),
                            ]
                        } else {
                            vec![
                                ("pkg".into(), true),
                                ("evilpkg".into(), false),
                                ("x%2Fpkg".into(), false),
                                ("@vendor/pkg".into(), false),
                            ]
                        };
                        for (holder, exact) in &holders {
                            // (file in the link, it is this version's file)
                            for (file, this) in [
                                ("pkg-1.0.0.tgz", true),
                                ("pkg-1.1.0.tgz", false),
                                ("pkg-1.0.0.tgz.sig", false),
                                ("pkg-1.0.0.tgzx", false),
                                ("pkg-1.0.0.tgz/x", false),
                            ] {
                                rows += 1;
                                let creds = if userinfo { "u:p@" } else { "" };
                                let up_path = if with_path {
                                    "/api/v4/packages/npm"
                                } else {
                                    ""
                                };
                                let upstream =
                                    format!("https://{creds}gitlab.example{up_port}{up_path}");
                                let link = format!(
                                    "https://gitlab.example{link_port}{PROJECT}/{holder}/-/{file}"
                                );
                                let path = format!("{package}/-/pkg-1.0.0.tgz");
                                let got = tarball_source(
                                    &upstream,
                                    NORA,
                                    package,
                                    &path,
                                    Some(&link),
                                    &any_key,
                                );
                                let expected = if same && *exact && this {
                                    TarballSource::Ask {
                                        asked: link.replacen(
                                            "https://",
                                            &format!("https://{creds}"),
                                            1,
                                        ),
                                        named: link.clone(),
                                    }
                                } else {
                                    TarballSource::NotListed
                                };
                                if got != expected {
                                    wrong.push(format!(
                                        "{upstream} {package} {link}: {got:?}, expected {expected:?}"
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(rows > 400, "{rows}");
        assert!(wrong.is_empty(), "{} of {rows}: {wrong:#?}", wrong.len());
    }

    /// The other links a packument may name: on NORA (as NORA caches it) or under the upstream
    /// (an older cache), each naming exactly the asked path, are fetched at `<upstream>/<path>`;
    /// the same with another path, userinfo, query or fragment, no link at all, or a path with a
    /// query, ask nothing.
    #[test]
    fn a_link_on_nora_or_under_the_upstream_is_fetched_at_the_upstream() {
        let upstream = "https://u:p@registry.example/npm";
        let path = "@vendor/pkg/-/pkg-1.0.0.tgz";
        let at = TarballSource::Ask {
            asked: format!("{upstream}/{path}"),
            named: format!("{upstream}/{path}"),
        };
        let mut wrong = Vec::new();
        for (link, path, expected) in [
            (format!("{NORA}/{path}"), path, &at),
            (format!("{NORA}/%40vendor/pkg/-/pkg-1.0.0.tgz"), path, &at),
            (format!("/npm/{path}"), path, &at),
            (format!("{upstream}/{path}"), path, &at),
            (
                format!("{}/{path}", upstream.replacen("https://", "http://", 1)),
                path,
                &at,
            ),
            (
                format!("{NORA}/@vendor/pkg/-/pkg-1.1.0.tgz"),
                path,
                &TarballSource::NotListed,
            ),
            (
                format!("{NORA}/{path}?x=1"),
                path,
                &TarballSource::NotListed,
            ),
            (format!("{NORA}/{path}#x"), path, &TarballSource::NotListed),
            (
                format!("https://a:b@nora.example/npm/{path}"),
                path,
                &TarballSource::NotListed,
            ),
            (
                format!("https://nora.example:8443/npm/{path}"),
                path,
                &TarballSource::NotListed,
            ),
            (
                format!("{upstream}/{path}?x=1"),
                path,
                &TarballSource::NotListed,
            ),
            (
                format!("{upstream}x/{path}"),
                path,
                &TarballSource::NotListed,
            ),
            (
                format!("{NORA}/{path}"),
                "@vendor/pkg/-/pkg-1.0.0.tgz?x",
                &TarballSource::NotListed,
            ),
        ] {
            let got = tarball_source(upstream, NORA, "@vendor/pkg", path, Some(&link), &any_key);
            if &got != expected {
                wrong.push(format!("{link} for {path}: {got:?}, expected {expected:?}"));
            }
        }
        let none = tarball_source(upstream, NORA, "@vendor/pkg", path, None, &any_key);
        if none != TarballSource::NotListed {
            wrong.push(format!("no link: {none:?}"));
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// A link whose storage key the server refuses is not the upstream's own file.
    #[test]
    fn a_file_whose_key_is_refused_is_not_asked() {
        let upstream = "https://gitlab.example/api/v4/packages/npm";
        let link = format!("https://gitlab.example{PROJECT}/pkg/-/pkg-1.0.0.tgz");
        assert!(origin_file(&link, upstream, "pkg", &any_key).is_some());
        assert_eq!(origin_file(&link, upstream, "pkg", &|_| false), None);
        let got = tarball_source(
            upstream,
            NORA,
            "pkg",
            "pkg/-/pkg-1.0.0.tgz",
            Some(&link),
            &|_| false,
        );
        assert_eq!(got, TarballSource::NotListed);
    }
}
