//! The user and password an address may carry, judged as the proxy client judges them.
//!
//! An upstream may be configured as `https://user:secret@host/…`, and its address reaches the
//! dashboard, the circuit-breaker key (a `/metrics` label and the body of a 503), the log and
//! the quarantine journal. Each of those used to find the userinfo with a parser of its own,
//! and each missed a spelling the client accepts: `https:///user:secret@host` and
//! `https:/user:secret@host` are read by the client as a user and password for `host`. Here
//! the address is read by `reqwest::Url`, the parser the client sends with, and every output
//! takes the userinfo out through this module.
//!
//! An `@` is the only thing that ends userinfo in an address, so text with none carries none,
//! whatever the parser makes of it.

use std::borrow::Cow;

/// What stands in for userinfo, or for a whole address that cannot be told apart from it.
pub(crate) const MASK: &str = "***";

/// How the proxy client reads an address.
enum Reading {
    /// An address with a host and no user or password.
    Clean,
    /// An address with a host whose user or password is set.
    WithUserinfo(reqwest::Url),
    /// Not an address with a host: the parser fails, or the scheme takes no authority
    /// (`foo:user:secret@host` is a path to it), so where userinfo would end is unknown.
    Unreadable,
}

fn read(url: &str) -> Reading {
    match reqwest::Url::parse(url) {
        Ok(parsed) if parsed.host_str().is_some() => {
            if parsed.username().is_empty() && parsed.password().is_none() {
                Reading::Clean
            } else {
                Reading::WithUserinfo(parsed)
            }
        }
        _ => Reading::Unreadable,
    }
}

/// `url` without its userinfo, for an output that shows the address:
/// * unchanged when the client reads no user or password in it, so a key or a label written
///   against the configured spelling keeps matching;
/// * the client's spelling of it without user and password when it reads some;
/// * unchanged when it is not an address and has no `@`;
/// * `None` when it is not an address but has an `@`: what precedes it cannot be told apart
///   from userinfo.
pub(crate) fn without_userinfo(url: &str) -> Option<Cow<'_, str>> {
    match read(url) {
        Reading::Clean => Some(Cow::Borrowed(url)),
        Reading::WithUserinfo(mut parsed) => {
            // A URL with a host takes a user and a password, so neither call fails.
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            Some(Cow::Owned(parsed.to_string()))
        }
        Reading::Unreadable if url.contains('@') => None,
        Reading::Unreadable => Some(Cow::Borrowed(url)),
    }
}

/// `url` for a record or a log line: as written, its userinfo replaced by [`MASK`]
/// (`https://***@host/x`), or [`MASK`] alone when it is not an address but has an `@`.
pub(crate) fn masked(url: &str) -> Cow<'_, str> {
    match read(url) {
        Reading::Unreadable if url.contains('@') => Cow::Borrowed(MASK),
        _ => match crate::log_redact::redact_userinfo(url.as_bytes()) {
            Cow::Borrowed(_) => Cow::Borrowed(url),
            // Only ASCII between ASCII delimiters is replaced, so the text stays UTF-8.
            Cow::Owned(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
        },
    }
}

/// `url` as the dashboard shows it to a caller allowed to see addresses: an `http(s)` address
/// without its userinfo, else `None` (not shown).
pub(crate) fn for_dashboard(url: &str) -> Option<Cow<'_, str>> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    without_userinfo(url)
}

/// Spellings of an address with userinfo, each with the text of that userinfo: what every
/// output is checked against, next to the request the client builds from it.
#[cfg(test)]
pub(crate) const FORMS: &[(&str, &[&str])] = &[
    (
        "https://ci-bot:s3cr3t@mirror.example/simple",
        &["ci-bot", "s3cr3t"],
    ),
    (
        "https:///ci-bot:s3cr3t@mirror.example/simple",
        &["ci-bot", "s3cr3t"],
    ),
    (
        "https:/ci-bot:s3cr3t@mirror.example/simple",
        &["ci-bot", "s3cr3t"],
    ),
    (
        "https:ci-bot:s3cr3t@mirror.example/simple",
        &["ci-bot", "s3cr3t"],
    ),
    (
        "https:\\\\ci-bot:s3cr3t@mirror.example/simple",
        &["ci-bot", "s3cr3t"],
    ),
    (
        "HTTPS://ci-bot:s3cr3t@mirror.example/simple",
        &["ci-bot", "s3cr3t"],
    ),
    (
        "HTTPS:/ci-bot:s3cr3t@mirror.example/simple",
        &["ci-bot", "s3cr3t"],
    ),
    ("https://ci-bot@mirror.example/simple", &["ci-bot"]),
    (
        "https://ci%40bot:s3%40cr3t@mirror.example/simple",
        &["ci%40bot", "s3%40cr3t", "cr3t"],
    ),
    (
        "https://ci-bot:s3@cr3t@mirror.example/x",
        &["ci-bot", "s3@", "cr3t"],
    ),
    (
        "https://ci-bot:pa(ss)'x@mirror.example/x",
        &["ci-bot", "pa(ss", "ss)'x"],
    ),
    (
        "https://ci-bot:s3cr3t@[2001:db8::1]:8443/simple",
        &["ci-bot", "s3cr3t"],
    ),
    (
        "https://ci-bot:s3cr3t@mirror.example:8443/simple",
        &["ci-bot", "s3cr3t"],
    ),
    (
        "http://ci-bot:s3cr3t@127.0.0.1:1/repo?ref=a@b#c@d",
        &["ci-bot", "s3cr3t"],
    ),
];

/// Checks shared by the tests of every output.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod check {
    /// `shown` names the target the client sends `form` to: same host, port, path and query.
    pub(crate) fn same_target(shown: &str, form: &str) {
        let sent = reqwest::Client::new().get(form).build().unwrap();
        let sent = sent.url();
        let shown = reqwest::Url::parse(shown).unwrap_or_else(|e| panic!("{shown}: {e}"));
        assert_eq!(shown.host_str(), sent.host_str(), "{form}: host");
        assert_eq!(
            shown.port_or_known_default(),
            sent.port_or_known_default(),
            "{form}"
        );
        assert_eq!(shown.path(), sent.path(), "{form}: path");
        assert_eq!(shown.query(), sent.query(), "{form}: query");
    }

    /// `out`, an output written about `form`, holds none of its userinfo.
    pub(crate) fn holds_no_secret(out: &str, form: &str, secrets: &[&str]) {
        for secret in secrets {
            assert!(
                !out.contains(secret),
                "{form}: output shows {secret}: {out}"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::check::{holds_no_secret, same_target};
    use super::*;

    /// The client sends each form with its userinfo (moved into an `Authorization` header);
    /// the address shown names the same target and none of the userinfo.
    #[test]
    fn every_form_is_shown_as_the_client_reads_it_without_its_userinfo() {
        for (form, secrets) in FORMS {
            let sent = reqwest::Client::new().get(*form).build().unwrap();
            assert!(
                sent.headers().contains_key(reqwest::header::AUTHORIZATION),
                "{form}: the client sends the userinfo"
            );
            let shown = without_userinfo(form).unwrap();
            same_target(&shown, form);
            let parsed = reqwest::Url::parse(&shown).unwrap();
            assert_eq!((parsed.username(), parsed.password()), ("", None), "{form}");
            holds_no_secret(&shown, form, secrets);
        }
    }

    /// Masked, each form names the same target, with `***` as its only user and no password.
    #[test]
    fn every_form_is_masked_as_the_client_reads_it() {
        for (form, secrets) in FORMS {
            let shown = masked(form);
            holds_no_secret(&shown, form, secrets);
            same_target(&shown, form);
            let parsed = reqwest::Url::parse(&shown).unwrap();
            assert_eq!(
                (parsed.username(), parsed.password()),
                (MASK, None),
                "{form}"
            );
        }
    }

    /// An address the client reads no user or password in stays as written, whatever its
    /// spelling, so a breaker override written against it keeps matching.
    #[test]
    fn an_address_without_userinfo_is_unchanged() {
        for url in [
            "https://registry-1.docker.io",
            "https://Mirror.Example:443/simple/",
            "https:///mirror.example/simple",
            "https://mirror.example/@scope/pkg",
            "https://mirror.example\\@scope/pkg",
            "https://mirror.example/simple?ref=a@b#c@d",
        ] {
            assert_eq!(without_userinfo(url).as_deref(), Some(url), "{url}");
            assert_eq!(masked(url), url, "{url}");
        }
    }

    /// Text the parser cannot read as an address is shown only when it has no `@`.
    #[test]
    fn an_unreadable_address_with_an_at_is_not_shown() {
        for url in [
            "ci-bot:s3cr3t@mirror.example/simple",
            "foo:ci-bot:s3cr3t@mirror.example",
            "https://ci-bot:pa/ss@mirror.example",
            "https://ci-bot:s3cr3t@",
        ] {
            assert_eq!(without_userinfo(url), None, "{url}");
            assert_eq!(masked(url), MASK, "{url}");
            assert_eq!(for_dashboard(url), None, "{url}");
        }
        for url in ["", "not an address", "npm"] {
            assert_eq!(without_userinfo(url).as_deref(), Some(url), "{url}");
            assert_eq!(masked(url), url, "{url}");
        }
    }

    /// The dashboard shows `http(s)` addresses only.
    #[test]
    fn the_dashboard_shows_http_addresses_only() {
        assert_eq!(for_dashboard("ftp://ci-bot:s3cr3t@mirror.example/x"), None);
        assert_eq!(for_dashboard("not an address"), None);
        assert_eq!(for_dashboard(""), None);
        assert_eq!(
            for_dashboard("https://ci-bot:s3cr3t@mirror.example/x").as_deref(),
            Some("https://mirror.example/x")
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod one_judge_tests {
    //! Userinfo is judged in one place. A new output that cuts it by hand, or reads it off a
    //! parsed URL, is how each leak of the family came in (the breaker key, the log filter, the
    //! proxy log line), so every place in the server's code that does either is listed here,
    //! by file and function, with why it may: a new one fails until it is.
    use std::collections::BTreeSet;
    use std::path::Path;

    /// Text that cuts userinfo by hand or reads it off a parsed URL.
    const HAND_CUTS: [&str; 9] = [
        "find(\"://\")",
        "find('@')",
        "split_once('@')",
        "split('@')",
        "== b'@'",
        ".username()",
        ".password()",
        "set_username(",
        "set_password(",
    ];

    /// The places allowed to, by file and function, with why.
    const ALLOWED: &[(&str, &str, &str)] = &[
        (
            "url_userinfo.rs",
            "read",
            "the one judge: the client parser",
        ),
        (
            "url_userinfo.rs",
            "without_userinfo",
            "the one judge: the client parser",
        ),
        (
            "log_redact.rs",
            "redact_userinfo",
            "free text: pinned to FORMS against the parser",
        ),
        (
            "main.rs",
            "parse_explain_spec",
            "the @ of a package spec, not an address",
        ),
        (
            "mirror/docker.rs",
            "parse_image_ref",
            "the @ of an image digest, not an address",
        ),
        (
            "mirror/npm.rs",
            "extract_yarn_package_name",
            "the @ of a package spec",
        ),
        (
            "npm_links.rs",
            "origin_file",
            "the client parser, deciding which links are local",
        ),
        (
            "npm_links.rs",
            "with_userinfo_of",
            "the client parser, forwarding to the upstream",
        ),
        (
            "npm_links.rs",
            "names_path_on",
            "the client parser, deciding which links are local",
        ),
        (
            "npm_links.rs",
            "place_tarball",
            "the client parser, deciding which links are local",
        ),
        (
            "registry/nuget.rs",
            "strip_url_path",
            "a request base: userinfo goes to the upstream",
        ),
        (
            "registry/terraform.rs",
            "split_subdir",
            "the // of a go-getter subdir",
        ),
    ];

    /// `(file, function)` of each line of `source` outside test modules and comments that
    /// holds one of [`HAND_CUTS`].
    fn hand_cuts(file: &str, source: &str) -> BTreeSet<(String, String)> {
        let lines: Vec<&str> = source.lines().collect();
        let mut found = BTreeSet::new();
        let mut function = String::from("-");
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim_start();
            if trimmed == "#[cfg(test)]" {
                let module = lines[i + 1..]
                    .iter()
                    .find(|l| !l.trim_start().starts_with("#["))
                    .filter(|l| {
                        let l = l.trim_start();
                        l.starts_with("mod ")
                            || l.starts_with("pub mod ")
                            || l.starts_with("pub(crate) mod ")
                    });
                if let Some(module) = module {
                    let close =
                        format!("{}}}", &module[..module.len() - module.trim_start().len()]);
                    i += lines[i..]
                        .iter()
                        .position(|l| *l == close)
                        .unwrap_or(lines.len());
                    i += 1;
                    continue;
                }
            }
            if !trimmed.starts_with("//") {
                if let Some(at) = line
                    .find("fn ")
                    .filter(|&at| at == 0 || line.as_bytes()[at - 1] == b' ')
                {
                    let name: String = line[at + 3..]
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        function = name;
                    }
                }
                if HAND_CUTS.iter().any(|cut| line.contains(cut)) {
                    found.insert((file.to_string(), function.clone()));
                }
            }
            i += 1;
        }
        found
    }

    fn sources(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                if name != "tests" {
                    sources(&path, root, out);
                }
            } else if name.ends_with(".rs")
                && !name.ends_with("tests.rs")
                && !matches!(name.as_str(), "test_helpers.rs" | "test_env.rs" | "lib.rs")
            {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.push((rel, std::fs::read_to_string(&path).unwrap()));
            }
        }
    }

    #[test]
    fn userinfo_is_cut_by_hand_only_where_listed() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        sources(&root, &root, &mut files);
        let found: BTreeSet<(String, String)> = files
            .iter()
            .flat_map(|(file, source)| hand_cuts(file, source))
            .collect();
        let allowed: BTreeSet<(String, String)> = ALLOWED
            .iter()
            .map(|(file, function, _)| (file.to_string(), function.to_string()))
            .collect();
        assert_eq!(
            found, allowed,
            "a place that cuts userinfo by hand: show the address through crate::url_userinfo, \
             or list the place with why"
        );
    }

    /// The check sees a hand cut, and skips a test module and a comment.
    #[test]
    fn the_check_sees_a_hand_cut_and_skips_tests() {
        let leak = "fn key(url: &str) -> &str {\n    let at = url.rfind('@');\n    url\n}\n";
        assert_eq!(
            hand_cuts("x.rs", leak),
            BTreeSet::from([("x.rs".to_string(), "key".to_string())])
        );
        let parsed =
            "pub(crate) fn label(u: &reqwest::Url) -> String {\n    u.password().into()\n}\n";
        assert_eq!(hand_cuts("x.rs", parsed).len(), 1);
        let tests =
            "#[cfg(test)]\nmod tests {\n    fn t() { \"a@b\".find('@'); }\n}\n// url.find('@')\n";
        assert!(hand_cuts("x.rs", tests).is_empty());
    }
}
