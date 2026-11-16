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

/// `url` for a record, a log line or an error: its userinfo replaced by [`MASK`]
/// (`https://***@host/x`), or [`MASK`] alone when it is not an address but has an `@`.
///
/// What is userinfo is the parser's call. The written spelling is kept when the log filter's
/// mask of it reads, to the parser, as the same address with [`MASK`] for its only user;
/// otherwise (a password with a space, `"`, `<` or `>`, which the parser takes and the filter
/// stops at) the parser's own spelling is written, with [`MASK`] for the user.
pub(crate) fn masked(url: &str) -> Cow<'_, str> {
    match read(url) {
        Reading::Clean => Cow::Borrowed(url),
        Reading::Unreadable if url.contains('@') => Cow::Borrowed(MASK),
        Reading::Unreadable => Cow::Borrowed(url),
        Reading::WithUserinfo(mut parsed) => {
            if let Cow::Owned(bytes) = crate::log_redact::redact_userinfo(url.as_bytes()) {
                if let Ok(text) = String::from_utf8(bytes) {
                    if masks_only_userinfo(&text, &parsed) {
                        return Cow::Owned(text);
                    }
                }
            }
            let _ = parsed.set_username(MASK);
            let _ = parsed.set_password(None);
            Cow::Owned(parsed.to_string())
        }
    }
}

/// Whether `text` reads as `parsed` with [`MASK`] for its user and no password.
fn masks_only_userinfo(text: &str, parsed: &reqwest::Url) -> bool {
    reqwest::Url::parse(text).is_ok_and(|t| {
        t.username() == MASK
            && t.password().is_none()
            && t.scheme() == parsed.scheme()
            && t.host() == parsed.host()
            && t.port() == parsed.port()
            && t.path() == parsed.path()
            && t.query() == parsed.query()
            && t.fragment() == parsed.fragment()
    })
}

/// The host of `url` as written, read after its userinfo is taken out by the parser: the text
/// between `http(s)://` and the first `/` or `:`. An address without userinfo gives the same
/// host it always gave, so a Docker storage namespace derived from it does not move. `None`
/// when it is not an address but has an `@`.
pub(crate) fn written_host(url: &str) -> Option<String> {
    let clean = without_userinfo(url)?;
    let rest = clean
        .strip_prefix("https://")
        .or_else(|| clean.strip_prefix("http://"))
        .unwrap_or(&clean);
    rest.split(['/', ':']).next().map(str::to_string)
}

/// Every spelling `text` takes in an output: as it is (a `%` field, a message, stderr), as
/// `{:?}` writes it (a `?` field, an error's `Debug`, serde's "invalid type: string …"), as a
/// JSON string holds it (a field of a JSON log line), and as a JSON string holds its `{:?}`
/// (a `?` field of a JSON log line). The one place the spellings of a secret are made.
pub(crate) fn spellings(text: &str) -> [String; 4] {
    let debug = format!("{text:?}");
    let debug = unquoted(&debug).to_string();
    [text.to_string(), debug.clone(), json(text), json(&debug)]
}

/// `text` as a JSON string holds it, without the quotes.
fn json(text: &str) -> String {
    // A `str` is always a JSON string; the fallback is never taken.
    let quoted = serde_json::to_string(text).unwrap_or_default();
    unquoted(&quoted).to_string()
}

fn unquoted(text: &str) -> &str {
    text.strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .unwrap_or(text)
}

/// The texts of `url`'s userinfo that the log filter cannot find by reading a URL, for it to
/// mask wherever they appear; empty when it finds them all.
///
/// The filter is asked, not second-guessed: each spelling of the address ([`spellings`]) goes
/// through it, and a user or password it leaves is masked by its text, in every spelling of
/// every form it takes: as written in the configuration, as the parser writes it, and decoded
/// (`pa %73s`, `pa%20%73s`, `pa ss`). An address the parser cannot read but that has an `@`
/// is masked whole, in every spelling.
pub(crate) fn texts_the_filter_misses(url: &str) -> Vec<String> {
    let parsed = match read(url) {
        Reading::Clean => return Vec::new(),
        Reading::Unreadable if url.contains('@') => return unreadable_spellings(url),
        Reading::Unreadable => return Vec::new(),
        Reading::WithUserinfo(parsed) => parsed,
    };
    let Some((start, end)) = written_userinfo(url, &parsed) else {
        // The parser read userinfo that cannot be found in the text: mask the address whole.
        return spellings(url).into();
    };
    let written = &url[start..end];
    let (user, password) = match written.split_once(':') {
        Some((user, password)) => (user, Some(password)),
        None => (written, None),
    };
    let forms = |as_written: &str, as_parsed: &str| -> Vec<String> {
        let decoded = percent_encoding::percent_decode_str(as_parsed)
            .decode_utf8_lossy()
            .into_owned();
        [as_written.to_string(), as_parsed.to_string(), decoded]
            .iter()
            .flat_map(|form| spellings(form))
            .filter(|form| !form.is_empty())
            .collect()
    };
    let mut parts = vec![forms(user, parsed.username())];
    if let (Some(written), Some(as_parsed)) = (password, parsed.password()) {
        parts.push(forms(written, as_parsed));
    }
    // What the filter should leave: the address with [`MASK`] for its userinfo.
    let ideal = format!("{}{MASK}{}", &url[..start], &url[end..]);
    let ideal = spellings(&ideal);
    let missed: Vec<&Vec<String>> = parts
        .iter()
        .filter(|forms| {
            spellings(url).iter().zip(&ideal).any(|(spelled, ideal)| {
                let out = crate::log_redact::redact_userinfo(spelled.as_bytes());
                let out = String::from_utf8_lossy(&out);
                // More often than in the masked address: a user named like its host is not a
                // leak where the host shows it.
                forms.iter().any(|form| {
                    out.matches(form.as_str()).count() > ideal.matches(form.as_str()).count()
                })
            })
        })
        .collect();
    missed.into_iter().flatten().cloned().collect()
}

/// Every spelling of an address the parser cannot read as one with a host but that has an `@`:
/// as written, and as the client writes it when it takes it as something else (`ciLeakBot:pw@h`
/// is the scheme `cileakbot` with a path, and a client error names it so).
fn unreadable_spellings(url: &str) -> Vec<String> {
    let mut texts: Vec<String> = spellings(url).into();
    if let Ok(parsed) = reqwest::Url::parse(url) {
        if parsed.as_str() != url {
            texts.extend(spellings(parsed.as_str()));
        }
    }
    texts
}

/// Where in `url` the userinfo the parser read in `parsed` is written: the narrowest range
/// ending at an `@` that, replaced by one user, reads as the same address with that user and no
/// password. The text proposes the ranges; the parser judges them.
fn written_userinfo(url: &str, parsed: &reqwest::Url) -> Option<(usize, usize)> {
    let ats: Vec<usize> = url.match_indices('@').map(|(at, _)| at).collect();
    let starts: Vec<usize> = std::iter::once(0)
        .chain(
            url.char_indices()
                .filter(|(_, c)| matches!(c, ':' | '/' | '\\'))
                .map(|(at, c)| at + c.len_utf8()),
        )
        .collect();
    ats.iter().rev().find_map(|&end| {
        starts
            .iter()
            .rev()
            .filter(|&&start| start < end)
            .find_map(|&start| {
                let probe = format!("{}x{}", &url[..start], &url[end..]);
                reqwest::Url::parse(&probe)
                    .is_ok_and(|p| {
                        p.username() == "x"
                            && p.password().is_none()
                            && p.scheme() == parsed.scheme()
                            && p.host() == parsed.host()
                            && p.port() == parsed.port()
                            && p.path() == parsed.path()
                            && p.query() == parsed.query()
                            && p.fragment() == parsed.fragment()
                    })
                    .then_some((start, end))
            })
    })
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
    (
        "https://ci-bot:pa ss@mirror.example/x",
        &["ci-bot", "pa ss", "pa%20ss"],
    ),
    (
        "https://ci-bot:pa\"ss@mirror.example/x",
        &["ci-bot", "pa\"ss", "pa\\\"ss", "pa%22ss"],
    ),
    (
        "https://ci-bot:pa<s>s@mirror.example/x",
        &["ci-bot", "pa<s>s", "pa%3Cs%3Es"],
    ),
    (
        "https://ci bot:s3cr3t@mirror.example/x",
        &["ci bot", "ci%20bot", "s3cr3t"],
    ),
    // A control character: `{:?}` writes it `\u{1}`, JSON `\u0001`; each `\` stops the filter.
    (
        "https://ci-bot:pa\u{1}ss@mirror.example/x",
        &["ci-bot", "pa\u{1}ss", "pa%01ss"],
    ),
    // Encoded and raw in one password: neither the decoded text nor the filter finds it.
    (
        "http://ci-bot:pa %73s@127.0.0.1:9/repo",
        &["ci-bot", "pa %73s", "pa ss", "pa%20%73s"],
    ),
];

/// Addresses the parser cannot read but with an `@`, each with the text of what may be
/// userinfo: masked whole wherever they appear.
#[cfg(test)]
pub(crate) const UNREADABLE_FORMS: &[(&str, &[&str])] = &[
    ("robot:pa\"ss@mirror.example/repo", &["robot", "pa\"ss"]),
    ("robot:pa ss@mirror.example/repo", &["robot", "pa ss"]),
    ("ci-bot:s3cr3t@mirror.example/repo", &["ci-bot", "s3cr3t"]),
    ("https://ci-bot:pa/ss@mirror.example", &["ci-bot", "pa/ss"]),
    // The client reads a scheme `cirobot` in it and writes it in lower case.
    (
        "CiRobot:s3cr3t@mirror.example/repo",
        &["CiRobot", "cirobot", "s3cr3t"],
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

    /// `out` holds no secret in any spelling an output takes it in: as it is, `{:?}`, a JSON
    /// string, a JSON string of its `{:?}`. Made here, not by [`super::spellings`], so a
    /// spelling that function loses is still looked for.
    pub(crate) fn holds_no_spelling(out: &str, form: &str, secrets: &[&str]) {
        let unquote = |t: String| t[1..t.len() - 1].to_string();
        for secret in secrets {
            let debug = unquote(format!("{secret:?}"));
            let json = |t: &str| unquote(serde_json::to_string(t).unwrap());
            for spelled in [
                secret.to_string(),
                json(secret),
                json(&debug),
                debug.clone(),
            ] {
                assert!(
                    !out.contains(&spelled),
                    "{form}: output shows {spelled}: {out}"
                );
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::check::{holds_no_secret, same_target};
    use super::*;

    /// An address the filter reads by itself adds no text to mask: the filter leaves its
    /// host, so a user named like the host (`mirror` of `mirror.example`) is not masked in
    /// every line that names that host.
    #[test]
    fn an_address_the_filter_reads_adds_no_text() {
        for url in [
            "https://ci-bot:s3cr3t@mirror.example/simple",
            "https:///ci-bot:s3cr3t@mirror.example/simple",
            "HTTPS:/ci-bot:s3cr3t@mirror.example/simple",
            "https://mirror:s3cr3t@mirror.example/simple",
            "https://mirror.example/simple",
        ] {
            assert_eq!(texts_the_filter_misses(url), Vec::<String>::new(), "{url}");
        }
    }

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
    //! Userinfo is judged in one place. A new output that cuts it by hand, reads it off a parsed
    //! URL, or takes a host from an address by hand (and takes the user for it) is how each
    //! leak of the family came in: the breaker key, the log filter, the proxy log line, the
    //! Docker namespace, the leak detector's host. Every place in the server's code that does
    //! one of these is listed here, by file and function, with why it may: a new one fails
    //! until it is.
    use std::collections::BTreeSet;
    use std::path::Path;

    /// Text that cuts userinfo by hand, reads it off a parsed URL, or takes a host by hand.
    const HAND_CUTS: [&str; 13] = [
        "find(\"://\")",
        "split_once(\"://\")",
        "split(\"://\")",
        "strip_prefix(\"https://\")",
        "strip_prefix(\"http://\")",
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
            "written_userinfo",
            "proposes where the written userinfo is; the parser accepts each range or not",
        ),
        (
            "url_userinfo.rs",
            "masked",
            "the one judge: the client parser",
        ),
        (
            "url_userinfo.rs",
            "masks_only_userinfo",
            "the one judge: the client parser",
        ),
        (
            "url_userinfo.rs",
            "written_host",
            "the one judge: a host read after the parser took the userinfo out",
        ),
        (
            "url_userinfo.rs",
            "texts_the_filter_misses",
            "the one judge: the client parser",
        ),
        (
            "config/server.rs",
            "public_host",
            "NORA's own public URL, not an upstream",
        ),
        (
            "npm_links.rs",
            "upstream_url_forms",
            "the http and https spellings an upstream link may take, searched for, not shown",
        ),
        (
            "upstream_rewrite.rs",
            "url_path_component",
            "the path after the authority, searched for, not shown",
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
        let new: Vec<_> = found.difference(&allowed).collect();
        let stale: Vec<_> = allowed.difference(&found).collect();
        assert!(
            new.is_empty() && stale.is_empty(),
            "places that cut userinfo or read a host by hand, not listed: {new:?}; listed, gone: \
             {stale:?}. Show the address through crate::url_userinfo, or list the place with why"
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod hosts_tests {
    //! A host derived from an address is the host the client sends to, never its user.
    use super::check::holds_no_secret;
    use super::FORMS;
    use crate::config::{extract_docker_namespace, Config, DockerUpstream};

    /// The host the client sends `form` to.
    fn sent_host(form: &str) -> String {
        let sent = reqwest::Client::new().get(form).build().unwrap();
        sent.url().host_str().unwrap().to_string()
    }

    /// A Docker storage namespace is a storage key and a name `/api/ui/docker/list` shows,
    /// anonymously under `anonymous_read`: for every spelling it is the host, not the user.
    #[test]
    fn a_docker_namespace_is_the_host_never_the_user() {
        assert_eq!(
            extract_docker_namespace("https://robot-token:x@mirror.example"),
            "mirror.example"
        );
        for (form, secrets) in FORMS {
            let namespace = extract_docker_namespace(form);
            holds_no_secret(&namespace, form, secrets);
            // An IPv6 host has always given `[2001`: kept, so no namespace moves.
            if !form.contains('[') {
                assert_eq!(namespace, sent_host(form), "{form}");
            }
            let upstream = DockerUpstream {
                url: form.to_string(),
                auth: None,
                namespace: None,
                prefix: None,
                namespaces: Vec::new(),
            };
            assert!(
                !upstream.serves_host("ci-bot"),
                "{form}: the user is not a host"
            );
            assert!(upstream.serves_host(&namespace), "{form}");
        }
        // Without userinfo, the namespace it always had: the cache stays where it is.
        for (url, namespace) in [
            ("https://registry-1.docker.io", "docker.io"),
            ("https://ghcr.io/", "ghcr.io"),
            ("http://Mirror.Example:5000/v2", "Mirror.Example"),
            ("https://registry.gitlab.com", "gitlab.com"),
        ] {
            assert_eq!(extract_docker_namespace(url), namespace, "{url}");
        }
    }

    /// The leak detector looks for the host in served bodies and logs it when found: for
    /// every spelling it is the host, not the user.
    #[test]
    fn a_leak_detector_host_is_the_host_never_the_user() {
        for (form, secrets) in FORMS {
            let mut config = Config::default();
            config.cargo.proxy = Some(form.to_string());
            let hosts = config.upstream_hostnames();
            let cargo: Vec<&str> = hosts
                .iter()
                .filter(|(registry, _)| registry == "cargo")
                .map(|(_, host)| host.as_str())
                .collect();
            // An IPv6 host has always given `[2001`, kept as it was; the loopback is not looked
            // for.
            let host = sent_host(form);
            if host == "127.0.0.1" {
                assert!(cargo.is_empty(), "{form}");
            } else if !form.contains('[') {
                assert_eq!(cargo, [host.as_str()], "{form}");
            }
            for (_, host) in &hosts {
                holds_no_secret(host, form, secrets);
            }
        }
    }
}
