// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! The rewrites of an upstream's URLs in a JSON document it served, as raw text, to NORA's: one
//! implementation, for the server's handlers and for the fuzz targets alike. Every mapping
//! replaces an upstream URL only where it ends ([`crate::upstream_url::ends`]), in its plain and
//! its `\/`-escaped form.

/// The path of a Galaxy (pulp) collection index under an upstream's root.
pub const ANSIBLE_API_PREFIX: &str = "/api/v3/plugin/ansible/content/published/collections/index";

/// Replace `from`→`to` in raw JSON text, matching BOTH the plain form and the
/// JSON slash-escaped form (`\/`) of `from`.
///
/// Raw-text registry rewrites (ansible, nuget) `.replace()` on the unparsed
/// upstream response. A valid JSON escaping that many origins emit —
/// `"https:\/\/host\/path"` — dodges a plain `https://host/path` needle, so the
/// upstream URL survives the rewrite and leaks the host once the client's JSON
/// parser unescapes `\/`→`/` (#385, class of #377/#379/#380/#381). Handling the
/// `\/` form here closes that. NB: `\uXXXX`-escaped separators are a documented
/// residual — see `rewrite-drops-upstream-host` — caught by the runtime
/// `UPSTREAM_URL_LEAK_TOTAL` detector, not by this string pass.
///
/// Like every upstream rewrite, it replaces `from` only where the URL ends
/// ([`crate::upstream_url::ends`]), in both forms.
pub fn replace_url_escape_aware(text: &str, from: &str, to: &str) -> String {
    let plain = crate::upstream_url::replace_str(text, from, to);
    let esc_from = from.replace('/', "\\/");
    if !plain.contains(&esc_from) {
        return plain;
    }
    let esc_to = to.replace('/', "\\/");
    crate::upstream_url::replace_str(&plain, &esc_from, &esc_to)
}

/// Path component of a URL (`https://host/prefix/` → `/prefix/`), or `""` when
/// there is no path. The scheme is optional — a bare path is returned unchanged.
/// Does not trim a trailing slash (callers that want it trimmed do so). Single
/// source of truth for "drop scheme + authority, keep path"; used by the server's
/// `ServerConfig::base_path` and the ansible metadata rewrite so the two cannot drift.
pub fn url_path_component(url: &str) -> &str {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    after_scheme.find('/').map_or("", |i| &after_scheme[i..])
}

/// Rewrite upstream Galaxy URLs in JSON responses to point through NORA.
///
/// Replacements are applied most-specific-first to avoid double-rewriting:
/// 1. `{upstream}/download/` → `{base}/ansible/download/`
/// 2. `{upstream}/.../artifacts/` → `{base}/ansible/download/` (#438)
/// 3. `{upstream}{ANSIBLE_API_PREFIX}/` → `{base}/ansible/v3/collections/`
/// 4. `{upstream}` (remaining) → `{base}/ansible`
pub fn rewrite_ansible_urls(json_text: &str, upstream_url: &str, base_url: &str) -> String {
    let upstream = upstream_url.trim_end_matches('/');
    let base = base_url.trim_end_matches('/');
    let nora_ansible = format!("{}/ansible", base);
    // Each mapping is escape-aware (plain + `\/`-escaped) so a slash-escaped upstream
    // URL cannot survive and leak the host to the client (#385).
    use replace_url_escape_aware as rw;

    // Most specific first: download URLs
    let s = rw(
        json_text,
        &format!("{}/download/", upstream),
        &format!("{}/download/", nora_ansible),
    );
    // Artifact URLs → download path (#438)
    let s = rw(
        &s,
        &format!(
            "{}/api/v3/plugin/ansible/content/published/collections/artifacts/",
            upstream
        ),
        &format!("{}/download/", nora_ansible),
    );
    // Pulp-style API paths → short v3 paths
    let s = rw(
        &s,
        &format!("{}{}/", upstream, ANSIBLE_API_PREFIX),
        &format!("{}/v3/collections/", nora_ansible),
    );
    // Catch-all: any remaining upstream references
    let s = rw(&s, upstream, &nora_ansible);

    // Root-relative pagination links (#851-followup): galaxy_ng emits
    // `links.next`/`first`/`last` as host-relative paths (no scheme/host), e.g.
    // `/api/v3/plugin/ansible/content/published/collections/index/community/docker/versions/?limit=100&offset=100`.
    // The absolute rewrites above never match these, so without this the client
    // resolves them against NORA's host root — dropping the `/ansible` mount —
    // and every collection with >100 versions (e.g. community.docker) 404s on page 2.
    // Rewrite to root-relative NORA paths so the client's relative-link
    // resolution keeps them under `/ansible`.
    //
    // These needles are anchored on the opening `"` of the JSON string value
    // (the escape-aware `rw` also matches the `\"`…`\/`-escaped form). Unlike the
    // absolute rules above — pinned by a full `scheme://host` — a bare path is a
    // weak anchor, so without the quote it would also rewrite the middle of a
    // *different* host's URL or a literal path in free text (`docs_blob`). The
    // pagination links are whole string values, so the quote is always adjacent.
    let nora_ansible_path = format!("{}/ansible", url_path_component(base));
    let s = rw(
        &s,
        "\"/api/v3/plugin/ansible/content/published/collections/artifacts/",
        &format!("\"{}/download/", nora_ansible_path),
    );
    rw(
        &s,
        &format!("\"{}/", ANSIBLE_API_PREFIX),
        &format!("\"{}/v3/collections/", nora_ansible_path),
    )
}

/// Rewrite upstream registration URLs in NuGet registration index/page responses.
/// Replaces all registration5-* variants with NORA registration path,
/// and v3-flatcontainer packageContent URLs with NORA flatcontainer path.
pub fn rewrite_registration_urls(json_text: &str, upstream_url: &str, base_url: &str) -> String {
    let upstream = upstream_url.trim_end_matches('/');
    let nora_nuget = format!("{}/nuget", base_url.trim_end_matches('/'));
    let nora_reg = format!("{}/v3/registration/", nora_nuget);

    // Rewrite registration and flatcontainer URLs to point to Nora.
    // catalog0 URLs (catalogEntry.@id) are intentionally left as-is: Nora has
    // no catalog handler, and NuGet clients do not fetch these during restore.
    // Rewriting them would produce Nora URLs that 404.
    // Each mapping is escape-aware (plain + `\/`-escaped) so a slash-escaped upstream
    // registration/flatcontainer URL cannot survive and leak the host — sending the
    // client back to the origin, past Nora — after the client unescapes `\/` (#385).
    use replace_url_escape_aware as rw;
    let s = rw(
        json_text,
        &format!("{}/v3/registration5-semver1/", upstream),
        &nora_reg,
    );
    let s = rw(
        &s,
        &format!("{}/v3/registration5-gz-semver1/", upstream),
        &nora_reg,
    );
    let s = rw(
        &s,
        &format!("{}/v3/registration5-gz-semver2/", upstream),
        &nora_reg,
    );
    rw(
        &s,
        &format!("{}/v3-flatcontainer/", upstream),
        &format!("{}/v3/flatcontainer/", nora_nuget),
    )
}

#[cfg(test)]
mod tests {
    //! The host boundary, on the rewrites the server runs: an upstream URL followed by the end
    //! of the text or by one of `/ ? # \ "` is the upstream's and is rewritten; followed by
    //! anything else it names another host and is left as it is. In the plain and the
    //! `\/`-escaped form, with the upstream configured under either scheme.
    use super::{rewrite_ansible_urls, rewrite_registration_urls};

    const NORA: &str = "http://nora.test";
    const UPSTREAMS: [&str; 2] = ["https://origin-host.invalid", "http://origin-host.invalid"];

    /// The `\/`-escaped form of `text`, as a JSON encoder that escapes slashes writes it.
    fn escaped(text: &str) -> String {
        text.replace('/', "\\/")
    }

    /// What follows the URL where it ends: `/`, `?`, `#`, `\` (the start of every JSON escape),
    /// `"` (the end of a JSON string) and the end of the text.
    const ENDS: [&str; 6] = ["/x", "?q=1", "#f", "\\u002fx", "\"}", ""];

    /// What continues the URL into somewhere else: a longer host, a port, credentials before
    /// another host, a longer label.
    const CONTINUES: [&str; 6] = [
        ".evil/x",
        ".invalid.evil",
        ":8443/x",
        "@evil.test/x",
        "x/",
        "-x",
    ];

    #[test]
    fn ansible_rewrites_the_upstream_where_its_url_ends() {
        for up in UPSTREAMS {
            for end in ENDS {
                let text = format!("{up}{end}");
                let want = format!("{NORA}/ansible{end}");
                assert_eq!(rewrite_ansible_urls(&text, up, NORA), want, "{text}");
                let (text, want) = (escaped(&text), escaped(&want));
                assert_eq!(rewrite_ansible_urls(&text, up, NORA), want, "{text}");
            }
        }
    }

    #[test]
    fn ansible_leaves_a_url_that_only_starts_like_the_upstream() {
        for up in UPSTREAMS {
            for more in CONTINUES {
                for text in [format!("{up}{more}"), escaped(&format!("{up}{more}"))] {
                    let text = format!(r#"{{"d":"{text}"}}"#);
                    assert_eq!(rewrite_ansible_urls(&text, up, NORA), text);
                }
            }
        }
    }

    #[test]
    fn nuget_rewrites_the_upstream_registration_and_package_urls() {
        for up in UPSTREAMS {
            for (from, to) in [
                (
                    "/v3-flatcontainer/p/1.0.0/p.1.0.0.nupkg",
                    "/nuget/v3/flatcontainer/p/1.0.0/p.1.0.0.nupkg",
                ),
                (
                    "/v3/registration5-semver1/p/index.json",
                    "/nuget/v3/registration/p/index.json",
                ),
                (
                    "/v3/registration5-gz-semver1/p/1.0.0.json",
                    "/nuget/v3/registration/p/1.0.0.json",
                ),
                (
                    "/v3/registration5-gz-semver2/p/page/1.0.0/2.0.0.json",
                    "/nuget/v3/registration/p/page/1.0.0/2.0.0.json",
                ),
            ] {
                let text = format!(r#"{{"@id":"{up}{from}"}}"#);
                let want = format!(r#"{{"@id":"{NORA}{to}"}}"#);
                assert_eq!(rewrite_registration_urls(&text, up, NORA), want);
                let (text, want) = (escaped(&text), escaped(&want));
                assert_eq!(rewrite_registration_urls(&text, up, NORA), want);
            }
        }
    }

    #[test]
    fn nuget_leaves_a_url_that_only_starts_like_the_upstream() {
        for up in UPSTREAMS {
            for more in CONTINUES {
                for path in [
                    "/v3-flatcontainer/p",
                    "/v3/registration5-semver1/p/index.json",
                ] {
                    let url = format!("{up}{more}{path}");
                    for text in [url.clone(), escaped(&url)] {
                        let text = format!(r#"{{"@id":"{text}"}}"#);
                        assert_eq!(rewrite_registration_urls(&text, up, NORA), text);
                    }
                }
            }
            // A longer path segment is another resource.
            for path in ["/v3-flatcontainerx/p", "/v3/registration5-semver1x/p"] {
                let text = format!(r#"{{"@id":"{up}{path}"}}"#);
                assert_eq!(rewrite_registration_urls(&text, up, NORA), text);
            }
        }
    }

    /// The cases the fuzz target found before the rewrite was escape-aware: both forms of the
    /// upstream are gone, under a mount path too.
    #[test]
    fn an_escaped_upstream_is_rewritten_and_a_foreign_one_is_not() {
        let up = UPSTREAMS[0];
        let out = rewrite_ansible_urls(
            r#"{"d":"https:\/\/origin-host.invalid\/download\/a.tar.gz"}"#,
            up,
            NORA,
        );
        assert_eq!(
            out,
            r#"{"d":"http:\/\/nora.test\/ansible\/download\/a.tar.gz"}"#
        );
        let text = r#"{"d":"https:\/\/origin-host.invalid.evil\/x"}"#;
        assert_eq!(rewrite_ansible_urls(text, up, NORA), text);
        let text = r#"{"@id":"https:\/\/origin-host.invalid.evil\/v3-flatcontainer\/p"}"#;
        assert_eq!(rewrite_registration_urls(text, up, NORA), text);
        let out = rewrite_registration_urls(
            r#"{"@id":"https:\/\/origin-host.invalid\/v3\/registration5-semver1\/p\/i.json"}"#,
            up,
            "https://nora.test/prefix",
        );
        assert_eq!(
            out,
            r#"{"@id":"https:\/\/nora.test\/prefix\/nuget\/v3\/registration\/p\/i.json"}"#
        );
    }
}
