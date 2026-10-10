// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::config::UpstreamAuth;
use crate::secrets::{expose_opt, ProtectedString};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmConfig {
    #[serde(default = "super::super::default_true")]
    pub enabled: bool,
    /// Single upstream — the back-compat path (`NORA_NPM_PROXY`, old TOML).
    /// Used only when `proxies` is empty; see [`NpmConfig::route`].
    #[serde(default = "default_npm_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    /// Upstreams with scope routing (#1055). An entry with `scopes` is the only
    /// upstream asked for packages in those scopes; at most one entry has no
    /// `scopes` and serves everything else. Non-empty replaces `proxy`/`proxy_auth`.
    #[serde(default)]
    pub proxies: Vec<NpmProxyEntry>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
    /// Revalidate stale metadata with a conditional request (`If-None-Match`)
    /// instead of always re-downloading the full body (#596). Fail-open: any
    /// error falls back to a full fetch.
    #[serde(default = "super::super::default_true")]
    pub revalidate: bool,
}

/// One npm upstream: a bare URL, or a table with scopes and a credential.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum NpmProxyEntry {
    Simple(String),
    Full(NpmProxy),
}

/// Not `#[serde(untagged)]` on the way in: untagged swallows the table's own error
/// and reports only "did not match any variant", so a misspelt key would not be named.
impl<'de> Deserialize<'de> for NpmProxyEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EntryVisitor;
        impl<'de> serde::de::Visitor<'de> for EntryVisitor {
            type Value = NpmProxyEntry;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an upstream URL or a table with `url`")
            }
            fn visit_str<E: serde::de::Error>(self, url: &str) -> Result<Self::Value, E> {
                Ok(NpmProxyEntry::Simple(url.to_string()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<Self::Value, A::Error> {
                NpmProxy::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map(NpmProxyEntry::Full)
            }
        }
        deserializer.deserialize_any(EntryVisitor)
    }
}

/// An npm upstream with optional scope ownership and credential (#1055).
///
/// Unknown keys are rejected: a misspelt `scopes` would otherwise turn a private
/// registry into the default upstream for every package.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NpmProxy {
    pub url: String,
    /// Scopes this upstream owns, e.g. `["@vendor"]`.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// `user:pass`, sent as Basic.
    #[serde(default, skip_serializing)]
    pub auth: Option<ProtectedString>,
    /// Name of the environment variable holding a Bearer token (npm `_authToken`).
    #[serde(default)]
    pub auth_bearer_env: Option<String>,
    /// The token read from `auth_bearer_env` at startup. Never serialized.
    #[serde(skip)]
    pub(crate) auth_bearer: Option<ProtectedString>,
}

/// The upstream a request goes to, and the credential it presents there.
pub struct NpmUpstream<'a> {
    pub url: &'a str,
    pub auth: Option<UpstreamAuth<'a>>,
}

impl NpmProxyEntry {
    pub fn url(&self) -> &str {
        match self {
            NpmProxyEntry::Simple(url) => url,
            NpmProxyEntry::Full(p) => &p.url,
        }
    }

    pub fn scopes(&self) -> &[String] {
        match self {
            NpmProxyEntry::Simple(_) => &[],
            NpmProxyEntry::Full(p) => &p.scopes,
        }
    }

    fn upstream(&self) -> NpmUpstream<'_> {
        let auth = match self {
            NpmProxyEntry::Simple(_) => None,
            NpmProxyEntry::Full(p) => match &p.auth_bearer {
                Some(token) => Some(UpstreamAuth::Bearer(token.expose())),
                None => expose_opt(&p.auth).map(UpstreamAuth::Basic),
            },
        };
        NpmUpstream {
            url: self.url(),
            auth,
        }
    }
}

/// The npm scope a request path belongs to: the first path segment that starts
/// with `@` and is followed by a name — `@vendor` for `@vendor/pkg`,
/// `@vendor/pkg/-/pkg-1.0.0.tgz`, `-/package/@vendor/pkg/dist-tags` and GitHub
/// Packages' `download/@vendor/pkg/1.0.0/<sha>`; `None` for unscoped packages and
/// registry endpoints. Any segment, not only the first: a path that names a private
/// scope anywhere must not be routed to the default upstream. The path is the
/// decoded one axum hands the handler, so `@vendor%2fpkg` arrives as `@vendor/pkg`.
pub fn npm_scope_of(path: &str) -> Option<&str> {
    let mut segments = path.split('/');
    while let Some(segment) = segments.next() {
        if segment.starts_with('@') {
            return segments.next().map(|_| segment);
        }
    }
    None
}

/// npm scope syntax: `@` + a lowercase, URL-safe name not starting with `.` or `_`.
fn is_valid_scope(scope: &str) -> bool {
    let Some(name) = scope.strip_prefix('@') else {
        return false;
    };
    !name.is_empty()
        && !name.starts_with(['.', '_'])
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._~".contains(&b))
}

/// Default npm upstream. Single source for both the serde field-default and the
/// `Default` impl, so the "table present without `proxy`" path and the "table
/// omitted" path produce the same upstream (they diverged before — `#[serde(default)]`
/// on an `Option` yields `None`, silently disabling proxying when `[npm]` is present).
fn default_npm_proxy() -> Option<String> {
    Some("https://registry.npmjs.org".to_string())
}

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: default_npm_proxy(),
            proxy_auth: None,
            proxies: Vec::new(),
            proxy_timeout: 30,
            metadata_ttl: 300,
            serve_stale: true,
            revalidate: true,
        }
    }
}

impl NpmConfig {
    /// The one upstream a request path goes to (#1055) — the single routing point
    /// for packuments, tarballs, revalidation and refetch.
    ///
    /// A scope owned by a `proxies` entry goes only there; anything else goes to
    /// the entry without scopes. Callers do not fall back to another upstream when
    /// the chosen one fails: that is what keeps a private scope off the public
    /// registry. With `proxies` empty the legacy `proxy` (+ `proxy_auth` as Basic)
    /// serves everything; `None` means no upstream (local-only).
    pub fn route(&self, path: &str) -> Option<NpmUpstream<'_>> {
        if self.proxies.is_empty() {
            return self.proxy.as_deref().map(|url| NpmUpstream {
                url,
                auth: expose_opt(&self.proxy_auth).map(UpstreamAuth::Basic),
            });
        }
        let owner = npm_scope_of(path).and_then(|scope| {
            self.proxies
                .iter()
                .find(|e| e.scopes().iter().any(|s| s == scope))
        });
        owner
            .or_else(|| self.proxies.iter().find(|e| e.scopes().is_empty()))
            .map(NpmProxyEntry::upstream)
    }

    /// Scopes owned by a non-default upstream. Their package names must never be
    /// sent to the default upstream — `npm audit` bodies included.
    pub fn owned_scopes(&self) -> impl Iterator<Item = &str> {
        self.proxies
            .iter()
            .flat_map(|e| e.scopes().iter().map(String::as_str))
    }

    /// Every configured upstream URL (UI, startup checks).
    pub fn upstream_urls(&self) -> Vec<&str> {
        if self.proxies.is_empty() {
            self.proxy.as_deref().into_iter().collect()
        } else {
            self.proxies.iter().map(NpmProxyEntry::url).collect()
        }
    }

    /// Configuration errors in `proxies` (fail-closed at load) and warnings.
    pub(in crate::config) fn proxies_problems(&self) -> (Vec<String>, Vec<String>) {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();
        if self.proxies.is_empty() {
            return (warnings, errors);
        }
        let mut seen = std::collections::HashSet::new();
        let mut defaults = 0;
        for (i, entry) in self.proxies.iter().enumerate() {
            let url = entry.url();
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                errors.push(format!(
                    "npm.proxies[{i}]: url \"{url}\" must start with http:// or https://"
                ));
            }
            if entry.scopes().is_empty() {
                defaults += 1;
            }
            for scope in entry.scopes() {
                if !is_valid_scope(scope) {
                    errors.push(format!(
                        "npm.proxies[{i}]: scope \"{scope}\" is not an npm scope (expected \"@name\", lowercase)"
                    ));
                } else if !seen.insert(scope.as_str()) {
                    errors.push(format!(
                        "npm.proxies[{i}]: scope \"{scope}\" is already owned by another entry"
                    ));
                }
            }
            if let NpmProxyEntry::Full(p) = entry {
                if p.auth.is_some() && p.auth_bearer_env.is_some() {
                    errors.push(format!(
                        "npm.proxies[{i}]: set either auth (Basic) or auth_bearer_env (Bearer), not both"
                    ));
                }
                if let Some(var) = &p.auth_bearer_env {
                    match &p.auth_bearer {
                        None => errors.push(format!(
                            "npm.proxies[{i}]: auth_bearer_env names {var}, which is unset or empty"
                        )),
                        Some(token) => {
                            if UpstreamAuth::Bearer(token.expose()).header_value().is_err() {
                                errors.push(format!(
                                    "npm.proxies[{i}]: the token in {var} has characters an HTTP header cannot carry (a trailing newline?)"
                                ));
                            }
                        }
                    }
                }
            }
        }
        if defaults > 1 {
            errors.push(format!(
                "npm.proxies: {defaults} entries have no scopes; at most one may (it serves every package no other entry owns)"
            ));
        } else if defaults == 0 {
            warnings.push(
                "npm.proxies: no entry without scopes — packages outside the configured scopes are served from local storage only"
                    .to_string(),
            );
        }
        if self.proxy_auth.is_some() {
            warnings.push(
                "npm.proxy_auth is ignored because npm.proxies is set — put the credential on the entry"
                    .to_string(),
            );
        }
        (warnings, errors)
    }

    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_NPM_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_NPM_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_NPM_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_NPM_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_NPM_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_NPM_METADATA_TTL") {
            super::super::parse_env_warn("NORA_NPM_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_NPM_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_NPM_REVALIDATE") {
            self.revalidate = !matches!(val.as_str(), "false" | "0");
        }
        // Bearer tokens are read once, here; validation rejects a missing one.
        for entry in &mut self.proxies {
            if let NpmProxyEntry::Full(p) = entry {
                if let Some(var) = &p.auth_bearer_env {
                    p.auth_bearer = env::var(var)
                        .ok()
                        .filter(|v| !v.is_empty())
                        .map(ProtectedString::new);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_src: &str) -> NpmConfig {
        toml::from_str(toml_src).expect("valid npm config")
    }

    /// The issue's example: public registry by default, `@vendor` from a private one.
    fn two_upstreams() -> NpmConfig {
        let mut c = parse(
            r#"
            proxies = [
              "https://registry.npmjs.org",
              { url = "https://npm.vendor.example", scopes = ["@vendor"], auth_bearer_env = "NORA_NPM_VENDOR_TOKEN" },
            ]
            "#,
        );
        if let NpmProxyEntry::Full(p) = &mut c.proxies[1] {
            p.auth_bearer = Some(ProtectedString::from("vendor-tok"));
        }
        c
    }

    fn header(up: &NpmUpstream<'_>) -> Option<String> {
        up.auth
            .map(|a| a.header_value().unwrap().to_str().unwrap().to_string())
    }

    #[test]
    fn scope_of_covers_packument_tarball_and_registry_paths() {
        assert_eq!(npm_scope_of("@vendor/pkg"), Some("@vendor"));
        assert_eq!(npm_scope_of("@vendor/pkg/-/pkg-1.0.0.tgz"), Some("@vendor"));
        assert_eq!(
            npm_scope_of("-/package/@vendor/pkg/dist-tags"),
            Some("@vendor")
        );
        assert_eq!(
            npm_scope_of("download/@vendor/pkg/1.0.0/d113f588ab0b17ddabe8d0db55fa83a741df6871"),
            Some("@vendor")
        );
        assert_eq!(npm_scope_of("lodash"), None);
        assert_eq!(npm_scope_of("lodash/-/lodash-4.17.21.tgz"), None);
        assert_eq!(npm_scope_of("-/v1/search"), None);
        assert_eq!(npm_scope_of("@vendor"), None);
    }

    #[test]
    fn owned_scope_goes_only_to_its_upstream_with_its_token() {
        let c = two_upstreams();
        for path in [
            "@vendor/a",
            "@vendor/a/-/a-1.0.0.tgz",
            "-/package/@vendor/a/dist-tags",
        ] {
            let up = c.route(path).unwrap();
            assert_eq!(up.url, "https://npm.vendor.example", "{path}");
            assert_eq!(header(&up).as_deref(), Some("Bearer vendor-tok"), "{path}");
        }
        for path in ["lodash", "@types/node", "lodash/-/lodash-4.17.21.tgz"] {
            let up = c.route(path).unwrap();
            assert_eq!(up.url, "https://registry.npmjs.org", "{path}");
            assert!(
                up.auth.is_none(),
                "the public upstream never gets the vendor token: {path}"
            );
        }
    }

    #[test]
    fn scope_match_is_the_whole_token_not_a_prefix() {
        let c = two_upstreams();
        for path in ["@vendor-evil/a", "@vendorx/a", "@VENDOR/a", "@vendo/a"] {
            assert_eq!(
                c.route(path).unwrap().url,
                "https://registry.npmjs.org",
                "{path}"
            );
        }
    }

    #[test]
    fn legacy_single_proxy_keeps_working_with_basic_auth() {
        let mut c = NpmConfig::default();
        c.proxy_auth = Some(ProtectedString::from("user:pass"));
        let up = c.route("@vendor/a").unwrap();
        assert_eq!(up.url, "https://registry.npmjs.org");
        assert_eq!(header(&up).as_deref(), Some("Basic dXNlcjpwYXNz"));
        assert_eq!(c.upstream_urls(), vec!["https://registry.npmjs.org"]);

        c.proxy = None;
        assert!(c.route("lodash").is_none(), "no upstream = local-only");
    }

    #[test]
    fn without_a_default_entry_unscoped_packages_have_no_upstream() {
        let mut c =
            parse(r#"proxies = [{ url = "https://npm.vendor.example", scopes = ["@vendor"] }]"#);
        c.proxy = Some("https://registry.npmjs.org".into()); // legacy field is ignored
        assert!(c.route("lodash").is_none());
        assert_eq!(
            c.route("@vendor/a").unwrap().url,
            "https://npm.vendor.example"
        );
        let (warnings, errors) = c.proxies_problems();
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            warnings.iter().any(|w| w.contains("local storage only")),
            "{warnings:?}"
        );
    }

    #[test]
    fn basic_auth_on_an_entry() {
        let c = parse(
            r#"proxies = [{ url = "https://npm.vendor.example", scopes = ["@vendor"], auth = "user:pass" }, "https://registry.npmjs.org"]"#,
        );
        assert_eq!(
            header(&c.route("@vendor/a").unwrap()).as_deref(),
            Some("Basic dXNlcjpwYXNz")
        );
    }

    #[test]
    fn owned_scopes_lists_every_private_scope() {
        let c = parse(
            r#"proxies = ["https://registry.npmjs.org", { url = "https://a.example", scopes = ["@a", "@b"] }, { url = "https://c.example", scopes = ["@c"] }]"#,
        );
        assert_eq!(c.owned_scopes().collect::<Vec<_>>(), vec!["@a", "@b", "@c"]);
    }

    #[test]
    fn a_misspelt_key_is_a_parse_error_not_a_new_default() {
        let err = toml::from_str::<NpmConfig>(
            r#"proxies = ["https://registry.npmjs.org", { url = "https://npm.vendor.example", scope = ["@vendor"] }]"#,
        );
        let msg = err.expect_err("unknown key").to_string();
        assert!(
            msg.contains("`scope`"),
            "the error must name the key: {msg}"
        );
    }

    #[test]
    fn valid_two_upstream_config_has_no_problems() {
        let (warnings, errors) = two_upstreams().proxies_problems();
        assert!(errors.is_empty(), "{errors:?}");
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn config_problems_fail_closed() {
        let cases: &[(&str, &str)] = &[
            (
                r#"proxies = ["https://registry.npmjs.org", "https://mirror.example"]"#,
                "2 entries have no scopes",
            ),
            (
                r#"proxies = ["https://registry.npmjs.org", { url = "https://a.example", scopes = ["@x"] }, { url = "https://b.example", scopes = ["@x"] }]"#,
                "already owned",
            ),
            (
                r#"proxies = ["https://registry.npmjs.org", { url = "https://a.example", scopes = ["vendor"] }]"#,
                "is not an npm scope",
            ),
            (
                r#"proxies = ["https://registry.npmjs.org", { url = "https://a.example", scopes = ["@Vendor"] }]"#,
                "is not an npm scope",
            ),
            (
                r#"proxies = ["https://registry.npmjs.org", { url = "https://a.example", scopes = ["@vendor/x"] }]"#,
                "is not an npm scope",
            ),
            (
                r#"proxies = ["registry.npmjs.org"]"#,
                "must start with http",
            ),
            (
                r#"proxies = ["https://registry.npmjs.org", { url = "https://a.example", scopes = ["@x"], auth = "u:p", auth_bearer_env = "T" }]"#,
                "not both",
            ),
            (
                r#"proxies = ["https://registry.npmjs.org", { url = "https://a.example", scopes = ["@x"], auth_bearer_env = "NORA_TEST_UNSET_TOKEN" }]"#,
                "unset or empty",
            ),
        ];
        for (src, needle) in cases {
            let (_, errors) = parse(src).proxies_problems();
            assert!(
                errors.iter().any(|e| e.contains(needle)),
                "{src}\n expected an error containing {needle:?}, got {errors:?}"
            );
        }
    }

    #[test]
    fn a_token_with_a_newline_is_a_config_error_naming_the_variable_not_the_value() {
        let mut c = two_upstreams();
        if let NpmProxyEntry::Full(p) = &mut c.proxies[1] {
            p.auth_bearer = Some(ProtectedString::from("secret-tok\n"));
        }
        let (_, errors) = c.proxies_problems();
        assert!(
            errors.iter().any(|e| e.contains("NORA_NPM_VENDOR_TOKEN")),
            "{errors:?}"
        );
        assert!(
            errors.iter().all(|e| !e.contains("secret-tok")),
            "{errors:?}"
        );
    }
}
