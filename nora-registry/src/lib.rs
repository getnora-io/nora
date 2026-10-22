#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]
// Test code is linted under `--all-targets` but is not held to the production
// restriction/style lints: `.unwrap()`/`.expect()` are idiomatic in tests, and
// the small style nits (redundant clone/field names, `>= x + 1`, etc.) are not
// worth contorting assertions over. Scoped to `cfg(test)` so production keeps
// the strict profile (incl. the workspace `redundant_clone = deny`).
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::redundant_clone,
        clippy::int_plus_one,
        clippy::field_reassign_with_default,
        clippy::unnecessary_get_then_check,
        clippy::single_match,
        clippy::redundant_field_names,
        clippy::len_zero,
        clippy::items_after_test_module
    )
)]
//! NORA Registry — library interface for fuzzing and testing

pub mod npm_files;
pub mod pypi_files;
pub mod upstream_rewrite;
pub mod upstream_url;
pub mod validation;
pub mod verified;

/// Re-export Docker manifest parsing for fuzz targets
pub mod docker_fuzz {
    pub fn detect_manifest_media_type(data: &[u8]) -> String {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
            return "application/octet-stream".to_string();
        };
        if let Some(mt) = value.get("mediaType").and_then(|v| v.as_str()) {
            return mt.to_string();
        }
        if value.get("manifests").is_some() {
            return "application/vnd.oci.image.index.v1+json".to_string();
        }
        if value.get("schemaVersion").and_then(|v| v.as_i64()) == Some(2) {
            if value.get("layers").is_some() {
                return "application/vnd.oci.image.manifest.v1+json".to_string();
            }
            return "application/vnd.docker.distribution.manifest.v2+json".to_string();
        }
        if value.get("schemaVersion").and_then(|v| v.as_i64()) == Some(1) {
            return "application/vnd.docker.distribution.manifest.v1+json".to_string();
        }
        "application/vnd.docker.distribution.manifest.v2+json".to_string()
    }
}

/// Re-export npm metadata rewriting for fuzz targets
pub mod npm_fuzz {
    #[allow(clippy::result_unit_err)]
    pub fn rewrite_tarball_urls(
        data: &[u8],
        nora_base: &str,
        upstream_url: &str,
    ) -> Result<Vec<u8>, ()> {
        let mut json: serde_json::Value = serde_json::from_slice(data).map_err(|_| ())?;

        let upstream_trimmed = upstream_url.trim_end_matches('/');
        let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));

        if let Some(versions) = json.get_mut("versions").and_then(|v| v.as_object_mut()) {
            for (_ver, version_data) in versions.iter_mut() {
                if let Some(tarball_url) = version_data
                    .get("dist")
                    .and_then(|d| d.get("tarball"))
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string())
                {
                    let rewritten = upstream_url_forms(upstream_trimmed)
                        .iter()
                        .fold(tarball_url, |url, form| {
                            crate::upstream_url::replace_str(&url, form, &nora_npm_base)
                        });
                    if let Some(dist) = version_data.get_mut("dist") {
                        dist["tarball"] = serde_json::Value::String(rewritten);
                    }
                }
            }
        }

        let output = serde_json::to_vec(&json).map_err(|_| ())?;

        // Safety net: byte-level replace of any remaining upstream URL prefix (#439)
        Ok(replace_upstream_bytes(
            &output,
            upstream_trimmed,
            &nora_npm_base,
        ))
    }

    /// Byte-level replace of upstream URL prefix (safety net for fuzz targets), where that URL
    /// ends ([`crate::upstream_url::ends`]).
    fn replace_upstream_bytes(data: &[u8], upstream_url: &str, nora_npm_base: &str) -> Vec<u8> {
        if upstream_url.is_empty() {
            return data.to_vec();
        }
        let mut result = data.to_vec();
        for form in upstream_url_forms(upstream_url) {
            result =
                crate::upstream_url::replace(&result, form.as_bytes(), nora_npm_base.as_bytes());
        }
        result
    }

    /// Mirror of `registry::npm::upstream_url_forms`: the URL as configured and under the other
    /// scheme.
    fn upstream_url_forms(upstream_url: &str) -> Vec<String> {
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

    #[cfg(test)]
    mod url_leak_tests {
        //! #385: a rewrite must never leak the configured upstream host into
        //! client-facing output. The fuzz target `fuzz_url_leak` explores this;
        //! these deterministic cases enforce it on every CI run (there is no
        //! fuzz CI job, so this is the front-loop guard).
        use super::rewrite_tarball_urls;

        const UPSTREAM: &str = "https://upstream-host.invalid";
        const NORA: &str = "http://nora.test";

        #[test]
        fn tarball_rewrite_drops_upstream_host() {
            let meta = br#"{"versions":{"1.0.0":{"dist":{"tarball":"https://upstream-host.invalid/p/-/p-1.0.0.tgz"}}}}"#;
            let out = rewrite_tarball_urls(meta, NORA, UPSTREAM).expect("valid json");
            let out = String::from_utf8(out).expect("json is utf-8");
            assert!(!out.contains(UPSTREAM), "upstream host leaked: {out}");
            assert!(
                out.contains("http://nora.test/npm/p/-/p-1.0.0.tgz"),
                "tarball not rewritten to nora base: {out}"
            );
        }

        #[test]
        fn byte_safety_net_scrubs_upstream_outside_dist() {
            // An upstream URL hidden in a non-`dist` field must still be removed
            // by the #439 byte-level safety-net before the client sees it.
            let meta = br#"{"_note":"mirror of https://upstream-host.invalid/x","versions":{}}"#;
            let out = rewrite_tarball_urls(meta, NORA, UPSTREAM).expect("valid json");
            assert!(
                !String::from_utf8_lossy(&out).contains(UPSTREAM),
                "byte safety-net let the upstream host through"
            );
        }
    }
}

/// Re-export PyPI HTML parsing for fuzz targets
pub mod pypi_fuzz {
    pub fn extract_filename(url: &str) -> Option<String> {
        let url = url.split('#').next()?;
        let filename = url.rsplit('/').next()?;

        crate::pypi_files::served_extension(filename).map(|_| filename.to_string())
    }

    pub fn parse_upstream_html(html: &str) -> Vec<(String, Option<String>)> {
        let mut files = Vec::new();
        let mut remaining = html;

        while let Some(href_start) = remaining.find("href=\"") {
            remaining = &remaining[href_start + 6..];
            if let Some(href_end) = remaining.find('"') {
                let url = &remaining[..href_end];
                if let Some(filename) = extract_filename(url) {
                    let sha256 = url.find("#sha256=").map(|pos| url[pos + 8..].to_string());
                    files.push((filename, sha256));
                }
                remaining = &remaining[href_end..];
            }
        }
        files
    }
}

/// Re-export Maven path classification for fuzz targets
pub mod maven_fuzz {
    use crate::validation::ends_with_ci;

    #[derive(Debug, PartialEq)]
    pub enum MavenPathKind {
        VersionFile {
            group_path: String,
            artifact_id: String,
            version: String,
            filename: String,
        },
        ArtifactMeta {
            group_path: String,
            artifact_id: String,
            filename: String,
        },
        Opaque,
    }

    pub fn classify_path(path: &str) -> MavenPathKind {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        if segments.len() < 2 {
            return MavenPathKind::Opaque;
        }

        let last = segments[segments.len() - 1];

        if (last == "maven-metadata.xml" || last.starts_with("maven-metadata.xml."))
            && segments.len() >= 2
        {
            return MavenPathKind::ArtifactMeta {
                group_path: segments[..segments.len() - 2].join("/"),
                artifact_id: segments[segments.len() - 2].to_string(),
                filename: last.to_string(),
            };
        }

        if segments.len() >= 4 {
            return MavenPathKind::VersionFile {
                group_path: segments[..segments.len() - 3].join("/"),
                artifact_id: segments[segments.len() - 3].to_string(),
                version: segments[segments.len() - 2].to_string(),
                filename: last.to_string(),
            };
        }

        MavenPathKind::Opaque
    }

    pub fn is_checksum_file(filename: &str) -> bool {
        ends_with_ci(filename, ".md5")
            || ends_with_ci(filename, ".sha1")
            || ends_with_ci(filename, ".sha256")
            || ends_with_ci(filename, ".sha512")
    }

    pub fn is_snapshot(version: &str) -> bool {
        version.ends_with("-SNAPSHOT")
    }

    pub fn compare_maven_versions(a: &str, b: &str) -> std::cmp::Ordering {
        let a_base = a.strip_suffix("-SNAPSHOT").unwrap_or(a);
        let b_base = b.strip_suffix("-SNAPSHOT").unwrap_or(b);

        let a_parts: Vec<&str> = a_base.split(['.', '-']).collect();
        let b_parts: Vec<&str> = b_base.split(['.', '-']).collect();

        for (ap, bp) in a_parts.iter().zip(b_parts.iter()) {
            let ord = match (ap.parse::<u64>(), bp.parse::<u64>()) {
                (Ok(an), Ok(bn)) => an.cmp(&bn),
                _ => ap.cmp(bp),
            };
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }

        let base_ord = a_parts.len().cmp(&b_parts.len());
        if base_ord != std::cmp::Ordering::Equal {
            return base_ord;
        }

        let a_snap = a.ends_with("-SNAPSHOT");
        let b_snap = b.ends_with("-SNAPSHOT");
        b_snap.cmp(&a_snap)
    }

    pub fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }
}

/// Re-export version parsing for fuzz targets: the server's own readers, so the fuzz targets
/// drive the code that runs.
pub mod version_fuzz {
    pub use crate::npm_files::parse_npm_tarball_version;
    pub use crate::pypi_files::parse_pypi_version;
}

#[cfg(test)]
mod one_implementation_tests {
    //! The fuzz targets drive the code the server runs. A function with a body in this file is
    //! a copy of server code: a fuzz run explores the copy instead of it, a fix to one is no
    //! fix to the other. Shared code lives in a module the server and the fuzz targets both
    //! compile (`pub mod x;` here, used by the server as `nora_registry::x`), and this file
    //! only re-exports it.

    /// Copies of server code that remain, by name: a new one fails
    /// [`this_file_holds_no_copy_of_server_code_but_these`] until it is listed here. The npm copy
    /// stays until the npm rewrite it mirrors moves into a shared module; the others are no
    /// host-boundary code.
    const COPIES: &[&str] = &[
        "docker_fuzz::detect_manifest_media_type",
        "npm_fuzz::rewrite_tarball_urls",
        "npm_fuzz::replace_upstream_bytes",
        "npm_fuzz::upstream_url_forms",
        "pypi_fuzz::extract_filename",
        "pypi_fuzz::parse_upstream_html",
        "maven_fuzz::classify_path",
        "maven_fuzz::is_checksum_file",
        "maven_fuzz::is_snapshot",
        "maven_fuzz::compare_maven_versions",
        "maven_fuzz::xml_escape",
    ];

    /// The modules of their own files this file declares: the code they hold is compiled once,
    /// for the server and the fuzz targets alike.
    const SHARED: &[&str] = &[
        "npm_files",
        "pypi_files",
        "upstream_rewrite",
        "upstream_url",
        "validation",
        "verified",
    ];

    /// What a source file defines outside the items under `#[cfg(test)]`: each function with a
    /// body (`module::name`, `module::Type::name` for a method), each macro item or `include!`
    /// that could define one, each `#[path]`, and each module declared in a file of its own.
    /// Read with syn, so a form split over lines or written in another spacing is the same form.
    #[derive(Default, Debug)]
    struct Defined {
        bodies: Vec<String>,
        refused: Vec<String>,
        files: Vec<String>,
        path: Vec<String>,
    }

    fn under_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|a| {
            a.path().is_ident("cfg")
                && matches!(&a.meta, syn::Meta::List(l)
                    if l.tokens.to_string().split_whitespace().collect::<String>() == "test")
        })
    }

    impl Defined {
        fn read(text: &str) -> Self {
            let file = syn::parse_file(text).unwrap();
            let mut found = Self::default();
            if !under_test(&file.attrs) {
                syn::visit::Visit::visit_file(&mut found, &file);
            }
            found
        }

        fn name(&self, last: &str) -> String {
            self.path
                .iter()
                .map(String::as_str)
                .chain([last])
                .collect::<Vec<_>>()
                .join("::")
        }
    }

    impl<'ast> syn::visit::Visit<'ast> for Defined {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            let attrs: &[syn::Attribute] = match item {
                syn::Item::Mod(m) => &m.attrs,
                syn::Item::Fn(f) => &f.attrs,
                syn::Item::Impl(i) => &i.attrs,
                syn::Item::Trait(t) => &t.attrs,
                syn::Item::Macro(m) => &m.attrs,
                syn::Item::Use(u) => &u.attrs,
                syn::Item::Const(c) => &c.attrs,
                syn::Item::Static(s) => &s.attrs,
                syn::Item::Struct(s) => &s.attrs,
                syn::Item::Enum(e) => &e.attrs,
                syn::Item::Type(t) => &t.attrs,
                _ => &[],
            };
            if under_test(attrs) {
                return;
            }
            match item {
                syn::Item::Mod(m) => {
                    let ident = m.ident.to_string();
                    if m.content.is_none() {
                        self.files.push(self.name(&ident));
                    }
                    self.path.push(ident);
                    syn::visit::visit_item_mod(self, m);
                    self.path.pop();
                }
                syn::Item::Fn(f) => {
                    self.bodies.push(self.name(&f.sig.ident.to_string()));
                    syn::visit::visit_item_fn(self, f);
                }
                syn::Item::Impl(i) => {
                    let ty = i.self_ty.as_ref();
                    let ty = quote_type(ty);
                    for inner in &i.items {
                        if let syn::ImplItem::Fn(f) = inner {
                            if !under_test(&f.attrs) {
                                self.bodies
                                    .push(self.name(&format!("{ty}::{}", f.sig.ident)));
                            }
                        }
                    }
                    syn::visit::visit_item_impl(self, i);
                }
                syn::Item::Trait(t) => {
                    for inner in &t.items {
                        if let syn::TraitItem::Fn(f) = inner {
                            if f.default.is_some() {
                                self.bodies
                                    .push(self.name(&format!("{}::{}", t.ident, f.sig.ident)));
                            }
                        }
                    }
                    syn::visit::visit_item_trait(self, t);
                }
                syn::Item::Macro(m) => {
                    let mac = m.mac.path.segments.last().map(|s| s.ident.to_string());
                    self.refused
                        .push(self.name(&format!("{}!", mac.unwrap_or_default())));
                }
                _ => syn::visit::visit_item(self, item),
            }
        }

        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            if mac.path.is_ident("include") {
                self.refused.push(self.name("include!"));
            }
        }

        fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
            if attr.path().is_ident("path") {
                self.refused.push(self.name("#[path]"));
            }
        }
    }

    fn quote_type(ty: &syn::Type) -> String {
        match ty {
            syn::Type::Path(p) => p
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default(),
            _ => "impl".to_owned(),
        }
    }

    #[test]
    fn this_file_holds_no_copy_of_server_code_but_these() {
        let found = Defined::read(include_str!("lib.rs"));
        let mut bodies = found.bodies.clone();
        bodies.sort();
        let mut copies: Vec<String> = COPIES.iter().map(|c| c.to_string()).collect();
        copies.sort();
        assert_eq!(bodies, copies, "functions with a body in lib.rs");
        assert!(found.refused.is_empty(), "{:?}", found.refused);
        let mut files = found.files.clone();
        files.sort();
        assert_eq!(files, SHARED, "modules of their own files");
    }

    /// Each way to put a copy here is found, in any spacing or over several lines; re-exports,
    /// constants and test code are not.
    #[test]
    fn every_way_to_put_a_copy_here_is_found() {
        let fine = Defined::read(
            r#"
            pub mod upstream_url;
            pub mod rewrite_fuzz {
                pub use crate::upstream_rewrite::{rewrite_ansible_urls, rewrite_registration_urls};
                pub const UP: &str = "https://up.invalid";
                pub type Out = String;
                #[cfg(test)]
                mod tests {
                    fn helper() {}
                    #[test]
                    fn t() { helper() }
                }
            }
            #[cfg(test)]
            fn only_in_tests() {}
            "#,
        );
        assert!(fine.bodies.is_empty(), "{:?}", fine.bodies);
        assert!(fine.refused.is_empty(), "{:?}", fine.refused);
        assert_eq!(fine.files, ["upstream_url"]);

        for (bad, name) in [
            ("pub fn f() {}", "f"),
            (
                "pub mod rewrite_fuzz {\n    fn replace_url_escape_aware(\n        t: &str,\n    ) -> String { t.into() }\n}",
                "rewrite_fuzz::replace_url_escape_aware",
            ),
            (
                "pub mod a { pub mod b { pub(crate) const fn g() -> u8 { 1 } } }",
                "a::b::g",
            ),
            (
                "pub mod a { pub struct S; impl S { pub fn m(&self) {} } }",
                "a::S::m",
            ),
            (
                "pub mod a { pub trait T { fn d(&self) -> u8 { 1 } } }",
                "a::T::d",
            ),
            (
                "pub mod a { #[cfg(not(test))] pub fn h() {} }",
                "a::h",
            ),
            (
                "pub mod a { #[cfg(any(test, fuzzing))] pub fn h() {} }",
                "a::h",
            ),
        ] {
            assert_eq!(Defined::read(bad).bodies, [name], "{bad}");
        }
        for (bad, name) in [
            (
                "pub mod a { macro_rules! m { () => { fn f() {} } } }",
                "a::macro_rules!",
            ),
            (
                "pub mod a { copy_of!(rewrite_ansible_urls); }",
                "a::copy_of!",
            ),
            (
                "pub mod a { pub const X: &str = include!(\"../src/x.rs\"); }",
                "a::include!",
            ),
            (
                "#[path = \"registry/ansible.rs\"]\npub mod ansible;",
                "ansible::#[path]",
            ),
        ] {
            assert!(
                Defined::read(bad).refused.contains(&name.to_owned()),
                "{bad}: {:?}",
                Defined::read(bad).refused
            );
        }
        assert_eq!(Defined::read("pub mod a { mod copy; }").files, ["a::copy"]);
    }
}
