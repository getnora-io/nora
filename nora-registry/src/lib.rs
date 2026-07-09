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
                    let rewritten = tarball_url.replace(upstream_trimmed, &nora_npm_base);
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

    /// Byte-level replace of upstream URL prefix (safety net for fuzz targets).
    fn replace_upstream_bytes(data: &[u8], upstream_url: &str, nora_npm_base: &str) -> Vec<u8> {
        if upstream_url.is_empty() {
            return data.to_vec();
        }
        let needle = upstream_url.as_bytes();
        if memchr::memmem::find(data, needle).is_none() {
            return data.to_vec();
        }
        let replacement = nora_npm_base.as_bytes();
        let mut result = Vec::with_capacity(data.len());
        let mut start = 0;
        let finder = memchr::memmem::Finder::new(needle);
        while let Some(pos) = finder.find(&data[start..]) {
            result.extend_from_slice(&data[start..start + pos]);
            result.extend_from_slice(replacement);
            start += pos + needle.len();
        }
        result.extend_from_slice(&data[start..]);
        result
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
    use crate::validation::ends_with_ci;

    pub fn extract_filename(url: &str) -> Option<String> {
        let url = url.split('#').next()?;
        let filename = url.rsplit('/').next()?;

        if ends_with_ci(filename, ".tar.gz")
            || ends_with_ci(filename, ".tgz")
            || ends_with_ci(filename, ".whl")
            || ends_with_ci(filename, ".zip")
            || ends_with_ci(filename, ".egg")
        {
            Some(filename.to_string())
        } else {
            None
        }
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

/// Re-export version parsing for fuzz targets
pub mod version_fuzz {
    use crate::validation::ends_with_ci;

    pub fn parse_npm_tarball_version(package_name: &str, filename: &str) -> Option<String> {
        let filename = filename.strip_suffix(".tgz")?;
        let name_part = if package_name.contains('/') {
            package_name.rsplit('/').next()?
        } else {
            package_name
        };
        let version = filename.strip_prefix(name_part)?.strip_prefix('-')?;
        if version.is_empty() {
            return None;
        }
        Some(version.to_string())
    }

    pub fn parse_pypi_version(normalized_name: &str, filename: &str) -> Option<String> {
        let base = filename
            .strip_suffix(".tar.gz")
            .or_else(|| filename.strip_suffix(".tgz"))
            .or_else(|| filename.strip_suffix(".zip"))
            .or_else(|| filename.strip_suffix(".whl"))
            .or_else(|| filename.strip_suffix(".egg"))?;

        let name_underscore = normalized_name.replace('-', "_");
        let base_lower = base.to_lowercase();
        let prefix = format!("{}-", name_underscore.to_lowercase());

        let rest = base_lower.strip_prefix(&prefix)?;
        let version = if ends_with_ci(filename, ".whl") {
            rest.split('-').next()?
        } else {
            rest
        };
        if version.is_empty() {
            return None;
        }
        Some(version.to_string())
    }
}

/// Re-export of the escape-aware raw-JSON URL rewrites for fuzz targets (#385).
///
/// These MIRROR the private `registry::{ansible,nuget}` rewrites, which live in the
/// binary crate and are unreachable from this library — so a fuzz-friendly copy is
/// the only option (same constraint as `npm_fuzz`). The *real* functions are enforced
/// on every CI run by their in-module `#[cfg(test)]` leak tests; these byte-faithful
/// copies let `cargo fuzz` explore the encoding-space for new dodge forms. A finding
/// here must be reproduced against the real function before it counts.
pub mod rewrite_fuzz {
    /// Mirror of `registry::replace_url_escape_aware`.
    fn replace_url_escape_aware(text: &str, from: &str, to: &str) -> String {
        let plain = text.replace(from, to);
        let esc_from = from.replace('/', "\\/");
        if !plain.contains(&esc_from) {
            return plain;
        }
        let esc_to = to.replace('/', "\\/");
        plain.replace(&esc_from, &esc_to)
    }

    /// Mirror of `registry::ansible::rewrite_ansible_urls`.
    pub fn rewrite_ansible_urls(json_text: &str, upstream_url: &str, base_url: &str) -> String {
        const API_PREFIX: &str = "/api/v3/plugin/ansible/content/published/collections/index";
        let upstream = upstream_url.trim_end_matches('/');
        let base = base_url.trim_end_matches('/');
        let nora_ansible = format!("{}/ansible", base);
        let s = replace_url_escape_aware(
            json_text,
            &format!("{}/download/", upstream),
            &format!("{}/download/", nora_ansible),
        );
        let s = replace_url_escape_aware(
            &s,
            &format!(
                "{}/api/v3/plugin/ansible/content/published/collections/artifacts/",
                upstream
            ),
            &format!("{}/download/", nora_ansible),
        );
        let s = replace_url_escape_aware(
            &s,
            &format!("{}{}/", upstream, API_PREFIX),
            &format!("{}/v3/collections/", nora_ansible),
        );
        replace_url_escape_aware(&s, upstream, &nora_ansible)
    }

    /// Mirror of `registry::nuget::rewrite_registration_urls`.
    pub fn rewrite_registration_urls(
        json_text: &str,
        upstream_url: &str,
        base_url: &str,
    ) -> String {
        let upstream = upstream_url.trim_end_matches('/');
        let nora_nuget = format!("{}/nuget", base_url.trim_end_matches('/'));
        let nora_reg = format!("{}/v3/registration/", nora_nuget);
        let s = replace_url_escape_aware(
            json_text,
            &format!("{}/v3/registration5-semver1/", upstream),
            &nora_reg,
        );
        let s = replace_url_escape_aware(
            &s,
            &format!("{}/v3/registration5-gz-semver1/", upstream),
            &nora_reg,
        );
        let s = replace_url_escape_aware(
            &s,
            &format!("{}/v3/registration5-gz-semver2/", upstream),
            &nora_reg,
        );
        replace_url_escape_aware(
            &s,
            &format!("{}/v3-flatcontainer/", upstream),
            &format!("{}/v3/flatcontainer/", nora_nuget),
        )
    }

    #[cfg(test)]
    mod url_leak_tests {
        //! Deterministic front-loop cases (no fuzz CI job) — the fuzz targets
        //! `fuzz_rewrite_ansible` / `fuzz_rewrite_nuget` explore the rest.
        use super::*;
        const UP: &str = "https://origin-host.invalid";
        const NORA: &str = "http://nora.test";

        #[test]
        fn ansible_escaped_slash_scrubbed() {
            let out = rewrite_ansible_urls(
                r#"{"d":"https:\/\/origin-host.invalid\/download\/a.tar.gz"}"#,
                UP,
                NORA,
            );
            assert!(!out.contains("origin-host.invalid"), "leak: {out}");
        }

        #[test]
        fn nuget_escaped_slash_scrubbed() {
            let out = rewrite_registration_urls(
                r#"{"@id":"https:\/\/origin-host.invalid\/v3\/registration5-semver1\/p\/i.json"}"#,
                UP,
                NORA,
            );
            assert!(!out.contains("origin-host.invalid"), "leak: {out}");
        }
    }
}
