#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]
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
