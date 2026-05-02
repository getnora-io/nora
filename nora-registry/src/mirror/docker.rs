// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Docker image mirroring — fetch images from upstream registries and push to NORA.

use super::{create_progress_bar, MirrorResult};
use crate::registry::docker_auth::DockerAuth;
use reqwest::Client;
use std::time::Duration;

const DEFAULT_REGISTRY: &str = "https://registry-1.docker.io";
const DEFAULT_TIMEOUT: u64 = 300;

/// Parsed Docker image reference
#[derive(Debug, Clone, PartialEq)]
pub struct ImageRef {
    /// Upstream registry (e.g., "registry-1.docker.io", "ghcr.io")
    pub registry: String,
    /// Image name (e.g., "library/alpine", "grafana/grafana")
    pub name: String,
    /// Tag or digest reference (e.g., "3.20", "sha256:abc...")
    pub reference: String,
}

/// Parse an image reference string into structured components.
///
/// Supports formats:
/// - `alpine:3.20` → Docker Hub library/alpine:3.20
/// - `grafana/grafana:latest` → Docker Hub grafana/grafana:latest
/// - `ghcr.io/owner/repo:v1` → ghcr.io owner/repo:v1
/// - `alpine@sha256:abc` → Docker Hub library/alpine@sha256:abc
/// - `alpine` → Docker Hub library/alpine:latest
pub fn parse_image_ref(input: &str) -> ImageRef {
    let input = input.trim();

    // Split off @digest or :tag
    let (name_part, reference) = if let Some(idx) = input.rfind('@') {
        (&input[..idx], &input[idx + 1..])
    } else if let Some(idx) = input.rfind(':') {
        // Make sure colon is not part of a port (e.g., localhost:5000/image)
        let before_colon = &input[..idx];
        if let Some(last_slash) = before_colon.rfind('/') {
            let segment_after_slash = &input[last_slash + 1..];
            if segment_after_slash.contains(':') {
                // Colon in last segment — tag separator
                (&input[..idx], &input[idx + 1..])
            } else {
                // Colon in earlier segment (port) — no tag
                (input, "latest")
            }
        } else {
            (&input[..idx], &input[idx + 1..])
        }
    } else {
        (input, "latest")
    };

    // Determine if first segment is a registry hostname
    let parts: Vec<&str> = name_part.splitn(2, '/').collect();

    let (registry, name) = if parts.len() == 1 {
        // Simple name like "alpine" → Docker Hub library/
        (
            DEFAULT_REGISTRY.to_string(),
            format!("library/{}", parts[0]),
        )
    } else {
        let first = parts[0];
        // A segment is a registry if it contains a dot or colon (hostname/port)
        if first.contains('.') || first.contains(':') {
            let reg = if first.starts_with("http") {
                first.to_string()
            } else {
                format!("https://{}", first)
            };
            (reg, parts[1].to_string())
        } else {
            // Docker Hub with org, e.g., "grafana/grafana"
            (DEFAULT_REGISTRY.to_string(), name_part.to_string())
        }
    };

    ImageRef {
        registry,
        name,
        reference: reference.to_string(),
    }
}

/// Parse a list of image references from a newline-separated string.
pub fn parse_images_file(content: &str) -> Vec<ImageRef> {
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(parse_image_ref)
        .collect()
}

/// Mirror Docker images from upstream registries into NORA.
pub async fn run_docker_mirror(
    client: &Client,
    nora_url: &str,
    images: &[ImageRef],
    concurrency: usize,
) -> Result<MirrorResult, String> {
    let docker_auth = DockerAuth::new(DEFAULT_TIMEOUT);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));

    let pb = create_progress_bar(images.len() as u64);
    let nora_base = nora_url.trim_end_matches('/');

    let mut total_fetched = 0usize;
    let mut total_failed = 0usize;
    let mut total_bytes = 0u64;

    for image in images {
        let _permit = semaphore.acquire().await.map_err(|e| e.to_string())?;
        pb.set_message(format!("{}:{}", image.name, image.reference));

        match mirror_single_image(client, nora_base, image, &docker_auth).await {
            Ok(bytes) => {
                total_fetched += 1;
                total_bytes += bytes;
            }
            Err(e) => {
                tracing::warn!(
                    image = %format!("{}/{}:{}", image.registry, image.name, image.reference),
                    error = %e,
                    "Failed to mirror image"
                );
                total_failed += 1;
            }
        }
        pb.inc(1);
    }

    pb.finish_with_message("done");

    Ok(MirrorResult {
        total: images.len(),
        fetched: total_fetched,
        failed: total_failed,
        bytes: total_bytes,
    })
}

/// Mirror a single image: fetch manifest + blobs from upstream, push to NORA.
async fn mirror_single_image(
    client: &Client,
    nora_base: &str,
    image: &ImageRef,
    docker_auth: &DockerAuth,
) -> Result<u64, String> {
    let mut bytes = 0u64;

    // 1. Fetch manifest from upstream
    let (manifest_bytes, content_type) = crate::registry::docker::fetch_manifest_from_upstream(
        client,
        &image.registry,
        &image.name,
        &image.reference,
        docker_auth,
        DEFAULT_TIMEOUT,
        None,
    )
    .await
    .map_err(|()| format!("Failed to fetch manifest for {}", image.name))?;

    bytes += manifest_bytes.len() as u64;

    // 2. Parse manifest to find layer digests
    let manifest_json: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("Invalid manifest JSON: {}", e))?;

    // Check if this is a manifest list / OCI index
    let manifests_to_process = if is_manifest_list(&content_type, &manifest_json) {
        // Pick linux/amd64 manifest from the list
        resolve_platform_manifest(
            client,
            &image.registry,
            &image.name,
            docker_auth,
            &manifest_json,
        )
        .await?
    } else {
        vec![(
            manifest_bytes.clone(),
            manifest_json.clone(),
            content_type.clone(),
        )]
    };

    for (mf_bytes, mf_json, mf_ct) in &manifests_to_process {
        // 3. Get config digest and layer digests
        let blobs = extract_blob_digests(mf_json);

        // 4. For each blob, check if NORA already has it, otherwise fetch and push
        for digest in &blobs {
            if blob_exists(client, nora_base, &image.name, digest).await {
                tracing::debug!(digest = %digest, "Blob already exists, skipping");
                continue;
            }

            let blob_data = crate::registry::docker::fetch_blob_from_upstream(
                client,
                &image.registry,
                &image.name,
                digest,
                docker_auth,
                DEFAULT_TIMEOUT,
                None,
            )
            .await
            .map_err(|()| format!("Failed to fetch blob {}", digest))?;

            bytes += blob_data.len() as u64;
            push_blob(client, nora_base, &image.name, digest, &blob_data).await?;
        }

        // 5. Push manifest to NORA
        push_manifest(
            client,
            nora_base,
            &image.name,
            &image.reference,
            mf_bytes,
            mf_ct,
        )
        .await?;
    }

    // If this was a manifest list, also push the list itself
    if manifests_to_process.len() > 1 || is_manifest_list(&content_type, &manifest_json) {
        push_manifest(
            client,
            nora_base,
            &image.name,
            &image.reference,
            &manifest_bytes,
            &content_type,
        )
        .await?;
    }

    Ok(bytes)
}

/// Check if a manifest is a manifest list (fat manifest) or OCI index.
fn is_manifest_list(content_type: &str, json: &serde_json::Value) -> bool {
    content_type.contains("manifest.list")
        || content_type.contains("image.index")
        || json.get("manifests").is_some()
}

/// From a manifest list, resolve the linux/amd64 platform manifest.
async fn resolve_platform_manifest(
    client: &Client,
    upstream_url: &str,
    name: &str,
    docker_auth: &DockerAuth,
    list_json: &serde_json::Value,
) -> Result<Vec<(Vec<u8>, serde_json::Value, String)>, String> {
    let manifests = list_json
        .get("manifests")
        .and_then(|m| m.as_array())
        .ok_or("Manifest list has no manifests array")?;

    // Find linux/amd64 manifest
    let target = manifests
        .iter()
        .find(|m| {
            let platform = m.get("platform");
            let os = platform
                .and_then(|p| p.get("os"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let arch = platform
                .and_then(|p| p.get("architecture"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            os == "linux" && arch == "amd64"
        })
        .or_else(|| manifests.first())
        .ok_or("No suitable platform manifest found")?;

    let digest = target
        .get("digest")
        .and_then(|d| d.as_str())
        .ok_or("Manifest entry missing digest")?;

    let (mf_bytes, mf_ct) = crate::registry::docker::fetch_manifest_from_upstream(
        client,
        upstream_url,
        name,
        digest,
        docker_auth,
        DEFAULT_TIMEOUT,
        None,
    )
    .await
    .map_err(|()| format!("Failed to fetch platform manifest {}", digest))?;

    let mf_json: serde_json::Value = serde_json::from_slice(&mf_bytes)
        .map_err(|e| format!("Invalid platform manifest: {}", e))?;

    Ok(vec![(mf_bytes, mf_json, mf_ct)])
}

/// Extract all blob digests from a manifest (config + layers).
fn extract_blob_digests(manifest: &serde_json::Value) -> Vec<String> {
    let mut digests = Vec::new();

    // Config blob
    if let Some(digest) = manifest
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str())
    {
        digests.push(digest.to_string());
    }

    // Layer blobs
    if let Some(layers) = manifest.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            if let Some(digest) = layer.get("digest").and_then(|d| d.as_str()) {
                digests.push(digest.to_string());
            }
        }
    }

    digests
}

/// Check if NORA already has a blob via HEAD request.
async fn blob_exists(client: &Client, nora_base: &str, name: &str, digest: &str) -> bool {
    let url = format!("{}/v2/{}/blobs/{}", nora_base, name, digest);
    matches!(
        client
            .head(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await,
        Ok(r) if r.status().is_success()
    )
}

/// Push a blob to NORA via monolithic upload.
async fn push_blob(
    client: &Client,
    nora_base: &str,
    name: &str,
    digest: &str,
    data: &[u8],
) -> Result<(), String> {
    // Start upload session
    let start_url = format!("{}/v2/{}/blobs/uploads/", nora_base, name);
    let response = client
        .post(&start_url)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Failed to start blob upload: {}", e))?;

    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or("Missing Location header from upload start")?
        .to_string();

    // Complete upload with digest
    let upload_url = if location.contains('?') {
        format!("{}&digest={}", location, digest)
    } else {
        format!("{}?digest={}", location, digest)
    };

    // Make absolute URL if relative
    let upload_url = if upload_url.starts_with('/') {
        format!("{}{}", nora_base, upload_url)
    } else {
        upload_url
    };

    let resp = client
        .put(&upload_url)
        .header("Content-Type", "application/octet-stream")
        .body(data.to_vec())
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT))
        .send()
        .await
        .map_err(|e| format!("Failed to upload blob: {}", e))?;

    if !resp.status().is_success() && resp.status().as_u16() != 201 {
        return Err(format!("Blob upload failed with status {}", resp.status()));
    }

    Ok(())
}

/// Push a manifest to NORA.
async fn push_manifest(
    client: &Client,
    nora_base: &str,
    name: &str,
    reference: &str,
    data: &[u8],
    content_type: &str,
) -> Result<(), String> {
    let url = format!("{}/v2/{}/manifests/{}", nora_base, name, reference);
    let resp = client
        .put(&url)
        .header("Content-Type", content_type)
        .body(data.to_vec())
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Failed to push manifest: {}", e))?;

    if !resp.status().is_success() && resp.status().as_u16() != 201 {
        return Err(format!(
            "Manifest push failed with status {}",
            resp.status()
        ));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // --- parse_image_ref tests ---

    #[test]
    fn test_parse_simple_name() {
        let r = parse_image_ref("alpine");
        assert_eq!(r.registry, DEFAULT_REGISTRY);
        assert_eq!(r.name, "library/alpine");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn test_parse_name_with_tag() {
        let r = parse_image_ref("alpine:3.20");
        assert_eq!(r.registry, DEFAULT_REGISTRY);
        assert_eq!(r.name, "library/alpine");
        assert_eq!(r.reference, "3.20");
    }

    #[test]
    fn test_parse_org_image() {
        let r = parse_image_ref("grafana/grafana:latest");
        assert_eq!(r.registry, DEFAULT_REGISTRY);
        assert_eq!(r.name, "grafana/grafana");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn test_parse_org_image_no_tag() {
        let r = parse_image_ref("grafana/grafana");
        assert_eq!(r.registry, DEFAULT_REGISTRY);
        assert_eq!(r.name, "grafana/grafana");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn test_parse_custom_registry() {
        let r = parse_image_ref("ghcr.io/owner/repo:v1.0");
        assert_eq!(r.registry, "https://ghcr.io");
        assert_eq!(r.name, "owner/repo");
        assert_eq!(r.reference, "v1.0");
    }

    #[test]
    fn test_parse_digest_reference() {
        let r = parse_image_ref("alpine@sha256:abcdef1234567890");
        assert_eq!(r.registry, DEFAULT_REGISTRY);
        assert_eq!(r.name, "library/alpine");
        assert_eq!(r.reference, "sha256:abcdef1234567890");
    }

    #[test]
    fn test_parse_registry_with_port() {
        let r = parse_image_ref("localhost:5000/myimage:v1");
        assert_eq!(r.registry, "https://localhost:5000");
        assert_eq!(r.name, "myimage");
        assert_eq!(r.reference, "v1");
    }

    #[test]
    fn test_parse_deep_path() {
        let r = parse_image_ref("ghcr.io/org/sub/image:latest");
        assert_eq!(r.registry, "https://ghcr.io");
        assert_eq!(r.name, "org/sub/image");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn test_parse_trimmed() {
        let r = parse_image_ref("  alpine:3.20  ");
        assert_eq!(r.name, "library/alpine");
        assert_eq!(r.reference, "3.20");
    }

    #[test]
    fn test_parse_images_file() {
        let content = "alpine:3.20\n# comment\npostgres:15\n\nnginx:1.25\n";
        let images = parse_images_file(content);
        assert_eq!(images.len(), 3);
        assert_eq!(images[0].name, "library/alpine");
        assert_eq!(images[1].name, "library/postgres");
        assert_eq!(images[2].name, "library/nginx");
    }

    #[test]
    fn test_parse_images_file_empty() {
        let images = parse_images_file("");
        assert!(images.is_empty());
    }

    #[test]
    fn test_parse_images_file_comments_only() {
        let images = parse_images_file("# comment\n# another\n");
        assert!(images.is_empty());
    }

    // --- extract_blob_digests tests ---

    #[test]
    fn test_extract_blob_digests_full_manifest() {
        let manifest = serde_json::json!({
            "config": {
                "digest": "sha256:config111"
            },
            "layers": [
                {"digest": "sha256:layer111"},
                {"digest": "sha256:layer222"}
            ]
        });
        let digests = extract_blob_digests(&manifest);
        assert_eq!(digests.len(), 3);
        assert_eq!(digests[0], "sha256:config111");
        assert_eq!(digests[1], "sha256:layer111");
        assert_eq!(digests[2], "sha256:layer222");
    }

    #[test]
    fn test_extract_blob_digests_no_layers() {
        let manifest = serde_json::json!({
            "config": { "digest": "sha256:config111" }
        });
        let digests = extract_blob_digests(&manifest);
        assert_eq!(digests.len(), 1);
    }

    #[test]
    fn test_extract_blob_digests_empty() {
        let manifest = serde_json::json!({});
        let digests = extract_blob_digests(&manifest);
        assert!(digests.is_empty());
    }

    // --- is_manifest_list tests ---

    #[test]
    fn test_is_manifest_list_by_content_type() {
        let json = serde_json::json!({});
        assert!(is_manifest_list(
            "application/vnd.docker.distribution.manifest.list.v2+json",
            &json
        ));
    }

    #[test]
    fn test_is_manifest_list_oci_index() {
        let json = serde_json::json!({});
        assert!(is_manifest_list(
            "application/vnd.oci.image.index.v1+json",
            &json
        ));
    }

    #[test]
    fn test_is_manifest_list_by_manifests_key() {
        let json = serde_json::json!({
            "manifests": [{"digest": "sha256:abc"}]
        });
        assert!(is_manifest_list(
            "application/vnd.docker.distribution.manifest.v2+json",
            &json
        ));
    }

    #[test]
    fn test_is_not_manifest_list() {
        let json = serde_json::json!({
            "config": {},
            "layers": []
        });
        assert!(!is_manifest_list(
            "application/vnd.docker.distribution.manifest.v2+json",
            &json
        ));
    }
}
