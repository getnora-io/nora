// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Docker image mirroring — fetch images from upstream registries and push to NORA.

use super::{create_progress_bar, MirrorResult};
use crate::circuit_breaker::CircuitBreakerRegistry;
use crate::registry::docker_auth::DockerAuth;
use crate::registry::ProxyError;
use futures::future::BoxFuture;
use reqwest::Client;
use std::time::Duration;

/// Typed error for Docker mirror push operations.
#[derive(Debug, thiserror::Error)]
enum PushError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("{context}: status {status}")]
    Status { context: &'static str, status: u16 },
    #[error("Missing Location header from upload start")]
    MissingLocation,
}

/// Why one image could not be mirrored.
#[derive(Debug, thiserror::Error)]
enum MirrorError {
    #[error("Failed to fetch manifest {reference} for {name}: {cause:?}")]
    FetchManifest {
        reference: String,
        name: String,
        cause: ProxyError,
    },
    #[error("Failed to fetch blob {digest}: {cause:?}")]
    FetchBlob { digest: String, cause: ProxyError },
    #[error("Failed to read fetched blob: {0}")]
    ReadBlob(std::io::Error),
    #[error("Invalid manifest JSON for {reference}: {cause}")]
    InvalidManifest {
        reference: String,
        cause: serde_json::Error,
    },
    #[error("manifest {reference}: image indexes nested deeper than {MAX_INDEX_DEPTH}")]
    IndexTooDeep { reference: String },
    #[error("Manifest list has no manifests array")]
    NoManifestsArray,
    #[error("Manifest list entry missing digest")]
    EntryWithoutDigest,
    /// Content whose hash is not the digest it was asked for (#587/#608).
    #[error("{0}")]
    Integrity(String),
    #[error("Failed to mount blob {digest}: {cause}")]
    MountBlob { digest: String, cause: PushError },
    #[error("Failed to push blob {digest}: {cause}")]
    PushBlob { digest: String, cause: PushError },
    #[error("Failed to push manifest {reference}: {cause}")]
    PushManifest { reference: String, cause: PushError },
}

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
    let docker_auth = DockerAuth::new(client.clone(), DEFAULT_TIMEOUT);
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

/// Where one image is mirrored from and to: the upstream it is read from and the NORA it is
/// pushed into.
struct ImageMirror<'a> {
    client: &'a Client,
    nora_base: &'a str,
    image: &'a ImageRef,
    docker_auth: &'a DockerAuth,
    /// Mirror uses a no-op circuit breaker — it's a background sync job, not user-facing.
    cb: CircuitBreakerRegistry,
}

/// How deep image indexes may nest. An index that lists an index is valid OCI; content
/// addressing rules out a cycle, and this bounds what a hostile upstream can make us walk.
const MAX_INDEX_DEPTH: usize = 4;

/// Mirror a single image: its manifest and everything that manifest references, fetched from
/// upstream and pushed to NORA. Returns the bytes fetched from upstream.
async fn mirror_single_image(
    client: &Client,
    nora_base: &str,
    image: &ImageRef,
    docker_auth: &DockerAuth,
) -> Result<u64, MirrorError> {
    let mirror = ImageMirror {
        client,
        nora_base,
        image,
        docker_auth,
        cb: CircuitBreakerRegistry::noop(),
    };

    let (manifest_bytes, content_type) = mirror.fetch_manifest(&image.reference).await?;
    // If pinned by digest, the manifest's content hash must match the requested
    // digest before we propagate it (#608). No-op for tag references.
    verify_manifest_digest(&image.reference, &manifest_bytes).map_err(MirrorError::Integrity)?;

    mirror
        .mirror_manifest(image.reference.clone(), manifest_bytes, content_type, 0)
        .await
}

impl ImageMirror<'_> {
    /// Fetch a manifest (by tag or digest) from the upstream.
    async fn fetch_manifest(&self, reference: &str) -> Result<(Vec<u8>, String), MirrorError> {
        crate::registry::docker::fetch_manifest_from_upstream(
            self.client,
            &self.image.registry,
            &self.image.name,
            reference,
            self.docker_auth,
            DEFAULT_TIMEOUT,
            None,
            &self.cb,
        )
        .await
        .map_err(|cause| MirrorError::FetchManifest {
            reference: reference.to_string(),
            name: self.image.name.clone(),
            cause,
        })
    }

    /// Mirror a manifest and everything it references, the referenced content first. NORA
    /// refuses a manifest that names a blob or a sub-manifest it does not hold
    /// (`MANIFEST_BLOB_UNKNOWN`), so an image index goes in after every manifest it lists —
    /// each platform and each attestation, exactly as the index names them, so its digest is
    /// the upstream's — and an image manifest after its config and layers (#1184).
    ///
    /// `reference` is the tag or digest the manifest is pushed under: the image's own
    /// reference at the top, its digest for a manifest an index lists.
    fn mirror_manifest(
        &self,
        reference: String,
        bytes: Vec<u8>,
        content_type: String,
        depth: usize,
    ) -> BoxFuture<'_, Result<u64, MirrorError>> {
        Box::pin(async move {
            let json: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|cause| MirrorError::InvalidManifest {
                    reference: reference.clone(),
                    cause,
                })?;
            let mut fetched = bytes.len() as u64;

            if is_manifest_list(&content_type, &json) {
                if depth >= MAX_INDEX_DEPTH {
                    return Err(MirrorError::IndexTooDeep { reference });
                }
                // Fetch and verify every listed manifest before any blob is downloaded, so a
                // tampered entry stops the image before its layers cost anything.
                let mut children = Vec::new();
                for digest in index_entry_digests(&json)? {
                    let (child, child_ct) = self.fetch_manifest(&digest).await?;
                    // An index entry is content-addressed by `digest`: its bytes must hash to
                    // it, or a tampered upstream could swap the layers of a multi-arch image
                    // (#608).
                    verify_manifest_digest(&digest, &child).map_err(MirrorError::Integrity)?;
                    children.push((digest, child, child_ct));
                }
                for (digest, child, child_ct) in children {
                    fetched += self
                        .mirror_manifest(digest, child, child_ct, depth + 1)
                        .await?;
                }
            } else {
                for digest in extract_blob_digests(&json) {
                    fetched += self.mirror_blob(&digest).await?;
                }
            }

            push_manifest(
                self.client,
                self.nora_base,
                &self.image.name,
                &reference,
                &bytes,
                &content_type,
            )
            .await
            .map_err(|cause| MirrorError::PushManifest { reference, cause })?;
            Ok(fetched)
        })
    }

    /// Leave one blob in the image's repository on NORA. Returns the bytes fetched from
    /// upstream (0 when NORA already had the blob).
    ///
    /// NORA's HEAD answers 200 for a blob readable under the name, a copy cached by a pull
    /// through NORA included, while a pushed manifest is checked against what the repository
    /// itself holds. So a blob NORA reports is mounted into the repository from wherever it
    /// lies rather than skipped; where the mount cannot happen, NORA opens an upload and the
    /// blob is fetched and pushed (#1184).
    async fn mirror_blob(&self, digest: &str) -> Result<u64, MirrorError> {
        let name = &self.image.name;
        let session = if blob_exists(self.client, self.nora_base, name, digest).await {
            match mount_blob(self.client, self.nora_base, name, digest)
                .await
                .map_err(|cause| MirrorError::MountBlob {
                    digest: digest.to_string(),
                    cause,
                })? {
                Mount::Mounted => {
                    tracing::debug!(digest = %digest, "Blob already in NORA, mounted");
                    return Ok(0);
                }
                Mount::Upload(location) => Some(location),
            }
        } else {
            None
        };

        let mirror_temp = std::env::temp_dir().join("nora-mirror");
        let _ = std::fs::create_dir_all(&mirror_temp);
        let fetched = crate::registry::docker::fetch_blob_from_upstream(
            self.client,
            &self.image.registry,
            name,
            digest,
            self.docker_auth,
            DEFAULT_TIMEOUT,
            60, // per-chunk read timeout
            None,
            &self.cb,
            &mirror_temp,
        )
        .await
        .map_err(|cause| MirrorError::FetchBlob {
            digest: digest.to_string(),
            cause,
        })?;

        // Verify the blob's content hash matches the requested digest
        // BEFORE propagating it. A compromised / MITM'd / misconfigured
        // upstream can return arbitrary bytes for sha256:<X>; without this
        // check `nora mirror` would accept and push them as that digest.
        // Fail-closed, mirroring the proxy-path check in registry/docker.rs
        // (#587, the mirror counterpart of #581).
        verify_blob_digest(digest, &fetched.sha256).map_err(MirrorError::Integrity)?;

        let blob_data = tokio::fs::read(&fetched.path)
            .await
            .map_err(MirrorError::ReadBlob)?;
        let push_failed = |cause| MirrorError::PushBlob {
            digest: digest.to_string(),
            cause,
        };
        let location = match session {
            Some(location) => location,
            None => start_upload(self.client, self.nora_base, name)
                .await
                .map_err(push_failed)?,
        };
        finish_upload(self.client, self.nora_base, &location, digest, &blob_data)
            .await
            .map_err(push_failed)?;
        Ok(blob_data.len() as u64)
    }
}

/// Check if a manifest is a manifest list (fat manifest) or OCI index.
fn is_manifest_list(content_type: &str, json: &serde_json::Value) -> bool {
    content_type.contains("manifest.list")
        || content_type.contains("image.index")
        || json.get("manifests").is_some()
}

/// The digest of every manifest an image index lists, in its order. An entry without a
/// digest makes the index unmirrorable: NORA could not hold what it names.
fn index_entry_digests(index: &serde_json::Value) -> Result<Vec<String>, MirrorError> {
    index
        .get("manifests")
        .and_then(|m| m.as_array())
        .ok_or(MirrorError::NoManifestsArray)?
        .iter()
        .map(|m| {
            m.get("digest")
                .and_then(|d| d.as_str())
                .map(String::from)
                .ok_or(MirrorError::EntryWithoutDigest)
        })
        .collect()
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

/// Verify a downloaded artifact's content hash matches the requested digest.
///
/// `what` labels the artifact ("blob"/"manifest") for error messages. `digest`
/// is the `sha256:<hex>` reference; `actual_sha256` is the lowercase hex hash
/// computed over the bytes actually received. Returns `Err` on mismatch so the
/// caller aborts fail-closed and never propagates tampered content (#587/#608).
/// A non-`sha256:` digest is compared verbatim.
fn verify_digest(what: &str, digest: &str, actual_sha256: &str) -> Result<(), String> {
    let expected = digest.strip_prefix("sha256:").unwrap_or(digest);
    if actual_sha256 != expected {
        return Err(format!(
            "{what} {digest} SHA-256 mismatch: upstream returned sha256:{actual_sha256} \
             (refusing to mirror tampered content)"
        ));
    }
    Ok(())
}

/// Verify a downloaded blob's content hash matches the requested digest (#587).
fn verify_blob_digest(digest: &str, actual_sha256: &str) -> Result<(), String> {
    verify_digest("blob", digest, actual_sha256)
}

/// Verify a manifest fetched by digest matches that digest. A no-op when the
/// image reference is a tag (not content-addressed). Closes the manifest-level
/// integrity gap left by #587 — a tampered upstream could otherwise return a
/// different manifest for a requested `sha256:<X>` (#608).
fn verify_manifest_digest(reference: &str, manifest_bytes: &[u8]) -> Result<(), String> {
    if reference.starts_with("sha256:") {
        use sha2::Digest;
        let actual = hex::encode(sha2::Sha256::digest(manifest_bytes));
        return verify_digest("manifest", reference, &actual);
    }
    // A digest-pinned reference with an algorithm we cannot compute must fail
    // closed — silently treating `sha512:…` as unverifiable would be a bypass.
    // A Docker tag never contains ':', so this reliably distinguishes the two.
    if reference.contains(':') {
        return Err(format!(
            "manifest {reference}: unsupported digest algorithm (only sha256 is verifiable)"
        ));
    }
    // Tag reference — not content-addressed, nothing to verify.
    Ok(())
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

/// What NORA did with a blob mount request.
enum Mount {
    /// The blob is in the repository now (it was there, or NORA linked its copy in).
    Mounted,
    /// NORA could not mount it and opened an upload session at this location instead.
    Upload(String),
}

/// The `Location` header of an upload response.
fn upload_location(response: &reqwest::Response) -> Result<String, PushError> {
    response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or(PushError::MissingLocation)
}

/// Ask NORA to mount a blob it already holds for `name` into `name`'s own repository:
/// `POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<name>`. 201 means the repository holds
/// it; per the OCI distribution spec a registry that cannot mount opens an upload (202).
async fn mount_blob(
    client: &Client,
    nora_base: &str,
    name: &str,
    digest: &str,
) -> Result<Mount, PushError> {
    let url = format!(
        "{}/v2/{}/blobs/uploads/?mount={}&from={}",
        nora_base, name, digest, name
    );
    let response = client
        .post(&url)
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
    match response.status().as_u16() {
        201 => Ok(Mount::Mounted),
        202 => upload_location(&response).map(Mount::Upload),
        status => Err(PushError::Status {
            context: "blob mount",
            status,
        }),
    }
}

/// Open an upload session for a blob in `name`; returns its location.
async fn start_upload(client: &Client, nora_base: &str, name: &str) -> Result<String, PushError> {
    let start_url = format!("{}/v2/{}/blobs/uploads/", nora_base, name);
    let response = client
        .post(&start_url)
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
    upload_location(&response)
}

/// Complete an upload session with the whole blob (monolithic upload).
async fn finish_upload(
    client: &Client,
    nora_base: &str,
    location: &str,
    digest: &str,
    data: &[u8],
) -> Result<(), PushError> {
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
        .await?;

    let status = resp.status().as_u16();
    if !resp.status().is_success() && status != 201 {
        return Err(PushError::Status {
            context: "blob upload",
            status,
        });
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
) -> Result<(), PushError> {
    let url = format!("{}/v2/{}/manifests/{}", nora_base, name, reference);
    let resp = client
        .put(&url)
        .header("Content-Type", content_type)
        .body(data.to_vec())
        .timeout(Duration::from_secs(30))
        .send()
        .await?;

    let status = resp.status().as_u16();
    if !resp.status().is_success() && status != 201 {
        return Err(PushError::Status {
            context: "manifest push",
            status,
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // --- verify_blob_digest tests (#587) ---

    /// Regression for #587: the mirror path must abort when an upstream blob's
    /// content hash does not match the requested digest, instead of pushing
    /// tampered bytes onward. `ImageMirror::mirror_blob` gates its upload on
    /// this exact function, so it is the real call-path check, not a vacuum
    /// reimplementation.
    #[test]
    fn verify_blob_digest_rejects_mismatch() {
        let digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let actual = "2222222222222222222222222222222222222222222222222222222222222222";
        let result = verify_blob_digest(digest, actual);
        assert!(result.is_err(), "mismatched hash must be rejected");
        // Error must not leak as a silent success — it carries the digest.
        assert!(result.unwrap_err().contains("mismatch"));
    }

    #[test]
    fn verify_blob_digest_accepts_match() {
        let hex = "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab";
        let digest = format!("sha256:{hex}");
        assert!(verify_blob_digest(&digest, hex).is_ok());
    }

    #[test]
    fn verify_blob_digest_handles_unprefixed_digest() {
        // A bare (non-"sha256:") digest is compared verbatim.
        let hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0";
        assert!(verify_blob_digest(hex, hex).is_ok());
        assert!(verify_blob_digest(
            hex,
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err());
    }

    // --- verify_manifest_digest tests (#608) ---

    /// Regression for #608: a manifest pulled by digest must match that digest
    /// before being mirrored. `mirror_single_image` gates `push_manifest` on
    /// this function via `?`, so it is the real call-path check.
    #[test]
    fn verify_manifest_digest_rejects_tampered() {
        use sha2::Digest;
        let bytes = br#"{"schemaVersion":2,"layers":[]}"#;
        let real = hex::encode(sha2::Sha256::digest(bytes));
        // Reference a DIFFERENT digest than the bytes actually hash to.
        let wrong = format!("sha256:{}", "0".repeat(64));
        assert_ne!(format!("sha256:{real}"), wrong);
        assert!(verify_manifest_digest(&wrong, bytes).is_err());
    }

    #[test]
    fn verify_manifest_digest_accepts_matching() {
        use sha2::Digest;
        let bytes = br#"{"schemaVersion":2,"layers":[]}"#;
        let reference = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
        assert!(verify_manifest_digest(&reference, bytes).is_ok());
    }

    /// A tag reference is not content-addressed, so verification is a no-op
    /// (any bytes pass).
    #[test]
    fn verify_manifest_digest_tag_is_noop() {
        assert!(verify_manifest_digest("latest", b"anything at all").is_ok());
        assert!(verify_manifest_digest("3.20", b"whatever").is_ok());
    }

    /// A digest-pinned reference with a non-sha256 algorithm must fail closed,
    /// not silently pass as unverifiable.
    #[test]
    fn verify_manifest_digest_rejects_unsupported_algorithm() {
        let sha512 = format!("sha512:{}", "a".repeat(128));
        assert!(verify_manifest_digest(&sha512, b"anything").is_err());
    }

    /// Integration regression for #587/#608: when an upstream returns a blob
    /// whose content does not match the digest the manifest references, the
    /// mirror must abort the image and must NOT push anything to NORA. Drives
    /// the real `run_docker_mirror` → `mirror_single_image` path against a mock
    /// upstream; a mock NORA target records requests to prove no push happened.
    #[tokio::test]
    async fn mirror_aborts_on_tampered_blob_and_does_not_push() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // A layer digest the manifest claims, and tampered bytes that DON'T hash
        // to it.
        let layer_digest =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{{"digest":"{layer_digest}","size":3}},"layers":[]}}"#
        );

        // Upstream: serves the manifest and the (tampered) blob.
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/v2/.+/manifests/.+$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "content-type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .set_body_string(manifest),
            )
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/v2/.+/blobs/.+$"))
            .respond_with(ResponseTemplate::new(200).set_body_string("XXX")) // != layer_digest
            .mount(&upstream)
            .await;

        // NORA target: HEAD says "blob absent" (so mirror tries to fetch it);
        // every other request is recorded so we can assert no push occurred.
        let nora = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&nora)
            .await;

        let image = ImageRef {
            registry: upstream.uri(),
            name: "library/tampered".to_string(),
            reference: "latest".to_string(),
        };
        let client = Client::new();
        let result = run_docker_mirror(&client, &nora.uri(), std::slice::from_ref(&image), 1)
            .await
            .expect("mirror run should complete");

        assert_eq!(result.failed, 1, "tampered image must be reported failed");
        assert_eq!(result.fetched, 0, "nothing should be successfully mirrored");

        // No PUT/POST (push) ever reached NORA — only the HEAD existence probe.
        let pushes = nora
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| {
                matches!(
                    r.method,
                    wiremock::http::Method::PUT | wiremock::http::Method::POST
                )
            })
            .count();
        assert_eq!(pushes, 0, "tampered blob must never be pushed to NORA");
    }

    /// Integration regression for #608: when an image is pinned by digest but the
    /// upstream returns a manifest whose content does not hash to that digest,
    /// the mirror must abort BEFORE fetching blobs or pushing — driving the real
    /// `verify_manifest_digest` gate in `mirror_single_image`.
    #[tokio::test]
    async fn mirror_aborts_on_tampered_manifest_by_digest() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Pin by a digest the manifest will NOT hash to.
        let pinned = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/v2/.+/manifests/.+$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "content-type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .set_body_string(
                        r#"{"schemaVersion":2,"config":{"digest":"sha256:abc"},"layers":[]}"#,
                    ),
            )
            .mount(&upstream)
            .await;

        // Any request to NORA would be a bug — manifest verify happens first.
        let nora = MockServer::start().await;

        let image = ImageRef {
            registry: upstream.uri(),
            name: "library/tampered".to_string(),
            reference: pinned.to_string(),
        };
        let client = Client::new();
        let result = run_docker_mirror(&client, &nora.uri(), std::slice::from_ref(&image), 1)
            .await
            .expect("mirror run should complete");

        assert_eq!(result.failed, 1, "digest-mismatched manifest must fail");
        assert_eq!(result.fetched, 0);
        let nora_hits = nora.received_requests().await.unwrap_or_default().len();
        assert_eq!(
            nora_hits, 0,
            "must abort at manifest verify, before any NORA contact"
        );
    }

    /// Integration regression for #608 (multi-arch): a manifest LIST entry is
    /// content-addressed by digest, so the fetched platform sub-manifest must
    /// hash to that digest. A tampered sub-manifest body must abort the mirror —
    /// driving the real gate in `ImageMirror::mirror_manifest`.
    #[tokio::test]
    async fn mirror_aborts_on_tampered_platform_submanifest() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // List references a linux/amd64 sub-manifest at this digest; the body
        // served for it will NOT hash to it.
        let sub_digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        let list = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","manifests":[{{"digest":"{sub_digest}","platform":{{"os":"linux","architecture":"amd64"}}}}]}}"#
        );

        let upstream = MockServer::start().await;
        // Top-level (by tag) → the list.
        Mock::given(method("GET"))
            .and(path_regex(r"/manifests/latest$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "content-type",
                        "application/vnd.docker.distribution.manifest.list.v2+json",
                    )
                    .set_body_string(list),
            )
            .mount(&upstream)
            .await;
        // The platform sub-manifest fetched by digest → tampered body.
        Mock::given(method("GET"))
            .and(path_regex(r"/manifests/sha256:.+$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "content-type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .set_body_string(r#"{"schemaVersion":2,"layers":[]}"#), // != sub_digest
            )
            .mount(&upstream)
            .await;

        let nora = MockServer::start().await;

        let image = ImageRef {
            registry: upstream.uri(),
            name: "library/multiarch".to_string(),
            reference: "latest".to_string(),
        };
        let client = Client::new();
        let result = run_docker_mirror(&client, &nora.uri(), std::slice::from_ref(&image), 1)
            .await
            .expect("mirror run should complete");

        assert_eq!(
            result.failed, 1,
            "tampered sub-manifest must fail the image"
        );
        assert_eq!(result.fetched, 0);
        let nora_hits = nora.received_requests().await.unwrap_or_default().len();
        assert_eq!(nora_hits, 0, "must abort before pushing the swapped layers");
    }

    // --- an image index mirrors whole (#1184) ---

    /// `sha256:<hex>` of some bytes.
    fn digest_of(bytes: &[u8]) -> String {
        use sha2::Digest;
        format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
    }

    const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
    const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

    /// An upstream image laid out the way Docker Hub serves `alpine:3.20`: an OCI index whose
    /// entries are a linux/amd64 manifest, that manifest's attestation (platform
    /// `unknown/unknown`) and a linux/arm64 manifest, each with its own config and layer.
    struct IndexedImage {
        index: Vec<u8>,
        index_digest: String,
        /// Every manifest the index references: (digest, body).
        manifests: Vec<(String, Vec<u8>)>,
        /// Every blob those manifests reference: (digest, body).
        blobs: Vec<(String, Vec<u8>)>,
    }

    impl IndexedImage {
        fn new() -> Self {
            let mut blobs = Vec::new();
            let mut manifests = Vec::new();
            let mut entries = Vec::new();
            for (label, platform) in [
                ("amd64", r#"{"architecture":"amd64","os":"linux"}"#),
                (
                    "attestation",
                    r#"{"architecture":"unknown","os":"unknown"}"#,
                ),
                ("arm64", r#"{"architecture":"arm64","os":"linux"}"#),
            ] {
                let config = format!(r#"{{"label":"{label}"}}"#).into_bytes();
                let layer = format!("the {label} layer").into_bytes();
                let manifest = format!(
                    r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{}","size":{}}}]}}"#,
                    digest_of(&config),
                    config.len(),
                    digest_of(&layer),
                    layer.len()
                )
                .into_bytes();
                entries.push(format!(
                    r#"{{"mediaType":"{OCI_MANIFEST}","digest":"{}","size":{},"platform":{platform}}}"#,
                    digest_of(&manifest),
                    manifest.len()
                ));
                blobs.push((digest_of(&config), config));
                blobs.push((digest_of(&layer), layer));
                manifests.push((digest_of(&manifest), manifest));
            }
            let index = format!(
                r#"{{"schemaVersion":2,"mediaType":"{OCI_INDEX}","manifests":[{}]}}"#,
                entries.join(",")
            )
            .into_bytes();
            Self {
                index_digest: digest_of(&index),
                index,
                manifests,
                blobs,
            }
        }

        /// Serve the image as `library/demo:3.20` (and the index by its digest).
        async fn serve(&self) -> wiremock::MockServer {
            use wiremock::matchers::path;
            use wiremock::{Mock, MockServer, ResponseTemplate};
            let upstream = MockServer::start().await;
            let body = |ct: &str, b: &[u8]| {
                ResponseTemplate::new(200)
                    .insert_header("content-type", ct)
                    .insert_header("docker-content-digest", digest_of(b).as_str())
                    .set_body_bytes(b.to_vec())
            };
            for reference in ["3.20", self.index_digest.as_str()] {
                Mock::given(path(format!("/v2/library/demo/manifests/{reference}")))
                    .respond_with(body(OCI_INDEX, &self.index))
                    .mount(&upstream)
                    .await;
            }
            for (d, m) in &self.manifests {
                Mock::given(path(format!("/v2/library/demo/manifests/{d}")))
                    .respond_with(body(OCI_MANIFEST, m))
                    .mount(&upstream)
                    .await;
            }
            for (d, b) in &self.blobs {
                Mock::given(path(format!("/v2/library/demo/blobs/{d}")))
                    .respond_with(body("application/octet-stream", b))
                    .mount(&upstream)
                    .await;
            }
            upstream
        }
    }

    /// A NORA instance served over real HTTP, as `nora mirror` talks to one; the server
    /// stops when this is dropped.
    struct ServedNora {
        url: String,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for ServedNora {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    async fn serve_nora(ctx: &crate::test_helpers::TestContext) -> ServedNora {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = ctx.app.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        ServedNora { url, server }
    }

    /// GET through NORA: status, `Docker-Content-Digest` and body.
    async fn nora_get(
        ctx: &crate::test_helpers::TestContext,
        uri: &str,
    ) -> (u16, Option<String>, Vec<u8>) {
        let response = crate::test_helpers::send_with_headers(
            &ctx.app,
            axum::http::Method::GET,
            uri,
            vec![("accept", &format!("{OCI_INDEX}, {OCI_MANIFEST}"))],
            "",
        )
        .await;
        let status = response.status().as_u16();
        let digest = response
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let body = crate::test_helpers::body_bytes(response).await.to_vec();
        (status, digest, body)
    }

    fn demo(upstream: &wiremock::MockServer, reference: &str) -> ImageRef {
        ImageRef {
            registry: upstream.uri(),
            name: "library/demo".to_string(),
            reference: reference.to_string(),
        }
    }

    /// #1184: `nora mirror docker --images alpine:3.20` failed with "references an absent
    /// blob/sub-manifest (sha256:6243dec9…)" — that digest is the second entry of the
    /// alpine:3.20 index, the amd64 attestation. The mirror stored one platform and pushed an
    /// index that names them all. Now every manifest the index references, and every blob
    /// those reference, is in NORA before the index; with no upstream configured, NORA serves
    /// the whole image from what the mirror stored.
    #[tokio::test]
    async fn mirror_stores_every_manifest_an_index_references() {
        let image = IndexedImage::new();
        let upstream = image.serve().await;
        let ctx = crate::test_helpers::create_test_context_in_memory(|_| {});
        let nora = serve_nora(&ctx).await;
        let nora_url = nora.url.as_str();

        let result = run_docker_mirror(&Client::new(), nora_url, &[demo(&upstream, "3.20")], 1)
            .await
            .expect("mirror run completes");
        assert_eq!((result.fetched, result.failed), (1, 0), "the image mirrors");
        drop(upstream);

        let (status, digest, body) = nora_get(&ctx, "/v2/library/demo/manifests/3.20").await;
        assert_eq!(status, 200, "the tag is served");
        assert_eq!(digest.as_deref(), Some(image.index_digest.as_str()));
        assert_eq!(
            body, image.index,
            "the tag is the upstream index, byte for byte"
        );
        for (d, m) in &image.manifests {
            let (status, _, body) =
                nora_get(&ctx, &format!("/v2/library/demo/manifests/{d}")).await;
            assert_eq!(status, 200, "sub-manifest {d} is stored");
            assert_eq!(&body, m);
        }
        for (d, b) in &image.blobs {
            let (status, _, body) = nora_get(&ctx, &format!("/v2/library/demo/blobs/{d}")).await;
            assert_eq!(status, 200, "blob {d} is stored");
            assert_eq!(&body, b);
        }
    }

    /// #1184, an image pinned by its index digest (`alpine@sha256:<index>`): the platform
    /// manifests go in under their own digests and the index under the pinned one.
    #[tokio::test]
    async fn mirror_by_index_digest_stores_the_index_under_it() {
        let image = IndexedImage::new();
        let upstream = image.serve().await;
        let ctx = crate::test_helpers::create_test_context_in_memory(|_| {});
        let nora = serve_nora(&ctx).await;
        let nora_url = nora.url.as_str();

        let pinned = demo(&upstream, &image.index_digest);
        let result = run_docker_mirror(&Client::new(), nora_url, &[pinned], 1)
            .await
            .expect("mirror run completes");
        assert_eq!((result.fetched, result.failed), (1, 0), "the image mirrors");
        drop(upstream);

        let uri = format!("/v2/library/demo/manifests/{}", image.index_digest);
        let (status, _, body) = nora_get(&ctx, &uri).await;
        assert_eq!(status, 200);
        assert_eq!(body, image.index);
    }

    /// #1184, after a `docker pull` of the image through NORA: the pull cached the amd64
    /// blobs, so NORA's HEAD answers 200 for them, but a manifest pushed to the repository is
    /// checked against what the repository itself holds. The mirror must leave every blob in
    /// the repository, not skip the cached ones and have the manifest refused.
    #[tokio::test]
    async fn mirror_after_a_pull_through_nora_still_mirrors() {
        let image = IndexedImage::new();
        let upstream = image.serve().await;
        let url = upstream.uri();
        let ctx = crate::test_helpers::create_test_context_in_memory(|cfg| {
            cfg.docker.upstreams = vec![crate::test_helpers::docker_upstream(url)];
        });
        let nora = serve_nora(&ctx).await;
        let nora_url = nora.url.as_str();

        // `docker pull` on amd64: the index, the amd64 manifest, its config and layer.
        let (amd64, amd64_manifest) = &image.manifests[0];
        assert_eq!(
            nora_get(&ctx, "/v2/library/demo/manifests/3.20").await.0,
            200
        );
        assert_eq!(
            nora_get(&ctx, &format!("/v2/library/demo/manifests/{amd64}"))
                .await
                .0,
            200
        );
        let manifest: serde_json::Value = serde_json::from_slice(amd64_manifest).unwrap();
        let pulled = extract_blob_digests(&manifest);
        let client = Client::new();
        for d in &pulled {
            assert_eq!(
                nora_get(&ctx, &format!("/v2/library/demo/blobs/{d}"))
                    .await
                    .0,
                200
            );
        }
        // The cache fill lands in the background: wait until NORA's HEAD reports every pulled
        // blob present, which is the answer that used to make the mirror skip them.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        for d in &pulled {
            while !blob_exists(&client, nora_url, "library/demo", d).await {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the pulled blob {d} never became visible to HEAD"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        let result = run_docker_mirror(&client, nora_url, &[demo(&upstream, "3.20")], 1)
            .await
            .expect("mirror run completes");
        assert_eq!((result.fetched, result.failed), (1, 0), "the image mirrors");

        let (status, digest, _) = nora_get(&ctx, "/v2/library/demo/manifests/3.20").await;
        assert_eq!(status, 200);
        assert_eq!(digest.as_deref(), Some(image.index_digest.as_str()));
    }

    /// Wrap `inner` in `levels` image indexes, each listing the one below; returns the
    /// outermost index and every wrapper as (digest, body), outermost first.
    fn wrap_in_indexes(inner: &[u8], levels: usize) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
        let mut wrappers = Vec::new();
        let mut current = inner.to_vec();
        for _ in 0..levels {
            current = format!(
                r#"{{"schemaVersion":2,"mediaType":"{OCI_INDEX}","manifests":[{{"mediaType":"{OCI_INDEX}","digest":"{}","size":{}}}]}}"#,
                digest_of(&current),
                current.len()
            )
            .into_bytes();
            wrappers.push((digest_of(&current), current.clone()));
        }
        wrappers.reverse();
        (current, wrappers)
    }

    /// Serve `top` as `library/demo:nested`, and every listed index by its digest, on top of
    /// the [`IndexedImage`] fixture.
    async fn serve_nested(
        image: &IndexedImage,
        top: &[u8],
        wrappers: &[(String, Vec<u8>)],
    ) -> wiremock::MockServer {
        use wiremock::matchers::path;
        use wiremock::{Mock, ResponseTemplate};
        let upstream = image.serve().await;
        let mut served: Vec<(String, Vec<u8>)> = wrappers.to_vec();
        served.push(("nested".to_string(), top.to_vec()));
        for (reference, body) in served {
            Mock::given(path(format!("/v2/library/demo/manifests/{reference}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", OCI_INDEX)
                        .set_body_bytes(body),
                )
                .mount(&upstream)
                .await;
        }
        upstream
    }

    /// An index may list an index (valid OCI): the mirror walks down to the image manifests
    /// and stores every level before the one that lists it.
    #[tokio::test]
    async fn mirror_stores_an_index_that_lists_an_index() {
        let image = IndexedImage::new();
        let (top, wrappers) = wrap_in_indexes(&image.index, 1);
        let upstream = serve_nested(&image, &top, &wrappers[1..]).await;
        let ctx = crate::test_helpers::create_test_context_in_memory(|_| {});
        let nora = serve_nora(&ctx).await;
        let nora_url = nora.url.as_str();

        let result = run_docker_mirror(&Client::new(), nora_url, &[demo(&upstream, "nested")], 1)
            .await
            .expect("mirror run completes");
        assert_eq!((result.fetched, result.failed), (1, 0), "the image mirrors");
        drop(upstream);

        let (status, _, body) = nora_get(&ctx, "/v2/library/demo/manifests/nested").await;
        assert_eq!((status, body), (200, top));
        let inner = format!("/v2/library/demo/manifests/{}", image.index_digest);
        assert_eq!(nora_get(&ctx, &inner).await.0, 200, "the listed index");
        for (d, _) in &image.blobs {
            let blob = format!("/v2/library/demo/blobs/{d}");
            assert_eq!(nora_get(&ctx, &blob).await.0, 200, "blob {d}");
        }
    }

    /// Indexes nested past `MAX_INDEX_DEPTH` are refused before anything reaches NORA.
    #[tokio::test]
    async fn mirror_refuses_indexes_nested_too_deep() {
        let image = IndexedImage::new();
        let (top, wrappers) = wrap_in_indexes(&image.index, MAX_INDEX_DEPTH);
        let upstream = serve_nested(&image, &top, &wrappers[1..]).await;
        let nora = wiremock::MockServer::start().await;

        let result =
            run_docker_mirror(&Client::new(), &nora.uri(), &[demo(&upstream, "nested")], 1)
                .await
                .expect("mirror run completes");
        assert_eq!(
            (result.fetched, result.failed),
            (0, 1),
            "the image is refused"
        );
        let nora_hits = nora.received_requests().await.unwrap_or_default().len();
        assert_eq!(nora_hits, 0, "nothing is pushed for a refused image");
    }

    /// #1184, a NORA that reports a blob but does not mount it (a server without cross-repo
    /// mount answers 202 with an upload session, as the OCI distribution spec has it): the
    /// mirror fetches the blob and completes that session, rather than taking the HEAD 200
    /// as the blob being in the repository.
    #[tokio::test]
    async fn mirror_uploads_a_blob_nora_reports_but_does_not_mount() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let layer = b"a layer NORA reports but cannot mount".to_vec();
        let layer_digest = digest_of(&layer);
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"{OCI_MANIFEST}","config":{{"digest":"{layer_digest}","size":{}}},"layers":[]}}"#,
            layer.len()
        );
        let upstream = MockServer::start().await;
        Mock::given(path("/v2/library/demo/manifests/1.0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", OCI_MANIFEST)
                    .set_body_string(manifest),
            )
            .mount(&upstream)
            .await;
        Mock::given(path(format!("/v2/library/demo/blobs/{layer_digest}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(layer.clone()))
            .mount(&upstream)
            .await;

        let nora = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&nora)
            .await;
        Mock::given(method("POST"))
            .and(path("/v2/library/demo/blobs/uploads/"))
            .and(query_param("mount", layer_digest.as_str()))
            .and(query_param("from", "library/demo"))
            .respond_with(
                ResponseTemplate::new(202)
                    .insert_header("location", "/v2/library/demo/blobs/uploads/session-1"),
            )
            .mount(&nora)
            .await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&nora)
            .await;

        let result = run_docker_mirror(&Client::new(), &nora.uri(), &[demo(&upstream, "1.0")], 1)
            .await
            .expect("mirror run completes");
        assert_eq!((result.fetched, result.failed), (1, 0), "the image mirrors");

        let requests = nora.received_requests().await.unwrap_or_default();
        let posts = requests
            .iter()
            .filter(|r| r.method == wiremock::http::Method::POST)
            .count();
        assert_eq!(
            posts, 1,
            "the mount's session is used, no second one opened"
        );
        let upload = requests
            .iter()
            .find(|r| r.url.path() == "/v2/library/demo/blobs/uploads/session-1")
            .expect("the blob goes into the session the mount opened");
        assert_eq!(upload.method, wiremock::http::Method::PUT);
        assert_eq!(upload.body, layer, "the blob itself is uploaded");
    }

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
