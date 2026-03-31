#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]
//! NORA Registry — library interface for fuzzing and testing

pub mod validation;

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
