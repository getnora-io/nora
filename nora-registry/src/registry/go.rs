// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Go module proxy (GOPROXY protocol).
//!
//! Implements the 5 required endpoints:
//!   GET /go/{module}/@v/list        — list known versions
//!   GET /go/{module}/@v/{ver}.info  — version metadata (JSON)
//!   GET /go/{module}/@v/{ver}.mod   — go.mod file
//!   GET /go/{module}/@v/{ver}.zip   — module zip archive
//!   GET /go/{module}/@latest        — latest version info

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::{circuit_open_response, proxy_fetch, proxy_fetch_text, ProxyError};
use crate::validation::ends_with_ci;
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use percent_encoding::percent_decode;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/go/{*path}", get(handle))
}

/// Main handler — parses the wildcard path and dispatches to the right logic.
async fn handle(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
) -> Response {
    // URL-decode the path: Go client sends %21 for !, Axum wildcard may not decode it
    let path = percent_decode(path.as_bytes())
        .decode_utf8()
        .map(|s| s.into_owned())
        .unwrap_or(path);

    tracing::debug!(path = %path, "Go proxy request");

    // Validate path: no traversal, no null bytes
    if !is_safe_path(&path) {
        tracing::debug!(path = %path, "Go proxy: unsafe path");
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Split: "github.com/!azure/sdk/@v/v1.0.0.info" → module + file
    let (module_encoded, file) = match split_go_path(&path) {
        Some(parts) => parts,
        None => {
            tracing::debug!(path = %path, "Go proxy: cannot split path");
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    // Parse curation coords for .zip downloads (used in both pre-download and integrity checks)
    let go_curation = if ends_with_ci(&file, ".zip") {
        let module_name =
            decode_module_path(&module_encoded).unwrap_or_else(|_| module_encoded.clone());
        let version = file
            .strip_prefix("@v/")
            .and_then(|f| f.strip_suffix(".zip"))
            .map(|v| v.to_string());
        Some((module_name, version))
    } else {
        None
    };

    // Curation check — .zip downloads only (metadata passes through)
    if let Some((ref module_name, ref version)) = go_curation {
        // Extract publish date from cached .info file
        let publish_date = if let Some(ref ver) = version {
            let info_key = format!("go/{}/@v/{}.info", module_encoded, ver);
            extract_go_publish_date(&state.storage, &info_key).await
        } else {
            None
        };

        if let Some(response) = crate::curation::check_download(
            &state.curation,
            state.config.curation.bypass_token.as_deref(),
            &headers,
            crate::curation::RegistryType::Go,
            module_name,
            version.as_deref(),
            publish_date,
        ) {
            return response;
        }
    }

    let storage_key = format!("go/{}", path);
    let content_type = content_type_for(&file);

    // Mutable endpoints: @v/list and @latest can be refreshed from upstream
    let is_mutable = file == "@v/list" || file == "@latest";
    // Immutable: .info, .mod, .zip — once cached, never overwrite
    let is_immutable = !is_mutable;

    // 1. Try local cache (for immutable files, this is authoritative)
    if let Ok(data) = state.storage.get(&storage_key).await {
        // Curation integrity verification (issue #189)
        if let Some((ref module_name, ref version)) = go_curation {
            if let Some(response) = crate::curation::verify_integrity(
                &state.curation,
                crate::curation::RegistryType::Go,
                module_name,
                version.as_deref(),
                &data,
            ) {
                return response;
            }
        }

        state.metrics.record_download("go");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            format_artifact(&module_encoded, &file),
            "go",
            "CACHE",
        ));
        return with_content_type(data.to_vec(), content_type);
    }

    // 2. Try upstream proxy
    let proxy_url = match &state.config.go.proxy {
        Some(url) => url.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // Validate module path encoding (but keep encoded for upstream — proxy.golang.org expects ! encoding)
    if decode_module_path(&module_encoded).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let upstream_url = format!(
        "{}/{}",
        proxy_url.trim_end_matches('/'),
        format_upstream_path(&module_encoded, &file)
    );

    // Use longer timeout for .zip files
    let timeout = if ends_with_ci(&file, ".zip") {
        state.config.go.proxy_timeout_zip
    } else {
        state.config.go.proxy_timeout
    };

    // Fetch: binary for .zip, text for everything else
    let data = if ends_with_ci(&file, ".zip") {
        proxy_fetch(
            &state.http_client,
            &upstream_url,
            timeout,
            state.config.go.proxy_auth.as_deref(),
            &state.circuit_breaker,
            "go",
        )
        .await
    } else {
        proxy_fetch_text(
            &state.http_client,
            &upstream_url,
            timeout,
            state.config.go.proxy_auth.as_deref(),
            None,
            &state.circuit_breaker,
            "go",
        )
        .await
        .map(|s| s.into_bytes())
    };

    match data {
        Ok(bytes) => {
            // Enforce size limit for .zip
            if ends_with_ci(&file, ".zip") && bytes.len() as u64 > state.config.go.max_zip_size {
                tracing::warn!(
                    module = module_encoded,
                    size = bytes.len(),
                    limit = state.config.go.max_zip_size,
                    "Go module zip exceeds size limit"
                );
                return StatusCode::PAYLOAD_TOO_LARGE.into_response();
            }

            state.metrics.record_download("go");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format_artifact(&module_encoded, &file),
                "go",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "go", ""));

            // Background cache: immutable = put_if_absent, mutable = always overwrite
            let storage = state.storage.clone();
            let key = storage_key.clone();
            let data_clone = bytes.clone();
            tokio::spawn(async move {
                if is_immutable {
                    // Only write if not already cached (immutability guarantee)
                    if storage.stat(&key).await.is_none() {
                        let _ = storage.put(&key, &data_clone).await;
                    }
                } else {
                    let _ = storage.put(&key, &data_clone).await;
                }
            });

            state.repo_index.invalidate("go");
            with_content_type(bytes, content_type)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(
                module = module_encoded,
                file = file,
                error = ?e,
                "Go upstream proxy error"
            );
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ============================================================================
// Module path encoding/decoding
// ============================================================================

/// Extract publish date from a cached Go .info file.
///
/// Go .info JSON has a `Time` field in RFC 3339 format:
/// ```json
/// { "Version": "v1.0.0", "Time": "2024-01-15T10:30:00Z" }
/// ```
async fn extract_go_publish_date(storage: &crate::storage::Storage, info_key: &str) -> Option<i64> {
    let data = storage.get(info_key).await.ok()?;
    let json: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let date_str = json.get("Time")?.as_str()?;
    crate::curation::parse_iso8601_to_unix(date_str)
}

/// Decode Go module path: `!x` → `X`
///
/// Go module proxy spec requires uppercase letters to be encoded as `!`
/// followed by the lowercase letter. Raw uppercase in encoded path is invalid.
fn decode_module_path(encoded: &str) -> Result<String, ()> {
    let mut result = String::with_capacity(encoded.len());
    let mut chars = encoded.chars();
    while let Some(c) = chars.next() {
        if c == '!' {
            match chars.next() {
                Some(next) if next.is_ascii_lowercase() => {
                    result.push(next.to_ascii_uppercase());
                }
                _ => return Err(()),
            }
        } else if c.is_ascii_uppercase() {
            // Raw uppercase in encoded path is invalid per spec
            return Err(());
        } else {
            result.push(c);
        }
    }
    Ok(result)
}

/// Encode Go module path: `X` → `!x`
#[cfg(test)]
fn encode_module_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len() + 8);
    for c in path.chars() {
        if c.is_ascii_uppercase() {
            result.push('!');
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }
    result
}

// ============================================================================
// Path parsing helpers
// ============================================================================

/// Split Go path into (encoded_module, file).
///
/// Examples:
///   "github.com/user/repo/@v/v1.0.0.info" → ("github.com/user/repo", "@v/v1.0.0.info")
///   "github.com/user/repo/v2/@v/list"     → ("github.com/user/repo/v2", "@v/list")
///   "github.com/user/repo/@latest"        → ("github.com/user/repo", "@latest")
fn split_go_path(path: &str) -> Option<(String, String)> {
    // Try @latest first (it's simpler)
    if let Some(pos) = path.rfind("/@latest") {
        let module = &path[..pos];
        if !module.is_empty() {
            return Some((module.to_string(), "@latest".to_string()));
        }
    }

    // Try @v/ — find the last occurrence (handles /v2/@v/ correctly)
    if let Some(pos) = path.rfind("/@v/") {
        let module = &path[..pos];
        let file = &path[pos + 1..]; // "@v/..."
        if !module.is_empty() && !file.is_empty() {
            return Some((module.to_string(), file.to_string()));
        }
    }

    None
}

/// Path validation: no traversal attacks
fn is_safe_path(path: &str) -> bool {
    !path.contains("..")
        && !path.starts_with('/')
        && !path.contains("//")
        && !path.contains('\0')
        && !path.is_empty()
}

/// Content-Type for Go proxy responses
fn content_type_for(file: &str) -> &'static str {
    if ends_with_ci(file, ".info") || file == "@latest" {
        "application/json"
    } else if ends_with_ci(file, ".zip") {
        "application/zip"
    } else {
        // .mod, @v/list
        "text/plain; charset=utf-8"
    }
}

/// Build upstream URL path (uses decoded module path)
fn format_upstream_path(module_decoded: &str, file: &str) -> String {
    format!("{}/{}", module_decoded, file)
}

/// Human-readable artifact name for activity log
fn format_artifact(module: &str, file: &str) -> String {
    if file == "@v/list" || file == "@latest" {
        format!("{} {}", module, file)
    } else if let Some(version_file) = file.strip_prefix("@v/") {
        // "v1.0.0.info" → "module@v1.0.0"
        let version = version_file
            .rsplit_once('.')
            .map(|(v, _ext)| v)
            .unwrap_or(version_file);
        format!("{}@{}", module, version)
    } else {
        format!("{}/{}", module, file)
    }
}

/// Build response with Content-Type header
fn with_content_type(data: Vec<u8>, content_type: &'static str) -> Response {
    // .zip and .mod are content-addressed/versioned (immutable)
    // .info, list, @latest are metadata (mutable)
    let cache_control = if content_type == "application/zip" || content_type == "text/plain" {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=60, must-revalidate"
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static(cache_control),
            ),
        ],
        data,
    )
        .into_response()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── Encoding/decoding ───────────────────────────────────────────────

    #[test]
    fn test_decode_azure() {
        assert_eq!(
            decode_module_path("github.com/!azure/sdk").unwrap(),
            "github.com/Azure/sdk"
        );
    }

    #[test]
    fn test_decode_multiple_uppercase() {
        assert_eq!(
            decode_module_path("!google!cloud!platform/foo").unwrap(),
            "GoogleCloudPlatform/foo"
        );
    }

    #[test]
    fn test_decode_no_uppercase() {
        assert_eq!(
            decode_module_path("github.com/user/repo").unwrap(),
            "github.com/user/repo"
        );
    }

    #[test]
    fn test_decode_invalid_bang_at_end() {
        assert!(decode_module_path("foo!").is_err());
    }

    #[test]
    fn test_decode_invalid_bang_followed_by_uppercase() {
        assert!(decode_module_path("foo!A").is_err());
    }

    #[test]
    fn test_decode_raw_uppercase_is_invalid() {
        assert!(decode_module_path("github.com/Azure/sdk").is_err());
    }

    #[test]
    fn test_encode_roundtrip() {
        let original = "github.com/Azure/azure-sdk-for-go";
        let encoded = encode_module_path(original);
        assert_eq!(encoded, "github.com/!azure/azure-sdk-for-go");
        assert_eq!(decode_module_path(&encoded).unwrap(), original);
    }

    #[test]
    fn test_encode_no_change() {
        assert_eq!(
            encode_module_path("github.com/user/repo"),
            "github.com/user/repo"
        );
    }

    // ── Path splitting ──────────────────────────────────────────────────

    #[test]
    fn test_split_version_info() {
        let (module, file) = split_go_path("github.com/user/repo/@v/v1.0.0.info").unwrap();
        assert_eq!(module, "github.com/user/repo");
        assert_eq!(file, "@v/v1.0.0.info");
    }

    #[test]
    fn test_split_version_list() {
        let (module, file) = split_go_path("github.com/user/repo/@v/list").unwrap();
        assert_eq!(module, "github.com/user/repo");
        assert_eq!(file, "@v/list");
    }

    #[test]
    fn test_split_latest() {
        let (module, file) = split_go_path("github.com/user/repo/@latest").unwrap();
        assert_eq!(module, "github.com/user/repo");
        assert_eq!(file, "@latest");
    }

    #[test]
    fn test_split_major_version_suffix() {
        let (module, file) = split_go_path("github.com/user/repo/v2/@v/list").unwrap();
        assert_eq!(module, "github.com/user/repo/v2");
        assert_eq!(file, "@v/list");
    }

    #[test]
    fn test_split_incompatible_version() {
        let (module, file) =
            split_go_path("github.com/user/repo/@v/v4.1.2+incompatible.info").unwrap();
        assert_eq!(module, "github.com/user/repo");
        assert_eq!(file, "@v/v4.1.2+incompatible.info");
    }

    #[test]
    fn test_split_pseudo_version() {
        let (module, file) =
            split_go_path("github.com/user/repo/@v/v0.0.0-20210101000000-abcdef123456.info")
                .unwrap();
        assert_eq!(module, "github.com/user/repo");
        assert_eq!(file, "@v/v0.0.0-20210101000000-abcdef123456.info");
    }

    #[test]
    fn test_split_no_at() {
        assert!(split_go_path("github.com/user/repo/v1.0.0").is_none());
    }

    #[test]
    fn test_split_empty_module() {
        assert!(split_go_path("/@v/list").is_none());
    }

    // ── Path safety ─────────────────────────────────────────────────────

    #[test]
    fn test_safe_path_normal() {
        assert!(is_safe_path("github.com/user/repo/@v/list"));
    }

    #[test]
    fn test_reject_traversal() {
        assert!(!is_safe_path("../../etc/passwd"));
    }

    #[test]
    fn test_reject_absolute() {
        assert!(!is_safe_path("/etc/passwd"));
    }

    #[test]
    fn test_reject_double_slash() {
        assert!(!is_safe_path("github.com//evil/@v/list"));
    }

    #[test]
    fn test_reject_null() {
        assert!(!is_safe_path("github.com/\0evil/@v/list"));
    }

    #[test]
    fn test_reject_empty() {
        assert!(!is_safe_path(""));
    }

    // ── Content-Type ────────────────────────────────────────────────────

    #[test]
    fn test_content_type_info() {
        assert_eq!(content_type_for("@v/v1.0.0.info"), "application/json");
    }

    #[test]
    fn test_content_type_latest() {
        assert_eq!(content_type_for("@latest"), "application/json");
    }

    #[test]
    fn test_content_type_zip() {
        assert_eq!(content_type_for("@v/v1.0.0.zip"), "application/zip");
    }

    #[test]
    fn test_content_type_mod() {
        assert_eq!(
            content_type_for("@v/v1.0.0.mod"),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn test_content_type_list() {
        assert_eq!(content_type_for("@v/list"), "text/plain; charset=utf-8");
    }

    // ── Artifact formatting ─────────────────────────────────────────────

    #[test]
    fn test_format_artifact_version() {
        assert_eq!(
            format_artifact("github.com/user/repo", "@v/v1.0.0.info"),
            "github.com/user/repo@v1.0.0"
        );
    }

    #[test]
    fn test_format_artifact_list() {
        assert_eq!(
            format_artifact("github.com/user/repo", "@v/list"),
            "github.com/user/repo @v/list"
        );
    }

    #[test]
    fn test_format_artifact_latest() {
        assert_eq!(
            format_artifact("github.com/user/repo", "@latest"),
            "github.com/user/repo @latest"
        );
    }

    #[test]
    fn test_format_artifact_zip() {
        assert_eq!(
            format_artifact("github.com/user/repo", "@v/v1.0.0.zip"),
            "github.com/user/repo@v1.0.0"
        );
    }
}
