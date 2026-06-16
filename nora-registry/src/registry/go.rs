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
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::validation::ends_with_ci;
use crate::AppState;
use axum::body::Bytes;
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use percent_encoding::percent_decode;
use std::time::Duration;

pub fn routes() -> Router<AppState> {
    Router::new().route("/go/{*path}", get(handle))
}

/// Main handler — parses the wildcard path and dispatches to the right logic.
async fn handle(
    State(state): State<AppState>,
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
            extract_go_publish_date(
                &state.storage,
                &info_key,
                state.config.server.trust_upstream_dates,
            )
            .await
        } else {
            None
        };

        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
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

    // Mutable endpoints: @v/list, @latest, and a non-canonical `@v/<query>.info` (a branch,
    // revision, or partial version like `v1`/`v1.2`) all resolve to a moving target and may be
    // refreshed from upstream. A canonical-version .info/.mod/.zip names an immutable snapshot.
    let is_mutable = file == "@v/list" || file == "@latest" || is_noncanonical_info_query(&file);
    // Immutable: once cached, never overwrite.
    let is_immutable = !is_mutable;

    // 1. Try local cache.
    //    Immutable files (.info/.mod/.zip) are content-addressed by an exact version and are
    //    authoritative once cached. The mutable listing endpoints (@v/list, @latest) must be
    //    revalidated against upstream before serving — otherwise a newly published version never
    //    appears — unless there is no upstream (locally authoritative) or the cached copy is still
    //    within the positive `metadata_ttl` window. `cached` is kept for the stale-on-error path.
    let cached = state.storage.get(&storage_key).await.ok();
    let modified = if cached.is_some() && is_mutable {
        state.storage.stat(&storage_key).await.map(|m| m.modified)
    } else {
        None
    };
    let cache_fresh = cached.is_some()
        && go_cache_fresh(
            is_immutable,
            state.config.go.proxy.is_some(),
            state.config.go.metadata_ttl,
            modified,
        );
    if let Some(ref data) = cached {
        if cache_fresh {
            // Curation integrity verification (issue #189)
            if let Some((ref module_name, ref version)) = go_curation {
                if let Some(response) = crate::curation::verify_integrity(
                    &state.curation().curation_engine,
                    crate::curation::RegistryType::Go,
                    module_name,
                    version.as_deref(),
                    data,
                ) {
                    return response;
                }
            }

            state.metrics.record_download("go");
            state.metrics.record_cache_hit("go");
            state.activity.push(ActivityEntry::new(
                ActionType::CacheHit,
                format_artifact(&module_encoded, &file),
                "go",
                "CACHE",
            ));
            return with_content_type(data.to_vec(), content_type, is_mutable);
        }
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

    // #68 namespace isolation: an internal-namespace module must never be fetched
    // upstream (dependency confusion). The fresh-cache fast path above already served
    // a fresh copy; here, serve any stale cached copy rather than re-proxying, and
    // block only when nothing is cached — never proxy. (The .zip artifact path also
    // runs check_download.)
    let module_path =
        decode_module_path(&module_encoded).unwrap_or_else(|_| module_encoded.clone());
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Go,
        &module_path,
    ) {
        if let Some(ref data) = cached {
            state.metrics.record_cache_hit("go");
            return with_content_type(data.to_vec(), content_type, is_mutable);
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Go,
            &module_path,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    let upstream_url = format!(
        "{}/{}",
        proxy_url.trim_end_matches('/'),
        format_upstream_path(&module_encoded, &file)
    );

    // Use longer timeout for .zip files
    let timeout = Duration::from_secs(if ends_with_ci(&file, ".zip") {
        state.config.go.proxy_timeout_zip
    } else {
        state.config.go.proxy_timeout
    });

    // Fetch: binary for .zip, text for everything else
    let data = if ends_with_ci(&file, ".zip") {
        proxy_fetch(
            &state.http_client,
            &upstream_url,
            timeout,
            expose_opt(&state.config.go.proxy_auth),
            &state.circuit_breaker,
            RegistryType::Go,
        )
        .await
    } else {
        proxy_fetch_text(
            &state.http_client,
            &upstream_url,
            timeout,
            expose_opt(&state.config.go.proxy_auth),
            None,
            &state.circuit_breaker,
            RegistryType::Go,
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
            state.metrics.record_cache_miss("go");
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
            if is_immutable {
                state.spawn_cache_immutable("go", storage_key, Bytes::from(bytes.clone()));
            } else {
                state.spawn_cache("go", storage_key, Bytes::from(bytes.clone()));
            }

            with_content_type(bytes, content_type, is_mutable)
        }
        Err(e) => {
            // Upstream unreachable — serve the stale cached copy if we have one (graceful).
            // Only the mutable listing endpoints reach here with a cached copy; immutable hits
            // returned above, so this never serves a wrong content-addressed file.
            if let Some(ref data) = cached {
                tracing::warn!(
                    module = module_encoded,
                    file = file,
                    "Go upstream failed, serving stale cached copy"
                );
                let mut response = with_content_type(data.to_vec(), content_type, is_mutable);
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static("x-nora-stale"),
                    axum::http::header::HeaderValue::from_static("true"),
                );
                return response;
            }
            match e {
                ProxyError::NotFound => StatusCode::NOT_FOUND.into_response(),
                ProxyError::CircuitOpen(reg) => circuit_open_response(&reg),
                _ => {
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
async fn extract_go_publish_date(
    storage: &crate::storage::Storage,
    info_key: &str,
    trust_upstream: bool,
) -> Option<i64> {
    // #513: untrusted upstream dates → NORA cache mtime, never upstream .info Time.
    if !trust_upstream {
        return crate::curation::extract_mtime_as_publish_date(storage, info_key).await;
    }
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

/// Whether a Go version string is a canonical semantic version — one that names an immutable
/// snapshot.
///
/// Canonical = `vMAJOR.MINOR.PATCH` (all three present, each a digit run with no leading zeros)
/// with an optional `-prerelease` and/or `+build` suffix. This admits pseudo-versions
/// (`v0.0.0-20210101000000-abcdef123456`) and `+incompatible`. It rejects branch names
/// (`master`), revisions (`abcdef`), partial queries (`v1`, `v1.2`), and operators (`latest`),
/// all of which resolve to a moving target. When in doubt this returns `false` (treat as mutable
/// → revalidate), which is the fail-safe for freshness.
fn is_canonical_go_version(v: &str) -> bool {
    let Some(rest) = v.strip_prefix('v') else {
        return false;
    };
    // Peel off the optional `+build` then the optional `-prerelease`; the remainder is the core.
    let core_pre = rest.split('+').next().unwrap_or(rest);
    let core = core_pre.split('-').next().unwrap_or(core_pre);
    // The suffix (everything after the core) must be non-empty if a separator was present.
    if core.len() != core_pre.len() && core_pre[core.len()..].len() < 2 {
        return false; // a bare trailing `-` or empty prerelease
    }
    if core_pre.len() != rest.len() && rest[core_pre.len()..].len() < 2 {
        return false; // a bare trailing `+` or empty build
    }
    // Core must be exactly MAJOR.MINOR.PATCH, each a digit run with no leading zeros.
    let mut segments = core.split('.');
    let (Some(major), Some(minor), Some(patch), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    [major, minor, patch].iter().all(|s| is_numeric_id(s))
}

/// A numeric identifier: a non-empty run of ASCII digits with no leading zero (except `"0"`).
fn is_numeric_id(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s.len() == 1 || s.as_bytes()[0] != b'0')
}

/// Whether `file` is a `@v/<version>.info` request whose version is NON-canonical — a branch,
/// revision, or partial query that resolves to a moving target and so must be revalidated, unlike
/// a canonical-version `.info` (or any `.mod`/`.zip`) which names an immutable snapshot.
fn is_noncanonical_info_query(file: &str) -> bool {
    file.strip_prefix("@v/")
        .and_then(|rest| rest.strip_suffix(".info"))
        .is_some_and(|ver| !is_canonical_go_version(ver))
}

/// Whether a cached Go proxy response may be served without revalidating against upstream.
///
/// Immutable per-version files (`.info`/`.mod`/`.zip`) are content-addressed by an exact version
/// and are authoritative once cached. The mutable listing endpoints (`@v/list`, `@latest`) defer
/// to [`crate::cache_ttl::mutable_ref_fresh`]: a hosted registry (no upstream) is locally
/// authoritative, a positive `metadata_ttl` allows a bounded staleness window, and otherwise the
/// listing is revalidated against upstream so a newly published version appears.
fn go_cache_fresh(
    is_immutable: bool,
    has_upstream: bool,
    metadata_ttl: i64,
    modified: Option<u64>,
) -> bool {
    is_immutable || crate::cache_ttl::mutable_ref_fresh(has_upstream, metadata_ttl, modified)
}

/// Build response with Content-Type and Cache-Control headers.
/// `is_mutable` controls caching: mutable endpoints (@v/list, @latest) get short TTL,
/// immutable content (.zip, .mod, .info) gets long TTL.
fn with_content_type(data: Vec<u8>, content_type: &'static str, is_mutable: bool) -> Response {
    let cache_control = if is_mutable {
        "public, max-age=60, must-revalidate"
    } else {
        "public, max-age=31536000, immutable"
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
    use proptest::prelude::*;

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

    // ── Cache freshness (revalidation) ────────────────────────────────────

    #[test]
    fn test_go_cache_fresh_immutable_always() {
        // Per-version files are content-addressed → always servable from cache, even proxied.
        assert!(go_cache_fresh(true, true, -1, Some(0)));
        assert!(go_cache_fresh(true, true, 0, None));
    }

    #[test]
    fn test_go_cache_fresh_mutable_hosted() {
        // Hosted (no upstream) listing is locally authoritative → fresh regardless of ttl.
        assert!(go_cache_fresh(false, false, 0, None));
    }

    #[test]
    fn test_go_cache_fresh_mutable_proxied_revalidates() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Proxied listing with non-positive ttl → revalidate every pull (the fix).
        assert!(!go_cache_fresh(false, true, 0, Some(now)));
        // Proxied listing within a positive ttl window → bounded staleness, served from cache.
        assert!(go_cache_fresh(false, true, 300, Some(now - 10)));
        // Proxied listing beyond the window → revalidate.
        assert!(!go_cache_fresh(false, true, 300, Some(now - 600)));
    }

    // ── Canonical version / non-canonical .info mutability ─────────────────

    #[test]
    fn test_is_canonical_go_version() {
        // Canonical: full vMAJOR.MINOR.PATCH, pseudo-versions, +incompatible, prerelease.
        for v in [
            "v1.0.0",
            "v0.0.0",
            "v10.20.30",
            "v1.2.3-rc.1",
            "v2.0.0+incompatible",
            "v0.0.0-20210101000000-abcdef123456",
            "v1.2.4-0.20210101000000-abcdef123456",
            "v1.0.0-rc.1+build.5",
        ] {
            assert!(is_canonical_go_version(v), "expected canonical: {v}");
        }
        // Non-canonical: partial queries, branches, revisions, operators, malformed.
        for v in [
            "v1",
            "v1.2",
            "master",
            "main",
            "latest",
            "abcdef123456",
            "v2",
            "1.0.0",
            "v01.2.3",
            "v1.0.0-",
            "v1.0.0+",
            "v1.2.3.4",
            "",
        ] {
            assert!(!is_canonical_go_version(v), "expected non-canonical: {v}");
        }
    }

    #[test]
    fn test_is_noncanonical_info_query() {
        // Non-canonical .info → mutable (the fix).
        assert!(is_noncanonical_info_query("@v/v1.info"));
        assert!(is_noncanonical_info_query("@v/v1.2.info"));
        assert!(is_noncanonical_info_query("@v/master.info"));
        assert!(is_noncanonical_info_query("@v/abcdef123456.info"));
        // Canonical .info → not mutable (immutable snapshot).
        assert!(!is_noncanonical_info_query("@v/v1.2.3.info"));
        assert!(!is_noncanonical_info_query(
            "@v/v0.0.0-20210101000000-abcdef123456.info"
        ));
        // Non-.info files are never matched here (handled by the immutable path).
        assert!(!is_noncanonical_info_query("@v/v1.2.3.mod"));
        assert!(!is_noncanonical_info_query("@v/master.zip"));
        assert!(!is_noncanonical_info_query("@v/list"));
        assert!(!is_noncanonical_info_query("@latest"));
    }

    proptest! {
        // Any fully-formed vMAJOR.MINOR.PATCH (no leading zeros) is canonical → immutable.
        #[test]
        fn canonical_triples_are_immutable(
            maj in 0u32..100000, min in 0u32..100000, pat in 0u32..100000
        ) {
            let v = format!("v{maj}.{min}.{pat}");
            let info = format!("@v/{}.info", v);
            prop_assert!(is_canonical_go_version(&v));
            prop_assert!(!is_noncanonical_info_query(&info));
        }

        // A two-segment query (vMAJOR.MINOR) is never canonical → always revalidated.
        #[test]
        fn partial_queries_are_mutable(maj in 0u32..100000, min in 0u32..100000) {
            let v = format!("v{maj}.{min}");
            let info = format!("@v/{}.info", v);
            prop_assert!(!is_canonical_go_version(&v));
            prop_assert!(is_noncanonical_info_query(&info));
        }

        // Branch/revision-like names (the charset has no `.`, so no MAJOR.MINOR.PATCH core can
        // form) are never canonical → always revalidated.
        #[test]
        fn branch_names_are_mutable(name in "[a-zA-Z][a-zA-Z0-9_/-]{0,30}") {
            prop_assert!(!is_canonical_go_version(&name));
        }
    }

    // ── Cache-Control headers ─────────────────────────────────────────────

    #[test]
    fn test_cache_control_immutable() {
        let resp = with_content_type(b"data".to_vec(), "application/zip", false);
        let cc = resp.headers().get(header::CACHE_CONTROL).unwrap();
        assert_eq!(cc, "public, max-age=31536000, immutable");
    }

    #[test]
    fn test_cache_control_mutable_list() {
        let resp = with_content_type(b"v1.0.0\n".to_vec(), "text/plain; charset=utf-8", true);
        let cc = resp.headers().get(header::CACHE_CONTROL).unwrap();
        assert_eq!(cc, "public, max-age=60, must-revalidate");
    }

    #[test]
    fn test_cache_control_mutable_latest() {
        let resp = with_content_type(b"{}".to_vec(), "application/json", true);
        let cc = resp.headers().get(header::CACHE_CONTROL).unwrap();
        assert_eq!(cc, "public, max-age=60, must-revalidate");
    }

    #[test]
    fn test_cache_control_immutable_mod() {
        // .mod is text/plain but immutable — must get long TTL
        let resp = with_content_type(
            b"module example".to_vec(),
            "text/plain; charset=utf-8",
            false,
        );
        let cc = resp.headers().get(header::CACHE_CONTROL).unwrap();
        assert_eq!(cc, "public, max-age=31536000, immutable");
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
