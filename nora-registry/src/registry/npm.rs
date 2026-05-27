// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::{
    circuit_open_response, method_not_allowed, nora_base_url, proxy_fetch, ProxyError,
};
use crate::registry_type::RegistryType;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use base64::Engine;
use sha2::Digest;
use std::sync::Arc;
use std::time::Duration;

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/npm/{*path}",
        get(handle_request)
            .put(handle_publish)
            .fallback(|| async { method_not_allowed("GET, PUT") }),
    )
}

/// Rewrite tarball URLs in npm metadata to point to NORA.
///
/// Replaces upstream registry URLs (e.g. `https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz`)
/// with NORA URLs (e.g. `http://nora:5000/npm/lodash/-/lodash-4.17.21.tgz`).
///
/// Two-layer approach (#439):
/// 1. Targeted: parse JSON, rewrite `versions.*.dist.tarball`
/// 2. Safety net: byte-level replace of upstream URL prefix in serialized output
fn rewrite_tarball_urls(data: &[u8], nora_base: &str, upstream_url: &str) -> Result<Vec<u8>, ()> {
    let mut json: serde_json::Value = serde_json::from_slice(data).map_err(|e| {
        tracing::debug!(error = %e, "npm: JSON parse failed in rewrite_tarball_urls");
    })?;

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

    let output = serde_json::to_vec(&json).map_err(|e| {
        tracing::debug!(error = %e, "npm: JSON serialize failed in rewrite_tarball_urls");
    })?;

    // Safety net: byte-level replace of any remaining upstream URL prefix (#439).
    // Catches edge cases where targeted rewrite missed (e.g. new npm metadata fields).
    Ok(replace_upstream_bytes(
        &output,
        upstream_trimmed,
        &nora_npm_base,
    ))
}

/// Byte-level replace of upstream URL prefix in response body (#439).
///
/// Used as safety net after targeted JSON rewrite, and as fallback when JSON
/// parsing fails. Replaces full URL prefix (e.g. `https://registry.npmjs.org`)
/// rather than bare hostname to avoid corrupting unrelated fields.
fn replace_upstream_bytes(data: &[u8], upstream_url: &str, nora_npm_base: &str) -> Vec<u8> {
    if upstream_url.is_empty() {
        return data.to_vec();
    }
    let needle = upstream_url.as_bytes();
    if memchr::memmem::find(data, needle).is_none() {
        return data.to_vec();
    }
    // Replace all occurrences of the upstream URL prefix
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

async fn handle_request(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let is_tarball = path.contains("/-/");

    let key = if is_tarball {
        let parts: Vec<&str> = path.splitn(2, "/-/").collect();
        if parts.len() == 2 {
            format!("npm/{}/tarballs/{}", parts[0], parts[1])
        } else {
            format!("npm/{}", path)
        }
    } else {
        format!("npm/{}/metadata.json", path)
    };

    let package_name = if is_tarball {
        path.split("/-/").next().unwrap_or(&path).to_string()
    } else {
        path.clone()
    };

    // Parse tarball version (used for both pre-download and integrity checks)
    let tarball_version = if is_tarball {
        let filename = path.split("/-/").nth(1).unwrap_or("");
        crate::curation::parse_npm_tarball_version(&package_name, filename)
    } else {
        None
    };

    // Curation check — tarball downloads only (metadata passes through)
    if is_tarball {
        // Extract publish date from cached metadata (npm time field)
        let publish_date = if let Some(ref ver) = tarball_version {
            let meta_key = format!("npm/{}/metadata.json", package_name);
            extract_npm_publish_date(&state.storage, &meta_key, ver).await
        } else {
            None
        };

        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Npm,
            &package_name,
            tarball_version.as_deref(),
            publish_date,
        ) {
            return response;
        }
    }

    // --- Cache hit path ---
    if let Ok(data) = state.storage.get(&key).await {
        // Metadata TTL: if stale, try to refetch from upstream
        if !is_tarball {
            let ttl = state.config.npm.metadata_ttl;
            if let Some(meta) = state.storage.stat(&key).await {
                if !crate::cache_ttl::is_within_ttl(meta.modified, ttl) {
                    if let Some(fresh) = refetch_metadata(&state, &path, &key).await {
                        return with_content_type(false, fresh.into()).into_response();
                    }
                    // Upstream failed — serve stale cache
                }
            }
            return with_content_type(false, data).into_response();
        }

        // Tarball: integrity check if hash exists
        let hash_key = format!("{}.sha256", key);
        if let Ok(stored_hash) = state.storage.get(&hash_key).await {
            let computed = hex::encode(sha2::Sha256::digest(&data));
            let expected = String::from_utf8_lossy(&stored_hash);
            if computed != expected.as_ref() {
                tracing::error!(
                    key = %key,
                    expected = %expected,
                    computed = %computed,
                    "SECURITY: npm tarball integrity check FAILED — possible tampering"
                );
                return (StatusCode::INTERNAL_SERVER_ERROR, "Integrity check failed")
                    .into_response();
            }
        }

        // Curation integrity verification (issue #189)
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Npm,
            &package_name,
            tarball_version.as_deref(),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("npm");
        state.metrics.record_cache_hit("npm");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            package_name,
            "npm",
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "api", "", "npm", ""));
        return with_content_type(true, data).into_response();
    }

    // --- Proxy fetch path ---
    if let Some(proxy_url) = &state.config.npm.proxy {
        let url = format!("{}/{}", proxy_url.trim_end_matches('/'), path);

        match proxy_fetch(
            &state.http_client,
            &url,
            Duration::from_secs(state.config.npm.proxy_timeout),
            state.config.npm.proxy_auth.as_deref(),
            &state.circuit_breaker,
            RegistryType::Npm,
        )
        .await
        {
            Ok(data) => {
                let data_to_cache;
                let data_to_serve;

                if is_tarball {
                    // Compute and store sha256
                    let hash = hex::encode(sha2::Sha256::digest(&data));
                    let hash_key = format!("{}.sha256", key);
                    let storage = state.storage.clone();
                    tokio::spawn(async move {
                        if let Err(e) = storage.put(&hash_key, hash.as_bytes()).await {
                            tracing::warn!(key = %hash_key, error = ?e, "npm proxy: failed to cache hash sidecar");
                        }
                    });

                    state.metrics.record_download("npm");
                    state.metrics.record_cache_miss("npm");
                    state.activity.push(ActivityEntry::new(
                        ActionType::ProxyFetch,
                        package_name,
                        "npm",
                        "PROXY",
                    ));
                    state
                        .audit
                        .log(AuditEntry::new("proxy_fetch", "api", "", "npm", ""));

                    data_to_cache = data.clone();
                    data_to_serve = data;
                } else {
                    // Metadata: rewrite tarball URLs to point to NORA
                    let nora_base = nora_base_url(&state);
                    let rewritten = rewrite_tarball_urls(&data, &nora_base, proxy_url)
                        .unwrap_or_else(|()| {
                            tracing::warn!(
                                path = %path,
                                "npm metadata JSON parse failed, using byte-level URL rewrite"
                            );
                            let upstream_trimmed = proxy_url.trim_end_matches('/');
                            let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));
                            replace_upstream_bytes(&data, upstream_trimmed, &nora_npm_base)
                        });

                    data_to_cache = rewritten.clone();
                    data_to_serve = rewritten;
                }

                // Cache in background, invalidate index AFTER write completes
                let storage = state.storage.clone();
                let key_clone = key.clone();
                let invalidate_npm = is_tarball;
                let repo_index = Arc::clone(&state.repo_index);
                tokio::spawn(async move {
                    if let Err(e) = storage.put(&key_clone, &data_to_cache).await {
                        tracing::warn!(key = %key_clone, error = ?e, "npm proxy: failed to cache artifact");
                    } else if invalidate_npm {
                        repo_index.invalidate("npm");
                    }
                });

                return with_content_type(is_tarball, data_to_serve.into()).into_response();
            }
            Err(ProxyError::CircuitOpen(reg)) => return circuit_open_response(&reg),
            Err(e) => {
                tracing::debug!(error = ?e, path = %path, "npm proxy fetch failed");
            }
        }
        tracing::warn!(registry = "npm", path = %path, "Proxy failed, returning 404");
    }

    StatusCode::NOT_FOUND.into_response()
}

/// Refetch metadata from upstream, rewrite URLs, update cache.
/// Returns None if upstream is unavailable (caller serves stale cache).
async fn refetch_metadata(state: &AppState, path: &str, key: &str) -> Option<Vec<u8>> {
    let proxy_url = state.config.npm.proxy.as_ref()?;
    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), path);

    let data = proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        state.config.npm.proxy_auth.as_deref(),
        &state.circuit_breaker,
        RegistryType::Npm,
    )
    .await
    .ok()?;

    let nora_base = nora_base_url(state);
    let rewritten = rewrite_tarball_urls(&data, &nora_base, proxy_url).unwrap_or_else(|()| {
        tracing::warn!(
            path = %path,
            "npm metadata refetch: JSON parse failed, using byte-level URL rewrite"
        );
        let upstream_trimmed = proxy_url.trim_end_matches('/');
        let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));
        replace_upstream_bytes(&data, upstream_trimmed, &nora_npm_base)
    });

    let storage = state.storage.clone();
    let key_clone = key.to_string();
    let cache_data = rewritten.clone();
    tokio::spawn(async move {
        if let Err(e) = storage.put(&key_clone, &cache_data).await {
            tracing::warn!(key = %key_clone, error = ?e, "npm proxy: failed to cache metadata");
        }
    });

    Some(rewritten)
}

// ============================================================================
// npm publish
// ============================================================================

/// Validate attachment filename: only safe characters, no path traversal.
fn is_valid_attachment_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
}

async fn handle_publish(
    State(state): State<AppState>,
    Path(path): Path<String>,
    body: Bytes,
) -> Response {
    let package_name = path;

    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)).into_response(),
    };

    // Security: verify payload name matches URL path (required field)
    match payload.get("name").and_then(|n| n.as_str()) {
        Some(payload_name) if payload_name == package_name => {}
        Some(payload_name) => {
            tracing::warn!(
                url_name = %package_name,
                payload_name = %payload_name,
                "SECURITY: npm publish name mismatch — possible spoofing attempt"
            );
            return (
                StatusCode::BAD_REQUEST,
                "Package name in URL does not match payload",
            )
                .into_response();
        }
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Missing required 'name' field in publish payload",
            )
                .into_response();
        }
    }

    let attachments = match payload.get("_attachments").and_then(|a| a.as_object()) {
        Some(a) => a,
        None => return (StatusCode::BAD_REQUEST, "Missing _attachments").into_response(),
    };

    let new_versions = match payload.get("versions").and_then(|v| v.as_object()) {
        Some(v) => v,
        None => return (StatusCode::BAD_REQUEST, "Missing versions").into_response(),
    };

    // TOCTOU protection: lock per package to prevent concurrent version conflicts
    let metadata_key = format!("npm/{}/metadata.json", package_name);
    let lock = state.publish_lock(&metadata_key);
    let _guard = lock.lock().await;

    // Load or create metadata
    let mut metadata = if let Ok(existing) = state.storage.get(&metadata_key).await {
        serde_json::from_slice::<serde_json::Value>(&existing)
            .unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    // Version immutability
    if let Some(existing_versions) = metadata.get("versions").and_then(|v| v.as_object()) {
        for ver in new_versions.keys() {
            if existing_versions.contains_key(ver) {
                return (
                    StatusCode::CONFLICT,
                    format!("Version {} already exists", ver),
                )
                    .into_response();
            }
        }
    }

    // Store tarballs
    for (filename, attachment_data) in attachments {
        if !is_valid_attachment_name(filename) {
            tracing::warn!(
                filename = %filename,
                package = %package_name,
                "SECURITY: npm publish rejected — invalid attachment filename"
            );
            return (StatusCode::BAD_REQUEST, "Invalid attachment filename").into_response();
        }

        let base64_data = match attachment_data.get("data").and_then(|d| d.as_str()) {
            Some(d) => d,
            None => continue,
        };

        let tarball_bytes = match base64::engine::general_purpose::STANDARD.decode(base64_data) {
            Ok(b) => b,
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "Invalid base64 in attachment").into_response()
            }
        };

        let tarball_key = format!("npm/{}/tarballs/{}", package_name, filename);
        if let Err(e) = state.storage.put(&tarball_key, &tarball_bytes).await {
            tracing::error!(key = %tarball_key, error = ?e, "npm publish: failed to store tarball");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        // Store sha256
        let hash = hex::encode(sha2::Sha256::digest(&tarball_bytes));
        let hash_key = format!("{}.sha256", tarball_key);
        if let Err(e) = state.storage.put(&hash_key, hash.as_bytes()).await {
            tracing::warn!(key = %hash_key, error = ?e, "npm publish: failed to store hash sidecar");
        }
    }

    // Merge versions
    let Some(meta_obj) = metadata.as_object_mut() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "invalid metadata format").into_response();
    };
    let stored_versions = meta_obj.entry("versions").or_insert(serde_json::json!({}));
    if let Some(sv) = stored_versions.as_object_mut() {
        for (ver, ver_data) in new_versions {
            sv.insert(ver.clone(), ver_data.clone());
        }
    }

    // Copy standard fields
    for field in &["name", "_id", "description", "readme", "license"] {
        if let Some(val) = payload.get(*field) {
            meta_obj.insert(field.to_string(), val.clone());
        }
    }

    // Merge dist-tags
    if let Some(new_dist_tags) = payload.get("dist-tags").and_then(|d| d.as_object()) {
        let stored_dist_tags = meta_obj.entry("dist-tags").or_insert(serde_json::json!({}));
        if let Some(sdt) = stored_dist_tags.as_object_mut() {
            for (tag, ver) in new_dist_tags {
                sdt.insert(tag.clone(), ver.clone());
            }
        }
    }

    // Rewrite tarball URLs for published packages
    let nora_base = nora_base_url(&state);
    if let Some(versions) = metadata.get_mut("versions").and_then(|v| v.as_object_mut()) {
        for (ver, ver_data) in versions.iter_mut() {
            if let Some(dist) = ver_data.get_mut("dist") {
                let short_name = package_name.split('/').next_back().unwrap_or(&package_name);
                let tarball_url = format!(
                    "{}/npm/{}/-/{}-{}.tgz",
                    nora_base.trim_end_matches('/'),
                    package_name,
                    short_name,
                    ver
                );
                dist["tarball"] = serde_json::Value::String(tarball_url);
            }
        }
    }

    // Store metadata
    match serde_json::to_vec(&metadata) {
        Ok(bytes) => {
            if let Err(e) = state.storage.put(&metadata_key, &bytes).await {
                tracing::error!(key = %metadata_key, error = ?e, "npm publish: failed to store metadata");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        Err(e) => {
            tracing::error!(error = ?e, "npm publish: failed to serialize metadata");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    state.metrics.record_upload("npm");
    state
        .audit
        .log(AuditEntry::new("push", "api", &package_name, "npm", ""));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        package_name,
        "npm",
        "LOCAL",
    ));
    state.repo_index.invalidate("npm");

    StatusCode::CREATED.into_response()
}

// ============================================================================
// Helpers
// ============================================================================

/// Extract publish date for a specific version from cached npm metadata.
///
/// npm metadata JSON has a `time` object mapping versions to ISO 8601 dates:
/// ```json
/// { "time": { "1.0.0": "2024-01-15T10:30:00.000Z" } }
/// ```
async fn extract_npm_publish_date(
    storage: &crate::storage::Storage,
    metadata_key: &str,
    version: &str,
) -> Option<i64> {
    let data = storage.get(metadata_key).await.ok()?;
    let json: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let date_str = json.get("time")?.get(version)?.as_str()?;
    crate::curation::parse_iso8601_to_unix(date_str)
}

fn with_content_type(
    is_tarball: bool,
    data: Bytes,
) -> (StatusCode, [(header::HeaderName, &'static str); 2], Bytes) {
    let (content_type, cache_control) = if is_tarball {
        (
            "application/octet-stream",
            "public, max-age=31536000, immutable",
        )
    } else {
        ("application/json", "public, max-age=60, must-revalidate")
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, cache_control),
        ],
        data,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrite_tarball_urls_regular_package() {
        let metadata = serde_json::json!({
            "name": "lodash",
            "versions": {
                "4.17.21": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                        "shasum": "abc123"
                    }
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(
            json["versions"]["4.17.21"]["dist"]["tarball"],
            "http://nora:5000/npm/lodash/-/lodash-4.17.21.tgz"
        );
        assert_eq!(json["versions"]["4.17.21"]["dist"]["shasum"], "abc123");
    }

    #[test]
    fn test_rewrite_tarball_urls_scoped_package() {
        let metadata = serde_json::json!({
            "name": "@babel/core",
            "versions": {
                "7.26.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@babel/core/-/core-7.26.0.tgz",
                        "integrity": "sha512-test"
                    }
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(
            json["versions"]["7.26.0"]["dist"]["tarball"],
            "http://nora:5000/npm/@babel/core/-/core-7.26.0.tgz"
        );
    }

    #[test]
    fn test_rewrite_tarball_urls_multiple_versions() {
        let metadata = serde_json::json!({
            "name": "express",
            "versions": {
                "4.18.2": { "dist": { "tarball": "https://registry.npmjs.org/express/-/express-4.18.2.tgz" } },
                "4.19.0": { "dist": { "tarball": "https://registry.npmjs.org/express/-/express-4.19.0.tgz" } }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result = rewrite_tarball_urls(
            &data,
            "https://demo.getnora.io",
            "https://registry.npmjs.org",
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(
            json["versions"]["4.18.2"]["dist"]["tarball"],
            "https://demo.getnora.io/npm/express/-/express-4.18.2.tgz"
        );
        assert_eq!(
            json["versions"]["4.19.0"]["dist"]["tarball"],
            "https://demo.getnora.io/npm/express/-/express-4.19.0.tgz"
        );
    }

    #[test]
    fn test_rewrite_tarball_urls_no_versions() {
        let metadata = serde_json::json!({ "name": "empty-pkg" });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(json["name"], "empty-pkg");
    }

    #[test]
    fn test_rewrite_invalid_json() {
        assert!(rewrite_tarball_urls(
            b"not json",
            "http://nora:5000",
            "https://registry.npmjs.org"
        )
        .is_err());
    }

    #[test]
    fn test_valid_attachment_names() {
        assert!(is_valid_attachment_name("lodash-4.17.21.tgz"));
        assert!(is_valid_attachment_name("core-7.26.0.tgz"));
        assert!(is_valid_attachment_name("my_package-1.0.0.tgz"));
        assert!(is_valid_attachment_name("@scope-pkg-1.0.0.tgz"));
    }

    #[test]
    fn test_path_traversal_attachment_names() {
        assert!(!is_valid_attachment_name("../../etc/passwd"));
        assert!(!is_valid_attachment_name(
            "../docker/nginx/manifests/latest.json"
        ));
        assert!(!is_valid_attachment_name("foo/bar.tgz"));
        assert!(!is_valid_attachment_name("foo\\bar.tgz"));
    }

    #[test]
    fn test_empty_and_null_attachment_names() {
        assert!(!is_valid_attachment_name(""));
        assert!(!is_valid_attachment_name("foo\0bar.tgz"));
    }

    #[test]
    fn test_with_content_type_tarball() {
        let data = Bytes::from("tarball-data");
        let (status, headers, body) = with_content_type(true, data.clone());
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[0].1, "application/octet-stream");
        assert_eq!(body, data);
    }

    #[test]
    fn test_with_content_type_json() {
        let data = Bytes::from("json-data");
        let (status, headers, body) = with_content_type(false, data.clone());
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[0].1, "application/json");
        assert_eq!(body, data);
    }

    #[test]
    fn test_rewrite_tarball_urls_trailing_slash() {
        let metadata = serde_json::json!({
            "name": "test",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
                    }
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000/", "https://registry.npmjs.org/")
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        let tarball = json["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert!(tarball.starts_with("http://nora:5000/npm/"));
    }

    #[test]
    fn test_rewrite_tarball_urls_preserves_other_fields() {
        let metadata = serde_json::json!({
            "name": "test",
            "description": "A test package",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz",
                        "shasum": "abc123"
                    },
                    "dependencies": {"lodash": "^4.0.0"}
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(json["description"], "A test package");
        assert_eq!(json["versions"]["1.0.0"]["dist"]["shasum"], "abc123");
    }

    // ── Safety net tests (#439) ──

    #[test]
    fn test_replace_upstream_bytes_basic() {
        let data = b"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";
        let result =
            replace_upstream_bytes(data, "https://registry.npmjs.org", "http://nora:5000/npm");
        assert_eq!(
            String::from_utf8(result).unwrap(),
            "http://nora:5000/npm/lodash/-/lodash-4.17.21.tgz"
        );
    }

    #[test]
    fn test_replace_upstream_bytes_no_match() {
        let data = b"no upstream urls here";
        let result = replace_upstream_bytes(data, "https://registry.npmjs.org", "http://nora/npm");
        assert_eq!(result, data);
    }

    #[test]
    fn test_replace_upstream_bytes_empty_upstream() {
        let data = b"https://registry.npmjs.org/test";
        let result = replace_upstream_bytes(data, "", "http://nora/npm");
        assert_eq!(result, data);
    }

    #[test]
    fn test_replace_upstream_bytes_multiple_occurrences() {
        let data = b"url1: https://registry.npmjs.org/a url2: https://registry.npmjs.org/b";
        let result =
            replace_upstream_bytes(data, "https://registry.npmjs.org", "http://nora:5000/npm");
        let s = String::from_utf8(result).unwrap();
        assert!(!s.contains("registry.npmjs.org"));
        assert!(s.contains("http://nora:5000/npm/a"));
        assert!(s.contains("http://nora:5000/npm/b"));
    }

    #[test]
    fn test_rewrite_tarball_urls_safety_net_catches_unknown_fields() {
        // Simulate metadata with upstream URL in an unexpected field
        let metadata = serde_json::json!({
            "name": "test",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
                    },
                    "_resolved": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let body = String::from_utf8(result).unwrap();
        // Safety net should catch the _resolved field too
        assert!(
            !body.contains("registry.npmjs.org"),
            "upstream URL leaked through _resolved field: {}",
            &body[..body.len().min(500)]
        );
    }

    #[test]
    fn test_rewrite_tarball_urls_preserves_non_upstream_urls() {
        // homepage and repository.url should NOT be mangled
        let metadata = serde_json::json!({
            "name": "test",
            "homepage": "https://github.com/test/test",
            "repository": { "url": "git+https://github.com/test/test.git" },
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
                    }
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(json["homepage"], "https://github.com/test/test");
        assert_eq!(
            json["repository"]["url"],
            "git+https://github.com/test/test.git"
        );
    }

    #[test]
    fn test_is_valid_attachment_name_valid() {
        assert!(is_valid_attachment_name("package-1.0.0.tgz"));
        assert!(is_valid_attachment_name("@scope-pkg-2.0.tgz"));
        assert!(is_valid_attachment_name("my_pkg.tgz"));
    }

    #[test]
    fn test_is_valid_attachment_name_traversal() {
        assert!(!is_valid_attachment_name("../etc/passwd"));
        assert!(!is_valid_attachment_name("foo/../bar"));
    }

    #[test]
    fn test_is_valid_attachment_name_slash() {
        assert!(!is_valid_attachment_name("path/file.tgz"));
        assert!(!is_valid_attachment_name("path\\file.tgz"));
    }

    #[test]
    fn test_is_valid_attachment_name_null_byte() {
        assert!(!is_valid_attachment_name("file\0.tgz"));
    }

    #[test]
    fn test_is_valid_attachment_name_empty() {
        assert!(!is_valid_attachment_name(""));
    }

    #[test]
    fn test_is_valid_attachment_name_special_chars() {
        assert!(!is_valid_attachment_name("file name.tgz")); // space
        assert!(!is_valid_attachment_name("file;cmd.tgz")); // semicolon
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use base64::Engine;

    #[tokio::test]
    async fn test_npm_metadata_from_cache() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "lodash",
            "versions": {
                "4.17.21": { "dist": { "tarball": "http://example.com/lodash.tgz" } }
            }
        });
        let metadata_bytes = serde_json::to_vec(&metadata).unwrap();

        ctx.state
            .storage
            .put("npm/lodash/metadata.json", &metadata_bytes)
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/npm/lodash", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "lodash");
    }

    #[tokio::test]
    async fn test_npm_tarball_from_cache() {
        let ctx = create_test_context();

        let tarball_data = b"fake-tarball-bytes";
        ctx.state
            .storage
            .put("npm/lodash/tarballs/lodash-4.17.21.tgz", tarball_data)
            .await
            .unwrap();

        let response = send(
            &ctx.app,
            Method::GET,
            "/npm/lodash/-/lodash-4.17.21.tgz",
            "",
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        assert_eq!(&body[..], tarball_data);
    }

    #[tokio::test]
    async fn test_npm_not_found_no_proxy() {
        let ctx = create_test_context();

        // No proxy configured, no local data
        let response = send(&ctx.app, Method::GET, "/npm/nonexistent", "").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_npm_publish_basic() {
        let ctx = create_test_context();

        let tarball_data = b"fake-tarball";
        let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

        let payload = serde_json::json!({
            "name": "mypkg",
            "versions": {
                "1.0.0": { "dist": {} }
            },
            "_attachments": {
                "mypkg-1.0.0.tgz": { "data": base64_data }
            },
            "dist-tags": { "latest": "1.0.0" }
        });

        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let response = send(&ctx.app, Method::PUT, "/npm/mypkg", Body::from(body_bytes)).await;

        assert_eq!(response.status(), StatusCode::CREATED);

        // Verify tarball was stored
        let stored_tarball = ctx
            .state
            .storage
            .get("npm/mypkg/tarballs/mypkg-1.0.0.tgz")
            .await
            .unwrap();
        assert_eq!(&stored_tarball[..], tarball_data);
    }

    #[tokio::test]
    async fn test_npm_publish_name_mismatch() {
        let ctx = create_test_context();

        let tarball_data = b"fake-tarball";
        let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

        let payload = serde_json::json!({
            "name": "other",
            "versions": {
                "1.0.0": { "dist": {} }
            },
            "_attachments": {
                "other-1.0.0.tgz": { "data": base64_data }
            },
            "dist-tags": { "latest": "1.0.0" }
        });

        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let response = send(&ctx.app, Method::PUT, "/npm/mypkg", Body::from(body_bytes)).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

// ── Spec conformance tests (#390) ─────────────────────────────────────
//
// Invariant: after tarball URL rewriting, no upstream registry domains
// remain in the response. Uses golden fixtures from testdata/npm/.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod spec_conformance_tests {
    use super::*;

    const NPM_UPSTREAM_DOMAIN: &str = "registry.npmjs.org";

    /// Assert that no upstream URLs remain in rewritten response body.
    fn assert_no_upstream_urls(body: &str, context: &str) {
        assert!(
            !body.contains(NPM_UPSTREAM_DOMAIN),
            "upstream domain '{}' leaked in {}: {}",
            NPM_UPSTREAM_DOMAIN,
            context,
            &body[..body.len().min(500)]
        );
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/testdata/npm/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("failed to load fixture {}: {}", path, e))
    }

    // ── Regular package rewrite ──

    #[test]
    fn test_regular_package_golden_no_upstream_leak() {
        let fixture = load_fixture("package-metadata.json");
        let result =
            rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap();
        let body = String::from_utf8(result).unwrap();
        assert_no_upstream_urls(&body, "regular package rewrite");
    }

    #[test]
    fn test_regular_package_golden_all_tarballs_rewritten() {
        let fixture = load_fixture("package-metadata.json");
        let result =
            rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        let versions = json["versions"].as_object().unwrap();
        for (ver, data) in versions {
            let tarball = data["dist"]["tarball"].as_str().unwrap();
            assert!(
                tarball.starts_with("http://nora:4000/npm/"),
                "version {} tarball not rewritten: {}",
                ver,
                tarball
            );
        }
    }

    #[test]
    fn test_regular_package_golden_preserves_integrity() {
        let fixture = load_fixture("package-metadata.json");
        let result =
            rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        // integrity and shasum must survive rewriting
        let dist = &json["versions"]["4.17.21"]["dist"];
        assert!(
            dist["shasum"].as_str().is_some(),
            "shasum must be preserved"
        );
        assert!(
            dist["integrity"].as_str().is_some(),
            "integrity must be preserved"
        );
    }

    #[test]
    fn test_regular_package_golden_snapshot() {
        let fixture = load_fixture("package-metadata.json");
        let result =
            rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        // Snapshot only tarball URLs (stable against other metadata changes)
        let tarball_urls: Vec<&str> = json["versions"]
            .as_object()
            .unwrap()
            .values()
            .filter_map(|v| v["dist"]["tarball"].as_str())
            .collect();
        insta::assert_json_snapshot!("npm_regular_tarball_urls", tarball_urls);
    }

    // ── Scoped package rewrite ──

    #[test]
    fn test_scoped_package_golden_no_upstream_leak() {
        let fixture = load_fixture("scoped-package-metadata.json");
        let result = rewrite_tarball_urls(
            &fixture,
            "https://registry.airgap.local",
            "https://registry.npmjs.org",
        )
        .unwrap();
        let body = String::from_utf8(result).unwrap();
        assert_no_upstream_urls(&body, "scoped package rewrite");
    }

    #[test]
    fn test_scoped_package_golden_all_tarballs_rewritten() {
        let fixture = load_fixture("scoped-package-metadata.json");
        let result =
            rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        let versions = json["versions"].as_object().unwrap();
        for (ver, data) in versions {
            let tarball = data["dist"]["tarball"].as_str().unwrap();
            assert!(
                tarball.starts_with("http://nora:4000/npm/"),
                "scoped version {} tarball not rewritten: {}",
                ver,
                tarball
            );
            // Scoped packages must preserve the @scope prefix in the path
            assert!(
                tarball.contains("@babel/core"),
                "scoped package path lost: {}",
                tarball
            );
        }
    }

    #[test]
    fn test_scoped_package_golden_snapshot() {
        let fixture = load_fixture("scoped-package-metadata.json");
        let result =
            rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        let tarball_urls: Vec<&str> = json["versions"]
            .as_object()
            .unwrap()
            .values()
            .filter_map(|v| v["dist"]["tarball"].as_str())
            .collect();
        insta::assert_json_snapshot!("npm_scoped_tarball_urls", tarball_urls);
    }

    // ── Content-Type assertions ──

    #[test]
    fn test_with_content_type_metadata_is_json() {
        let data = Bytes::from(b"{}".to_vec());
        let (status, headers, _body) = with_content_type(false, data);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[0].1, "application/json");
    }

    #[test]
    fn test_with_content_type_tarball_is_octet() {
        let data = Bytes::from(b"\x1f\x8b".to_vec());
        let (status, headers, _body) = with_content_type(true, data);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[0].1, "application/octet-stream");
    }

    // ── Edge cases for URL rewriting ──

    #[test]
    fn test_rewrite_custom_upstream_no_leak() {
        let metadata = serde_json::json!({
            "name": "pkg",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://private.npm.corp/pkg/-/pkg-1.0.0.tgz"
                    }
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:4000", "https://private.npm.corp").unwrap();
        let body = String::from_utf8(result).unwrap();
        assert!(
            !body.contains("private.npm.corp"),
            "custom upstream domain leaked"
        );
    }

    #[test]
    fn test_rewrite_preserves_non_dist_urls() {
        let metadata = serde_json::json!({
            "name": "pkg",
            "repository": {"url": "https://github.com/test/pkg.git"},
            "homepage": "https://pkg.example.com",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
                    },
                    "repository": {"url": "https://github.com/test/pkg.git"}
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:4000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        // Non-dist URLs must be untouched
        assert_eq!(
            json["repository"]["url"].as_str().unwrap(),
            "https://github.com/test/pkg.git"
        );
        assert_eq!(
            json["homepage"].as_str().unwrap(),
            "https://pkg.example.com"
        );
    }
}
