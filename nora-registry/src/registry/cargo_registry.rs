// Copyright (c) 2026 Volkov Pavel | DevITWay
// SPDX-License-Identifier: MIT

//! Cargo registry with sparse index (RFC 2789).
//!
//! Implements:
//!   GET  /cargo/index/config.json                  — registry configuration
//!   GET  /cargo/index/{prefix}/{crate}             — sparse index entries
//!   GET  /cargo/api/v1/crates/{crate_name}         — crate metadata (proxy)
//!   GET  /cargo/api/v1/crates/{name}/{ver}/download — download .crate
//!   PUT  /cargo/api/v1/crates/new                  — cargo publish

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::proxy_fetch;
use crate::validation::validate_storage_key;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
    Router,
};
use sha2::Digest;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/cargo/index/config.json", get(index_config))
        .route("/cargo/index/{*path}", get(sparse_index))
        .route("/cargo/api/v1/crates/{crate_name}", get(get_metadata))
        .route(
            "/cargo/api/v1/crates/{crate_name}/{version}/download",
            get(download),
        )
        .route("/cargo/api/v1/crates/new", put(publish))
}

// ============================================================================
// Sparse index — RFC 2789
// ============================================================================

/// GET /cargo/index/config.json — tells cargo where to download crates.
async fn index_config(State(state): State<Arc<AppState>>) -> Response {
    let base = nora_base_url(&state);
    let config = serde_json::json!({
        "dl": format!("{}/cargo/api/v1/crates", base.trim_end_matches('/')),
        "api": format!("{}/cargo", base.trim_end_matches('/'))
    });
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=300"),
            ),
        ],
        serde_json::to_vec(&config).unwrap_or_default(),
    )
        .into_response()
}

/// GET /cargo/index/{prefix}/{crate} — sparse index lookup.
///
/// Cargo sparse index uses a directory structure based on crate name length:
///   1 char:  /cargo/index/1/{name}
///   2 chars: /cargo/index/2/{name}
///   3 chars: /cargo/index/3/{first_char}/{name}
///   4+ chars: /cargo/index/{first_two}/{next_two}/{name}
///
/// Each entry is one JSON line per version (newline-delimited).
async fn sparse_index(State(state): State<Arc<AppState>>, Path(path): Path<String>) -> Response {
    // Extract crate name from the path (last segment), normalized to lowercase
    let crate_name = match path.rsplit('/').next() {
        Some(name) if !name.is_empty() => name.to_lowercase(),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };

    // Validate crate name
    if !is_valid_crate_name(&crate_name) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Verify prefix matches the crate name (case-insensitive)
    let expected_prefix = crate_index_prefix(&crate_name);
    if path.to_lowercase() != format!("{}/{}", expected_prefix, crate_name) {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Try local index first
    let index_key = format!("cargo/index/{}/{}", expected_prefix, crate_name);
    if let Ok(data) = state.storage.get(&index_key).await {
        state.metrics.record_download("cargo");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            crate_name.to_string(),
            "cargo",
            "CACHE",
        ));
        return sparse_index_response(data.to_vec());
    }

    // Try upstream sparse index (sparse+https://index.crates.io/)
    let proxy_url = match &state.config.cargo.proxy {
        Some(url) => url.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // crates.io sparse index lives at index.crates.io
    let upstream_index_url = if proxy_url.contains("crates.io") {
        format!("https://index.crates.io/{}/{}", expected_prefix, crate_name)
    } else {
        // Custom registry: assume sparse index at {proxy}/index/{prefix}/{crate}
        format!(
            "{}/index/{}/{}",
            proxy_url.trim_end_matches('/'),
            expected_prefix,
            crate_name
        )
    };

    match proxy_fetch(
        &state.http_client,
        &upstream_index_url,
        state.config.cargo.proxy_timeout,
        state.config.cargo.proxy_auth.as_deref(),
    )
    .await
    {
        Ok(data) => {
            state.metrics.record_download("cargo");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                crate_name.to_string(),
                "cargo",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "cargo", ""));

            // Cache in background
            let storage = state.storage.clone();
            let key = index_key;
            let data_clone = data.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key, &data_clone).await;
            });

            state.repo_index.invalidate("cargo");
            sparse_index_response(data)
        }
        Err(crate::registry::ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(
                crate_name = crate_name,
                error = ?e,
                "Cargo sparse index upstream error"
            );
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

// ============================================================================
// Metadata & download (existing, refactored)
// ============================================================================

/// GET /cargo/api/v1/crates/{crate_name} — JSON metadata.
async fn get_metadata(
    State(state): State<Arc<AppState>>,
    Path(crate_name): Path<String>,
) -> Response {
    if validate_storage_key(&crate_name).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let crate_name = crate_name.to_lowercase();
    let key = format!("cargo/{}/metadata.json", crate_name);

    if let Ok(data) = state.storage.get(&key).await {
        return (StatusCode::OK, data).into_response();
    }

    // Proxy fetch metadata from upstream
    let proxy_url = match &state.config.cargo.proxy {
        Some(url) => url.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let url = format!(
        "{}/api/v1/crates/{}",
        proxy_url.trim_end_matches('/'),
        crate_name
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        state.config.cargo.proxy_timeout,
        state.config.cargo.proxy_auth.as_deref(),
    )
    .await
    {
        Ok(data) => {
            let storage = state.storage.clone();
            let key_clone = key.clone();
            let data_clone = data.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &data_clone).await;
            });
            (StatusCode::OK, data).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// GET /cargo/api/v1/crates/{name}/{version}/download — download .crate file.
async fn download(
    State(state): State<Arc<AppState>>,
    Path((crate_name, version)): Path<(String, String)>,
) -> Response {
    if validate_storage_key(&crate_name).is_err() || validate_storage_key(&version).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let crate_name = crate_name.to_lowercase();
    let key = format!(
        "cargo/{}/{}/{}-{}.crate",
        crate_name, version, crate_name, version
    );

    // Try local storage first
    if let Ok(data) = state.storage.get(&key).await {
        state.metrics.record_download("cargo");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::Pull,
            format!("{}@{}", crate_name, version),
            "cargo",
            "LOCAL",
        ));
        state
            .audit
            .log(AuditEntry::new("pull", "api", "", "cargo", ""));
        return (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/x-tar"),
                ),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=31536000, immutable"),
                ),
            ],
            data,
        )
            .into_response();
    }

    // Proxy fetch from upstream
    let proxy_url = match &state.config.cargo.proxy {
        Some(url) => url.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let url = format!(
        "{}/api/v1/crates/{}/{}/download",
        proxy_url.trim_end_matches('/'),
        crate_name,
        version
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        state.config.cargo.proxy_timeout,
        state.config.cargo.proxy_auth.as_deref(),
    )
    .await
    {
        Ok(data) => {
            let storage = state.storage.clone();
            let key_clone = key.clone();
            let data_clone = data.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &data_clone).await;
            });
            state.metrics.record_download("cargo");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::Pull,
                format!("{}@{}", crate_name, version),
                "cargo",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "cargo", ""));
            (
                StatusCode::OK,
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/x-tar"),
                    ),
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=31536000, immutable"),
                    ),
                ],
                data,
            )
                .into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// ============================================================================
// Cargo publish
// ============================================================================

/// PUT /cargo/api/v1/crates/new — publish a crate.
///
/// Wire format (cargo puts this as the body):
///   4 bytes LE: metadata JSON length
///   N bytes:    metadata JSON
///   4 bytes LE: .crate tarball length
///   M bytes:    .crate tarball
async fn publish(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    if body.len() < 8 {
        return (StatusCode::BAD_REQUEST, "Payload too small").into_response();
    }

    // Parse wire format
    let metadata_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if body.len() < 4 + metadata_len + 4 {
        return (StatusCode::BAD_REQUEST, "Truncated metadata").into_response();
    }

    let metadata_bytes = &body[4..4 + metadata_len];
    let metadata: serde_json::Value = match serde_json::from_slice(metadata_bytes) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid metadata JSON: {}", e),
            )
                .into_response()
        }
    };

    let crate_len_offset = 4 + metadata_len;
    let crate_len = u32::from_le_bytes([
        body[crate_len_offset],
        body[crate_len_offset + 1],
        body[crate_len_offset + 2],
        body[crate_len_offset + 3],
    ]) as usize;

    let crate_start = crate_len_offset + 4;
    if body.len() < crate_start + crate_len {
        return (StatusCode::BAD_REQUEST, "Truncated crate tarball").into_response();
    }

    let crate_data = &body[crate_start..crate_start + crate_len];

    // Extract required fields
    let name = match metadata.get("name").and_then(|n| n.as_str()) {
        Some(n) => n,
        None => return (StatusCode::BAD_REQUEST, "Missing crate name").into_response(),
    };

    let vers = match metadata.get("vers").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return (StatusCode::BAD_REQUEST, "Missing crate version").into_response(),
    };

    // Validate
    if !is_valid_crate_name(name) {
        return (StatusCode::BAD_REQUEST, "Invalid crate name").into_response();
    }
    if validate_storage_key(vers).is_err() {
        return (StatusCode::BAD_REQUEST, "Invalid version").into_response();
    }

    // Normalize to lowercase for consistent storage keys
    let name = name.to_lowercase();
    let vers = vers.to_string();

    // TOCTOU protection: lock per crate (not per version!) to serialize
    // index read-modify-write. The index file is shared across all versions
    // of the same crate, so concurrent publishes of different versions
    // must be serialized to prevent lost index entries.
    let crate_key = format!("cargo/{}/{}/{}-{}.crate", name, vers, name, vers);
    let prefix = crate_index_prefix(&name);
    let index_lock_key = format!("cargo/index/{}/{}", prefix, name);
    let lock = state.publish_lock(&index_lock_key);
    let _guard = lock.lock().await;

    // Check version immutability
    if state.storage.stat(&crate_key).await.is_some() {
        let err = serde_json::json!({
            "errors": [{"detail": format!("crate version `{}@{}` already exists", name, vers)}]
        });
        return (
            StatusCode::CONFLICT,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            serde_json::to_vec(&err).unwrap_or_default(),
        )
            .into_response();
    }

    // Compute checksum
    let cksum = hex::encode(sha2::Sha256::digest(crate_data));

    // Build sparse index entry (one JSON line per version)
    // Transform deps: Cargo publish sends `version_req` but index format requires `req`,
    // and `explicit_name_in_toml` becomes `package` in the index.
    let deps = metadata
        .get("deps")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .map(|dep| {
                    let mut d = dep.clone();
                    if let Some(obj) = d.as_object_mut() {
                        // version_req -> req
                        if let Some(vr) = obj.remove("version_req") {
                            obj.insert("req".to_string(), vr);
                        }
                        // explicit_name_in_toml -> package
                        if let Some(ent) = obj.remove("explicit_name_in_toml") {
                            if !ent.is_null() {
                                obj.insert("package".to_string(), ent);
                            }
                        }
                    }
                    d
                })
                .collect::<Vec<_>>()
        })
        .map(serde_json::Value::Array)
        .unwrap_or(serde_json::json!([]));
    let features = metadata
        .get("features")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let features2 = metadata.get("features2").cloned();
    let links = metadata.get("links").cloned();

    let mut index_entry = serde_json::json!({
        "name": name,
        "vers": vers,
        "deps": deps,
        "cksum": cksum,
        "features": features,
        "yanked": false,
    });

    if let Some(f2) = features2 {
        index_entry["features2"] = f2;
    }
    if let Some(l) = links {
        index_entry["links"] = l;
    }

    let entry_line = serde_json::to_string(&index_entry).unwrap_or_default();

    // Write index FIRST — if it fails, no orphaned .crate file
    // If .crate write fails later, re-publish is possible (immutability checks .crate, not index)
    let index_key = index_lock_key.clone();

    let mut index_content = state
        .storage
        .get(&index_key)
        .await
        .map(|d| d.to_vec())
        .unwrap_or_default();

    // Ensure newline separator
    if !index_content.is_empty() && !index_content.ends_with(b"\n") {
        index_content.push(b'\n');
    }
    index_content.extend_from_slice(entry_line.as_bytes());
    index_content.push(b'\n');

    if state.storage.put(&index_key, &index_content).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Store .crate tarball SECOND
    if state.storage.put(&crate_key, crate_data).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    state.metrics.record_upload("cargo");
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        format!("{}@{}", name, vers),
        "cargo",
        "LOCAL",
    ));
    state
        .audit
        .log(AuditEntry::new("push", "api", "", "cargo", ""));
    state.repo_index.invalidate("cargo");

    // Cargo expects a JSON response with warnings array
    let response = serde_json::json!({
        "warnings": {
            "invalid_categories": [],
            "invalid_badges": [],
            "other": []
        }
    });

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::to_vec(&response).unwrap_or_default(),
    )
        .into_response()
}

// ============================================================================
// Helpers
// ============================================================================

/// Compute sparse index prefix for a crate name (RFC 2789).
fn crate_index_prefix(name: &str) -> String {
    let lower = name.to_lowercase();
    match lower.len() {
        1 => "1".to_string(),
        2 => "2".to_string(),
        3 => format!("3/{}", &lower[..1]),
        _ => format!("{}/{}", &lower[..2], &lower[2..4]),
    }
}

/// Validate crate name per Cargo spec.
fn is_valid_crate_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    // Must start with alphanumeric
    let first = name.chars().next().unwrap_or('\0');
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    // Only alphanumeric, `-`, `_`
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Construct NORA base URL from config.
fn nora_base_url(state: &AppState) -> String {
    if let Some(url) = &state.config.server.public_url {
        return url.clone();
    }
    format!(
        "http://{}:{}",
        state.config.server.host, state.config.server.port
    )
}

/// Build response with sparse index content-type.
fn sparse_index_response(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=300"),
            ),
        ],
        data,
    )
        .into_response()
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── Prefix computation (RFC 2789) ───────────────────────────────────

    #[test]
    fn test_prefix_single_char() {
        assert_eq!(crate_index_prefix("a"), "1");
        assert_eq!(crate_index_prefix("Z"), "1");
    }

    #[test]
    fn test_prefix_two_chars() {
        assert_eq!(crate_index_prefix("ab"), "2");
        assert_eq!(crate_index_prefix("IO"), "2");
    }

    #[test]
    fn test_prefix_three_chars() {
        assert_eq!(crate_index_prefix("abc"), "3/a");
        assert_eq!(crate_index_prefix("Foo"), "3/f");
    }

    #[test]
    fn test_prefix_four_plus_chars() {
        assert_eq!(crate_index_prefix("serde"), "se/rd");
        assert_eq!(crate_index_prefix("tokio"), "to/ki");
        assert_eq!(crate_index_prefix("Axum"), "ax/um");
        assert_eq!(crate_index_prefix("ab_cd_ef"), "ab/_c");
    }

    // ── Crate name validation ───────────────────────────────────────────

    #[test]
    fn test_valid_crate_names() {
        assert!(is_valid_crate_name("serde"));
        assert!(is_valid_crate_name("my-crate"));
        assert!(is_valid_crate_name("my_crate"));
        assert!(is_valid_crate_name("a"));
        assert!(is_valid_crate_name("crate123"));
    }

    #[test]
    fn test_invalid_crate_names() {
        assert!(!is_valid_crate_name(""));
        assert!(!is_valid_crate_name("-start"));
        assert!(!is_valid_crate_name("_start"));
        assert!(!is_valid_crate_name("has space"));
        assert!(!is_valid_crate_name("has/slash"));
        assert!(!is_valid_crate_name("has..dots"));
        assert!(!is_valid_crate_name("has\\backslash"));
        assert!(!is_valid_crate_name(&"a".repeat(65)));
    }

    #[test]
    fn test_crate_name_max_length() {
        assert!(is_valid_crate_name(&"a".repeat(64)));
        assert!(!is_valid_crate_name(&"a".repeat(65)));
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::body::Body;
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_cargo_index_config() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::GET, "/cargo/index/config.json", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("dl").is_some());
        assert!(json.get("api").is_some());
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_from_storage() {
        let ctx = create_test_context();
        let index_data = br#"{"name":"serde","vers":"1.0.0","deps":[],"cksum":"abc123","features":{},"yanked":false}"#;
        ctx.state
            .storage
            .put("cargo/index/se/rd/serde", index_data)
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/cargo/index/se/rd/serde", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], index_data);
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_wrong_prefix() {
        let ctx = create_test_context();
        // "serde" should be at se/rd/serde, not 1/serde
        let resp = send(&ctx.app, Method::GET, "/cargo/index/1/serde", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_single_char() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("cargo/index/1/a", b"index-data")
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/cargo/index/1/a", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_two_char() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("cargo/index/2/ab", b"index-data")
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/cargo/index/2/ab", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_three_char() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("cargo/index/3/f/foo", b"index-data")
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/cargo/index/3/f/foo", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_cargo_sparse_index_not_found_no_proxy() {
        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::GET, "/cargo/index/se/rd/serde", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_cargo_metadata_not_found() {
        let ctx = create_test_context();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/nonexistent",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_cargo_metadata_from_storage() {
        let ctx = create_test_context();
        let meta = r#"{"name":"test-crate","versions":[]}"#;
        ctx.state
            .storage
            .put("cargo/test-crate/metadata.json", meta.as_bytes())
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/cargo/api/v1/crates/test-crate", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], meta.as_bytes());
    }

    #[tokio::test]
    async fn test_cargo_download_not_found() {
        let ctx = create_test_context();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/missing/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_cargo_download_from_storage() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("cargo/my-crate/1.2.3/my-crate-1.2.3.crate", b"crate-data")
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/my-crate/1.2.3/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"crate-data");
    }

    // ── Publish tests ───────────────────────────────────────────────────

    /// Build cargo publish wire format: 4-byte LE metadata len + metadata + 4-byte LE crate len + crate
    fn build_publish_payload(metadata: &serde_json::Value, crate_data: &[u8]) -> Vec<u8> {
        let meta_bytes = serde_json::to_vec(metadata).unwrap();
        let meta_len = (meta_bytes.len() as u32).to_le_bytes();
        let crate_len = (crate_data.len() as u32).to_le_bytes();

        let mut payload = Vec::new();
        payload.extend_from_slice(&meta_len);
        payload.extend_from_slice(&meta_bytes);
        payload.extend_from_slice(&crate_len);
        payload.extend_from_slice(crate_data);
        payload
    }

    #[tokio::test]
    async fn test_cargo_publish_basic() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "my-crate",
            "vers": "0.1.0",
            "deps": [],
            "features": {},
        });
        let crate_data = b"fake-crate-tarball";
        let payload = build_publish_payload(&metadata, crate_data);

        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify .crate stored
        let stored = ctx
            .state
            .storage
            .get("cargo/my-crate/0.1.0/my-crate-0.1.0.crate")
            .await
            .unwrap();
        assert_eq!(&stored[..], crate_data);

        // Verify sparse index entry created
        let index = ctx
            .state
            .storage
            .get("cargo/index/my/-c/my-crate")
            .await
            .unwrap();
        let index_str = String::from_utf8_lossy(&index);
        assert!(index_str.contains("\"name\":\"my-crate\""));
        assert!(index_str.contains("\"vers\":\"0.1.0\""));
        assert!(index_str.contains("\"cksum\":"));
    }

    #[tokio::test]
    async fn test_cargo_publish_version_immutability() {
        let ctx = create_test_context();

        // First publish
        let metadata = serde_json::json!({
            "name": "immut-test",
            "vers": "1.0.0",
            "deps": [],
            "features": {},
        });
        let payload = build_publish_payload(&metadata, b"crate-v1");
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Second publish with same version → CONFLICT
        let payload2 = build_publish_payload(&metadata, b"crate-v1-again");
        let resp2 = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload2),
        )
        .await;
        assert_eq!(resp2.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_cargo_publish_multiple_versions() {
        let ctx = create_test_context();

        // v0.1.0
        let m1 =
            serde_json::json!({"name": "multi-ver", "vers": "0.1.0", "deps": [], "features": {}});
        let p1 = build_publish_payload(&m1, b"crate-01");
        let r1 = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(p1),
        )
        .await;
        assert_eq!(r1.status(), StatusCode::OK);

        // v0.2.0
        let m2 =
            serde_json::json!({"name": "multi-ver", "vers": "0.2.0", "deps": [], "features": {}});
        let p2 = build_publish_payload(&m2, b"crate-02");
        let r2 = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(p2),
        )
        .await;
        assert_eq!(r2.status(), StatusCode::OK);

        // Index should have 2 lines
        let index = ctx
            .state
            .storage
            .get("cargo/index/mu/lt/multi-ver")
            .await
            .unwrap();
        let index_str = String::from_utf8_lossy(&index);
        let lines: Vec<&str> = index_str.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("0.1.0"));
        assert!(lines[1].contains("0.2.0"));
    }

    #[tokio::test]
    async fn test_cargo_publish_invalid_name() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "../traversal",
            "vers": "1.0.0",
            "deps": [],
            "features": {},
        });
        let payload = build_publish_payload(&metadata, b"bad");

        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_cargo_publish_truncated_payload() {
        let ctx = create_test_context();
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(vec![0u8; 3]),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_cargo_publish_response_has_warnings() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "warn-test",
            "vers": "1.0.0",
            "deps": [],
            "features": {},
        });
        let payload = build_publish_payload(&metadata, b"crate-data");

        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("warnings").is_some());
    }

    #[tokio::test]
    async fn test_cargo_publish_then_download() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "roundtrip",
            "vers": "2.0.0",
            "deps": [],
            "features": {},
        });
        let crate_data = b"published-crate-content";
        let payload = build_publish_payload(&metadata, crate_data);

        // Publish
        let publish_resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(publish_resp.status(), StatusCode::OK);

        // Download
        let dl_resp = send(
            &ctx.app,
            Method::GET,
            "/cargo/api/v1/crates/roundtrip/2.0.0/download",
            "",
        )
        .await;
        assert_eq!(dl_resp.status(), StatusCode::OK);
        let body = body_bytes(dl_resp).await;
        assert_eq!(&body[..], crate_data);
    }

    #[tokio::test]
    async fn test_cargo_publish_then_sparse_index() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "idx-test",
            "vers": "1.0.0",
            "deps": [{"name": "serde", "req": "^1", "features": [], "optional": false, "default_features": true, "target": null, "kind": "normal"}],
            "features": {"default": ["serde"]},
            "links": null,
        });
        let payload = build_publish_payload(&metadata, b"crate");

        let publish_resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(publish_resp.status(), StatusCode::OK);

        // Sparse index lookup
        let idx_resp = send(&ctx.app, Method::GET, "/cargo/index/id/x-/idx-test", "").await;
        assert_eq!(idx_resp.status(), StatusCode::OK);

        let body = body_bytes(idx_resp).await;
        let line: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&body).lines().next().unwrap()).unwrap();
        assert_eq!(line["name"], "idx-test");
        assert_eq!(line["vers"], "1.0.0");
        assert!(line["deps"].as_array().unwrap().len() == 1);
        assert!(line["cksum"].as_str().unwrap().len() == 64); // sha256 hex
    }

    #[tokio::test]
    async fn test_cargo_publish_transforms_deps_version_req_to_req() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "dep-test",
            "vers": "1.0.0",
            "deps": [{
                "name": "serde",
                "version_req": "^1.0",
                "features": ["derive"],
                "optional": false,
                "default_features": true,
                "target": null,
                "kind": "normal",
                "registry": null,
                "explicit_name_in_toml": null
            }, {
                "name": "my_serde",
                "version_req": "^1.0",
                "features": [],
                "optional": false,
                "default_features": true,
                "target": null,
                "kind": "normal",
                "registry": null,
                "explicit_name_in_toml": "serde_json"
            }],
            "features": {},
        });
        let payload = build_publish_payload(&metadata, b"crate-data");

        let resp = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Read the sparse index entry
        let index = ctx
            .state
            .storage
            .get("cargo/index/de/p-/dep-test")
            .await
            .unwrap();
        let line: serde_json::Value =
            serde_json::from_str(String::from_utf8_lossy(&index).lines().next().unwrap()).unwrap();

        let deps = line["deps"].as_array().unwrap();
        assert_eq!(deps.len(), 2);

        // version_req must be renamed to req
        assert!(
            deps[0].get("version_req").is_none(),
            "version_req should not be in index"
        );
        assert_eq!(deps[0]["req"], "^1.0", "version_req must be renamed to req");

        // explicit_name_in_toml=null should be dropped (not become package=null)
        assert!(deps[0].get("explicit_name_in_toml").is_none());
        assert!(
            deps[0].get("package").is_none(),
            "null explicit_name_in_toml should not create package field"
        );

        // explicit_name_in_toml="serde_json" should become package="serde_json"
        assert!(deps[1].get("explicit_name_in_toml").is_none());
        assert_eq!(
            deps[1]["package"], "serde_json",
            "explicit_name_in_toml must become package"
        );
    }

    #[tokio::test]
    async fn test_cargo_publish_conflict_json_format() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "conflict-fmt",
            "vers": "1.0.0",
            "deps": [],
            "features": {},
        });
        let payload = build_publish_payload(&metadata, b"v1");
        let r1 = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload),
        )
        .await;
        assert_eq!(r1.status(), StatusCode::OK);

        // Second publish -> CONFLICT with Cargo JSON format
        let payload2 = build_publish_payload(&metadata, b"v1-again");
        let r2 = send(
            &ctx.app,
            Method::PUT,
            "/cargo/api/v1/crates/new",
            Body::from(payload2),
        )
        .await;
        assert_eq!(r2.status(), StatusCode::CONFLICT);

        let body = body_bytes(r2).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["errors"].as_array().unwrap().len() > 0);
        assert!(json["errors"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("already exists"));
    }
}
