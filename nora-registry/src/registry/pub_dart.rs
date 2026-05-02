// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Dart/Flutter pub registry proxy.
//!
//! Implements hosted pub repository endpoints from repository spec v2:
//!   GET /pub/api/packages?q={term}&page={page}         — package search
//!   GET /pub/api/packages/{package}                    — package metadata with versions
//!   GET /pub/api/packages/{package}/versions/{version} — version metadata
//!   GET /pub/api/packages/{package}/advisories         — security advisories
//!   GET /pub/packages/{package}/versions/{version}.tar.gz — package archive
//!
//! Client config:
//!   export PUB_HOSTED_URL=http://nora:4000/pub
//!   dart pub get

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::{proxy_fetch, ProxyError};
use crate::validation::validate_storage_key;
use crate::AppState;
use axum::{
    extract::{Path, RawQuery, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde_json::{Map, Value};
use sha2::Digest;
use std::sync::Arc;

const PUB_CONTENT_TYPE: &str = "application/vnd.pub.v2+json";
const PUB_ARCHIVE_CONTENT_TYPE: &str = "application/octet-stream";
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/pub/api/packages", get(search_packages))
        .route(
            "/pub/api/packages/{package}/advisories",
            get(package_advisories),
        )
        .route(
            "/pub/api/packages/{package}/versions/{version}",
            get(version_metadata),
        )
        .route("/pub/api/packages/{package}", get(package_listing))
        .route(
            "/pub/packages/{package}/versions/{archive}",
            get(download_archive),
        )
}

async fn search_packages(
    State(state): State<Arc<AppState>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let raw_query = raw_query.unwrap_or_default();
    let key = format!(
        "pub/search/{}.json",
        hex::encode(sha2::Sha256::digest(raw_query.as_bytes()))
    );

    if let Ok(data) = state.storage.get(&key).await {
        return pub_json_response(data.to_vec());
    }

    let Some(proxy_url) = &state.config.pub_dart.proxy else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let url = if raw_query.is_empty() {
        format!("{}/api/packages", proxy_url.trim_end_matches('/'))
    } else {
        format!(
            "{}/api/packages?{}",
            proxy_url.trim_end_matches('/'),
            raw_query
        )
    };

    match fetch_pub_api(&state, &url).await {
        Ok(data) => {
            let nora_base = nora_base_url(&state);
            let rewritten = rewrite_search_response(&data, &nora_base, proxy_url).unwrap_or(data);
            cache_bytes(&state, key, rewritten.clone()).await;
            pub_json_response(rewritten)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, query = raw_query, "pub search upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn package_listing(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(package): Path<String>,
) -> Response {
    if !is_valid_pub_package_name(&package) {
        return pub_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_package",
            "Invalid pub package name",
        );
    }

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::PubDart,
        &package,
        None,
        None,
    ) {
        return response;
    }

    let key = format!("pub/api/packages/{}.json", package);
    if let Ok(data) = state.storage.get(&key).await {
        return pub_json_response(data.to_vec());
    }

    let Some(proxy_url) = &state.config.pub_dart.proxy else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let url = format!(
        "{}/api/packages/{}",
        proxy_url.trim_end_matches('/'),
        encode_segment(&package)
    );

    match fetch_pub_api(&state, &url).await {
        Ok(data) => {
            let nora_base = nora_base_url(&state);
            let rewritten = rewrite_package_response(&data, &nora_base, &package).unwrap_or(data);
            cache_bytes(&state, key, rewritten.clone()).await;
            state.repo_index.invalidate("pub");
            pub_json_response(rewritten)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, package, "pub package upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn version_metadata(
    State(state): State<Arc<AppState>>,
    Path((package, version)): Path<(String, String)>,
) -> Response {
    if !is_valid_pub_package_name(&package) || !is_valid_pub_version(&version) {
        return pub_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_version",
            "Invalid package name or version",
        );
    }

    let key = format!("pub/api/packages/{}/versions/{}.json", package, version);
    if let Ok(data) = state.storage.get(&key).await {
        return pub_json_response(data.to_vec());
    }

    let Some(proxy_url) = &state.config.pub_dart.proxy else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let url = format!(
        "{}/api/packages/{}/versions/{}",
        proxy_url.trim_end_matches('/'),
        encode_segment(&package),
        encode_segment(&version)
    );

    match fetch_pub_api(&state, &url).await {
        Ok(data) => {
            let nora_base = nora_base_url(&state);
            let rewritten = rewrite_version_response(&data, &nora_base, &package).unwrap_or(data);
            cache_bytes(&state, key, rewritten.clone()).await;
            pub_json_response(rewritten)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, package, version, "pub version upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn package_advisories(
    State(state): State<Arc<AppState>>,
    Path(package): Path<String>,
) -> Response {
    if !is_valid_pub_package_name(&package) {
        return pub_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_package",
            "Invalid pub package name",
        );
    }

    let key = format!("pub/api/packages/{}/advisories.json", package);
    if let Ok(data) = state.storage.get(&key).await {
        return pub_json_response(data.to_vec());
    }

    let Some(proxy_url) = &state.config.pub_dart.proxy else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let url = format!(
        "{}/api/packages/{}/advisories",
        proxy_url.trim_end_matches('/'),
        encode_segment(&package)
    );

    match fetch_pub_api(&state, &url).await {
        Ok(data) => {
            cache_bytes(&state, key, data.clone()).await;
            pub_json_response(data)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, package, "pub advisories upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn download_archive(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((package, archive)): Path<(String, String)>,
) -> Response {
    let Some(version) = archive.strip_suffix(".tar.gz") else {
        return pub_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_version",
            "Invalid package archive name",
        );
    };

    if !is_valid_pub_package_name(&package) || !is_valid_pub_version(version) {
        return pub_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_version",
            "Invalid package name or version",
        );
    }

    // Extract publish date from cached metadata (works for both hosted and proxy)
    let publish_date = extract_pub_publish_date(&state.storage, &package, version).await;

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::PubDart,
        &package,
        Some(version),
        publish_date,
    ) {
        return response;
    }

    let key = format!("pub/packages/{}/versions/{}.tar.gz", package, version);

    if let Ok(data) = state.storage.get(&key).await {
        // Integrity verification (curation allowlist)
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation,
            crate::curation::RegistryType::PubDart,
            &package,
            Some(version),
            &data,
        ) {
            return response;
        }

        if let Ok(stored_hash) = state.storage.get(&format!("{}.sha256", key)).await {
            let expected = String::from_utf8_lossy(&stored_hash);
            let computed = hex::encode(sha2::Sha256::digest(&data));
            if computed != expected.as_ref() {
                tracing::error!(package, version, "pub archive integrity check failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }

        state.metrics.record_download("pub");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::Pull,
            format!("{}@{}", package, version),
            "pub",
            "LOCAL",
        ));
        state
            .audit
            .log(AuditEntry::new("pull", "api", "", "pub", ""));

        return archive_response(data.to_vec());
    }

    let Some(proxy_url) = &state.config.pub_dart.proxy else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let encoded_version = encode_segment(version);
    let url = if proxy_url.contains("pub.dev") {
        format!(
            "{}/api/archives/{}-{}.tar.gz",
            proxy_url.trim_end_matches('/'),
            encode_segment(&package),
            encoded_version
        )
    } else {
        format!(
            "{}/packages/{}/versions/{}.tar.gz",
            proxy_url.trim_end_matches('/'),
            encode_segment(&package),
            encoded_version
        )
    };

    match proxy_fetch(
        &state.http_client,
        &url,
        state.config.pub_dart.proxy_timeout,
        state.config.pub_dart.proxy_auth.as_deref(),
    )
    .await
    {
        Ok(data) => {
            let hash = hex::encode(sha2::Sha256::digest(&data));
            cache_bytes(&state, key.clone(), data.clone()).await;
            cache_bytes(&state, format!("{}.sha256", key), hash.into_bytes()).await;
            state.repo_index.invalidate("pub");

            state.metrics.record_download("pub");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::Pull,
                format!("{}@{}", package, version),
                "pub",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "pub", ""));

            archive_response(data)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, package, version, "pub archive upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn fetch_pub_api(state: &AppState, url: &str) -> Result<Vec<u8>, ProxyError> {
    super::proxy_fetch_core(
        &state.http_client,
        url,
        state.config.pub_dart.proxy_timeout,
        state.config.pub_dart.proxy_auth.as_deref(),
        Some(("Accept", PUB_CONTENT_TYPE)),
        |response| async { response.bytes().await.map(|b| b.to_vec()) },
    )
    .await
}

async fn cache_bytes(state: &Arc<AppState>, key: String, data: Vec<u8>) {
    let _ = state.storage.put(&key, &data).await;
}

fn pub_json_response(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(PUB_CONTENT_TYPE),
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

fn archive_response(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(PUB_ARCHIVE_CONTENT_TYPE),
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

fn pub_error_response(status: StatusCode, code: &str, message: &str) -> Response {
    let body = serde_json::json!({
        "error": {
            "code": code,
            "message": message,
        }
    });
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(PUB_CONTENT_TYPE),
        )],
        serde_json::to_vec(&body).unwrap_or_default(),
    )
        .into_response()
}

fn rewrite_package_response(data: &[u8], nora_base: &str, package: &str) -> Result<Vec<u8>, ()> {
    let mut json: Value = serde_json::from_slice(data).map_err(|_| ())?;

    if let Some(latest) = json.get_mut("latest").and_then(|v| v.as_object_mut()) {
        rewrite_version_object(latest, nora_base, package, false);
    }
    if let Some(versions) = json.get_mut("versions").and_then(|v| v.as_array_mut()) {
        for version in versions {
            if let Some(obj) = version.as_object_mut() {
                rewrite_version_object(obj, nora_base, package, false);
            }
        }
    }

    serde_json::to_vec(&json).map_err(|_| ())
}

fn rewrite_version_response(data: &[u8], nora_base: &str, package: &str) -> Result<Vec<u8>, ()> {
    let mut json: Value = serde_json::from_slice(data).map_err(|_| ())?;
    let Some(obj) = json.as_object_mut() else {
        return Err(());
    };
    rewrite_version_object(obj, nora_base, package, false);
    serde_json::to_vec(&json).map_err(|_| ())
}

fn rewrite_search_response(data: &[u8], nora_base: &str, proxy_url: &str) -> Result<Vec<u8>, ()> {
    let mut json: Value = serde_json::from_slice(data).map_err(|_| ())?;

    if let Some(packages) = json.get_mut("packages").and_then(|v| v.as_array_mut()) {
        for package in packages {
            let Some(name) = package
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
            else {
                continue;
            };
            if let Some(latest) = package.get_mut("latest").and_then(|v| v.as_object_mut()) {
                rewrite_version_object(latest, nora_base, &name, true);
            }
        }
    }

    if let Some(next_url) = json.get("next_url").and_then(|v| v.as_str()) {
        let rewritten = rewrite_next_url(next_url, nora_base, proxy_url);
        json["next_url"] = Value::String(rewritten);
    }

    serde_json::to_vec(&json).map_err(|_| ())
}

fn rewrite_version_object(
    object: &mut Map<String, Value>,
    nora_base: &str,
    package: &str,
    include_search_urls: bool,
) {
    let Some(version) = object
        .get("version")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
    else {
        return;
    };
    let version = version.as_str();

    object.insert(
        "archive_url".to_string(),
        Value::String(nora_archive_url(nora_base, package, version)),
    );

    if include_search_urls && object.contains_key("package_url") {
        object.insert(
            "package_url".to_string(),
            Value::String(nora_package_url(nora_base, package)),
        );
    }
    if include_search_urls && object.contains_key("url") {
        object.insert(
            "url".to_string(),
            Value::String(nora_version_url(nora_base, package, version)),
        );
    }
}

fn rewrite_next_url(next_url: &str, nora_base: &str, proxy_url: &str) -> String {
    let upstream_prefix = format!("{}/api/packages", proxy_url.trim_end_matches('/'));
    let nora_prefix = format!("{}/api/packages", nora_base.trim_end_matches('/'));

    next_url
        .strip_prefix(&upstream_prefix)
        .map(|suffix| format!("{}{}", nora_prefix, suffix))
        .unwrap_or_else(|| next_url.to_string())
}

fn nora_archive_url(nora_base: &str, package: &str, version: &str) -> String {
    format!(
        "{}/packages/{}/versions/{}.tar.gz",
        nora_base.trim_end_matches('/'),
        encode_segment(package),
        encode_segment(version)
    )
}

fn nora_package_url(nora_base: &str, package: &str) -> String {
    format!(
        "{}/api/packages/{}",
        nora_base.trim_end_matches('/'),
        encode_segment(package)
    )
}

fn nora_version_url(nora_base: &str, package: &str, version: &str) -> String {
    format!(
        "{}/api/packages/{}/versions/{}",
        nora_base.trim_end_matches('/'),
        encode_segment(package),
        encode_segment(version)
    )
}

/// Build NORA base URL with /pub prefix for URL rewriting.
fn nora_base_url(state: &AppState) -> String {
    if let Some(url) = &state.config.server.public_url {
        return format!("{}/pub", url.trim_end_matches('/'));
    }
    format!(
        "http://{}:{}/pub",
        state.config.server.host, state.config.server.port
    )
}

fn encode_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

/// Extract publish date from cached pub.dev package metadata.
///
/// Pub metadata JSON has a `versions` array, each with `published`:
/// ```json
/// { "versions": [{ "version": "1.0.0", "published": "2024-01-15T10:30:00.000Z" }] }
/// ```
async fn extract_pub_publish_date(
    storage: &crate::storage::Storage,
    package: &str,
    version: &str,
) -> Option<i64> {
    let meta_key = format!("pub/api/packages/{}.json", package);
    let data = storage.get(&meta_key).await.ok()?;
    let json: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let versions = json.get("versions")?.as_array()?;
    for v in versions {
        if v.get("version")?.as_str()? == version {
            let date_str = v.get("published")?.as_str()?;
            return crate::curation::parse_iso8601_to_unix(date_str);
        }
    }
    None
}

fn is_valid_pub_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }

    let Some(first) = name.chars().next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && first != '_' {
        return false;
    }

    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn is_valid_pub_version(version: &str) -> bool {
    validate_storage_key(version).is_ok()
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '_'))
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn create_pub_proxy_test_context(proxy_url: String) -> TestContext {
        create_test_context_with_config(move |cfg| {
            cfg.pub_dart.enabled = true;
            cfg.pub_dart.proxy = Some(proxy_url);
        })
    }

    #[test]
    fn test_valid_pub_package_names() {
        assert!(is_valid_pub_package_name("http"));
        assert!(is_valid_pub_package_name("flutter_test"));
        assert!(is_valid_pub_package_name("a1_b2"));
        assert!(is_valid_pub_package_name("_private_pkg"));
    }

    #[test]
    fn test_invalid_pub_package_names() {
        assert!(!is_valid_pub_package_name(""));
        assert!(!is_valid_pub_package_name("Http"));
        assert!(!is_valid_pub_package_name("with-dash"));
        assert!(!is_valid_pub_package_name("1starts_with_digit"));
        assert!(!is_valid_pub_package_name("with/slash"));
    }

    #[test]
    fn test_rewrite_package_response_rewrites_archive_urls() {
        let source = serde_json::json!({
            "name": "http",
            "latest": {
                "version": "1.2.0",
                "archive_url": "https://pub.dev/api/archives/http-1.2.0.tar.gz"
            },
            "versions": [{
                "version": "1.2.0",
                "archive_url": "https://pub.dev/api/archives/http-1.2.0.tar.gz"
            }]
        });

        let rewritten = rewrite_package_response(
            &serde_json::to_vec(&source).unwrap(),
            "http://127.0.0.1:4000/pub",
            "http",
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(
            json["latest"]["archive_url"],
            "http://127.0.0.1:4000/pub/packages/http/versions/1.2.0.tar.gz"
        );
        assert_eq!(
            json["versions"][0]["archive_url"],
            "http://127.0.0.1:4000/pub/packages/http/versions/1.2.0.tar.gz"
        );
    }

    #[test]
    fn test_rewrite_search_response_rewrites_next_and_package_urls() {
        let source = serde_json::json!({
            "next_url": "https://pub.dev/api/packages?page=2&q=http",
            "packages": [{
                "name": "http",
                "latest": {
                    "version": "1.2.0",
                    "archive_url": "https://pub.dev/api/archives/http-1.2.0.tar.gz",
                    "package_url": "https://pub.dev/api/packages/http",
                    "url": "https://pub.dev/api/packages/http/versions/1.2.0"
                }
            }]
        });

        let rewritten = rewrite_search_response(
            &serde_json::to_vec(&source).unwrap(),
            "http://127.0.0.1:4000/pub",
            "https://pub.dev",
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();

        assert_eq!(
            json["next_url"],
            "http://127.0.0.1:4000/pub/api/packages?page=2&q=http"
        );
        assert_eq!(
            json["packages"][0]["latest"]["package_url"],
            "http://127.0.0.1:4000/pub/api/packages/http"
        );
        assert_eq!(
            json["packages"][0]["latest"]["url"],
            "http://127.0.0.1:4000/pub/api/packages/http/versions/1.2.0"
        );
    }

    #[tokio::test]
    async fn test_pub_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.pub_dart.enabled = false;
        });
        let resp = send(&ctx.app, Method::GET, "/pub/api/packages/http", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_pub_package_metadata_proxy_and_cache() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/packages/http"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", PUB_CONTENT_TYPE)
                    .set_body_json(serde_json::json!({
                        "name": "http",
                        "latest": {
                            "version": "1.2.0",
                            "archive_url": format!("{}/api/archives/http-1.2.0.tar.gz", server.uri()),
                            "archive_sha256": "abc123",
                            "pubspec": {"name": "http", "version": "1.2.0"}
                        },
                        "versions": [{
                            "version": "1.2.0",
                            "archive_url": format!("{}/api/archives/http-1.2.0.tar.gz", server.uri()),
                            "archive_sha256": "abc123",
                            "pubspec": {"name": "http", "version": "1.2.0"}
                        }]
                    })),
            )
            .mount(&server)
            .await;

        let ctx = create_pub_proxy_test_context(server.uri());

        let resp = send(&ctx.app, Method::GET, "/pub/api/packages/http", "").await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_bytes(resp).await;
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(json["latest"]["archive_url"]
            .as_str()
            .unwrap()
            .contains("/pub/packages/http/versions/1.2.0.tar.gz"));

        let cached = ctx
            .state
            .storage
            .get("pub/api/packages/http.json")
            .await
            .unwrap();
        let cached_json: Value = serde_json::from_slice(&cached).unwrap();
        assert_eq!(cached_json["name"], "http");
    }

    #[tokio::test]
    async fn test_pub_archive_from_storage() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.pub_dart.enabled = true;
        });
        ctx.state
            .storage
            .put("pub/packages/http/versions/1.2.0.tar.gz", b"archive-data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                "pub/packages/http/versions/1.2.0.tar.gz.sha256",
                hex::encode(sha2::Sha256::digest(b"archive-data")).as_bytes(),
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/pub/packages/http/versions/1.2.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"archive-data");
    }

    #[tokio::test]
    async fn test_pub_advisories_proxy_and_cache() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/packages/http/advisories"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", PUB_CONTENT_TYPE)
                    .set_body_json(serde_json::json!({
                        "advisories": [],
                        "advisoriesUpdated": "2024-04-28T09:27:57.869544Z"
                    })),
            )
            .mount(&server)
            .await;

        let ctx = create_pub_proxy_test_context(server.uri());

        let resp = send(
            &ctx.app,
            Method::GET,
            "/pub/api/packages/http/advisories",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cached = ctx
            .state
            .storage
            .get("pub/api/packages/http/advisories.json")
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&cached).unwrap();
        assert!(json["advisories"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_extract_pub_publish_date_found() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let meta = serde_json::json!({
            "name": "http",
            "versions": [
                {"version": "0.13.0", "published": "2021-01-08T12:30:00.000Z"},
                {"version": "1.0.0", "published": "2023-05-15T08:00:00.000Z"}
            ]
        });
        storage
            .put(
                "pub/api/packages/http.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let result = super::extract_pub_publish_date(&storage, "http", "1.0.0").await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_extract_pub_publish_date_version_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let meta = serde_json::json!({
            "name": "http",
            "versions": [{"version": "1.0.0", "published": "2023-05-15T08:00:00Z"}]
        });
        storage
            .put(
                "pub/api/packages/http.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let result = super::extract_pub_publish_date(&storage, "http", "2.0.0").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_extract_pub_publish_date_no_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

        let result = super::extract_pub_publish_date(&storage, "nonexistent", "1.0.0").await;
        assert!(result.is_none());
    }
}
