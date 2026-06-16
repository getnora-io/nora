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
use crate::cache_ttl::is_within_ttl;
use crate::registry::{
    circuit_open_response, nora_base_url as nora_base_url_shared, proxy_fetch,
    proxy_fetch_conditional, read_validators, write_validators, ProxyError, Revalidation,
    Validators,
};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
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
use std::time::Duration;

/// Storage prefix and file suffix for repo index scanning.
pub const INDEX_PATTERN: (&str, &str) = ("pub/", ".tar.gz");

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

pub fn routes() -> Router<AppState> {
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

async fn search_packages(State(state): State<AppState>, RawQuery(raw_query): RawQuery) -> Response {
    let raw_query = raw_query.unwrap_or_default();
    let key = format!(
        "pub/search/{}.json",
        hex::encode(sha2::Sha256::digest(raw_query.as_bytes()))
    );

    let cached_data = state.storage.get(&key).await.ok();
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&key).await {
            if is_within_ttl(meta.modified, state.config.pub_dart.metadata_ttl) {
                return pub_json_response(data.to_vec());
            }
        }
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

    match fetch_pub_api(&state, &url, &state.circuit_breaker).await {
        Ok(data) => {
            let nora_base = pub_base_url(&state);
            let rewritten = rewrite_search_response(&data, &nora_base, proxy_url).unwrap_or(data);
            cache_bytes(&state, key, rewritten.clone()).await;
            pub_json_response(rewritten)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            if let Some(ref data) = cached_data {
                if state.config.pub_dart.serve_stale {
                    tracing::warn!(
                        registry = "pub",
                        query = raw_query,
                        error = ?e,
                        "Pub upstream error, serving stale search results"
                    );
                    return pub_stale_json_response(data.to_vec());
                }
            }
            tracing::debug!(error = ?e, query = raw_query, "pub search upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn package_listing(
    State(state): State<AppState>,
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
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        crate::curation::RegistryType::PubDart,
        &package,
        None,
        None,
    ) {
        return response;
    }

    let key = format!("pub/api/packages/{}.json", package);
    let cached_data = state.storage.get(&key).await.ok();
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&key).await {
            if is_within_ttl(meta.modified, state.config.pub_dart.metadata_ttl) {
                return pub_json_response(data.to_vec());
            }
        }
    }

    let Some(proxy_url) = &state.config.pub_dart.proxy else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let url = format!(
        "{}/api/packages/{}",
        proxy_url.trim_end_matches('/'),
        encode_segment(&package)
    );

    // Revalidate stale metadata with a conditional request when enabled (a cheap
    // 304 — pub.dev returns validators) and fall back to a full fetch otherwise.
    // Empty validators ⇒ no conditional headers ⇒ always a 200, which is also how
    // the first fetch captures validators for next time.
    let validators = if state.config.pub_dart.revalidate {
        read_validators(&state.storage, &key)
            .await
            .unwrap_or_default()
    } else {
        Validators::default()
    };
    let had_validators = validators.is_some();

    match proxy_fetch_conditional(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.pub_dart.proxy_timeout),
        expose_opt(&state.config.pub_dart.proxy_auth),
        &validators,
        &state.circuit_breaker,
        RegistryType::PubDart,
    )
    .await
    {
        // Upstream unchanged — serve the cached (already-rewritten) body and bump
        // its freshness. No body downloaded.
        Ok(Revalidation::NotModified) => {
            let body = match state.storage.get(&key).await {
                Ok(b) => b,
                Err(_) => match &cached_data {
                    Some(b) => b.clone(),
                    None => return StatusCode::BAD_GATEWAY.into_response(),
                },
            };
            crate::metrics::PROXY_UPSTREAM_304_TOTAL
                .with_label_values(&["pub"])
                .inc();
            crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                .with_label_values(&["pub"])
                .inc_by(body.len() as u64);
            let storage = state.storage.clone();
            let key_clone = key.clone();
            let bump = body.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key_clone, &bump).await;
            });
            pub_json_response(body.to_vec())
        }
        // New body — rewrite, cache the rewritten body first, then persist the
        // fresh validators (body-before-sidecar ordering).
        Ok(Revalidation::Modified { body, validators }) => {
            let nora_base = pub_base_url(&state);
            let rewritten = rewrite_package_response(&body, &nora_base, &package).unwrap_or(body);
            cache_bytes(&state, key.clone(), rewritten.clone()).await;
            write_validators(&state.storage, &key, &validators).await;
            state.repo_index.invalidate("pub");
            pub_json_response(rewritten)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["pub"])
                    .inc();
            }
            if let Some(ref data) = cached_data {
                if state.config.pub_dart.serve_stale {
                    tracing::warn!(
                        registry = "pub",
                        package = %package,
                        error = ?e,
                        "Pub upstream error, serving stale package listing"
                    );
                    return pub_stale_json_response(data.to_vec());
                }
            }
            tracing::debug!(error = ?e, package, "pub package upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn version_metadata(
    State(state): State<AppState>,
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
    let cached_data = state.storage.get(&key).await.ok();
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&key).await {
            if is_within_ttl(meta.modified, state.config.pub_dart.metadata_ttl) {
                return pub_json_response(data.to_vec());
            }
        }
    }

    // #68 namespace isolation: an internal-namespace package's version metadata must
    // never be fetched upstream (dependency confusion). Serve any local copy (fresh
    // path returned above), else block — never proxy.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::PubDart,
        &package,
    ) {
        if let Some(ref data) = cached_data {
            return pub_json_response(data.to_vec());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::PubDart,
            &package,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
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

    match fetch_pub_api(&state, &url, &state.circuit_breaker).await {
        Ok(data) => {
            let nora_base = pub_base_url(&state);
            let rewritten = rewrite_version_response(&data, &nora_base, &package).unwrap_or(data);
            cache_bytes(&state, key, rewritten.clone()).await;
            pub_json_response(rewritten)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            if let Some(ref data) = cached_data {
                if state.config.pub_dart.serve_stale {
                    tracing::warn!(
                        registry = "pub",
                        package = %package,
                        version = %version,
                        error = ?e,
                        "Pub upstream error, serving stale version metadata"
                    );
                    return pub_stale_json_response(data.to_vec());
                }
            }
            tracing::debug!(error = ?e, package, version, "pub version upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn package_advisories(
    State(state): State<AppState>,
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
    let cached_data = state.storage.get(&key).await.ok();
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&key).await {
            if is_within_ttl(meta.modified, state.config.pub_dart.metadata_ttl) {
                return pub_json_response(data.to_vec());
            }
        }
    }

    // #68 namespace isolation: an internal-namespace package's advisories must never
    // be fetched upstream (dependency confusion). Serve any local copy (fresh path
    // returned above), else block — never proxy.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::PubDart,
        &package,
    ) {
        if let Some(ref data) = cached_data {
            return pub_json_response(data.to_vec());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::PubDart,
            &package,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    let Some(proxy_url) = &state.config.pub_dart.proxy else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let url = format!(
        "{}/api/packages/{}/advisories",
        proxy_url.trim_end_matches('/'),
        encode_segment(&package)
    );

    match fetch_pub_api(&state, &url, &state.circuit_breaker).await {
        Ok(data) => {
            cache_bytes(&state, key, data.clone()).await;
            pub_json_response(data)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            if let Some(ref data) = cached_data {
                if state.config.pub_dart.serve_stale {
                    tracing::warn!(
                        registry = "pub",
                        package = %package,
                        error = ?e,
                        "Pub upstream error, serving stale advisories"
                    );
                    return pub_stale_json_response(data.to_vec());
                }
            }
            tracing::debug!(error = ?e, package, "pub advisories upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn download_archive(
    State(state): State<AppState>,
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
    let publish_date = extract_pub_publish_date(
        &state.storage,
        &package,
        version,
        state.config.server.trust_upstream_dates,
    )
    .await;

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        crate::curation::RegistryType::PubDart,
        &package,
        Some(version),
        publish_date,
    ) {
        return response;
    }

    let key = format!("pub/packages/{}/versions/{}.tar.gz", package, version);

    // get_verified discharges the integrity witness at the serve site (compile-time
    // guarantee — see crate::verified). The .sha256 sidecar check below is kept: it
    // is the integrity check on S3 (storage pins are local-only).
    if let Ok(outcome) = state.storage.get_verified(&key).await {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        // Integrity verification (curation allowlist)
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
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
        state.metrics.record_cache_hit("pub");
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
        Duration::from_secs(state.config.pub_dart.proxy_timeout),
        expose_opt(&state.config.pub_dart.proxy_auth),
        &state.circuit_breaker,
        RegistryType::PubDart,
    )
    .await
    {
        Ok(data) => {
            let hash = hex::encode(sha2::Sha256::digest(&data));
            cache_bytes(&state, key.clone(), data.clone()).await;
            cache_bytes(&state, format!("{}.sha256", key), hash.into_bytes()).await;
            state.repo_index.invalidate("pub");

            state.metrics.record_download("pub");
            state.metrics.record_cache_miss("pub");
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
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, package, version, "pub archive upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn fetch_pub_api(
    state: &AppState,
    url: &str,
    cb: &crate::circuit_breaker::CircuitBreakerRegistry,
) -> Result<Vec<u8>, ProxyError> {
    super::proxy_fetch_core(
        &state.http_client,
        url,
        Duration::from_secs(state.config.pub_dart.proxy_timeout),
        expose_opt(&state.config.pub_dart.proxy_auth),
        Some(("Accept", PUB_CONTENT_TYPE)),
        |response| async { response.bytes().await.map(|b| b.to_vec()) },
        cb,
        RegistryType::PubDart,
    )
    .await
}

async fn cache_bytes(state: &AppState, key: String, data: Vec<u8>) {
    if let Err(e) = state.storage.put(&key, &data).await {
        tracing::warn!(key = %key, error = %e, "pub: failed to cache proxy data");
    }
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

fn pub_stale_json_response(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(PUB_CONTENT_TYPE),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=0, must-revalidate"),
            ),
            (
                axum::http::header::HeaderName::from_static("x-nora-stale"),
                HeaderValue::from_static("true"),
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
    let mut json: Value = serde_json::from_slice(data).map_err(|e| {
        tracing::debug!(error = %e, package, "pub: failed to parse package response");
    })?;

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

    serde_json::to_vec(&json).map_err(|e| {
        tracing::debug!(error = %e, package, "pub: failed to serialize package response");
    })
}

fn rewrite_version_response(data: &[u8], nora_base: &str, package: &str) -> Result<Vec<u8>, ()> {
    let mut json: Value = serde_json::from_slice(data).map_err(|e| {
        tracing::debug!(error = %e, package, "pub: failed to parse version response");
    })?;
    let Some(obj) = json.as_object_mut() else {
        return Err(());
    };
    rewrite_version_object(obj, nora_base, package, false);
    serde_json::to_vec(&json).map_err(|e| {
        tracing::debug!(error = %e, package, "pub: failed to serialize version response");
    })
}

fn rewrite_search_response(data: &[u8], nora_base: &str, proxy_url: &str) -> Result<Vec<u8>, ()> {
    let mut json: Value = serde_json::from_slice(data).map_err(|e| {
        tracing::debug!(error = %e, "pub: failed to parse search response");
    })?;

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
        .unwrap_or_else(|| {
            tracing::warn!(
                next_url,
                expected_prefix = %upstream_prefix,
                "pub: next_url does not match expected upstream prefix, returning as-is"
            );
            next_url.to_string()
        })
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
fn pub_base_url(state: &AppState) -> String {
    format!("{}/pub", nora_base_url_shared(state))
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
    trust_upstream: bool,
) -> Option<i64> {
    let meta_key = format!("pub/api/packages/{}.json", package);
    // #513: untrusted upstream dates → NORA cache mtime, never upstream published.
    if !trust_upstream {
        return crate::curation::extract_mtime_as_publish_date(storage, &meta_key).await;
    }
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

    // ========================================================================
    // URL-rewrite systematic tests (#387)
    // ========================================================================

    /// Response without upstream URLs passes through with only archive_url rewritten (#387).
    #[test]
    fn test_rewrite_package_response_no_upstream_urls_noop() {
        let source = serde_json::json!({
            "name": "http",
            "latest": {
                "version": "1.2.0",
                "archive_url": "https://pub.dev/api/archives/http-1.2.0.tar.gz",
                "pubspec": {"name": "http", "version": "1.2.0"}
            },
            "versions": [{
                "version": "1.2.0",
                "archive_url": "https://pub.dev/api/archives/http-1.2.0.tar.gz",
                "pubspec": {"name": "http", "version": "1.2.0"}
            }]
        });
        let rewritten = rewrite_package_response(
            &serde_json::to_vec(&source).unwrap(),
            "http://nora:4000/pub",
            "http",
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        // archive_url rewritten
        assert!(
            json["latest"]["archive_url"]
                .as_str()
                .unwrap()
                .starts_with("http://nora:4000/pub/"),
            "archive_url must be rewritten"
        );
        // pubspec preserved unchanged
        assert_eq!(json["latest"]["pubspec"]["name"], "http");
    }

    /// Custom upstream (not pub.dev) — archive_url still rewritten to NORA (#387).
    #[test]
    fn test_rewrite_package_response_custom_upstream() {
        let source = serde_json::json!({
            "name": "my_pkg",
            "latest": {
                "version": "3.0.0",
                "archive_url": "https://private-dart.corp.com/api/archives/my_pkg-3.0.0.tar.gz"
            },
            "versions": [{
                "version": "3.0.0",
                "archive_url": "https://private-dart.corp.com/api/archives/my_pkg-3.0.0.tar.gz"
            }]
        });
        let rewritten = rewrite_package_response(
            &serde_json::to_vec(&source).unwrap(),
            "http://nora:4000/pub",
            "my_pkg",
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(
            json["latest"]["archive_url"],
            "http://nora:4000/pub/packages/my_pkg/versions/3.0.0.tar.gz",
        );
        let body = String::from_utf8(rewritten).unwrap();
        assert!(
            !body.contains("private-dart.corp.com"),
            "upstream URL must not leak (#387)"
        );
    }

    /// Trailing slash on nora_base must not produce double-slash (#387).
    #[test]
    fn test_rewrite_package_response_trailing_slash() {
        let source = serde_json::json!({
            "name": "http",
            "latest": {
                "version": "1.0.0",
                "archive_url": "https://pub.dev/api/archives/http-1.0.0.tar.gz"
            },
            "versions": []
        });
        let rewritten = rewrite_package_response(
            &serde_json::to_vec(&source).unwrap(),
            "http://nora:4000/pub/",
            "http",
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        let url = json["latest"]["archive_url"].as_str().unwrap();
        assert!(
            !url.contains("//packages"),
            "trailing slash must not produce double-slash: {url}"
        );
    }

    /// Search response without next_url — no pagination rewrite needed (#387).
    #[test]
    fn test_rewrite_search_response_no_next_url() {
        let source = serde_json::json!({
            "packages": [{
                "name": "http",
                "latest": {
                    "version": "1.2.0",
                    "archive_url": "https://pub.dev/api/archives/http-1.2.0.tar.gz"
                }
            }]
        });
        let rewritten = rewrite_search_response(
            &serde_json::to_vec(&source).unwrap(),
            "http://nora:4000/pub",
            "https://pub.dev",
        )
        .unwrap();
        let json: Value = serde_json::from_slice(&rewritten).unwrap();
        assert!(
            json.get("next_url").is_none(),
            "missing next_url must not appear in rewritten response"
        );
        let body = String::from_utf8(rewritten).unwrap();
        assert!(
            !body.contains("pub.dev"),
            "upstream URL must not leak in search response (#387)"
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

        let result = super::extract_pub_publish_date(&storage, "http", "1.0.0", true).await;
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

        let result = super::extract_pub_publish_date(&storage, "http", "2.0.0", true).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_extract_pub_publish_date_no_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

        let result = super::extract_pub_publish_date(&storage, "nonexistent", "1.0.0", true).await;
        assert!(result.is_none());
    }

    /// #52 acceptance: with a cached package listing + stored validators, a stale
    /// request revalidates with `If-None-Match`; on upstream 304 the cached body
    /// is served with no 200-body download. pub.dev returns validators on the
    /// package-listing endpoint, so this is a real revalidation.
    #[tokio::test]
    async fn test_pub_revalidation_304_serves_cache_no_body_download() {
        use crate::registry::{write_validators, Validators};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Conditional request (has If-None-Match) → 304. A request WITHOUT it
        // would 404 (no other mount), so any full fetch would visibly fail.
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.pub_dart.enabled = true;
            cfg.pub_dart.proxy = Some(upstream.uri());
            cfg.pub_dart.metadata_ttl = 0; // always stale → always revalidate
            cfg.pub_dart.revalidate = true;
            cfg.pub_dart.serve_stale = false;
        });

        let key = "pub/api/packages/http.json";
        ctx.state
            .storage
            .put(key, br#"{"name":"http","versions":[{"version":"1.0.0"}]}"#)
            .await
            .unwrap();
        write_validators(
            &ctx.state.storage,
            key,
            &Validators {
                etag: Some("\"v1\"".to_string()),
                last_modified: None,
            },
        )
        .await;

        let before = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["pub"])
            .get();

        let resp = send(&ctx.app, Method::GET, "/pub/api/packages/http", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert!(
            String::from_utf8_lossy(&body).contains("1.0.0"),
            "must serve the cached package listing"
        );

        let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["pub"])
            .get();
        assert!(after > before, "a 304 revalidation must be recorded");
    }
}
