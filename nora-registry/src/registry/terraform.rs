// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Terraform provider/module registry proxy.
//!
//! Implements a caching proxy for registry.terraform.io:
//!   GET /terraform/.well-known/terraform.json     — service discovery
//!   GET /terraform/v1/providers/{ns}/{type}/versions — list provider versions
//!   GET /terraform/v1/providers/{ns}/{type}/{ver}/download/{os}/{arch} — download metadata
//!   GET /terraform/v1/providers/download/{ns}/{type}/{ver}/{filename}  — binary download
//!   GET /terraform/v1/modules/{ns}/{name}/{provider}/versions — list module versions
//!   GET /terraform/v1/modules/{ns}/{name}/{provider}/{ver}/download — module download
//!
//! Client config:
//!   In ~/.terraformrc:
//!     provider_installation {
//!       network_mirror { url = "http://nora:4000/terraform/" }
//!     }

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::{
    circuit_open_response, nora_base_url, proxy_fetch, proxy_fetch_text, ProxyError,
};
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;

const UPSTREAM_DEFAULT: &str = "https://registry.terraform.io";

/// Storage prefix and file suffix for repo index scanning.
pub const INDEX_PATTERN: (&str, &str) = ("terraform/", ".zip");

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Service discovery
        .route(
            "/terraform/.well-known/terraform.json",
            get(service_discovery),
        )
        // Provider versions
        .route(
            "/terraform/v1/providers/{ns}/{ptype}/versions",
            get(provider_versions),
        )
        // Provider download metadata (returns JSON with download_url)
        .route(
            "/terraform/v1/providers/{ns}/{ptype}/{ver}/download/{os}/{arch}",
            get(provider_download_meta),
        )
        // Provider binary download (cached, immutable)
        .route(
            "/terraform/v1/providers/download/{*path}",
            get(provider_download_binary),
        )
        // Module versions
        .route(
            "/terraform/v1/modules/{ns}/{name}/{provider}/versions",
            get(module_versions),
        )
        // Module download (returns X-Terraform-Get header)
        .route(
            "/terraform/v1/modules/{ns}/{name}/{provider}/{ver}/download",
            get(module_download),
        )
        // Module source download (cached, proxied)
        .route(
            "/terraform/v1/modules/download/{ns}/{name}/{provider}/{ver}/source",
            get(module_source_download),
        )
}

// ── Service discovery ──────────────────────────────────────────────────

async fn service_discovery(State(state): State<Arc<AppState>>) -> Response {
    let base = nora_base_url(&state);
    let json = serde_json::json!({
        "providers.v1": format!("{}/terraform/v1/providers/", base),
        "modules.v1": format!("{}/terraform/v1/modules/", base)
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
        serde_json::to_vec(&json).unwrap_or_default(),
    )
        .into_response()
}

// ── Provider versions (mutable, TTL cached) ────────────────────────────

async fn provider_versions(
    State(state): State<Arc<AppState>>,
    Path((ns, ptype)): Path<(String, String)>,
) -> Response {
    if !is_valid_name(&ns) || !is_valid_name(&ptype) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!("terraform/providers/{}/{}/versions.json", ns, ptype);

    // TTL cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.terraform.metadata_ttl) {
                state.metrics.record_download("terraform");
                state.metrics.record_cache_hit("terraform");
                return with_json(data.to_vec());
            }
        }
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v1/providers/{}/{}/versions",
        proxy_url.trim_end_matches('/'),
        ns,
        ptype
    );

    match proxy_fetch_text(
        &state.http_client,
        &url,
        state.config.terraform.proxy_timeout,
        state.config.terraform.proxy_auth.as_deref(),
        None,
        &state.circuit_breaker,
        "terraform",
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss("terraform");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/{}", ns, ptype),
                "terraform",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "terraform", ""));

            state.spawn_cache("terraform", storage_key, Bytes::from(text.clone()));
            with_json(text.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(provider = format!("{}/{}", ns, ptype), error = ?e, "Terraform upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Provider download metadata ─────────────────────────────────────────

async fn provider_download_meta(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((ns, ptype, ver, os, arch)): Path<(String, String, String, String, String)>,
) -> Response {
    if !is_valid_name(&ns)
        || !is_valid_name(&ptype)
        || !is_valid_version(&ver)
        || !is_valid_name(&os)
        || !is_valid_name(&arch)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let base_url = nora_base_url(&state);
    let artifact = format!("{}/{} v{} {}/{}", ns, ptype, ver, os, arch);

    // Extract publish date from cached metadata
    let publish_date = extract_terraform_publish_date(&state, &ns, &ptype, &ver).await;

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        crate::curation::RegistryType::Terraform,
        &format!("{}/{}", ns, ptype),
        Some(&ver),
        publish_date,
    ) {
        return response;
    }

    let storage_key = format!(
        "terraform/providers/{}/{}/{}/{}_{}.json",
        ns, ptype, ver, os, arch
    );

    // TTL cache for metadata
    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.terraform.metadata_ttl) {
                state.metrics.record_download("terraform");
                state.metrics.record_cache_hit("terraform");
                return with_json(strip_nora_internal_fields(&data));
            }
        }
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v1/providers/{}/{}/{}/download/{}/{}",
        proxy_url.trim_end_matches('/'),
        ns,
        ptype,
        ver,
        os,
        arch
    );

    match proxy_fetch_text(
        &state.http_client,
        &url,
        state.config.terraform.proxy_timeout,
        state.config.terraform.proxy_auth.as_deref(),
        None,
        &state.circuit_breaker,
        "terraform",
    )
    .await
    {
        Ok(text) => {
            // Rewrite download_url to point through NORA
            let rewritten = rewrite_download_url(&text, &base_url, &ns, &ptype, &ver);

            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss("terraform");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact,
                "terraform",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "terraform", ""));

            state.spawn_cache("terraform", storage_key, Bytes::from(rewritten.clone()));
            with_json(strip_nora_internal_fields(rewritten.as_bytes()))
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "Terraform download metadata error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Provider binary download (immutable) ───────────────────────────────

async fn provider_download_binary(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> Response {
    if !is_safe_path(&path) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!("terraform/download/{}", path);

    // Immutable: if cached, serve directly
    if let Ok(data) = state.storage.get(&storage_key).await {
        state.metrics.record_download("terraform");
        state.metrics.record_cache_hit("terraform");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            path.clone(),
            "terraform",
            "CACHE",
        ));
        return with_binary(data.to_vec());
    }

    // Try upstream — resolve the real download URL from cached metadata.
    // Path format: {ns}/{type}/{ver}/{filename}
    let parts: Vec<&str> = path.splitn(4, '/').collect();
    if parts.len() < 4 {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (ns, ptype, ver, filename) = (parts[0], parts[1], parts[2], parts[3]);

    // Resolve the real upstream URL from cached provider metadata.
    // The metadata JSON (cached by provider_download_meta) stores the
    // original download_url in `_nora_upstream_url`.
    let url = resolve_upstream_download_url(&state, ns, ptype, ver, filename).await;

    match proxy_fetch(
        &state.http_client,
        &url,
        state.config.terraform.proxy_timeout_dl,
        state.config.terraform.proxy_auth.as_deref(),
        &state.circuit_breaker,
        "terraform",
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss("terraform");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                path,
                "terraform",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "terraform", ""));

            // Immutable cache
            state.spawn_cache_immutable("terraform", storage_key, Bytes::from(bytes.clone()));
            with_binary(bytes)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "Terraform binary download error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Module versions ────────────────────────────────────────────────────

async fn module_versions(
    State(state): State<Arc<AppState>>,
    Path((ns, name, provider)): Path<(String, String, String)>,
) -> Response {
    if !is_valid_name(&ns) || !is_valid_name(&name) || !is_valid_name(&provider) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!(
        "terraform/modules/{}/{}/{}/versions.json",
        ns, name, provider
    );

    // TTL cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.terraform.metadata_ttl) {
                state.metrics.record_download("terraform");
                state.metrics.record_cache_hit("terraform");
                return with_json(data.to_vec());
            }
        }
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v1/modules/{}/{}/{}/versions",
        proxy_url.trim_end_matches('/'),
        ns,
        name,
        provider
    );

    match proxy_fetch_text(
        &state.http_client,
        &url,
        state.config.terraform.proxy_timeout,
        state.config.terraform.proxy_auth.as_deref(),
        None,
        &state.circuit_breaker,
        "terraform",
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss("terraform");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/{}/{}", ns, name, provider),
                "terraform",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "terraform", ""));

            state.spawn_cache("terraform", storage_key, Bytes::from(text.clone()));
            with_json(text.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "Terraform module versions error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Module download ────────────────────────────────────────────────────

async fn module_download(
    State(state): State<Arc<AppState>>,
    Path((ns, name, provider, ver)): Path<(String, String, String, String)>,
) -> Response {
    if !is_valid_name(&ns)
        || !is_valid_name(&name)
        || !is_valid_name(&provider)
        || !is_valid_version(&ver)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let base_url = nora_base_url(&state);

    // If we have a cached source URL, return the rewritten header immediately
    let source_url_key = format!(
        "terraform/modules/{}/{}/{}/{}/_source_url",
        ns, name, provider, ver
    );
    if let Ok(data) = state.storage.get(&source_url_key).await {
        let original_url = String::from_utf8_lossy(&data);
        let rewritten =
            rewrite_module_source_url(&original_url, &base_url, &ns, &name, &provider, &ver);
        state.metrics.record_download("terraform");
        state.metrics.record_cache_hit("terraform");
        return (
            StatusCode::NO_CONTENT,
            [("x-terraform-get", rewritten.as_str())],
        )
            .into_response();
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/v1/modules/{}/{}/{}/{}/download",
        proxy_url.trim_end_matches('/'),
        ns,
        name,
        provider,
        ver
    );

    // Module download returns 204 with X-Terraform-Get header pointing to source
    let client = &state.http_client;
    let timeout = state.config.terraform.proxy_timeout;

    let mut request = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(timeout));
    if let Some(auth) = state.config.terraform.proxy_auth.as_deref() {
        request = request.header("Authorization", crate::config::basic_auth_header(auth));
    }

    match request.send().await {
        Ok(response) => {
            if let Some(tf_get) = response.headers().get("x-terraform-get") {
                let original_url = tf_get.to_str().unwrap_or("").to_string();

                state.metrics.record_download("terraform");
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{}/{}/{} v{}", ns, name, provider, ver),
                    "terraform",
                    "PROXY",
                ));

                // Rewrite X-Terraform-Get to point through NORA (air-gap safe)
                let rewritten = rewrite_module_source_url(
                    &original_url,
                    &base_url,
                    &ns,
                    &name,
                    &provider,
                    &ver,
                );

                // Cache the inner URL (stripping VCS prefix like git::) for module_source_download
                let (_, inner_url) = strip_vcs_prefix(&original_url);
                state.spawn_cache(
                    "terraform",
                    source_url_key,
                    Bytes::from(inner_url.to_string()),
                );

                return (
                    StatusCode::NO_CONTENT,
                    [("x-terraform-get", rewritten.as_str())],
                )
                    .into_response();
            }
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::debug!(error = ?e, "Terraform module download error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Module source download (cached, proxied) ─────────────────────────

async fn module_source_download(
    State(state): State<Arc<AppState>>,
    Path((ns, name, provider, ver)): Path<(String, String, String, String)>,
) -> Response {
    if !is_valid_name(&ns)
        || !is_valid_name(&name)
        || !is_valid_name(&provider)
        || !is_valid_version(&ver)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!(
        "terraform/modules/{}/{}/{}/{}/source.tar.gz",
        ns, name, provider, ver
    );

    // Immutable: if cached, serve directly
    if let Ok(data) = state.storage.get(&storage_key).await {
        state.metrics.record_download("terraform");
        state.metrics.record_cache_hit("terraform");
        return with_binary(data.to_vec());
    }

    // Resolve original upstream URL from cached metadata
    let source_url_key = format!(
        "terraform/modules/{}/{}/{}/{}/_source_url",
        ns, name, provider, ver
    );
    let upstream_url = match state.storage.get(&source_url_key).await {
        Ok(data) => String::from_utf8_lossy(&data).to_string(),
        Err(_) => {
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    // Only proxy HTTP/HTTPS URLs (git:: or other schemes can't be proxied)
    if !upstream_url.starts_with("http://") && !upstream_url.starts_with("https://") {
        tracing::debug!(url = %upstream_url, "Module source URL is not HTTP — cannot proxy");
        return StatusCode::NOT_FOUND.into_response();
    }

    match proxy_fetch(
        &state.http_client,
        &upstream_url,
        state.config.terraform.proxy_timeout_dl,
        state.config.terraform.proxy_auth.as_deref(),
        &state.circuit_breaker,
        "terraform",
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss("terraform");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/{}/{} v{}", ns, name, provider, ver),
                "terraform",
                "PROXY",
            ));

            // Immutable cache
            state.spawn_cache_immutable("terraform", storage_key, Bytes::from(bytes.clone()));
            with_binary(bytes)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            tracing::debug!(error = ?e, "Terraform module source download error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Extract publish date from cached Terraform provider versions metadata.
///
/// Terraform registry API does not reliably include `published_at` in the
/// versions listing. Falls back to mtime for hosted-only mode.
// TODO(v1.0): trust_upstream_dates config for high-security installs
async fn extract_terraform_publish_date(
    state: &AppState,
    ns: &str,
    ptype: &str,
    ver: &str,
) -> Option<i64> {
    // Try download metadata JSON (per-version cached file)
    let storage_key = format!("terraform/providers/{}/{}/{}/download.json", ns, ptype, ver);
    if let Ok(data) = state.storage.get(&storage_key).await {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) {
            if let Some(date_str) = json.get("published_at").and_then(|v| v.as_str()) {
                return crate::curation::parse_iso8601_to_unix(date_str);
            }
        }
    }

    // mtime fallback — only for hosted mode (proxy mtime = cache time)
    if state.config.terraform.proxy.is_none() {
        // Try any cached platform-specific metadata
        for suffix in &["linux_amd64.json", "linux_arm64.json", "darwin_amd64.json"] {
            let meta_key = format!("terraform/providers/{}/{}/{}/{}", ns, ptype, ver, suffix);
            if let Some(ts) =
                crate::curation::extract_mtime_as_publish_date(&state.storage, &meta_key).await
            {
                return Some(ts);
            }
        }
    }
    None
}

/// Resolve the real upstream download URL for a provider file.
///
/// Looks up the cached metadata JSON to find the original URL (typically on
/// releases.hashicorp.com). Checks `_nora_upstream_url` for binaries,
/// `_nora_upstream_shasums_url` for SHA256SUMS, and
/// `_nora_upstream_shasums_sig_url` for signature files.
/// Falls back to constructing a releases.hashicorp.com URL from path components.
async fn resolve_upstream_download_url(
    state: &AppState,
    ns: &str,
    ptype: &str,
    ver: &str,
    filename: &str,
) -> String {
    // Determine which metadata field to look up based on filename
    let meta_field = if filename.ends_with(".sig") {
        "_nora_upstream_shasums_sig_url"
    } else if filename.contains("SHA256SUMS") || filename.contains("SHA512SUMS") {
        "_nora_upstream_shasums_url"
    } else {
        "_nora_upstream_url"
    };

    // For binary .zip files, parse os/arch from filename to find the right metadata
    if let Some((os, arch)) = parse_os_arch_from_filename(filename) {
        let meta_key = format!(
            "terraform/providers/{}/{}/{}/{}_{}.json",
            ns, ptype, ver, os, arch
        );
        if let Ok(data) = state.storage.get(&meta_key).await {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) {
                if let Some(url) = json.get(meta_field).and_then(|v| v.as_str()) {
                    return url.to_string();
                }
            }
        }
    } else {
        // For shasums/sig files, scan any cached metadata for this provider version
        // (shasums URLs are the same regardless of os/arch)
        let prefix = format!("terraform/providers/{}/{}/{}/", ns, ptype, ver);
        let keys = state.storage.list(&prefix).await;
        for key in keys {
            if key.ends_with(".json") {
                if let Ok(data) = state.storage.get(&key).await {
                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) {
                        if let Some(url) = json.get(meta_field).and_then(|v| v.as_str()) {
                            return url.to_string();
                        }
                    }
                }
            }
        }
    }

    // Fallback: construct releases.hashicorp.com URL from path parts
    format!(
        "https://releases.hashicorp.com/terraform-provider-{}/{}/{}",
        ptype, ver, filename
    )
}

/// Extract OS and arch from a terraform provider filename.
/// e.g. `terraform-provider-null_3.2.3_linux_amd64.zip` -> Some(("linux", "amd64"))
fn parse_os_arch_from_filename(filename: &str) -> Option<(&str, &str)> {
    let name = filename.strip_suffix(".zip")?;
    // Split from the right: ..._os_arch
    let (rest, arch) = name.rsplit_once('_')?;
    let (_, os) = rest.rsplit_once('_')?;
    Some((os, arch))
}

fn upstream_url(state: &AppState) -> String {
    state
        .config
        .terraform
        .proxy
        .clone()
        .unwrap_or_else(|| UPSTREAM_DEFAULT.to_string())
}

use crate::cache_ttl::is_within_ttl;

fn with_json(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60, must-revalidate"),
            ),
        ],
        data,
    )
        .into_response()
}

fn with_binary(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/zip"),
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

/// Rewrite download_url, shasums_url, and shasums_signature_url in provider
/// metadata JSON to point through NORA.
///
/// Also stores the original upstream URLs in `_nora_upstream_*` fields so the
/// binary download handler can fetch from the real host (e.g.
/// releases.hashicorp.com) instead of the registry API endpoint.
fn rewrite_download_url(
    json_text: &str,
    base_url: &str,
    ns: &str,
    ptype: &str,
    ver: &str,
) -> String {
    if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(json_text) {
        if let Some(obj) = json.as_object_mut() {
            let download_base = format!(
                "{}/terraform/v1/providers/download/{}/{}/{}",
                base_url, ns, ptype, ver
            );

            // Rewrite download_url
            if let Some(url_str) = obj
                .get("download_url")
                .and_then(|v| v.as_str())
                .map(String::from)
            {
                obj.insert(
                    "_nora_upstream_url".to_string(),
                    serde_json::Value::String(url_str.clone()),
                );
                let filename = url_str.rsplit('/').next().unwrap_or("provider.zip");
                obj.insert(
                    "download_url".to_string(),
                    serde_json::Value::String(format!("{}/{}", download_base, filename)),
                );
            }

            // Rewrite shasums_url
            if let Some(url_str) = obj
                .get("shasums_url")
                .and_then(|v| v.as_str())
                .map(String::from)
            {
                obj.insert(
                    "_nora_upstream_shasums_url".to_string(),
                    serde_json::Value::String(url_str.clone()),
                );
                let filename = url_str.rsplit('/').next().unwrap_or("SHA256SUMS");
                obj.insert(
                    "shasums_url".to_string(),
                    serde_json::Value::String(format!("{}/{}", download_base, filename)),
                );
            }

            // Rewrite shasums_signature_url
            if let Some(url_str) = obj
                .get("shasums_signature_url")
                .and_then(|v| v.as_str())
                .map(String::from)
            {
                obj.insert(
                    "_nora_upstream_shasums_sig_url".to_string(),
                    serde_json::Value::String(url_str.clone()),
                );
                let filename = url_str.rsplit('/').next().unwrap_or("SHA256SUMS.sig");
                obj.insert(
                    "shasums_signature_url".to_string(),
                    serde_json::Value::String(format!("{}/{}", download_base, filename)),
                );
            }
        }
        serde_json::to_string(&json).unwrap_or_else(|_| json_text.to_string())
    } else {
        json_text.to_string()
    }
}

/// Rewrite X-Terraform-Get URL to point through NORA.
///
/// HTTP/HTTPS URLs are rewritten to NORA's module source proxy endpoint.
/// VCS-prefixed URLs like `git::https://...` have their inner URL extracted
/// and rewritten (the VCS prefix is dropped since NORA proxies via HTTP).
/// Non-HTTP URLs (s3::, ssh://, relative paths) are returned as-is.
fn rewrite_module_source_url(
    original_url: &str,
    base_url: &str,
    ns: &str,
    name: &str,
    provider: &str,
    ver: &str,
) -> String {
    let (vcs_prefix, inner_url) = strip_vcs_prefix(original_url);

    if inner_url.starts_with("http://") || inner_url.starts_with("https://") {
        if !vcs_prefix.is_empty() {
            tracing::warn!(
                module = %format!("{}/{}/{}", ns, name, provider),
                version = %ver,
                vcs = vcs_prefix.trim_end_matches("::"),
                "Module uses VCS prefix — source download via HTTP proxy may not work"
            );
        }
        format!(
            "{}/terraform/v1/modules/download/{}/{}/{}/{}/source",
            base_url.trim_end_matches('/'),
            ns,
            name,
            provider,
            ver
        )
    } else {
        // s3::, ssh://, relative paths — pass through as-is
        original_url.to_string()
    }
}

/// Strip internal `_nora_*` fields from cached metadata before sending to clients.
///
/// The cached JSON contains `_nora_upstream_url`, `_nora_upstream_shasums_url`, and
/// `_nora_upstream_shasums_sig_url` — needed internally by `resolve_upstream_download_url`
/// but must NOT be exposed to clients (air-gap URL leak).
fn strip_nora_internal_fields(data: &[u8]) -> Vec<u8> {
    if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(data) {
        if let Some(obj) = json.as_object_mut() {
            obj.retain(|k, _| !k.starts_with("_nora_"));
        }
        serde_json::to_vec(&json).unwrap_or_else(|_| data.to_vec())
    } else {
        tracing::warn!(
            "strip_nora_internal_fields: failed to parse cached JSON, returning raw data"
        );
        data.to_vec()
    }
}

/// Extract VCS prefix (`git::`, `hg::`) from a Terraform module source URL.
///
/// Returns `(prefix, inner_url)`. If no VCS prefix is present, prefix is empty.
fn strip_vcs_prefix(url: &str) -> (&str, &str) {
    for prefix in &["git::", "hg::"] {
        if let Some(inner) = url.strip_prefix(prefix) {
            return (prefix, inner);
        }
    }
    ("", url)
}

/// Validate namespace/type/provider names
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains('/')
        && !name.contains('\0')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Validate version string
fn is_valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && !version.contains('/')
        && !version.contains('\0')
        && !version.contains("..")
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '+')
}

/// Path safety validation
fn is_safe_path(path: &str) -> bool {
    !path.contains("..")
        && !path.starts_with('/')
        && !path.contains("//")
        && !path.contains('\0')
        && !path.is_empty()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_names() {
        assert!(is_valid_name("hashicorp"));
        assert!(is_valid_name("aws"));
        assert!(is_valid_name("google-beta"));
        assert!(is_valid_name("terraform-provider-azurerm"));
    }

    #[test]
    fn test_invalid_names() {
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("../evil"));
        assert!(!is_valid_name("foo/bar"));
        assert!(!is_valid_name("foo\0bar"));
    }

    #[test]
    fn test_valid_versions() {
        assert!(is_valid_version("5.0.0"));
        assert!(is_valid_version("3.67.0"));
        assert!(is_valid_version("1.0.0-beta1"));
    }

    #[test]
    fn test_rewrite_download_url() {
        let input = r#"{"download_url":"https://releases.hashicorp.com/terraform-provider-aws/5.0.0/terraform-provider-aws_5.0.0_linux_amd64.zip","shasum":"abc123"}"#;
        let result = rewrite_download_url(input, "https://nora:4000", "hashicorp", "aws", "5.0.0");
        assert!(result.contains("https://nora:4000/terraform/v1/providers/download/hashicorp/aws/5.0.0/terraform-provider-aws_5.0.0_linux_amd64.zip"));
        // Original upstream URL preserved
        assert!(result.contains("_nora_upstream_url"));
        assert!(result.contains("https://releases.hashicorp.com/terraform-provider-aws/5.0.0/terraform-provider-aws_5.0.0_linux_amd64.zip"));
        // Other fields preserved
        assert!(result.contains("abc123"));
    }

    #[test]
    fn test_rewrite_download_url_no_url() {
        let input = r#"{"shasum":"abc123"}"#;
        let result = rewrite_download_url(input, "http://nora:4000", "hashicorp", "aws", "5.0.0");
        assert_eq!(result, input);
    }

    #[test]
    fn test_rewrite_download_url_invalid_json() {
        let input = "not json";
        let result = rewrite_download_url(input, "http://nora:4000", "hashicorp", "aws", "5.0.0");
        assert_eq!(result, input);
    }

    #[test]
    fn test_safe_path() {
        assert!(is_safe_path("hashicorp/aws/5.0.0/provider.zip"));
        assert!(!is_safe_path("../../etc/passwd"));
        assert!(!is_safe_path("/absolute/path"));
    }

    #[test]
    fn test_rewrite_module_source_url_http() {
        let result = rewrite_module_source_url(
            "https://codeload.github.com/hashicorp/terraform-aws-consul/tar.gz/v0.1.0",
            "http://nora:4000",
            "hashicorp",
            "consul",
            "aws",
            "0.1.0",
        );
        assert_eq!(
            result,
            "http://nora:4000/terraform/v1/modules/download/hashicorp/consul/aws/0.1.0/source"
        );
        assert!(!result.contains("github.com"), "upstream URL must not leak");
    }

    #[test]
    fn test_rewrite_module_source_url_git_rewrite() {
        let git_url = "git::https://example.com/module.git";
        let result = rewrite_module_source_url(
            git_url,
            "http://nora:4000",
            "hashicorp",
            "consul",
            "aws",
            "0.1.0",
        );
        assert_eq!(
            result,
            "http://nora:4000/terraform/v1/modules/download/hashicorp/consul/aws/0.1.0/source",
            "git::https:// URLs must be rewritten through NORA (air-gap)"
        );
        assert!(
            !result.contains("example.com"),
            "upstream URL must not leak"
        );
        assert!(!result.contains("git::"), "VCS prefix must be stripped");
    }

    #[test]
    fn test_rewrite_module_source_url_hg_rewrite() {
        let hg_url = "hg::https://example.com/module.hg";
        let result = rewrite_module_source_url(
            hg_url,
            "http://nora:4000",
            "hashicorp",
            "consul",
            "aws",
            "0.1.0",
        );
        assert_eq!(
            result,
            "http://nora:4000/terraform/v1/modules/download/hashicorp/consul/aws/0.1.0/source",
            "hg::https:// URLs must be rewritten through NORA"
        );
    }

    #[test]
    fn test_rewrite_module_source_url_s3_passthrough() {
        let s3_url = "s3::https://bucket.s3.amazonaws.com/module.zip";
        let result = rewrite_module_source_url(
            s3_url,
            "http://nora:4000",
            "hashicorp",
            "consul",
            "aws",
            "0.1.0",
        );
        assert_eq!(result, s3_url, "s3:: URLs should pass through unchanged");
    }

    #[test]
    fn test_strip_nora_internal_fields() {
        let input = serde_json::json!({
            "download_url": "http://nora:4000/terraform/providers/download/test.zip",
            "_nora_upstream_url": "https://releases.hashicorp.com/test.zip",
            "_nora_upstream_shasums_url": "https://releases.hashicorp.com/SHA256SUMS",
            "_nora_upstream_shasums_sig_url": "https://releases.hashicorp.com/SHA256SUMS.sig",
            "shasum": "abc123"
        });
        let stripped = strip_nora_internal_fields(input.to_string().as_bytes());
        let json: serde_json::Value = serde_json::from_slice(&stripped).unwrap();
        assert!(
            json.get("download_url").is_some(),
            "download_url must remain"
        );
        assert!(json.get("shasum").is_some(), "shasum must remain");
        assert!(
            json.get("_nora_upstream_url").is_none(),
            "_nora_upstream_url must be stripped"
        );
        assert!(
            json.get("_nora_upstream_shasums_url").is_none(),
            "shasums must be stripped"
        );
        assert!(
            json.get("_nora_upstream_shasums_sig_url").is_none(),
            "sig must be stripped"
        );
    }

    #[test]
    fn test_strip_nora_internal_fields_invalid_json() {
        let input = b"not json at all";
        let result = strip_nora_internal_fields(input);
        assert_eq!(result, input, "invalid JSON must pass through unchanged");
    }

    #[test]
    fn test_strip_vcs_prefix() {
        assert_eq!(
            strip_vcs_prefix("git::https://example.com"),
            ("git::", "https://example.com")
        );
        assert_eq!(
            strip_vcs_prefix("hg::https://example.com"),
            ("hg::", "https://example.com")
        );
        assert_eq!(
            strip_vcs_prefix("https://example.com"),
            ("", "https://example.com")
        );
        assert_eq!(strip_vcs_prefix("./local/path"), ("", "./local/path"));
        assert_eq!(
            strip_vcs_prefix("s3::https://bucket.s3.amazonaws.com/mod.zip"),
            ("", "s3::https://bucket.s3.amazonaws.com/mod.zip")
        );
    }

    // ========================================================================
    // URL-rewrite systematic tests (#387)
    // ========================================================================

    /// Rewrite all three URL fields: download_url, shasums_url, shasums_signature_url (#387).
    #[test]
    fn test_rewrite_download_url_all_fields() {
        let input = serde_json::json!({
            "os": "linux",
            "arch": "amd64",
            "download_url": "https://releases.hashicorp.com/terraform-provider-aws/5.0.0/terraform-provider-aws_5.0.0_linux_amd64.zip",
            "shasums_url": "https://releases.hashicorp.com/terraform-provider-aws/5.0.0/terraform-provider-aws_5.0.0_SHA256SUMS",
            "shasums_signature_url": "https://releases.hashicorp.com/terraform-provider-aws/5.0.0/terraform-provider-aws_5.0.0_SHA256SUMS.sig",
            "shasum": "abc123"
        });
        let result = rewrite_download_url(
            &input.to_string(),
            "http://nora:4000",
            "hashicorp",
            "aws",
            "5.0.0",
        );
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        // All three URLs must point to NORA
        assert!(
            json["download_url"]
                .as_str()
                .unwrap()
                .starts_with("http://nora:4000/terraform/"),
            "download_url must point to NORA"
        );
        assert!(
            json["shasums_url"]
                .as_str()
                .unwrap()
                .starts_with("http://nora:4000/terraform/"),
            "shasums_url must point to NORA"
        );
        assert!(
            json["shasums_signature_url"]
                .as_str()
                .unwrap()
                .starts_with("http://nora:4000/terraform/"),
            "shasums_signature_url must point to NORA"
        );
        // No upstream leak
        assert!(
            !result.contains("releases.hashicorp.com") || result.contains("_nora_upstream"),
            "upstream URL must only appear in _nora_upstream fields"
        );
        // Upstream URLs preserved in _nora_upstream_* fields
        assert!(json.get("_nora_upstream_url").is_some());
        assert!(json.get("_nora_upstream_shasums_url").is_some());
        assert!(json.get("_nora_upstream_shasums_sig_url").is_some());
    }

    /// Custom upstream (not hashicorp) — URLs still rewritten to NORA (#387).
    #[test]
    fn test_rewrite_download_url_custom_upstream() {
        let input = r#"{"download_url":"https://private.registry.corp/providers/myorg/myprovider/1.0.0/terraform-provider-myprovider_1.0.0_linux_amd64.zip"}"#;
        let result =
            rewrite_download_url(input, "http://nora:4000", "myorg", "myprovider", "1.0.0");
        assert!(
            result.contains(
                "http://nora:4000/terraform/v1/providers/download/myorg/myprovider/1.0.0/"
            ),
            "custom upstream must be rewritten to NORA"
        );
        assert!(
            !result.contains("private.registry.corp") || result.contains("_nora_upstream"),
            "custom upstream must not leak outside _nora_upstream fields"
        );
    }

    /// Base URL with trailing slash must not produce double-slash (#387).
    #[test]
    fn test_rewrite_module_source_url_trailing_slash() {
        let result = rewrite_module_source_url(
            "https://codeload.github.com/hashicorp/terraform-aws-consul/tar.gz/v0.1.0",
            "http://nora:4000/",
            "hashicorp",
            "consul",
            "aws",
            "0.1.0",
        );
        assert!(
            !result.contains("4000//terraform"),
            "trailing slash must not produce double-slash: {result}"
        );
        assert_eq!(
            result,
            "http://nora:4000/terraform/v1/modules/download/hashicorp/consul/aws/0.1.0/source"
        );
    }

    #[test]
    fn test_rewrite_module_source_url_relative_passthrough() {
        let result = rewrite_module_source_url(
            "./modules/foo",
            "http://nora:4000",
            "hashicorp",
            "consul",
            "aws",
            "0.1.0",
        );
        assert_eq!(
            result, "./modules/foo",
            "relative paths should pass through"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_terraform_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = false;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/.well-known/terraform.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_terraform_service_discovery() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/.well-known/terraform.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("providers.v1").is_some());
        assert!(json.get("modules.v1").is_some());
    }

    #[tokio::test]
    async fn test_terraform_cached_binary() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
        });

        ctx.state
            .storage
            .put(
                "terraform/download/hashicorp/aws/5.0.0/provider.zip",
                b"zip-binary",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/providers/download/hashicorp/aws/5.0.0/provider.zip",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"zip-binary");
    }

    #[tokio::test]
    async fn test_terraform_unreachable_proxy() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.terraform.proxy_timeout = 1;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/providers/hashicorp/aws/versions",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_terraform_invalid_name_rejected() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/providers/../evil/versions",
            "",
        )
        .await;
        assert!(resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_terraform_module_download_rewrites_cached_source_url() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
        });

        // Seed the source URL metadata (as if module_download had cached it)
        ctx.state
            .storage
            .put(
                "terraform/modules/hashicorp/consul/aws/0.1.0/_source_url",
                b"https://codeload.github.com/hashicorp/terraform-aws-consul/tar.gz/v0.1.0",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/hashicorp/consul/aws/0.1.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let tf_get = resp
            .headers()
            .get("x-terraform-get")
            .expect("must have x-terraform-get header")
            .to_str()
            .unwrap();

        // Must point through NORA, not upstream
        assert!(
            tf_get.contains("/terraform/v1/modules/download/"),
            "X-Terraform-Get must point through NORA, got: {}",
            tf_get
        );
        assert!(
            !tf_get.contains("github.com"),
            "X-Terraform-Get must not leak upstream URL, got: {}",
            tf_get
        );
    }

    #[tokio::test]
    async fn test_terraform_module_source_from_cache() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
        });

        // Seed cached module source tarball
        ctx.state
            .storage
            .put(
                "terraform/modules/hashicorp/consul/aws/0.1.0/source.tar.gz",
                b"fake-tarball-content",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/download/hashicorp/consul/aws/0.1.0/source",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"fake-tarball-content");
    }

    #[tokio::test]
    async fn test_terraform_curation_enforce_blocks() {
        use crate::test_helpers::send_with_headers;

        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{"registry": "terraform", "name": "evilcorp/backdoor", "version": "*", "reason": "compromised"}]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.terraform.proxy_timeout = 1;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        // Curation check happens before proxy fetch, so it should block even without upstream
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/terraform/v1/providers/evilcorp/backdoor/1.0.0/download/linux/amd64",
            vec![],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
