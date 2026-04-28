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
use crate::registry::{proxy_fetch, proxy_fetch_text, ProxyError};
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;

const UPSTREAM_DEFAULT: &str = "https://registry.terraform.io";

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
}

// ── Service discovery ──────────────────────────────────────────────────

async fn service_discovery(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let host = extract_host(&state, &headers);
    let base = format!("http://{}", host);
    let json = serde_json::json!({
        "providers.v1": format!("{}/terraform/v1/providers/", base),
        "modules.v1": format!("{}/terraform/v1/modules/", base)
    });
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
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
            if is_within_ttl(meta.modified, 300) {
                state.metrics.record_download("terraform");
                state.metrics.record_cache_hit();
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
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/{}", ns, ptype),
                "terraform",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "terraform", ""));

            let storage = state.storage.clone();
            let key = storage_key;
            let data = text.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key, data.as_bytes()).await;
            });

            state.repo_index.invalidate("terraform");
            with_json(text.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(provider = format!("{}/{}", ns, ptype), error = ?e, "Terraform upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Provider download metadata ─────────────────────────────────────────

async fn provider_download_meta(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
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

    let host = extract_host(&state, &headers);
    let artifact = format!("{}/{} v{} {}/{}", ns, ptype, ver, os, arch);

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::Terraform,
        &format!("{}/{}", ns, ptype),
        Some(&ver),
        None,
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
            if is_within_ttl(meta.modified, 300) {
                state.metrics.record_download("terraform");
                state.metrics.record_cache_hit();
                return with_json(data.to_vec());
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
    )
    .await
    {
        Ok(text) => {
            // Rewrite download_url to point through NORA
            let rewritten = rewrite_download_url(&text, &host, &ns, &ptype, &ver);

            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact,
                "terraform",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "terraform", ""));

            let storage = state.storage.clone();
            let key = storage_key;
            let data = rewritten.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key, data.as_bytes()).await;
            });

            state.repo_index.invalidate("terraform");
            with_json(rewritten.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
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
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            path.clone(),
            "terraform",
            "CACHE",
        ));
        return with_binary(data.to_vec());
    }

    // Try upstream — reconstruct original URL from path
    // Path format: {ns}/{type}/{ver}/{filename}
    let parts: Vec<&str> = path.splitn(4, '/').collect();
    if parts.len() < 4 {
        return StatusCode::NOT_FOUND.into_response();
    }

    let proxy_url = upstream_url(&state);
    // The download URL from registry.terraform.io is typically a direct URL
    // We proxy the binary from releases.hashicorp.com or similar
    let url = format!(
        "{}/v1/providers/download/{}",
        proxy_url.trim_end_matches('/'),
        path
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        state.config.terraform.proxy_timeout_download,
        state.config.terraform.proxy_auth.as_deref(),
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss();
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
            let storage = state.storage.clone();
            let key = storage_key;
            let data = bytes.clone();
            tokio::spawn(async move {
                if storage.stat(&key).await.is_none() {
                    let _ = storage.put(&key, &data).await;
                }
            });

            state.repo_index.invalidate("terraform");
            with_binary(bytes)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
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
            if is_within_ttl(meta.modified, 300) {
                state.metrics.record_download("terraform");
                state.metrics.record_cache_hit();
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
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/{}/{}", ns, name, provider),
                "terraform",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "terraform", ""));

            let storage = state.storage.clone();
            let key = storage_key;
            let data = text.clone();
            tokio::spawn(async move {
                let _ = storage.put(&key, data.as_bytes()).await;
            });

            state.repo_index.invalidate("terraform");
            with_json(text.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
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
                state.metrics.record_download("terraform");
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{}/{}/{} v{}", ns, name, provider, ver),
                    "terraform",
                    "PROXY",
                ));

                // Pass through the X-Terraform-Get header
                return (
                    StatusCode::NO_CONTENT,
                    [("x-terraform-get", tf_get.to_str().unwrap_or(""))],
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

// ── Helpers ────────────────────────────────────────────────────────────

/// Extract Host from request headers, fallback to config or default
fn extract_host(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(public_url) = &state.config.server.public_url {
        // Strip protocol prefix
        return public_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .to_string();
    }
    headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:4000")
        .to_string()
}

fn upstream_url(state: &AppState) -> String {
    state
        .config
        .terraform
        .proxy
        .clone()
        .unwrap_or_else(|| UPSTREAM_DEFAULT.to_string())
}

fn is_within_ttl(modified_unix: u64, ttl_secs: u64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(modified_unix) < ttl_secs
}

fn with_json(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        data,
    )
        .into_response()
}

fn with_binary(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/zip"),
        )],
        data,
    )
        .into_response()
}

/// Rewrite download_url in provider metadata JSON to point through NORA.
fn rewrite_download_url(json_text: &str, host: &str, ns: &str, ptype: &str, ver: &str) -> String {
    // Parse JSON, find download_url, rewrite it
    if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(json_text) {
        if let Some(obj) = json.as_object_mut() {
            if let Some(download_url) = obj.get("download_url") {
                if let Some(url_str) = download_url.as_str() {
                    // Extract filename from original URL
                    let filename = url_str.rsplit('/').next().unwrap_or("provider.zip");
                    let new_url = format!(
                        "http://{}/terraform/v1/providers/download/{}/{}/{}/{}",
                        host, ns, ptype, ver, filename
                    );
                    obj.insert(
                        "download_url".to_string(),
                        serde_json::Value::String(new_url),
                    );
                }
            }
        }
        serde_json::to_string(&json).unwrap_or_else(|_| json_text.to_string())
    } else {
        json_text.to_string()
    }
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
        let result = rewrite_download_url(input, "nora:4000", "hashicorp", "aws", "5.0.0");
        assert!(result.contains("http://nora:4000/terraform/v1/providers/download/hashicorp/aws/5.0.0/terraform-provider-aws_5.0.0_linux_amd64.zip"));
        // Other fields preserved
        assert!(result.contains("abc123"));
    }

    #[test]
    fn test_rewrite_download_url_no_url() {
        let input = r#"{"shasum":"abc123"}"#;
        let result = rewrite_download_url(input, "nora:4000", "hashicorp", "aws", "5.0.0");
        assert_eq!(result, input);
    }

    #[test]
    fn test_rewrite_download_url_invalid_json() {
        let input = "not json";
        let result = rewrite_download_url(input, "nora:4000", "hashicorp", "aws", "5.0.0");
        assert_eq!(result, input);
    }

    #[test]
    fn test_safe_path() {
        assert!(is_safe_path("hashicorp/aws/5.0.0/provider.zip"));
        assert!(!is_safe_path("../../etc/passwd"));
        assert!(!is_safe_path("/absolute/path"));
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
