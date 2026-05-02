// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Ansible Galaxy collection proxy (API v3).
//!
//! Implements a caching proxy for galaxy.ansible.com:
//!   GET /ansible/api/v3/plugin/ansible/content/published/collections/index/
//!   GET /ansible/api/v3/plugin/ansible/content/published/collections/index/{ns}/{name}/
//!   GET /ansible/api/v3/plugin/ansible/content/published/collections/index/{ns}/{name}/versions/
//!   GET /ansible/api/v3/plugin/ansible/content/published/collections/index/{ns}/{name}/versions/{ver}/
//!   GET /ansible/download/{ns}-{name}-{ver}.tar.gz — collection tarball (immutable)
//!
//! Client config:
//!   ansible-galaxy collection install community.general -s http://nora:4000/ansible/

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::{proxy_fetch, proxy_fetch_text, ProxyError};
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::sync::Arc;

const UPSTREAM_DEFAULT: &str = "https://galaxy.ansible.com";
const API_PREFIX: &str = "/api/v3/plugin/ansible/content/published/collections/index";

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Collection listing
        .route(
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/",
            get(collection_list),
        )
        // Collection detail
        .route(
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/{ns}/{name}/",
            get(collection_detail),
        )
        // Version listing
        .route(
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/{ns}/{name}/versions/",
            get(version_list),
        )
        // Version detail
        .route(
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/{ns}/{name}/versions/{ver}/",
            get(version_detail),
        )
        // Collection tarball download (immutable)
        .route("/ansible/download/{filename}", get(download_tarball))
}

// ── Collection list ────────────────────────────────────────────────────

async fn collection_list(State(state): State<Arc<AppState>>) -> Response {
    let proxy_url = upstream_url(&state);
    let url = format!("{}{}/", proxy_url.trim_end_matches('/'), API_PREFIX);

    proxy_json(&state, &url, "ansible-collections").await
}

// ── Collection detail ──────────────────────────────────────────────────

async fn collection_detail(
    State(state): State<Arc<AppState>>,
    Path((ns, name)): Path<(String, String)>,
) -> Response {
    if !is_valid_name(&ns) || !is_valid_name(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}{}/{}/{}/",
        proxy_url.trim_end_matches('/'),
        API_PREFIX,
        ns,
        name
    );

    proxy_json(&state, &url, &format!("{}.{}", ns, name)).await
}

// ── Version listing ────────────────────────────────────────────────────

async fn version_list(
    State(state): State<Arc<AppState>>,
    Path((ns, name)): Path<(String, String)>,
) -> Response {
    if !is_valid_name(&ns) || !is_valid_name(&name) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}{}/{}/{}/versions/",
        proxy_url.trim_end_matches('/'),
        API_PREFIX,
        ns,
        name
    );

    proxy_json(&state, &url, &format!("{}.{}/versions", ns, name)).await
}

// ── Version detail ─────────────────────────────────────────────────────

async fn version_detail(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((ns, name, ver)): Path<(String, String, String)>,
) -> Response {
    if !is_valid_name(&ns) || !is_valid_name(&name) || !is_valid_version(&ver) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::Ansible,
        &format!("{}.{}", ns, name),
        Some(&ver),
        None,
    ) {
        return response;
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}{}/{}/{}/versions/{}/",
        proxy_url.trim_end_matches('/'),
        API_PREFIX,
        ns,
        name,
        ver
    );

    proxy_json(&state, &url, &format!("{}.{} v{}", ns, name, ver)).await
}

// ── Tarball download (immutable) ───────────────────────────────────────

async fn download_tarball(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(filename): Path<String>,
) -> Response {
    // filename = "namespace-name-version.tar.gz"
    if !filename.ends_with(".tar.gz") || !is_safe_filename(&filename) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Parse namespace, name, version from filename
    let stem = filename.strip_suffix(".tar.gz").unwrap_or(&filename);
    let parts: Vec<&str> = stem.splitn(3, '-').collect();
    if parts.len() < 3 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let (ns, name, ver) = (parts[0], parts[1], parts[2]);

    let storage_key = format!("ansible/download/{}", filename);

    // mtime fallback for hosted-only mode (proxy mtime = cache time, not publish time)
    let publish_date = if state.config.ansible.proxy.is_none() {
        crate::curation::extract_mtime_as_publish_date(&state.storage, &storage_key).await
    } else {
        None
    };

    // Curation check
    if let Some(response) = crate::curation::check_download(
        &state.curation,
        state.config.curation.bypass_token.as_deref(),
        &headers,
        crate::curation::RegistryType::Ansible,
        &format!("{}.{}", ns, name),
        Some(ver),
        publish_date,
    ) {
        return response;
    }

    // Immutable cache
    if let Ok(data) = state.storage.get(&storage_key).await {
        // Integrity check
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation,
            crate::curation::RegistryType::Ansible,
            &format!("{}.{}", ns, name),
            Some(ver),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("ansible");
        state.metrics.record_cache_hit();
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            filename,
            "ansible",
            "CACHE",
        ));
        return with_binary(data.to_vec());
    }

    // Fetch from upstream
    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/download/{}-{}-{}.tar.gz",
        proxy_url.trim_end_matches('/'),
        ns,
        name,
        ver
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        state.config.ansible.proxy_timeout,
        state.config.ansible.proxy_auth.as_deref(),
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("ansible");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                filename,
                "ansible",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "ansible", ""));

            let storage = state.storage.clone();
            let key = storage_key;
            let data = bytes.clone();
            tokio::spawn(async move {
                if storage.stat(&key).await.is_none() {
                    let _ = storage.put(&key, &data).await;
                }
            });

            state.repo_index.invalidate("ansible");
            with_binary(bytes)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, "Ansible Galaxy download error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Generic JSON proxy ─────────────────────────────────────────────────

async fn proxy_json(state: &AppState, url: &str, artifact_name: &str) -> Response {
    match proxy_fetch_text(
        &state.http_client,
        url,
        state.config.ansible.proxy_timeout,
        state.config.ansible.proxy_auth.as_deref(),
        None,
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("ansible");
            state.metrics.record_cache_miss();
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact_name.to_string(),
                "ansible",
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "ansible", ""));

            state.repo_index.invalidate("ansible");
            with_json(text.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, "Ansible Galaxy upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn upstream_url(state: &AppState) -> String {
    state
        .config
        .ansible
        .proxy
        .clone()
        .unwrap_or_else(|| UPSTREAM_DEFAULT.to_string())
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
            HeaderValue::from_static("application/gzip"),
        )],
        data,
    )
        .into_response()
}

fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains('/')
        && !name.contains('\0')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn is_valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && !version.contains('/')
        && !version.contains('\0')
        && !version.contains("..")
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

fn is_safe_filename(name: &str) -> bool {
    !name.contains("..")
        && !name.contains('/')
        && !name.contains('\0')
        && !name.is_empty()
        && name.len() <= 512
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_names() {
        assert!(is_valid_name("community"));
        assert!(is_valid_name("ansible"));
        assert!(is_valid_name("cloud-common"));
    }

    #[test]
    fn test_invalid_names() {
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("../evil"));
        assert!(!is_valid_name("foo/bar"));
    }

    #[test]
    fn test_safe_filename() {
        assert!(is_safe_filename("community-general-7.0.0.tar.gz"));
        assert!(!is_safe_filename("../evil.tar.gz"));
        assert!(!is_safe_filename("evil/path.tar.gz"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_ansible_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = false;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_ansible_cached_tarball() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
        });

        ctx.state
            .storage
            .put(
                "ansible/download/community-general-7.0.0.tar.gz",
                b"tarball-data",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/download/community-general-7.0.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"tarball-data");
    }

    #[tokio::test]
    async fn test_ansible_unreachable_proxy() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.ansible.enabled = true;
            cfg.ansible.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.ansible.proxy_timeout = 1;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
