// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Terraform provider/module registry proxy.
//!
//! Serves TWO distinct Terraform protocols against the same upstream.
//!
//! Provider Registry Protocol (origin-registry, service-discovery based):
//!   GET /terraform/.well-known/terraform.json     — service discovery
//!   GET /terraform/v1/providers/{ns}/{type}/versions — list provider versions
//!   GET /terraform/v1/providers/{ns}/{type}/{ver}/download/{os}/{arch} — download metadata
//!   GET /terraform/v1/providers/download/{ns}/{type}/{ver}/{filename}  — binary download
//!   GET /terraform/v1/modules/{ns}/{name}/{provider}/versions — list module versions
//!   GET /terraform/v1/modules/{ns}/{name}/{provider}/{ver}/download — module download
//!
//! Provider Network Mirror Protocol (#801 — what `network_mirror` speaks; no service
//! discovery, coordinates carry the origin {hostname}, providers only):
//!   GET /terraform/{hostname}/{ns}/{type}/index.json   — list available versions
//!   GET /terraform/{hostname}/{ns}/{type}/{version}.json — list installation packages
//!
//! Client config (network mirror; note: Terraform requires an `https:` URL):
//!   In ~/.terraformrc:
//!     provider_installation {
//!       network_mirror { url = "https://nora.example.com/terraform/" }
//!     }

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::{
    circuit_open_response, nora_base_url, proxy_fetch, proxy_fetch_text, ProxyError,
};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::time::Duration;

const UPSTREAM_DEFAULT: &str = "https://registry.terraform.io";

/// Storage prefix and file suffix for repo index scanning.
pub const INDEX_PATTERN: (&str, &str) = ("terraform/", ".zip");

pub fn routes() -> Router<AppState> {
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
        // ── Provider Network Mirror Protocol (#801) ──
        // Distinct from the Registry Protocol above. A Terraform client configured
        // with `provider_installation { network_mirror { url = ".../terraform/" } }`
        // does NOT use service discovery; it requests these two endpoints directly.
        // The `index.json` static segment takes matchit priority over the dynamic
        // `{version_file}` sibling, and `{hostname}` (param) coexists with the static
        // `v1`/`.well-known` seg-2 branches (static wins) — verified on axum 0.8/matchit 0.8.
        .route(
            "/terraform/{hostname}/{ns}/{ptype}/index.json",
            get(mirror_provider_index),
        )
        .route(
            "/terraform/{hostname}/{ns}/{ptype}/{version_file}",
            get(mirror_provider_version),
        )
}

// ── Service discovery ──────────────────────────────────────────────────

async fn service_discovery(State(state): State<AppState>) -> Response {
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
    State(state): State<AppState>,
    Path((ns, ptype)): Path<(String, String)>,
) -> Response {
    if !is_valid_name(&ns) || !is_valid_name(&ptype) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!("terraform/providers/{}/{}/versions.json", ns, ptype);

    // Read cache eagerly — preserve for serve-stale fallback (#532)
    let cached_data = state.storage.get(&storage_key).await.ok();

    // TTL cache — serve fresh if within TTL
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.terraform.metadata_ttl) {
                state.metrics.record_download("terraform");
                state.metrics.record_cache_hit("terraform");
                return with_json(data.to_vec());
            }
        }
    }

    // #68 namespace isolation: an internal-namespace provider's version list must
    // never be fetched upstream (dependency confusion). Serve any local copy (fresh
    // path returned above), else block — never proxy. Name form matches the existing
    // provider check_download: "{ns}/{ptype}".
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Terraform,
        &format!("{}/{}", ns, ptype),
    ) {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_hit("terraform");
            return with_json(data.to_vec());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Terraform,
            &format!("{}/{}", ns, ptype),
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
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
        Duration::from_secs(state.config.terraform.proxy_timeout),
        expose_opt(&state.config.terraform.proxy_auth),
        None,
        &state.circuit_breaker,
        RegistryType::Terraform,
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss("terraform");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/{}", ns, ptype),
                crate::registry_type::RegistryType::Terraform,
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
            serve_stale_or_bad_gateway(&state, cached_data, "provider_versions")
        }
    }
}

// ── Provider download metadata ─────────────────────────────────────────

async fn provider_download_meta(
    State(state): State<AppState>,
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

    // Extract publish date from cached metadata. The download-metadata endpoint is
    // not the artifact serve path (no quarantine here), so the /v2 lookup is not
    // gated on cache state — `already_cached = false`.
    let publish_date = extract_terraform_publish_date(&state, &ns, &ptype, &ver, false).await;

    // Curation check. #733 serve-local: an internal-namespace provider is operator-owned — skip
    // curation and serve any local copy below; block the upstream branch separately.
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Terraform,
        &format!("{}/{}", ns, ptype),
    );
    if !internal {
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
    }

    let storage_key = format!(
        "terraform/providers/{}/{}/{}/{}_{}.json",
        ns, ptype, ver, os, arch
    );

    // Read cache eagerly — preserve for serve-stale fallback (#532).
    // Strip internal fields now so stale response is client-safe.
    let cached_data = state
        .storage
        .get(&storage_key)
        .await
        .ok()
        .map(|d| Bytes::from(strip_nora_internal_fields(&d)));

    // TTL cache — serve fresh if within TTL
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.terraform.metadata_ttl) {
                state.metrics.record_download("terraform");
                state.metrics.record_cache_hit("terraform");
                return with_json(data.to_vec());
            }
        }
    }

    // #733: an internal-namespace provider — serve any (stale) local copy, else block; never proxy.
    if internal {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_hit("terraform");
            return with_json(data.to_vec());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Terraform,
            &format!("{}/{}", ns, ptype),
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
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
        Duration::from_secs(state.config.terraform.proxy_timeout),
        expose_opt(&state.config.terraform.proxy_auth),
        None,
        &state.circuit_breaker,
        RegistryType::Terraform,
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
                crate::registry_type::RegistryType::Terraform,
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
            serve_stale_or_bad_gateway(&state, cached_data, "provider_download_meta")
        }
    }
}

// ── Provider binary download (immutable) ───────────────────────────────

async fn provider_download_binary(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Response {
    if !is_safe_path(&path) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!("terraform/download/{}", path);

    // Release date for the quarantine first-seen clock (#748/#750). The rewritten
    // binary path is {ns}/{ptype}/{ver}/{file}, so reuse the cached provider
    // metadata date (gated internally on trust_upstream_dates; None → NORA's clock).
    // #754: skip the /v2 round-trip on a cache hit (the digest is already recorded).
    let already_cached = state.storage.stat(&storage_key).await.is_some();
    let bin_coords: Vec<&str> = path.split('/').collect();
    let publish_date = if bin_coords.len() >= 3 {
        extract_terraform_publish_date(
            &state,
            bin_coords[0],
            bin_coords[1],
            bin_coords[2],
            already_cached,
        )
        .await
    } else {
        None
    };

    // Immutable: if cached, serve directly. get_verified discharges the integrity
    // witness at serve (compile-time guarantee — see crate::verified).
    if let Ok(outcome) = state.storage.get_verified(&storage_key).await {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        state.metrics.record_download("terraform");
        state.metrics.record_cache_hit("terraform");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            path.clone(),
            crate::registry_type::RegistryType::Terraform,
            "CACHE",
        ));
        let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
            state.config.curation.terraform.quarantine.as_ref().or(state
                .config
                .curation
                .quarantine
                .as_ref()),
            state
                .config
                .curation
                .terraform
                .quarantine_ttl
                .as_deref()
                .or(state.config.curation.quarantine_ttl.as_deref()),
        );
        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "terraform",
            &data,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }
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
        Duration::from_secs(state.config.terraform.proxy_timeout_dl),
        expose_opt(&state.config.terraform.proxy_auth),
        &state.circuit_breaker,
        RegistryType::Terraform,
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss("terraform");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                path,
                crate::registry_type::RegistryType::Terraform,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "terraform", ""));

            // Immutable cache
            state.spawn_cache_immutable("terraform", storage_key, Bytes::from(bytes.clone()));
            let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                state.config.curation.terraform.quarantine.as_ref().or(state
                    .config
                    .curation
                    .quarantine
                    .as_ref()),
                state
                    .config
                    .curation
                    .terraform
                    .quarantine_ttl
                    .as_deref()
                    .or(state.config.curation.quarantine_ttl.as_deref()),
            );
            if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                &state.digest_store,
                "terraform",
                &bytes,
                &q_mode,
                q_secs,
                &url,
                publish_date,
            ) {
                return resp;
            }
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
    State(state): State<AppState>,
    Path((ns, name, provider)): Path<(String, String, String)>,
) -> Response {
    if !is_valid_name(&ns) || !is_valid_name(&name) || !is_valid_name(&provider) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!(
        "terraform/modules/{}/{}/{}/versions.json",
        ns, name, provider
    );

    // Read cache eagerly — preserve for serve-stale fallback (#532)
    let cached_data = state.storage.get(&storage_key).await.ok();

    // TTL cache — serve fresh if within TTL
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.terraform.metadata_ttl) {
                state.metrics.record_download("terraform");
                state.metrics.record_cache_hit("terraform");
                return with_json(data.to_vec());
            }
        }
    }

    // #68 namespace isolation: an internal-namespace module's version list must never
    // be fetched upstream (dependency confusion). Serve any local copy (fresh path
    // returned above), else block — never proxy. Module name form: "{ns}/{name}/{provider}".
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Terraform,
        &format!("{}/{}/{}", ns, name, provider),
    ) {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_hit("terraform");
            return with_json(data.to_vec());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Terraform,
            &format!("{}/{}/{}", ns, name, provider),
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
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
        Duration::from_secs(state.config.terraform.proxy_timeout),
        expose_opt(&state.config.terraform.proxy_auth),
        None,
        &state.circuit_breaker,
        RegistryType::Terraform,
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss("terraform");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/{}/{}", ns, name, provider),
                crate::registry_type::RegistryType::Terraform,
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
            serve_stale_or_bad_gateway(&state, cached_data, "module_versions")
        }
    }
}

// ── Module download ────────────────────────────────────────────────────

async fn module_download(
    State(state): State<AppState>,
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
    if let Some(auth) = expose_opt(&state.config.terraform.proxy_auth) {
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
                    crate::registry_type::RegistryType::Terraform,
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
    State(state): State<AppState>,
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

    // Immutable: if cached, serve directly. get_verified discharges the integrity
    // witness at serve (compile-time guarantee — see crate::verified).
    if let Ok(outcome) = state.storage.get_verified(&storage_key).await {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        state.metrics.record_download("terraform");
        state.metrics.record_cache_hit("terraform");
        let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
            state.config.curation.terraform.quarantine.as_ref().or(state
                .config
                .curation
                .quarantine
                .as_ref()),
            state
                .config
                .curation
                .terraform
                .quarantine_ttl
                .as_deref()
                .or(state.config.curation.quarantine_ttl.as_deref()),
        );
        if let Some(resp) = crate::digest_quarantine::proxy_gate(
            &state.digest_store,
            "terraform",
            &data,
            &q_mode,
            q_secs,
            "cache",
        ) {
            return resp;
        }
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
        Duration::from_secs(state.config.terraform.proxy_timeout_dl),
        expose_opt(&state.config.terraform.proxy_auth),
        &state.circuit_breaker,
        RegistryType::Terraform,
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_miss("terraform");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/{}/{} v{}", ns, name, provider, ver),
                crate::registry_type::RegistryType::Terraform,
                "PROXY",
            ));

            // Immutable cache
            state.spawn_cache_immutable("terraform", storage_key, Bytes::from(bytes.clone()));
            let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                state.config.curation.terraform.quarantine.as_ref().or(state
                    .config
                    .curation
                    .quarantine
                    .as_ref()),
                state
                    .config
                    .curation
                    .terraform
                    .quarantine_ttl
                    .as_deref()
                    .or(state.config.curation.quarantine_ttl.as_deref()),
            );
            if let Some(resp) = crate::digest_quarantine::proxy_gate(
                &state.digest_store,
                "terraform",
                &bytes,
                &q_mode,
                q_secs,
                &upstream_url,
            ) {
                return resp;
            }
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

// ── Provider Network Mirror Protocol handlers (#801) ───────────────────
//
// Terraform's `network_mirror` speaks a different protocol from the Registry
// Protocol above: no service discovery, provider coordinates carry the origin
// {hostname}, and metadata is served as `index.json` (version list) and
// `{version}.json` (per-platform archives). These two handlers are thin adapters
// that reuse the Registry-Protocol cache/upstream/curation primitives and route
// the actual binary download through the existing (cached, quarantined,
// integrity-verified) `/terraform/v1/providers/download/{*path}` handler.
//
// Single-upstream limitation (accepted): NORA has one configured Terraform
// upstream (`terraform.proxy`); the {hostname} path segment is validated but not
// used to select an upstream, so only the configured upstream's providers resolve.
//
// Integrity note (accepted): NORA does not itself GPG-verify SHA256SUMS.sig, and
// Terraform in network_mirror mode does not run the origin-registry GPG check —
// so mirror mode is a weaker trust anchor than the Registry Protocol. Archives are
// served with a `zh:<sha256>` hash from the upstream metadata; any platform whose
// shasum is unavailable is omitted (fail-closed: never serve an unhashed archive).

/// `index.json` — List Available Versions (network mirror protocol).
/// Reshapes the Registry-Protocol versions list into `{"versions":{"X":{}}}`.
async fn mirror_provider_index(
    State(state): State<AppState>,
    Path((hostname, ns, ptype)): Path<(String, String, String)>,
) -> Response {
    if !is_valid_name(&hostname) || !is_valid_name(&ns) || !is_valid_name(&ptype) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Enforces #68/#733 namespace isolation internally (never proxies an internal ns).
    let versions_json = match mirror_fetch_versions(&state, &ns, &ptype).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };

    let mirror = build_mirror_index(&versions_json);
    debug_assert!(
        mirror
            .get("versions")
            .map(|v| v.is_object())
            .unwrap_or(false),
        "mirror index must carry a `versions` object"
    );
    state.metrics.record_download("terraform");
    with_json(serde_json::to_vec(&mirror).unwrap_or_default())
}

/// `{version}.json` — List Available Installation Packages (network mirror protocol).
/// Emits `{"archives":{"os_arch":{"url":<NORA path>,"hashes":["zh:<sha256>"]}}}`.
async fn mirror_provider_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((hostname, ns, ptype, version_file)): Path<(String, String, String, String)>,
) -> Response {
    // `{version}.json` — strip the `.json` BEFORE validating (is_valid_version allows
    // '.', so `1.0.0.json` would otherwise pass the charset check and reach storage keys).
    let ver = match version_file.strip_suffix(".json") {
        Some(v) => v,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    if !is_valid_name(&hostname)
        || !is_valid_name(&ns)
        || !is_valid_name(&ptype)
        || !is_valid_version(ver)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Version list drives the platform enumeration AND enforces namespace isolation.
    let versions_json = match mirror_fetch_versions(&state, &ns, &ptype).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let platforms = extract_platforms(&versions_json, ver);
    if platforms.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Curation parity (SEC #2): the binary path runs only the quarantine gate, so
    // blocklist / min-release-age is enforced ONLY at the download-metadata step.
    // A mirror client hits the binary path directly, so version.json must run the
    // same `check_download` or blocked providers leak to mirror clients. Skip for
    // internal namespaces (operator-owned) — mirror_fetch_versions already served
    // any local copy / blocked upstream for those.
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Terraform,
        &format!("{}/{}", ns, ptype),
    );
    if !internal {
        let publish_date = extract_terraform_publish_date(&state, &ns, &ptype, ver, false).await;
        if let Some(resp) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Terraform,
            &format!("{}/{}", ns, ptype),
            Some(ver),
            publish_date,
        ) {
            return resp;
        }
    }

    let base_url = nora_base_url(&state);
    // Fetch every platform's metadata concurrently (bounded by the platform count,
    // typically ≤ ~14). A cold-cache `terraform init` against a fresh mirror is the
    // #801 reporter's exact scenario; a serial per-platform fan-out would risk
    // blowing Terraform's client-side request timeout. Bind shared refs (all Copy) so
    // each future captures its own copy rather than moving the owned values.
    let (state_ref, base_ref, ns_ref, ptype_ref) =
        (&state, base_url.as_str(), ns.as_str(), ptype.as_str());
    let results = futures::future::join_all(platforms.iter().map(|(os, arch)| async move {
        let res = mirror_fetch_archive(state_ref, base_ref, ns_ref, ptype_ref, ver, os, arch).await;
        (os.clone(), arch.clone(), res)
    }))
    .await;

    let mut archives = serde_json::Map::new();
    for (os, arch, res) in results {
        // Fail-closed (SEC #1): only serve an archive that carries an integrity
        // hash. `zh:` is Terraform's zip-hash scheme (hex sha256 of the .zip).
        if let Some((url, Some(shasum))) = res {
            archives.insert(
                format!("{}_{}", os, arch),
                serde_json::json!({ "url": url, "hashes": [format!("zh:{}", shasum)] }),
            );
        }
    }
    if archives.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    state.metrics.record_download("terraform");
    with_json(serde_json::to_vec(&serde_json::json!({ "archives": archives })).unwrap_or_default())
}

/// Fetch + parse the Registry-Protocol versions JSON for the mirror handlers.
/// Mirrors `provider_versions`' cache/TTL/namespace-isolation/serve-stale logic but
/// returns parsed JSON. `Err(Response)` carries the terminal response (block, 404,
/// circuit-open, 502) to return verbatim.
async fn mirror_fetch_versions(
    state: &AppState,
    ns: &str,
    ptype: &str,
) -> Result<serde_json::Value, Box<Response>> {
    let storage_key = format!("terraform/providers/{}/{}/versions.json", ns, ptype);
    let cached_data = state.storage.get(&storage_key).await.ok();

    // TTL cache — serve fresh if within TTL.
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.terraform.metadata_ttl) {
                state.metrics.record_cache_hit("terraform");
                return parse_json(data);
            }
        }
    }

    // #68/#733 namespace isolation: an internal-namespace provider must never be
    // fetched upstream. Serve any local copy, else block — never proxy.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Terraform,
        &format!("{}/{}", ns, ptype),
    ) {
        if let Some(ref data) = cached_data {
            state.metrics.record_cache_hit("terraform");
            return parse_json(data);
        }
        return Err(Box::new(
            crate::curation::check_namespace_isolation(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Terraform,
                &format!("{}/{}", ns, ptype),
            )
            .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response()),
        ));
    }

    let proxy_url = upstream_url(state);
    let url = format!(
        "{}/v1/providers/{}/{}/versions",
        proxy_url.trim_end_matches('/'),
        ns,
        ptype
    );
    match proxy_fetch_text(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.terraform.proxy_timeout),
        expose_opt(&state.config.terraform.proxy_auth),
        None,
        &state.circuit_breaker,
        RegistryType::Terraform,
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_cache_miss("terraform");
            state.spawn_cache("terraform", storage_key, Bytes::from(text.clone()));
            parse_json(text.as_bytes())
        }
        Err(ProxyError::NotFound) => Err(Box::new(StatusCode::NOT_FOUND.into_response())),
        Err(ProxyError::CircuitOpen(reg)) => Err(Box::new(circuit_open_response(&reg))),
        Err(e) => {
            tracing::debug!(provider = format!("{}/{}", ns, ptype), error = ?e, "Terraform mirror versions upstream error");
            // Serve stale parsed metadata if allowed, else 502.
            if let Some(ref data) = cached_data {
                if state.config.terraform.serve_stale {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
                        return Ok(v);
                    }
                }
            }
            Err(Box::new(StatusCode::BAD_GATEWAY.into_response()))
        }
    }
}

/// Resolve one platform's NORA download URL + upstream shasum for the archives map.
/// Reuses the download-metadata cache (NORA-rewritten `download_url` via
/// `rewrite_download_url` — air-gap safe) or fetches + rewrites + caches upstream.
/// Returns `(nora_url, shasum?)`; `None` if the platform metadata is unavailable.
async fn mirror_fetch_archive(
    state: &AppState,
    base_url: &str,
    ns: &str,
    ptype: &str,
    ver: &str,
    os: &str,
    arch: &str,
) -> Option<(String, Option<String>)> {
    if !is_valid_name(os) || !is_valid_name(arch) {
        return None;
    }
    let storage_key = format!(
        "terraform/providers/{}/{}/{}/{}_{}.json",
        ns, ptype, ver, os, arch
    );

    // Cached metadata already carries the NORA-rewritten download_url; reuse it.
    let meta_text = match state.storage.get(&storage_key).await.ok() {
        Some(data) => String::from_utf8_lossy(&data).to_string(),
        None => {
            let proxy_url = upstream_url(state);
            let url = format!(
                "{}/v1/providers/{}/{}/{}/download/{}/{}",
                proxy_url.trim_end_matches('/'),
                ns,
                ptype,
                ver,
                os,
                arch
            );
            let text = proxy_fetch_text(
                &state.http_client,
                &url,
                Duration::from_secs(state.config.terraform.proxy_timeout),
                expose_opt(&state.config.terraform.proxy_auth),
                None,
                &state.circuit_breaker,
                RegistryType::Terraform,
            )
            .await
            .ok()?;
            let rewritten = rewrite_download_url(&text, base_url, ns, ptype, ver);
            state.spawn_cache("terraform", storage_key, Bytes::from(rewritten.clone()));
            rewritten
        }
    };

    let json: serde_json::Value = serde_json::from_str(&meta_text).ok()?;
    let url = json
        .get("download_url")
        .and_then(|v| v.as_str())?
        .to_string();
    let shasum = json
        .get("shasum")
        .and_then(|v| v.as_str())
        .map(String::from);
    Some((url, shasum))
}

/// Reshape Registry-Protocol `{"versions":[{"version":"X",..}]}` into the network
/// mirror `{"versions":{"X":{},..}}` form.
fn build_mirror_index(versions_json: &serde_json::Value) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(arr) = versions_json.get("versions").and_then(|v| v.as_array()) {
        for entry in arr {
            if let Some(ver) = entry.get("version").and_then(|v| v.as_str()) {
                map.insert(ver.to_string(), serde_json::json!({}));
            }
        }
    }
    serde_json::json!({ "versions": serde_json::Value::Object(map) })
}

/// Extract the `[(os, arch)]` platform list for `ver` from the versions JSON.
fn extract_platforms(versions_json: &serde_json::Value, ver: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(arr) = versions_json.get("versions").and_then(|v| v.as_array()) {
        for entry in arr {
            if entry.get("version").and_then(|v| v.as_str()) == Some(ver) {
                if let Some(plats) = entry.get("platforms").and_then(|v| v.as_array()) {
                    for p in plats {
                        if let (Some(os), Some(arch)) = (
                            p.get("os").and_then(|v| v.as_str()),
                            p.get("arch").and_then(|v| v.as_str()),
                        ) {
                            out.push((os.to_string(), arch.to_string()));
                        }
                    }
                }
            }
        }
    }
    out
}

/// Parse cached/proxied JSON bytes, mapping a parse failure to a 502 Response.
fn parse_json(data: &[u8]) -> Result<serde_json::Value, Box<Response>> {
    serde_json::from_slice::<serde_json::Value>(data)
        .map_err(|_| Box::new(StatusCode::BAD_GATEWAY.into_response()))
}

// ── Helpers ────────────────────────────────────────────────────────────

/// True when a configured Terraform proxy points at the official
/// registry.terraform.io — the only upstream with a per-version date source (its
/// `/v2` API). Gates the v2 query so internal namespaces are never sent there.
/// True when a URL points at the official registry.terraform.io — the only Terraform
/// upstream with a per-version date source (its `/v2` API). A private/self-hosted
/// registry returns false, so its coordinates are never sent to the public host
/// (#68/#733).
fn url_is_official_terraform(u: &str) -> bool {
    u.contains("registry.terraform.io")
}

fn terraform_upstream_is_official(state: &AppState) -> bool {
    url_is_official_terraform(&upstream_url(state))
}

/// Best-effort release date for a Terraform provider version via the
/// registry.terraform.io `/v2` API. The *standard* provider protocol exposes no
/// date (neither `versions` nor `download/{os}/{arch}` carry one — verified
/// against the live API), so this v2 endpoint is the only trusted source, and it
/// only exists on the official registry. Any failure → `None`.
async fn fetch_terraform_registry_date(
    client: &reqwest::Client,
    ns: &str,
    ptype: &str,
    ver: &str,
    timeout_secs: u64,
) -> Option<i64> {
    let url = format!(
        "https://registry.terraform.io/v2/providers/{}/{}?include=provider-versions",
        ns, ptype
    );
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let json: serde_json::Value = resp.json().await.ok()?;
    let included = json.get("included")?.as_array()?;
    for item in included {
        let attrs = match item.get("attributes") {
            Some(a) => a,
            None => continue,
        };
        if attrs.get("version").and_then(|v| v.as_str()) == Some(ver) {
            let date_str = attrs.get("published-at").and_then(|v| v.as_str())?;
            return crate::curation::parse_iso8601_to_unix(date_str);
        }
    }
    None
}

/// Release date for the quarantine first-seen clock (#748/#750).
///
/// The standard Terraform provider protocol carries no publish date, so the only
/// trusted source is registry.terraform.io's `/v2` API (official upstream only,
/// and spoofable → gated on `trust_upstream_dates` per #513). For self-hosted
/// providers the mtime of cached metadata ≈ first-publish. Otherwise `None` and
/// the quarantine falls back to NORA's own first-seen clock.
async fn extract_terraform_publish_date(
    state: &AppState,
    ns: &str,
    ptype: &str,
    ver: &str,
    already_cached: bool,
) -> Option<i64> {
    // Proxy mode: only the official registry has a per-version date, and only when
    // we're configured to trust upstream-provided dates (#513 — an attacker on a
    // custom mirror could spoof it).
    if state.config.terraform.proxy.is_some() {
        // #68/#733 dependency-confusion: an internal-namespace provider's coordinates
        // must never be sent to the hardcoded public registry.terraform.io/v2 — that
        // would leak them upstream. Block the date query for internal namespaces.
        if crate::curation::is_internal_namespace(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Terraform,
            &format!("{}/{}", ns, ptype),
        ) {
            return None;
        }
        // #754: only query /v2 on a cache MISS — on a cache hit the digest is already
        // recorded (idempotent `record` ignores the date), so skip the round-trip.
        if !already_cached
            && state.config.server.trust_upstream_dates
            && terraform_upstream_is_official(state)
        {
            return fetch_terraform_registry_date(
                &state.http_client,
                ns,
                ptype,
                ver,
                state.config.terraform.proxy_timeout,
            )
            .await;
        }
        return None;
    }

    // Hosted mode: mtime of any cached platform metadata ≈ first-publish time.
    // This is NORA's own observation (not upstream-controlled), so it is safe
    // regardless of the trust flag.
    for suffix in &["linux_amd64.json", "linux_arm64.json", "darwin_amd64.json"] {
        let meta_key = format!("terraform/providers/{}/{}/{}/{}", ns, ptype, ver, suffix);
        if let Some(ts) =
            crate::curation::extract_mtime_as_publish_date(&state.storage, &meta_key).await
        {
            return Some(ts);
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
        let keys = state.storage.list(&prefix).await.unwrap_or_default();
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

/// Serve stale cached metadata when upstream is unreachable, or 502 if no cache.
fn serve_stale_or_bad_gateway(state: &AppState, cached: Option<Bytes>, endpoint: &str) -> Response {
    if let Some(data) = cached {
        if state.config.terraform.serve_stale {
            tracing::warn!(
                registry = "terraform",
                endpoint,
                "Upstream unreachable, serving stale cached metadata"
            );
            return (
                StatusCode::OK,
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    ),
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=0, must-revalidate"),
                    ),
                    (
                        axum::http::header::HeaderName::from_static("x-nora-stale"),
                        axum::http::header::HeaderValue::from_static("true"),
                    ),
                ],
                data.to_vec(),
            )
                .into_response();
        }
    }
    StatusCode::BAD_GATEWAY.into_response()
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
    fn test_url_is_official_terraform() {
        // official registry → true (the /v2 date source)
        assert!(url_is_official_terraform("https://registry.terraform.io"));
        assert!(url_is_official_terraform(
            "https://registry.terraform.io/v2/providers"
        ));
        // private/self-hosted registries → false: coordinates must NEVER reach the
        // public registry.terraform.io/v2 (#68/#733)
        assert!(!url_is_official_terraform("https://tf.internal.corp"));
        assert!(!url_is_official_terraform("https://app.terraform.io")); // TFC, not the public registry host
        assert!(!url_is_official_terraform(""));
    }

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

    // ── Network Mirror Protocol reshape (#801) ──

    #[test]
    fn test_build_mirror_index() {
        let versions = serde_json::json!({
            "versions": [
                {"version": "3.2.3", "protocols": ["5.0"], "platforms": [{"os": "linux", "arch": "amd64"}]},
                {"version": "3.2.2", "platforms": []}
            ]
        });
        let mirror = build_mirror_index(&versions);
        let obj = mirror.get("versions").and_then(|v| v.as_object()).unwrap();
        assert!(obj.contains_key("3.2.3"), "version must be a key");
        assert!(obj.contains_key("3.2.2"));
        // Each value is an empty object per the mirror protocol.
        assert!(obj["3.2.3"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_build_mirror_index_empty() {
        let mirror = build_mirror_index(&serde_json::json!({"versions": []}));
        assert_eq!(mirror, serde_json::json!({"versions": {}}));
        // Malformed input → empty versions, never a panic.
        let mirror2 = build_mirror_index(&serde_json::json!({"nope": 1}));
        assert_eq!(mirror2, serde_json::json!({"versions": {}}));
    }

    #[test]
    fn test_extract_platforms() {
        let versions = serde_json::json!({
            "versions": [
                {"version": "3.2.3", "platforms": [
                    {"os": "linux", "arch": "amd64"},
                    {"os": "darwin", "arch": "arm64"}
                ]},
                {"version": "3.2.2", "platforms": [{"os": "windows", "arch": "amd64"}]}
            ]
        });
        let mut p = extract_platforms(&versions, "3.2.3");
        p.sort();
        assert_eq!(
            p,
            vec![
                ("darwin".to_string(), "arm64".to_string()),
                ("linux".to_string(), "amd64".to_string())
            ]
        );
        // Unknown version → no platforms (→ handler returns 404).
        assert!(extract_platforms(&versions, "9.9.9").is_empty());
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

    /// Stale cache + unreachable upstream + serve_stale=true → 200 with X-Nora-Stale header (#532)
    #[tokio::test]
    async fn test_serve_stale_provider_versions() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.terraform.proxy_timeout = 1;
            cfg.terraform.metadata_ttl = 0; // force TTL expiry
            cfg.terraform.serve_stale = true;
        });

        // Pre-populate cache
        ctx.state
            .storage
            .put(
                "terraform/providers/hashicorp/aws/versions.json",
                br#"{"versions":[{"version":"5.0.0"}]}"#,
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/providers/hashicorp/aws/versions",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
            Some(b"true".as_ref()),
        );
        let body = body_bytes(resp).await;
        assert!(String::from_utf8_lossy(&body).contains("5.0.0"));
    }

    /// Stale cache + unreachable upstream + serve_stale=false → 502 (#532)
    #[tokio::test]
    async fn test_serve_stale_disabled_returns_502() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.terraform.proxy_timeout = 1;
            cfg.terraform.metadata_ttl = 0;
            cfg.terraform.serve_stale = false;
        });

        ctx.state
            .storage
            .put(
                "terraform/providers/hashicorp/aws/versions.json",
                br#"{"versions":[{"version":"5.0.0"}]}"#,
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/providers/hashicorp/aws/versions",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert!(resp.headers().get("x-nora-stale").is_none());
    }

    /// No cache + unreachable upstream → 502 regardless of serve_stale (#532)
    #[tokio::test]
    async fn test_no_cache_upstream_down_returns_502() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.terraform.proxy_timeout = 1;
            cfg.terraform.serve_stale = true;
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

    // ── Provider Network Mirror Protocol (#801) ──

    /// index.json (mirror) reshapes the cached versions list into {"versions":{"X":{}}}.
    /// Also proves routing: index.json hits the mirror index handler, not {version_file}.
    #[tokio::test]
    async fn test_mirror_index_from_cache() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
        });
        ctx.state
            .storage
            .put(
                "terraform/providers/hashicorp/null/versions.json",
                br#"{"versions":[{"version":"3.2.3","platforms":[{"os":"linux","arch":"amd64"}]},{"version":"3.2.2","platforms":[]}]}"#,
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/registry.terraform.io/hashicorp/null/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let versions = json.get("versions").and_then(|v| v.as_object()).unwrap();
        assert!(versions.contains_key("3.2.3"));
        assert!(versions.contains_key("3.2.2"));
        assert!(versions["3.2.3"].as_object().unwrap().is_empty());
    }

    /// {version}.json (mirror) emits archives with the NORA download URL + zh: hash.
    /// url must go through NORA (air-gap); hash is zh:<upstream shasum>.
    #[tokio::test]
    async fn test_mirror_version_archives_from_cache() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
        });
        ctx.state
            .storage
            .put(
                "terraform/providers/hashicorp/null/versions.json",
                br#"{"versions":[{"version":"3.2.3","platforms":[{"os":"linux","arch":"amd64"}]}]}"#,
            )
            .await
            .unwrap();
        // Cached download-metadata already carries the NORA-rewritten download_url.
        ctx.state
            .storage
            .put(
                "terraform/providers/hashicorp/null/3.2.3/linux_amd64.json",
                br#"{"download_url":"http://localhost:4000/terraform/v1/providers/download/hashicorp/null/3.2.3/terraform-provider-null_3.2.3_linux_amd64.zip","shasum":"deadbeef"}"#,
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/registry.terraform.io/hashicorp/null/3.2.3.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arch = &json["archives"]["linux_amd64"];
        assert!(
            arch["url"]
                .as_str()
                .unwrap()
                .contains("/terraform/v1/providers/download/"),
            "url must route through NORA, got {arch}"
        );
        assert!(
            !arch["url"]
                .as_str()
                .unwrap()
                .contains("releases.hashicorp.com"),
            "upstream host must not leak"
        );
        assert_eq!(arch["hashes"][0].as_str().unwrap(), "zh:deadbeef");
    }

    /// SEC #2: mirror {version}.json MUST enforce the blocklist (curation parity with
    /// download-meta) — otherwise a mirror client bypasses it via the binary path.
    #[tokio::test]
    async fn test_mirror_version_blocklist_enforced() {
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
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl_path);
        });
        // Seed versions so the platform list resolves from cache (no upstream needed).
        ctx.state
            .storage
            .put(
                "terraform/providers/evilcorp/backdoor/versions.json",
                br#"{"versions":[{"version":"1.0.0","platforms":[{"os":"linux","arch":"amd64"}]}]}"#,
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/registry.terraform.io/evilcorp/backdoor/1.0.0.json",
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "blocklisted provider must be blocked on the mirror path too"
        );
    }

    /// Internal-namespace providers must never be proxied upstream via the mirror
    /// path either (#68/#733 dependency confusion).
    #[tokio::test]
    async fn test_mirror_internal_namespace_not_proxied() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:1".to_string()); // would 502 if proxied
            cfg.terraform.proxy_timeout = 1;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces = vec!["internalcorp/**".to_string()];
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/registry.terraform.io/internalcorp/secret/index.json",
            "",
        )
        .await;
        // Blocked (not proxied): never 200, never a 502 from an upstream attempt.
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::NOT_FOUND,
            "internal namespace must be blocked, got {}",
            resp.status()
        );
    }

    /// version_file without a `.json` suffix → 404 (strip guard before validation).
    #[tokio::test]
    async fn test_mirror_version_requires_json_suffix() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/registry.terraform.io/hashicorp/null/3.2.3",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Feature flag: terraform disabled → mirror routes are not mounted → 404.
    #[tokio::test]
    async fn test_mirror_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = false;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/registry.terraform.io/hashicorp/null/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
