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
use crate::config::UpstreamAuth;
use crate::registry::{
    circuit_open_response, nora_base_url, proxy_fetch, proxy_fetch_text, ProxyError, UpstreamMiss,
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

// ── One decision for every request ─────────────────────────────────────

/// The name curation and namespace isolation decide on for a provider: `ns/type`.
fn provider_identity(ns: &str, ptype: &str) -> String {
    format!("{}/{}", ns, ptype)
}

/// The name curation and namespace isolation decide on for a module: `ns/name/system`.
fn module_identity(ns: &str, name: &str, system: &str) -> String {
    format!("{}/{}/{}", ns, name, system)
}

/// What curation and namespace isolation decide for a request, taken by every handler before it
/// serves or fetches anything: `Ok(true)` for an internal name (#68/#733), which is answered from
/// its local copy only and never fetched; `Ok(false)` for a name to serve from a fresh local copy
/// or fetch; `Err` with curation's refusal. A version list (`version` none) is not refused.
fn tf_decide(
    state: &AppState,
    headers: &HeaderMap,
    identity: &str,
    version: Option<&str>,
    publish_date: Option<i64>,
) -> Result<bool, Box<Response>> {
    let engine = &state.curation().curation_engine;
    if crate::curation::is_internal_namespace(
        engine,
        crate::curation::RegistryType::Terraform,
        identity,
    ) {
        return Ok(true);
    }
    match version.and_then(|version| {
        crate::curation::check_download(
            engine,
            state.bypass_token().as_deref(),
            headers,
            crate::curation::RegistryType::Terraform,
            identity,
            crate::curation::RequestVersion::Known(version.to_string()),
            publish_date,
        )
    }) {
        Some(refusal) => Err(Box::new(refusal)),
        None => Ok(false),
    }
}

/// The answer to an internal name with no local copy: an isolation refusal, counted.
fn tf_isolation_refusal(state: &AppState, identity: &str) -> Response {
    crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Terraform,
        identity,
    )
    .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
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
    let provider = provider_identity(&ns, &ptype);
    let internal = match tf_decide(&state, &HeaderMap::new(), &provider, None, None) {
        Ok(internal) => internal,
        Err(refusal) => return *refusal,
    };

    let storage_key = format!("terraform/providers/{}/{}/versions.json", ns, ptype);

    // Read cache eagerly — preserve for serve-stale fallback (#532)
    let (cached_data, read_failure) =
        crate::registry::cached_read(state.storage.get(&storage_key).await);

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
    // path returned above), else block — never proxy.
    if internal {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_hit("terraform");
            return with_json(data.to_vec());
        }
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("terraform", &storage_key, e);
        }
        return tf_isolation_refusal(&state, &provider);
    }

    // No upstream when the operator switched it off: what is stored is all there is.
    let Some(proxy_url) = upstream_url(&state) else {
        return match cached_data {
            Some(data) => with_json(data.to_vec()),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    };
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
        expose_opt(&state.config.terraform.proxy_auth).map(UpstreamAuth::Basic),
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
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "terraform", ""));

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
    let provider = provider_identity(&ns, &ptype);
    let internal = match tf_decide(&state, &headers, &provider, Some(&ver), publish_date) {
        Ok(internal) => internal,
        Err(refusal) => return *refusal,
    };

    let storage_key = format!(
        "terraform/providers/{}/{}/{}/{}_{}.json",
        ns, ptype, ver, os, arch
    );

    // Read cache eagerly — preserve for serve-stale fallback (#532).
    // Strip internal fields now so stale response is client-safe.
    let (cached_raw, read_failure) =
        crate::registry::cached_read(state.storage.get(&storage_key).await);
    let cached_data = cached_raw.map(|d| Bytes::from(strip_nora_internal_fields(&d)));

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
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("terraform", &storage_key, e);
        }
        return tf_isolation_refusal(&state, &provider);
    }

    // No upstream when the operator switched it off: what is stored is all there is.
    let Some(proxy_url) = upstream_url(&state) else {
        return match cached_data {
            Some(data) => with_json(data.to_vec()),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    };
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
        expose_opt(&state.config.terraform.proxy_auth).map(UpstreamAuth::Basic),
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
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "terraform", ""));

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
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
) -> Response {
    if !is_safe_path(&path) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    // Path format: {ns}/{type}/{ver}/{filename}, as `rewrite_download_url` writes it.
    let parts: Vec<&str> = path.splitn(4, '/').collect();
    if parts.len() < 4 {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (ns, ptype, ver, filename) = (parts[0], parts[1], parts[2], parts[3]);
    let provider = provider_identity(ns, ptype);

    let storage_key = format!("terraform/download/{}", path);

    // Release date for the quarantine first-seen clock (#748/#750): the cached provider
    // metadata's date (gated internally on trust_upstream_dates; None → NORA's clock).
    // #754: skip the /v2 round-trip on a cache hit (the digest is already recorded).
    let already_cached = state.storage.stat(&storage_key).await.is_some();
    let publish_date = extract_terraform_publish_date(&state, ns, ptype, ver, already_cached).await;

    // A provider's files pass the curation its download metadata passes: a client can ask for
    // them directly. An internal provider is operator-owned — served from the cache below and
    // never fetched upstream.
    let internal = match tf_decide(&state, &headers, &provider, Some(ver), publish_date) {
        Ok(internal) => internal,
        Err(refusal) => return *refusal,
    };

    // Immutable: if cached, serve directly. get_verified discharges the integrity
    // witness at serve (compile-time guarantee — see crate::verified).
    let (cached, read_failure) =
        crate::registry::cached_read(state.storage.get_verified(&storage_key).await);
    if let Some(outcome) = cached {
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

        // Resume support: 206 for a `Range` request, 416 when the client asks past the
        // end — a provider zip is large and worth resuming. It sits after the gates
        // above because the quarantine digest check needs the whole object. A partial
        // body cannot be rehashed, so the serve relies on the SHA256SUMS terraform
        // verifies itself (docker did the same in #657). An absent/malformed range
        // falls through to the full 200.
        if let Some(response) = range_binary(&state, &storage_key, &headers, data.len()).await {
            return response;
        }
        return with_binary(data.to_vec());
    }

    // #733: an internal provider's file that is not cached is refused, whatever URL metadata
    // cached before the namespace became internal names.
    if internal {
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("terraform", &storage_key, e);
        }
        return tf_isolation_refusal(&state, &provider);
    }

    // No upstream when the operator switched it off: a provider file not stored is not fetched
    // from anywhere, the release host its metadata names included.
    if upstream_url(&state).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Try upstream — resolve the real upstream URL from cached provider metadata.
    // The metadata JSON (cached by provider_download_meta) stores the
    // original download_url in `_nora_upstream_url`.
    let url = resolve_upstream_download_url(&state, ns, ptype, ver, filename).await;

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.terraform.proxy_timeout_dl),
        expose_opt(&state.config.terraform.proxy_auth).map(UpstreamAuth::Basic),
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
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "terraform", ""));

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
    let module = module_identity(&ns, &name, &provider);
    let internal = match tf_decide(&state, &HeaderMap::new(), &module, None, None) {
        Ok(internal) => internal,
        Err(refusal) => return *refusal,
    };

    let storage_key = format!(
        "terraform/modules/{}/{}/{}/versions.json",
        ns, name, provider
    );

    // Read cache eagerly — preserve for serve-stale fallback (#532)
    let (cached_data, read_failure) =
        crate::registry::cached_read(state.storage.get(&storage_key).await);

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
    // returned above), else block — never proxy.
    if internal {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_hit("terraform");
            return with_json(data.to_vec());
        }
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("terraform", &storage_key, e);
        }
        return tf_isolation_refusal(&state, &module);
    }

    // No upstream when the operator switched it off: what is stored is all there is.
    let Some(proxy_url) = upstream_url(&state) else {
        return match cached_data {
            Some(data) => with_json(data.to_vec()),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    };
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
        expose_opt(&state.config.terraform.proxy_auth).map(UpstreamAuth::Basic),
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
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "terraform", ""));

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
    headers: axum::http::HeaderMap,
    Path((ns, name, provider, ver)): Path<(String, String, String, String)>,
) -> Response {
    if !is_valid_name(&ns)
        || !is_valid_name(&name)
        || !is_valid_name(&provider)
        || !is_valid_version(&ver)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // The download names the module itself: curation decides on it, and an internal-namespace
    // module (#68/#733) is answered from a cached source URL only, never asked upstream.
    let module = module_identity(&ns, &name, &provider);
    let internal = match tf_decide(&state, &headers, &module, Some(&ver), None) {
        Ok(internal) => internal,
        Err(refusal) => return *refusal,
    };

    let base_url = nora_base_url(&state);

    // If we have a cached source URL, return the rewritten header immediately
    let source_url_key = format!(
        "terraform/modules/{}/{}/{}/{}/_source_url",
        ns, name, provider, ver
    );
    let (cached, read_failure) =
        crate::registry::cached_read(state.storage.get(&source_url_key).await);
    // Only an archive source is stored. One an older release stored for a git source (the
    // repository address, prefix stripped) names no archive: the upstream is asked again (#1209).
    if let Some(data) = cached {
        let stored = String::from_utf8_lossy(&data);
        let rewritten = rewrite_module_source_url(&stored, &base_url, &ns, &name, &provider, &ver);
        if rewritten != stored {
            state.metrics.record_download("terraform");
            state.metrics.record_cache_hit("terraform");
            return (
                StatusCode::NO_CONTENT,
                [("x-terraform-get", rewritten.as_str())],
            )
                .into_response();
        }
    }

    if internal {
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("terraform", &source_url_key, e);
        }
        return tf_isolation_refusal(&state, &module);
    }

    // No upstream when the operator switched it off.
    let Some(proxy_url) = upstream_url(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let url = format!(
        "{}/v1/modules/{}/{}/{}/{}/download",
        proxy_url.trim_end_matches('/'),
        ns,
        name,
        provider,
        ver
    );

    // Module download returns 204 with X-Terraform-Get header pointing to source. Asked through
    // the `terraform` breaker like every other path (#1202): an open breaker is 503, a failure
    // counts toward opening it.
    let fetched = super::proxy_fetch_core(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.terraform.proxy_timeout),
        expose_opt(&state.config.terraform.proxy_auth).map(UpstreamAuth::Basic),
        None,
        |response| async move {
            Ok(response
                .headers()
                .get("x-terraform-get")
                .map(|v| v.to_str().unwrap_or("").to_string()))
        },
        &state.circuit_breaker,
        RegistryType::Terraform,
    )
    .await;

    match fetched {
        Ok(Some(original_url)) => {
            state.metrics.record_download("terraform");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/{}/{} v{}", ns, name, provider, ver),
                crate::registry_type::RegistryType::Terraform,
                "PROXY",
            ));

            // An archive source goes through NORA (air-gap safe); anything else is the
            // client's to fetch, and nothing is stored for it (#1209).
            let rewritten =
                rewrite_module_source_url(&original_url, &base_url, &ns, &name, &provider, &ver);
            if rewritten != original_url {
                state.spawn_cache("terraform", source_url_key, Bytes::from(original_url));
            }

            (
                StatusCode::NO_CONTENT,
                [("x-terraform-get", rewritten.as_str())],
            )
                .into_response()
        }
        // A 2xx without the source header breaks the protocol: a failed upstream.
        Ok(None) => UpstreamMiss::of(&ProxyError::Upstream(502))
            .response("terraform", &format!("{ns}/{name}/{provider}/{ver}")),
        // A 4xx says the module is not there; a 5xx, network error or timeout is a failed
        // upstream; an open breaker is the 503 it is everywhere.
        Err(e) => {
            tracing::debug!(error = ?e, "Terraform module download error");
            UpstreamMiss::of(&e).response("terraform", &format!("{ns}/{name}/{provider}/{ver}"))
        }
    }
}

// ── Module source download (cached, proxied) ─────────────────────────

async fn module_source_download(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((ns, name, provider, ver)): Path<(String, String, String, String)>,
) -> Response {
    if !is_valid_name(&ns)
        || !is_valid_name(&name)
        || !is_valid_name(&provider)
        || !is_valid_version(&ver)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // The archive is the module: curation decides on it, and an internal-namespace module is
    // served from the cache only, never fetched from its source URL.
    let module = module_identity(&ns, &name, &provider);
    let internal = match tf_decide(&state, &headers, &module, Some(&ver), None) {
        Ok(internal) => internal,
        Err(refusal) => return *refusal,
    };

    let storage_key = format!(
        "terraform/modules/{}/{}/{}/{}/source.tar.gz",
        ns, name, provider, ver
    );

    // Immutable: if cached, serve directly. get_verified discharges the integrity
    // witness at serve (compile-time guarantee — see crate::verified).
    let (cached, read_failure) =
        crate::registry::cached_read(state.storage.get_verified(&storage_key).await);
    if let Some(outcome) = cached {
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

        // Resume support for the module archive — same rationale as the provider
        // binary above.
        if let Some(response) = range_binary(&state, &storage_key, &headers, data.len()).await {
            return response;
        }
        return with_binary(data.to_vec());
    }

    if internal {
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("terraform", &storage_key, e);
        }
        return tf_isolation_refusal(&state, &module);
    }
    // With the upstream switched off, a source URL stored while it was on is not followed: the
    // archive is served from storage or not at all.
    if upstream_url(&state).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Resolve original upstream URL from cached metadata
    let source_url_key = format!(
        "terraform/modules/{}/{}/{}/{}/_source_url",
        ns, name, provider, ver
    );
    let upstream_url = match state.storage.get(&source_url_key).await {
        // The stored address may carry a `//subdir`: that is the client's, not part of the URL.
        Ok(data) => split_subdir(&String::from_utf8_lossy(&data)).0,
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
        expose_opt(&state.config.terraform.proxy_auth).map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        RegistryType::Terraform,
    )
    .await
    {
        // A web page (a repository's) is no module: not served, not cached as one (#1209).
        Ok(bytes) if !looks_like_archive(&bytes) => {
            tracing::warn!(
                module = %format!("{ns}/{name}/{provider}"),
                version = %ver,
                url = %upstream_url,
                "module source is not an archive, not served or cached"
            );
            StatusCode::BAD_GATEWAY.into_response()
        }
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
    let provider = provider_identity(&ns, &ptype);
    let internal = match tf_decide(&state, &HeaderMap::new(), &provider, None, None) {
        Ok(internal) => internal,
        Err(refusal) => return *refusal,
    };

    // An internal provider's version list comes from the cache only (#68/#733).
    let versions_json = match mirror_fetch_versions(&state, &ns, &ptype, internal).await {
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

    // Curation parity (SEC #2): version.json is decided as the download-metadata step is, so a
    // blocked version lists no archives to a mirror client (its files are refused on the binary
    // path as well). An internal provider (#68/#733) is answered from the cache only: its version
    // list and each platform's metadata.
    let provider = provider_identity(&ns, &ptype);
    let publish_date = extract_terraform_publish_date(&state, &ns, &ptype, ver, false).await;
    let internal = match tf_decide(&state, &headers, &provider, Some(ver), publish_date) {
        Ok(internal) => internal,
        Err(refusal) => return *refusal,
    };

    // Version list drives the platform enumeration.
    let versions_json = match mirror_fetch_versions(&state, &ns, &ptype, internal).await {
        Ok(v) => v,
        Err(resp) => return *resp,
    };
    let platforms = extract_platforms(&versions_json, ver);
    if platforms.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
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
        let res = mirror_fetch_archive(
            state_ref,
            base_ref,
            ns_ref,
            ptype_ref,
            ver,
            (os.as_str(), arch.as_str()),
            internal,
        )
        .await;
        (os.clone(), arch.clone(), res)
    }))
    .await;

    let mut archives = serde_json::Map::new();
    let mut incomplete = false;
    let mut unreadable: Option<Box<Response>> = None;
    for (os, arch, res) in results {
        match res {
            // Fail-closed (SEC #1): only serve an archive that carries an integrity
            // hash. `zh:` is Terraform's zip-hash scheme (hex sha256 of the .zip).
            Ok(Some((url, Some(shasum)))) => {
                archives.insert(
                    format!("{}_{}", os, arch),
                    serde_json::json!({ "url": url, "hashes": [format!("zh:{}", shasum)] }),
                );
            }
            Ok(_) => {}
            // A platform the upstream failed to describe (not one it answered 4xx for):
            // the list would be incomplete, and a client on that platform would read
            // "not supported" from an outage.
            Err(ArchiveMiss::Upstream(e)) => {
                incomplete |= UpstreamMiss::of(&e).status().is_server_error()
            }
            Err(ArchiveMiss::Unreadable(response)) => unreadable = Some(response),
        }
    }
    if let Some(response) = unreadable {
        return *response;
    }
    if incomplete {
        tracing::warn!(registry = "terraform", %ns, %ptype, %ver, "upstream failed for a platform, returning 502");
        return StatusCode::BAD_GATEWAY.into_response();
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
    internal: bool,
) -> Result<serde_json::Value, Box<Response>> {
    let storage_key = format!("terraform/providers/{}/{}/versions.json", ns, ptype);
    let (cached_data, read_failure) =
        crate::registry::cached_read(state.storage.get(&storage_key).await);

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
    if internal {
        if let Some(ref data) = cached_data {
            state.metrics.record_cache_hit("terraform");
            return parse_json(data);
        }
        if let Some(e) = &read_failure {
            return Err(Box::new(crate::registry::local_copy_unreadable(
                "terraform",
                &storage_key,
                e,
            )));
        }
        return Err(Box::new(tf_isolation_refusal(
            state,
            &provider_identity(ns, ptype),
        )));
    }

    // No upstream when the operator switched it off: what is stored is all there is.
    let Some(proxy_url) = upstream_url(state) else {
        return match cached_data {
            Some(ref data) => parse_json(data),
            None => Err(Box::new(StatusCode::NOT_FOUND.into_response())),
        };
    };
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
        expose_opt(&state.config.terraform.proxy_auth).map(UpstreamAuth::Basic),
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
/// Returns `(nora_url, shasum?)`; `None` if the platform metadata is not usable, and the
/// upstream's error if fetching it failed.
async fn mirror_fetch_archive(
    state: &AppState,
    base_url: &str,
    ns: &str,
    ptype: &str,
    ver: &str,
    (os, arch): (&str, &str),
    internal: bool,
) -> Result<Option<(String, Option<String>)>, ArchiveMiss> {
    if !is_valid_name(os) || !is_valid_name(arch) {
        return Ok(None);
    }
    let storage_key = format!(
        "terraform/providers/{}/{}/{}/{}_{}.json",
        ns, ptype, ver, os, arch
    );

    // Cached metadata already carries the NORA-rewritten download_url; reuse it. An internal
    // provider's platform without it is not listed: its metadata is never fetched (#68/#733).
    let (cached, read_failure) =
        crate::registry::cached_read(state.storage.get(&storage_key).await);
    let meta_text = match cached {
        Some(data) => String::from_utf8_lossy(&data).to_string(),
        // An internal provider's platform whose metadata the store could not read is unavailable:
        // dropped from the list, it would read as "not supported on this platform".
        None if internal => {
            return match read_failure {
                Some(e) => Err(ArchiveMiss::Unreadable(Box::new(
                    crate::registry::local_copy_unreadable("terraform", &storage_key, &e),
                ))),
                None => Ok(None),
            }
        }
        None => {
            // No upstream when the operator switched it off: the archive is not listed.
            let Some(proxy_url) = upstream_url(state) else {
                return Ok(None);
            };
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
                expose_opt(&state.config.terraform.proxy_auth).map(UpstreamAuth::Basic),
                None,
                &state.circuit_breaker,
                RegistryType::Terraform,
            )
            .await
            .map_err(ArchiveMiss::Upstream)?;
            let rewritten = rewrite_download_url(&text, base_url, ns, ptype, ver);
            state.spawn_cache("terraform", storage_key, Bytes::from(rewritten.clone()));
            rewritten
        }
    };

    let Ok(json) = serde_json::from_str::<serde_json::Value>(&meta_text) else {
        return Ok(None);
    };
    let Some(url) = json.get("download_url").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let shasum = json
        .get("shasum")
        .and_then(|v| v.as_str())
        .map(String::from);
    Ok(Some((url.to_string(), shasum)))
}

/// Why a platform's archive could not be listed by the network mirror.
enum ArchiveMiss {
    /// The upstream failed, or answered no.
    Upstream(ProxyError),
    /// The store could not read an internal provider's cached metadata: the answer to give.
    Unreadable(Box<Response>),
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
    upstream_url(state).is_some_and(|u| url_is_official_terraform(&u))
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
    if upstream_url(state).is_some() {
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

/// The configured upstream, or None when the operator switched it off with an empty
/// NORA_TF_PROXY: then nothing is asked of any upstream.
fn upstream_url(state: &AppState) -> Option<String> {
    crate::config::configured_upstream(&state.config.terraform.proxy).map(str::to_string)
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
            (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        ],
        data,
    )
        .into_response()
}

/// 206/416 counterpart of [`with_binary`]; `None` when there is no usable `Range`.
async fn range_binary(
    state: &AppState,
    storage_key: &str,
    headers: &axum::http::HeaderMap,
    size: usize,
) -> Option<Response> {
    crate::registry::range::range_response(
        &state.storage,
        &[storage_key],
        headers,
        size as u64,
        "application/zip",
        &[(
            header::CACHE_CONTROL,
            "public, max-age=31536000, immutable".to_string(),
        )],
    )
    .await
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

/// The `X-Terraform-Get` NORA answers for the source the upstream named (#1209). An HTTP source
/// that names an archive goes through NORA's module source endpoint, with `archive=<kind>` so
/// go-getter unpacks it and its `//subdir` kept. Anything else — a VCS source (`git::`, `hg::`),
/// a non-HTTP one (`s3::`, `ssh://`, a relative path), or an HTTP address nothing marks as an
/// archive — is answered unchanged, for the client to fetch itself.
fn rewrite_module_source_url(
    original_url: &str,
    base_url: &str,
    ns: &str,
    name: &str,
    provider: &str,
    ver: &str,
) -> String {
    // A VCS source (git::, hg::) or any non-HTTP one is the client's to fetch: NORA cannot
    // serve a repository as an archive (#1209: it served the repository's web page).
    let (vcs_prefix, inner_url) = strip_vcs_prefix(original_url);
    if !vcs_prefix.is_empty()
        || !(inner_url.starts_with("http://") || inner_url.starts_with("https://"))
    {
        return original_url.to_string();
    }
    let (source, subdir) = split_subdir(inner_url);
    // An HTTP address nothing marks as an archive may be anything (go-getter asks it for an
    // X-Terraform-Get of its own): the client follows it itself.
    let Some(kind) = archive_kind(&source) else {
        return original_url.to_string();
    };
    format!(
        "{}/terraform/v1/modules/download/{}/{}/{}/{}/source{}?archive={}",
        base_url.trim_end_matches('/'),
        ns,
        name,
        provider,
        ver,
        subdir.map(|sub| format!("//{sub}")).unwrap_or_default(),
        kind
    )
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
/// Whether `bytes` open as an archive go-getter unpacks: gzip, zip, bzip2, xz or tar, by their
/// magic bytes. A module's source is served and cached only when they do (#1209): an HTTP
/// source can answer a web page (a git repository's), which is no module.
fn looks_like_archive(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x1f, 0x8b])
        || bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"BZh")
        || bytes.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00])
        || bytes.get(257..262) == Some(b"ustar".as_slice())
}

/// Archive kinds go-getter recognizes by extension, longest first.
const ARCHIVE_EXTENSIONS: [&str; 8] = [
    "tar.gz", "tar.bz2", "tar.xz", "tgz", "tbz2", "txz", "zip", "tar",
];

/// The kind of archive an HTTP source `address` names, as go-getter would read it: its
/// `archive=` query value, else the extension its path ends in, else GitHub's codeload form
/// (`/tar.gz/<ref>`, `/zip/<ref>`). `None` when nothing marks it as an archive.
fn archive_kind(address: &str) -> Option<String> {
    let (path, query) = address.split_once('?').unwrap_or((address, ""));
    if let Some(kind) = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("archive="))
        .filter(|k| !k.is_empty())
    {
        return Some(kind.to_string());
    }
    if let Some(ext) = ARCHIVE_EXTENSIONS
        .iter()
        .find(|ext| path.ends_with(&format!(".{ext}")))
    {
        return Some((*ext).to_string());
    }
    let after_host = path.splitn(4, '/').nth(3).unwrap_or("");
    if path.contains("://codeload.github.com/") {
        for kind in ["tar.gz", "zip"] {
            if after_host.contains(&format!("/{kind}/")) {
                return Some(kind.to_string());
            }
        }
    }
    None
}

/// A go-getter address split into the source and its `//subdir`, the query kept on the source.
fn split_subdir(address: &str) -> (String, Option<&str>) {
    let scheme_end = address.find("://").map_or(0, |i| i + 3);
    let (path, query) = address.split_once('?').unwrap_or((address, ""));
    let Some(i) = path[scheme_end..].find("//") else {
        return (address.to_string(), None);
    };
    let at = scheme_end + i;
    let subdir = Some(&path[at + 2..]).filter(|sub| !sub.is_empty());
    let source = if query.is_empty() {
        path[..at].to_string()
    } else {
        format!("{}?{query}", &path[..at])
    };
    (source, subdir)
}

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
            "http://nora:4000/terraform/v1/modules/download/hashicorp/consul/aws/0.1.0/source?archive=tar.gz"
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
        // #1209: NORA cannot serve a repository as an archive (it served the repository's web
        // page); the client clones the source itself.
        assert_eq!(result, git_url, "git:: sources pass through unchanged");
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
            result, hg_url,
            "hg:: sources pass through unchanged (#1209)"
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
            "http://nora:4000/terraform/v1/modules/download/hashicorp/consul/aws/0.1.0/source?archive=tar.gz"
        );
    }

    /// #1209: what NORA answers in `X-Terraform-Get` for each kind of source the upstream names.
    /// An archive is proxied with what tells the getter it is one (`archive=`) and its
    /// subdirectory kept; a VCS source, or an HTTP address nothing marks as an archive, passes
    /// through unchanged for the client to fetch itself.
    #[test]
    fn module_source_answer_decision_table() {
        let nora = "http://nora:4000/terraform/v1/modules/download/acme/vpc/aws/1.0.0/source";
        #[rustfmt::skip]
        let rows: [(&str, Option<&str>); 14] = [
            ("https://example.com/m.tar.gz",                 Some("?archive=tar.gz")),
            ("https://example.com/m.tgz",                    Some("?archive=tgz")),
            ("https://example.com/m.zip",                    Some("?archive=zip")),
            ("https://example.com/m.tar.bz2",                Some("?archive=tar.bz2")),
            ("https://example.com/m.tar.xz",                 Some("?archive=tar.xz")),
            ("https://example.com/m.tar",                    Some("?archive=tar")),
            ("https://gitlab.example/api/v4/m/file?archive=tgz", Some("?archive=tgz")),
            ("https://codeload.github.com/a/b/zip/v1",       Some("?archive=zip")),
            ("https://example.com/m.tar.gz//modules/vpc",    Some("//modules/vpc?archive=tar.gz")),
            ("git::https://github.com/a/b?ref=v1",           None),
            ("git::https://example.com/m.tar.gz",            None),
            ("hg::https://example.com/m",                    None),
            ("https://github.com/a/b",                       None),
            ("https://example.com/m.tar.gz.sig",             None),
        ];
        for (source, answer) in rows {
            let got = rewrite_module_source_url(
                source,
                "http://nora:4000",
                "acme",
                "vpc",
                "aws",
                "1.0.0",
            );
            match answer {
                Some(suffix) => assert_eq!(got, format!("{nora}{suffix}"), "{source}"),
                None => assert_eq!(got, source, "{source}"),
            }
        }
    }

    /// #1209: only bytes that open as an archive are served or cached as a module's source.
    #[test]
    fn a_module_source_is_an_archive_by_its_bytes() {
        let mut tar = vec![0u8; 512];
        tar[257..262].copy_from_slice(b"ustar");
        #[rustfmt::skip]
        let rows: [(&[u8], bool); 8] = [
            (&[0x1f, 0x8b, 0x08, 0x00],                    true),
            (b"PK\x03\x04rest",                           true),
            (b"PK\x05\x06",                               true),
            (b"BZh91AY",                                   true),
            (&[0xfd, b'7', b'z', b'X', b'Z', 0x00, 0x00], true),
            (&tar,                                         true),
            (b"<!DOCTYPE html><html>",                     false),
            (b"",                                          false),
        ];
        for (bytes, archive) in rows {
            assert_eq!(
                looks_like_archive(bytes),
                archive,
                "{:?}",
                &bytes[..bytes.len().min(8)]
            );
        }
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

    /// A cold miss is "not found" only when the upstream said so: a module download whose
    /// upstream failed (or answered without the source header) is 502, and a mirror version
    /// whose platform metadata failed is 502 rather than a list that leaves the platform out.
    #[tokio::test]
    async fn a_cold_miss_is_404_only_when_the_upstream_said_not_found() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let versions = r#"{"versions":[{"version":"3.2.3","protocols":["5.0"],"platforms":[{"os":"linux","arch":"amd64"}]}]}"#;
        let upstream = |platform: u16| {
            let versions = versions.to_string();
            async move {
                let server = MockServer::start().await;
                Mock::given(method("GET"))
                    .and(path("/v1/providers/hashicorp/null/versions"))
                    .respond_with(ResponseTemplate::new(200).set_body_string(versions))
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .respond_with(ResponseTemplate::new(platform))
                    .mount(&server)
                    .await;
                server
            }
        };
        let down = upstream(503).await;
        let missing = upstream(404).await;
        let module = "/terraform/v1/modules/hashicorp/consul/aws/0.1.0/download";
        let mirror = "/terraform/registry.terraform.io/hashicorp/null/3.2.3.json";
        for (server, uri, want) in [
            (&down, module, StatusCode::BAD_GATEWAY),
            (&missing, module, StatusCode::NOT_FOUND),
            (&down, mirror, StatusCode::BAD_GATEWAY),
            (&missing, mirror, StatusCode::NOT_FOUND),
        ] {
            let url = server.uri();
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.terraform.enabled = true;
                cfg.terraform.proxy = Some(url);
            });
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), want, "{uri} {}", server.uri());
        }
        let asked = down.received_requests().await.unwrap();
        assert!(asked
            .iter()
            .any(|r| r.url.path().ends_with("/download/linux/amd64")));
        assert!(asked
            .iter()
            .any(|r| r.url.path().ends_with("/0.1.0/download")));
    }

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

    /// An upstream answering the module download with `X-Terraform-Get: <value>` at
    /// `/v1/modules/acme/vpc/aws/1.0.0/download`, serving `archive` at `/m.tar.gz`.
    async fn module_upstream(
        source: impl Fn(&str) -> String,
        archive: Vec<u8>,
    ) -> wiremock::MockServer {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/modules/acme/vpc/aws/1.0.0/download"))
            .respond_with(
                ResponseTemplate::new(204)
                    .insert_header("x-terraform-get", source(&server.uri()).as_str()),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/m.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(archive))
            .mount(&server)
            .await;
        server
    }

    const MODULE_DL: &str = "/terraform/v1/modules/acme/vpc/aws/1.0.0/download";
    const SOURCE_KEY: &str = "terraform/modules/acme/vpc/aws/1.0.0/source.tar.gz";

    fn tf_ctx(url: String) -> crate::test_helpers::TestContext {
        create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(url);
            cfg.terraform.proxy_timeout = 2;
        })
    }

    /// #1209: a git source is answered as the upstream named it; NORA stores no source URL for it.
    #[tokio::test]
    async fn a_git_module_source_is_passed_through() {
        let git = "git::https://github.com/acme/terraform-aws-vpc?ref=v1.0.0";
        let server = module_upstream(|_| git.to_string(), Vec::new()).await;
        let ctx = tf_ctx(server.uri());
        let resp = send(&ctx.app, Method::GET, MODULE_DL, "").await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(resp.headers().get("x-terraform-get").unwrap(), git);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(ctx
            .state
            .storage
            .get("terraform/modules/acme/vpc/aws/1.0.0/_source_url")
            .await
            .is_err());
    }

    /// #1209: an archive source is proxied with `archive=` so the getter unpacks it, and its
    /// bytes are served as the upstream sent them.
    #[tokio::test]
    async fn an_archive_module_source_is_proxied_as_an_archive() {
        let archive = vec![0x1f, 0x8b, 0x08, 0x00, 1, 2, 3];
        let server = module_upstream(|uri| format!("{uri}/m.tar.gz"), archive.clone()).await;
        let ctx = tf_ctx(server.uri());
        let resp = send(&ctx.app, Method::GET, MODULE_DL, "").await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let get = resp
            .headers()
            .get("x-terraform-get")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            get.ends_with(
                "/terraform/v1/modules/download/acme/vpc/aws/1.0.0/source?archive=tar.gz"
            ),
            "{get}"
        );
        let path = &get[get.find("/terraform/").unwrap()..];
        let mut resp = send(&ctx.app, Method::GET, path, "").await;
        for _ in 0..20 {
            if resp.status() == StatusCode::OK {
                break;
            }
            // the source URL is stored in the background
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            resp = send(&ctx.app, Method::GET, path, "").await;
        }
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await.as_ref(), archive.as_slice());
    }

    /// #1209: an archive source with a `//subdir`: the client is told the subdirectory, and NORA
    /// fetches the archive itself, without it.
    #[tokio::test]
    async fn an_archive_source_with_a_subdirectory_is_fetched_without_it() {
        let archive = vec![0x1f, 0x8b, 0x08, 0x00, 9];
        let server = module_upstream(
            |uri| format!("{uri}/m.tar.gz//modules/vpc"),
            archive.clone(),
        )
        .await;
        let ctx = tf_ctx(server.uri());
        let resp = send(&ctx.app, Method::GET, MODULE_DL, "").await;
        let get = resp
            .headers()
            .get("x-terraform-get")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            get.ends_with("/source//modules/vpc?archive=tar.gz"),
            "{get}"
        );
        // go-getter asks for the source without the subdirectory
        let path = "/terraform/v1/modules/download/acme/vpc/aws/1.0.0/source?archive=tar.gz";
        let mut resp = send(&ctx.app, Method::GET, path, "").await;
        for _ in 0..20 {
            if resp.status() == StatusCode::OK {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            resp = send(&ctx.app, Method::GET, path, "").await;
        }
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await.as_ref(), archive.as_slice());
    }

    /// #1209: what the source URL answers is served and cached only when it is an archive: a web
    /// page (a repository's) is a 502 and is not cached as the module.
    #[tokio::test]
    async fn a_source_that_is_not_an_archive_is_not_served_or_cached() {
        let server = module_upstream(
            |uri| format!("{uri}/m.tar.gz"),
            b"<!DOCTYPE html><html>".to_vec(),
        )
        .await;
        let ctx = tf_ctx(server.uri());
        let resp = send(&ctx.app, Method::GET, MODULE_DL, "").await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/download/acme/vpc/aws/1.0.0/source",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(ctx.state.storage.get(SOURCE_KEY).await.is_err());
    }

    /// #1209: a source URL an older release stored for a git source (the repository address,
    /// prefix stripped) names no archive: the module download asks the upstream again instead
    /// of pointing the client at it.
    #[tokio::test]
    async fn a_stored_source_url_that_names_no_archive_is_asked_again() {
        let git = "git::https://github.com/acme/terraform-aws-vpc?ref=v1.0.0";
        let server = module_upstream(|_| git.to_string(), Vec::new()).await;
        let ctx = tf_ctx(server.uri());
        ctx.state
            .storage
            .put(
                "terraform/modules/acme/vpc/aws/1.0.0/_source_url",
                b"https://github.com/acme/terraform-aws-vpc?ref=v1.0.0",
            )
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, MODULE_DL, "").await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(resp.headers().get("x-terraform-get").unwrap(), git);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
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

    /// A cached provider zip resumes: 206 for a satisfiable range, 416 once the
    /// client already holds the whole archive, `Accept-Ranges` on the full 200.
    #[tokio::test]
    async fn test_terraform_provider_binary_range_request() {
        use crate::test_helpers::send_with_headers;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
        });
        let zip = b"0123456789";
        ctx.state
            .storage
            .put(
                "terraform/download/hashicorp/null/3.2.1/terraform-provider-null_3.2.1_linux_amd64.zip",
                zip,
            )
            .await
            .unwrap();
        let url =
            "/terraform/v1/providers/download/hashicorp/null/3.2.1/terraform-provider-null_3.2.1_linux_amd64.zip";

        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get("content-range")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes 2-5/10"
        );
        assert_eq!(
            resp.headers()
                .get("accept-ranges")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(&body_bytes(resp).await[..], b"2345");

        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=10-")], "").await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()
                .get("content-range")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes */10"
        );

        let resp = send(&ctx.app, Method::GET, url, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("accept-ranges")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(&body_bytes(resp).await[..], zip);
    }

    /// The module source archive shares the provider binary's ranged serve.
    #[tokio::test]
    async fn test_terraform_module_source_range_request() {
        use crate::test_helpers::send_with_headers;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
        });
        ctx.state
            .storage
            .put(
                "terraform/modules/acme/vpc/aws/1.0.0/source.tar.gz",
                b"0123456789",
            )
            .await
            .unwrap();
        let url = "/terraform/v1/modules/download/acme/vpc/aws/1.0.0/source";

        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get("content-range")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes 2-5/10"
        );
        assert_eq!(&body_bytes(resp).await[..], b"2345");

        let resp = send(&ctx.app, Method::GET, url, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("accept-ranges")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
    }
}

#[cfg(test)]
mod upstream_failure_cases {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const MODULE: &str = "/terraform/v1/modules/hashicorp/consul/aws/0.1.0/download";

    fn ctx_for(url: String) -> crate::test_helpers::TestContext {
        create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(url);
        })
    }

    /// a module download that answers 2xx without `X-Terraform-Get` broke the protocol
    /// — a failed upstream, 502.
    #[tokio::test]
    async fn module_2xx_without_header_is_502() {
        for code in [200u16, 204] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(code))
                .mount(&server)
                .await;
            let ctx = ctx_for(server.uri());
            let resp = send(&ctx.app, Method::GET, MODULE, "").await;
            assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "{code}");
        }
    }

    /// a module download whose upstream is unreachable is 502.
    #[tokio::test]
    async fn module_unreachable_is_502() {
        let ctx = ctx_for("http://127.0.0.1:9".into());
        let resp = send(&ctx.app, Method::GET, MODULE, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// one platform described, another failed — 502, not a list that leaves it out.
    #[tokio::test]
    async fn mirror_one_platform_failed_is_502() {
        let versions = r#"{"versions":[{"version":"3.2.3","protocols":["5.0"],"platforms":[{"os":"linux","arch":"amd64"},{"os":"darwin","arch":"arm64"}]}]}"#;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/providers/hashicorp/null/versions"))
            .respond_with(ResponseTemplate::new(200).set_body_string(versions))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/providers/hashicorp/null/3.2.3/download/linux/amd64"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"download_url":"https://releases.example/null_3.2.3_linux_amd64.zip","shasum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#,
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let ctx = ctx_for(server.uri());
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/registry.terraform.io/hashicorp/null/3.2.3.json",
            "",
        )
        .await;
        let status = resp.status();
        let body = body_bytes(resp).await;
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "{}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[cfg(test)]
mod upstream_failure_edge_cases {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const MODULE: &str = "/terraform/v1/modules/hashicorp/consul/aws/0.1.0/download";
    const MIRROR: &str = "/terraform/registry.terraform.io/hashicorp/null/3.2.3.json";
    const OK_META: &str = r#"{"download_url":"https://releases.example/null.zip","shasum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#;

    fn ctx_for(url: String) -> crate::test_helpers::TestContext {
        create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy_timeout = 1;
            cfg.terraform.proxy = Some(url);
        })
    }

    /// A module download that times out is a failed upstream — 502.
    #[tokio::test]
    async fn module_timeout_is_502() {
        let slow = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_secs(5)))
            .mount(&slow)
            .await;
        let ctx = ctx_for(slow.uri());
        let resp = send(&ctx.app, Method::GET, MODULE, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// #1202: the module download reports to the `terraform` breaker like every other path. An
    /// open breaker answers 503 with Retry-After without asking the upstream.
    #[tokio::test]
    async fn module_download_behind_an_open_breaker_is_503_and_not_asked() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(204)
                    .insert_header("x-terraform-get", "https://example.invalid/m.tar.gz"),
            )
            .expect(0)
            .mount(&upstream)
            .await;
        let url = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy_timeout = 1;
            cfg.terraform.proxy = Some(url);
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.reset_timeout = 3600;
        });
        ctx.state.circuit_breaker.open_for_test("terraform");
        let resp = send(&ctx.app, Method::GET, MODULE, "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers().get("retry-after").map(|v| v.as_bytes()),
            Some(b"30".as_slice())
        );
    }

    /// #1202: a failed module download counts toward the breaker, so a dead upstream found by
    /// module downloads alone opens it for the other Terraform paths too.
    #[tokio::test]
    async fn a_failed_module_download_opens_the_breaker() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy_timeout = 1;
            cfg.terraform.proxy = Some("http://127.0.0.1:9".into());
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 1;
            cfg.circuit_breaker.reset_timeout = 3600;
        });
        let resp = send(&ctx.app, Method::GET, MODULE, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert!(ctx.state.circuit_breaker.check("terraform").is_err());
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/providers/hashicorp/null/versions",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A module upstream answering 400 said "not here" — 404.
    #[tokio::test]
    async fn module_400_is_404() {
        let bad = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&bad)
            .await;
        let ctx = ctx_for(bad.uri());
        let resp = send(&ctx.app, Method::GET, MODULE, "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A failed platform listed BEFORE a 4xx platform and a described one —
    /// still 502; a later 4xx must not erase the earlier failure.
    #[tokio::test]
    async fn mirror_failed_platform_before_a_4xx_one_is_502() {
        let versions = r#"{"versions":[{"version":"3.2.3","protocols":["5.0"],"platforms":[{"os":"linux","arch":"amd64"},{"os":"linux","arch":"arm"},{"os":"darwin","arch":"arm64"}]}]}"#;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/providers/hashicorp/null/versions"))
            .respond_with(ResponseTemplate::new(200).set_body_string(versions))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/v1/providers/hashicorp/null/3.2.3/download/linux/amd64",
            ))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/v1/providers/hashicorp/null/3.2.3/download/linux/arm",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/v1/providers/hashicorp/null/3.2.3/download/darwin/arm64",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(OK_META))
            .mount(&server)
            .await;
        let ctx = ctx_for(server.uri());
        let resp = send(&ctx.app, Method::GET, MIRROR, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// `versions.json` is cached and fresh, the upstream is now
    /// unreachable — every platform failed with a network error, which is 502, not a
    /// 404 "no platforms".
    #[tokio::test]
    async fn mirror_platform_unreachable_is_502() {
        let versions = r#"{"versions":[{"version":"3.2.3","protocols":["5.0"],"platforms":[{"os":"linux","arch":"amd64"}]}]}"#;
        let ctx = ctx_for("http://127.0.0.1:9".into());
        ctx.state
            .storage
            .put(
                "terraform/providers/hashicorp/null/versions.json",
                versions.as_bytes(),
            )
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, MIRROR, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// `versions.json` is cached and the breaker is open: the platform was not described, which
    /// is 502, not a list that leaves it out.
    #[tokio::test]
    async fn mirror_platform_behind_an_open_breaker_is_502() {
        let versions = r#"{"versions":[{"version":"3.2.3","protocols":["5.0"],"platforms":[{"os":"linux","arch":"amd64"}]}]}"#;
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:9".into());
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.reset_timeout = 3600;
        });
        ctx.state
            .storage
            .put(
                "terraform/providers/hashicorp/null/versions.json",
                versions.as_bytes(),
            )
            .await
            .unwrap();
        ctx.state.circuit_breaker.open_for_test("terraform");
        let resp = send(&ctx.app, Method::GET, MIRROR, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// The platform metadata times out — 502.
    #[tokio::test]
    async fn mirror_platform_timeout_is_502() {
        let versions = r#"{"versions":[{"version":"3.2.3","protocols":["5.0"],"platforms":[{"os":"linux","arch":"amd64"}]}]}"#;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/providers/hashicorp/null/versions"))
            .respond_with(ResponseTemplate::new(200).set_body_string(versions))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(OK_META)
                    .set_delay(Duration::from_secs(5)),
            )
            .mount(&server)
            .await;
        let ctx = ctx_for(server.uri());
        let resp = send(&ctx.app, Method::GET, MIRROR, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}

/// Terraform names compare as the registry resolves them: Terraform lowercases provider
/// namespaces and types (terraform-registry-address `ParseProviderPart`), and registry.terraform.io
/// answers provider and module paths in any case. So an internal namespace or a rule holds for a
/// request in any case — a module source written `Acme/vpc/aws` is still `acme/**`.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod terraform_names_in_any_case {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn upstream_paths(upstream: &MockServer) -> Vec<String> {
        upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    #[tokio::test]
    async fn an_internal_namespace_isolates_every_case() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"versions": []})),
            )
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.internal_namespaces = vec!["acme/**".to_string()];
        });
        for path in [
            "/terraform/v1/providers/Acme/infra/versions",
            "/terraform/v1/providers/ACME/infra/1.0.0/download/linux/amd64",
            "/terraform/v1/modules/Acme/vpc/aws/versions",
            "/terraform/v1/modules/Acme/vpc/aws/1.0.0/download",
        ] {
            let _ = send(&ctx.app, Method::GET, path, "").await;
        }
        let asked = upstream_paths(&upstream).await;
        assert!(asked.is_empty(), "internal names sent upstream: {asked:?}");
        // Control: the same paths for a public namespace reach the upstream.
        let _ = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/providers/Public/infra/versions",
            "",
        )
        .await;
        let _ = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/Public/vpc/aws/versions",
            "",
        )
        .await;
        assert_eq!(
            upstream_paths(&upstream).await.len(),
            2,
            "public twins reach the upstream"
        );
    }

    // A module download is the module itself: an internal one never reaches the upstream,
    // whatever its case, and the archive is not fetched from a source URL either.
    #[tokio::test]
    async fn an_internal_module_download_never_reaches_upstream() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(204)
                    .insert_header("x-terraform-get", "https://example.invalid/acme-vpc.tar.gz"),
            )
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri.clone());
            cfg.curation.internal_namespaces = vec!["acme/**".to_string()];
        });
        // A source URL left from before the namespace was internal.
        ctx.state
            .storage
            .put(
                "terraform/modules/acme/vpc/aws/1.0.0/_source_url",
                format!("{}/archive.tar.gz", upstream.uri()).as_bytes(),
            )
            .await
            .unwrap();
        for path in [
            "/terraform/v1/modules/acme/vpc/aws/2.0.0/download",
            "/terraform/v1/modules/download/acme/vpc/aws/1.0.0/source",
        ] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert!(!resp.status().is_success(), "{path}: {}", resp.status());
        }
        let asked = upstream_paths(&upstream).await;
        assert!(asked.is_empty(), "internal module sent upstream: {asked:?}");
    }

    // A blocklist rule on a module holds for its download and its archive.
    #[tokio::test]
    async fn a_blocked_module_is_refused() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(204)
                    .insert_header("x-terraform-get", "https://example.invalid/evil.tar.gz"),
            )
            .mount(&upstream)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "terraform", "name": "evilcorp/backdoor/aws", "version": "*", "reason": "r"}]}"#,
        )
        .unwrap();
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
        });
        ctx.state
            .storage
            .put(
                "terraform/modules/evilcorp/backdoor/aws/1.0.0/source.tar.gz",
                b"TGZ",
            )
            .await
            .unwrap();
        for path in [
            "/terraform/v1/modules/evilcorp/backdoor/aws/1.0.0/download",
            "/terraform/v1/modules/download/evilcorp/backdoor/aws/1.0.0/source",
        ] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        }
    }

    #[tokio::test]
    async fn a_rule_holds_for_every_case() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&upstream)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "terraform", "name": "HashiCorp/AWS", "version": "*", "reason": "r"}]}"#,
        )
        .unwrap();
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/providers/hashicorp/aws/5.0.0/download/linux/amd64",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}

/// A module's name and version reach curation whole, in lowercase only, and an internal module
/// is answered from its cache.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod terraform_module_identity_and_cache {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(204)
                    .insert_header("x-terraform-get", "https://example.invalid/m.tar.gz"),
            )
            .mount(&upstream)
            .await;
        upstream
    }

    fn list(dir: &tempfile::TempDir, file: &str, body: &str) -> String {
        let path = dir.path().join(file);
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    // P1 (m2): the module system compares without case like the namespace and the name.
    #[tokio::test]
    async fn a_module_rule_holds_for_every_case_of_every_segment() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = list(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [{"registry": "terraform", "name": "EvilCorp/Backdoor/AWS", "version": "*", "reason": "r"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/evilcorp/backdoor/aws/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // P2 (m3): `my-vpc` and `my_vpc` are two modules; an allowlist entry admits only its own.
    #[tokio::test]
    async fn an_allowlist_entry_admits_only_its_own_module() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = list(
            &dir,
            "allowlist.json",
            r#"{"version": 1, "entries": [{"registry": "terraform", "name": "acme/my-vpc/aws", "version": "1.0.0"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        let other = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/acme/my_vpc/aws/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(other.status(), StatusCode::FORBIDDEN, "a module not listed");
        let listed = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/ACME/My-VPC/aws/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(listed.status(), StatusCode::NO_CONTENT, "the listed module");
    }

    // P3 (m8): curation sees the module's version — a rule on 1.0.0 refuses 1.0.0 and only it.
    #[tokio::test]
    async fn a_version_rule_holds_for_the_download_and_the_archive() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = list(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [{"registry": "terraform", "name": "evilcorp/backdoor/aws", "version": "1.0.0", "reason": "r"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        ctx.state
            .storage
            .put(
                "terraform/modules/evilcorp/backdoor/aws/1.0.0/source.tar.gz",
                b"TGZ",
            )
            .await
            .unwrap();
        for path in [
            "/terraform/v1/modules/evilcorp/backdoor/aws/1.0.0/download",
            "/terraform/v1/modules/download/evilcorp/backdoor/aws/1.0.0/source",
        ] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        }
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/evilcorp/backdoor/aws/2.0.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "another version");
    }

    // P4 (m7, m7b, m12): an internal module is answered from its cache — the saved source URL
    // and the saved archive — with nothing sent upstream; the pattern names the module whole.
    #[tokio::test]
    async fn an_internal_module_is_served_from_its_cache() {
        let upstream = upstream().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.internal_namespaces = vec!["acme/vpc/aws".to_string()];
        });
        let base = "terraform/modules/acme/vpc/aws/1.0.0";
        ctx.state
            .storage
            .put(
                &format!("{base}/_source_url"),
                b"https://example.invalid/acme-vpc.tar.gz",
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(&format!("{base}/source.tar.gz"), b"TGZ")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/acme/vpc/aws/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "download");
        let get = resp.headers()["x-terraform-get"]
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            get.contains("/terraform/v1/modules/download/acme/vpc/aws/1.0.0/source"),
            "{get}"
        );
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/download/acme/vpc/aws/1.0.0/source",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "archive");
        assert_eq!(&body_bytes(resp).await[..], b"TGZ");
        let asked = upstream.received_requests().await.unwrap();
        assert!(asked.is_empty(), "internal module sent upstream: {asked:?}");
    }
}

/// A provider's files (binary, checksums, signature) pass the curation its download metadata
/// passes, since a client can ask for them directly, and an internal provider's files are served
/// only from the cache.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod provider_files_under_curation_and_isolation {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::Method;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Same scenario the diff closed for modules: metadata cached before the namespace became
    // internal still names an upstream URL; the binary download must not follow it.
    #[tokio::test]
    async fn an_internal_provider_binary_never_reaches_upstream() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ZIP".to_vec()))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.internal_namespaces = vec!["acme/**".to_string()];
        });
        ctx.state
            .storage
            .put(
                "terraform/providers/acme/infra/1.0.0/linux_amd64.json",
                serde_json::json!({"_nora_upstream_url": format!("{}/infra.zip", upstream.uri())})
                    .to_string()
                    .as_bytes(),
            )
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/providers/download/acme/infra/1.0.0/terraform-provider-infra_1.0.0_linux_amd64.zip",
            "",
        )
        .await;
        let asked = upstream.received_requests().await.unwrap();
        assert!(
            asked.is_empty(),
            "internal provider binary fetched upstream ({}): {:?}",
            resp.status(),
            asked
                .iter()
                .map(|r| r.url.path().to_string())
                .collect::<Vec<_>>()
        );
    }

    const BINARY: &str = "/terraform/v1/providers/download/acme/infra/1.0.0/terraform-provider-infra_1.0.0_linux_amd64.zip";

    // With no metadata cached either, an internal provider's file is an isolation refusal, not
    // a guess at a public download URL.
    #[tokio::test]
    async fn an_internal_provider_without_metadata_is_refused() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:9".to_string());
            cfg.curation.internal_namespaces = vec!["acme/**".to_string()];
        });
        let resp = send(&ctx.app, Method::GET, BINARY, "").await;
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
    }

    // An internal provider's cached file is served.
    #[tokio::test]
    async fn an_internal_provider_is_served_from_its_cache() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:9".to_string());
            cfg.curation.internal_namespaces = vec!["acme/**".to_string()];
        });
        ctx.state
            .storage
            .put(
                "terraform/download/acme/infra/1.0.0/terraform-provider-infra_1.0.0_linux_amd64.zip",
                b"ZIP",
            )
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, BINARY, "").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    // A blocked provider version is refused on its files too, cached or not; another version is
    // served.
    #[tokio::test]
    async fn a_blocked_provider_version_is_refused_on_its_files() {
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "terraform", "name": "hashicorp/null", "version": "3.2.3", "reason": "bad"}]}"#,
        )
        .unwrap();
        let blocklist = blocklist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:9".to_string());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        for ver in ["3.2.3", "3.2.4"] {
            for file in [
                format!("terraform-provider-null_{ver}_linux_amd64.zip"),
                format!("terraform-provider-null_{ver}_SHA256SUMS"),
            ] {
                ctx.state
                    .storage
                    .put(
                        &format!("terraform/download/hashicorp/null/{ver}/{file}"),
                        b"F",
                    )
                    .await
                    .unwrap();
            }
        }
        for (ver, expected) in [
            ("3.2.3", axum::http::StatusCode::FORBIDDEN),
            ("3.2.4", axum::http::StatusCode::OK),
        ] {
            for file in [
                format!("terraform-provider-null_{ver}_linux_amd64.zip"),
                format!("terraform-provider-null_{ver}_SHA256SUMS"),
            ] {
                let url = format!("/terraform/v1/providers/download/hashicorp/null/{ver}/{file}");
                let resp = send(&ctx.app, Method::GET, &url, "").await;
                assert_eq!(resp.status(), expected, "{url}");
            }
        }
    }
}

/// An internal module refused for want of a cache is refused as an isolation refusal, and counted.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod internal_module_refusal_counted {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn an_internal_module_refusal_is_counted() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:9".to_string());
            cfg.curation.internal_namespaces = vec!["acme/**".to_string()];
        });
        let refused = || {
            crate::metrics::NAMESPACE_ISOLATION_REFUSED_TOTAL
                .with_label_values(&["terraform"])
                .get()
        };
        let before = refused();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/acme/metric/aws/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(refused() > before, "isolation refusal not counted");
    }
}

/// Every Terraform path in one order: curation before any cached copy; an internal name, in any
/// case and named whole, served from its cache and never fetched — files and archives too; every
/// isolation refusal counted.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod terraform_every_path_one_order {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn recording() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-terraform-get", "https://example.invalid/m.tar.gz")
                    .set_body_bytes(b"UPSTREAM".to_vec()),
            )
            .mount(&upstream)
            .await;
        upstream
    }

    async fn asked(upstream: &MockServer) -> Vec<String> {
        upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    fn blocklist(dir: &tempfile::TempDir, name: &str, version: &str) -> String {
        let path = dir.path().join("blocklist.json");
        std::fs::write(
            &path,
            format!(
                r#"{{"version": 1, "rules": [{{"registry": "terraform", "name": "{name}", "version": "{version}", "reason": "r"}}]}}"#
            ),
        )
        .unwrap();
        path.to_string_lossy().into_owned()
    }

    /// Provider metadata cached before the namespace became internal, naming upstream URLs for
    /// the archive, the checksums and their signature.
    async fn seed_provider_meta(
        ctx: &crate::test_helpers::TestContext,
        ns: &str,
        ptype: &str,
        uri: &str,
    ) {
        ctx.state
            .storage
            .put(
                &format!("terraform/providers/{ns}/{ptype}/1.0.0/linux_amd64.json"),
                serde_json::json!({
                    "_nora_upstream_url": format!("{uri}/infra.zip"),
                    "_nora_upstream_shasums_url": format!("{uri}/SHA256SUMS"),
                    "_nora_upstream_shasums_sig_url": format!("{uri}/SHA256SUMS.sig"),
                })
                .to_string()
                .as_bytes(),
            )
            .await
            .unwrap();
    }

    // t1 (inv. 2): a blocked module is refused on its download even when its source URL is
    // cached from before the rule.
    #[tokio::test]
    async fn a_blocked_module_with_a_cached_source_url_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let list = blocklist(&dir, "evilcorp/backdoor/aws", "*");
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:9".to_string());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(list);
        });
        ctx.state
            .storage
            .put(
                "terraform/modules/evilcorp/backdoor/aws/1.0.0/_source_url",
                b"https://example.invalid/evil.tar.gz",
            )
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/EvilCorp/backdoor/aws/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "mixed case");
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/evilcorp/backdoor/aws/1.0.0/download",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "cached source URL");
    }

    // t2 (inv. 4): the download metadata a provider's files are curated like is curated with a
    // fresh cache too.
    #[tokio::test]
    async fn a_blocked_provider_version_is_refused_on_cached_download_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let list = blocklist(&dir, "hashicorp/null", "3.2.3");
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:9".to_string());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(list);
        });
        for ver in ["3.2.3", "3.2.4"] {
            ctx.state
                .storage
                .put(
                    &format!("terraform/providers/hashicorp/null/{ver}/linux_amd64.json"),
                    br#"{"download_url": "x", "shasum": "00"}"#,
                )
                .await
                .unwrap();
        }
        for (ver, expected) in [("3.2.3", StatusCode::FORBIDDEN), ("3.2.4", StatusCode::OK)] {
            let url = format!("/terraform/v1/providers/hashicorp/null/{ver}/download/linux/amd64");
            let resp = send(&ctx.app, Method::GET, &url, "").await;
            assert_eq!(resp.status(), expected, "{url}");
        }
    }

    // t3 (inv. 4): an internal provider's checksums and signature never reach the upstream,
    // whatever URL cached metadata names for them.
    #[tokio::test]
    async fn an_internal_provider_checksums_and_signature_never_reach_upstream() {
        let upstream = recording().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.internal_namespaces = vec!["acme/**".to_string()];
        });
        seed_provider_meta(&ctx, "acme", "infra", &upstream.uri()).await;
        for file in [
            "terraform-provider-infra_1.0.0_SHA256SUMS",
            "terraform-provider-infra_1.0.0_SHA256SUMS.sig",
        ] {
            let url = format!("/terraform/v1/providers/download/acme/infra/1.0.0/{file}");
            let resp = send(&ctx.app, Method::GET, &url, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{url}");
        }
        let sent = asked(&upstream).await;
        assert!(
            sent.is_empty(),
            "internal provider files sent upstream: {sent:?}"
        );
    }

    // t4 (inv. 1, 4): an internal namespace pattern naming the provider itself isolates its
    // files.
    #[tokio::test]
    async fn an_internal_provider_named_whole_is_isolated_and_served_from_its_cache() {
        let upstream = recording().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.internal_namespaces = vec!["acme/infra".to_string()];
        });
        seed_provider_meta(&ctx, "acme", "infra", &upstream.uri()).await;
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/providers/download/acme/infra/1.0.0/terraform-provider-infra_1.0.0_linux_amd64.zip",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let sent = asked(&upstream).await;
        assert!(
            sent.is_empty(),
            "internal provider binary sent upstream: {sent:?}"
        );
        // Its own cached file is served: the pattern makes it internal, not merely refused.
        ctx.state.storage.put("terraform/download/acme/infra/2.0.0/terraform-provider-infra_2.0.0_linux_amd64.zip", b"OWN").await.unwrap();
        let resp = send(&ctx.app, Method::GET, "/terraform/v1/providers/download/acme/infra/2.0.0/terraform-provider-infra_2.0.0_linux_amd64.zip", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "cached internal provider file"
        );
    }

    // t5 (inv. 1, 4): an internal provider's files are isolated in any case.
    #[tokio::test]
    async fn an_internal_provider_in_any_case_is_isolated_and_served_from_its_cache() {
        let upstream = recording().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.internal_namespaces = vec!["acme/**".to_string()];
        });
        seed_provider_meta(&ctx, "Acme", "INFRA", &upstream.uri()).await;
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/providers/download/Acme/INFRA/1.0.0/terraform-provider-infra_1.0.0_linux_amd64.zip",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let sent = asked(&upstream).await;
        assert!(
            sent.is_empty(),
            "internal provider binary sent upstream: {sent:?}"
        );
        // Its own cached file is served: the pattern makes it internal, not merely refused.
        ctx.state.storage.put("terraform/download/Acme/INFRA/2.0.0/terraform-provider-infra_2.0.0_linux_amd64.zip", b"OWN").await.unwrap();
        let resp = send(&ctx.app, Method::GET, "/terraform/v1/providers/download/Acme/INFRA/2.0.0/terraform-provider-infra_2.0.0_linux_amd64.zip", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "cached internal provider file, mixed case"
        );
    }

    // t6 (inv. 1, 3): an internal module's archive is isolated in any case.
    #[tokio::test]
    async fn an_internal_module_archive_in_any_case_is_isolated_and_served_from_its_cache() {
        let upstream = recording().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.internal_namespaces = vec!["acme/**".to_string()];
        });
        ctx.state
            .storage
            .put(
                "terraform/modules/Acme/VPC/aws/1.0.0/_source_url",
                format!("{}/acme-vpc.tar.gz", upstream.uri()).as_bytes(),
            )
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/download/Acme/VPC/aws/1.0.0/source",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let sent = asked(&upstream).await;
        assert!(
            sent.is_empty(),
            "internal module archive sent upstream: {sent:?}"
        );
        // Its own cached file is served: the pattern makes it internal, not merely refused.
        ctx.state
            .storage
            .put("terraform/modules/Acme/VPC/aws/2.0.0/source.tar.gz", b"OWN")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/v1/modules/download/Acme/VPC/aws/2.0.0/source",
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "cached internal module archive, mixed case"
        );
    }

    // t7 (inv. 3): an internal module's archive refused for want of a cache is counted as an
    // isolation refusal. Many refusals, so parallel tests cannot make up the count.
    #[tokio::test]
    async fn an_internal_module_archive_refusal_is_counted() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://127.0.0.1:9".to_string());
            cfg.curation.internal_namespaces = vec!["acme/**".to_string()];
        });
        let refused = || {
            crate::metrics::NAMESPACE_ISOLATION_REFUSED_TOTAL
                .with_label_values(&["terraform"])
                .get()
        };
        let before = refused();
        const N: u64 = 64;
        for _ in 0..N {
            let resp = send(
                &ctx.app,
                Method::GET,
                "/terraform/v1/modules/download/acme/counted/aws/1.0.0/source",
                "",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
        assert!(
            refused() - before >= N,
            "archive isolation refusals not counted"
        );
    }

    // t11 (inv. 1): an internal namespace pattern naming the module whole isolates its version
    // list, in any case.
    #[tokio::test]
    async fn an_internal_module_named_whole_isolates_its_versions() {
        let upstream = recording().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.internal_namespaces = vec!["acme/vpc/aws".to_string()];
        });
        for path in [
            "/terraform/v1/modules/acme/vpc/aws/versions",
            "/terraform/v1/modules/ACME/Vpc/AWS/versions",
        ] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        }
        let sent = asked(&upstream).await;
        assert!(
            sent.is_empty(),
            "internal module versions sent upstream: {sent:?}"
        );
    }
}

/// A mirror `{version}.json` for an internal provider whose version list is cached does not ask
/// upstream for its platforms' download metadata.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod internal_mirror_version_stays_local {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::Method;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn an_internal_mirror_version_never_reaches_upstream() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "download_url": "https://example.invalid/infra.zip", "shasum": "00"
            })))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(uri);
            cfg.curation.internal_namespaces = vec!["acme/**".to_string()];
        });
        // The operator's own version list, published or cached; no platform metadata yet.
        ctx.state
            .storage
            .put(
                "terraform/providers/acme/infra/versions.json",
                serde_json::json!({"versions": [{"version": "1.0.0",
                    "platforms": [{"os": "linux", "arch": "amd64"}]}]})
                .to_string()
                .as_bytes(),
            )
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/terraform/registry.terraform.io/acme/infra/1.0.0.json",
            "",
        )
        .await;
        let asked: Vec<String> = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert!(
            asked.is_empty(),
            "internal provider metadata sent upstream ({}): {asked:?}",
            resp.status()
        );
    }
}

/// Every Terraform handler decides through `tf_decide` before it serves or fetches anything, the
/// decision's names come only from `provider_identity` and `module_identity`, and curation and
/// isolation are asked nowhere else: a white list over this file's production code. Its own
/// controls show the reader catches a handler that serves first, a second decision site and an
/// identity built by hand.
#[cfg(test)]
mod terraform_decides_once {
    use crate::test_helpers::source_reader::{body, holders, production};

    const HANDLERS: [&str; 8] = [
        "provider_versions",
        "provider_download_meta",
        "provider_download_binary",
        "module_versions",
        "module_download",
        "module_source_download",
        "mirror_provider_index",
        "mirror_provider_version",
    ];
    const SERVES_OR_FETCHES: [&str; 11] = [
        "with_json(",
        "with_binary(",
        "NO_CONTENT",
        "proxy_fetch",
        "resolve_upstream_download_url(",
        "mirror_fetch_versions(",
        "mirror_fetch_archive(",
        "range_binary(",
        "serve_stale_or_bad_gateway(",
        ".send()",
        "storage.get_verified(",
    ];

    fn violations(source: &str) -> Vec<String> {
        let code = production(source);
        let mut wrong = Vec::new();
        for (needle, allowed) in [
            (
                "is_internal_namespace(",
                &["extract_terraform_publish_date", "tf_decide"][..],
            ),
            ("check_download(", &["tf_decide"][..]),
            ("check_namespace_isolation(", &["tf_isolation_refusal"][..]),
            ("tf_decide(", &HANDLERS[..]),
        ] {
            for holder in holders(code, needle) {
                if !allowed.contains(&holder.as_str()) {
                    wrong.push(format!("{needle} in {holder}"));
                }
            }
        }
        for handler in HANDLERS {
            let Some(body) = body(code, handler) else {
                wrong.push(format!("{handler}: not found"));
                continue;
            };
            let Some(decide) = body.find("tf_decide(") else {
                wrong.push(format!("{handler}: no decision"));
                continue;
            };
            if let Some(first) = SERVES_OR_FETCHES
                .iter()
                .filter_map(|token| body.find(token).map(|at| (at, token)))
                .min()
            {
                if first.0 < decide {
                    wrong.push(format!("{handler}: {} before the decision", first.1));
                }
            }
            let call = &body[decide..];
            let identity = call[..call.find(';').unwrap_or(call.len())].to_string();
            if !(identity.contains("&provider") || identity.contains("&module")) {
                wrong.push(format!("{handler}: decides on {identity}"));
            }
            for (variable, builder) in [
                ("let provider = ", "provider_identity("),
                ("let module = ", "module_identity("),
            ] {
                if let Some(at) = body.find(variable) {
                    if !body[at + variable.len()..].starts_with(builder) {
                        wrong.push(format!("{handler}: {variable}not from {builder}"));
                    }
                }
            }
        }
        wrong
    }

    #[test]
    fn every_handler_decides_once_before_serving() {
        let wrong = violations(include_str!("terraform.rs"));
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    #[test]
    fn the_white_list_catches_a_handler_that_serves_first() {
        let source = include_str!("terraform.rs");
        let serves_first = source.replacen(
            "    let provider = provider_identity(&ns, &ptype);\n    let internal = match tf_decide(&state, &HeaderMap::new(), &provider, None, None) {",
            "    let _early = with_json(Vec::new());\n    let provider = provider_identity(&ns, &ptype);\n    let internal = match tf_decide(&state, &HeaderMap::new(), &provider, None, None) {",
            1,
        );
        assert_ne!(serves_first, source);
        assert!(!violations(&serves_first).is_empty());
        let second_site = source.replacen(
            "fn tf_isolation_refusal(",
            "fn tf_second(state: &AppState) { let _ = crate::curation::check_download(state); }\nfn tf_isolation_refusal(",
            1,
        );
        assert!(violations(&second_site)
            .iter()
            .any(|v| v.contains("check_download")));
        let by_hand = source.replacen(
            "    let provider = provider_identity(ns, ptype);",
            "    let provider = format!(\"{}\", ns);",
            1,
        );
        assert_ne!(by_hand, source);
        assert!(!violations(&by_hand).is_empty());
    }
}

/// The decision as a table: an internal name in any case and pattern form, a curation refusal
/// for an artifact's version only (a version list is not refused), every other name proxied.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tf_decide_table {
    use super::{module_identity, provider_identity, tf_decide};
    use crate::test_helpers::create_test_context_with_config;
    use axum::http::HeaderMap;

    #[test]
    fn every_name_is_decided_as_the_table_says() {
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [
                {"registry": "terraform", "name": "evilcorp/backdoor", "version": "1.0.0", "reason": "r"},
                {"registry": "terraform", "name": "evilcorp/vpc/aws", "version": "*", "reason": "r"}
            ]}"#,
        )
        .unwrap();
        let blocklist = blocklist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.terraform.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
            cfg.curation.internal_namespaces = vec![
                "acme/**".to_string(),
                "corp/infra".to_string(),
                "corp/vpc/aws".to_string(),
            ];
        });
        let cases = [
            (
                provider_identity("acme", "infra"),
                Some("1.0.0"),
                "internal",
            ),
            (
                provider_identity("Acme", "INFRA"),
                Some("1.0.0"),
                "internal",
            ),
            (module_identity("acme", "vpc", "aws"), None, "internal"),
            (provider_identity("corp", "infra"), None, "internal"),
            (
                provider_identity("Corp", "Infra"),
                Some("2.0.0"),
                "internal",
            ),
            (
                module_identity("corp", "vpc", "aws"),
                Some("1.0.0"),
                "internal",
            ),
            (module_identity("CORP", "VPC", "AWS"), None, "internal"),
            (provider_identity("corp", "other"), Some("1.0.0"), "proxy"),
            (
                module_identity("corp", "vpc", "gcp"),
                Some("1.0.0"),
                "proxy",
            ),
            (provider_identity("acmecorp", "x"), Some("1.0.0"), "proxy"),
            (
                provider_identity("evilcorp", "backdoor"),
                Some("1.0.0"),
                "refused",
            ),
            (
                provider_identity("EvilCorp", "Backdoor"),
                Some("1.0.0"),
                "refused",
            ),
            (
                provider_identity("evilcorp", "backdoor"),
                Some("2.0.0"),
                "proxy",
            ),
            (provider_identity("evilcorp", "backdoor"), None, "proxy"),
            (
                module_identity("evilcorp", "vpc", "aws"),
                Some("3.1.0"),
                "refused",
            ),
            (module_identity("evilcorp", "vpc", "aws"), None, "proxy"),
        ];
        for (identity, version, expected) in cases {
            let got = match tf_decide(&ctx.state, &HeaderMap::new(), &identity, version, None) {
                Ok(true) => "internal",
                Ok(false) => "proxy",
                Err(_) => "refused",
            };
            assert_eq!(got, expected, "{identity} {version:?}");
        }
    }
}

/// The decision is given the version's publish date: a version younger than the minimum release
/// age is refused on its download metadata and its files, one old enough is served (hosted mode:
/// the date is when its metadata was stored).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod terraform_release_age_decided {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    fn age(root: &std::path::Path, needle: &str, days: u64) {
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
        let mut dirs = vec![root.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.to_string_lossy().contains(needle) {
                    std::fs::File::options()
                        .write(true)
                        .open(&path)
                        .unwrap()
                        .set_modified(old)
                        .unwrap();
                }
            }
        }
    }

    #[tokio::test]
    async fn a_version_younger_than_the_minimum_age_is_refused() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = None;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
        });
        for ver in ["1.0.0", "2.0.0"] {
            ctx.state
                .storage
                .put(
                    &format!("terraform/providers/hashicorp/null/{ver}/linux_amd64.json"),
                    br#"{"download_url": "x"}"#,
                )
                .await
                .unwrap();
            ctx.state
                .storage
                .put(
                    &format!("terraform/download/hashicorp/null/{ver}/terraform-provider-null_{ver}_linux_amd64.zip"),
                    b"ZIP",
                )
                .await
                .unwrap();
        }
        age(ctx._tempdir.path(), "null/1.0.0/linux_amd64.json", 30);
        for (ver, expected) in [("1.0.0", StatusCode::OK), ("2.0.0", StatusCode::FORBIDDEN)] {
            for url in [
                format!("/terraform/v1/providers/hashicorp/null/{ver}/download/linux/amd64"),
                format!("/terraform/v1/providers/download/hashicorp/null/{ver}/terraform-provider-null_{ver}_linux_amd64.zip"),
            ] {
                let resp = send(&ctx.app, Method::GET, &url, "").await;
                assert_eq!(resp.status(), expected, "{url}");
            }
        }
    }
}
