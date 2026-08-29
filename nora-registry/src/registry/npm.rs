// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, AuthenticatedUser, NamespaceAuthority};
use crate::metrics::METADATA_CORRUPT_TOTAL;
use crate::registry::{
    circuit_open_response, method_not_allowed, nora_base_url, proxy_fetch, proxy_fetch_conditional,
    proxy_forward_post, read_validators, validators_key, write_validators, ProxyError,
    Revalidation, Validators,
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
    Extension, Router,
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
            .post(handle_npm_post)
            .fallback(|| async { method_not_allowed("GET, PUT, POST") }),
    )
}

/// Max body accepted on the `npm audit` POST. Real audit payloads are well under
/// 1 MB; the global `body_limit_mb` (default 2 GB, for tarball PUTs) must not let a
/// client shove a huge body through NORA into the upstream (#597 SEC).
const NPM_AUDIT_BODY_CAP: usize = 8 * 1024 * 1024;

/// `npm audit` proxy (#597). npm sends its audit request as a POST — npm7 to
/// `/-/npm/v1/security/advisories/bulk` (body `{"<pkg>":["<ver>",…]}`), npm6 to
/// `/-/npm/v1/security/audits/quick` (body = a possibly-gzipped lockfile).
///
/// NORA keeps no advisory DB, so for a remote/proxy repo it forwards the request to
/// the configured upstream and returns the response verbatim. Any other POST path
/// is a 405. Dependency-confusion guard (#68/#733): internal-namespace package
/// names must not leak upstream — see `strip_internal_bulk` / the quick refuse.
async fn handle_npm_post(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    let is_bulk = path == "-/npm/v1/security/advisories/bulk";
    let is_quick = path == "-/npm/v1/security/audits/quick";
    if !is_bulk && !is_quick {
        // POST is only meaningful on the audit endpoints.
        return method_not_allowed("GET, PUT");
    }

    // Bound the body AT READ TIME. The global DefaultBodyLimit is 2 GB (for tarball
    // PUTs); audit bodies are <1 MB. `to_bytes` aborts collection past the cap, so a
    // chunked / no-Content-Length client cannot force NORA to buffer gigabytes (#597).
    let body = match axum::body::to_bytes(body, NPM_AUDIT_BODY_CAP).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    // Only a remote/proxy repo can answer audits (advisories come from upstream).
    // Hosted-only (no proxy) → npm-compatible empty result so `npm audit` doesn't
    // hard-fail — npm treats a 200 `{}` as "no advisories".
    let Some(proxy_url) = state.config.npm.proxy.clone() else {
        return npm_empty_audit();
    };

    // #68/#733 dependency-confusion: never send internal package names upstream.
    // When a namespace filter is configured we must SEE plaintext names to strip
    // them, so ANY body we cannot verify — the quick lockfile, an encoded bulk body,
    // or a bulk body that is not the expected JSON object — is refused (fail CLOSED,
    // symmetric across both paths). With no filter, nothing is internal → forward
    // verbatim.
    let engine = &state.curation().curation_engine;
    let filter_active = crate::curation::namespace_filter_active(engine);
    let content_encoded = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| !s.eq_ignore_ascii_case("identity"));
    let forward_body: Vec<u8> = if !filter_active {
        body.to_vec()
    } else if is_quick || content_encoded {
        return npm_empty_audit();
    } else {
        match strip_internal_bulk(&body, engine) {
            Some(stripped) => stripped,
            None => return npm_empty_audit(), // unparsable under a filter → refuse
        }
    };

    // Allowlist the forwarded headers; carry the configured proxy credential only —
    // NEVER the client's Authorization (it's the caller's NORA token).
    let mut fwd: Vec<(&str, &str)> = Vec::new();
    if let Some(v) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        fwd.push(("content-type", v));
    }
    if let Some(v) = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
    {
        fwd.push(("content-encoding", v));
    }
    if let Some(v) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) {
        fwd.push(("accept", v));
    }

    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), path);
    match proxy_forward_post(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        expose_opt(&state.config.npm.proxy_auth),
        &fwd,
        &forward_body,
        &state.circuit_breaker,
        RegistryType::Npm,
    )
    .await
    {
        Ok((code, resp_body, resp_ct)) => {
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "npm", "audit"));
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY);
            let ct = resp_ct
                .as_deref()
                .and_then(|v| HeaderValue::from_str(v).ok())
                .unwrap_or_else(|| HeaderValue::from_static("application/json"));
            (status, [(header::CONTENT_TYPE, ct)], resp_body).into_response()
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        // Upstream failure must NOT be masked as `200 {}` — that renders in npm as
        // "0 vulnerabilities" (a false-clean security signal). Surface 502 so npm
        // reports an audit-endpoint error instead (non-fatal to the install), and
        // log it so the failure is observable.
        Err(e) => {
            tracing::warn!(error = ?e, "npm audit upstream forward failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// npm-compatible "no advisories" response — a `200 {}` that `npm audit` accepts
/// without erroring.
fn npm_empty_audit() -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        b"{}".to_vec(),
    )
        .into_response()
}

/// Strip internal-namespace package keys from an npm7 bulk-advisories body
/// (`{"<pkg>":[…]}`). `Some(bytes)` = the (possibly unchanged) body safe to forward;
/// `None` = the body is NOT the expected JSON object, so the caller must fail closed
/// under an active namespace filter (we could not verify no internal name is present).
fn strip_internal_bulk(body: &[u8], engine: &crate::curation::CurationEngine) -> Option<Vec<u8>> {
    let mut map =
        serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(body).ok()?;
    let before = map.len();
    map.retain(|k, _| {
        !crate::curation::is_internal_namespace(engine, crate::curation::RegistryType::Npm, k)
    });
    if map.len() == before {
        Some(body.to_vec())
    } else {
        // Re-serializing a just-parsed JSON map cannot fail in practice, but if it
        // ever did, refuse (`None`) rather than fall back to the ORIGINAL body —
        // that still contains the internal names. Keep the invariant fail-closed.
        serde_json::to_vec(&map).ok()
    }
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
        tracing::warn!(error = %e, "npm: JSON parse failed in rewrite_tarball_urls");
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
        tracing::warn!(error = %e, "npm: JSON serialize failed in rewrite_tarball_urls");
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

/// npm whoami handler: returns `{"username": "..."}`
async fn handle_whoami(user: &AuthenticatedUser) -> Response {
    // Serialize via serde_json, NOT format!: a username can contain `"` (e.g. the
    // OIDC `sub` claim, which is not charset-validated) and would otherwise break
    // the JSON or inject extra fields into the response.
    axum::Json(serde_json::json!({ "username": user.0 })).into_response()
}

// LOCK-SAFE: cache-through proxy — get miss → fetch upstream → put; no RMW race
async fn handle_request(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Response {
    // Handle npm whoami endpoint
    if path == "-/whoami" {
        return handle_whoami(&user).await;
    }

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

    // Extract publish date from cached metadata (npm `time` field). Hoisted to
    // function scope so the digest-quarantine serve gate below can seed first_seen
    // from a trusted upstream release date (#750). Non-tarball requests have no
    // version, so this is `None` without any extra storage read.
    let publish_date = if let Some(ref ver) = tarball_version {
        let meta_key = format!("npm/{}/metadata.json", package_name);
        // #748: a tarball download may arrive without a prior packument request
        // (direct/locked fetch), so `metadata.json` (the carrier of per-version
        // `time[version]`) would never be cached and the quarantine would fall
        // back to NORA's own clock. Self-prime the metadata here (synchronously,
        // so the date is readable on this same request) — gated on trust,
        // namespace-safe, best-effort. Mirrors Cargo's `ensure_cargo_metadata_cached`
        // and PyPI's `ensure_pypi_dates_cached`.
        if state.config.server.trust_upstream_dates {
            ensure_npm_metadata_cached(&state, &package_name).await;
        }
        extract_npm_publish_date(
            &state.storage,
            &meta_key,
            ver,
            state.config.server.trust_upstream_dates,
        )
        .await
    } else {
        None
    };

    // Curation check — tarball downloads only (metadata passes through)
    if is_tarball {
        // #733: an internal-namespace package is operator-owned — skip curation; the cache-hit
        // serve below handles a locally-published tarball, and the namespace guard at the
        // cache-miss boundary (below) blocks the upstream branch for internal names.
        if !crate::curation::is_internal_namespace(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Npm,
            &package_name,
        ) {
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
    }

    // Resolved here, not at the serve site, so the range branch below can see it.
    let (q_mode, q_secs) =
        crate::digest_quarantine::resolve_global(
            state.config.curation.npm.quarantine.as_ref().or(state
                .config
                .curation
                .quarantine
                .as_ref()),
            state.config.curation.npm.quarantine_ttl.as_deref().or(state
                .config
                .curation
                .quarantine_ttl
                .as_deref()),
        );

    // Resumable download (#657): serve the requested bytes from the backend and skip
    // the full read below. Tarballs only — a packument is mutable and has a TTL. A
    // partial read cannot be hashed, so neither the quarantine gate nor the .sha256
    // sidecar / curation integrity checks can run on it: the range serve stands down
    // while quarantine holds artifacts, and integrity is the client's own lockfile
    // hash, as docker does.
    if is_tarball
        && headers.contains_key(header::RANGE)
        && matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off)
    {
        if let Some(meta) = state.storage.stat(&key).await {
            if let Some(response) = crate::registry::range::range_response(
                &state.storage,
                &[&key],
                &headers,
                meta.size,
                "application/octet-stream",
                &[(
                    header::CACHE_CONTROL,
                    "public, max-age=31536000, immutable".to_string(),
                )],
            )
            .await
            {
                if response.status() == StatusCode::PARTIAL_CONTENT {
                    state.metrics.record_download("npm");
                    state.metrics.record_cache_hit("npm");
                }
                return response;
            }
        }
    }

    // --- Cache hit path ---
    // get_verified discharges the integrity witness at the serve site (compile-time
    // guarantee — see crate::verified). Both the tarball serve (pinned, Verified arm)
    // and the metadata serve (unpinned, Unpinned arm) flow the discharged bytes. The
    // .sha256 sidecar check below stays: it is the integrity check on S3 (storage
    // pins are local-only).
    if let Ok(outcome) = state.storage.get_verified(&key).await {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        // Metadata TTL: if stale, try to refetch from upstream
        if !is_tarball {
            let ttl = state.config.npm.metadata_ttl;
            if let Some(meta) = state.storage.stat(&key).await {
                if !crate::cache_ttl::is_within_ttl(meta.modified, ttl) {
                    // #68 namespace isolation: a stale internal-namespace package must
                    // NOT be revalidated upstream (dependency confusion) — refetch_metadata
                    // proxies the name. Serve the cached copy already in hand instead; an
                    // internal package is owned/hosted locally, never upstream-refreshed.
                    // (The cache-miss proxy path is guarded separately below.)
                    if crate::curation::is_internal_namespace(
                        &state.curation().curation_engine,
                        crate::curation::RegistryType::Npm,
                        &package_name,
                    ) {
                        return with_content_type(false, data).into_response();
                    }
                    // Single-flight: when a popular packument expires and a CI
                    // fleet stampedes the same key, one request revalidates
                    // upstream and the rest serve its in-memory result (#595).
                    let fresh = if state.config.server.proxy_coalesce {
                        let budget =
                            crate::proxy_coalesce::follower_budget(state.config.npm.proxy_timeout);
                        state
                            .proxy_coalesce
                            .coalesced(&key, "npm", budget, || async {
                                refetch_metadata(&state, &path, &key).await.map(Bytes::from)
                            })
                            .await
                    } else {
                        refetch_metadata(&state, &path, &key).await.map(Bytes::from)
                    };
                    if let Some(fresh) = fresh {
                        return with_content_type(false, fresh).into_response();
                    }
                    // Upstream failed — serve stale if configured, otherwise 502
                    if state.config.npm.serve_stale {
                        tracing::warn!(
                            registry = "npm",
                            path = %path,
                            "npm upstream unavailable, serving stale metadata"
                        );
                        return (
                            StatusCode::OK,
                            [
                                (
                                    header::CONTENT_TYPE,
                                    axum::http::HeaderValue::from_static("application/json"),
                                ),
                                (
                                    header::CACHE_CONTROL,
                                    axum::http::HeaderValue::from_static(
                                        "public, max-age=0, must-revalidate",
                                    ),
                                ),
                                (
                                    axum::http::header::HeaderName::from_static("x-nora-stale"),
                                    axum::http::HeaderValue::from_static("true"),
                                ),
                            ],
                            data.to_vec(),
                        )
                            .into_response();
                    }
                    return StatusCode::BAD_GATEWAY.into_response();
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
            crate::registry_type::RegistryType::Npm,
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "api", "", "npm", ""));
        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "npm",
            &data,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }
        let mut response = with_content_type(true, data).into_response();
        response
            .headers_mut()
            .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        return response;
    }

    // --- Namespace isolation: prevent proxying internal namespaces ---
    // Metadata requests skip the curation check_download (which only runs for
    // tarballs), so we must protect the proxy path separately. This runs after
    // cache lookup so locally-published packages are still served from cache.
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        &package_name,
    ) {
        return response;
    }

    // --- Proxy fetch path ---
    if let Some(proxy_url) = &state.config.npm.proxy {
        let url = format!("{}/{}", proxy_url.trim_end_matches('/'), path);

        match proxy_fetch(
            &state.http_client,
            &url,
            Duration::from_secs(state.config.npm.proxy_timeout),
            expose_opt(&state.config.npm.proxy_auth),
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
                        crate::registry_type::RegistryType::Npm,
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

                if is_tarball {
                    let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                        state.config.curation.npm.quarantine.as_ref().or(state
                            .config
                            .curation
                            .quarantine
                            .as_ref()),
                        state.config.curation.npm.quarantine_ttl.as_deref().or(state
                            .config
                            .curation
                            .quarantine_ttl
                            .as_deref()),
                    );
                    if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                        &state.digest_store,
                        "npm",
                        &data_to_serve,
                        &q_mode,
                        q_secs,
                        &url,
                        publish_date,
                    ) {
                        return resp;
                    }
                }
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

    // Revalidate with a conditional request when enabled and we have stored
    // validators. Empty validators ⇒ no conditional headers ⇒ always a 200,
    // which is also how the first fetch captures validators for next time (#596).
    let validators = if state.config.npm.revalidate {
        read_validators(&state.storage, key)
            .await
            .unwrap_or_default()
    } else {
        Validators::default()
    };
    let had_validators = validators.is_some();

    match proxy_fetch_conditional(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        expose_opt(&state.config.npm.proxy_auth),
        &validators,
        &state.circuit_breaker,
        RegistryType::Npm,
    )
    .await
    {
        // Upstream unchanged — serve the cached (already-rewritten) body and
        // refresh its freshness so we don't revalidate again until the next TTL
        // window. No body was downloaded.
        Ok(Revalidation::NotModified) => {
            match state.storage.get(key).await {
                Ok(cached) => {
                    crate::metrics::PROXY_UPSTREAM_304_TOTAL
                        .with_label_values(&["npm"])
                        .inc();
                    crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                        .with_label_values(&["npm"])
                        .inc_by(cached.len() as u64);
                    // Re-put bumps the file mtime (the freshness source) without an
                    // upstream download.
                    let storage = state.storage.clone();
                    let key_clone = key.to_string();
                    let body = cached.clone();
                    tokio::spawn(async move {
                        let _ = storage.put(&key_clone, &body).await;
                    });
                    Some(cached.to_vec())
                }
                Err(_) => {
                    // Body gone (GC, retention, corruption). Delete the stale
                    // validator sidecar so the next revalidation cycle does a
                    // full unconditional fetch instead of looping on 304 (#867).
                    let vkey = validators_key(key);
                    let _ = state.storage.delete(&vkey).await;
                    tracing::warn!(
                        key = %key,
                        "304 but cached body missing; cleared validators for full refetch"
                    );
                    None
                }
            }
        }
        // New body — rewrite, cache it, then persist the fresh validators.
        Ok(Revalidation::Modified { body, validators }) => {
            let nora_base = nora_base_url(state);
            let rewritten =
                rewrite_tarball_urls(&body, &nora_base, proxy_url).unwrap_or_else(|()| {
                    tracing::warn!(
                        path = %path,
                        "npm metadata refetch: JSON parse failed, using byte-level URL rewrite"
                    );
                    let upstream_trimmed = proxy_url.trim_end_matches('/');
                    let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));
                    replace_upstream_bytes(&body, upstream_trimmed, &nora_npm_base)
                });

            let storage = state.storage.clone();
            let key_clone = key.to_string();
            let cache_data = rewritten.clone();
            tokio::spawn(async move {
                // Body first; the validator sidecar must never advertise
                // freshness for a body that isn't there (#596).
                if let Err(e) = storage.put(&key_clone, &cache_data).await {
                    tracing::warn!(key = %key_clone, error = ?e, "npm proxy: failed to cache metadata");
                    return;
                }
                write_validators(&storage, &key_clone, &validators).await;
            });

            Some(rewritten)
        }
        // Upstream unavailable / error — fall back to the caller's serve_stale /
        // 502 path exactly as before.
        Err(_) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["npm"])
                    .inc();
            }
            None
        }
    }
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
    Extension(authority): Extension<NamespaceAuthority>,
    body: Bytes,
) -> Response {
    let package_name = path;

    // Enforce OIDC namespace_scope on the package coordinate (#583).
    if enforce_namespace_scope(&authority, &package_name).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }

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

    // Lock per package to serialize the packument regeneration within one process.
    let metadata_key = format!("npm/{}/metadata.json", package_name);
    let lock = state.publish_lock(&metadata_key);
    let _guard = lock.lock().await;

    // Read the existing packument ONCE — only to (a) refuse on corruption and (b) enforce version
    // immutability against versions still embedded in an un-migrated packument. The new versions
    // are NOT merged into it: each is written to its own immutable key and the packument is
    // regenerated by listing those keys, so concurrent publishers never read-modify-write the same
    // shared file (the multi-replica lost-update of #39).
    let existing_meta: Option<serde_json::Value> = match state.storage.get(&metadata_key).await {
        Ok(existing) => match serde_json::from_slice::<serde_json::Value>(&existing) {
            Ok(val) => Some(val),
            Err(e) => {
                // Corrupt metadata — refuse publish to protect existing versions (#533).
                tracing::error!(
                    registry = "npm",
                    key = %metadata_key,
                    error = %e,
                    bytes = existing.len(),
                    "Corrupt metadata detected during publish — refusing to overwrite"
                );
                METADATA_CORRUPT_TOTAL.with_label_values(&["npm"]).inc();
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Existing package metadata is corrupt; publish blocked to prevent data loss",
                )
                    .into_response();
            }
        },
        Err(_) => None, // No existing metadata — first publish
    };

    // Version immutability: a version already published — as its own immutable key, or still
    // embedded in an un-migrated packument — may not be overwritten.
    for ver in new_versions.keys() {
        let version_key = format!("npm/{}/versions/{}.json", package_name, ver);
        let in_keys = state.storage.stat(&version_key).await.is_some();
        let in_embedded = existing_meta
            .as_ref()
            .and_then(|m| m.get("versions"))
            .and_then(|v| v.as_object())
            .map(|o| o.contains_key(ver))
            .unwrap_or(false);
        if in_keys || in_embedded {
            return (
                StatusCode::CONFLICT,
                format!("Version {} already exists", ver),
            )
                .into_response();
        }
    }

    // Lazily migrate an old embedded-packument package to per-version keys BEFORE writing the new
    // version, so the regenerate below lists both the migrated and the new versions (no loss).
    if let Some(existing) = &existing_meta {
        migrate_embedded_packument(&state, &package_name, existing).await;
    }

    // Store tarballs
    for (filename, attachment_data) in attachments {
        // Scoped packages (e.g. @scope/name) may have attachment filenames
        // like "@scope/name-1.0.0.tgz". Strip the scope prefix since it is
        // already captured in the package name — the filename part must be a
        // flat name without path separators to prevent path traversal.
        let normalized_name = if let Some(scope_end) = package_name.find('/') {
            let scope_prefix = &package_name[..=scope_end];
            filename.strip_prefix(scope_prefix).unwrap_or(filename)
        } else {
            filename
        };

        if !is_valid_attachment_name(normalized_name) {
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

        let tarball_key = format!("npm/{}/tarballs/{}", package_name, normalized_name);
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

    // Write each new version as its OWN immutable key, with the tarball URL rewritten to point at
    // this registry. Concurrent publishes of DIFFERENT versions write distinct keys, so none is
    // lost — the heart of the #39 fix (vs the old read-merge-write of the shared packument).
    let nora_base = nora_base_url(&state);
    let short_name = package_name.split('/').next_back().unwrap_or(&package_name);
    for (ver, ver_data) in new_versions {
        let mut vd = ver_data.clone();
        if let Some(dist) = vd.get_mut("dist") {
            let tarball_url = format!(
                "{}/npm/{}/-/{}-{}.tgz",
                nora_base.trim_end_matches('/'),
                package_name,
                short_name,
                ver
            );
            dist["tarball"] = serde_json::Value::String(tarball_url);
        }
        let version_key = format!("npm/{}/versions/{}.json", package_name, ver);
        match serde_json::to_vec(&vd) {
            Ok(bytes) => {
                if let Err(e) = state.storage.put(&version_key, &bytes).await {
                    tracing::error!(key = %version_key, error = ?e, "npm publish: failed to store version");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
            Err(e) => {
                tracing::error!(error = ?e, "npm publish: failed to serialize version");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }

    // dist-tags: one small mutable pointer per tag (tag -> version). Last-writer-wins on a single
    // tag is an acceptable pointer-flip — it never loses a version (each version is its own key).
    if let Some(new_dist_tags) = payload.get("dist-tags").and_then(|d| d.as_object()) {
        for (tag, ver) in new_dist_tags {
            if let Some(ver_str) = ver.as_str() {
                let tag_key = format!("npm/{}/dist-tags/{}", package_name, tag);
                if let Err(e) = state.storage.put(&tag_key, ver_str.as_bytes()).await {
                    tracing::warn!(key = %tag_key, error = ?e, "npm publish: failed to store dist-tag");
                }
            }
        }
    }

    // Package-level descriptive fields (not per-version) — overwrite (last-writer-wins is fine).
    let mut pkg_fields = serde_json::Map::new();
    for field in &["name", "_id", "description", "readme", "license"] {
        if let Some(val) = payload.get(*field) {
            pkg_fields.insert(field.to_string(), val.clone());
        }
    }
    if let Ok(bytes) = serde_json::to_vec(&serde_json::Value::Object(pkg_fields)) {
        let pkg_key = format!("npm/{}/pkg.json", package_name);
        if let Err(e) = state.storage.put(&pkg_key, &bytes).await {
            tracing::warn!(key = %pkg_key, error = ?e, "npm publish: failed to store package fields");
        }
    }

    // Regenerate the packument (metadata.json) by listing the immutable per-version keys.
    if regenerate_packument(&state, &package_name).await.is_err() {
        tracing::error!(package = %package_name, "npm publish: failed to regenerate packument");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Fail-closed (#878): a 201 MUST mean the published version is actually visible in
    // the packument. scan-regenerate derives `versions` by LISTING the per-version keys
    // and reading each back; a storage key-encoding round-trip bug (the object_store
    // `%40`->`%2540` double-encoding for `@scope/...` keys) silently produced an empty
    // `versions` map, yet publish still returned 201 and `npm install` then failed
    // ENOVERSIONS. Read the regenerated packument back and refuse (500) unless every
    // just-published version is present, so a regen round-trip defect can never again
    // hide behind a 201.
    let published_visible = match state.storage.get(&metadata_key).await {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|m| {
                m.get("versions")
                    .and_then(|v| v.as_object())
                    .map(|vs| new_versions.keys().all(|v| vs.contains_key(v)))
            })
            .unwrap_or(false),
        Err(_) => false,
    };
    if !published_visible {
        tracing::error!(
            package = %package_name,
            "npm publish: regenerated packument does not list the just-published version(s) — refusing 201 (scan-regenerate round-trip broke, see #878)"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    state.metrics.record_upload("npm");
    state
        .audit
        .log(AuditEntry::new("push", "api", &package_name, "npm", ""));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        package_name,
        crate::registry_type::RegistryType::Npm,
        "LOCAL",
    ));
    state.repo_index.invalidate("npm");

    StatusCode::CREATED.into_response()
}

// ============================================================================
// Helpers
// ============================================================================

/// Regenerate the npm packument (`metadata.json`) by LISTING the immutable per-version keys, the
/// dist-tag pointers and the package-level fields — never by read-modify-write of the shared file.
/// Concurrent publishers each write their own `versions/{v}.json`; whoever regenerates last lists
/// them all, so no version is permanently lost (the maven scan-regenerate guarantee, #39). Old
/// embedded-packument packages are migrated to per-version keys by `migrate_embedded_packument`
/// in the publish handler BEFORE the new version is written, so this stays a pure list-derive.
async fn regenerate_packument(state: &AppState, package_name: &str) -> Result<(), ()> {
    let versions_prefix = format!("npm/{}/versions/", package_name);
    let version_keys = state
        .storage
        .list(&versions_prefix)
        .await
        .unwrap_or_default();

    // versions map, keyed by the filename (version) without the .json suffix.
    let mut versions = serde_json::Map::new();
    for key in &version_keys {
        let Ok(data) = state.storage.get(key).await else {
            continue;
        };
        let Ok(vd) = serde_json::from_slice::<serde_json::Value>(&data) else {
            continue;
        };
        if let Some(ver) = key.rsplit('/').next().and_then(|f| f.strip_suffix(".json")) {
            versions.insert(ver.to_string(), vd);
        }
    }

    // dist-tags from the pointer keys (+ derive `latest` if publish left it unset).
    let dt_prefix = format!("npm/{}/dist-tags/", package_name);
    let mut dist_tags = serde_json::Map::new();
    for key in state.storage.list(&dt_prefix).await.unwrap_or_default() {
        if let Ok(data) = state.storage.get(&key).await {
            if let (Some(tag), Ok(ver)) = (key.rsplit('/').next(), String::from_utf8(data.to_vec()))
            {
                dist_tags.insert(tag.to_string(), serde_json::Value::String(ver));
            }
        }
    }
    if !dist_tags.contains_key("latest") {
        if let Some(latest) = max_semver(versions.keys()) {
            dist_tags.insert("latest".to_string(), serde_json::Value::String(latest));
        }
    }

    // Package-level fields + the assembled maps -> the packument.
    let mut packument = match state
        .storage
        .get(&format!("npm/{}/pkg.json", package_name))
        .await
    {
        Ok(d) => serde_json::from_slice(&d).unwrap_or_else(|_| serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };
    let obj = packument.as_object_mut().ok_or(())?;
    obj.insert(
        "name".to_string(),
        serde_json::Value::String(package_name.to_string()),
    );
    obj.insert(
        "dist-tags".to_string(),
        serde_json::Value::Object(dist_tags),
    );
    obj.insert("versions".to_string(), serde_json::Value::Object(versions));

    let bytes = serde_json::to_vec(&packument).map_err(|_| ())?;
    state
        .storage
        .put(&format!("npm/{}/metadata.json", package_name), &bytes)
        .await
        .map_err(|_| ())
}

/// Seed per-version keys from an old embedded packument (versions inside `metadata.json`, no
/// per-version keys) so the scan-regenerate path does not drop them. Idempotent; a no-op once the
/// package has per-version keys. Runs BEFORE the new version is written.
async fn migrate_embedded_packument(
    state: &AppState,
    package_name: &str,
    existing: &serde_json::Value,
) {
    let versions_prefix = format!("npm/{}/versions/", package_name);
    if !state
        .storage
        .list(&versions_prefix)
        .await
        .unwrap_or_default()
        .is_empty()
    {
        return; // already migrated
    }
    if let Some(embedded) = existing.get("versions").and_then(|v| v.as_object()) {
        for (ver, data) in embedded {
            if let Ok(bytes) = serde_json::to_vec(data) {
                let vkey = format!("npm/{}/versions/{}.json", package_name, ver);
                let _ = state.storage.put(&vkey, &bytes).await;
            }
        }
    }
    if let Some(tags) = existing.get("dist-tags").and_then(|d| d.as_object()) {
        for (tag, ver) in tags {
            if let Some(vs) = ver.as_str() {
                let tkey = format!("npm/{}/dist-tags/{}", package_name, tag);
                let _ = state.storage.put(&tkey, vs.as_bytes()).await;
            }
        }
    }
}

/// Highest version by a naive numeric semver comparison (a release outranks a prerelease at the
/// same core). Used only as the `latest` dist-tag fallback when publish did not set one.
fn max_semver<'a>(versions: impl Iterator<Item = &'a String>) -> Option<String> {
    versions
        .max_by(|a, b| semver_key(a).cmp(&semver_key(b)))
        .cloned()
}

fn semver_key(v: &str) -> (u64, u64, u64, bool) {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let mut it = core.trim_start_matches('v').split('.');
    let n = |x: Option<&str>| x.and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    (n(it.next()), n(it.next()), n(it.next()), !v.contains('-'))
}

/// Self-prime `npm/{name}/metadata.json` so the release-age date (#748) is
/// available on the tarball download path itself.
///
/// A locked/direct tarball fetch (`/npm/{name}/-/{name}-{version}.tgz`) may
/// arrive without a prior packument request, so `metadata.json` (the carrier of
/// the per-version `time[version]`) would never be cached and the quarantine
/// would always fall back to NORA's own clock — a provably-old npm artifact is
/// then held for the full TTL as "new to this mirror". Without this, the
/// release-age maturation never fires for npm. Synchronous `put` (not
/// `spawn_cache`) so the date is readable on the same request. Best-effort: any
/// failure leaves the date `None` (fail-safe — the package is held as new).
/// Namespace-safe: an internal-namespace package is never fetched upstream
/// (#68). Mirrors Cargo's `ensure_cargo_metadata_cached` and PyPI's
/// `ensure_pypi_dates_cached`.
async fn ensure_npm_metadata_cached(state: &AppState, package_name: &str) {
    let key = format!("npm/{}/metadata.json", package_name);
    if state.storage.get(&key).await.is_ok() {
        return;
    }
    // #68: never fetch an internal-namespace package's metadata upstream.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        package_name,
    ) {
        return;
    }
    let Some(proxy_url) = state.config.npm.proxy.clone() else {
        return;
    };
    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), package_name);
    if let Ok(data) = proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        expose_opt(&state.config.npm.proxy_auth),
        &state.circuit_breaker,
        RegistryType::Npm,
    )
    .await
    {
        // Rewrite tarball URLs to point at NORA, exactly as the proxy path and
        // refetch_metadata do, so a subsequent client reading the cached
        // packument is not sent back to the upstream.
        let nora_base = nora_base_url(state);
        let rewritten = rewrite_tarball_urls(&data, &nora_base, &proxy_url).unwrap_or_else(|()| {
            tracing::warn!(
                package = %package_name,
                "npm metadata self-prime: JSON parse failed, using byte-level URL rewrite",
            );
            let upstream_trimmed = proxy_url.trim_end_matches('/');
            let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));
            replace_upstream_bytes(&data, upstream_trimmed, &nora_npm_base)
        });
        let _ = state.storage.put(&key, &rewritten).await;
    }
}

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
    trust_upstream: bool,
) -> Option<i64> {
    // #513: when upstream dates are not trusted, derive age from NORA's own
    // cache mtime instead of the (spoofable) upstream metadata date. Never fall
    // back to the upstream date here — that would reopen the spoof vector.
    if !trust_upstream {
        return crate::curation::extract_mtime_as_publish_date(storage, metadata_key).await;
    }
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
    use crate::test_helpers::{
        body_bytes, create_test_context, create_test_context_with_auth, send, send_with_headers,
    };

    #[tokio::test]
    async fn test_npm_namespace_scope_enforced() {
        use crate::auth::NamespaceAuthority;
        use crate::config::ScopeEnforcement;
        use axum::body::Bytes;
        use axum::extract::{Path, State};
        use axum::http::StatusCode;
        use axum::Extension;

        let ctx = create_test_context();
        let scoped = NamespaceAuthority::from_oidc_scope(
            "ci",
            &["@myorg/**".to_string()],
            ScopeEnforcement::Enforce,
        );

        // Out of scope -> 403, decided before any payload parsing.
        let resp = super::handle_publish(
            State(ctx.state.clone()),
            Path("@other/pkg".to_string()),
            Extension(scoped.clone()),
            Bytes::from_static(b"{}"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // In scope -> enforcement passes (then fails payload validation, not 403).
        let resp = super::handle_publish(
            State(ctx.state.clone()),
            Path("@myorg/pkg".to_string()),
            Extension(scoped),
            Bytes::from_static(b"{}"),
        )
        .await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }
    use axum::body::Body;
    use axum::http::{header, Method, StatusCode};
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
    async fn test_npm_tarball_range_request() {
        let ctx = create_test_context();
        let tarball = b"0123456789abcdef";
        ctx.state
            .storage
            .put("npm/lodash/tarballs/lodash-4.17.21.tgz", tarball)
            .await
            .unwrap();
        let url = "/npm/lodash/-/lodash-4.17.21.tgz";

        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes 2-5/{}", tarball.len())
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(body_bytes(resp).await.as_ref(), &tarball[2..=5]);

        // A client that already holds the whole tarball resumes with `bytes=<size>-`.
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            url,
            vec![("range", &format!("bytes={}-", tarball.len())[..])],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes */{}", tarball.len())
        );

        let resp = send(&ctx.app, Method::GET, url, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(body_bytes(resp).await.as_ref(), &tarball[..]);
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
    async fn test_npm_publish_multi_version_scan_regenerate() {
        // Two separate publishes of different versions must BOTH survive in the regenerated
        // packument — the version data lives in immutable per-version keys, not a merged file
        // (the #39 multi-replica lost-update fix).
        let ctx = create_test_context();
        for v in ["1.0.0", "2.0.0"] {
            let b64 = base64::engine::general_purpose::STANDARD.encode(b"tgz");
            let mut versions = serde_json::Map::new();
            versions.insert(v.to_string(), serde_json::json!({ "dist": {} }));
            let mut atts = serde_json::Map::new();
            atts.insert(
                format!("multi-{}.tgz", v),
                serde_json::json!({ "data": b64 }),
            );
            let payload =
                serde_json::json!({ "name": "multi", "versions": versions, "_attachments": atts });
            let resp = send(
                &ctx.app,
                Method::PUT,
                "/npm/multi",
                Body::from(serde_json::to_vec(&payload).unwrap()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }
        // both per-version keys exist (immutable, distinct — no merge)
        assert!(ctx
            .state
            .storage
            .get("npm/multi/versions/1.0.0.json")
            .await
            .is_ok());
        assert!(ctx
            .state
            .storage
            .get("npm/multi/versions/2.0.0.json")
            .await
            .is_ok());
        // the regenerated packument lists BOTH
        let meta = ctx
            .state
            .storage
            .get("npm/multi/metadata.json")
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&meta).unwrap();
        let versions = json["versions"].as_object().unwrap();
        assert!(versions.contains_key("1.0.0"), "v1 lost from packument");
        assert!(versions.contains_key("2.0.0"), "v2 lost from packument");
    }

    #[tokio::test]
    async fn test_npm_publish_migrates_embedded_packument() {
        // An old-layout package (versions embedded in metadata.json, no per-version keys) is
        // lazily migrated on the next publish, preserving the old versions.
        let ctx = create_test_context();
        let old = serde_json::json!({
            "name": "legacy",
            "versions": { "1.0.0": { "name": "legacy", "version": "1.0.0", "dist": {} } },
            "dist-tags": { "latest": "1.0.0" }
        });
        ctx.state
            .storage
            .put(
                "npm/legacy/metadata.json",
                &serde_json::to_vec(&old).unwrap(),
            )
            .await
            .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"tgz");
        let payload = serde_json::json!({
            "name": "legacy",
            "versions": { "2.0.0": { "dist": {} } },
            "_attachments": { "legacy-2.0.0.tgz": { "data": b64 } },
        });
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/npm/legacy",
            Body::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        // old version migrated to its own per-version key
        assert!(
            ctx.state
                .storage
                .get("npm/legacy/versions/1.0.0.json")
                .await
                .is_ok(),
            "old embedded version not migrated to a per-version key"
        );
        // packument has BOTH the migrated old and the new version
        let meta = ctx
            .state
            .storage
            .get("npm/legacy/metadata.json")
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&meta).unwrap();
        let versions = json["versions"].as_object().unwrap();
        assert!(versions.contains_key("1.0.0"), "migrated v1 lost");
        assert!(versions.contains_key("2.0.0"), "new v2 lost");
    }

    #[tokio::test]
    async fn test_npm_publish_scoped_with_prefixed_attachment() {
        use crate::auth::NamespaceAuthority;
        use axum::body::Bytes;
        use axum::extract::{Path, State};
        use axum::http::StatusCode;
        use axum::Extension;

        let ctx = create_test_context();

        let tarball_data = b"fake-tarball";
        let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

        // Scoped package where the attachment filename includes the scope prefix
        // (e.g. "@scope/pkg-1.0.0.tgz" instead of "pkg-1.0.0.tgz"). The handler
        // must normalize this by stripping the scope prefix.
        let payload = serde_json::json!({
            "name": "@scope/mypkg",
            "versions": {
                "1.0.0": { "dist": {} }
            },
            "_attachments": {
                "@scope/mypkg-1.0.0.tgz": { "data": base64_data }
            },
            "dist-tags": { "latest": "1.0.0" }
        });

        let body_bytes = serde_json::to_vec(&payload).unwrap();

        let resp = super::handle_publish(
            State(ctx.state.clone()),
            Path("@scope/mypkg".to_string()),
            Extension(NamespaceAuthority::Unrestricted),
            Bytes::from(body_bytes),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Verify tarball was stored with the normalized (scope-stripped) filename
        let stored_tarball = ctx
            .state
            .storage
            .get("npm/@scope/mypkg/tarballs/mypkg-1.0.0.tgz")
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

    /// Corrupt metadata in storage → publish returns 500 (#533).
    #[tokio::test]
    async fn test_publish_corrupt_metadata_returns_500() {
        let ctx = create_test_context();

        // Plant corrupt (non-JSON) data in metadata key
        ctx.state
            .storage
            .put("npm/mypkg/metadata.json", b"NOT VALID JSON{{{")
            .await
            .unwrap();

        let tarball_data = b"fake-tarball";
        let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

        let payload = serde_json::json!({
            "name": "mypkg",
            "versions": {
                "2.0.0": { "dist": {} }
            },
            "_attachments": {
                "mypkg-2.0.0.tgz": { "data": base64_data }
            },
            "dist-tags": { "latest": "2.0.0" }
        });

        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let response = send(&ctx.app, Method::PUT, "/npm/mypkg", Body::from(body_bytes)).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Corrupt data must NOT be overwritten — preserved for forensics
        let stored = ctx
            .state
            .storage
            .get("npm/mypkg/metadata.json")
            .await
            .unwrap();
        assert_eq!(&stored[..], b"NOT VALID JSON{{{");
    }

    /// First publish (no existing metadata) still works (#533 regression guard).
    #[tokio::test]
    async fn test_first_publish_no_existing_metadata() {
        let ctx = create_test_context();

        let tarball_data = b"fake-tarball";
        let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

        let payload = serde_json::json!({
            "name": "newpkg",
            "versions": {
                "1.0.0": { "dist": {} }
            },
            "_attachments": {
                "newpkg-1.0.0.tgz": { "data": base64_data }
            },
            "dist-tags": { "latest": "1.0.0" }
        });

        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let response = send(&ctx.app, Method::PUT, "/npm/newpkg", Body::from(body_bytes)).await;

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_npm_whoami_anonymous() {
        use axum::http::StatusCode;

        let ctx = create_test_context();
        let resp = send(&ctx.app, axum::http::Method::GET, "/npm/-/whoami", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["username"], "anonymous");
    }

    #[tokio::test]
    async fn test_npm_whoami_authenticated() {
        use axum::http::StatusCode;
        use base64::Engine;

        let ctx = create_test_context_with_auth(&[("alice", "hunter2")]);

        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("alice:hunter2")
        );
        let resp = send_with_headers(
            &ctx.app,
            axum::http::Method::GET,
            "/npm/-/whoami",
            vec![("authorization", &basic)],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["username"], "alice");
    }

    #[tokio::test]
    async fn test_npm_whoami_requires_auth() {
        use axum::http::StatusCode;

        let ctx = create_test_context_with_auth(&[("alice", "hunter2")]);

        let resp = send(&ctx.app, axum::http::Method::GET, "/npm/-/whoami", "").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // A username containing `"` (reachable via the OIDC `sub` claim) must NOT
    // break the JSON or inject extra fields — handle_whoami serializes via serde.
    #[tokio::test]
    async fn test_npm_whoami_escapes_username() {
        use crate::auth::AuthenticatedUser;

        let evil = r#"a","admin":"x"#;
        let resp = super::handle_whoami(&AuthenticatedUser(evil.to_string())).await;
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["username"], evil);
        assert!(json.get("admin").is_none());
    }

    // ── ensure_npm_metadata_cached self-prime (#748) ──
    //
    // A tarball download (direct/locked fetch) arrives without a prior packument
    // request, so metadata.json is uncached. ensure_npm_metadata_cached fetches
    // the packument upstream and caches it (rewritten to NORA URLs) so the
    // per-version `time[version]` date is readable on the same request.

    /// Happy path: tarball cache-miss → ensure_npm_metadata_cached fetches and
    /// caches the packument; tarball is also proxied and served. The cached
    /// metadata must carry the upstream release date AND have its tarball URLs
    /// rewritten to NORA.
    #[tokio::test]
    async fn test_npm_tarball_self_primes_metadata_on_cache_miss() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;

        // Packument (fetched by ensure_npm_metadata_cached → GET {proxy}/testpkg).
        let packument = serde_json::json!({
            "name": "testpkg",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": format!("{}/testpkg/-/testpkg-1.0.0.tgz", upstream.uri())
                    }
                }
            },
            "time": { "1.0.0": "2020-01-15T10:30:00.000Z" }
        });
        Mock::given(method("GET"))
            .and(path("/testpkg"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
            .mount(&upstream)
            .await;

        // Tarball (fetched by the cache-miss proxy path → GET {proxy}/testpkg/-/testpkg-1.0.0.tgz).
        let tarball = b"TGZ-BYTES";
        Mock::given(method("GET"))
            .and(path("/testpkg/-/testpkg-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.to_vec()))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });

        // Direct/locked tarball fetch — no prior packument request.
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/testpkg/-/testpkg-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], tarball);

        // ensure_npm_metadata_cached must have synchronously cached the packument.
        let cached = ctx
            .state
            .storage
            .get("npm/testpkg/metadata.json")
            .await
            .expect("metadata.json must be self-primed");
        let json: serde_json::Value = serde_json::from_slice(&cached).unwrap();
        assert_eq!(
            json["time"]["1.0.0"].as_str().unwrap(),
            "2020-01-15T10:30:00.000Z",
            "upstream release date must survive into the cached packument"
        );
        // Tarball URLs must be rewritten to NORA, not left pointing upstream.
        let tarball_url = json["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert!(
            !tarball_url.contains(&upstream.uri()[..]),
            "upstream tarball URL leaked into cached metadata: {tarball_url}"
        );
        assert!(
            tarball_url.starts_with("http://127.0.0.1") && tarball_url.contains("/npm/"),
            "tarball URL not rewritten to NORA: {tarball_url}"
        );

        // The publish date must now be resolvable from the cached packument.
        let date = super::extract_npm_publish_date(
            &ctx.state.storage,
            "npm/testpkg/metadata.json",
            "1.0.0",
            true,
        )
        .await;
        assert_eq!(
            date,
            Some(1579084200),
            "ISO 8601 → Unix for 2020-01-15T10:30:00Z"
        );
    }

    /// Cached metadata short-circuits ensure_npm_metadata_cached — no upstream
    /// hit on a second tarball fetch (the packument is already in storage).
    #[tokio::test]
    async fn test_npm_tarball_self_prime_skips_when_metadata_cached() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;

        // Pre-seed the packument so ensure_npm_metadata_cached early-returns.
        let packument = serde_json::json!({
            "name": "cachedpkg",
            "versions": { "1.0.0": { "dist": {} } },
            "time": { "1.0.0": "2019-05-01T00:00:00.000Z" }
        });

        let tarball = b"TGZ";
        Mock::given(method("GET"))
            .and(path("/cachedpkg/-/cachedpkg-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.to_vec()))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });
        ctx_seed_metadata(&ctx, "cachedpkg", &packument).await;

        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/cachedpkg/-/cachedpkg-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], tarball);

        let packument_hits = upstream
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == "/cachedpkg")
            .count();
        assert_eq!(
            packument_hits, 0,
            "metadata already cached → ensure_npm_metadata_cached must NOT hit upstream"
        );
    }

    /// Internal-namespace package: ensure_npm_metadata_cached must never fetch
    /// the packument upstream (#68 dependency confusion).
    #[tokio::test]
    async fn test_npm_tarball_self_prime_skips_internal_namespace() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Any upstream hit would be a dependency-confusion leak — mount a canary.
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces = vec!["@internal/*".to_string()];
        });

        // Tarball not in cache → proxy path, but ensure_npm_metadata_cached must
        // skip the packument fetch for the internal name. Namespace isolation
        // blocks the upstream branch for an internal name → 403 (not 404).
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/@internal/secret/-/secret-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let packument_hits = upstream
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path().contains("@internal/secret"))
            .count();
        assert_eq!(
            packument_hits, 0,
            "internal-namespace packument must never be fetched upstream (#68)"
        );
    }

    /// `trust_upstream_dates = false` → ensure_npm_metadata_cached is never
    /// called (the gating `if` in handle_request is false).
    #[tokio::test]
    async fn test_npm_tarball_self_prime_skipped_when_distrust_upstream_dates() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let tarball = b"TGZ";
        Mock::given(method("GET"))
            .and(path("/distrust/-/distrust-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.to_vec()))
            .mount(&upstream)
            .await;
        // A packument hit would prove ensure_npm_metadata_cached ran.
        Mock::given(method("GET"))
            .and(path("/distrust"))
            .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.server.trust_upstream_dates = false; // gate closed
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/distrust/-/distrust-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], tarball);

        let packument_hits = upstream
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == "/distrust")
            .count();
        assert_eq!(
            packument_hits, 0,
            "trust_upstream_dates=false must skip ensure_npm_metadata_cached"
        );
    }

    /// No upstream proxy configured → ensure_npm_metadata_cached early-returns
    /// (proxy_url is None) and the tarball cache-miss yields 404.
    #[tokio::test]
    async fn test_npm_tarball_self_prime_skipped_when_no_proxy() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};

        // No proxy → both the tarball and the self-prime fetch have nowhere to go.
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = None;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/noproxy/-/noproxy-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // metadata.json must NOT exist (self-prime had no upstream to fetch from).
        assert!(
            ctx.state
                .storage
                .get("npm/noproxy/metadata.json")
                .await
                .is_err(),
            "no proxy → metadata.json must not be self-primed"
        );
    }

    /// JSON-parse failure in the upstream packument falls back to byte-level URL
    /// rewrite (replace_upstream_bytes), so the cached metadata still has NORA
    /// URLs and the body is preserved (fail-safe, not dropped).
    #[tokio::test]
    async fn test_npm_tarball_self_prime_byte_level_rewrite_on_invalid_json() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;

        // Malformed packument (not valid JSON) carrying an upstream tarball URL
        // that the byte-level rewrite must still replace.
        let upstream_uri = upstream.uri();
        let upstream_uri_trimmed = upstream_uri.trim_end_matches('/');
        let bogus_packument = format!(
            "{{ not-valid-json \"tarball\": \"{upstream_uri_trimmed}/badpkg/-/badpkg-1.0.0.tgz\" }}"
        );
        Mock::given(method("GET"))
            .and(path("/badpkg"))
            .respond_with(ResponseTemplate::new(200).set_body_string(bogus_packument.clone()))
            .mount(&upstream)
            .await;

        let tarball = b"TGZ";
        Mock::given(method("GET"))
            .and(path("/badpkg/-/badpkg-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.to_vec()))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });

        let resp = send(&ctx.app, Method::GET, "/npm/badpkg/-/badpkg-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], tarball);

        let cached = ctx
            .state
            .storage
            .get("npm/badpkg/metadata.json")
            .await
            .expect("metadata.json must be cached even for non-JSON packument");
        let cached_str = String::from_utf8_lossy(&cached);
        assert!(
            !cached_str.contains(upstream_uri_trimmed),
            "upstream URL leaked through byte-level rewrite: {cached_str}"
        );
        // Body preserved (byte-level rewrite is a prefix replace, not a drop).
        assert!(
            cached_str.contains("/npm/badpkg/-/badpkg-1.0.0.tgz"),
            "byte-level rewrite must substitute the NORA npm base: {cached_str}"
        );
    }

    // ── ensure_npm_metadata_cached test helpers ──

    async fn ctx_seed_metadata(
        ctx: &crate::test_helpers::TestContext,
        name: &str,
        packument: &serde_json::Value,
    ) {
        ctx.state
            .storage
            .put(
                &format!("npm/{name}/metadata.json"),
                &serde_json::to_vec(packument).unwrap(),
            )
            .await
            .unwrap();
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

    /// #596 acceptance: with a cached metadata body + stored validators, a stale
    /// request revalidates with `If-None-Match`; on upstream 304 the cached body
    /// is served and NO 200-with-body is ever fetched. Drives the real handler.
    #[tokio::test]
    async fn test_npm_revalidation_304_serves_cache_no_body_download() {
        use crate::registry::{write_validators, Validators};
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Conditional request (has If-None-Match) → 304. A request WITHOUT it
        // would 404 here (no mount), so any full fetch would visibly fail —
        // proving the 304 path served from cache.
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.npm.metadata_ttl = 0; // always stale → always revalidate
            cfg.npm.revalidate = true;
            cfg.npm.serve_stale = false;
        });

        // Pre-seed the cache body + validator sidecar (as a prior 200 would have).
        let key = "npm/testpkg/metadata.json";
        ctx.state
            .storage
            .put(key, b"CACHED-PACKUMENT")
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
            .with_label_values(&["npm"])
            .get();

        let resp = send(&ctx.app, Method::GET, "/npm/testpkg", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"CACHED-PACKUMENT", "must serve the cached body");

        let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["npm"])
            .get();
        assert!(after > before, "a 304 revalidation must be recorded");
    }

    /// #595: a thundering herd of concurrent requests for the same expired
    /// metadata key must collapse to a SINGLE upstream fetch. M clients race
    /// `GET /npm/testpkg` while the key is stale; a counting mock upstream
    /// (delayed so followers pile up) must observe exactly one request, and
    /// every client must receive the leader's body.
    #[tokio::test]
    async fn test_npm_concurrent_metadata_miss_coalesces_to_one_upstream_fetch() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use std::sync::Arc;
        use std::time::Duration;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Delay the response so all followers reach the single-flight election
        // while the leader is still fetching. Body is not valid JSON, so the
        // handler's byte-level URL rewrite passes it through unchanged.
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("FRESH-PACKUMENT")
                    .set_delay(Duration::from_millis(400)),
            )
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.npm.metadata_ttl = 0; // always stale → always refetch
            cfg.npm.revalidate = false; // plain 200, no conditional headers
            cfg.npm.serve_stale = false;
            // proxy_coalesce defaults to true.
        });

        // Pre-seed a stale cached body so the stale-metadata refetch path runs.
        let key = "npm/testpkg/metadata.json";
        ctx.state.storage.put(key, b"STALE").await.unwrap();

        let before = crate::metrics::PROXY_COALESCED_TOTAL
            .with_label_values(&["npm"])
            .get();

        const M: usize = 16;
        let app = Arc::new(ctx.app.clone());
        let mut handles = Vec::new();
        for _ in 0..M {
            let app = Arc::clone(&app);
            handles.push(tokio::spawn(async move {
                let resp = send(&app, Method::GET, "/npm/testpkg", "").await;
                let status = resp.status();
                let body = body_bytes(resp).await;
                (status, body)
            }));
        }

        for h in handles {
            let (status, body) = h.await.unwrap();
            assert_eq!(status, StatusCode::OK);
            assert_eq!(&body[..], b"FRESH-PACKUMENT", "every client gets the body");
        }

        let upstream_hits = upstream.received_requests().await.unwrap().len();
        assert_eq!(
            upstream_hits, 1,
            "M concurrent requests for one key must hit upstream exactly once"
        );

        let after = crate::metrics::PROXY_COALESCED_TOTAL
            .with_label_values(&["npm"])
            .get();
        assert_eq!(
            after - before,
            (M - 1) as u64,
            "M-1 followers must be served without their own upstream fetch"
        );
    }

    /// #595 kill-switch: with `server.proxy_coalesce = false`, the coalescer is
    /// bypassed and every concurrent request fetches independently — so the
    /// counting upstream observes one hit per client (proves the gate works).
    #[tokio::test]
    async fn test_npm_coalesce_disabled_lets_every_request_fetch() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use std::sync::Arc;
        use std::time::Duration;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("FRESH-PACKUMENT")
                    .set_delay(Duration::from_millis(200)),
            )
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.npm.metadata_ttl = 0;
            cfg.npm.revalidate = false;
            cfg.npm.serve_stale = false;
            cfg.server.proxy_coalesce = false; // kill-switch off
        });

        let key = "npm/testpkg/metadata.json";
        ctx.state.storage.put(key, b"STALE").await.unwrap();

        const M: usize = 8;
        let app = Arc::new(ctx.app.clone());
        let mut handles = Vec::new();
        for _ in 0..M {
            let app = Arc::clone(&app);
            handles.push(tokio::spawn(async move {
                let resp = send(&app, Method::GET, "/npm/testpkg", "").await;
                let status = resp.status();
                let _ = body_bytes(resp).await;
                status
            }));
        }
        for h in handles {
            assert_eq!(h.await.unwrap(), StatusCode::OK);
        }

        let upstream_hits = upstream.received_requests().await.unwrap().len();
        assert_eq!(
            upstream_hits, M,
            "with coalescing disabled every request fetches independently"
        );
    }

    // ── npm audit proxy (#597) ──

    /// bulk audit is forwarded to upstream and returned verbatim; internal-namespace
    /// package names are stripped from the forwarded body (dependency-confusion).
    #[tokio::test]
    async fn test_npm_audit_bulk_forwards_and_strips_internal() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/npm/v1/security/advisories/bulk"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"lodash":[]}"#))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces = vec!["@internal/*".to_string()];
        });

        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            r#"{"lodash":["4.17.0"],"@internal/secret":["1.0.0"]}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(
            &body[..],
            br#"{"lodash":[]}"#,
            "upstream body returned verbatim"
        );

        // The forwarded request must NOT carry the internal package name.
        let reqs = upstream.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let fwd = String::from_utf8_lossy(&reqs[0].body);
        assert!(fwd.contains("lodash"), "public pkg forwarded: {fwd}");
        assert!(
            !fwd.contains("@internal/secret"),
            "internal pkg name must be stripped before forwarding: {fwd}"
        );
    }

    /// Hosted-only repo (no upstream proxy) → npm-compatible empty result, not 405/500.
    #[tokio::test]
    async fn test_npm_audit_no_proxy_returns_empty() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = None;
        });
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            r#"{"lodash":["4.17.0"]}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"{}");
    }

    /// quick audit (gzipped lockfile — cannot per-name strip) is refused with an
    /// empty result when an internal-namespace filter is configured; upstream is
    /// never contacted (no internal-name leak).
    #[tokio::test]
    async fn test_npm_audit_quick_refused_under_filter() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("SHOULD-NOT-BE-CALLED"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces = vec!["@internal/*".to_string()];
        });
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/audits/quick",
            "lockfile-payload",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"{}");
        assert_eq!(
            upstream.received_requests().await.unwrap().len(),
            0,
            "quick must not reach upstream under a namespace filter"
        );
    }

    /// POST on a non-audit npm path → 405 (POST is only valid on the audit endpoints).
    #[tokio::test]
    async fn test_npm_audit_non_audit_post_405() {
        use crate::test_helpers::{create_test_context, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::POST, "/npm/lodash", "x").await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// An oversized audit body is rejected with 413 before any upstream forward.
    #[tokio::test]
    async fn test_npm_audit_body_too_large() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some("http://127.0.0.1:1".to_string());
        });
        let big = "x".repeat(NPM_AUDIT_BODY_CAP + 1);
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            big,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Review #1 regression: a Content-Encoded (e.g. gzipped) bulk body under an
    /// active namespace filter cannot be name-verified → must fail CLOSED (refuse,
    /// upstream never contacted), not forward internal names.
    #[tokio::test]
    async fn test_npm_audit_bulk_encoded_refused_under_filter() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send_with_headers};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces = vec!["@internal/*".to_string()];
        });
        // Claims gzip encoding → NORA cannot see the names → must refuse.
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            vec![("content-encoding", "gzip")],
            "gzipped-body-not-inspected-because-refused",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"{}");
        assert_eq!(
            upstream.received_requests().await.unwrap().len(),
            0,
            "encoded bulk under a filter must NOT be forwarded"
        );
    }

    /// Review #3 regression: upstream 5xx must surface as 502 (audit-endpoint error),
    /// NOT `200 {}` (which npm renders as a false "0 vulnerabilities").
    #[tokio::test]
    async fn test_npm_audit_upstream_5xx_returns_502() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            r#"{"lodash":["4.17.0"]}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// Review #5: the client's Authorization (its NORA token) must never be
    /// forwarded upstream — only the allowlisted headers + configured proxy_auth.
    #[tokio::test]
    async fn test_npm_audit_client_authorization_not_forwarded() {
        use crate::test_helpers::{create_test_context_with_config, send_with_headers};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            vec![("authorization", "Bearer nora-client-token")],
            r#"{"lodash":["4.17.0"]}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let reqs = upstream.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(
            reqs[0].headers.get("authorization").is_none(),
            "client Authorization must not be forwarded upstream"
        );
    }

    /// Under `anonymous_read`, an unauthenticated `npm audit` POST must pass the
    /// auth gate (audit is a read-semantics query) and reach the handler — hosted-
    /// only (no proxy) → 200 `{}`. A non-audit npm POST stays gated → 401.
    #[tokio::test]
    async fn test_npm_audit_anonymous_read_allows_post() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context_with_config(|cfg| {
            cfg.auth.enabled = true;
            cfg.auth.anonymous_read = true;
            cfg.npm.proxy = None; // hosted-only → handler returns 200 {}
        });
        let audit = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            r#"{"lodash":["4.17.0"]}"#,
        )
        .await;
        assert_eq!(
            audit.status(),
            StatusCode::OK,
            "anonymous npm audit must pass the auth gate under anonymous_read"
        );
        // A non-audit npm POST is not read-eligible → still requires auth.
        let other = send(&ctx.app, Method::POST, "/npm/somepkg", "x").await;
        assert_eq!(other.status(), StatusCode::UNAUTHORIZED);
    }

    /// #867: when a 304 revalidation finds the cached body missing (deleted by
    /// GC, retention, or corruption between the handler's `get_verified` and
    /// `refetch_metadata`'s second read), the stale `.meta` validator sidecar
    /// must be deleted so the next revalidation cycle does a full unconditional
    /// GET instead of looping on 304 forever.
    ///
    /// The handler's cache-hit gate (`get_verified`) requires the body to be
    /// present, so the GC race can't be reproduced through the HTTP layer.
    /// We call `refetch_metadata` directly with `.meta` seeded but body absent.
    #[tokio::test]
    async fn test_867_304_body_miss_clears_validators() {
        use crate::registry::{read_validators, write_validators, Validators};
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Respond 304 to any conditional request (has If-None-Match).
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.npm.metadata_ttl = 0;
            cfg.npm.revalidate = true;
            cfg.npm.serve_stale = false;
        });

        let key = "npm/ghost-pkg/metadata.json";

        // Seed validator sidecar WITHOUT the body — simulates GC/retention
        // deleting the cached body while .meta survives.
        write_validators(
            &ctx.state.storage,
            key,
            &Validators {
                etag: Some("\"stale-etag\"".to_string()),
                last_modified: None,
            },
        )
        .await;

        // Preconditions: .meta exists, body does not.
        assert!(
            read_validators(&ctx.state.storage, key).await.is_some(),
            "precondition: .meta must exist"
        );
        assert!(
            ctx.state.storage.get(key).await.is_err(),
            "precondition: body must be absent"
        );

        // Call refetch_metadata directly — simulates the race where the handler
        // entered the cache-hit path (body was present at get_verified), TTL
        // expired, but GC deleted the body before refetch_metadata re-reads it.
        let result = refetch_metadata(&ctx.state, "ghost-pkg", key).await;
        assert!(
            result.is_none(),
            "must return None when body is missing on 304"
        );

        // The critical assertion: .meta must be gone after the 304 body-miss.
        // Before the fix, `.ok()?` silently returned None but left .meta intact,
        // causing an infinite 304 loop on every subsequent TTL expiry.
        assert!(
            read_validators(&ctx.state.storage, key).await.is_none(),
            "#867: validators must be cleared after 304 body-miss to break the infinite loop"
        );
    }
}
