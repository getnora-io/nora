// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
// Production code only: tests may seed storage and build a backend. Handlers name no concrete storage backend (clippy.toml).
#![cfg_attr(not(test), deny(clippy::disallowed_types))]

pub(crate) mod ansible;
mod cargo_registry;
mod conan;
pub(crate) mod cpan;
pub(crate) mod deb;
pub mod docker;
pub mod docker_auth;
pub(crate) mod gems;
mod go;
pub(crate) mod hf;
mod maven;
pub(crate) mod npm;
pub(crate) mod nuget;
pub(crate) mod pub_dart;
mod pypi;
pub(crate) mod range;
pub(crate) mod raw;
pub(crate) mod rpm;
pub(crate) mod terraform;

// Cross-registry regression suite for namespace isolation on metadata paths (#732).
#[cfg(test)]
mod ns_isolation_metadata_tests;

pub use ansible::routes as ansible_routes;
pub(crate) use cargo_registry::canonical_crate_name;
pub use cargo_registry::rebuild_crate_name_records as rebuild_cargo_name_records;
pub use cargo_registry::routes as cargo_routes;
pub use conan::routes as conan_routes;
pub use cpan::routes as cpan_routes;
pub use deb::routes as deb_routes;
pub use docker::routes as docker_routes;
pub use docker_auth::DockerAuth;
pub use gems::routes as gems_routes;
pub use go::routes as go_routes;
pub use hf::routes as hf_routes;
pub use maven::routes as maven_routes;
pub use npm::routes as npm_routes;

// Storage-key builders reused by `nora import` so imported keys are
// byte-identical to the keys these handlers serve — GC/retention/UI browse walk
// keys as strings (review R7, contract `import-key-format-equals-handler-key-format`).
pub(crate) use maven::storage_key as maven_storage_key;
pub use nuget::alias_routes as nuget_alias_routes;
pub use nuget::routes as nuget_routes;
pub(crate) use nuget::{
    imported_package as nuget_imported_package, package_key as nuget_package_key,
    ImportedPackageError as NugetImportedPackageError,
};
pub use pub_dart::routes as pub_dart_routes;
pub use pypi::routes as pypi_routes;
pub(crate) use pypi::{
    claim_imported_project as pypi_claim_imported_project, own_file_key as pypi_own_file_key,
    record_own_file as pypi_record_own_file, record_stored_file as pypi_record_stored_file,
    storage_key as pypi_storage_key, OWN_PREFIX as PYPI_OWN_PREFIX,
};
// Retention retires a PyPI file's hash markers together with the file.
pub(crate) use pypi::HASH_MARKER_PREFIX as PYPI_HASH_MARKER_PREFIX;
pub use raw::routes as raw_routes;
pub(crate) use raw::storage_key as raw_storage_key;
pub use rpm::routes as rpm_routes;
pub use terraform::routes as terraform_routes;

use crate::circuit_breaker::{BreakerScope, CircuitBreakerRegistry};
use crate::config::UpstreamAuth;
use crate::metrics::{UPSTREAM_POLICY_BLOCKED_TOTAL, UPSTREAM_REQUEST_DURATION};
use crate::AppState;
use axum::body::{Body, Bytes};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use std::time::{Duration, Instant};

/// Remove the files directly in `dir` whose last write is at least `max_age` ago.
///
/// For the dedicated temp directories of streamed uploads and proxy fetches: a
/// transfer in progress keeps writing its file, so it never gets that old, while a
/// file orphaned by a crash (SIGKILL, OOM) or a failed commit stops changing and is
/// reaped. A missing directory is not an error. Returns how many files were removed.
pub(crate) fn remove_stale_temp_files(dir: &std::path::Path, max_age: Duration) -> u64 {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            tracing::warn!(path = %dir.display(), error = %e, "Failed to read temp directory for cleanup");
            return 0;
        }
    };
    let mut removed = 0u64;
    for entry in entries.flatten() {
        let is_stale = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= max_age);
        if is_stale && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// 405 Method Not Allowed with `Allow` header (RFC 9110 §15.5.6).
pub(crate) fn method_not_allowed(allow: &'static str) -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, allow)]).into_response()
}

/// How many JSON sidecars an index rebuild fetches from storage at once.
/// The rpm/deb rebuild runs inside every publish request; sequential reads
/// made each PUT O(repo size) in storage round-trips (~2 min per upload at
/// ~1.7k packages on GCS).
const SIDECAR_READ_CONCURRENCY: usize = 32;

/// Read and parse every JSON sidecar under `prefix`, fetching concurrently.
///
/// Returns records in arbitrary order — callers sort for deterministic
/// index output, so ordering here is free to follow fetch completion.
pub(crate) async fn read_json_sidecars<T: serde::de::DeserializeOwned>(
    storage: &crate::storage::Storage,
    prefix: &str,
) -> Result<Vec<T>, String> {
    use futures::TryStreamExt;
    let keys = storage
        .list(prefix)
        .await
        .map_err(|e| format!("list sidecars: {e}"))?;
    futures::stream::iter(keys)
        .map(|key| async move {
            let data = storage
                .get(&key)
                .await
                .map_err(|e| format!("read sidecar {key}: {e}"))?;
            serde_json::from_slice::<T>(&data).map_err(|e| format!("parse sidecar {key}: {e}"))
        })
        .buffer_unordered(SIDECAR_READ_CONCURRENCY)
        .try_collect()
        .await
}

/// Read every key under `prefix` concurrently, returning the pairs that came back.
///
/// [`read_json_sidecars`] drops the key and fails the whole batch on the first bad
/// entry, which suits an index rebuild that parses records. A packument rebuild needs
/// neither: the key *is* the version, and one unreadable version must not turn a
/// partial packument into no packument — the sequential loop this replaces skipped
/// such a key and carried on. Same concurrency, same reason: on an object store each
/// read is a network round-trip, and a package with a few thousand versions paid them
/// one at a time.
pub(crate) async fn read_keyed_blobs(
    storage: &crate::storage::Storage,
    prefix: &str,
) -> Vec<(String, axum::body::Bytes)> {
    use futures::StreamExt;
    let Ok(keys) = storage.list(prefix).await else {
        return Vec::new();
    };
    futures::stream::iter(keys)
        .map(|key| async move {
            let data = storage.get(&key).await.ok()?;
            Some((key, data))
        })
        .buffer_unordered(SIDECAR_READ_CONCURRENCY)
        .filter_map(|pair| async move { pair })
        .collect()
        .await
}

/// 409 for a write against a pull-through repo (rpm/deb `proxies` entry) —
/// its content mirrors the upstream; local publish/delete/reindex would
/// diverge from (and be clobbered by) the next upstream metadata refresh.
pub(crate) fn proxied_repo_conflict() -> Response {
    (
        StatusCode::CONFLICT,
        "Repository is a pull-through proxy (read-only)",
    )
        .into_response()
}

/// Replace `from`→`to` in raw JSON text, matching BOTH the plain form and the
/// JSON slash-escaped form (`\/`) of `from`.
///
/// Raw-text registry rewrites (ansible, nuget) `.replace()` on the unparsed
/// upstream response. A valid JSON escaping that many origins emit —
/// `"https:\/\/host\/path"` — dodges a plain `https://host/path` needle, so the
/// upstream URL survives the rewrite and leaks the host once the client's JSON
/// parser unescapes `\/`→`/` (#385, class of #377/#379/#380/#381). Handling the
/// `\/` form here closes that. NB: `\uXXXX`-escaped separators are a documented
/// residual — see `rewrite-drops-upstream-host` — caught by the runtime
/// `UPSTREAM_URL_LEAK_TOTAL` detector, not by this string pass.
pub(crate) fn replace_url_escape_aware(text: &str, from: &str, to: &str) -> String {
    let plain = text.replace(from, to);
    let esc_from = from.replace('/', "\\/");
    if !plain.contains(&esc_from) {
        return plain;
    }
    let esc_to = to.replace('/', "\\/");
    plain.replace(&esc_from, &esc_to)
}

/// Build NORA base URL from config (for URL rewriting).
///
/// Thin wrapper over [`ServerConfig::public_base_url`] — the single source of
/// truth for client-facing URLs.
pub(crate) fn nora_base_url(state: &AppState) -> String {
    state.config.server.public_base_url()
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ProxyError {
    NotFound,
    Upstream(u16),
    Network(String),
    CircuitOpen(String),
}

/// The `Authorization` value for an upstream request, built before the breaker is
/// consulted: a credential that cannot be a header is a configuration fault, not an
/// upstream outage, so it must neither reach the wire nor count toward opening the
/// breaker. Config loading rejects such tokens first (#1055); this is the backstop.
fn upstream_auth_header(
    auth: Option<UpstreamAuth<'_>>,
) -> Result<Option<reqwest::header::HeaderValue>, ProxyError> {
    auth.map(UpstreamAuth::header_value)
        .transpose()
        // `InvalidHeaderValue` displays a fixed text, never the header bytes — the
        // token cannot leak into the error (http 1.5 `header/value.rs`).
        .map_err(|e| ProxyError::Network(format!("upstream credential rejected: {e}")))
}

/// What the upstreams of a cold miss said, to answer it once every upstream was asked. A
/// miss is "not found" only when an upstream said so; when every upstream failed (5xx after
/// the retry, unreachable, breaker open) it is a gateway failure: a client that records a
/// 404 as "this artifact does not exist" (Maven) must not learn that from an outage.
/// One upstream answering "not found" decides 404 while another failed, as a group
/// repository skips a member that is down; with no upstream configured it is 404.
#[derive(Debug, Default)]
pub(crate) struct UpstreamMiss {
    not_found: bool,
    failed: bool,
}

impl UpstreamMiss {
    /// The miss of a format with a single upstream, from its one answer.
    pub(crate) fn of(e: &ProxyError) -> Self {
        let mut miss = Self::default();
        miss.record(e);
        miss
    }

    /// Record one upstream's answer. Any 4xx is an answer, even where a fetch reports it as
    /// `Upstream(4xx)` rather than `NotFound` (Docker manifests); 5xx, network errors and an
    /// open breaker are failures.
    pub(crate) fn record(&mut self, e: &ProxyError) {
        match e {
            ProxyError::NotFound => self.not_found = true,
            ProxyError::Upstream(code) if (400..500).contains(code) => self.not_found = true,
            ProxyError::Upstream(_) | ProxyError::Network(_) | ProxyError::CircuitOpen(_) => {
                self.failed = true
            }
        }
    }

    /// Record an upstream that answered without the artifact (a listing that does not name it).
    pub(crate) fn answered(&mut self) {
        self.not_found = true;
    }

    /// Fold in one upstream that was asked under several names (Docker's `library/` fallback
    /// asks it for `alpine` and `library/alpine`): it said "not found" only if it failed
    /// under none of them, since a 4xx for one name says nothing about the other.
    pub(crate) fn record_upstream(&mut self, asked: &UpstreamMiss) {
        if asked.failed {
            self.failed = true;
        } else if asked.not_found {
            self.not_found = true;
        }
    }

    /// The status for the miss: 502 when upstreams were asked and every one failed.
    pub(crate) fn status(&self) -> StatusCode {
        if self.failed && !self.not_found {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::NOT_FOUND
        }
    }

    /// The response for the miss, logging a gateway failure for the operator.
    pub(crate) fn response(&self, registry: &str, path: &str) -> Response {
        let status = self.status();
        if status == StatusCode::BAD_GATEWAY {
            tracing::warn!(registry, path, "every upstream failed, returning 502");
        }
        status.into_response()
    }
}

/// A read of a stored copy split into what it found and why it failed: `(Some, None)` the copy,
/// `(None, None)` nothing stored there, `(None, Some)` the store failed and says nothing either
/// way. A cache read may treat the last two alike; a package served only from local copies may
/// not (see [`local_copy_unreadable`]).
pub(crate) fn cached_read<T>(
    read: Result<T, crate::storage::StorageError>,
) -> (Option<T>, Option<crate::storage::StorageError>) {
    match read {
        Ok(found) => (Some(found), None),
        Err(crate::storage::StorageError::NotFound) => (None, None),
        Err(e) => (None, Some(e)),
    }
}

/// 503 for a package served only from local copies (one in an internal namespace) whose copy the
/// store could not be asked about. The package is unavailable, not absent: a 403 or a 404 here
/// sends a client with several feeds to look for the name in the next one.
pub(crate) fn storage_unavailable(registry: &str, key: &str) -> Response {
    tracing::warn!(
        registry,
        key,
        "storage cannot be read for a package served only from local copies, returning 503"
    );
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [("retry-after", "30")],
        "storage temporarily unavailable",
    )
        .into_response()
}

/// The answer for a package served only from local copies when the store failed to read its copy
/// at `key`: 500 for a copy that failed its integrity check, else [`storage_unavailable`].
pub(crate) fn local_copy_unreadable(
    registry: &str,
    key: &str,
    error: &crate::storage::StorageError,
) -> Response {
    if matches!(error, crate::storage::StorageError::IntegrityViolation) {
        tracing::error!(registry, key, "stored copy failed its integrity check");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "stored copy failed its integrity check",
        )
            .into_response();
    }
    tracing::warn!(registry, key, error = %error, "storage read failed");
    storage_unavailable(registry, key)
}

/// 503 response for circuit breaker open state with Retry-After header.
pub(crate) fn circuit_open_response(registry: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [("retry-after", "30")],
        format!("upstream {} temporarily unavailable", registry),
    )
        .into_response()
}

/// Detect a policy/geo block signature on an upstream 4xx response, returning a
/// bounded reason label (low metric cardinality) or `None` for a genuine 4xx.
///
/// Currently keys off `x-amzn-waf-reason`, which AWS CloudFront + WAF sets when a
/// rule blocks a request — a trade-control/geo rule returns it as a 404 that is
/// otherwise indistinguishable from a not-found (#881). More signatures can be
/// added here without touching the call site.
fn policy_block_reason(headers: &reqwest::header::HeaderMap) -> Option<&'static str> {
    let reason = headers.get("x-amzn-waf-reason")?;
    let is_geo = reason
        .to_str()
        .map(|v| v.eq_ignore_ascii_case("geo"))
        .unwrap_or(false);
    Some(if is_geo { "geo" } else { "waf" })
}

/// Core fetch logic with retry. Callers provide a response extractor.
#[allow(clippy::too_many_arguments)]
async fn proxy_fetch_core<T, F, Fut>(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<UpstreamAuth<'_>>,
    extra_headers: Option<(&str, &str)>,
    extract: F,
    cb: &CircuitBreakerRegistry,
    scope: impl Into<BreakerScope<'_>>,
) -> Result<T, ProxyError>
where
    F: Fn(reqwest::Response) -> Fut + Copy,
    Fut: std::future::Future<Output = Result<T, reqwest::Error>>,
{
    let auth_header = upstream_auth_header(auth)?;
    let scope = scope.into();
    let registry_str = scope.registry().as_str();
    let cb_key = scope.key();
    let probe = cb.check(&cb_key)?;

    for attempt in 0..2 {
        let mut request = client.get(url).timeout(timeout);
        if let Some(value) = &auth_header {
            request = request.header(header::AUTHORIZATION, value.clone());
        }
        if let Some((key, val)) = extra_headers {
            request = request.header(key, val);
        }

        let upstream_start = Instant::now();
        match request.send().await {
            Ok(response) => {
                let elapsed = upstream_start.elapsed().as_secs_f64();
                if response.status().is_success() {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "2xx"])
                        .observe(elapsed);
                    let result = extract(response)
                        .await
                        .map_err(|e| ProxyError::Network(e.to_string()));
                    if result.is_ok() {
                        cb.record_success(&cb_key, probe);
                    } else {
                        // 2xx but the body could not be read (e.g. a mid-stream
                        // drop) — treat as a fetch failure for the breaker.
                        cb.record_failure(&cb_key, probe);
                    }
                    return result;
                }
                let status = response.status().as_u16();
                if (400..500).contains(&status) {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "4xx"])
                        .observe(elapsed);
                    // A policy/geo block (e.g. an AWS WAF geo rule) is a 4xx that is
                    // effectively an outage dressed up as a not-found: it logs nothing,
                    // never moves the breaker, and only bumps the 4xx metric — so an
                    // operator cannot tell it apart from a genuine 404. Surface it
                    // distinctly when the response carries a block signature (#881).
                    // A plain 4xx (no signature) stays silent, exactly as before.
                    if let Some(reason) = policy_block_reason(response.headers()) {
                        UPSTREAM_POLICY_BLOCKED_TOTAL
                            .with_label_values(&[registry_str, reason])
                            .inc();
                        tracing::warn!(
                            registry = registry_str,
                            url,
                            status,
                            reason,
                            "upstream returned a policy/geo block, relayed as 404 (not a genuine not-found) — check egress/region"
                        );
                    }
                    // A 4xx means the upstream is alive and answered — not an
                    // availability failure. `record_alive` closes the breaker
                    // from HalfOpen (so it recovers instead of slow-probing) but
                    // is a no-op in Closed, so a 4xx never clears a real failure
                    // tally (#606).
                    cb.record_alive(&cb_key, probe);
                    return Err(ProxyError::NotFound);
                }
                if attempt == 0 {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "5xx"])
                        .observe(elapsed);
                    tracing::debug!(url, status, "upstream 5xx, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                UPSTREAM_REQUEST_DURATION
                    .with_label_values(&[registry_str, "5xx"])
                    .observe(elapsed);
                cb.record_failure(&cb_key, probe);
                return Err(ProxyError::Upstream(status));
            }
            Err(e) => {
                let elapsed = upstream_start.elapsed().as_secs_f64();
                let status_label = if e.is_timeout() { "timeout" } else { "error" };
                UPSTREAM_REQUEST_DURATION
                    .with_label_values(&[registry_str, status_label])
                    .observe(elapsed);
                if attempt == 0 {
                    tracing::debug!(url, error = %e, "upstream error, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                cb.record_failure(&cb_key, probe);
                return Err(ProxyError::Network(e.to_string()));
            }
        }
    }
    cb.record_failure(&cb_key, probe);
    Err(ProxyError::Network("max retries exceeded".into()))
}

/// Fetch binary content from upstream proxy with timeout and 1 retry.
pub(crate) async fn proxy_fetch(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<UpstreamAuth<'_>>,
    cb: &CircuitBreakerRegistry,
    scope: impl Into<BreakerScope<'_>>,
) -> Result<Vec<u8>, ProxyError> {
    proxy_fetch_core(
        client,
        url,
        timeout,
        auth,
        None,
        |r| async { r.bytes().await.map(|b| b.to_vec()) },
        cb,
        scope,
    )
    .await
}

/// Fetch text content from upstream proxy with timeout and 1 retry.
pub(crate) async fn proxy_fetch_text(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<UpstreamAuth<'_>>,
    extra_headers: Option<(&str, &str)>,
    cb: &CircuitBreakerRegistry,
    scope: impl Into<BreakerScope<'_>>,
) -> Result<String, ProxyError> {
    proxy_fetch_core(
        client,
        url,
        timeout,
        auth,
        extra_headers,
        |r| r.text(),
        cb,
        scope,
    )
    .await
}

/// One pull-through download for a per-repo proxied rpm/deb repository.
///
/// Shared by `rpm::download` and `deb::download` — the flow is the Maven proxy
/// flow minus name-based curation (a proxied repo is declared in config and
/// disjoint from hosted repos, so dependency-confusion gating does not apply;
/// the digest quarantine still gates immutable packages):
/// fresh-cache serve → upstream fetch → background cache → stale fallback.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn repo_proxy_download(
    state: &AppState,
    registry: &'static str,
    rt: crate::registry_type::RegistryType,
    display: String,
    key: String,
    url: String,
    auth: Option<UpstreamAuth<'_>>,
    timeout_secs: u64,
    metadata_ttl: i64,
    immutable: bool,
    content_type: &'static str,
) -> Response {
    use crate::activity_log::{ActionType, ActivityEntry};
    use crate::audit::AuditEntry;

    let q_override = match registry {
        "rpm" => &state.config.curation.rpm,
        _ => &state.config.curation.deb,
    };
    let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
        q_override
            .quarantine
            .as_ref()
            .or(state.config.curation.quarantine.as_ref()),
        q_override
            .quarantine_ttl
            .as_deref()
            .or(state.config.curation.quarantine_ttl.as_deref()),
    );

    let serve = |data: Bytes| {
        let mut builder = axum::http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type);
        if !immutable {
            builder = builder.header(header::CACHE_CONTROL, "no-cache");
        }
        builder.body(Body::from(data)).expect("valid response")
    };

    let cached = state.storage.get(&key).await.ok();
    let cache_fresh = match &cached {
        None => false,
        Some(_) if immutable => true,
        Some(_) => {
            let modified = state.storage.stat(&key).await.map(|m| m.modified);
            crate::cache_ttl::mutable_ref_fresh(true, metadata_ttl, modified)
        }
    };

    if let Some(ref data) = cached {
        if cache_fresh {
            state.metrics.record_download(registry);
            state.metrics.record_cache_hit(registry);
            state.activity.push(ActivityEntry::new(
                ActionType::CacheHit,
                display,
                rt,
                "CACHE",
            ));
            state
                .audit
                .log(AuditEntry::new("cache_hit", "proxy", "", registry, ""));
            // Quarantine only immutable packages — metadata is rewritten
            // upstream on every sync and its digest would change forever.
            if immutable {
                if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                    &state.digest_store,
                    registry,
                    data,
                    &q_mode,
                    q_secs,
                    "cache",
                    None,
                ) {
                    return resp;
                }
            }
            return serve(data.clone()).into_response();
        }
    }

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(timeout_secs),
        auth,
        &state.circuit_breaker,
        rt,
    )
    .await
    {
        Ok(data) => {
            let data = Bytes::from(data);
            state.metrics.record_download(registry);
            state.metrics.record_cache_miss(registry);
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                display,
                rt,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", registry, ""));
            if immutable {
                state.spawn_cache_immutable(registry, key, data.clone());
                if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                    &state.digest_store,
                    registry,
                    &data,
                    &q_mode,
                    q_secs,
                    &url,
                    None,
                ) {
                    return resp;
                }
            } else {
                state.spawn_cache(registry, key, data.clone());
            }
            serve(data).into_response()
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            // Upstream failed — serve the stale cached copy if we have one.
            if let Some(data) = cached {
                tracing::warn!(registry, url = %url, error = ?e, "upstream failed, serving stale cached copy");
                if immutable {
                    if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                        &state.digest_store,
                        registry,
                        &data,
                        &q_mode,
                        q_secs,
                        "cache-stale",
                        None,
                    ) {
                        return resp;
                    }
                }
                let mut response = serve(data).into_response();
                response.headers_mut().insert(
                    header::HeaderName::from_static("x-nora-stale"),
                    header::HeaderValue::from_static("true"),
                );
                return response;
            }
            tracing::debug!(registry, url = %url, error = ?e, "proxy fetch failed with no cached copy");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

/// Forward a POST (request body + an allowlist of headers) to an upstream and
/// return its `(status, body, content-type)` verbatim. Mirrors `proxy_fetch_core`'s
/// circuit-breaker discipline (`check` → send → `record_success`/`record_alive`/
/// `record_failure`, one retry on 5xx/network).
///
/// Used for `npm audit` (#597): a query POST that must return the upstream's answer
/// as-is — including a 4xx (a real audit response, upstream is alive) — with only
/// 5xx / network / circuit-open surfaced as `ProxyError`.
///
/// `auth` is the configured proxy credential (Basic or Bearer); the caller's own
/// `Authorization` is never forwarded — pass only the intended headers in
/// `fwd_headers` (allowlist). The body is not inspected or decompressed here.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_forward_post(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<UpstreamAuth<'_>>,
    fwd_headers: &[(&str, &str)],
    body: &[u8],
    cb: &CircuitBreakerRegistry,
    scope: impl Into<BreakerScope<'_>>,
) -> Result<(u16, Vec<u8>, Option<String>), ProxyError> {
    let auth_header = upstream_auth_header(auth)?;
    let scope = scope.into();
    let registry_str = scope.registry().as_str();
    let cb_key = scope.key();
    let probe = cb.check(&cb_key)?;

    for attempt in 0..2 {
        let mut request = client.post(url).timeout(timeout).body(body.to_vec());
        if let Some(value) = &auth_header {
            request = request.header(header::AUTHORIZATION, value.clone());
        }
        for (k, v) in fwd_headers {
            request = request.header(*k, *v);
        }

        let upstream_start = Instant::now();
        match request.send().await {
            Ok(response) => {
                let elapsed = upstream_start.elapsed().as_secs_f64();
                let code = response.status().as_u16();
                let content_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                if response.status().is_success() {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "2xx"])
                        .observe(elapsed);
                    match response.bytes().await {
                        Ok(b) => {
                            cb.record_success(&cb_key, probe);
                            return Ok((code, b.to_vec(), content_type));
                        }
                        Err(e) => {
                            cb.record_failure(&cb_key, probe);
                            return Err(ProxyError::Network(e.to_string()));
                        }
                    }
                }
                if (400..500).contains(&code) {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "4xx"])
                        .observe(elapsed);
                    // Upstream is alive and answered — a 4xx audit response is a real
                    // answer, forward it verbatim (not an availability failure). #606.
                    cb.record_alive(&cb_key, probe);
                    let b = response
                        .bytes()
                        .await
                        .map(|b| b.to_vec())
                        .unwrap_or_default();
                    return Ok((code, b, content_type));
                }
                UPSTREAM_REQUEST_DURATION
                    .with_label_values(&[registry_str, "5xx"])
                    .observe(elapsed);
                if attempt == 0 {
                    tracing::debug!(url, status = code, "upstream 5xx on POST, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                cb.record_failure(&cb_key, probe);
                return Err(ProxyError::Upstream(code));
            }
            Err(e) => {
                let elapsed = upstream_start.elapsed().as_secs_f64();
                let status_label = if e.is_timeout() { "timeout" } else { "error" };
                UPSTREAM_REQUEST_DURATION
                    .with_label_values(&[registry_str, status_label])
                    .observe(elapsed);
                if attempt == 0 {
                    tracing::debug!(url, error = %e, "upstream error on POST, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                cb.record_failure(&cb_key, probe);
                return Err(ProxyError::Network(e.to_string()));
            }
        }
    }
    cb.record_failure(&cb_key, probe);
    Err(ProxyError::Network("max retries exceeded".into()))
}

// ============================================================================
// Streaming upload helpers (shared by docker blob uploads and raw uploads)
// ============================================================================

/// Outcome of streaming a request body to a temp file with a byte budget.
pub(crate) enum StreamOutcome {
    /// Wrote N bytes successfully.
    Ok(u64),
    /// Budget exceeded — aborted before writing the offending frame (413).
    TooLarge,
    /// Request-body stream errored mid-flight (client disconnect).
    ClientGone,
    /// Local write/flush failure (500).
    Io(std::io::Error),
}

/// Stream `body` into `file`, bounded to `budget` bytes, never holding more than
/// one frame in RAM (#817). The running total is checked BEFORE each write, so at
/// most `budget` bytes ever reach disk — a request over budget aborts without
/// writing the offending frame.
///
/// CANCEL-SAFETY: a pure per-frame read→write loop with no lock held and no
/// shared state mutated. If the future is dropped mid-stream, the partially
/// written file is reclaimed by the caller's `TempFileGuard`; nothing is left
/// half-set.
pub(crate) async fn stream_body_to_file(
    body: Body,
    file: &mut tokio::fs::File,
    budget: u64,
) -> StreamOutcome {
    use tokio::io::AsyncWriteExt;
    let mut stream = body.into_data_stream();
    let mut written: u64 = 0;
    while let Some(frame) = stream.next().await {
        let chunk = match frame {
            Ok(c) => c,
            Err(_) => return StreamOutcome::ClientGone,
        };
        written = written.saturating_add(chunk.len() as u64);
        if written > budget {
            return StreamOutcome::TooLarge;
        }
        if let Err(e) = file.write_all(&chunk).await {
            return StreamOutcome::Io(e);
        }
    }
    if let Err(e) = file.flush().await {
        return StreamOutcome::Io(e);
    }
    // Durability: put_from_path's direct-rename commit relies on the caller
    // having fsync'd the source — without this, a power loss just after the
    // rename can leave the key's directory entry pointing at data that never
    // reached disk (latent for docker since the switch to streaming; #846).
    if let Err(e) = file.sync_all().await {
        return StreamOutcome::Io(e);
    }
    // Postcondition: a successful stream never exceeds the budget — the loop
    // returns TooLarge before writing any frame that would cross it.
    debug_assert!(
        written <= budget,
        "stream_body_to_file wrote {written} bytes > budget {budget}"
    );
    StreamOutcome::Ok(written)
}

/// Parse the `Content-Length` header, if present and well-formed.
pub(crate) fn content_length(headers: &axum::http::HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

/// RAII: delete a temp file on drop unless disarmed.
///
/// Ensures temp files are cleaned up on ALL error paths (network errors,
/// hash mismatch, panics, early returns via `?` operator) — #580.
pub(crate) struct TempFileGuard {
    path: Option<std::path::PathBuf>,
}

impl TempFileGuard {
    pub(crate) fn new(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Disarm the guard — caller takes ownership of cleanup.
    /// Call this after successful `put_from_path` (which moves/deletes the file).
    pub(crate) fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// sha256 of a file's contents, read in 256 KiB chunks — used to hash a
/// streamed upload without ever holding the body in memory.
pub(crate) async fn sha256_of_file(path: &std::path::Path) -> std::io::Result<String> {
    use sha2::Digest;
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path).await?;
    let mut reader = tokio::io::BufReader::new(file);
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match reader.read(&mut buf).await? {
            0 => break,
            n => hasher.update(&buf[..n]),
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

// ============================================================================
// Conditional revalidation (#596)
// ============================================================================

/// Upstream cache validators persisted next to a cached object so a later
/// revalidation can send `If-None-Match` / `If-Modified-Since`. Stored as a
/// `<key>.meta` JSON sidecar — filesystem-first, survives restarts (ADR-2).
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Validators {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

impl Validators {
    /// True if at least one validator is present to drive a conditional request.
    pub fn is_some(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }
}

/// Outcome of a conditional upstream request.
pub(crate) enum Revalidation {
    /// Upstream answered `304 Not Modified` — the cached body is still valid.
    NotModified,
    /// Upstream answered `200` with a (possibly) new body and fresh validators.
    Modified {
        body: Vec<u8>,
        validators: Validators,
    },
}

/// Storage key of the validator sidecar for a cached object.
pub(crate) fn validators_key(key: &str) -> String {
    format!("{key}.meta")
}

/// Read the stored upstream validators for `key`, if any. Fail-open: any
/// read/parse error yields `None` (caller does a full fetch).
pub(crate) async fn read_validators(storage: &crate::Storage, key: &str) -> Option<Validators> {
    let data = storage.get(&validators_key(key)).await.ok()?;
    serde_json::from_slice::<Validators>(&data).ok()
}

/// Persist upstream validators next to `key`. Written AFTER the body so a
/// sidecar never advertises freshness for a body that is not there. A no-op
/// when there is nothing to store.
pub(crate) async fn write_validators(storage: &crate::Storage, key: &str, v: &Validators) {
    if !v.is_some() {
        return;
    }
    if let Ok(data) = serde_json::to_vec(v) {
        if let Err(e) = storage.put(&validators_key(key), &data).await {
            tracing::warn!(key = %key, error = ?e, "failed to write validator sidecar");
        }
    }
}

fn header_string(resp: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Conditional upstream fetch (#596). Sends `If-None-Match`/`If-Modified-Since`
/// from `validators`; returns `NotModified` on 304 (no body downloaded) or
/// `Modified { body, validators }` on 200. With empty `validators` it sends no
/// conditional headers, so it always yields `Modified` — that is how the full
/// fetch path captures validators for the first time.
///
/// Circuit breaker: 304/200 record success; transport/5xx and a 200 whose body
/// cannot be read record failure; 4xx returns `NotFound` (matching
/// `proxy_fetch_core`). No retry — revalidation is a lightweight check and the
/// caller falls back to a full fetch on error.
pub(crate) async fn proxy_fetch_conditional(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<UpstreamAuth<'_>>,
    validators: &Validators,
    cb: &CircuitBreakerRegistry,
    scope: impl Into<BreakerScope<'_>>,
) -> Result<Revalidation, ProxyError> {
    let auth_header = upstream_auth_header(auth)?;
    let cb_key = scope.into().key();
    let probe = cb.check(&cb_key)?;

    let mut request = client.get(url).timeout(timeout);
    if let Some(value) = auth_header {
        request = request.header(header::AUTHORIZATION, value);
    }
    if let Some(ref etag) = validators.etag {
        request = request.header(header::IF_NONE_MATCH, etag);
    }
    if let Some(ref lm) = validators.last_modified {
        request = request.header(header::IF_MODIFIED_SINCE, lm);
    }

    match request.send().await {
        Ok(response) => {
            let status = response.status();
            if status == reqwest::StatusCode::NOT_MODIFIED {
                cb.record_success(&cb_key, probe);
                return Ok(Revalidation::NotModified);
            }
            if status.is_success() {
                let new_validators = Validators {
                    etag: header_string(&response, header::ETAG),
                    last_modified: header_string(&response, header::LAST_MODIFIED),
                };
                return match response.bytes().await {
                    Ok(body) => {
                        cb.record_success(&cb_key, probe);
                        Ok(Revalidation::Modified {
                            body: body.to_vec(),
                            validators: new_validators,
                        })
                    }
                    Err(e) => {
                        // 2xx but the body could not be read (e.g. a mid-stream
                        // drop) — a fetch failure for the breaker, as in
                        // proxy_fetch_core; unreported, a half-open probe would
                        // hold its slot until the #585 stall recovery.
                        cb.record_failure(&cb_key, probe);
                        Err(ProxyError::Network(e.to_string()))
                    }
                };
            }
            let code = status.as_u16();
            if (400..500).contains(&code) {
                // 4xx — upstream alive; recover the breaker without clearing a
                // real failure tally, consistent with proxy_fetch_core (#606).
                cb.record_alive(&cb_key, probe);
                return Err(ProxyError::NotFound);
            }
            cb.record_failure(&cb_key, probe);
            Err(ProxyError::Upstream(code))
        }
        Err(e) => {
            cb.record_failure(&cb_key, probe);
            Err(ProxyError::Network(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_type::RegistryType;

    /// 404 only when an upstream said "not found"; 502 when upstreams were asked and every
    /// one failed; 404 with no upstream at all.
    #[test]
    fn a_miss_is_not_found_only_when_an_upstream_said_so() {
        use axum::http::StatusCode;
        let miss = |answers: &[ProxyError]| {
            let mut m = UpstreamMiss::default();
            for a in answers {
                m.record(a);
            }
            m.status()
        };
        let down = || ProxyError::Upstream(503);
        let unreachable = || ProxyError::Network("refused".into());
        let open = || ProxyError::CircuitOpen("maven".into());
        assert_eq!(miss(&[]), StatusCode::NOT_FOUND);
        assert_eq!(miss(&[ProxyError::NotFound]), StatusCode::NOT_FOUND);
        assert_eq!(miss(&[ProxyError::Upstream(401)]), StatusCode::NOT_FOUND);
        assert_eq!(miss(&[ProxyError::Upstream(499)]), StatusCode::NOT_FOUND);
        assert_eq!(miss(&[ProxyError::Upstream(500)]), StatusCode::BAD_GATEWAY);
        assert_eq!(miss(&[ProxyError::Upstream(399)]), StatusCode::BAD_GATEWAY);
        assert_eq!(miss(&[down()]), StatusCode::BAD_GATEWAY);
        assert_eq!(miss(&[unreachable()]), StatusCode::BAD_GATEWAY);
        assert_eq!(miss(&[open()]), StatusCode::BAD_GATEWAY);
        assert_eq!(miss(&[down(), unreachable()]), StatusCode::BAD_GATEWAY);
        assert_eq!(miss(&[down(), ProxyError::NotFound]), StatusCode::NOT_FOUND);
        assert_eq!(miss(&[ProxyError::NotFound, down()]), StatusCode::NOT_FOUND);

        // One upstream asked under two names: not found under one and failed under the
        // other is a failed upstream; another upstream's "not found" still decides 404.
        let asked = |answers: &[ProxyError]| {
            let mut m = UpstreamMiss::default();
            for a in answers {
                m.record(a);
            }
            m
        };
        let folded = |upstreams: &[UpstreamMiss]| {
            let mut m = UpstreamMiss::default();
            for u in upstreams {
                m.record_upstream(u);
            }
            m.status()
        };
        let hub = asked(&[ProxyError::NotFound, down()]);
        let gone = asked(&[ProxyError::NotFound, ProxyError::NotFound]);
        assert_eq!(folded(&[]), StatusCode::NOT_FOUND);
        assert_eq!(folded(&[asked(&[])]), StatusCode::NOT_FOUND);
        assert_eq!(
            folded(&[asked(&[ProxyError::NotFound, down()])]),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(folded(&[gone]), StatusCode::NOT_FOUND);
        assert_eq!(
            folded(&[hub, asked(&[ProxyError::NotFound])]),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn test_proxy_fetch_invalid_url() {
        let client = reqwest::Client::new();
        let cb = crate::circuit_breaker::CircuitBreakerRegistry::new(
            crate::config::CircuitBreakerConfig::default(),
        );
        let result = proxy_fetch(
            &client,
            "http://127.0.0.1:1/nonexistent",
            Duration::from_secs(2),
            None,
            &cb,
            RegistryType::Docker, // arbitrary variant, testing proxy logic not registry type
        )
        .await;
        assert!(matches!(result, Err(ProxyError::Network(_))));
    }

    // --- Policy/geo upstream block observability (#881) ---

    #[test]
    fn policy_block_reason_detects_waf_geo() {
        use reqwest::header::HeaderMap;
        let mut geo = HeaderMap::new();
        geo.insert("x-amzn-waf-reason", "geo".parse().unwrap());
        assert_eq!(policy_block_reason(&geo), Some("geo"));

        let mut other = HeaderMap::new();
        other.insert("x-amzn-waf-reason", "rate-based".parse().unwrap());
        assert_eq!(policy_block_reason(&other), Some("waf"));

        // A genuine 4xx (no WAF signature) is not a policy block.
        assert_eq!(policy_block_reason(&HeaderMap::new()), None);
    }

    /// A geo-blocked upstream 4xx (WAF `x-amzn-waf-reason: geo`) bumps the policy-block
    /// metric and is still relayed as `NotFound`; a plain 4xx does neither (#881).
    #[tokio::test]
    async fn upstream_waf_geo_block_surfaced_but_plain_4xx_silent() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Geo-blocked upstream: 404 + x-amzn-waf-reason: geo.
        let blocked = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404).insert_header("x-amzn-waf-reason", "geo"))
            .mount(&blocked)
            .await;
        let reg = RegistryType::Terraform;
        let before = UPSTREAM_POLICY_BLOCKED_TOTAL
            .with_label_values(&[reg.as_str(), "geo"])
            .get();
        let r = proxy_fetch_text(
            &reqwest::Client::new(),
            &blocked.uri(),
            Duration::from_secs(5),
            None,
            None,
            &noop_cb(),
            reg,
        )
        .await;
        assert!(matches!(r, Err(ProxyError::NotFound)));
        assert_eq!(
            UPSTREAM_POLICY_BLOCKED_TOTAL
                .with_label_values(&[reg.as_str(), "geo"])
                .get(),
            before + 1,
            "a WAF geo 4xx must bump the policy-block metric"
        );

        // Control: a plain 404 (no WAF signature) must NOT bump the metric.
        let plain = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&plain)
            .await;
        let reg2 = RegistryType::Cargo;
        let before2 = UPSTREAM_POLICY_BLOCKED_TOTAL
            .with_label_values(&[reg2.as_str(), "geo"])
            .get();
        let r2 = proxy_fetch_text(
            &reqwest::Client::new(),
            &plain.uri(),
            Duration::from_secs(5),
            None,
            None,
            &noop_cb(),
            reg2,
        )
        .await;
        assert!(matches!(r2, Err(ProxyError::NotFound)));
        assert_eq!(
            UPSTREAM_POLICY_BLOCKED_TOTAL
                .with_label_values(&[reg2.as_str(), "geo"])
                .get(),
            before2,
            "a plain 4xx must NOT bump the policy-block metric"
        );
    }

    // --- Conditional revalidation (#596) ---

    fn noop_cb() -> CircuitBreakerRegistry {
        CircuitBreakerRegistry::new(crate::config::CircuitBreakerConfig::default())
    }

    /// With no stored validators, the conditional fetch sends no `If-None-Match`,
    /// always gets a 200, and captures the upstream validators (this is also the
    /// full-fetch path that seeds the sidecar for next time).
    #[tokio::test]
    async fn conditional_200_captures_validators() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"v1\"")
                    .set_body_string("BODY-V1"),
            )
            .mount(&upstream)
            .await;

        let cb = noop_cb();
        let out = proxy_fetch_conditional(
            &reqwest::Client::new(),
            &upstream.uri(),
            Duration::from_secs(5),
            None,
            &Validators::default(),
            &cb,
            RegistryType::Npm,
        )
        .await
        .unwrap();

        match out {
            Revalidation::Modified { body, validators } => {
                assert_eq!(body, b"BODY-V1");
                assert_eq!(validators.etag.as_deref(), Some("\"v1\""));
            }
            Revalidation::NotModified => panic!("expected Modified"),
        }
    }

    /// When validators are present they are sent as `If-None-Match`, and a 304
    /// yields `NotModified` with NO body download. The mock only answers 304 when
    /// the header is present, so a pass proves the header was sent.
    #[tokio::test]
    async fn conditional_304_sends_if_none_match_and_returns_not_modified() {
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;

        let validators = Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        };
        let cb = noop_cb();
        let out = proxy_fetch_conditional(
            &reqwest::Client::new(),
            &upstream.uri(),
            Duration::from_secs(5),
            None,
            &validators,
            &cb,
            RegistryType::Npm,
        )
        .await
        .unwrap();

        assert!(matches!(out, Revalidation::NotModified));
    }

    /// Run one half-open probe through `proxy_fetch_conditional` against an
    /// upstream that answers with a 200 declaring `declared_len` bytes, writes
    /// `body`, and hangs up — with `declared_len > body.len()` the body breaks off
    /// mid-stream. The breaker (threshold 1, reset 1 h, so the #585 stall
    /// recovery cannot release the slot during the test) is tripped and its open
    /// timer backdated first, so the call IS the probe.
    async fn conditional_half_open_probe(
        cb: &CircuitBreakerRegistry,
        declared_len: usize,
        body: &[u8],
    ) -> Result<Revalidation, ProxyError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let serve_once = async {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 4096];
            let _ = sock.read(&mut req).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {declared_len}\r\nconnection: close\r\n\r\n"
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.shutdown().await;
        };

        cb.record_failure("npm", crate::circuit_breaker::ProbeToken::BACKGROUND);
        cb.expire_open_for_test("npm");
        let client = reqwest::Client::new();
        let validators = Validators::default();
        let fetch = proxy_fetch_conditional(
            &client,
            &upstream,
            Duration::from_secs(5),
            None,
            &validators,
            cb,
            RegistryType::Npm,
        );
        let ((), out) = tokio::join!(serve_once, fetch);
        out
    }

    fn half_open_test_cb() -> CircuitBreakerRegistry {
        CircuitBreakerRegistry::new(crate::config::CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            reset_timeout: 3600,
            overrides: std::collections::HashMap::new(),
        })
    }

    /// A half-open probe that gets a 200 whose body breaks off must report back
    /// as a failure, exactly like `proxy_fetch_core` ("2xx but the body could not
    /// be read"). Unreported, the probe slot stays held, and every request is
    /// rejected with CircuitOpen until the #585 stall recovery (reset_timeout)
    /// gives up on it.
    #[tokio::test]
    async fn conditional_truncated_200_returns_the_probe_as_a_failure() {
        let cb = half_open_test_cb();

        match conditional_half_open_probe(&cb, 64, b"only-part-of-the-body").await {
            Err(ProxyError::Network(_)) => {}
            Err(e) => panic!("a broken-off body is a network error, got {e:?}"),
            Ok(_) => panic!("a broken-off body must not be returned as a revalidation"),
        }

        // The breaker counted the failed probe: back to Open, not stuck HalfOpen.
        let health = cb.health_snapshot("npm").expect("breaker recorded");
        assert_eq!(
            health.status, "open",
            "the failed probe must re-open the breaker"
        );

        // The probe slot came back: once the open timer runs out, a new probe is
        // granted. A probe that never reported keeps the slot and this check is
        // CircuitOpen for the whole reset_timeout.
        cb.expire_open_for_test("npm");
        assert!(
            cb.check("npm").is_ok(),
            "the probe slot must be released, not held by the lost probe"
        );
    }

    /// Control for the harness above: the same raw upstream with a complete body
    /// is a successful probe that closes the breaker, so the failure above comes
    /// from the broken-off body and not from the harness.
    #[tokio::test]
    async fn conditional_complete_200_closes_the_half_open_breaker() {
        let body: &[u8] = b"the-whole-body";
        let cb = half_open_test_cb();

        match conditional_half_open_probe(&cb, body.len(), body).await {
            Ok(Revalidation::Modified { body: got, .. }) => assert_eq!(got, body),
            Ok(Revalidation::NotModified) => panic!("expected Modified, got NotModified"),
            Err(e) => panic!("expected Modified, got {e:?}"),
        }
        assert_eq!(cb.health_snapshot("npm").unwrap().status, "closed");
    }

    /// Every shared upstream helper sends the credential with its own scheme (#1055).
    /// The mock answers only when the exact `Authorization` value arrives, so each
    /// `Ok` proves the header went out as `Bearer <token>` / `Basic <b64>` — a helper
    /// that dropped the header or forced Basic would get a 404 instead.
    #[tokio::test]
    async fn every_upstream_helper_sends_the_configured_scheme() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for (auth, expected) in [
            (UpstreamAuth::Bearer("npm_tok-1"), "Bearer npm_tok-1"),
            (UpstreamAuth::Basic("user:pass"), "Basic dXNlcjpwYXNz"),
        ] {
            let upstream = MockServer::start().await;
            Mock::given(method("GET"))
                .and(header("authorization", expected))
                .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
                .mount(&upstream)
                .await;
            Mock::given(method("POST"))
                .and(header("authorization", expected))
                .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
                .mount(&upstream)
                .await;
            let client = reqwest::Client::new();
            let cb = noop_cb();
            let url = upstream.uri();
            let t = Duration::from_secs(5);

            let bytes = proxy_fetch(&client, &url, t, Some(auth), &cb, RegistryType::Npm).await;
            assert_eq!(bytes.unwrap(), b"ok", "proxy_fetch with {expected}");

            let text =
                proxy_fetch_text(&client, &url, t, Some(auth), None, &cb, RegistryType::Npm).await;
            assert_eq!(text.unwrap(), "ok", "proxy_fetch_text with {expected}");

            let cond = proxy_fetch_conditional(
                &client,
                &url,
                t,
                Some(auth),
                &Validators::default(),
                &cb,
                RegistryType::Npm,
            )
            .await;
            assert!(
                matches!(cond, Ok(Revalidation::Modified { .. })),
                "proxy_fetch_conditional with {expected}"
            );

            let post = proxy_forward_post(
                &client,
                &url,
                t,
                Some(auth),
                &[],
                b"{}",
                &cb,
                RegistryType::Npm,
            )
            .await;
            assert_eq!(post.unwrap().0, 200, "proxy_forward_post with {expected}");
        }
    }

    /// A credential that cannot be a header never reaches the wire and is not an
    /// upstream outage: with a breaker that opens on the first failure, repeated
    /// bad-credential calls leave it closed. Control: one real network failure under
    /// the same config does open it, so the config is live and the test not vacuous.
    #[tokio::test]
    async fn invalid_credential_neither_sent_nor_counted_by_breaker() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&upstream)
            .await;
        let client = reqwest::Client::new();
        let t = Duration::from_secs(5);
        let strict = || {
            CircuitBreakerRegistry::new(crate::config::CircuitBreakerConfig {
                enabled: true,
                failure_threshold: 1,
                reset_timeout: 300,
                overrides: Default::default(),
            })
        };

        let cb = strict();
        for _ in 0..3 {
            let bad = proxy_fetch(
                &client,
                &upstream.uri(),
                t,
                Some(UpstreamAuth::Bearer("tok\n")),
                &cb,
                RegistryType::Npm,
            )
            .await;
            assert!(matches!(bad, Err(ProxyError::Network(_))));
        }
        let requests = upstream.received_requests().await.unwrap();
        assert!(
            requests.is_empty(),
            "a bad credential must not reach the upstream"
        );
        let good = proxy_fetch(&client, &upstream.uri(), t, None, &cb, RegistryType::Npm).await;
        assert_eq!(good.unwrap(), b"ok", "breaker must still be closed");

        // Control: a genuine transport failure opens the same strict breaker.
        let cb = strict();
        let refused = proxy_fetch(
            &client,
            "http://127.0.0.1:1/x",
            t,
            None,
            &cb,
            RegistryType::Npm,
        )
        .await;
        assert!(matches!(refused, Err(ProxyError::Network(_))));
        let after = proxy_fetch(&client, &upstream.uri(), t, None, &cb, RegistryType::Npm).await;
        assert!(
            matches!(after, Err(ProxyError::CircuitOpen(_))),
            "control: breaker opens"
        );
    }

    /// Validators round-trip through storage (the sidecar lives on disk, so they
    /// survive a restart) — acceptance criterion for #596.
    #[tokio::test]
    async fn validators_sidecar_roundtrips_through_storage() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = crate::Storage::new_local(dir.path().to_str().unwrap());

        // No body yet, but the sidecar is just another key — write then read.
        let key = "npm/pkg/metadata.json";
        let v = Validators {
            etag: Some("\"abc\"".to_string()),
            last_modified: Some("Wed, 21 Oct 2026 07:28:00 GMT".to_string()),
        };
        write_validators(&storage, key, &v).await;

        // Fresh Storage over the same dir = "after restart".
        let reloaded = crate::Storage::new_local(dir.path().to_str().unwrap());
        let got = read_validators(&reloaded, key)
            .await
            .expect("sidecar persists");
        assert_eq!(got, v);
        assert_eq!(validators_key(key), "npm/pkg/metadata.json.meta");
    }

    /// An empty validator set writes no sidecar (nothing to persist).
    #[tokio::test]
    async fn empty_validators_write_no_sidecar() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = crate::Storage::new_local(dir.path().to_str().unwrap());
        write_validators(&storage, "npm/x/metadata.json", &Validators::default()).await;
        assert!(read_validators(&storage, "npm/x/metadata.json")
            .await
            .is_none());
    }

    /// What the router hands a handler for paths with empty segments (axum 0.8 / matchit 0.8):
    /// a `{param}` followed by a literal `/` matches an EMPTY segment; `Path` percent-decodes,
    /// so `%2F` puts `/` inside a single `{param}`; `{*rest}` keeps `//`, a leading `/` and a
    /// trailing `/`; nothing normalizes. Every handler must refuse such names itself.
    #[tokio::test]
    async fn the_router_hands_empty_segments_to_handlers_as_sent() {
        use crate::test_helpers::{body_bytes, send};
        use axum::extract::Path;
        use axum::http::{Method, StatusCode};
        use axum::routing::get;

        async fn one(Path(p): Path<String>) -> String {
            format!("[{p}]")
        }
        async fn two(Path((a, b)): Path<(String, String)>) -> String {
            format!("[{a}][{b}]")
        }
        let app: axum::Router = axum::Router::new()
            .route("/simple/{name}/", get(one))
            .route("/simple/{name}/{filename}", get(two))
            .route("/gems/info/{name}", get(one))
            .route("/w/{*path}", get(one))
            .route("/r/{repo}/{*path}", get(two));
        let cases = [
            ("/simple//", Some("[]")),
            ("/simple//x", Some("[][x]")),
            ("/simple/foo%2F/", Some("[foo/]")),
            ("/simple/%2Ffoo/x", Some("[/foo][x]")),
            ("/gems/info/", None),
            ("/gems/info/x%2F%2Fy", Some("[x//y]")),
            ("/w/a//b", Some("[a//b]")),
            ("/w//a", Some("[/a]")),
            ("/w/a/b/", Some("[a/b/]")),
            ("/w/a%2F%2Fb", Some("[a//b]")),
            ("/r//x", Some("[][x]")),
            ("/r/a//b", Some("[a][/b]")),
        ];
        for (uri, want) in cases {
            let resp = send(&app, Method::GET, uri, axum::body::Body::empty()).await;
            match want {
                Some(body) => {
                    assert_eq!(resp.status(), StatusCode::OK, "{uri}");
                    assert_eq!(&body_bytes(resp).await[..], body.as_bytes(), "{uri}");
                }
                None => assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}"),
            }
        }
    }
}

/// An allowlist entry that pins an artifact's SHA-256 refuses other bytes on the first download
/// from the upstream, in every format that checks it on a cache hit: the pin is the operator's
/// statement of what the artifact is, and the first client (often CI) is the one it protects.
#[cfg(test)]
mod first_download_integrity {
    #![allow(clippy::unwrap_used)]

    use crate::config::{Config, CurationMode, MavenProxyEntry};
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use sha2::Digest;
    use wiremock::matchers::{any, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SERVED: &[u8] = b"TAMPERED";

    /// An upstream that answers every request with bytes other than the pinned ones.
    async fn upstream() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(SERVED.to_vec()))
            .mount(&server)
            .await;
        server
    }

    /// Requests `uri` twice under an allowlist that pins `name@version` to the SHA-256 of
    /// b"GOOD"; both answers are 403 and neither carries the upstream's bytes.
    async fn refused(
        server: &MockServer,
        registry: &str,
        name: &str,
        version: &str,
        uri: &str,
        configure: fn(&mut Config, String),
    ) {
        let entries = serde_json::json!([
            {"registry": registry, "name": name, "version": version, "integrity": pinned()}
        ]);
        refused_entries(server, registry, entries, uri, configure).await;
    }

    fn pinned() -> String {
        format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"GOOD")))
    }

    /// A context in enforce mode with an allowlist of `entries`, its upstream at `url`.
    fn enforced(
        entries: serde_json::Value,
        url: String,
        configure: fn(&mut Config, String),
    ) -> crate::test_helpers::TestContext {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            serde_json::json!({"version": 1, "entries": entries}).to_string(),
        )
        .unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        // The allowlist is read when the context is built; the directory may go after that.
        let ctx = create_test_context_with_config(move |cfg| {
            configure(cfg, url);
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        drop(dir);
        ctx
    }

    async fn refused_entries(
        server: &MockServer,
        registry: &str,
        entries: serde_json::Value,
        uri: &str,
        configure: fn(&mut Config, String),
    ) {
        let ctx = enforced(entries, server.uri(), configure);
        for attempt in ["first download", "second download"] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            let status = resp.status();
            let body = body_bytes(resp).await;
            assert!(
                !body.windows(SERVED.len()).any(|w| w == SERVED),
                "{registry} {attempt}: the upstream's bytes were served"
            );
            assert_eq!(status, StatusCode::FORBIDDEN, "{registry} {attempt}");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    async fn maven() {
        let s = upstream().await;
        let uri = "/maven2/com/corp/lib/1.0.0/lib-1.0.0.jar";
        refused(&s, "maven", "com.corp:lib", "1.0.0", uri, |c, u| {
            c.maven.proxies = vec![MavenProxyEntry::Simple(u)];
        })
        .await;
    }

    #[tokio::test]
    async fn cargo() {
        let s = upstream().await;
        let uri = "/cargo/api/v1/crates/corp-lib/1.0.0/download";
        refused(&s, "cargo", "corp-lib", "1.0.0", uri, |c, u| {
            c.cargo.proxy = Some(u);
        })
        .await;
    }

    #[tokio::test]
    async fn npm() {
        let s = upstream().await;
        let uri = "/npm/corp-lib/-/corp-lib-1.0.0.tgz";
        refused(&s, "npm", "corp-lib", "1.0.0", uri, |c, u| {
            c.npm.proxy = Some(u);
        })
        .await;
    }

    #[tokio::test]
    async fn pypi() {
        let s = MockServer::start().await;
        let file = format!("{}/files/corp_lib-1.0.0.tar.gz", s.uri());
        Mock::given(method("GET"))
            .and(path("/corp-lib/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{file}">corp_lib-1.0.0.tar.gz</a></body></html>"#
            )))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/files/corp_lib-1.0.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(SERVED.to_vec()))
            .mount(&s)
            .await;
        let uri = "/simple/corp-lib/corp_lib-1.0.0.tar.gz";
        refused(&s, "pypi", "corp-lib", "1.0.0", uri, |c, u| {
            c.pypi.proxies = serde_json::from_value(serde_json::json!([u])).unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn gems() {
        let s = upstream().await;
        refused(
            &s,
            "gems",
            "corp",
            "1.0.0",
            "/gems/gems/corp-1.0.0.gem",
            |c, u| {
                c.gems.enabled = true;
                c.gems.proxy = Some(u);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn nuget() {
        let s = upstream().await;
        let uri = "/nuget/v3/flatcontainer/corp.lib/1.0.0/corp.lib.1.0.0.nupkg";
        refused(&s, "nuget", "corp.lib", "1.0.0", uri, |c, u| {
            c.nuget.enabled = true;
            c.nuget.proxy = Some(u);
        })
        .await;
    }

    #[tokio::test]
    async fn pub_dart() {
        let s = upstream().await;
        let uri = "/pub/packages/corp/versions/1.0.0.tar.gz";
        refused(&s, "pub", "corp", "1.0.0", uri, |c, u| {
            c.pub_dart.enabled = true;
            c.pub_dart.proxy = Some(u);
        })
        .await;
    }

    #[tokio::test]
    async fn ansible() {
        let s = upstream().await;
        let uri = "/ansible/download/corp-lib-1.0.0.tar.gz";
        refused(&s, "ansible", "corp.lib", "1.0.0", uri, |c, u| {
            c.ansible.enabled = true;
            c.ansible.proxy = Some(u);
        })
        .await;
    }

    #[tokio::test]
    async fn cpan() {
        let s = upstream().await;
        let uri = "/cpan/authors/id/C/CO/CORP/Corp-Lib-1.0.tar.gz";
        refused(&s, "cpan", "Corp-Lib", "1.0", uri, |c, u| {
            c.cpan.enabled = true;
            c.cpan.proxy = Some(u);
        })
        .await;
    }

    #[tokio::test]
    async fn docker_manifest() {
        let s = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "content-type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .set_body_bytes(SERVED.to_vec()),
            )
            .mount(&s)
            .await;
        refused(
            &s,
            "docker",
            "corp/app",
            "1.0",
            "/v2/corp/app/manifests/1.0",
            |c, u| {
                c.docker.upstreams = vec![crate::config::DockerUpstream {
                    url: u,
                    auth: None,
                    namespace: None,
                    prefix: None,
                }];
            },
        )
        .await;
    }

    /// A gem file name read two ways: the pin of the second reading holds.
    #[tokio::test]
    async fn gems_every_reading_of_the_file_name() {
        let s = upstream().await;
        let entries = serde_json::json!([
            {"registry": "gems", "name": "evil", "version": "1"},
            {"registry": "gems", "name": "evil-1", "version": "2.0", "integrity": pinned()}
        ]);
        refused_entries(
            &s,
            "gems",
            entries,
            "/gems/gems/evil-1-2.0-java.gem",
            |c, u| {
                c.gems.enabled = true;
                c.gems.proxy = Some(u);
            },
        )
        .await;
    }

    /// The package file in any case of its extension.
    #[tokio::test]
    async fn nuget_upper_case_extension() {
        let s = upstream().await;
        let uri = "/nuget/v3/flatcontainer/corp.lib/1.0.0/corp.lib.1.0.0.NUPKG";
        refused(&s, "nuget", "corp.lib", "1.0.0", uri, |c, u| {
            c.nuget.enabled = true;
            c.nuget.proxy = Some(u);
        })
        .await;
    }

    /// Every file of a pinned Maven version, the pom as well as the jar.
    #[tokio::test]
    async fn maven_pom() {
        let s = upstream().await;
        let uri = "/maven2/com/corp/lib/1.0.0/lib-1.0.0.pom";
        refused(&s, "maven", "com.corp:lib", "1.0.0", uri, |c, u| {
            c.maven.proxies = vec![MavenProxyEntry::Simple(u)];
        })
        .await;
    }

    /// A conan package file, as well as the recipe files.
    #[tokio::test]
    async fn conan_package_file() {
        let s = upstream().await;
        let uri = "/conan/v2/conans/corp/1.0/_/_/revisions/r1/packages/p1/revisions/pr1/files/conan_package.tgz";
        refused(&s, "conan", "corp", "1.0", uri, |c, u| {
            c.conan.enabled = true;
            c.conan.proxy = Some(u);
        })
        .await;
    }

    /// An official image asked of the upstream under its `library/` name: the pin is on the name
    /// the client asked for.
    #[tokio::test]
    async fn docker_official_image() {
        let s = MockServer::start().await;
        Mock::given(path("/v2/library/app/manifests/1.0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "content-type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .set_body_bytes(SERVED.to_vec()),
            )
            .mount(&s)
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&s)
            .await;
        refused(
            &s,
            "docker",
            "app",
            "1.0",
            "/v2/app/manifests/1.0",
            |c, u| {
                c.docker.upstreams = vec![crate::config::DockerUpstream {
                    url: u,
                    auth: None,
                    namespace: None,
                    prefix: None,
                }];
            },
        )
        .await;
    }

    /// A copy stored before the pin (an older release cached it on its first download): a range of
    /// it is refused like the whole file, while a range of an unpinned file is still served.
    async fn range_refused(
        registry: &str,
        name: &str,
        version: &str,
        uri: &str,
        key: &str,
        configure: fn(&mut Config, String),
    ) {
        for pin in [true, false] {
            let mut entry =
                serde_json::json!({"registry": registry, "name": name, "version": version});
            if pin {
                entry["integrity"] = serde_json::Value::String(pinned());
            }
            let ctx = enforced(
                serde_json::json!([entry]),
                "http://127.0.0.1:9".to_string(),
                configure,
            );
            ctx.state.storage.put(key, SERVED).await.unwrap();
            let resp = crate::test_helpers::send_with_headers(
                &ctx.app,
                Method::GET,
                uri,
                vec![("range", "bytes=0-")],
                "",
            )
            .await;
            let status = resp.status();
            let body = body_bytes(resp).await;
            if pin {
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{registry} range of a pinned file"
                );
                assert!(
                    !body.windows(SERVED.len()).any(|w| w == SERVED),
                    "{registry}: a range served the stored bytes"
                );
            } else {
                assert_eq!(
                    status,
                    StatusCode::PARTIAL_CONTENT,
                    "{registry} range of an unpinned file"
                );
            }
        }
    }

    /// In audit mode a pin refuses nothing, so a range of a pinned file is still a range: the range
    /// serve stands down only where a byte check could refuse.
    #[tokio::test]
    async fn range_of_a_pinned_file_in_audit_mode_is_still_served() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            serde_json::json!({"version": 1, "entries": [
                {"registry": "gems", "name": "corp", "version": "1.0.0", "integrity": pinned()}
            ]})
            .to_string(),
        )
        .unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some("http://127.0.0.1:9".to_string());
            cfg.curation.mode = CurationMode::Audit;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        ctx.state
            .storage
            .put("gems/gems/corp-1.0.0.gem", SERVED)
            .await
            .unwrap();
        let resp = crate::test_helpers::send_with_headers(
            &ctx.app,
            Method::GET,
            "/gems/gems/corp-1.0.0.gem",
            vec![("range", "bytes=0-")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    }

    /// A gem file name read two ways, a stored copy and a range: the pin of the second reading
    /// holds the range too.
    #[tokio::test]
    async fn range_of_a_gem_with_two_readings() {
        let entries = serde_json::json!([
            {"registry": "gems", "name": "evil", "version": "1"},
            {"registry": "gems", "name": "evil-1", "version": "2.0", "integrity": pinned()}
        ]);
        let ctx = enforced(entries, "http://127.0.0.1:9".to_string(), |c, u| {
            c.gems.enabled = true;
            c.gems.proxy = Some(u);
        });
        ctx.state
            .storage
            .put("gems/gems/evil-1-2.0-java.gem", SERVED)
            .await
            .unwrap();
        let resp = crate::test_helpers::send_with_headers(
            &ctx.app,
            Method::GET,
            "/gems/gems/evil-1-2.0-java.gem",
            vec![("range", "bytes=0-")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// A blocklist ahead of the allowlist in the chain (it skips this artifact): the pin still
    /// holds the range, as it holds a full download.
    #[tokio::test]
    async fn range_with_a_blocklist_ahead_of_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            serde_json::json!({"version": 1, "rules": [
                {"registry": "pypi", "name": "other-lib", "version": "*", "reason": "test"}
            ]})
            .to_string(),
        )
        .unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            serde_json::json!({"version": 1, "entries": [
                {"registry": "pypi", "name": "corp-lib", "version": "1.0.0", "integrity": pinned()}
            ]})
            .to_string(),
        )
        .unwrap();
        let (blocklist, allowlist) = (
            blocklist.to_string_lossy().into_owned(),
            allowlist.to_string_lossy().into_owned(),
        );
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxies =
                serde_json::from_value(serde_json::json!(["http://127.0.0.1:9"])).unwrap();
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
            cfg.curation.allowlist_path = Some(allowlist);
        });
        ctx.state
            .storage
            .put("pypi/corp-lib/corp_lib-1.0.0.tar.gz", SERVED)
            .await
            .unwrap();
        let resp = crate::test_helpers::send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/corp-lib/corp_lib-1.0.0.tar.gz",
            vec![("range", "bytes=0-")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// A stale copy of a pinned SNAPSHOT, served because every upstream failed: the pin holds it.
    #[tokio::test]
    async fn maven_stale_snapshot_holds_the_pin() {
        let entries = serde_json::json!([
            {"registry": "maven", "name": "com.corp:lib", "version": "1.0-SNAPSHOT", "integrity": pinned()}
        ]);
        let ctx = enforced(entries, "http://127.0.0.1:9".to_string(), |c, u| {
            c.maven.proxies = vec![MavenProxyEntry::Simple(u)];
            c.maven.metadata_ttl = 0;
        });
        ctx.state
            .storage
            .put(
                "maven/com/corp/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar",
                SERVED,
            )
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/corp/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar",
            "",
        )
        .await;
        let status = resp.status();
        let body = body_bytes(resp).await;
        assert!(
            !body.windows(SERVED.len()).any(|w| w == SERVED),
            "stale bytes served"
        );
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn range_gems() {
        range_refused(
            "gems",
            "corp",
            "1.0.0",
            "/gems/gems/corp-1.0.0.gem",
            "gems/gems/corp-1.0.0.gem",
            |c, u| {
                c.gems.enabled = true;
                c.gems.proxy = Some(u);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn range_maven() {
        range_refused(
            "maven",
            "com.corp:lib",
            "1.0.0",
            "/maven2/com/corp/lib/1.0.0/lib-1.0.0.jar",
            "maven/com/corp/lib/1.0.0/lib-1.0.0.jar",
            |c, u| c.maven.proxies = vec![MavenProxyEntry::Simple(u)],
        )
        .await;
    }

    #[tokio::test]
    async fn range_pypi() {
        range_refused(
            "pypi",
            "corp-lib",
            "1.0.0",
            "/simple/corp-lib/corp_lib-1.0.0.tar.gz",
            "pypi/corp-lib/corp_lib-1.0.0.tar.gz",
            |c, u| c.pypi.proxies = serde_json::from_value(serde_json::json!([u])).unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn range_npm() {
        range_refused(
            "npm",
            "corp-lib",
            "1.0.0",
            "/npm/corp-lib/-/corp-lib-1.0.0.tgz",
            "npm/corp-lib/tarballs/corp-lib-1.0.0.tgz",
            |c, u| c.npm.proxy = Some(u),
        )
        .await;
    }

    #[tokio::test]
    async fn conan() {
        let s = upstream().await;
        let uri = "/conan/v2/conans/corp/1.0/_/_/revisions/r1/files/conan_sources.tgz";
        refused(&s, "conan", "corp", "1.0", uri, |c, u| {
            c.conan.enabled = true;
            c.conan.proxy = Some(u);
        })
        .await;
    }
}

/// An empty `NORA_<FORMAT>_PROXY` switches the format's upstream off: the config then reads the
/// format as having no upstream, and a request for something not stored is answered 404 without
/// asking anyone. Each case names an artifact the public default upstream does serve, so a
/// fallback to that default answers 200 (or 502 offline) instead of 404.
#[cfg(test)]
mod proxy_off_means_off {
    #![allow(clippy::unwrap_used)]

    use crate::config::Config;
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    async fn not_found(uri: &str, configure: fn(&mut Config)) {
        let ctx = create_test_context_with_config(configure);
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
    }

    #[tokio::test]
    async fn gems() {
        not_found("/gems/gems/rake-13.0.6.gem", |c| {
            c.gems.enabled = true;
            c.gems.proxy = None;
        })
        .await;
    }

    #[tokio::test]
    async fn nuget() {
        let uri = "/nuget/v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg";
        not_found(uri, |c| {
            c.nuget.enabled = true;
            c.nuget.proxy = None;
        })
        .await;
    }

    #[tokio::test]
    async fn conan() {
        not_found("/conan/v2/conans/zlib/1.3.1/_/_/latest", |c| {
            c.conan.enabled = true;
            c.conan.proxy = None;
        })
        .await;
    }

    #[tokio::test]
    async fn terraform() {
        not_found("/terraform/v1/providers/hashicorp/null/versions", |c| {
            c.terraform.enabled = true;
            c.terraform.proxy = None;
        })
        .await;
    }

    #[tokio::test]
    async fn ansible() {
        let uri =
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/community/general/";
        not_found(uri, |c| {
            c.ansible.enabled = true;
            c.ansible.proxy = None;
        })
        .await;
    }

    /// What is stored keeps being served, whatever its age: with the upstream off it is all
    /// there is, and nothing reaches an upstream to refresh it.
    async fn stored(uri: &str, key: &str, body: &[u8], configure: fn(&mut Config)) {
        let ctx = create_test_context_with_config(configure);
        ctx.state.storage.put(key, body).await.unwrap();
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let served = crate::test_helpers::body_bytes(resp).await;
        assert_eq!(served.as_ref(), body, "{uri}");
    }

    #[tokio::test]
    async fn gems_stored_index() {
        stored("/gems/specs.4.8.gz", "gems/specs.4.8.gz", b"SPECS", |c| {
            c.gems.enabled = true;
            c.gems.proxy = None;
            c.gems.metadata_ttl = 0;
        })
        .await;
    }

    #[tokio::test]
    async fn cpan_stored_index() {
        let key = "cpan/modules/02packages.details.txt.gz";
        stored(
            "/cpan/modules/02packages.details.txt.gz",
            key,
            b"PKGS",
            |c| {
                c.cpan.enabled = true;
                c.cpan.proxy = None;
                c.cpan.metadata_ttl = 0;
            },
        )
        .await;
    }

    #[tokio::test]
    async fn terraform_stored_versions() {
        let key = "terraform/providers/corp/thing/versions.json";
        let body = br#"{"versions":[{"version":"1.0.0"}]}"#;
        stored(
            "/terraform/v1/providers/corp/thing/versions",
            key,
            body,
            |c| {
                c.terraform.enabled = true;
                c.terraform.proxy = None;
                c.terraform.metadata_ttl = 0;
            },
        )
        .await;
    }

    #[tokio::test]
    async fn nuget_stored_version_list() {
        let key = "nuget/flatcontainer/corp.lib/index.json";
        let body = br#"{"versions":["1.0.0"]}"#;
        stored(
            "/nuget/v3/flatcontainer/corp.lib/index.json",
            key,
            body,
            |c| {
                c.nuget.enabled = true;
                c.nuget.proxy = None;
                c.nuget.metadata_ttl = 0;
            },
        )
        .await;
    }

    #[tokio::test]
    async fn cpan() {
        not_found("/cpan/authors/id/H/HA/HAARG/Moo-2.005005.tar.gz", |c| {
            c.cpan.enabled = true;
            c.cpan.proxy = None;
        })
        .await;
    }

    // ---- Every route, measured: nothing leaves NORA ----

    const TF_PROVIDER_META: &[u8] = br#"{"_nora_upstream_url":"https://releases.example/p.zip","_nora_upstream_shasums_url":"https://releases.example/SHA256SUMS","_nora_upstream_shasums_sig_url":"https://releases.example/SHA256SUMS.sig"}"#;

    /// How the upstream setting is written: absent, blank (whatever wrote it: a file, the
    /// environment or code — handlers must read it as off too), or the public default.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Mode {
        Off,
        Blank,
        On,
    }

    fn set_upstream(proxy: &mut Option<String>, mode: Mode) {
        match mode {
            Mode::Off => *proxy = None,
            Mode::Blank => *proxy = Some("  ".to_string()),
            Mode::On => {}
        }
    }

    /// Where an address goes when the upstream is on: nowhere (answered locally), to the upstream
    /// over an empty store, or to an address an earlier configuration stored (needs the seeds).
    #[derive(Clone, Copy)]
    enum Reach {
        Local,
        Cold,
        Seeded,
    }

    /// Every route of a format with its upstream switched off, over an empty store and over one
    /// holding stale copies and the upstream addresses an earlier configuration stored: no request
    /// leaves NORA, whatever host a handler meant to ask (the client goes through a recording proxy
    /// without idle connections, so each request is seen), and the answer is the stored copy (200)
    /// or 404. The control, per address: with the public default upstream on and nothing stored,
    /// every address not marked local reaches the upstream.
    async fn no_egress(
        format: &str,
        uris: &[(&str, Reach)],
        seeds: &[(&str, &[u8])],
        configure: fn(&mut Config, Mode),
    ) {
        use crate::test_helpers::{create_test_context_with_egress_proxy, EgressRecorder};
        for mode in [Mode::Off, Mode::Blank, Mode::On] {
            let upstream_on = mode == Mode::On;
            let recorder = EgressRecorder::start().await;
            let ctx =
                create_test_context_with_egress_proxy(&recorder.url, move |c| configure(c, mode));
            for seeded in [false, true] {
                if seeded {
                    for (key, body) in seeds {
                        ctx.state.storage.put(key, body).await.unwrap();
                    }
                }
                for (uri, reach) in uris {
                    let before = recorder.seen().await.len();
                    let status = send(&ctx.app, Method::GET, uri, "").await.status();
                    // Revalidations and cache fills that run off the request path.
                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                    let seen = recorder.seen().await;
                    let asked = &seen[before..];
                    if upstream_on {
                        let expected = match reach {
                            Reach::Cold => !seeded,
                            Reach::Seeded => seeded,
                            Reach::Local => false,
                        };
                        if expected {
                            assert!(
                                !asked.is_empty(),
                                "{format} control: {uri} never reached the default upstream (seeded: {seeded})"
                            );
                        }
                    } else {
                        assert!(
                            asked.is_empty(),
                            "{format} {uri} asked with the upstream {mode:?}: {asked:?}"
                        );
                        // 200: a stored copy; 204: Terraform's module answer pointing at NORA's own
                        // source route; 404: nothing stored.
                        assert!(
                            [StatusCode::OK, StatusCode::NO_CONTENT, StatusCode::NOT_FOUND]
                                .contains(&status),
                            "{format} {uri} with the upstream {mode:?} answered {status} (seeded: {seeded})"
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn gems_every_route() {
        no_egress(
            "gems",
            &[
                ("/gems/specs.4.8.gz", Reach::Cold),
                ("/gems/latest_specs.4.8.gz", Reach::Cold),
                ("/gems/prerelease_specs.4.8.gz", Reach::Cold),
                ("/gems/info/rake", Reach::Cold),
                ("/gems/gems/rake-13.0.6.gem", Reach::Cold),
                (
                    "/gems/quick/Marshal.4.8/rake-13.0.6.gemspec.rz",
                    Reach::Cold,
                ),
            ],
            &[
                ("gems/specs.4.8.gz", b"SPECS"),
                ("gems/latest_specs.4.8.gz", b"SPECS"),
                ("gems/info/rake", b"---\n13.0.6 |checksum:00"),
            ],
            |c, mode| {
                c.gems.enabled = true;
                c.gems.metadata_ttl = 0;
                set_upstream(&mut c.gems.proxy, mode);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn nuget_every_route() {
        let mut uris = Vec::new();
        for prefix in ["nuget", "chocolatey", "pwsh"] {
            for (path, reach) in [
                ("v3/index.json", Reach::Local),
                ("v3/query?q=newtonsoft", Reach::Cold),
                ("v3/autocomplete?q=newt", Reach::Cold),
                ("v3/registration/newtonsoft.json/index.json", Reach::Cold),
                (
                    "v3/registration/awssdk.core/page/3.7.0/3.7.400.json",
                    Reach::Cold,
                ),
                ("v3/flatcontainer/newtonsoft.json/index.json", Reach::Cold),
                (
                    "v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
                    Reach::Cold,
                ),
                (
                    "v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.nuspec",
                    Reach::Cold,
                ),
                ("v3/other/resource.json", Reach::Local),
            ] {
                uris.push((format!("/{prefix}/{path}"), reach));
            }
        }
        let uris: Vec<(&str, Reach)> = uris.iter().map(|(u, r)| (u.as_str(), *r)).collect();
        no_egress(
            "nuget",
            &uris,
            &[(
                "nuget/flatcontainer/newtonsoft.json/index.json",
                br#"{"versions":["13.0.1"]}"#,
            )],
            |c, mode| {
                c.nuget.enabled = true;
                c.nuget.metadata_ttl = 0;
                set_upstream(&mut c.nuget.proxy, mode);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn conan_every_route() {
        let r = "/conan/v2/conans/zlib/1.3.1/_/_";
        let uris = [
            ("/conan/v1/ping".to_string(), Reach::Local),
            ("/conan/v2/ping".to_string(), Reach::Local),
            ("/conan/v2/conans/search?q=zlib".to_string(), Reach::Cold),
            (format!("{r}/latest"), Reach::Cold),
            (format!("{r}/revisions"), Reach::Cold),
            (format!("{r}/revisions/r1/files"), Reach::Cold),
            (format!("{r}/revisions/r1/files/conanfile.py"), Reach::Cold),
            (format!("{r}/revisions/r1/packages/p1/latest"), Reach::Cold),
            (
                format!("{r}/revisions/r1/packages/p1/revisions"),
                Reach::Cold,
            ),
            (
                format!("{r}/revisions/r1/packages/p1/revisions/pr1/files"),
                Reach::Cold,
            ),
            (
                format!("{r}/revisions/r1/packages/p1/revisions/pr1/files/conan_package.tgz"),
                Reach::Cold,
            ),
        ];
        let uris: Vec<(&str, Reach)> = uris.iter().map(|(u, r)| (u.as_str(), *r)).collect();
        no_egress("conan", &uris, &[], |c, mode| {
            c.conan.enabled = true;
            c.conan.metadata_ttl = 0;
            set_upstream(&mut c.conan.proxy, mode);
        })
        .await;
    }

    #[tokio::test]
    async fn terraform_every_route() {
        let d = "/terraform/v1/providers/download/hashicorp/null/3.2.2";
        let uris = [
            (
                "/terraform/.well-known/terraform.json".to_string(),
                Reach::Local,
            ),
            (
                "/terraform/v1/providers/hashicorp/null/versions".to_string(),
                Reach::Cold,
            ),
            (
                "/terraform/v1/providers/hashicorp/null/3.2.2/download/linux/amd64".to_string(),
                Reach::Cold,
            ),
            (
                format!("{d}/terraform-provider-null_3.2.2_linux_amd64.zip"),
                Reach::Cold,
            ),
            (
                format!("{d}/terraform-provider-null_3.2.2_SHA256SUMS"),
                Reach::Cold,
            ),
            (
                format!("{d}/terraform-provider-null_3.2.2_SHA256SUMS.sig"),
                Reach::Cold,
            ),
            (
                "/terraform/v1/modules/corp/net/aws/versions".to_string(),
                Reach::Cold,
            ),
            (
                "/terraform/v1/modules/corp/net/aws/1.0.0/download".to_string(),
                Reach::Cold,
            ),
            (
                "/terraform/v1/modules/download/corp/net/aws/1.0.0/source".to_string(),
                Reach::Seeded,
            ),
            (
                "/terraform/registry.terraform.io/hashicorp/null/index.json".to_string(),
                Reach::Cold,
            ),
            (
                "/terraform/registry.terraform.io/hashicorp/null/3.2.2.json".to_string(),
                Reach::Cold,
            ),
            // A version whose platforms are listed but whose archives are not stored: the mirror
            // asks for each archive (`mirror_fetch_archive`).
            (
                "/terraform/registry.terraform.io/hashicorp/random/1.0.0.json".to_string(),
                Reach::Cold,
            ),
        ];
        let uris: Vec<(&str, Reach)> = uris.iter().map(|(u, r)| (u.as_str(), *r)).collect();
        no_egress(
            "terraform",
            &uris,
            &[
                (
                    "terraform/modules/corp/net/aws/1.0.0/_source_url",
                    b"https://source.example/net.tar.gz",
                ),
                (
                    "terraform/providers/hashicorp/null/3.2.2/linux_amd64.json",
                    TF_PROVIDER_META,
                ),
                (
                    "terraform/providers/hashicorp/null/versions.json",
                    br#"{"versions":[{"version":"3.2.2","platforms":[{"os":"linux","arch":"amd64"}]}]}"#,
                ),
                (
                    "terraform/providers/hashicorp/random/versions.json",
                    br#"{"versions":[{"version":"1.0.0","platforms":[{"os":"linux","arch":"amd64"}]}]}"#,
                ),
            ],
            |c, mode| {
                c.terraform.enabled = true;
                c.terraform.metadata_ttl = 0;
                set_upstream(&mut c.terraform.proxy, mode);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn ansible_every_route() {
        let v3 = "/ansible/v3/collections/community/general";
        let idx = "/ansible/api/v3/plugin/ansible/content/published/collections/index";
        let uris = [
            ("/ansible/".to_string(), Reach::Local),
            ("/ansible/api/".to_string(), Reach::Local),
            ("/ansible/v3/collections/".to_string(), Reach::Cold),
            (format!("{v3}/"), Reach::Cold),
            (format!("{v3}/versions/"), Reach::Cold),
            (format!("{v3}/versions/8.0.0/"), Reach::Cold),
            (format!("{idx}/"), Reach::Cold),
            (format!("{idx}/community/general/"), Reach::Cold),
            (format!("{idx}/community/general/versions/"), Reach::Cold),
            (format!("{idx}/community/general/versions/8.0.0/"), Reach::Cold),
            ("/ansible/download/community-general-8.0.0.tar.gz".to_string(), Reach::Cold),
            (
                "/ansible/api/v3/plugin/ansible/content/published/collections/artifacts/community-general-8.0.0.tar.gz"
                    .to_string(),
                Reach::Cold,
            ),
        ];
        let uris: Vec<(&str, Reach)> = uris.iter().map(|(u, r)| (u.as_str(), *r)).collect();
        no_egress("ansible", &uris, &[], |c, mode| {
            c.ansible.enabled = true;
            c.ansible.metadata_ttl = 0;
            set_upstream(&mut c.ansible.proxy, mode);
        })
        .await;
    }

    #[tokio::test]
    async fn cpan_every_route() {
        no_egress(
            "cpan",
            &[
                ("/cpan/modules/02packages.details.txt.gz", Reach::Cold),
                ("/cpan/modules/03modlist.data.gz", Reach::Cold),
                ("/cpan/authors/01mailrc.txt.gz", Reach::Cold),
                (
                    "/cpan/authors/id/H/HA/HAARG/Moo-2.005005.tar.gz",
                    Reach::Cold,
                ),
            ],
            &[("cpan/modules/02packages.details.txt.gz", b"PKGS")],
            |c, mode| {
                c.cpan.enabled = true;
                c.cpan.metadata_ttl = 0;
                set_upstream(&mut c.cpan.proxy, mode);
            },
        )
        .await;
    }

    /// Only `upstream_url` reads a format's upstream setting in its handler: every decision about
    /// asking an upstream goes through the one rule that reads a blank setting as switched off.
    #[test]
    fn only_upstream_url_reads_the_upstream_setting() {
        for (format, field, source) in [
            ("gems", "gems", include_str!("gems.rs")),
            ("nuget", "nuget", include_str!("nuget.rs")),
            ("conan", "conan", include_str!("conan.rs")),
            ("terraform", "terraform", include_str!("terraform.rs")),
            ("ansible", "ansible", include_str!("ansible.rs")),
            ("cpan", "cpan", include_str!("cpan.rs")),
        ] {
            let code = source.split("#[cfg(test)]").next().unwrap();
            let read = format!("state.config.{field}.proxy");
            // The field itself, not `proxy_timeout` or `proxy_auth`.
            let at: Vec<usize> = code
                .match_indices(&read)
                .map(|(i, _)| i)
                .filter(|i| {
                    !code[i + read.len()..]
                        .starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
                })
                .collect();
            assert_eq!(at.len(), 1, "{format}: {read} read {} times", at.len());
            let before = &code[..at[0]];
            let function = before.rfind("\nfn ").unwrap_or(0);
            assert!(
                before[function..].starts_with("\nfn upstream_url(state: &AppState)"),
                "{format}: {read} read outside upstream_url"
            );
        }
    }
}

/// An upstream's credential goes only to that upstream: a PyPI index may name its files on
/// another host, and that host must not receive the index's Basic credential.
#[cfg(test)]
mod pypi_credential_host {
    #![allow(clippy::unwrap_used)]

    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::Method;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn a_file_on_another_host_is_fetched_without_the_index_credential() {
        let files = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files/corp_lib-1.0.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SDIST".to_vec()))
            .mount(&files)
            .await;
        let index = MockServer::start().await;
        let href = format!("{}/files/corp_lib-1.0.0.tar.gz", files.uri());
        Mock::given(method("GET"))
            .and(path("/corp-lib/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{href}">corp_lib-1.0.0.tar.gz</a></body></html>"#
            )))
            .mount(&index)
            .await;
        let url = index.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!([
                {"url": url, "auth": "corp:s3cret"}
            ]))
            .unwrap();
        });
        let _ = send(
            &ctx.app,
            Method::GET,
            "/simple/corp-lib/corp_lib-1.0.0.tar.gz",
            "",
        )
        .await;
        let leaked: Vec<_> = files
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.headers.get("authorization").is_some())
            .collect();
        assert!(
            leaked.is_empty(),
            "the index credential reached another host"
        );
    }

    /// Several upstreams: the credential of the upstream whose index named the file goes only to
    /// that upstream's origin — never to another configured upstream's host.
    #[tokio::test]
    async fn a_credential_never_reaches_another_configured_upstream() {
        let first = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files/corp_lib-1.0.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SDIST".to_vec()))
            .mount(&first)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&first)
            .await;
        let second = MockServer::start().await;
        let href = format!("{}/files/corp_lib-1.0.0.tar.gz", first.uri());
        Mock::given(method("GET"))
            .and(path("/corp-lib/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{href}">corp_lib-1.0.0.tar.gz</a></body></html>"#
            )))
            .mount(&second)
            .await;
        let (a, b) = (first.uri(), second.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!([
                {"url": a},
                {"url": b, "auth": "corp:s3cret"}
            ]))
            .unwrap();
        });
        let _ = send(
            &ctx.app,
            Method::GET,
            "/simple/corp-lib/corp_lib-1.0.0.tar.gz",
            "",
        )
        .await;
        let requests = first.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .any(|r| r.url.path() == "/files/corp_lib-1.0.0.tar.gz"),
            "control: the file was asked of the first upstream's host"
        );
        assert!(
            requests
                .iter()
                .all(|r| r.headers.get("authorization").is_none()),
            "the second upstream's credential reached the first"
        );
    }

    #[tokio::test]
    async fn a_file_on_the_index_host_is_fetched_with_the_credential() {
        let index = MockServer::start().await;
        let href = format!("{}/files/corp_lib-1.0.0.tar.gz", index.uri());
        Mock::given(method("GET"))
            .and(path("/corp-lib/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{href}">corp_lib-1.0.0.tar.gz</a></body></html>"#
            )))
            .mount(&index)
            .await;
        Mock::given(method("GET"))
            .and(path("/files/corp_lib-1.0.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SDIST".to_vec()))
            .mount(&index)
            .await;
        let url = index.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!([
                {"url": url, "auth": "corp:s3cret"}
            ]))
            .unwrap();
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/simple/corp-lib/corp_lib-1.0.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let file_requests: Vec<_> = index
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path().starts_with("/files/"))
            .collect();
        assert!(!file_requests.is_empty());
        assert!(
            file_requests
                .iter()
                .all(|r| r.headers.get("authorization").is_some()),
            "the index host must receive its credential for its own files"
        );
    }
}

/// The upstream-failure class as one table: every proxied cold-miss path of Maven, Docker,
/// Cargo, PyPI and Terraform, against every shape an upstream can answer in, alone and mixed
/// with another upstream. The expected status is the invariant itself: 404 when an upstream
/// answered 4xx ("not found"), 502 when every upstream failed — 5xx, refused, timed out.
#[cfg(test)]
mod upstream_failure_matrix {
    #![allow(clippy::unwrap_used)]

    use crate::config::{Config, DockerUpstream, MavenProxyEntry};
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use sha2::Digest;
    use std::time::Duration;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// How one upstream answers every request.
    #[derive(Clone, Copy, Debug)]
    enum Shape {
        Status(u16),
        Refused,
        /// Answers after the 1 s proxy timeout every case configures.
        Timeout,
    }

    /// The status a cold miss must get from upstreams answering in `shapes`.
    fn expected(shapes: &[Shape]) -> StatusCode {
        if shapes
            .iter()
            .any(|s| matches!(s, Shape::Status(code) if (400..500).contains(code)))
        {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_GATEWAY
        }
    }

    /// An upstream answering in `shape`; the server is returned so it lives as long as the case.
    async fn upstream(shape: Shape) -> (String, Option<MockServer>) {
        let template = match shape {
            Shape::Refused => return ("http://127.0.0.1:9".to_string(), None),
            Shape::Status(code) => ResponseTemplate::new(code),
            Shape::Timeout => ResponseTemplate::new(200).set_delay(Duration::from_secs(5)),
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(template)
            .mount(&server)
            .await;
        (server.uri(), Some(server))
    }

    const ALONE: &[&[Shape]] = &[
        &[Shape::Status(503)],
        &[Shape::Refused],
        &[Shape::Timeout],
        &[Shape::Status(400)],
        &[Shape::Status(404)],
    ];

    const MIXED: &[&[Shape]] = &[
        &[Shape::Status(503), Shape::Status(404)],
        &[Shape::Status(404), Shape::Status(503)],
        &[Shape::Timeout, Shape::Status(404)],
        &[Shape::Status(400), Shape::Refused],
        &[Shape::Status(503), Shape::Refused],
        &[Shape::Refused, Shape::Timeout],
    ];

    /// Runs every case for one path; `configure` points the format at the upstream URLs (in
    /// order) with a 1 s proxy timeout. One test per path, so the timed-out cases run side by side.
    async fn run(path: &str, configure: fn(&mut Config, Vec<String>), several: bool) {
        let mut cases: Vec<&[Shape]> = ALONE.to_vec();
        if several {
            cases.extend_from_slice(MIXED);
        }
        for shapes in cases {
            let mut urls = Vec::new();
            let mut servers = Vec::new();
            for shape in shapes {
                let (url, server) = upstream(*shape).await;
                urls.push(url);
                servers.push(server);
            }
            let ctx = create_test_context_with_config(move |cfg| configure(cfg, urls));
            let resp = send(&ctx.app, Method::GET, path, Body::empty()).await;
            assert_eq!(resp.status(), expected(shapes), "{path} {shapes:?}");
            drop(servers);
        }
    }

    fn maven(cfg: &mut Config, urls: Vec<String>) {
        cfg.maven.proxies = urls.into_iter().map(MavenProxyEntry::Simple).collect();
        cfg.maven.proxy_timeout = 1;
    }

    fn docker(cfg: &mut Config, urls: Vec<String>) {
        cfg.docker.upstreams = urls
            .into_iter()
            .map(|url| DockerUpstream {
                url,
                auth: None,
                namespace: None,
                prefix: None,
            })
            .collect();
        cfg.docker.proxy_timeout = 1;
    }

    fn cargo(cfg: &mut Config, urls: Vec<String>) {
        cfg.cargo.proxy = urls.into_iter().next();
        cfg.cargo.proxy_timeout = 1;
    }

    fn pypi(cfg: &mut Config, urls: Vec<String>) {
        // Plain URL entries, as `proxies = ["https://..."]` reads from the config file.
        cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
        cfg.pypi.proxy_timeout = 1;
    }

    fn terraform(cfg: &mut Config, urls: Vec<String>) {
        cfg.terraform.enabled = true;
        cfg.terraform.proxy = urls.into_iter().next();
        cfg.terraform.proxy_timeout = 1;
    }

    #[tokio::test]
    async fn maven_artifact() {
        run("/maven2/com/example/lib/1.0.0/lib-1.0.0.jar", maven, true).await;
    }

    #[tokio::test]
    async fn maven_metadata() {
        run("/maven2/com/example/lib/maven-metadata.xml", maven, true).await;
    }

    #[tokio::test]
    async fn maven_metadata_checksum() {
        run(
            "/maven2/com/example/lib/maven-metadata.xml.sha1",
            maven,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn docker_manifest() {
        run("/v2/myorg/app/manifests/1.0", docker, true).await;
    }

    #[tokio::test]
    async fn docker_blob() {
        let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"layer")));
        run(&format!("/v2/myorg/app/blobs/{blob}"), docker, true).await;
    }

    #[tokio::test]
    async fn cargo_sparse_index() {
        run("/cargo/index/se/rd/serde", cargo, false).await;
    }

    #[tokio::test]
    async fn cargo_crate_metadata() {
        run("/cargo/api/v1/crates/serde", cargo, false).await;
    }

    #[tokio::test]
    async fn cargo_crate_download() {
        run("/cargo/api/v1/crates/serde/1.0.0/download", cargo, false).await;
    }

    #[tokio::test]
    async fn pypi_simple_index() {
        run("/simple/flask/", pypi, true).await;
    }

    #[tokio::test]
    async fn pypi_file() {
        run("/simple/flask/flask-2.0.tar.gz", pypi, true).await;
    }

    #[tokio::test]
    async fn terraform_module_download() {
        run(
            "/terraform/v1/modules/hashicorp/consul/aws/0.1.0/download",
            terraform,
            false,
        )
        .await;
    }
}

/// Every handler names its own registry to curation: per-registry thresholds, quarantine
/// and rules are looked up by that label, so a handler passing another registry's would
/// apply another registry's settings (#1098). In the code of `registry/<format>.rs`
/// (before its test module) the only `RegistryType::` variant is its own.
#[cfg(test)]
mod curation_label_whitelist {
    use crate::registry_type::RegistryType;
    use std::collections::BTreeSet;

    const HANDLERS: &[(&str, RegistryType, &str)] = &[
        (
            "ansible.rs",
            RegistryType::Ansible,
            include_str!("ansible.rs"),
        ),
        (
            "cargo_registry.rs",
            RegistryType::Cargo,
            include_str!("cargo_registry.rs"),
        ),
        ("conan.rs", RegistryType::Conan, include_str!("conan.rs")),
        ("cpan.rs", RegistryType::Cpan, include_str!("cpan.rs")),
        ("deb.rs", RegistryType::Deb, include_str!("deb.rs")),
        ("docker.rs", RegistryType::Docker, include_str!("docker.rs")),
        ("gems.rs", RegistryType::Gems, include_str!("gems.rs")),
        ("go.rs", RegistryType::Go, include_str!("go.rs")),
        ("hf.rs", RegistryType::HuggingFace, include_str!("hf.rs")),
        ("maven.rs", RegistryType::Maven, include_str!("maven.rs")),
        ("npm.rs", RegistryType::Npm, include_str!("npm.rs")),
        ("nuget.rs", RegistryType::Nuget, include_str!("nuget.rs")),
        (
            "pub_dart.rs",
            RegistryType::PubDart,
            include_str!("pub_dart.rs"),
        ),
        ("pypi.rs", RegistryType::PyPI, include_str!("pypi.rs")),
        ("raw.rs", RegistryType::Raw, include_str!("raw.rs")),
        ("rpm.rs", RegistryType::Rpm, include_str!("rpm.rs")),
        (
            "terraform.rs",
            RegistryType::Terraform,
            include_str!("terraform.rs"),
        ),
    ];

    /// The file up to its first test module: a module-level `#[cfg(test)]` whose item,
    /// after any further attributes, is a `mod`. A `#[cfg(test)]` helper function between
    /// production items (go.rs has one) does not end the production code.
    fn code(src: &str) -> &str {
        let mut at = 0;
        while let Some(i) = src[at..].find("\n#[cfg(test)]") {
            let start = at + i + 1;
            let item = src[start..]
                .lines()
                .skip(1)
                .find(|l| !l.trim_start().starts_with("#["))
                .unwrap_or("");
            if item.starts_with("mod ") || item.starts_with("pub mod ") {
                return &src[..start];
            }
            at = start;
        }
        src
    }

    /// The variants named as `RegistryType::<Variant>` in `code`.
    fn variants(code: &str) -> BTreeSet<String> {
        code.split("RegistryType::")
            .skip(1)
            .map(|rest| {
                rest.chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect()
            })
            .collect()
    }

    #[test]
    fn the_production_code_ends_at_the_first_test_module() {
        let src = "fn a() {}\n#[cfg(test)]\nfn helper() {}\nfn b() { RegistryType::Go }\n#[cfg(test)]\n#[allow(x)]\nmod tests {\n    fn t() { RegistryType::Npm }\n}\n";
        let code = code(src);
        assert!(code.contains("fn b()"), "{code}");
        assert!(!code.contains("mod tests"), "{code}");
        assert_eq!(variants(code), BTreeSet::from(["Go".to_string()]));
    }

    #[test]
    fn every_handler_names_only_its_own_registry() {
        let owns: BTreeSet<String> = HANDLERS
            .iter()
            .map(|(_, rt, _)| format!("{rt:?}"))
            .collect();
        assert_eq!(
            owns.len(),
            RegistryType::all().len(),
            "every registry has its handler here"
        );
        for (file, own, src) in HANDLERS {
            let code = code(src);
            for alias in ["RegistryType as", "RegistryType::{", "RegistryType::*"] {
                assert!(!code.contains(alias), "{file}: `{alias}` hides the label");
            }
            assert_eq!(
                variants(code),
                BTreeSet::from([format!("{own:?}")]),
                "{file} names another registry to curation"
            );
        }
    }
}
