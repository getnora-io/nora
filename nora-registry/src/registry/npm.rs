// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, AuthenticatedUser, NamespaceAuthority};
use crate::circuit_breaker::BreakerScope;
use crate::config::npm_scope_of;
use crate::metrics::{METADATA_CORRUPT_TOTAL, PACKUMENT_REBUILT_TOTAL};
use crate::registry::{
    circuit_open_response, method_not_allowed, nora_base_url, proxy_fetch, proxy_fetch_conditional,
    proxy_fetch_hop, proxy_forward_post, read_validators, validators_key, write_validators, Hopped,
    ProxyError, Revalidation, Validators,
};
use crate::registry_type::RegistryType;
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
use nora_registry::npm_links::{
    self, github_packages_tarball, link_host, max_semver, replace_upstream_bytes, Hop, Links,
    Placed, Refetched, TarballAsk, TarballStep, Unrewritable,
};
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
    // pnpm posts an npm6 dependency tree here (measured with pnpm 10.17, #1055).
    let is_full = path == "-/npm/v1/security/audits";
    if !is_bulk && !is_quick && !is_full {
        // POST is only meaningful on the audit endpoints.
        return method_not_allowed("GET, PUT");
    }

    // Bound the body AT READ TIME. The global DefaultBodyLimit is 2 GB (for tarball
    // PUTs); audit bodies are <1 MB. `to_bytes` aborts collection past the cap, so a
    // chunked / no-Content-Length client cannot force NORA to buffer gigabytes (#597).
    let body = match axum::body::to_bytes(body, NPM_AUDIT_BODY_CAP).await {
        Ok(b) => b,
        Err(_) => {
            return audit_refused(
                StatusCode::PAYLOAD_TOO_LARGE,
                "audit body is larger than NORA accepts (8 MB)",
            )
        }
    };

    // Only a remote/proxy repo can answer audits (advisories come from upstream).
    // Hosted-only (no proxy) → npm-compatible empty result so `npm audit` doesn't
    // hard-fail — npm treats a 200 `{}` as "no advisories".
    let Some(upstream) = state.config.npm.route(&path) else {
        return npm_empty_audit();
    };

    // #68/#733 dependency-confusion: never send internal package names upstream.
    // #1055: the same holds for scopes owned by a private upstream — the audit goes
    // to the default upstream, which must not learn the private package names.
    // When a namespace filter is configured we must SEE plaintext names to strip
    // them, so ANY body we cannot verify — the quick lockfile, an encoded bulk body,
    // or a bulk body that is not the expected JSON object — is refused (fail CLOSED,
    // symmetric across both paths). With no filter, nothing is internal → forward
    // verbatim.
    let engine = &state.curation().curation_engine;
    let owned_scopes: Vec<&str> = state.config.npm.owned_scopes().collect();
    let filter_active =
        crate::curation::namespace_filter_active(engine) || !owned_scopes.is_empty();
    let encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.eq_ignore_ascii_case("identity"));
    // npm 7+ always gzips the bulk body (measured with real clients, #1055): refusing
    // every encoded body made `npm audit` report no vulnerabilities whenever a filter
    // was active. Gzip is decoded under the same cap and checked like plain JSON; any
    // other encoding, or a body that does not decode, is still refused.
    let mut decoded = false;
    // A body that cannot be checked is refused with a 4xx and a JSON `error` — never
    // `200 {}`, which npm and yarn render as "0 vulnerabilities" (Pavel 10.10). 4xx,
    // not 5xx: pnpm retries a 5xx for about 70 s before failing anyway, and every
    // client prints the error text on a 4xx (kit npm-audit-matrix).
    // A bulk body is always read: the names of packages published here are stripped from it
    // whether or not a namespace filter is configured.
    let forward_body: Vec<u8> = if !filter_active && !is_bulk {
        body.to_vec()
    } else if is_quick || is_full {
        return audit_refused(
            StatusCode::UNPROCESSABLE_ENTITY,
            "this audit format carries a whole dependency tree that NORA cannot strip of \
             private or internal package names; use npm 7+ (bulk advisories) or yarn npm audit",
        );
    } else {
        let plain = match encoding {
            None => body.to_vec(),
            Some(enc) if enc.eq_ignore_ascii_case("gzip") => {
                match gunzip_bounded(&body, NPM_AUDIT_BODY_CAP) {
                    Ok(plain) => {
                        decoded = true;
                        plain
                    }
                    Err(GunzipError::TooLarge) => {
                        return audit_refused(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "decompressed audit body is larger than NORA accepts (8 MB)",
                        )
                    }
                    Err(GunzipError::Corrupt(e)) => {
                        tracing::debug!(error = %e, "npm audit: gzip body does not decompress");
                        return audit_refused(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "audit body says gzip but does not decompress",
                        );
                    }
                }
            }
            Some(_) => {
                return audit_refused(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "audit body encoding is not supported; send it plain or gzip",
                )
            }
        };
        let Some(stripped) = strip_internal_bulk(&plain, engine, &owned_scopes) else {
            return audit_refused(
                StatusCode::UNPROCESSABLE_ENTITY,
                "audit body is not the expected JSON object of package versions",
            );
        };
        match strip_published_bulk(&state, stripped).await {
            Ok(stripped) => stripped,
            Err(response) => return response,
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
    // A body decoded above goes out as the plain JSON it was checked as.
    if let Some(v) = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .filter(|_| !decoded)
    {
        fwd.push(("content-encoding", v));
    }
    if let Some(v) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) {
        fwd.push(("accept", v));
    }

    let url = format!("{}/{}", upstream.url.trim_end_matches('/'), path);
    match proxy_forward_post(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        upstream.auth,
        &fwd,
        &forward_body,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Npm, upstream.url),
    )
    .await
    {
        Ok((code, resp_body, resp_ct)) => {
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "npm", "audit"));
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

/// Why a gzip audit body was not decoded.
#[derive(Debug)]
enum GunzipError {
    /// Not gzip, or a corrupt stream.
    Corrupt(std::io::Error),
    /// Expands past the cap (a small gzip can inflate into gigabytes).
    TooLarge,
}

/// Gunzip an audit body, refusing output past `cap` bytes.
fn gunzip_bounded(data: &[u8], cap: usize) -> Result<Vec<u8>, GunzipError> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .take(cap as u64 + 1)
        .read_to_end(&mut out)
        .map_err(GunzipError::Corrupt)?;
    if out.len() > cap {
        return Err(GunzipError::TooLarge);
    }
    Ok(out)
}

/// An audit NORA will not forward: the status and a JSON `error` the clients print
/// (npm `npm warn audit <code> … - <error>`, pnpm `responded with <code>: …`,
/// yarn 4 `[Error]: <error>`).
fn audit_refused(status: StatusCode, reason: &str) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::json!({ "error": reason }).to_string(),
    )
        .into_response()
}

/// Strip internal-namespace and private-scope package keys from an npm7 bulk-advisories body
/// (`{"<pkg>":[…]}`). `Some(bytes)` = the (possibly unchanged) body safe to forward;
/// `None` = the body is NOT the expected JSON object, so the caller must fail closed
/// under an active namespace filter (we could not verify no internal name is present).
fn strip_internal_bulk(
    body: &[u8],
    engine: &crate::curation::CurationEngine,
    owned_scopes: &[&str],
) -> Option<Vec<u8>> {
    let mut map =
        serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(body).ok()?;
    let before = map.len();
    map.retain(|k, _| {
        let private = npm_scope_of(k).is_some_and(|scope| owned_scopes.contains(&scope));
        !private
            && !crate::curation::is_internal_namespace(
                engine,
                crate::curation::RegistryType::Npm,
                k,
            )
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

/// The most packages a bulk audit may name: each is a listing of the store to tell whether it is
/// published here. Lockfiles of large monorepos name a few thousand.
const NPM_AUDIT_MAX_PACKAGES: usize = 10_000;

/// Strip the packages published here from a bulk-advisories body that [`strip_internal_bulk`]
/// returned: a published name is NORA's, and an upstream that learns it can register it. The
/// body is forwarded unchanged when it names none. A name whose published state cannot be read
/// refuses the audit (503): forwarding it could hand the name over, and dropping it would hide
/// its advisories.
async fn strip_published_bulk(state: &AppState, body: Vec<u8>) -> Result<Vec<u8>, Response> {
    use futures::StreamExt;
    let Ok(mut map) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&body)
    else {
        return Err(audit_refused(
            StatusCode::UNPROCESSABLE_ENTITY,
            "audit body is not the expected JSON object of package versions",
        ));
    };
    if map.len() > NPM_AUDIT_MAX_PACKAGES {
        return Err(audit_refused(
            StatusCode::PAYLOAD_TOO_LARGE,
            "audit body names more packages than NORA checks (10000)",
        ));
    }
    let states: Vec<(String, Published)> = futures::stream::iter(map.keys().cloned())
        .map(|name| async move {
            // A name that is no valid key cannot be published here.
            let prefix = format!("npm/{name}/versions/");
            let published = match crate::validation::validate_storage_key(
                crate::validation::listing_key(&prefix),
            ) {
                Ok(()) => published_state(&state.storage, &name).await,
                Err(_) => Published::No,
            };
            (name, published)
        })
        .buffer_unordered(32)
        .collect()
        .await;
    let mut stripped = false;
    for (name, published) in states {
        match published {
            Published::Yes(_) => {
                map.remove(&name);
                stripped = true;
            }
            Published::No => {}
            Published::Unknown => {
                return Err(crate::registry::storage_unavailable(
                    "npm",
                    &format!("npm/{name}/versions/"),
                ))
            }
        }
    }
    if !stripped {
        return Ok(body);
    }
    serde_json::to_vec(&map).map_err(|e| {
        tracing::error!(error = %e, "npm audit: re-serializing the stripped body failed");
        audit_refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            "audit body could not be re-serialized",
        )
    })
}

/// [`npm_links::place_document`] with the server's storage-key check.
fn place_document(
    data: &[u8],
    nora_base: &str,
    upstream_url: &str,
    package_asked: Option<&str>,
    links: Links,
) -> Result<Placed, Unrewritable> {
    let key_ok = |key: &str| crate::validation::validate_storage_key(key).is_ok();
    npm_links::place_document(data, nora_base, upstream_url, package_asked, links, &key_ok)
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
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    Extension(user): Extension<AuthenticatedUser>,
) -> Response {
    // Handle npm whoami endpoint
    if path == "-/whoami" {
        return handle_whoami(&user).await;
    }

    let github_packages = github_packages_tarball(&path);
    let is_tarball = github_packages.is_some() || path.contains("/-/");

    let key = if let Some((name, version)) = github_packages {
        // Stored under the npmjs file name of that version, like any other tarball.
        let bare = name.rsplit('/').next().unwrap_or(name);
        format!("npm/{name}/tarballs/{bare}-{version}.tgz")
    } else if is_tarball {
        let parts: Vec<&str> = path.splitn(2, "/-/").collect();
        if parts.len() == 2 {
            format!("npm/{}/tarballs/{}", parts[0], parts[1])
        } else {
            format!("npm/{}", path)
        }
    } else {
        legacy_cache_key(&path)
    };
    // A path with an empty segment (`npm//x`, `npm/x/`) would name another package's files
    // and slip past name-based checks (`internal*` does not match `/x`): refuse it before
    // curation, storage or any upstream request sees the name.
    if let Err(e) = crate::validation::validate_storage_key(&key) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let package_name = if let Some((name, _)) = github_packages {
        name.to_string()
    } else if is_tarball {
        path.split("/-/").next().unwrap_or(&path).to_string()
    } else {
        path.clone()
    };

    // Parse tarball version (used for both pre-download and integrity checks)
    let tarball_version = if let Some((_, version)) = github_packages {
        Some(version.to_string())
    } else if is_tarball {
        let filename = path.split("/-/").nth(1).unwrap_or("");
        crate::curation::parse_npm_tarball_version(&package_name, filename)
    } else {
        None
    };

    // Every metadata path: a published package's documents come from its own keys and never
    // from an upstream (see `serve_metadata`); any other path is answered by the upstream and
    // not cached. What follows is the tarball path only.
    if !is_tarball {
        return match classify_metadata_path(&path) {
            MetadataPath::Other => match dist_tags_package(&path) {
                Some(name) => serve_dist_tags(&state, &headers, &path, name).await,
                None => {
                    let query = query.as_deref().filter(|q| !q.is_empty());
                    uncached_upstream_metadata(&state, &headers, &path, &package_name, query).await
                }
            },
            target => serve_metadata(&state, &headers, &path, target).await,
        };
    }

    // Extract publish date from cached metadata (npm `time` field). Hoisted to
    // function scope so the digest-quarantine serve gate below can seed first_seen
    // from a trusted upstream release date (#750). Non-tarball requests have no
    // version, so this is `None` without any extra storage read.
    let publish_date = if let Some(ref ver) = tarball_version {
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
        let meta_key = packument_key_for_reading(&state.storage, &package_name).await;
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

    // #733: an internal-namespace package is operator-owned — skip curation; the cache-hit
    // serve below handles a locally-published tarball, and the namespace guard at the
    // cache-miss boundary (below) blocks the upstream branch for internal names.
    let internal = is_internal(&state, &package_name);

    // Curation check — tarball downloads only (metadata passes through)
    if is_tarball && !internal {
        // Without trusted dates a release is as old as NORA's first sight of it in a
        // packument: the cache mtime above restarts at every refetch, so a client that
        // asks more often than the minimum age never saw its release mature. The
        // quarantine reads neither: a version listed long ago says nothing about bytes
        // first fetched now, so without trusted dates it counts from the first fetch. A
        // version the ledger lacks keeps the mtime date.
        let mut release_date = publish_date;
        if let Some(ver) = tarball_version
            .as_deref()
            .filter(|_| first_seen_tracked(&state))
        {
            release_date =
                first_seen_date(&state.storage, &upstream_packument_key(&package_name), ver)
                    .await
                    .or(publish_date);
        }
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Npm,
            &package_name,
            crate::curation::RequestVersion::of_artifact(tarball_version.as_deref()),
            release_date,
        ) {
            return response;
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
    // while quarantine holds artifacts or a curation integrity rule applies to the
    // tarball.
    // #1055: in a scope owned by a private upstream, only what that owner delivered
    // (or what was published here) may be served from cache — never a copy cached
    // from another upstream before the scope had an owner.
    let cache_trusted = cached_copy_trusted(
        &state,
        &path,
        &key,
        &package_name,
        tarball_version.as_deref(),
    )
    .await;
    if is_tarball
        && cache_trusted
        && headers.contains_key(header::RANGE)
        && matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off)
        && !crate::curation::integrity_applies(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Npm,
            &package_name,
            tarball_version.as_deref(),
        )
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
    let (cached, read_failure) = if cache_trusted {
        crate::registry::cached_read(state.storage.get_verified(&key).await)
    } else {
        (None, None)
    };
    let cached = match cached {
        Some(outcome) => {
            use nora_registry::verified::{verified_body, GateOutcome};
            let data = match outcome {
                GateOutcome::Verified(blob) => verified_body(blob),
                GateOutcome::Unpinned(blob) => blob.into_inner(),
            };
            // Tarball: integrity check against the sidecar written with it.
            match crate::registry::check_sidecar(&state.storage, &key, &data).await {
                crate::registry::Sidecar::Holds => Some(data),
                crate::registry::Sidecar::Differs { expected, computed } => {
                    tracing::error!(
                        key = %key,
                        expected = %expected,
                        computed = %computed,
                        "SECURITY: npm tarball integrity check FAILED — possible tampering"
                    );
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Integrity check failed")
                        .into_response();
                }
                // A copy NORA owns has nowhere else to come from: unavailable, its bytes not sent.
                // A proxied one is fetched again below and checked as on its first download.
                crate::registry::Sidecar::Unreadable(e) => {
                    let own = internal
                        || state.config.npm.route(&path).is_none()
                        || !matches!(
                            published_state(&state.storage, &package_name).await,
                            Published::No
                        );
                    if own {
                        return crate::registry::local_copy_unreadable(
                            "npm",
                            &format!("{key}.sha256"),
                            &e,
                        );
                    }
                    tracing::warn!(key = %key, error = %e, "npm: tarball sidecar unreadable, fetching the tarball again");
                    None
                }
            }
        }
        None => None,
    };
    if let Some(data) = cached {
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
            .log(AuditEntry::new("cache_hit", "proxy", "", "npm", ""));
        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "npm",
            &data,
            &q_mode,
            q_secs,
            "cache",
            crate::digest_quarantine::first_seen_seed(
                state.config.server.trust_upstream_dates,
                publish_date,
            ),
        ) {
            return resp;
        }
        let mut response = with_content_type(true, data).into_response();
        response
            .headers_mut()
            .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        return response;
    }

    // An internal package whose copy the store could not read is unavailable, not absent.
    if let Some(e) = read_failure.as_ref().filter(|_| internal) {
        return crate::registry::local_copy_unreadable("npm", &key, e);
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

    // A tarball of a published package that NORA does not store is no version of it: the upstream
    // is not asked, so what it has under the name is neither served nor stored beside the published
    // versions (as for cargo, #1158). The packument lists the published versions only, so only a
    // direct or locked URL gets here. When the published versions cannot be listed NORA cannot
    // tell whether the name is its own: unavailable (503), the upstream not asked.
    match published_state(&state.storage, &package_name).await {
        Published::Yes(_) => return StatusCode::NOT_FOUND.into_response(),
        Published::Unknown => {
            return crate::registry::storage_unavailable(
                "npm",
                &format!("npm/{package_name}/versions/"),
            )
        }
        Published::No => {}
    }

    // --- Proxy fetch path ---
    if let Some(upstream) = state.config.npm.route(&path) {
        let proxy_url = upstream.url;
        let (url, fetched) = fetch_upstream_tarball(
            &state,
            upstream.url,
            upstream.auth,
            &path,
            TarballAsk::parse(&path).as_ref(),
        )
        .await;

        match fetched {
            Ok(data) => {
                // The allowlist's pinned integrity holds on the first download too, before anything
                // is cached: the cache-hit branch checks the same rule.
                if is_tarball {
                    if let Some(response) = crate::curation::verify_integrity(
                        &state.curation().curation_engine,
                        crate::curation::RegistryType::Npm,
                        &package_name,
                        tarball_version.as_deref(),
                        &data,
                    ) {
                        return response;
                    }
                }
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
                    .log(AuditEntry::new("proxy_fetch", "proxy", "", "npm", ""));

                let data_to_cache = data.clone();
                let data_to_serve = data;
                // LOCK-SAFE: a tarball is immutable; no lock is held here.
                // Cache in background, invalidate index AFTER write completes
                let storage = state.storage.clone();
                let key_clone = key.clone();
                let repo_index = Arc::clone(&state.repo_index);
                let origin = origin_of(proxy_url);
                tokio::spawn(async move {
                    if let Err(e) =
                        put_with_origin(&storage, &key_clone, &data_to_cache, &origin).await
                    {
                        tracing::warn!(key = %key_clone, error = ?e, "npm proxy: failed to cache artifact");
                    } else {
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
                        crate::digest_quarantine::first_seen_seed(
                            state.config.server.trust_upstream_dates,
                            publish_date,
                        ),
                    ) {
                        return resp;
                    }
                }
                return with_content_type(true, data_to_serve.into()).into_response();
            }
            Err(ProxyError::CircuitOpen(reg)) => return circuit_open_response(&reg),
            // The upstream answered "no such package": a real 404.
            Err(ProxyError::NotFound) => {}
            // The upstream is down or unreachable: a gateway failure, not a missing
            // package — npm retries a 502 and reports E502 instead of E404 (#1055).
            Err(
                e @ (ProxyError::Upstream(_)
                | ProxyError::Network(_)
                | ProxyError::CredentialsRefused),
            ) => {
                tracing::warn!(registry = "npm", path = %path, error = ?e, "npm upstream failed, returning 502");
                return StatusCode::BAD_GATEWAY.into_response();
            }
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

/// Fetch the tarball `ask` names from `upstream` where [`npm_links::tarball_step`] decides, with
/// the upstream's credential: only for a version the owner's trusted packument lists, that
/// packument fetched again once when it does not (the version may be newer than the copy).
/// Returns what the download is recorded as, with what it gave; `None` (no tarball of a version)
/// and a version not listed are `NotFound` without a request for the tarball.
///
/// The credential goes as far as the upstream's origin, the redirects followed by
/// [`fetch_following`].
async fn fetch_upstream_tarball(
    state: &AppState,
    upstream: &str,
    auth: Option<crate::config::UpstreamAuth<'_>>,
    path: &str,
    ask: Option<&TarballAsk<'_>>,
) -> (String, Result<Vec<u8>, ProxyError>) {
    let at_upstream = format!("{}/{}", upstream.trim_end_matches('/'), path);
    let Some(ask) = ask else {
        return (at_upstream, Err(ProxyError::NotFound));
    };
    let nora_npm_base = format!("{}/npm", nora_base_url(state).trim_end_matches('/'));
    let key_ok = |key: &str| crate::validation::validate_storage_key(key).is_ok();
    let copy = trusted_copy(state, ask.package())
        .await
        .and_then(|copy| copy.listed_link(ask.version()));
    let step = |refetched| {
        npm_links::tarball_step(
            ask,
            upstream,
            &nora_npm_base,
            copy.as_deref(),
            refetched,
            &key_ok,
        )
    };
    let mut decided = step(None);
    if matches!(decided, TarballStep::Refetch) {
        let key = upstream_packument_key(ask.package());
        let refetched = match refetch_metadata(state, ask.package(), &key, &key, true, false).await
        {
            Ok(doc) => Refetched::Packument(npm_links::listed_link(&doc, ask.version())),
            Err(ProxyError::NotFound) => Refetched::NoPackument,
            Err(e) => Refetched::Failed(e),
        };
        decided = step(Some(refetched));
    }
    let (asked, named) = match decided {
        TarballStep::Ask { asked, named } => (asked, named),
        TarballStep::UpstreamFailed(e) => return (at_upstream, Err(e)),
        TarballStep::NotFound | TarballStep::Refetch => {
            tracing::info!(
                registry = "npm",
                package = %ask.package(),
                version = %ask.version(),
                "tarball not listed by its upstream's packument, not asked for"
            );
            return (at_upstream, Err(ProxyError::NotFound));
        }
    };
    let fetched = fetch_following(state, upstream, &asked, auth, &nora_npm_base).await;
    (named, fetched)
}

/// Download `asked` from `upstream` with its credential, following the redirects here, one at
/// a time: the client follows none, so the whole chain has one budget and every hop is decided
/// by [`npm_links::next_hop`] — ten redirects pass and the eleventh is a failure (502), and the
/// credential goes only while the chain is on `asked`'s origin. A registry keeping its files on
/// a storage host is reached without it, and so is its origin again from there: reqwest drops
/// the header on the hop to another host but puts it back on the next hop within that host.
/// The chain shares one `proxy_timeout`.
async fn fetch_following(
    state: &AppState,
    upstream: &str,
    asked: &str,
    mut auth: Option<crate::config::UpstreamAuth<'_>>,
    nora_npm_base: &str,
) -> Result<Vec<u8>, ProxyError> {
    let origin = reqwest::Url::parse(asked)
        .map_err(|e| ProxyError::Network(format!("tarball URL not readable: {e}")))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(state.config.npm.proxy_timeout);
    let mut url = asked.to_string();
    let mut left_origin = false;
    let mut hop = 0;
    loop {
        hop += 1;
        let next = match proxy_fetch_hop(
            &state.http_client_no_redirect,
            &url,
            deadline.saturating_duration_since(std::time::Instant::now()),
            auth,
            &state.circuit_breaker,
            BreakerScope::upstream(RegistryType::Npm, upstream),
        )
        .await?
        {
            Hopped::Body(body) => return Ok(body),
            Hopped::Redirect(next) => next,
        };
        url = match npm_links::next_hop(hop, &origin, left_origin, &next) {
            // The URL asked carries the upstream's userinfo, if its URL has one; the hop on
            // its origin carries it too.
            Hop::WithCredential => {
                npm_links::with_userinfo_of(next.as_str(), asked).unwrap_or_else(|| next.into())
            }
            Hop::WithoutCredential => {
                if !left_origin {
                    tracing::debug!(
                        registry = "npm",
                        to = %link_host(next.as_str(), nora_npm_base),
                        "tarball on another origin, fetched without the upstream's credential"
                    );
                }
                left_origin = true;
                auth = None;
                next.into()
            }
            Hop::Refuse => {
                tracing::warn!(
                    registry = "npm",
                    hop,
                    to = %link_host(next.as_str(), nora_npm_base),
                    "tarball redirect not followed: past the redirect limit or not http(s)"
                );
                return Err(ProxyError::Network("redirect not followed".to_string()));
            }
        };
    }
}

/// The client an upstream's metadata is fetched with. An upstream bound to a scope answers from
/// its own origin only: a redirect off it is not followed, and the fetch fails with the 3xx (a
/// 502 to the client), so neither the scope's package names nor the credential reach another
/// origin. The default upstream follows redirects.
fn metadata_client(state: &AppState, scoped: bool) -> &reqwest::Client {
    if scoped {
        &state.http_client_same_origin
    } else {
        &state.http_client
    }
}

/// The trusted cached packument of `package`: the copy under the upstream key, else an older
/// release's upstream cache under the legacy key (reached for a package not published here),
/// each trusted on its own provenance ([`trusted::TrustedPackument::at`]).
async fn trusted_copy(state: &AppState, package: &str) -> Option<trusted::TrustedPackument> {
    for key in [upstream_packument_key(package), legacy_cache_key(package)] {
        if let Some(copy) = trusted::TrustedPackument::at(state, package, &key).await {
            return Some(copy);
        }
    }
    None
}

mod trusted {
    use crate::AppState;
    use nora_registry::npm_links;

    /// A cached packument its owner delivered: the only copy a tarball link is taken from.
    /// Its one constructor checks the copy's provenance at the key it is read from.
    pub(super) struct TrustedPackument(axum::body::Bytes);

    impl TrustedPackument {
        /// The copy at `key`, if [`super::cached_copy_trusted`] trusts it and it reads.
        pub(super) async fn at(state: &AppState, package: &str, key: &str) -> Option<Self> {
            if !super::cached_copy_trusted(state, package, key, package, None).await {
                return None;
            }
            let (Some(outcome), _) =
                crate::registry::cached_read(state.storage.get_verified(key).await)
            else {
                return None;
            };
            use nora_registry::verified::{verified_body, GateOutcome};
            Some(Self(match outcome {
                GateOutcome::Verified(blob) => verified_body(blob),
                GateOutcome::Unpinned(blob) => blob.into_inner(),
            }))
        }

        /// The link this copy names for the tarball of `version`, if it lists that version.
        pub(super) fn listed_link(&self, version: &str) -> Option<String> {
            npm_links::listed_link(&self.0, version)
        }
    }
}

/// Whether `name` is in an internal namespace: served from its local copies only, never asked of
/// an upstream (#68, #733).
fn is_internal(state: &AppState, name: &str) -> bool {
    crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        name,
    )
}

/// Internal prefix holding npm cache provenance sidecars (#1055).
pub(crate) const ORIGINS_PREFIX: &str = ".nora-origins/";

/// Provenance sidecar of a cached npm object: which upstream delivered it (#1055).
///
/// `<key>` → `.nora-origins/<key>`: one-to-one, and outside every registry's key space
/// — every npm key starts with `npm/`, so no request can read or overwrite a sidecar,
/// and listings hide `.nora-` keys, so no retention, GC, UI or stats walk of this or an
/// older release counts one. A sidecar next to its tarball made 1.3.3's retention keep
/// fewer real versions after a rollback (measured: keep_last=2 kept one).
pub(crate) fn origin_key(key: &str) -> String {
    format!("{ORIGINS_PREFIX}{key}")
}

/// The cached object a provenance sidecar describes — the inverse of [`origin_key`].
pub(crate) fn origin_primary(sidecar: &str) -> Option<&str> {
    sidecar
        .strip_prefix(ORIGINS_PREFIX)
        .filter(|key| key.starts_with("npm/"))
}

/// Internal prefix holding when NORA first saw each npm version listed upstream.
pub(crate) const FIRST_SEEN_PREFIX: &str = ".nora-first-seen/";

/// First-seen ledger of the package whose packument is cached at `metadata_key`:
/// `.nora-first-seen/npm/<name>/metadata.json`. Internal like [`origin_key`], so no
/// request, listing, retention or GC walk of the npm key space reaches it.
pub(crate) fn first_seen_key(metadata_key: &str) -> String {
    format!("{FIRST_SEEN_PREFIX}{metadata_key}")
}

/// Version → Unix time NORA first saw it listed in an upstream packument.
type FirstSeen = std::collections::BTreeMap<String, i64>;

/// The internal state carried by backup and migrate along with what `list()` shows.
pub(crate) const INTERNAL_PREFIXES: &[&str] = &[ORIGINS_PREFIX, FIRST_SEEN_PREFIX];

/// Whether release ages come from the first-seen ledger: upstream dates are not trusted
/// and curation runs. Otherwise nothing reads it, and nothing is written.
fn first_seen_tracked(state: &AppState) -> bool {
    !state.config.server.trust_upstream_dates && state.curation().curation_engine.is_active()
}

/// The versions a packument lists, without building their manifests.
fn packument_versions(body: &[u8]) -> Option<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Listing {
        #[serde(default)]
        versions: std::collections::HashMap<String, serde::de::IgnoredAny>,
    }
    let listing: Listing = serde_json::from_slice(body).ok()?;
    Some(listing.versions.into_keys().collect())
}

/// Record when NORA first saw each version `body` lists — the upstream packument about to
/// be served for `key`. A version keeps the time it was first recorded, so no refetch, 200
/// or 304, makes a release younger; a version the upstream adds later starts now.
///
/// `cached_before`: the copy at `key` is NORA's own earlier one. A cache from before the
/// ledger existed starts the versions it lists at its file time, when NORA last wrote it —
/// never earlier than NORA saw them. Awaited before the packument is served, so a client
/// cannot ask for a version the ledger does not hold yet.
async fn record_first_seen(state: &AppState, key: &str, body: &[u8], seed_from: Option<&str>) {
    if !first_seen_tracked(state) {
        return;
    }
    let Some(versions) = packument_versions(body) else {
        return;
    };
    let ledger_key = first_seen_key(key);
    // LOCK-SAFE: tokio mutex, the one the publish path takes for this packument; it
    // serializes the read-modify-write of the ledger. Nothing else is locked under it.
    let lock = state.publish_lock(key);
    let _guard = lock.lock().await;
    let (mut ledger, existed) = match state.storage.get(&ledger_key).await {
        Ok(bytes) => match serde_json::from_slice::<FirstSeen>(&bytes) {
            Ok(ledger) => (ledger, true),
            Err(e) => {
                // Rewritten from now on: an unreadable time can only make a release younger.
                tracing::warn!(key = %ledger_key, error = %e, "npm: unreadable first-seen ledger");
                (FirstSeen::new(), false)
            }
        },
        // No ledger yet: a cached packument (this key's, or what an older release cached)
        // starts its versions at its own write time.
        Err(crate::storage::StorageError::NotFound) => match seed_from {
            Some(seed) => (cached_first_seen(&state.storage, seed).await, false),
            None => (FirstSeen::new(), false),
        },
        // The bytes do not match their pin: the ledger is known bad, not merely unread.
        // Rewritten from now on, as an unparsable one: every release starts young again,
        // which holds more, never less, and the ledger heals instead of staying unread.
        Err(crate::storage::StorageError::IntegrityViolation) => {
            tracing::warn!(key = %ledger_key, "npm: first-seen ledger failed its pin; rewritten");
            (FirstSeen::new(), false)
        }
        Err(e) => {
            // Not written over a ledger that may exist: a later refetch records the rest.
            tracing::warn!(key = %ledger_key, error = %e, "npm: first-seen ledger unreadable");
            return;
        }
    };
    let now = chrono::Utc::now().timestamp();
    let known = ledger.len();
    for version in versions {
        ledger.entry(version).or_insert(now);
    }
    if existed && ledger.len() == known {
        return;
    }
    match serde_json::to_vec(&ledger) {
        Ok(bytes) => {
            if let Err(e) = state.storage.put(&ledger_key, &bytes).await {
                tracing::warn!(key = %ledger_key, error = ?e, "npm: failed to record first-seen times");
            }
        }
        Err(e) => {
            tracing::warn!(key = %ledger_key, error = %e, "npm: first-seen ledger not encoded")
        }
    }
}

/// First-seen times of a packument cached before the ledger: every version it lists at its
/// file time. The body is read before the time, so a write landing in between can only make
/// the time later.
async fn cached_first_seen(storage: &crate::Storage, key: &str) -> FirstSeen {
    let Ok(body) = storage.get(key).await else {
        return FirstSeen::new();
    };
    let Some(written) = storage.stat(key).await.map(|m| m.modified as i64) else {
        return FirstSeen::new();
    };
    packument_versions(&body)
        .unwrap_or_default()
        .into_iter()
        .map(|version| (version, written))
        .collect()
}

/// When NORA first saw `version` listed in the packument at `metadata_key`.
async fn first_seen_date(
    storage: &crate::Storage,
    metadata_key: &str,
    version: &str,
) -> Option<i64> {
    let bytes = storage.get(&first_seen_key(metadata_key)).await.ok()?;
    let ledger: FirstSeen = serde_json::from_slice(&bytes).ok()?;
    ledger.get(version).copied()
}

/// The identity recorded in the sidecar — the breaker's canonical upstream key, so
/// userinfo and a trailing slash do not make one upstream look like two.
fn origin_of(upstream_url: &str) -> String {
    crate::circuit_breaker::upstream_key("npm", upstream_url)
}

/// Cache an upstream object, then record where it came from. Data first: a sidecar
/// that exists always describes bytes already written; a failed sidecar write only
/// costs a refetch.
async fn put_with_origin(
    storage: &crate::Storage,
    key: &str,
    data: &[u8],
    origin: &str,
) -> Result<(), crate::storage::StorageError> {
    storage.put(key, data).await?;
    let record = provenance_record(origin, data);
    if let Err(e) = storage.put(&origin_key(key), record.as_bytes()).await {
        tracing::warn!(key = %key, error = ?e, "npm: failed to record cache provenance");
    }
    Ok(())
}

/// The provenance record of `data` cached from `origin`: the upstream identity, then
/// the SHA-256 of exactly these bytes. The digest makes a record vouch only for the
/// bytes it was written with: whatever replaces the object later — an older release
/// after a rollback, which knows nothing of these records — changes the object's
/// pin, and the record no longer matches it.
fn provenance_record(origin: &str, data: &[u8]) -> String {
    format!("{origin}\n{}", hex::encode(sha2::Sha256::digest(data)))
}

/// May the cached copy at `key` be served for `path`?
///
/// Outside scopes owned by an `npm.proxies` entry: yes, as before. Inside one: only
/// what that owner delivered (sidecar names it) or what was published here
/// (`versions/` keys). A copy cached from another upstream — a squatter on the public
/// registry cached before the scope got an owner, any cache from before provenance
/// was recorded, or bytes that replaced the owner's after its record was written —
/// is treated as absent: refetched from the owner, and never served as a stale
/// fallback when the owner is down.
async fn cached_copy_trusted(
    state: &AppState,
    path: &str,
    key: &str,
    package_name: &str,
    tarball_version: Option<&str>,
) -> bool {
    let Some(scope) = npm_scope_of(path) else {
        return true;
    };
    if !state.config.npm.owned_scopes().any(|owned| owned == scope) {
        return true;
    }
    let published_here = match tarball_version {
        Some(version) => state
            .storage
            .stat(&format!("npm/{package_name}/versions/{version}.json"))
            .await
            .is_some(),
        None => !state
            .storage
            .list(&format!("npm/{package_name}/versions/"))
            .await
            .unwrap_or_default()
            .is_empty(),
    };
    if published_here {
        return true;
    }
    let Some(owner) = state.config.npm.route(path) else {
        return false;
    };
    let recorded = state.storage.get(&origin_key(key)).await.ok();
    let pin = state.storage.pin(key).await;
    npm_links::copy_is_owners(recorded.as_deref(), pin.as_deref(), owner.url)
}

/// Refetch metadata from upstream, rewrite URLs, update cache. An error says why there is no
/// document: `NotFound` for one the upstream does not have or NORA does not serve, the
/// upstream's failure otherwise (a caller with a cached copy serves it stale).
///
/// `key` is the cache written; `seed_key` holds the copy being revalidated (`key`, or what an
/// older release cached), from which a missing first-seen ledger starts. `ledger` says whether
/// the document is a packument, whose versions the ledger records. `conditional` says whether the
/// cached copy may be kept on a 304: not one holding a link past NORA.
async fn refetch_metadata(
    state: &AppState,
    path: &str,
    key: &str,
    seed_key: &str,
    ledger: bool,
    conditional: bool,
) -> Result<Vec<u8>, ProxyError> {
    let upstream = state.config.npm.route(path).ok_or(ProxyError::NotFound)?;
    let proxy_url = upstream.url;
    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), path);

    // Revalidate with a conditional request when enabled and we have stored
    // validators. Empty validators ⇒ no conditional headers ⇒ always a 200,
    // which is also how the first fetch captures validators for next time (#596).
    let validators = if state.config.npm.revalidate && conditional {
        read_validators(&state.storage, key)
            .await
            .unwrap_or_default()
    } else {
        Validators::default()
    };
    let had_validators = validators.is_some();

    match proxy_fetch_conditional(
        metadata_client(state, upstream.scoped),
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        upstream.auth,
        &validators,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Npm, upstream.url),
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
                    // upstream download. The release ages are not in it: before the re-put,
                    // the ledger takes over a cache from before it existed.
                    if ledger {
                        record_first_seen(state, key, &cached, Some(seed_key)).await;
                    }
                    let storage = state.storage.clone();
                    let key_clone = key.to_string();
                    let body = cached.clone();
                    let origin = origin_of(proxy_url);
                    tokio::spawn(async move {
                        let _ = put_with_origin(&storage, &key_clone, &body, &origin).await;
                    });
                    Ok(cached.to_vec())
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
                    Err(ProxyError::NotFound)
                }
            }
        }
        // New body — rewrite, cache it, then persist the fresh validators.
        Ok(Revalidation::Modified { body, validators }) => {
            // A version manifest whose tarball is now outside the upstream is not cached.
            let rewritten = rewrite_for_nora(state, &body, proxy_url, path, Links::Stored)
                .ok_or(ProxyError::NotFound)?;

            // Before the cached copy is replaced: it may be the one a ledger starts from.
            if ledger {
                record_first_seen(state, key, &rewritten, Some(seed_key)).await;
            }
            let storage = state.storage.clone();
            let key_clone = key.to_string();
            let cache_data = rewritten.clone();
            let origin = origin_of(proxy_url);
            tokio::spawn(async move {
                // Body first; the validator sidecar must never advertise
                // freshness for a body that isn't there (#596).
                if let Err(e) = put_with_origin(&storage, &key_clone, &cache_data, &origin).await {
                    tracing::warn!(key = %key_clone, error = ?e, "npm proxy: failed to cache metadata");
                    return;
                }
                write_validators(&storage, &key_clone, &validators).await;
            });

            Ok(rewritten)
        }
        // Upstream unavailable / error — fall back to the caller's serve_stale /
        // 502 path exactly as before.
        Err(e) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["npm"])
                    .inc();
            }
            Err(e)
        }
    }
}

// ============================================================================
// Published and upstream metadata, in separate keys
// ============================================================================
//
// A package published to NORA owns `npm/<name>/metadata.json` (the packument assembled from
// its versions), `versions/`, `dist-tags/` and `pkg.json`; only publish and the rebuild write
// them. What an upstream serves for a package NORA has not published is cached under
// `npm/<name>/upstream/`. A packument or version request for a published package is answered
// from its own keys and never reaches an upstream, so an upstream document cannot take a
// published one's place: the two never share a key.

/// What an npm metadata path (not a tarball) names.
#[derive(Debug, PartialEq, Eq)]
enum MetadataPath<'a> {
    /// A packument: `pkg` or `@scope/pkg`.
    Packument { name: &'a str },
    /// One version's manifest: `pkg/<spec>` or `@scope/pkg/<spec>`, spec a version or a dist-tag.
    VersionManifest { name: &'a str, spec: &'a str },
    /// Anything else, such as registry endpoints under `-/`.
    Other,
}

/// Classify an npm metadata path. Pure: which keys a request may read and write hangs on it.
fn classify_metadata_path(path: &str) -> MetadataPath<'_> {
    let segments: Vec<&str> = path.split('/').collect();
    // `-/…` is the registry's own endpoint space; a package name may still start with `-`.
    if segments.iter().any(|s| s.is_empty()) || segments[0] == "-" {
        return MetadataPath::Other;
    }
    let name_segments = if segments[0].starts_with('@') { 2 } else { 1 };
    if segments.len() < name_segments {
        return MetadataPath::Other;
    }
    let name_len = segments[..name_segments]
        .iter()
        .map(|s| s.len())
        .sum::<usize>()
        + name_segments
        - 1;
    let name = &path[..name_len];
    match segments.len() - name_segments {
        0 => MetadataPath::Packument { name },
        1 => MetadataPath::VersionManifest {
            name,
            spec: segments[name_segments],
        },
        _ => MetadataPath::Other,
    }
}

/// The package `npm dist-tag ls` asks about: `-/package/<name>/dist-tags`, name `pkg` or
/// `@scope/pkg`.
fn dist_tags_package(path: &str) -> Option<&str> {
    let name = path
        .strip_prefix("-/package/")?
        .strip_suffix("/dist-tags")?;
    match classify_metadata_path(name) {
        MetadataPath::Packument { name } => Some(name),
        _ => None,
    }
}

/// `GET -/package/<name>/dist-tags`: a published package's tags from its own keys; for any
/// other package the upstream answers, uncached.
async fn serve_dist_tags(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    name: &str,
) -> Response {
    let own = match published_state(&state.storage, name).await {
        // Tags derived from the versions (`latest` when no pointer names it) need them all.
        Published::Yes(published) => match assemble_packument(&state.storage, name).await {
            Ok(bytes) if listed_versions(&bytes).as_ref() != Some(&published) => {
                return published_versions_unreadable(state, name, &published, &bytes).await;
            }
            Ok(bytes) => Some(bytes),
            Err(unassembled) => return unassembled.response(name),
        },
        Published::Unknown => {
            let key = published_packument_key(name);
            match state.storage.get(&key).await {
                Ok(data) if is_assembled_by_nora(&state.storage, &key, &data).await => {
                    Some(data.to_vec())
                }
                // Without one NORA cannot tell whether the tags are its own.
                _ => return crate::registry::storage_unavailable("npm", &key),
            }
        }
        Published::No => None,
    };
    let Some(packument) = own else {
        return uncached_upstream_metadata(state, headers, path, name, None).await;
    };
    let tags = serde_json::from_slice::<serde_json::Value>(&packument)
        .ok()
        .and_then(|doc| doc.get("dist-tags").cloned())
        .unwrap_or_else(|| serde_json::json!({}));
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        tags.to_string(),
    )
        .into_response()
}

/// The packument NORA assembles for a package published to it. Publish and the rebuild are
/// its only writers.
pub(crate) fn published_packument_key(name: &str) -> String {
    format!("npm/{name}/metadata.json")
}

/// Where the packument an upstream serves for a package NORA has not published is cached.
pub(crate) fn upstream_packument_key(name: &str) -> String {
    format!("npm/{name}/upstream/packument.json")
}

/// Where one version's manifest that an upstream serves is cached.
fn upstream_manifest_key(name: &str, spec: &str) -> String {
    format!("npm/{name}/upstream/manifests/{spec}.json")
}

/// Where a release before 1.4.0 cached an upstream document for `path`. Read as a cache until
/// the new key is written, never written or deleted, so a rollback still finds it.
fn legacy_cache_key(path: &str) -> String {
    format!("npm/{path}/metadata.json")
}

/// Whether a package is published to NORA, from its `versions/` listing.
enum Published {
    /// These versions are published.
    Yes(std::collections::BTreeSet<String>),
    No,
    /// The listing failed: nothing is decided on a guess.
    Unknown,
}

async fn published_state(storage: &crate::Storage, name: &str) -> Published {
    let prefix = format!("npm/{name}/versions/");
    match storage.list(&prefix).await {
        // An empty listing beside a packument NORA assembled is not taken at its word: the
        // package was published, and a backend that answers "nothing here" for files it cannot
        // read must not hand its name to an upstream.
        Ok(keys) if keys.is_empty() => {
            let key = published_packument_key(name);
            match storage.get(&key).await {
                Ok(data) if is_assembled_by_nora(storage, &key, &data).await => {
                    tracing::warn!(registry = "npm", package = %name, "npm: no published versions listed beside an assembled packument");
                    Published::Unknown
                }
                _ => Published::No,
            }
        }
        Ok(keys) => Published::Yes(
            keys.iter()
                .filter_map(|k| k.strip_prefix(&prefix)?.strip_suffix(".json"))
                .map(str::to_string)
                .collect(),
        ),
        Err(e) => {
            tracing::warn!(registry = "npm", package = %name, error = %e, "npm: versions listing failed");
            Published::Unknown
        }
    }
}

/// The key a reader of a package's packument (release dates, the web UI) reads: the
/// published one, else the upstream cache, else what an older release cached.
pub(crate) async fn packument_key_for_reading(storage: &crate::Storage, name: &str) -> String {
    match published_state(storage, name).await {
        Published::Yes(_) => return published_packument_key(name),
        // The listing failed: a packument NORA assembled is still the one to read.
        Published::Unknown => {
            let key = published_packument_key(name);
            if let Ok(data) = storage.get(&key).await {
                if is_assembled_by_nora(storage, &key, &data).await {
                    return key;
                }
            }
        }
        Published::No => {}
    }
    let cached = upstream_packument_key(name);
    if storage.stat(&cached).await.is_some() {
        cached
    } else {
        legacy_cache_key(name)
    }
}

/// The origin a published packument's provenance record names: NORA assembled these bytes
/// from the package's published keys.
const ASSEMBLED_BY_NORA: &str = "nora-published";

/// Whether a stored published packument may be served as it is. Only bytes NORA assembled are:
/// their record names [`ASSEMBLED_BY_NORA`] and the digest of exactly the bytes stored now.
/// Anything else — no record (an older release, which never wrote one, cached it), an upstream's
/// record, a record written for other bytes — is rebuilt from the published keys. Pure: the
/// whole decision is this function.
fn assembled_by_nora(record: Option<&str>, stored_digest: &str) -> bool {
    record
        .and_then(|r| r.split_once('\n'))
        .is_some_and(|(origin, digest)| {
            origin == ASSEMBLED_BY_NORA && !digest.is_empty() && digest == stored_digest
        })
}

/// [`assembled_by_nora`] for the object at `key` holding `data`.
async fn is_assembled_by_nora(storage: &crate::Storage, key: &str, data: &[u8]) -> bool {
    let record = storage.get(&origin_key(key)).await.ok();
    let record = record.as_deref().and_then(|r| std::str::from_utf8(r).ok());
    let digest = match storage.pin(key).await {
        Some(pin) => pin,
        None => hex::encode(sha2::Sha256::digest(data)),
    };
    assembled_by_nora(record, &digest)
}

/// Store a packument NORA assembled for a published package, with the record that lets it be
/// served as it is (see [`assembled_by_nora`]). Data first: a record always describes bytes
/// already written; a failed record write only costs a rebuild at the next read.
async fn store_assembled_packument(
    storage: &crate::Storage,
    name: &str,
    bytes: &[u8],
) -> Result<(), crate::storage::StorageError> {
    let key = published_packument_key(name);
    storage.put(&key, bytes).await?;
    let record = provenance_record(ASSEMBLED_BY_NORA, bytes);
    if let Err(e) = storage.put(&origin_key(&key), record.as_bytes()).await {
        tracing::warn!(key = %key, error = ?e, "npm: failed to record an assembled packument");
    }
    Ok(())
}

/// Whether the object at `key` was cached from an upstream: its provenance record exists and
/// was written for exactly the bytes stored now (the pin).
async fn is_upstream_copy(storage: &crate::Storage, key: &str) -> bool {
    let Ok(recorded) = storage.get(&origin_key(key)).await else {
        return false;
    };
    let Some((origin, digest)) = std::str::from_utf8(&recorded)
        .ok()
        .and_then(|r| r.split_once('\n'))
    else {
        return false;
    };
    origin != ASSEMBLED_BY_NORA && storage.pin(key).await.as_deref() == Some(digest)
}

/// The version names a packument document lists, or `None` when it does not parse. The
/// version documents are skipped, not built: this runs on every read of a published packument.
fn listed_versions(data: &[u8]) -> Option<std::collections::BTreeSet<String>> {
    #[derive(serde::Deserialize)]
    struct Listing {
        versions: std::collections::BTreeMap<String, serde::de::IgnoredAny>,
    }
    let listing: Listing = serde_json::from_slice(data).ok()?;
    Some(listing.versions.into_keys().collect())
}

/// Answer a packument or version request for a published package, or for one cached from an
/// upstream. `target` is a packument or a version manifest.
async fn serve_metadata(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    target: MetadataPath<'_>,
) -> Response {
    let (name, spec, cache_key) = match target {
        MetadataPath::Packument { name } => (name, None, upstream_packument_key(name)),
        MetadataPath::VersionManifest { name, spec } => {
            (name, Some(spec), upstream_manifest_key(name, spec))
        }
        MetadataPath::Other => return StatusCode::NOT_FOUND.into_response(),
    };
    if let Err(e) = crate::validation::validate_storage_key(&cache_key) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    match published_state(&state.storage, name).await {
        Published::Yes(versions) => match spec {
            None => published_packument_response(state, headers, name, &versions).await,
            Some(spec) => published_version_manifest(state, name, spec).await,
        },
        Published::No => {
            upstream_metadata(state, headers, path, name, &cache_key, spec.is_none()).await
        }
        // The listing failed. A packument NORA assembled is still here: the package is published,
        // and its documents are served as they are, read only. Without one, or with an upstream copy
        // in its place, the package is unavailable and no upstream is asked.
        Published::Unknown => {
            let key = published_packument_key(name);
            match state.storage.get(&key).await {
                Ok(data) if is_assembled_by_nora(&state.storage, &key, &data).await => match spec {
                    None => packument_response(headers, data),
                    Some(spec) => published_version_manifest(state, name, spec).await,
                },
                // Without one NORA cannot tell whether the package is its own: unavailable (503), as
                // cargo answers a crate it cannot tell is published. A published name is never an
                // upstream's to answer for.
                _ => crate::registry::storage_unavailable("npm", &key),
            }
        }
    }
}

/// The packument of a published package. The stored document is served when it lists exactly
/// the published versions and is not an upstream copy (an older release, or another replica
/// running one, could still have cached one over it); otherwise it is rebuilt from the
/// published keys under the publish lock. Rebuilt bytes are served even when they cannot be
/// stored; 503 only when they cannot be assembled.
async fn published_packument_response(
    state: &AppState,
    headers: &HeaderMap,
    name: &str,
    published: &std::collections::BTreeSet<String>,
) -> Response {
    let key = published_packument_key(name);
    let current = |data: &Bytes| listed_versions(data).as_ref() == Some(published);
    if let Ok(data) = state.storage.get(&key).await {
        if current(&data) && is_assembled_by_nora(&state.storage, &key, &data).await {
            state.metrics.record_cache_hit("npm");
            return packument_response(headers, data);
        }
    }
    // LOCK-SAFE: tokio mutex, the one publish holds while it writes this package; a CI fleet
    // reading a stale packument rebuilds it once. Nothing else is locked under it.
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;
    // A publish or a retention pass may have changed the versions while this read waited.
    let relisted = match published_state(&state.storage, name).await {
        Published::Yes(versions) => versions,
        _ => published.clone(),
    };
    let published = &relisted;
    let current = |data: &Bytes| listed_versions(data).as_ref() == Some(published);
    if let Ok(data) = state.storage.get(&key).await {
        if current(&data) && is_assembled_by_nora(&state.storage, &key, &data).await {
            state.metrics.record_cache_hit("npm");
            return packument_response(headers, data);
        }
    }
    match assemble_packument(&state.storage, name).await {
        // A version whose document cannot be read would silently leave the packument, and every
        // read would rebuild it again: the package is unavailable until it is repaired, and says
        // which versions keep it so.
        Ok(bytes) if listed_versions(&bytes).as_ref() != Some(published) => {
            published_versions_unreadable(state, name, published, &bytes).await
        }
        Ok(bytes) => {
            PACKUMENT_REBUILT_TOTAL.with_label_values(&["npm"]).inc();
            tracing::info!(registry = "npm", package = %name, "Rebuilt packument from per-version keys");
            if let Err(e) = store_assembled_packument(&state.storage, name, &bytes).await {
                tracing::warn!(registry = "npm", package = %name, error = %e, "rebuilt packument not stored; served anyway");
            }
            state.metrics.record_cache_hit("npm");
            packument_response(headers, Bytes::from(bytes))
        }
        Err(unassembled) => unassembled.response(name),
    }
}

/// The answer for a published package whose assembled packument `bytes` left out some of its
/// `published` versions: their documents could not be read. Each is read again and its failure
/// says why — 500 for a copy that fails its integrity check, else 503. The package is
/// unavailable until it is repaired, never served without the versions.
async fn published_versions_unreadable(
    state: &AppState,
    name: &str,
    published: &std::collections::BTreeSet<String>,
    bytes: &[u8],
) -> Response {
    let assembled = listed_versions(bytes).unwrap_or_default();
    let unreadable: Vec<&String> = published.difference(&assembled).collect();
    tracing::error!(
        registry = "npm",
        package = %name,
        versions = ?unreadable,
        "published versions cannot be read; packument not served"
    );
    let mut failure = None;
    for version in unreadable {
        let key = format!("npm/{name}/versions/{version}.json");
        match state.storage.get(&key).await {
            Err(e @ crate::storage::StorageError::IntegrityViolation) => {
                return crate::registry::local_copy_unreadable("npm", &key, &e);
            }
            Err(e) => failure = failure.or(Some((key, e))),
            Ok(_) => {}
        }
    }
    match failure {
        Some((key, e)) => crate::registry::local_copy_unreadable("npm", &key, &e),
        None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// The manifest of one version of a published package, by version or by dist-tag, from its
/// own keys; 404 when neither names a published version. No upstream is asked. A tag or a
/// document the store cannot read is unavailable (503, 500 for a copy that fails its integrity
/// check), not absent.
async fn published_version_manifest(state: &AppState, name: &str, spec: &str) -> Response {
    use crate::storage::StorageError;
    let tag_key = format!("npm/{name}/dist-tags/{spec}");
    let version = match state.storage.get(&tag_key).await {
        Ok(tagged) => String::from_utf8_lossy(&tagged).trim().to_string(),
        Err(StorageError::NotFound | StorageError::Validation(_)) => spec.to_string(),
        Err(e) => return crate::registry::local_copy_unreadable("npm", &tag_key, &e),
    };
    let key = format!("npm/{name}/versions/{version}.json");
    match state.storage.get(&key).await {
        Ok(doc) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            doc,
        )
            .into_response(),
        Err(StorageError::NotFound | StorageError::Validation(_)) => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => crate::registry::local_copy_unreadable("npm", &key, &e),
    }
}

/// Rewrite an upstream document's tarball URLs to point at NORA, leaving out the versions whose
/// tarball lies outside the upstream. `None` for a version manifest whose tarball does: no version
/// NORA serves.
fn rewrite_for_nora(
    state: &AppState,
    data: &[u8],
    proxy_url: &str,
    path: &str,
    links: Links,
) -> Option<Vec<u8>> {
    place_for_nora(state, data, proxy_url, path, links).map(|placed| placed.body)
}

/// [`rewrite_for_nora`], saying whether a version was left out.
fn place_for_nora(
    state: &AppState,
    data: &[u8],
    proxy_url: &str,
    path: &str,
    links: Links,
) -> Option<Placed> {
    let nora_base = nora_base_url(state);
    let package = match classify_metadata_path(path) {
        MetadataPath::Packument { name } | MetadataPath::VersionManifest { name, .. } => Some(name),
        MetadataPath::Other => None,
    };
    match place_document(data, &nora_base, proxy_url, package, links) {
        Ok(placed) => Some(placed),
        Err(Unrewritable::OffUpstream) => None,
        Err(Unrewritable::NotJson) => {
            tracing::warn!(path = %path, "npm metadata JSON parse failed, using byte-level URL rewrite");
            let upstream_trimmed = proxy_url.trim_end_matches('/');
            let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));
            Some(Placed {
                body: replace_upstream_bytes(data, upstream_trimmed, &nora_npm_base),
                left_out: false,
            })
        }
    }
}

/// Whether every tarball link of a cached document is already on NORA, as NORA writes it. Only the
/// links are read (the rest is skipped unbuilt), so a cached document is placed again
/// ([`served_copy`]) only when it holds a link of another form (a relative one) or one past NORA,
/// cached by a release that kept it — or does not read as a packument or manifest at all.
fn links_on_nora(data: &[u8], nora_base: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct Dist {
        tarball: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Version {
        dist: Option<Dist>,
    }
    #[derive(serde::Deserialize)]
    struct Document {
        versions: Option<std::collections::HashMap<String, Version>>,
        dist: Option<Dist>,
    }
    let Ok(doc) = serde_json::from_slice::<Document>(data) else {
        return false;
    };
    let nora = format!("{}/npm/", nora_base.trim_end_matches('/'));
    let on_nora = |dist: &Option<Dist>| {
        dist.as_ref()
            .and_then(|d| d.tarball.as_deref())
            .is_none_or(|link| link.starts_with(&nora))
    };
    on_nora(&doc.dist) && doc.versions.iter().flatten().all(|(_, v)| on_nora(&v.dist))
}

/// What NORA serves of an upstream document it cached: the document itself when every tarball
/// link in it is NORA's, else the document placed again, as a fresh one is — the versions whose
/// tarball lies outside the upstream left out. `None` for a version manifest whose tarball does.
/// The flag says whether the copy held such a link (cached by a release that kept one).
fn served_copy(state: &AppState, path: &str, data: Bytes) -> (Option<Bytes>, bool) {
    if links_on_nora(&data, &nora_base_url(state)) {
        return (Some(data), false);
    }
    let upstream = state
        .config
        .npm
        .route(path)
        .map(|u| u.url)
        .unwrap_or_default();
    match place_for_nora(state, &data, upstream, path, Links::Served) {
        Some(placed) => (Some(Bytes::from(placed.body)), placed.left_out),
        None => (None, true),
    }
}

/// The document an upstream serves for `path` and the client's `query`, for this request only:
/// nothing is cached. Used for registry endpoints such as search, and for the dist-tags of a
/// package NORA has not published. The query goes as the client sent it (#1148), unless it
/// names a private package (ADR-8, [`search_names_private`]).
async fn uncached_upstream_metadata(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    name: &str,
    query: Option<&str>,
) -> Response {
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        name,
    ) {
        return response;
    }
    if query.is_some_and(|q| search_names_private(state, q)) {
        return audit_refused(
            StatusCode::UNPROCESSABLE_ENTITY,
            "this search names an internal package or a scope of a private upstream; \
             NORA does not send such names to the upstream",
        );
    }
    let Some(upstream) = state.config.npm.route(path) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut url = format!("{}/{}", upstream.url.trim_end_matches('/'), path);
    if let Some(query) = query {
        url.push('?');
        url.push_str(query);
    }
    match proxy_fetch(
        metadata_client(state, upstream.scoped),
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        upstream.auth,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Npm, upstream.url),
    )
    .await
    {
        Ok(data) => match rewrite_for_nora(state, &data, upstream.url, path, Links::Served) {
            Some(rewritten) => packument_response(headers, Bytes::from(rewritten)),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

/// Whether a query names a package that must not reach the upstream: under a namespace filter
/// or a scope owned by a private upstream, a word of any value (`text=react @corp/x`,
/// `scope:corp`, `keywords:corp-x`) that is an internal name, or an owned scope. A value that
/// does not decode as UTF-8 cannot be checked and counts as naming one (fail closed). With no
/// filter and no owned scope, nothing is private.
fn search_names_private(state: &AppState, query: &str) -> bool {
    let engine = &state.curation().curation_engine;
    let owned: Vec<&str> = state.config.npm.owned_scopes().collect();
    if !crate::curation::namespace_filter_active(engine) && owned.is_empty() {
        return false;
    }
    let internal = |name: &str| {
        crate::curation::is_internal_namespace(engine, crate::curation::RegistryType::Npm, name)
    };
    let scope_is_private =
        |scope: &str| owned.contains(&scope) || internal(&format!("{scope}/x")) || internal(scope);
    query.split('&').any(|pair| {
        let value = pair
            .split_once('=')
            .map_or("", |(_, v)| v)
            .replace('+', " ");
        let Ok(value) = percent_encoding::percent_decode_str(&value).decode_utf8() else {
            return true;
        };
        value.split_whitespace().any(|word| {
            let (qualifier, term) = word.split_once(':').unwrap_or(("", word));
            if qualifier == "scope" {
                let scope = format!("@{}", term.trim_start_matches('@'));
                return scope_is_private(&scope);
            }
            let scope = if term.starts_with('@') {
                term.split('/').next()
            } else {
                None
            };
            internal(term) || scope.is_some_and(scope_is_private)
        })
    })
}

/// [`packument_response`] for a cached upstream document, as [`served_copy`] has it; 404 for a
/// version manifest whose tarball lies outside the upstream.
fn served_packument(state: &AppState, headers: &HeaderMap, path: &str, data: Bytes) -> Response {
    match served_copy(state, path, data) {
        (Some(data), _) => packument_response(headers, data),
        (None, _) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// A packument or version manifest of a package NORA has not published: from its cache under
/// `npm/<name>/upstream/` (or, until that is written, what an older release cached), revalidated
/// after the metadata TTL, else fetched from the upstream and cached. `packument` says whether
/// the document is a packument, whose versions the first-seen ledger records.
async fn upstream_metadata(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    name: &str,
    cache_key: &str,
    packument: bool,
) -> Response {
    let legacy_key = legacy_cache_key(path);
    let mut cached = None;
    let mut read_failure = None;
    for key in [cache_key, legacy_key.as_str()] {
        if !cached_copy_trusted(state, path, key, name, None).await {
            continue;
        }
        match crate::registry::cached_read(state.storage.get_verified(key).await) {
            (Some(outcome), _) => {
                use nora_registry::verified::{verified_body, GateOutcome};
                let data = match outcome {
                    GateOutcome::Verified(blob) => verified_body(blob),
                    GateOutcome::Unpinned(blob) => blob.into_inner(),
                };
                cached = Some((data, key.to_string()));
                break;
            }
            (None, failure) => {
                read_failure = read_failure.or_else(|| failure.map(|e| (key.to_string(), e)));
            }
        }
    }

    if let Some((data, from_key)) = cached {
        // A copy holding a link past NORA (cached by a release that kept one) is served placed
        // again, and refetched in full whatever its age: a 304 would keep it as it is.
        let (served, past_nora) = served_copy(state, path, data);
        let fresh = !past_nora
            && state.storage.stat(&from_key).await.is_some_and(|meta| {
                crate::cache_ttl::is_within_ttl(meta.modified, state.config.npm.metadata_ttl)
            });
        // #68 namespace isolation: an internal-namespace package is never revalidated upstream.
        if fresh
            || crate::curation::is_internal_namespace(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Npm,
                name,
            )
        {
            return match served {
                Some(data) => packument_response(headers, data),
                None => StatusCode::NOT_FOUND.into_response(),
            };
        }
        // Single-flight: a CI fleet stampeding one expired packument revalidates it once (#595).
        let refetch = || async {
            refetch_metadata(state, path, cache_key, &from_key, packument, !past_nora)
                .await
                .ok()
                .map(Bytes::from)
        };
        let refreshed = if state.config.server.proxy_coalesce {
            let budget = crate::proxy_coalesce::follower_budget(state.config.npm.proxy_timeout);
            state
                .proxy_coalesce
                .coalesced(cache_key, "npm", budget, refetch)
                .await
        } else {
            refetch().await
        };
        if let Some(refreshed) = refreshed {
            return served_packument(state, headers, path, refreshed);
        }
        if state.config.npm.serve_stale {
            tracing::warn!(registry = "npm", path = %path, "npm upstream unavailable, serving stale metadata");
            let Some(data) = served else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let (stale_body, stale_type) = packument_body(headers, data);
            return (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, HeaderValue::from_static(stale_type)),
                    (header::VARY, HeaderValue::from_static("Accept")),
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=0, must-revalidate"),
                    ),
                    (
                        axum::http::header::HeaderName::from_static("x-nora-stale"),
                        HeaderValue::from_static("true"),
                    ),
                ],
                stale_body.to_vec(),
            )
                .into_response();
        }
        return StatusCode::BAD_GATEWAY.into_response();
    }

    // An internal package whose cached copy the store could not read is unavailable, not absent.
    if let Some((key, e)) = read_failure.as_ref().filter(|_| is_internal(state, name)) {
        return crate::registry::local_copy_unreadable("npm", key, e);
    }
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        name,
    ) {
        return response;
    }
    let Some(upstream) = state.config.npm.route(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let url = format!("{}/{}", upstream.url.trim_end_matches('/'), path);
    match proxy_fetch(
        metadata_client(state, upstream.scoped),
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        upstream.auth,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Npm, upstream.url),
    )
    .await
    {
        Ok(data) => {
            let Some(rewritten) = rewrite_for_nora(state, &data, upstream.url, path, Links::Stored)
            else {
                return StatusCode::NOT_FOUND.into_response();
            };
            if packument {
                record_first_seen(state, cache_key, &rewritten, None).await;
            }
            use futures::FutureExt as _;
            use std::panic::AssertUnwindSafe;
            let storage = state.storage.clone();
            let key = cache_key.to_string();
            let body = rewritten.clone();
            let origin = origin_of(upstream.url);
            let task = async move {
                if let Err(e) = put_with_origin(&storage, &key, &body, &origin).await {
                    tracing::warn!(key = %key, error = ?e, "npm proxy: failed to cache metadata");
                }
            };
            tokio::spawn(AssertUnwindSafe(task).catch_unwind().map(|done| {
                if let Err(panic) = done {
                    tracing::error!(panic = ?panic, "npm metadata cache task panicked");
                }
            }));
            served_packument(state, headers, path, Bytes::from(rewritten))
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::warn!(registry = "npm", path = %path, error = ?e, "npm upstream failed, returning 502");
            StatusCode::BAD_GATEWAY.into_response()
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

/// Why an npm tarball cannot be imported as a published version.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ImportedTarballError {
    #[error("{0} is not the key of an npm tarball")]
    NotATarball(String),
    #[error("the tarball holds no package.json")]
    NoManifest,
    #[error("reading the tarball: {0}")]
    Read(#[from] std::io::Error),
    #[error("package.json: {0}")]
    Manifest(#[from] serde_json::Error),
    #[error("package.json names {found}, the tarball's key {expected}")]
    Mismatch { found: String, expected: String },
}

/// The most bytes of `package.json` an imported tarball is read for.
const IMPORTED_MANIFEST_MAX: u64 = 16 * 1024 * 1024;

/// The package, version and file name an npm tarball key (`npm/<name>/tarballs/<file>`) names.
fn tarball_key_parts(tarball_key: &str) -> Option<(&str, String, &str)> {
    let (name, file) = tarball_key
        .strip_prefix("npm/")?
        .rsplit_once("/tarballs/")?;
    let version = crate::curation::parse_npm_tarball_version(name, file)?;
    Some((name, version, file))
}

/// The key of the version document that publishes the npm tarball at `tarball_key`.
pub(crate) fn imported_version_key(tarball_key: &str) -> Option<String> {
    let (name, version, _) = tarball_key_parts(tarball_key)?;
    Some(format!("npm/{name}/versions/{version}.json"))
}

/// What an npm tarball imported from another registry publishes: the key of its version
/// document, and the document — the tarball's own `package.json` with the `dist` a publish
/// records: the tarball's URL at `public_base`, its SHA-1 (`shasum`) and SHA-512 (`integrity`).
/// The manifest must name the package and version the key does. Once the document is stored the
/// package is published: its packument is assembled from its own keys and never asked of an
/// upstream (see [`published_state`]).
pub(crate) fn imported_version_document(
    tarball_key: &str,
    tarball: impl std::io::Read,
    sha1_hex: &str,
    sha512: &[u8],
    public_base: &str,
) -> Result<(String, Vec<u8>), ImportedTarballError> {
    use std::io::Read;
    use std::path::Component;
    let (name, version, file) = tarball_key_parts(tarball_key)
        .ok_or_else(|| ImportedTarballError::NotATarball(tarball_key.to_string()))?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tarball));
    let mut manifest = None;
    for entry in archive.entries()? {
        let entry = entry?;
        // `npm pack` puts the manifest at `package/package.json`; older tarballs use another
        // top directory.
        let at_top = {
            let path = entry.path()?;
            let mut parts = path.components();
            matches!(
                (parts.next(), parts.next(), parts.next()),
                (Some(Component::Normal(_)), Some(Component::Normal(file)), None)
                    if file == "package.json"
            )
        };
        if at_top {
            let mut text = Vec::new();
            entry.take(IMPORTED_MANIFEST_MAX).read_to_end(&mut text)?;
            manifest = Some(serde_json::from_slice::<serde_json::Value>(&text)?);
            break;
        }
    }
    let mut doc = manifest.ok_or(ImportedTarballError::NoManifest)?;
    let found = format!(
        "{}@{}",
        doc.get("name").and_then(|v| v.as_str()).unwrap_or_default(),
        doc.get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
    );
    let expected = format!("{name}@{version}");
    let Some(obj) = doc.as_object_mut().filter(|_| found == expected) else {
        return Err(ImportedTarballError::Mismatch { found, expected });
    };
    obj.insert("_id".to_string(), serde_json::Value::String(expected));
    obj.insert(
        "dist".to_string(),
        serde_json::json!({
            "tarball": format!("{}/npm/{name}/-/{file}", public_base.trim_end_matches('/')),
            "shasum": sha1_hex,
            "integrity": format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(sha512)
            ),
        }),
    );
    Ok((
        format!("npm/{name}/versions/{version}.json"),
        serde_json::to_vec(&doc)?,
    ))
}

/// Why a publish's attachments were refused.
#[derive(Debug, thiserror::Error)]
enum AttachmentRefused {
    #[error("Invalid attachment filename")]
    InvalidName,
    #[error("attachment {0} is not the tarball of a version this publish carries")]
    NotThisPublish(String),
    #[error("Invalid base64 in attachment")]
    Base64(#[from] base64::DecodeError),
}

/// The file name a publish's attachment `filename` is stored under: the tarball
/// (`<name>-<version>.tgz`, the name with or without its scope) of one of the `versions` the
/// payload publishes. Anything else — another version's tarball, a key beside one, a path,
/// another scope's or another package's tarball — is refused.
fn tarball_of_this_publish<'a>(
    package_name: &str,
    filename: &'a str,
    versions: &serde_json::Map<String, serde_json::Value>,
) -> Result<&'a str, AttachmentRefused> {
    // A scoped package's attachment may carry its scope (`@scope/name-1.0.0.tgz`); without it
    // the name must be flat, with no path separator to traverse with.
    let (scope, short_name) = match package_name.split_once('/') {
        Some((scope, name)) => (Some(scope), name),
        None => (None, package_name),
    };
    let normalized_name = scope
        .and_then(|scope| filename.strip_prefix(scope)?.strip_prefix('/'))
        .unwrap_or(filename);
    if !is_valid_attachment_name(normalized_name) {
        return Err(AttachmentRefused::InvalidName);
    }
    if !versions
        .keys()
        .any(|version| normalized_name == format!("{short_name}-{version}.tgz"))
    {
        return Err(AttachmentRefused::NotThisPublish(
            normalized_name.to_string(),
        ));
    }
    Ok(normalized_name)
}

/// The tarballs a publish stores: each attachment decoded, under its tarball key. Every attachment,
/// with bytes or without, must be [`tarball_of_this_publish`]; one that is not refuses the whole
/// publish before anything is stored, so a publish cannot replace bytes clients installed or the
/// pin they are checked against.
fn publish_tarballs(
    package_name: &str,
    attachments: &serde_json::Map<String, serde_json::Value>,
    versions: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<(String, Vec<u8>)>, AttachmentRefused> {
    let mut tarballs = Vec::with_capacity(attachments.len());
    for (filename, attachment) in attachments {
        let tarball = tarball_of_this_publish(package_name, filename, versions)?;
        let Some(data) = attachment.get("data").and_then(|d| d.as_str()) else {
            continue;
        };
        let bytes = base64::engine::general_purpose::STANDARD.decode(data)?;
        tarballs.push((format!("npm/{package_name}/tarballs/{tarball}"), bytes));
    }
    Ok(tarballs)
}

async fn handle_publish(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Extension(authority): Extension<NamespaceAuthority>,
    user: Option<Extension<crate::auth::AuthenticatedUser>>,
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

    // Every attachment is checked, and decoded, before anything is stored.
    let tarballs = match publish_tarballs(&package_name, attachments, new_versions) {
        Ok(tarballs) => tarballs,
        Err(refused) => {
            tracing::warn!(
                package = %package_name,
                reason = %refused,
                "SECURITY: npm publish rejected — attachment refused"
            );
            return (StatusCode::BAD_REQUEST, refused.to_string()).into_response();
        }
    };

    // Lock per package to serialize the packument regeneration within one process.
    let metadata_key = published_packument_key(&package_name);
    let lock = state.publish_lock(&metadata_key);
    let _guard = lock.lock().await;

    // Read the existing packument ONCE — only to (a) refuse on corruption and (b) enforce version
    // immutability against versions still embedded in an un-migrated packument. The new versions
    // are NOT merged into it: each is written to its own immutable key and the packument is
    // regenerated by listing those keys, so concurrent publishers never read-modify-write the same
    // shared file (the multi-replica lost-update of #39).
    // A packument an upstream left at this key (an older release cached it there) holds no
    // published version: its versions are not imported, and do not block a publish.
    let upstream_copy = is_upstream_copy(&state.storage, &metadata_key).await;
    let existing_meta: Option<serde_json::Value> = match state.storage.get(&metadata_key).await {
        Ok(_) if upstream_copy => None,
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

    // Any other packument on a package with no per-version keys (no record of where it came
    // from, or one written for other bytes) may be a package published to NORA 0.9.3 or older,
    // or an upstream one NORA 1.3.3 or older cached: nothing tells them apart, and importing the
    // second would publish an upstream's versions.
    // The publish is refused until the operator says which it is.
    if existing_meta.is_some()
        && matches!(
            published_state(&state.storage, &package_name).await,
            Published::No
        )
        && !state.config.npm.import_embedded.contains(&package_name)
    {
        tracing::warn!(
            registry = "npm",
            package = %package_name,
            key = %metadata_key,
            "publish refused: packument of unknown origin"
        );
        return (
            StatusCode::CONFLICT,
            // npm shows a registry error's `error` field, not a plain-text body.
            axum::Json(serde_json::json!({ "error": format!(
                "{metadata_key} holds a packument with no record of where it came from: an upstream package cached by NORA 1.3.3 or older, or a package published to NORA 0.9.3 or older. Publishing over it would import its versions as published ones. If it is a cache, delete {metadata_key} and publish again; if it is your own package, set NORA_NPM_IMPORT_EMBEDDED={package_name} and publish again."
            ) })),
        )
            .into_response();
    }

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
    for (tarball_key, tarball_bytes) in &tarballs {
        if let Err(e) = state.storage.put(tarball_key, tarball_bytes).await {
            tracing::error!(key = %tarball_key, error = ?e, "npm publish: failed to store tarball");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        // Store sha256
        let hash = hex::encode(sha2::Sha256::digest(tarball_bytes));
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
    if regenerate_packument(&state.storage, &package_name)
        .await
        .is_err()
    {
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
    state.audit.log(AuditEntry::new(
        "push",
        crate::auth::audit_actor(&user),
        &package_name,
        "npm",
        "",
    ));
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
pub(crate) async fn regenerate_packument(
    storage: &crate::storage::Storage,
    package_name: &str,
) -> Result<(), ()> {
    let bytes = match assemble_packument(storage, package_name).await {
        Ok(bytes) => bytes,
        Err(unassembled) => {
            tracing::error!(registry = "npm", package = %package_name, reason = %unassembled, "packument not regenerated");
            return Err(());
        }
    };
    store_assembled_packument(storage, package_name, &bytes)
        .await
        .map_err(|_| ())
}

/// Why a published package's packument could not be assembled.
#[derive(Debug, thiserror::Error)]
enum Unassembled {
    /// The store could not read this key (or list this prefix).
    #[error("{0} cannot be read: {1}")]
    Unreadable(String, crate::storage::StorageError),
    /// The package fields are not a JSON object.
    #[error("the package fields are not a JSON object")]
    Malformed,
    /// The assembled document could not be encoded.
    #[error("the packument cannot be encoded: {0}")]
    Encode(#[from] serde_json::Error),
}

impl Unassembled {
    /// The answer for a read that needed the packument: 503, 500 for a copy that fails its
    /// integrity check.
    fn response(&self, name: &str) -> Response {
        match self {
            Unassembled::Unreadable(key, e) => {
                crate::registry::local_copy_unreadable("npm", key, e)
            }
            Unassembled::Malformed | Unassembled::Encode(_) => {
                tracing::warn!(registry = "npm", package = %name, reason = %self, "published packument cannot be assembled");
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            }
        }
    }
}

/// The packument of a published package, assembled from its published keys (`versions/`,
/// `dist-tags/`, `pkg.json`). A key the store cannot read fails it: a document without a tag or
/// the package fields would be served, or stored, as complete.
async fn assemble_packument(
    storage: &crate::storage::Storage,
    package_name: &str,
) -> Result<Vec<u8>, Unassembled> {
    let unreadable = |(key, e)| Unassembled::Unreadable(key, e);
    // versions map, keyed by the filename (version) without the .json suffix. Read
    // concurrently: on an object store every version is a round-trip, and this path now
    // runs on a read (#956), so a package with thousands of versions used to pay them
    // one after another. An unparsable document is skipped; the reader that compares the
    // versions with the published ones refuses the packument.
    let versions_prefix = format!("npm/{}/versions/", package_name);
    let mut versions = serde_json::Map::new();
    for (key, data) in super::read_keyed_blobs(storage, &versions_prefix)
        .await
        .map_err(unreadable)?
    {
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
    for (key, data) in super::read_keyed_blobs(storage, &dt_prefix)
        .await
        .map_err(unreadable)?
    {
        if let (Some(tag), Ok(ver)) = (key.rsplit('/').next(), String::from_utf8(data.to_vec())) {
            dist_tags.insert(tag.to_string(), serde_json::Value::String(ver));
        }
    }
    if !dist_tags.contains_key("latest") {
        if let Some(latest) = max_semver(versions.keys()) {
            dist_tags.insert("latest".to_string(), serde_json::Value::String(latest));
        }
    }

    // Package-level fields + the assembled maps -> the packument.
    let pkg_key = format!("npm/{}/pkg.json", package_name);
    let mut packument = match storage.get(&pkg_key).await {
        Ok(d) => serde_json::from_slice(&d).unwrap_or_else(|_| serde_json::json!({})),
        Err(crate::storage::StorageError::NotFound) => serde_json::json!({}),
        Err(e) => return Err(Unassembled::Unreadable(pkg_key, e)),
    };
    let obj = packument.as_object_mut().ok_or(Unassembled::Malformed)?;
    obj.insert(
        "name".to_string(),
        serde_json::Value::String(package_name.to_string()),
    );
    obj.insert(
        "dist-tags".to_string(),
        serde_json::Value::Object(dist_tags),
    );
    obj.insert("versions".to_string(), serde_json::Value::Object(versions));

    Ok(serde_json::to_vec(&packument)?)
}

/// Why retention could not bring a packument back in line with storage.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PackumentReconcileError {
    #[error("storage: {0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("cached packument is not JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cached packument is not a JSON object")]
    NotAnObject,
    #[error("regenerating the packument from published versions failed")]
    Regenerate,
}

/// Bring a package's packument back in line with storage after retention removed the
/// tarballs of `retired` versions. Runs under the package's packument `publish_lock`.
///
/// A package with published versions owns its packument (#975): it is reassembled from
/// `versions/`, as publish does. A proxied package has no `versions/` keys — its
/// packument is the cached upstream document, so it is edited instead of rebuilt:
/// regenerating it from `versions/` emptied it, and with the upstream unreachable the
/// surviving version could not be installed.
pub(crate) async fn reconcile_packument_after_retention(
    storage: &crate::storage::Storage,
    package_name: &str,
    retired: &std::collections::BTreeSet<String>,
) -> Result<(), PackumentReconcileError> {
    let published = storage
        .list(&format!("npm/{}/versions/", package_name))
        .await?;
    if published.is_empty() {
        prune_cached_packument(storage, package_name, retired).await
    } else {
        regenerate_packument(storage, package_name)
            .await
            .or(Err(PackumentReconcileError::Regenerate))
    }
}

/// Remove from a cached upstream packument the `retired` versions whose tarball is gone,
/// keeping every other version document as the upstream sent it.
///
/// Only what retention removed leaves the document: a version that was never fetched
/// through the proxy has no tarball here either, and that is a normal proxy cache, not
/// a retired version. A dist-tag left pointing at a removed version is dropped, and a
/// dropped `latest` is re-pointed at the highest version still advertised.
///
/// The upstream validators of the old document are cleared before it is replaced, so a
/// 304 cannot re-serve the edited copy as the upstream's. The provenance record is
/// carried over to the new bytes only when it vouched for the old ones.
async fn prune_cached_packument(
    storage: &crate::storage::Storage,
    package_name: &str,
    retired: &std::collections::BTreeSet<String>,
) -> Result<(), PackumentReconcileError> {
    // The upstream cache only: what an older release cached is never written (a rollback reads it).
    let key = upstream_packument_key(package_name);
    let old = match storage.get(&key).await {
        Ok(old) => old,
        // Nothing cached: the next read fetches the packument from the upstream.
        Err(crate::storage::StorageError::NotFound) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let tarballs = storage
        .list(&format!("npm/{}/tarballs/", package_name))
        .await?;
    let on_disk: std::collections::BTreeSet<String> = tarballs
        .iter()
        .filter_map(|key| key.rsplit('/').next())
        .filter_map(|file| crate::curation::parse_npm_tarball_version(package_name, file))
        .collect();

    let mut packument: serde_json::Value = serde_json::from_slice(&old)?;
    let obj = packument
        .as_object_mut()
        .ok_or(PackumentReconcileError::NotAnObject)?;
    let Some(versions) = obj.get_mut("versions").and_then(|v| v.as_object_mut()) else {
        return Ok(());
    };
    let before = versions.len();
    versions.retain(|version, _| !retired.contains(version) || on_disk.contains(version));
    if versions.len() == before {
        return Ok(());
    }
    let remaining: Vec<String> = versions.keys().cloned().collect();
    if let Some(tags) = obj.get_mut("dist-tags").and_then(|t| t.as_object_mut()) {
        tags.retain(|_, version| {
            version
                .as_str()
                .is_some_and(|v| remaining.iter().any(|r| r == v))
        });
        if !tags.contains_key("latest") {
            if let Some(latest) = max_semver(remaining.iter()) {
                tags.insert("latest".to_string(), serde_json::Value::String(latest));
            }
        }
    }
    let bytes = serde_json::to_vec(&packument)?;

    let validators = super::validators_key(&key);
    match storage.delete(&validators).await {
        Ok(()) | Err(crate::storage::StorageError::NotFound) => {}
        Err(e) => return Err(e.into()),
    }
    storage.put(&key, &bytes).await?;

    let record_key = origin_key(&key);
    if let Ok(record) = storage.get(&record_key).await {
        let vouched_origin = std::str::from_utf8(&record)
            .ok()
            .and_then(|record| record.split_once('\n'))
            .filter(|(_, digest)| *digest == hex::encode(sha2::Sha256::digest(&old)))
            .map(|(origin, _)| origin.to_string());
        if let Some(origin) = vouched_origin {
            if let Err(e) = storage
                .put(&record_key, provenance_record(&origin, &bytes).as_bytes())
                .await
            {
                tracing::warn!(key = %key, error = ?e, "npm: failed to record cache provenance");
            }
        }
    }
    Ok(())
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
    // A published package's dates are in its own packument; nothing upstream is cached for it.
    if !matches!(
        published_state(&state.storage, package_name).await,
        Published::No
    ) {
        return;
    }
    let key = upstream_packument_key(package_name);
    for cached in [key.as_str(), legacy_cache_key(package_name).as_str()] {
        if state.storage.get(cached).await.is_ok()
            && cached_copy_trusted(state, package_name, cached, package_name, None).await
        {
            return;
        }
    }
    // #68: never fetch an internal-namespace package's metadata upstream.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        package_name,
    ) {
        return;
    }
    let Some(upstream) = state.config.npm.route(package_name) else {
        return;
    };
    let proxy_url = upstream.url;
    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), package_name);
    if let Ok(data) = proxy_fetch(
        metadata_client(state, upstream.scoped),
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        upstream.auth,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Npm, upstream.url),
    )
    .await
    {
        // Rewrite tarball URLs to point at NORA, exactly as the proxy path and
        // refetch_metadata do, so a subsequent client reading the cached
        // packument is not sent back to the upstream.
        if let Some(rewritten) =
            rewrite_for_nora(state, &data, proxy_url, package_name, Links::Stored)
        {
            let _ = put_with_origin(&state.storage, &key, &rewritten, &origin_of(proxy_url)).await;
        }
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

/// npm's abbreviated packument — `application/vnd.npm.install-v1+json`, the
/// document an installer actually reads. Everything else (readme, maintainers,
/// repository, per-version `description`, `scripts`, `gitHead`) is dropped, and
/// on a package with many versions that is most of the bytes.
const NPM_INSTALL_V1: &str = "application/vnd.npm.install-v1+json";

/// The per-version fields npm keeps in the abbreviated form. This is an
/// allowlist on purpose: dropping a field an installer consults — `os`, `cpu`,
/// `engines`, `peerDependenciesMeta` — silently changes what gets resolved and
/// installed, so a field is added here, once, rather than at a call site.
const INSTALL_V1_VERSION_FIELDS: &[&str] = &[
    "name",
    "version",
    "dependencies",
    "optionalDependencies",
    "devDependencies",
    "bundleDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "acceptDependencies",
    "bin",
    "directories",
    "dist",
    "engines",
    "os",
    "cpu",
    "libc",
    "funding",
    "deprecated",
    "hasInstallScript",
    "_hasShrinkwrap",
];

/// Top-level fields kept alongside `versions`.
const INSTALL_V1_TOP_FIELDS: &[&str] = &["name", "dist-tags", "modified"];

/// True when the client asked for the abbreviated packument.
fn wants_install_v1(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains(NPM_INSTALL_V1))
}

/// Project a full packument down to the abbreviated form. `None` when the body
/// is not a packument we can parse — the caller then serves it unchanged.
fn abbreviate_packument(full: &[u8]) -> Option<Vec<u8>> {
    let doc: serde_json::Value = serde_json::from_slice(full).ok()?;
    let obj = doc.as_object()?;

    let mut out = serde_json::Map::new();
    for field in INSTALL_V1_TOP_FIELDS {
        if let Some(value) = obj.get(*field) {
            out.insert((*field).to_string(), value.clone());
        }
    }

    let mut versions = serde_json::Map::new();
    if let Some(source) = obj.get("versions").and_then(|v| v.as_object()) {
        for (version, manifest) in source {
            let Some(manifest) = manifest.as_object() else {
                continue;
            };
            let mut kept = serde_json::Map::new();
            for field in INSTALL_V1_VERSION_FIELDS {
                if let Some(value) = manifest.get(*field) {
                    kept.insert((*field).to_string(), value.clone());
                }
            }
            versions.insert(version.clone(), serde_json::Value::Object(kept));
        }
    }
    out.insert("versions".to_string(), serde_json::Value::Object(versions));

    serde_json::to_vec(&serde_json::Value::Object(out)).ok()
}

/// Serve a packument, honouring the abbreviated form when the client asks for it.
///
/// `Vary: Accept` is not decoration here: the body depends on a request header
/// and NORA marks metadata `Cache-Control: public`, so without it a shared cache
/// can hand the abbreviated document to a client that asked for the full one.
fn packument_body(headers: &HeaderMap, data: Bytes) -> (Bytes, &'static str) {
    if !wants_install_v1(headers) {
        return (data, "application/json");
    }
    match abbreviate_packument(&data) {
        Some(short) => (Bytes::from(short), NPM_INSTALL_V1),
        // Unparsable body: serve it unchanged. The client asked for a
        // projection of this document, not for an error.
        None => (data, "application/json"),
    }
}

fn packument_response(headers: &HeaderMap, data: Bytes) -> Response {
    let (body, content_type) = packument_body(headers, data);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60, must-revalidate"),
            ),
            (header::VARY, HeaderValue::from_static("Accept")),
        ],
        body,
    )
        .into_response()
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

/// Rewrite tarball URLs in npm metadata to point to NORA ([`place_document`]): the body alone,
/// as the tests read it.
#[cfg(test)]
fn rewrite_tarball_urls(
    data: &[u8],
    nora_base: &str,
    upstream_url: &str,
) -> Result<Vec<u8>, Unrewritable> {
    let package = serde_json::from_slice::<serde_json::Value>(data)
        .ok()
        .and_then(|doc| doc.get("name")?.as_str().map(str::to_string));
    place_document(
        data,
        nora_base,
        upstream_url,
        package.as_deref(),
        Links::Served,
    )
    .map(|placed| placed.body)
}

/// Serve at `<server>/<package>` a packument listing each `(version, at)`, its tarball at
/// `<server>/<at>`: NORA downloads an upstream tarball only for a listed version.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) async fn mount_listing(
    server: &wiremock::MockServer,
    package: &str,
    files: &[(&str, &str)],
) {
    let versions: serde_json::Map<String, serde_json::Value> = files
        .iter()
        .map(|(version, at)| {
            let tarball = format!("{}/{at}", server.uri());
            (
                version.to_string(),
                serde_json::json!({"dist": {"tarball": tarball}}),
            )
        })
        .collect();
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(format!("/{package}")))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"name": package, "versions": versions})),
        )
        .with_priority(1)
        .mount(server)
        .await;
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

    /// GitHub Packages' tarball path, as public lockfiles record it
    /// (`https://npm.pkg.github.com/download/@microsoft/…/1.11.0/<sha1>`).
    #[test]
    fn github_packages_tarball_path_is_recognised() {
        assert_eq!(
            github_packages_tarball(
                "download/@microsoft/security-devops-actions-toolkit/1.11.0/04fef883382f5a7c9b9ac2015dcc419009e2a858"
            ),
            Some(("@microsoft/security-devops-actions-toolkit", "1.11.0"))
        );
        assert_eq!(
            github_packages_tarball(
                "download/@CookieMonsterTeam/cookiemonsterframework/0.2.3/46a211d57dac557c86fc55f1622a6cccdf7dd25f"
            ),
            Some(("@CookieMonsterTeam/cookiemonsterframework", "0.2.3"))
        );
        // The npm package named `download`, its tarball and anything else.
        for path in [
            "download",
            "download/-/download-8.0.0.tgz",
            "download/@vendor/a/1.0.0",
            "download/@vendor/a/1.0.0/not-hex",
            "download/@vendor/a//04fef883382f5a7c9b9ac2015dcc419009e2a858",
            "download/@vendor/a/1.0.0/04fef883382f5a7c9b9ac2015dcc419009e2a858/x",
            "download/vendor/a/1.0.0/04fef883382f5a7c9b9ac2015dcc419009e2a858",
            "@vendor/a/-/a-1.0.0.tgz",
        ] {
            assert_eq!(github_packages_tarball(path), None, "{path}");
        }
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
            None,
            Bytes::from_static(b"{}"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // In scope -> enforcement passes (then fails payload validation, not 403).
        let resp = super::handle_publish(
            State(ctx.state.clone()),
            Path("@myorg/pkg".to_string()),
            Extension(scoped),
            None,
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
        // migrated on the next publish, preserving the old versions, once the operator has
        // said it is a published package (NORA 0.9.3 or older) and not an upstream's cache.
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.npm.import_embedded = vec!["legacy".to_string()];
        });
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
            None,
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
            .get("npm/testpkg/upstream/packument.json")
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
            "npm/testpkg/upstream/packument.json",
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
        let link = format!("{}/cachedpkg/-/cachedpkg-1.0.0.tgz", upstream.uri());
        let packument = serde_json::json!({
            "name": "cachedpkg",
            "versions": { "1.0.0": { "dist": { "tarball": link } } },
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

    /// Font Awesome's registry serves tarballs at `<name>/-/<version>/<file>.tgz`.
    /// The allowlist must read the version from that form too: without it the
    /// request carries no version and passes as a metadata request.
    #[tokio::test]
    async fn allowlist_checks_a_tarball_under_a_version_directory() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        for version in ["0.9.0", "1.0.0"] {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/@fortawesome/pro-test/-/{version}/pro-test-{version}.tgz"
                )))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_bytes(format!("TGZ {version}").into_bytes()),
                )
                .mount(&upstream)
                .await;
        }
        super::mount_listing(
            &upstream,
            "@fortawesome/pro-test",
            &[
                ("0.9.0", "@fortawesome/pro-test/-/0.9.0/pro-test-0.9.0.tgz"),
                ("1.0.0", "@fortawesome/pro-test/-/1.0.0/pro-test-1.0.0.tgz"),
            ],
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            r#"{"version": 1, "entries": [
                {"registry": "npm", "name": "@fortawesome/pro-test", "version": "0.9.0"}
            ]}"#,
        )
        .unwrap();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist.to_string_lossy().into_owned());
        });
        let tarball_requests = || async {
            upstream
                .received_requests()
                .await
                .unwrap()
                .into_iter()
                .filter(|r| r.url.path().ends_with(".tgz"))
                .count()
        };

        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/@fortawesome/pro-test/-/1.0.0/pro-test-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "unlisted version");
        assert_eq!(
            tarball_requests().await,
            0,
            "a blocked tarball is not fetched"
        );

        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/@fortawesome/pro-test/-/0.9.0/pro-test-0.9.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "control: the listed version");
        assert_eq!(&body_bytes(resp).await[..], b"TGZ 0.9.0");
    }

    /// The allowlist matches name and version. A tarball whose version cannot be
    /// read from its path is refused rather than passed on as a metadata request —
    /// including a version directory that names another version than the file.
    /// GitHub Packages serves tarballs at `download/<@scope/name>/<version>/<sha1>`, with
    /// no `/-/`. That is a tarball download: curation sees its version, and the object is
    /// stored as that version's tarball with its hash sidecar and served as one.
    #[tokio::test]
    async fn a_github_packages_tarball_is_a_download() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{header, Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const SHA: &str = "04fef883382f5a7c9b9ac2015dcc419009e2a858";
        let upstream = MockServer::start().await;
        for version in ["0.9.0", "1.0.0"] {
            Mock::given(method("GET"))
                .and(path(format!("/download/@vendor/a/{version}/{SHA}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_bytes(format!("TGZ {version}").into_bytes()),
                )
                .mount(&upstream)
                .await;
        }
        let at = |version: &str| format!("download/@vendor/a/{version}/{SHA}");
        let (old, new) = (at("0.9.0"), at("1.0.0"));
        super::mount_listing(&upstream, "@vendor/a", &[("0.9.0", &old), ("1.0.0", &new)]).await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            r#"{"version": 1, "entries": [{"registry": "npm", "name": "@vendor/a", "version": "0.9.0"}]}"#,
        )
        .unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/npm/download/@vendor/a/1.0.0/{SHA}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "unlisted version");
        let fetched = upstream.received_requests().await.unwrap();
        assert!(
            fetched
                .iter()
                .all(|r| !r.url.path().starts_with("/download/")),
            "a refused tarball is not fetched"
        );

        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/npm/download/@vendor/a/0.9.0/{SHA}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "control: the listed version");
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(&body_bytes(resp).await[..], b"TGZ 0.9.0");
        let storage = &ctx.state.storage;
        // The cache write runs in the background: wait for it, with a deadline.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        for key in [
            "npm/@vendor/a/tarballs/a-0.9.0.tgz",
            "npm/@vendor/a/tarballs/a-0.9.0.tgz.sha256",
        ] {
            while storage.stat(key).await.is_none() {
                assert!(tokio::time::Instant::now() < deadline, "{key} never stored");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        assert!(
            storage.list("npm/download/").await.unwrap().is_empty(),
            "no tarball stored as a packument"
        );
    }

    /// A GitHub Packages download path of a version the upstream's packument does not list is
    /// not asked for, as for the `/-/` form: 404, no `/download/` request.
    #[tokio::test]
    async fn an_unlisted_github_packages_download_is_not_asked_for() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const SHA: &str = "04fef883382f5a7c9b9ac2015dcc419009e2a858";
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/download/@vendor/a/0.9.0/{SHA}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"UNLISTED".to_vec()))
            .mount(&upstream)
            .await;
        let listed = format!("download/@vendor/a/1.0.0/{SHA}");
        super::mount_listing(&upstream, "@vendor/a", &[("1.0.0", &listed)]).await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/npm/download/@vendor/a/0.9.0/{SHA}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let fetched = upstream.received_requests().await.unwrap();
        assert!(
            fetched
                .iter()
                .all(|r| !r.url.path().starts_with("/download/")),
            "an unlisted tarball was fetched"
        );
    }

    /// A GitHub Packages download path of a package whose packument the upstream does not have
    /// (404) is not asked for either: 404, no `/download/` request, nothing cached.
    #[tokio::test]
    async fn a_github_packages_download_without_a_packument_upstream_is_not_asked_for() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const SHA: &str = "04fef883382f5a7c9b9ac2015dcc419009e2a858";
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/download/@vendor/a/1.0.0/{SHA}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"UNLISTED".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/npm/download/@vendor/a/1.0.0/{SHA}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let fetched = upstream.received_requests().await.unwrap();
        assert!(
            fetched
                .iter()
                .all(|r| !r.url.path().starts_with("/download/")),
            "a tarball without a packument was fetched"
        );
        let cached = ctx.state.storage.list("npm/").await.unwrap();
        assert!(cached.iter().all(|k| !k.contains("tarballs")), "{cached:?}");
    }

    #[tokio::test]
    async fn allowlist_refuses_a_tarball_whose_version_it_cannot_read() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"name":"pkg","versions":{}}"#),
            )
            .mount(&upstream)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"version": 1, "entries": [{"registry": "npm", "name": "pkg", "version": "1.0.0"}]}"#).unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        for path in ["/npm/pkg/-/pkg.tgz", "/npm/pkg/-/9.9.9/pkg-1.0.0.tgz"] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        }
        let fetched = upstream.received_requests().await.unwrap();
        assert!(
            fetched.iter().all(|r| !r.url.path().ends_with(".tgz")),
            "a refused tarball is not fetched: {:?}",
            fetched
                .iter()
                .map(|r| r.url.path().to_string())
                .collect::<Vec<_>>()
        );
        let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
        assert_ne!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "control: the packument passes"
        );
    }

    /// In audit mode the same tarball is logged, not refused; with no version to look up in the
    /// upstream's packument it is not fetched either.
    #[tokio::test]
    async fn audit_mode_does_not_refuse_a_tarball_with_an_unread_version() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg/-/pkg.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec()))
            .mount(&upstream)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"version": 1, "entries": [{"registry": "npm", "name": "pkg", "version": "1.0.0"}]}"#).unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Audit;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        let resp = send(&ctx.app, Method::GET, "/npm/pkg/-/pkg.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let asked = upstream.received_requests().await.unwrap();
        assert!(asked.iter().all(|r| r.url.path() != "/pkg/-/pkg.tgz"));
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

    /// `trust_upstream_dates = false`: the packument is asked once, for the listing the download
    /// is checked against. The count is the same whether or not the self-prime ran, so this does
    /// not tell the gate's branches apart; `upstream_dates_gate` does, by the release-age verdict.
    #[tokio::test]
    async fn with_distrusted_dates_a_tarball_asks_the_packument_once_for_its_listing() {
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
        super::mount_listing(
            &upstream,
            "distrust",
            &[("1.0.0", "distrust/-/distrust-1.0.0.tgz")],
        )
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
        assert_eq!(packument_hits, 1, "one fetch of the listing, no self-prime");
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
        for key in [
            "npm/noproxy/metadata.json",
            "npm/noproxy/upstream/packument.json",
        ] {
            assert!(
                ctx.state.storage.get(key).await.is_err(),
                "no proxy → {key} must not be self-primed"
            );
        }
    }

    /// JSON-parse failure in the upstream packument falls back to byte-level URL
    /// rewrite (replace_upstream_bytes), so the cached metadata still has NORA
    /// URLs and the body is preserved (fail-safe, not dropped). A packument that does not
    /// parse lists no version, so the tarball itself is not asked for.
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
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_ne!(&body_bytes(resp).await[..], tarball);
        let asked = upstream.received_requests().await.unwrap();
        assert!(asked.iter().all(|r| !r.url.path().ends_with(".tgz")));

        let cached = ctx
            .state
            .storage
            .get("npm/badpkg/upstream/packument.json")
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

    /// #975: `npm/{name}/metadata.json` is the assembled form of keys this registry
    /// owns, so the proxy branch must never cache an upstream packument there while
    /// `versions/` is non-empty. That branch is reached on the metadata path only by
    /// falling through the rebuild — its write failed, or the read-back missed — and a
    /// cached upstream document drops every locally published version. It does not
    /// self-heal either: the read-path rebuild triggers on the key being absent, and
    /// after such a write it exists with the wrong content.
    #[tokio::test]
    async fn npm_proxy_does_not_cache_upstream_packument_over_local_versions() {
        use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};
        use std::sync::{Arc, Mutex};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const UPSTREAM_MARKER: &str = "upstream-only-packument";
        const PACKUMENT_KEY: &str = "npm/hybrid/metadata.json";

        /// Reproduces the fall-through with no timing games: reads of the packument key
        /// always miss, so the rebuild runs, writes, and the read-back still misses.
        /// Every write is recorded so the test can assert what reached the key.
        struct PackumentReadAlwaysMisses {
            inner: ObjectStorage,
            writes: Arc<Mutex<Vec<(String, String)>>>,
        }

        #[async_trait::async_trait]
        impl StorageBackend for PackumentReadAlwaysMisses {
            async fn get(
                &self,
                key: &str,
            ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
                if key == PACKUMENT_KEY {
                    return Err(crate::storage::StorageError::NotFound);
                }
                self.inner.get(key).await
            }
            async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
                self.writes
                    .lock()
                    .expect("writes mutex")
                    .push((k.to_string(), String::from_utf8_lossy(d).to_string()));
                self.inner.put(k, d, sha256).await
            }
            async fn pin(&self, k: &str) -> Option<String> {
                self.inner.pin(k).await
            }
            async fn delete(&self, k: &str) -> crate::storage::Result<()> {
                self.inner.delete(k).await
            }
            async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
                self.inner.list(prefix).await
            }
            async fn list_with_meta(
                &self,
                prefix: &str,
            ) -> crate::storage::Result<Vec<(String, FileMeta)>> {
                self.inner.list_with_meta(prefix).await
            }
            async fn stat(&self, k: &str) -> Option<FileMeta> {
                self.inner.stat(k).await
            }
            async fn health_check(&self) -> bool {
                self.inner.health_check().await
            }
            async fn total_size(&self) -> u64 {
                self.inner.total_size().await
            }
            fn backend_name(&self) -> &'static str {
                "packument-read-misses-test"
            }
            async fn put_from_path(
                &self,
                k: &str,
                src: &std::path::Path,
                sha256: Option<&str>,
            ) -> crate::storage::Result<()> {
                self.inner.put_from_path(k, src, sha256).await
            }
            async fn copy(
                &self,
                src: &str,
                dst: &str,
                sha256: Option<&str>,
            ) -> crate::storage::Result<()> {
                self.inner.copy(src, dst, sha256).await
            }
            async fn get_reader(
                &self,
                k: &str,
            ) -> crate::storage::Result<(
                u64,
                Option<String>,
                std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
            )> {
                self.inner.get_reader(k).await
            }
        }

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/hybrid"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                concat!(
                    r#"{{"name":"hybrid","description":"{}","dist-tags":{{"latest":"9.9.9"}},"#,
                    r#""versions":{{"9.9.9":{{"name":"hybrid","version":"9.9.9","#,
                    r#""dist":{{"tarball":"http://up/hybrid/-/hybrid-9.9.9.tgz"}}}}}}}}"#
                ),
                UPSTREAM_MARKER
            )))
            .mount(&upstream)
            .await;

        let writes = Arc::new(Mutex::new(Vec::new()));
        let storage = Storage::from_backend(Arc::new(PackumentReadAlwaysMisses {
            inner: ObjectStorage::in_memory(),
            writes: Arc::clone(&writes),
        }));
        let ctx =
            crate::test_helpers::create_test_context_with_storage_and_config(storage, |cfg| {
                cfg.npm.proxy = Some(upstream.uri());
            });

        // One locally published version, so `versions/` is non-empty and the packument
        // key belongs to the local rebuild.
        ctx.state
            .storage
            .put(
                "npm/hybrid/versions/1.0.0.json",
                br#"{"name":"hybrid","version":"1.0.0","dist":{"tarball":"http://nora/npm/hybrid/-/hybrid-1.0.0.tgz"}}"#,
            )
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/npm/hybrid", "").await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the request is still served"
        );

        // The proxy cache write is detached; give it room to land.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let recorded = writes.lock().expect("writes mutex").clone();
        let to_packument: Vec<&(String, String)> = recorded
            .iter()
            .filter(|(k, _)| k == PACKUMENT_KEY)
            .collect();
        // Positive control: the rebuild really ran and wrote the assembled document,
        // which is what puts this request on the fall-through path in the first place.
        assert!(
            to_packument.iter().any(|(_, body)| body.contains("1.0.0")),
            "the local rebuild must have written the assembled packument: {to_packument:?}"
        );
        assert!(
            !to_packument
                .iter()
                .any(|(_, body)| body.contains(UPSTREAM_MARKER)),
            "#975: the upstream packument must never be cached over a key the local versions own — found: {to_packument:?}"
        );
    }

    /// The packument rebuild reads `versions/` concurrently. It used to walk the keys
    /// one at a time, which on an object store is a round-trip per version, and #956
    /// put that walk on a read path — so a package with a few thousand versions paid
    /// them serially on the first request after the packument went missing. A backend
    /// that records how many reads are in flight at once proves the fan-out is real; a
    /// sequential walk never exceeds one.
    #[tokio::test]
    async fn npm_packument_rebuild_reads_versions_concurrently() {
        use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct TracksInFlight {
            inner: ObjectStorage,
            in_flight: AtomicUsize,
            peak: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl StorageBackend for TracksInFlight {
            async fn get(
                &self,
                key: &str,
            ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
                let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(now, Ordering::SeqCst);
                // Hold the slot briefly so overlapping reads actually overlap.
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                let out = self.inner.get(key).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                out
            }
            async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
                self.inner.put(k, d, sha256).await
            }
            async fn pin(&self, k: &str) -> Option<String> {
                self.inner.pin(k).await
            }
            async fn delete(&self, k: &str) -> crate::storage::Result<()> {
                self.inner.delete(k).await
            }
            async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
                self.inner.list(prefix).await
            }
            async fn list_with_meta(
                &self,
                prefix: &str,
            ) -> crate::storage::Result<Vec<(String, FileMeta)>> {
                self.inner.list_with_meta(prefix).await
            }
            async fn stat(&self, k: &str) -> Option<FileMeta> {
                self.inner.stat(k).await
            }
            async fn health_check(&self) -> bool {
                self.inner.health_check().await
            }
            async fn total_size(&self) -> u64 {
                self.inner.total_size().await
            }
            fn backend_name(&self) -> &'static str {
                "in-flight-tracking-test"
            }
            async fn put_from_path(
                &self,
                k: &str,
                src: &std::path::Path,
                sha256: Option<&str>,
            ) -> crate::storage::Result<()> {
                self.inner.put_from_path(k, src, sha256).await
            }
            async fn copy(
                &self,
                src: &str,
                dst: &str,
                sha256: Option<&str>,
            ) -> crate::storage::Result<()> {
                self.inner.copy(src, dst, sha256).await
            }
            async fn get_reader(
                &self,
                k: &str,
            ) -> crate::storage::Result<(
                u64,
                Option<String>,
                std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
            )> {
                self.inner.get_reader(k).await
            }
        }

        let backend = Arc::new(TracksInFlight {
            inner: ObjectStorage::in_memory(),
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        });
        let storage = Storage::from_backend(Arc::clone(&backend) as Arc<dyn StorageBackend>);

        for i in 1..=8 {
            storage
                .put(
                    &format!("npm/conc/versions/1.0.{i}.json"),
                    format!(r#"{{"name":"conc","version":"1.0.{i}"}}"#).as_bytes(),
                )
                .await
                .unwrap();
        }
        backend.peak.store(0, Ordering::SeqCst);

        crate::registry::npm::regenerate_packument(&storage, "conc")
            .await
            .expect("rebuild succeeds");

        assert!(
            backend.peak.load(Ordering::SeqCst) > 1,
            "the rebuild must read versions concurrently — peak in-flight reads was {}",
            backend.peak.load(Ordering::SeqCst)
        );
        // Correctness is unchanged: every version is still in the assembled document.
        let packument = storage.get("npm/conc/metadata.json").await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&packument).unwrap();
        let versions = json["versions"].as_object().expect("versions object");
        assert_eq!(versions.len(), 8, "all versions assembled: {versions:?}");
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
        let key = "npm/testpkg/upstream/packument.json";
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
        // Refused explicitly, not "0 vulnerabilities" (Pavel 10.10; client matrix:
        // every client exits 1 and prints the error text on a 4xx).
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
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
        // Refused explicitly, not "0 vulnerabilities" (Pavel 10.10; client matrix:
        // every client exits 1 and prints the error text on a 4xx).
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
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
        let result = refetch_metadata(&ctx.state, "ghost-pkg", key, key, true, true).await;
        assert!(result.is_err(), "must fail when body is missing on 304");

        // The critical assertion: .meta must be gone after the 304 body-miss.
        // Before the fix, `.ok()?` silently returned None but left .meta intact,
        // causing an infinite 304 loop on every subsequent TTL expiry.
        assert!(
            read_validators(&ctx.state.storage, key).await.is_none(),
            "#867: validators must be cleared after 304 body-miss to break the infinite loop"
        );
    }
    /// #956: a hosted package whose derived packument is gone is still fully
    /// described by its per-version keys. Answering 404 loses data that is
    /// sitting in storage; the reassembly already exists and must be reached.
    #[tokio::test]
    async fn test_npm_packument_rebuilt_when_metadata_missing() {
        use crate::test_helpers::{body_bytes, create_test_context, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context();

        // Seed the immutable originals directly — what a direct-storage import
        // or a restore that skipped derived objects leaves behind.
        for ver in ["1.0.0", "2.0.0"] {
            let doc = serde_json::json!({ "name": "imported", "version": ver, "dist": {} });
            ctx.state
                .storage
                .put(
                    &format!("npm/imported/versions/{}.json", ver),
                    &serde_json::to_vec(&doc).unwrap(),
                )
                .await
                .unwrap();
        }
        ctx.state
            .storage
            .put(
                "npm/imported/pkg.json",
                &serde_json::to_vec(&serde_json::json!({ "description": "seeded" })).unwrap(),
            )
            .await
            .unwrap();
        assert!(
            ctx.state
                .storage
                .get("npm/imported/metadata.json")
                .await
                .is_err(),
            "precondition: the derived packument is absent"
        );

        let response = send(&ctx.app, Method::GET, "/npm/imported", "").await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "every version is in storage — a 404 here loses the package"
        );

        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["name"], "imported");
        let versions = json["versions"].as_object().unwrap();
        assert!(versions.contains_key("1.0.0"), "1.0.0 missing from rebuild");
        assert!(versions.contains_key("2.0.0"), "2.0.0 missing from rebuild");
        assert_eq!(
            json["dist-tags"]["latest"], "2.0.0",
            "latest must be derived from the version keys"
        );
        assert_eq!(
            json["description"], "seeded",
            "package-level fields must survive the rebuild"
        );

        assert!(
            ctx.state
                .storage
                .get("npm/imported/metadata.json")
                .await
                .is_ok(),
            "the rebuild must persist, or every request pays for it again"
        );
    }

    /// The rebuild must not invent a package out of an empty prefix.
    #[tokio::test]
    async fn test_npm_packument_absent_package_still_404() {
        use crate::test_helpers::{create_test_context, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context();

        let response = send(&ctx.app, Method::GET, "/npm/never-published", "").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            ctx.state
                .storage
                .get("npm/never-published/metadata.json")
                .await
                .is_err(),
            "a 404 must not leave a derived object behind"
        );
    }

    /// Concurrent readers of a package with a missing packument must all get the
    /// same correct answer — the rebuild is serialized on the publish lock.
    #[tokio::test]
    async fn test_npm_packument_rebuild_is_serialized() {
        use crate::test_helpers::{body_bytes, create_test_context, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context();
        for ver in ["1.0.0", "1.1.0", "2.0.0"] {
            let doc = serde_json::json!({ "name": "stampede", "version": ver, "dist": {} });
            ctx.state
                .storage
                .put(
                    &format!("npm/stampede/versions/{}.json", ver),
                    &serde_json::to_vec(&doc).unwrap(),
                )
                .await
                .unwrap();
        }

        let mut handles = Vec::new();
        for _ in 0..8 {
            let app = ctx.app.clone();
            handles.push(tokio::spawn(async move {
                let response = send(&app, Method::GET, "/npm/stampede", "").await;
                let status = response.status();
                (status, body_bytes(response).await)
            }));
        }

        let mut bodies = Vec::new();
        for handle in handles {
            let (status, body) = handle.await.unwrap();
            assert_eq!(status, StatusCode::OK);
            bodies.push(body);
        }
        assert!(
            bodies.windows(2).all(|pair| pair[0] == pair[1]),
            "concurrent rebuilds of the same package must agree"
        );
    }
    /// #957: `npm install` asks for the abbreviated packument. Serving the full
    /// document instead is correct but wasteful — and the fields it carries are
    /// exactly the ones an installer never reads.
    #[tokio::test]
    async fn test_npm_packument_abbreviated_on_install_v1_accept() {
        use crate::test_helpers::{body_bytes, create_test_context, send_with_headers};
        use axum::http::{header, Method, StatusCode};

        let ctx = create_test_context();
        let full = serde_json::json!({
            "name": "corgi",
            "dist-tags": { "latest": "1.0.0" },
            "readme": "a very long readme that no installer reads",
            "maintainers": [{ "name": "someone" }],
            "versions": {
                "1.0.0": {
                    "name": "corgi",
                    "version": "1.0.0",
                    "dist": { "tarball": "/npm/corgi/-/corgi-1.0.0.tgz" },
                    "dependencies": { "left-pad": "^1.0.0" },
                    "engines": { "node": ">=18" },
                    "os": ["linux"],
                    "cpu": ["x64"],
                    "peerDependenciesMeta": { "react": { "optional": true } },
                    "deprecated": "use corgi2",
                    "description": "dropped",
                    "scripts": { "test": "dropped" },
                    "gitHead": "dropped"
                }
            }
        });
        ctx.state
            .storage
            .put(
                "npm/corgi/metadata.json",
                &serde_json::to_vec(&full).unwrap(),
            )
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/corgi",
            vec![("accept", "application/vnd.npm.install-v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/vnd.npm.install-v1+json")
        );
        assert_eq!(
            response
                .headers()
                .get(header::VARY)
                .and_then(|v| v.to_str().ok()),
            Some("Accept"),
            "the body varies by Accept and metadata is cacheable — a shared cache \
             must not serve the abbreviated document to a client that wanted the full one"
        );

        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["name"], "corgi");
        assert_eq!(json["dist-tags"]["latest"], "1.0.0");
        assert!(json.get("readme").is_none(), "readme must be dropped");
        assert!(
            json.get("maintainers").is_none(),
            "maintainers must be dropped"
        );

        let manifest = &json["versions"]["1.0.0"];
        // Everything an installer consults survives — losing any of these
        // silently changes what gets resolved and installed.
        assert_eq!(manifest["version"], "1.0.0");
        assert_eq!(manifest["dependencies"]["left-pad"], "^1.0.0");
        assert_eq!(manifest["engines"]["node"], ">=18");
        assert_eq!(manifest["os"][0], "linux");
        assert_eq!(manifest["cpu"][0], "x64");
        assert_eq!(manifest["peerDependenciesMeta"]["react"]["optional"], true);
        assert_eq!(manifest["deprecated"], "use corgi2");
        assert!(manifest["dist"]["tarball"].is_string());
        // ...and what it never reads does not.
        assert!(manifest.get("description").is_none());
        assert!(manifest.get("scripts").is_none());
        assert!(manifest.get("gitHead").is_none());
    }

    /// Without the header the full document is served, unchanged.
    #[tokio::test]
    async fn test_npm_packument_full_without_install_v1_accept() {
        use crate::test_helpers::{body_bytes, create_test_context, send};
        use axum::http::{header, Method, StatusCode};

        let ctx = create_test_context();
        let full = serde_json::json!({
            "name": "corgi",
            "dist-tags": { "latest": "1.0.0" },
            "readme": "kept",
            "versions": {
                "1.0.0": { "name": "corgi", "version": "1.0.0", "description": "kept", "dist": {} }
            }
        });
        ctx.state
            .storage
            .put(
                "npm/corgi/metadata.json",
                &serde_json::to_vec(&full).unwrap(),
            )
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/npm/corgi", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );

        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["readme"], "kept", "the full document must be intact");
        assert_eq!(json["versions"]["1.0.0"]["description"], "kept");
    }

    /// A body that is not a packument is served unchanged rather than failing:
    /// the client asked for a projection of this document, not for an error.
    #[tokio::test]
    async fn test_npm_packument_unparsable_body_served_unchanged() {
        use crate::test_helpers::{body_bytes, create_test_context, send_with_headers};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context();
        ctx.state
            .storage
            .put("npm/broken/metadata.json", b"not json at all")
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/broken",
            vec![("accept", "application/vnd.npm.install-v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(&body_bytes(response).await[..], b"not json at all");
    }
    /// The degraded path is still a representation: when the packument is stale
    /// and upstream is gone, an install-v1 client must get the abbreviated body
    /// *and* the matching Content-Type. Serving the short body under
    /// `application/json` is the bug this guards.
    #[tokio::test]
    async fn test_npm_packument_stale_serve_honours_install_v1() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send_with_headers};
        use axum::http::{header, Method, StatusCode};

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = None; // no upstream to revalidate against
            cfg.npm.metadata_ttl = 0; // always stale
            cfg.npm.serve_stale = true;
        });

        let full = serde_json::json!({
            "name": "stale-corgi",
            "dist-tags": { "latest": "1.0.0" },
            "readme": "dropped in the abbreviated form",
            "versions": {
                "1.0.0": { "name": "stale-corgi", "version": "1.0.0", "dist": {}, "scripts": {} }
            }
        });
        ctx.state
            .storage
            .put(
                "npm/stale-corgi/metadata.json",
                &serde_json::to_vec(&full).unwrap(),
            )
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/stale-corgi",
            vec![("accept", "application/vnd.npm.install-v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-nora-stale")
                .and_then(|v| v.to_str().ok()),
            Some("true"),
            "precondition: this test must exercise the stale path"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/vnd.npm.install-v1+json"),
            "the stale path abbreviated the body — the Content-Type must say so"
        );
        assert_eq!(
            response
                .headers()
                .get(header::VARY)
                .and_then(|v| v.to_str().ok()),
            Some("Accept")
        );

        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert!(json.get("readme").is_none());
        assert!(json["versions"]["1.0.0"].get("scripts").is_none());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod index_cost_tests {
    //! Serving a stored packument must cost the same storage round-trips for 1 and 100 versions.
    use crate::test_helpers::{create_test_context_with_storage, op_counting_storage, send};
    use axum::http::{Method, StatusCode};

    async fn packument_ops(n: usize) -> (usize, String) {
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        let mut versions = serde_json::Map::new();
        for i in 0..n {
            let version = format!("1.0.{i}");
            let tarball = format!("costpkg-{version}.tgz");
            let tarball_key = format!("npm/costpkg/tarballs/{tarball}");
            ctx.state.storage.put(&tarball_key, b"TGZ").await.unwrap();
            let doc = serde_json::json!({
                "name": "costpkg",
                "version": version,
                "dist": { "tarball": format!("http://localhost/npm/costpkg/-/{tarball}") }
            });
            let doc_key = format!("npm/costpkg/versions/{version}.json");
            let doc_bytes = serde_json::to_vec(&doc).unwrap();
            ctx.state.storage.put(&doc_key, &doc_bytes).await.unwrap();
            versions.insert(version, doc);
        }
        let packument = serde_json::json!({
            "name": "costpkg",
            "dist-tags": { "latest": format!("1.0.{}", n - 1) },
            "versions": versions
        });
        let packument_bytes = serde_json::to_vec(&packument).unwrap();
        // As 1.4.0 stores it, through the rebuild publish runs: a packument an older release
        // wrote is rebuilt once, at its first read, which is not what this measures. The stored
        // document must carry the record that lets it be served as it is, or every read rebuilds.
        let _ = &packument_bytes;
        super::regenerate_packument(&ctx.state.storage, "costpkg")
            .await
            .unwrap();
        ops.reset();
        let resp = send(&ctx.app, Method::GET, "/npm/costpkg", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "packument with {n} versions");
        (ops.total(), format!("{:?}", ops.snapshot()))
    }

    #[tokio::test]
    async fn npm_packument_cost_is_independent_of_version_count() {
        let (small, small_ops) = packument_ops(1).await;
        let (large, large_ops) = packument_ops(100).await;
        assert_eq!(
            small, large,
            "a stored packument must cost the same storage round-trips for 1 and 100 versions: {small_ops} vs {large_ops}"
        );
    }
}

#[cfg(test)]
mod origin_layout_tests {
    use super::{origin_key, origin_primary};

    /// Sidecars live outside the npm key space: no client key maps onto one, the
    /// mapping is one-to-one even for package names that look like layout words, and
    /// `list()` (which every older release's retention and GC walk) never shows one.
    #[tokio::test]
    async fn provenance_is_outside_the_npm_key_space_and_round_trips() {
        let keys = [
            "npm/a/tarballs/a-1.0.0.tgz",
            "npm/@vendor/a/tarballs/a-1.0.0.tgz",
            "npm/@vendor/a/tarballs/@vendor/a-1.0.0.tgz",
            "npm/a/metadata.json",
            "npm/@vendor/a/metadata.json",
            // Package names equal to layout words must not alias anything.
            "npm/origins/metadata.json",
            "npm/origins/tarballs/origins-1.0.0.tgz",
            "npm/@x/origins/metadata.json",
            "npm/tarballs/tarballs/tarballs-1.0.0.tgz",
            "npm/x/tarballs/y/tarballs/z.tgz",
        ];
        let mut seen = std::collections::HashSet::new();
        for key in keys {
            let sidecar = origin_key(key);
            assert!(!sidecar.starts_with("npm/"), "{key} -> {sidecar}");
            assert!(sidecar.starts_with(".nora-"), "{key} -> {sidecar}");
            assert_eq!(origin_primary(&sidecar), Some(key), "{sidecar}");
            assert!(seen.insert(sidecar), "{key}: two keys share a sidecar");
            // A real npm key is never mistaken for a sidecar.
            assert_eq!(origin_primary(key), None, "{key}");
        }
        assert_eq!(origin_primary(".nora-origins/maven/x.jar"), None);

        let dir = tempfile::tempdir().unwrap();
        let storage = crate::Storage::new_local(dir.path().to_str().unwrap());
        storage.put(keys[0], b"tgz").await.unwrap();
        storage
            .put(&origin_key(keys[0]), b"npm:https://r.example")
            .await
            .unwrap();
        assert_eq!(storage.list("").await.unwrap(), vec![keys[0].to_string()]);
        // ...and the internal walk shows only internal keys.
        assert_eq!(
            storage.list_internal(".nora-").await.unwrap(),
            vec![origin_key(keys[0])]
        );
        assert!(storage.list_internal("npm/").await.unwrap().is_empty());
    }
}

/// npm multi-upstream with scope routing (#1055), on the real router: a private
/// upstream that only answers the exact Bearer token, and a public one that answers
/// anything — so a request that reached the wrong upstream would succeed and only
/// the request log on the public mock can catch it.
#[cfg(test)]
mod multi_upstream_tests {
    use crate::config::{NpmConfig, NpmProxyEntry};
    use crate::secrets::ProtectedString;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{any, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const TOKEN: &str = "vendor-tok";

    fn vendor_proxies(public: &str, private: &str) -> Vec<NpmProxyEntry> {
        let mut npm: NpmConfig = toml::from_str(&format!(
            r#"proxies = ["{public}", {{ url = "{private}", scopes = ["@vendor"], auth_bearer_env = "NORA_NPM_VENDOR_TOKEN" }}]"#
        ))
        .unwrap();
        if let NpmProxyEntry::Full(p) = &mut npm.proxies[1] {
            p.auth_bearer = Some(ProtectedString::from(TOKEN));
        }
        npm.proxies
    }

    /// Public upstream: 200 to anything, so only its request log tells.
    async fn public_upstream() -> MockServer {
        let public = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"name":"lodash","versions":{}}"#),
            )
            .mount(&public)
            .await;
        public
    }

    /// The public upstream must never see a private-scope name or the private token.
    fn assert_public_clean(reqs: &[Request]) {
        for r in reqs {
            let url = r.url.as_str();
            let body = String::from_utf8_lossy(&r.body);
            assert!(
                !url.contains("vendor"),
                "private scope reached public upstream: {url}"
            );
            assert!(
                !body.contains("@vendor"),
                "private scope in a body sent to public: {body}"
            );
            let auth = r
                .headers
                .get("authorization")
                .map(|v| v.to_str().unwrap_or("?").to_string());
            assert!(
                auth.is_none(),
                "public upstream got an Authorization header: {auth:?} on {url}"
            );
        }
    }

    #[tokio::test]
    async fn owned_scope_is_fetched_only_from_its_upstream_with_its_token() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {
                "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
            } } },
            "time": { "1.0.0": "2020-01-15T10:30:00.000Z" }
        });
        Mock::given(method("GET"))
            .and(path("/@vendor/a"))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/a/-/a-1.0.0.tgz"))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"VENDOR-TGZ".to_vec()))
            .mount(&private)
            .await;

        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.npm.metadata_ttl = 0; // always stale → the second pass must refetch
            cfg.npm.serve_stale = false; // …so a refetch that went elsewhere fails loudly
        });

        // Packument twice: the second pass goes through the stale-refetch path,
        // which must route the same way.
        for pass in 0..2 {
            let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2fa", "").await;
            assert_eq!(resp.status(), StatusCode::OK, "packument pass {pass}");
            let body = String::from_utf8_lossy(&body_bytes(resp).await).to_string();
            assert!(
                !body.contains(&private.uri()),
                "private registry host leaked to the client: {body}"
            );
            // The cache write is a background task; wait for it so the next pass
            // deterministically takes the stale-refetch path, not a second cold fetch.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            // Settled = body AND provenance sidecar written (#1055: an owned scope's
            // copy is only served once its origin is recorded).
            while ctx
                .state
                .storage
                .get(&super::origin_key("npm/@vendor/a/upstream/packument.json"))
                .await
                .is_err()
            {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "packument never cached"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"VENDOR-TGZ");

        // An unscoped package still goes to the public upstream, without a credential.
        let resp = send(&ctx.app, Method::GET, "/npm/lodash", "").await;
        assert_eq!(resp.status(), StatusCode::OK);

        let packument_fetches = private
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/@vendor/a")
            .count();
        assert_eq!(
            packument_fetches, 2,
            "first fetch and stale refetch both go to the owner"
        );

        let public_reqs = public.received_requests().await.unwrap();
        assert!(
            !public_reqs.is_empty(),
            "control: lodash must have reached public"
        );
        assert_public_clean(&public_reqs);
    }

    /// A locked install asks for the tarball first; the metadata self-prime that
    /// resolves the release date (#748) must ask the owning upstream too.
    #[tokio::test]
    async fn tarball_first_self_prime_asks_the_owner() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {
                "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
            } } },
            "time": { "1.0.0": "2020-01-15T10:30:00.000Z" }
        });
        Mock::given(method("GET"))
            .and(path("/@vendor/a"))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/a/-/a-1.0.0.tgz"))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"VENDOR-TGZ".to_vec()))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.server.trust_upstream_dates = true;
        });

        let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            ctx.state
                .storage
                .get("npm/@vendor/a/upstream/packument.json")
                .await
                .is_ok(),
            "the self-prime must have cached the owner's packument"
        );
        assert!(public.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_failing_private_upstream_never_falls_back_to_public() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/@vendor/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/broken"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&private)
            .await;

        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        for uri in [
            "/npm/@vendor%2fmissing",
            "/npm/@vendor%2fbroken",
            "/npm/@vendor/missing/-/missing-1.0.0.tgz",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_ne!(
                resp.status(),
                StatusCode::OK,
                "{uri} must not be served from public"
            );
        }
        assert!(
            public.received_requests().await.unwrap().is_empty(),
            "no fallback to the public upstream for an owned scope"
        );
    }

    /// A dead private registry opens its own breaker only: public packages keep
    /// being served (decision Б.3 of #1055 — breaker per upstream).
    #[tokio::test]
    async fn a_dead_private_upstream_does_not_open_the_public_breaker() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 1;
            cfg.circuit_breaker.reset_timeout = 300;
        });

        for _ in 0..2 {
            let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2fdown", "").await;
            assert_ne!(resp.status(), StatusCode::OK);
        }
        let resp = send(&ctx.app, Method::GET, "/npm/lodash", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the public upstream must keep serving while the private one is down"
        );
        assert_public_clean(&public.received_requests().await.unwrap());
    }

    /// The second entry points — stale refetch and the tarball-first metadata
    /// self-prime — report to the per-upstream breaker too: after the private
    /// registry dies on both paths, the public one still refetches and self-primes.
    #[tokio::test]
    async fn refetch_and_self_prime_use_the_per_upstream_breaker() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {
                "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
            } } }
        });
        Mock::given(method("GET"))
            .and(path("/@vendor/a"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.npm.metadata_ttl = 0;
            cfg.npm.serve_stale = false;
            cfg.server.trust_upstream_dates = true;
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 1;
            cfg.circuit_breaker.reset_timeout = 300;
        });
        let cached = |key: &str| {
            let storage = ctx.state.storage.clone();
            let key = key.to_string();
            async move {
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                while storage.get(&key).await.is_err() {
                    if tokio::time::Instant::now() >= deadline {
                        return false;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                true
            }
        };

        // Both packuments cached while everything is up.
        for uri in ["/npm/lodash", "/npm/@vendor%2fa"] {
            assert_eq!(
                send(&ctx.app, Method::GET, uri, "").await.status(),
                StatusCode::OK
            );
        }
        assert!(cached("npm/lodash/upstream/packument.json").await);
        let packument_origin = super::origin_key("npm/@vendor/a/upstream/packument.json");
        assert!(cached(&packument_origin).await);

        // The private registry dies; fail it on the refetch and the self-prime paths.
        private.reset().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&private)
            .await;
        let r = send(&ctx.app, Method::GET, "/npm/@vendor%2fa", "").await;
        assert_ne!(r.status(), StatusCode::OK, "stale private refetch fails");
        let r = send(&ctx.app, Method::GET, "/npm/@vendor/b/-/b-1.0.0.tgz", "").await;
        assert_ne!(
            r.status(),
            StatusCode::OK,
            "private self-prime + fetch fail"
        );

        // Public: stale refetch and tarball-first self-prime still work.
        let r = send(&ctx.app, Method::GET, "/npm/lodash", "").await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "public refetch after private died"
        );
        let _ = send(
            &ctx.app,
            Method::GET,
            "/npm/lodash2/-/lodash2-1.0.0.tgz",
            "",
        )
        .await;
        assert!(
            cached("npm/lodash2/upstream/packument.json").await,
            "public self-prime after private died"
        );
        assert_public_clean(&public.received_requests().await.unwrap());
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// npm 7+ always gzips the bulk audit body (measured, kit npm-client-matrix).
    /// Refusing every encoded body made `npm audit` report "0 vulnerabilities" as
    /// soon as a private scope was configured; it must be decoded, stripped and
    /// forwarded, and the upstream's answer returned.
    #[tokio::test]
    async fn a_gzipped_bulk_audit_is_decoded_stripped_and_forwarded() {
        use crate::test_helpers::send_with_headers;
        let public = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/npm/v1/security/advisories/bulk"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"lodash":[{"id":1}]}"#))
            .mount(&public)
            .await;
        let private = MockServer::start().await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            vec![
                ("content-encoding", "gzip"),
                ("content-type", "application/json"),
            ],
            gzip(br#"{"lodash":["4.17.0"],"@vendor/a":["1.0.0"]}"#),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], br#"{"lodash":[{"id":1}]}"#);

        let reqs = public.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(
            reqs[0].headers.get("content-encoding").is_none(),
            "the stripped body goes out uncompressed"
        );
        assert!(String::from_utf8_lossy(&reqs[0].body).contains("lodash"));
        assert_public_clean(&reqs);
    }

    /// pnpm posts an npm6 dependency tree to `-/npm/v1/security/audits` (measured,
    /// kit npm-audit-matrix). Without a filter it is forwarded like bulk; with a
    /// private scope configured the tree cannot be stripped reliably, so it is
    /// refused with an error pnpm prints — never a 405 with an empty body.
    #[tokio::test]
    async fn pnpm_full_audit_is_forwarded_or_refused_explicitly() {
        let body = r#"{"dependencies":{".":{"dependencies":{"fixture-pub":{"version":"1.0.0"}}}},"requires":{".":"0.0.0"}}"#;

        // No filter: forwarded verbatim, the upstream's answer returned.
        let public = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/npm/v1/security/audits"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"advisories":{},"metadata":{"vulnerabilities":{}}}"#),
            )
            .mount(&public)
            .await;
        let url = public.uri();
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxy = Some(url));
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/audits",
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("vulnerabilities"));
        assert_eq!(public.received_requests().await.unwrap().len(), 1);

        // Private scope configured: refused, nothing sent.
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/audits",
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
        assert!(public.received_requests().await.unwrap().is_empty());
    }

    /// An encoding NORA does not decode is a 415, a corrupt gzip a 422 — both with
    /// a JSON error the clients print.
    #[tokio::test]
    async fn unverifiable_audit_bodies_get_explicit_errors() {
        use crate::test_helpers::send_with_headers;
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);
        let bulk = "/npm/-/npm/v1/security/advisories/bulk";

        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            bulk,
            vec![("content-encoding", "br")],
            "x",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            bulk,
            vec![("content-encoding", "gzip")],
            "not-gzip",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let resp = send(&ctx.app, Method::POST, bulk, "[1,2,3]").await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
        assert!(public.received_requests().await.unwrap().is_empty());
    }

    /// A small gzip that expands past the audit cap is refused, not inflated.
    #[tokio::test]
    async fn a_gzip_bomb_audit_is_refused() {
        use crate::test_helpers::send_with_headers;
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        let mut big = b"{\"lodash\":[\"".to_vec();
        big.extend(std::iter::repeat_n(b'1', super::NPM_AUDIT_BODY_CAP + 1));
        big.extend(b"\"]}");
        let bomb = gzip(&big);
        assert!(
            bomb.len() < 64 * 1024,
            "control: the bomb is small on the wire"
        );

        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            vec![("content-encoding", "gzip")],
            bomb,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
        assert!(public.received_requests().await.unwrap().is_empty());
    }

    /// GitHub Packages puts scoped tarballs under `/download/@scope/name/…`: the
    /// scope is not the first segment, and such a path must still go to the owner,
    /// never to the default upstream (measured leak on the B arm, kit matrix 10.10).
    #[tokio::test]
    async fn a_ghp_form_download_path_goes_to_the_owner() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/download/@vendor/a/1.0.0/d113f588ab0b17ddabe8d0db55fa83a741df6871",
            ))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"VENDOR-TGZ".to_vec()))
            .mount(&private)
            .await;
        super::mount_listing(
            &private,
            "@vendor/a",
            &[(
                "1.0.0",
                "download/@vendor/a/1.0.0/d113f588ab0b17ddabe8d0db55fa83a741df6871",
            )],
        )
        .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        let _ = send(
            &ctx.app,
            Method::GET,
            "/npm/download/@vendor/a/1.0.0/d113f588ab0b17ddabe8d0db55fa83a741df6871",
            "",
        )
        .await;
        // The tarball goes to the owner once; as for any tarball, so does the
        // packument read for the release date.
        let to_owner: Vec<String> = private
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        let tarball = "/download/@vendor/a/1.0.0/d113f588ab0b17ddabe8d0db55fa83a741df6871";
        assert_eq!(
            to_owner.iter().filter(|p| *p == tarball).count(),
            1,
            "{to_owner:?}"
        );
        assert!(
            to_owner.iter().all(|p| p == tarball || p == "/@vendor/a"),
            "{to_owner:?}"
        );
        assert_public_clean(&public.received_requests().await.unwrap());
    }

    /// Seed what a public-registry squatter left in the cache before `@vendor` got
    /// an owner: a packument advertising 1.99.0 and its tarball. `origin` = the
    /// upstream its provenance record names (None = a cache from before #1055);
    /// `recorded_for` = the bytes that record was written for (None = these).
    async fn seed_squatter(
        ctx: &crate::test_helpers::TestContext,
        origin: Option<String>,
        recorded_for: Option<&[u8]>,
    ) {
        let packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.99.0": { "dist": { "tarball": "http://127.0.0.1/npm/@vendor/a/-/a-1.99.0.tgz" } } },
            "dist-tags": { "latest": "1.99.0" }
        });
        let meta = "npm/@vendor/a/metadata.json";
        let tgz = "npm/@vendor/a/tarballs/a-1.99.0.tgz";
        let packument = packument.to_string();
        let objects: [(&str, &[u8]); 2] = [(meta, packument.as_bytes()), (tgz, b"SQUATTER")];
        for (key, bytes) in objects {
            ctx.state.storage.put(key, bytes).await.unwrap();
            if let Some(origin) = &origin {
                let record = super::provenance_record(origin, recorded_for.unwrap_or(bytes));
                ctx.state
                    .storage
                    .put(&super::origin_key(key), record.as_bytes())
                    .await
                    .unwrap();
            }
        }
    }

    /// Once a scope has an owner, a copy cached from anywhere else — a squatter on
    /// the public registry, a cache from before the scope was owned, or bytes that
    /// replaced the owner's copy under its record (an older release after a
    /// rollback) — is never served: not as a cache hit, not via Range,
    /// not as a stale fallback. The owner's copy replaces it.
    #[tokio::test]
    async fn a_foreign_cached_copy_of_an_owned_scope_is_never_served() {
        use crate::test_helpers::send_with_headers;
        for foreign_origin in [None, Some("PUBLIC"), Some("OWNER, OTHER BYTES")] {
            let public = public_upstream().await;
            let private = MockServer::start().await;
            let owner_packument = serde_json::json!({
                "name": "@vendor/a",
                "versions": { "1.0.0": { "dist": {
                    "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
                } } },
                "dist-tags": { "latest": "1.0.0" }
            });
            Mock::given(method("GET"))
                .and(path("/@vendor/a"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_string(owner_packument.to_string()),
                )
                .mount(&private)
                .await;
            Mock::given(method("GET"))
                .and(path("/@vendor/a/-/a-1.99.0.tgz"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&private)
                .await;
            let public_identity = crate::circuit_breaker::upstream_key("npm", &public.uri());
            let owner_identity = crate::circuit_breaker::upstream_key("npm", &private.uri());
            let proxies = vendor_proxies(&public.uri(), &private.uri());
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.npm.proxies = proxies;
                cfg.npm.metadata_ttl = 3600; // fresh: a plain TTL check would serve the squatter
            });
            match foreign_origin {
                None => seed_squatter(&ctx, None, None).await,
                Some("PUBLIC") => seed_squatter(&ctx, Some(public_identity.clone()), None).await,
                // The owner's record, left behind when other bytes replaced its copy.
                Some(_) => {
                    seed_squatter(&ctx, Some(owner_identity.clone()), Some(b"owner bytes")).await
                }
            }

            let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2fa", "").await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = String::from_utf8_lossy(&body_bytes(resp).await).to_string();
            assert!(
                body.contains("1.0.0") && !body.contains("1.99.0"),
                "owner's packument, not the squatter's: {body}"
            );

            let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.99.0.tgz", "").await;
            assert_ne!(
                &body_bytes(resp).await[..],
                b"SQUATTER",
                "{foreign_origin:?}"
            );
            let resp = send_with_headers(
                &ctx.app,
                Method::GET,
                "/npm/@vendor/a/-/a-1.99.0.tgz",
                vec![("range", "bytes=0-3")],
                "",
            )
            .await;
            assert_ne!(
                &body_bytes(resp).await[..],
                b"SQUA",
                "range must not serve it either"
            );
            assert_public_clean(&public.received_requests().await.unwrap());
        }
    }

    /// A dead owner is a gateway failure, not a missing package: 5xx or an
    /// unreachable upstream → 502 (npm retries and reports E502), a real upstream
    /// 404 → 404 (npm reports E404). Before, every cold-miss failure was a 404.
    #[tokio::test]
    async fn a_dead_upstream_is_502_and_a_missing_package_is_404() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/@vendor/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&private)
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        for (uri, want) in [
            ("/npm/@vendor%2fmissing", StatusCode::NOT_FOUND),
            ("/npm/@vendor%2fdown", StatusCode::BAD_GATEWAY),
            (
                "/npm/@vendor/down/-/down-1.0.0.tgz",
                StatusCode::BAD_GATEWAY,
            ),
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), want, "{uri}");
        }

        // Unreachable (connection refused) is a gateway failure too.
        let unreachable = vendor_proxies(&public.uri(), "http://127.0.0.1:1");
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = unreachable);
        let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2fdown", "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// With the owner down, the foreign copy is still not served (no stale fallback).
    #[tokio::test]
    async fn a_dead_owner_does_not_resurrect_a_foreign_copy() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.npm.metadata_ttl = 0;
            cfg.npm.serve_stale = true;
        });
        seed_squatter(&ctx, None, None).await;
        for uri in ["/npm/@vendor%2fa", "/npm/@vendor/a/-/a-1.99.0.tgz"] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_ne!(resp.status(), StatusCode::OK, "{uri}");
        }
    }

    /// The release date used by min-release-age comes from the owner's packument,
    /// not from a foreign copy left in the cache: a squatter that advertises an old
    /// publish time must not let a brand-new owner release past the age gate.
    #[tokio::test]
    async fn release_age_reads_the_owners_date_not_a_foreign_copy() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S.000Z")
            .to_string();
        let owner_packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {
                "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
            } } },
            "time": { "1.0.0": now }
        });
        Mock::given(method("GET"))
            .and(path("/@vendor/a"))
            .respond_with(ResponseTemplate::new(200).set_body_string(owner_packument.to_string()))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/a/-/a-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"NEW-TGZ".to_vec()))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.server.trust_upstream_dates = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
        });
        // A foreign packument claiming 1.0.0 is six years old, no provenance.
        let foreign = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {} } },
            "time": { "1.0.0": "2020-01-01T00:00:00.000Z" }
        });
        ctx.state
            .storage
            .put(
                "npm/@vendor/a/metadata.json",
                foreign.to_string().as_bytes(),
            )
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "a release the owner dates to today must be held by a 7d age gate"
        );
        assert_public_clean(&public.received_requests().await.unwrap());
    }

    /// What the owner delivered is cached and served without asking again; what was
    /// published here is served even with the owner down.
    #[tokio::test]
    async fn owner_copies_and_local_publishes_are_served_from_cache() {
        use axum::body::Body;
        use base64::Engine as _;
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {
                "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
            } } }
        });
        Mock::given(method("GET"))
            .and(path("/@vendor/a"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/a/-/a-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"OWNER-TGZ".to_vec()))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
        assert_eq!(&body_bytes(resp).await[..], b"OWNER-TGZ");
        let origin_key = super::origin_key("npm/@vendor/a/tarballs/a-1.0.0.tgz");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while ctx.state.storage.get(&origin_key).await.is_err() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "origin never recorded"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Owner goes down: its own copy is still served from cache.
        private.reset().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&private)
            .await;
        let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"OWNER-TGZ");

        // A package published here under the owned scope is ours: served.
        let payload = serde_json::json!({
            "name": "@vendor/local",
            "versions": { "1.0.0": { "dist": {} } },
            "_attachments": { "local-1.0.0.tgz": {
                "data": base64::engine::general_purpose::STANDARD.encode(b"LOCAL-TGZ")
            } },
            "dist-tags": { "latest": "1.0.0" }
        });
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/npm/@vendor%2flocal",
            Body::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/@vendor/local/-/local-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"LOCAL-TGZ");
        let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2flocal", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_public_clean(&public.received_requests().await.unwrap());
    }

    #[tokio::test]
    async fn audit_to_the_default_upstream_never_carries_private_names() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            r#"{"lodash":["4.17.0"],"@vendor/a":["1.0.0"]}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // npm6 quick audit is a gzipped lockfile — names cannot be stripped, so it is
        // refused outright while any private scope is configured.
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/audits/quick",
            r#"{"dependencies":{"@vendor/a":{"version":"1.0.0"}}}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let reqs = public.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1, "only the stripped bulk audit is forwarded");
        assert!(String::from_utf8_lossy(&reqs[0].body).contains("lodash"));
        assert_public_clean(&reqs);
        assert!(private.received_requests().await.unwrap().is_empty());
    }

    // ── A name with an empty segment never names another key's file ─────────

    /// `/npm/evil-pkg//-/evil-pkg-1.0.0.tgz` and `/npm//evil-pkg/-/...` name the canonical
    /// tarball under the package names `evil-pkg/` and `/evil-pkg`, which the rule `evil-pkg`
    /// does not match — refused before curation and storage.
    #[tokio::test]
    async fn a_tarball_path_with_an_empty_segment_is_refused_before_curation() {
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "npm", "name": "evil-pkg", "version": "*", "reason": "malware"}]}"#,
        )
        .unwrap();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
        });
        // A tarball cached (or published) before the version was blocklisted.
        ctx.state
            .storage
            .put("npm/evil-pkg/tarballs/evil-pkg-1.0.0.tgz", b"MALWARE")
            .await
            .unwrap();
        let canonical = send(
            &ctx.app,
            Method::GET,
            "/npm/evil-pkg/-/evil-pkg-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(canonical.status(), StatusCode::FORBIDDEN, "control");

        let mut served = Vec::new();
        for alias in [
            "/npm/evil-pkg//-/evil-pkg-1.0.0.tgz",
            "/npm//evil-pkg/-/evil-pkg-1.0.0.tgz",
        ] {
            let resp = send(&ctx.app, Method::GET, alias, "").await;
            if resp.status() == StatusCode::OK {
                served.push(format!("{alias} -> {:?}", body_bytes(resp).await));
            }
        }
        assert!(served.is_empty(), "blocklisted tarball served: {served:?}");
    }

    /// `/npm//internalpkg` names `/internalpkg`, which the isolation pattern `internal*` does
    /// not match: it is refused, and the packument of an internal package is never requested
    /// from the public upstream or cached over its own file.
    #[tokio::test]
    async fn a_leading_slash_name_never_takes_an_internal_package_upstream() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "internalpkg",
                "versions": {"9.9.9": {"name": "internalpkg", "version": "9.9.9"}}
            })))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.internal_namespaces = vec!["internal*".to_string()];
        });
        let leaked = || async {
            upstream
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path().contains("internalpkg"))
                .count()
        };

        let resp = send(&ctx.app, Method::GET, "/npm/internalpkg", "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        assert_eq!(leaked().await, 0, "control: canonical name is not proxied");

        let resp = send(&ctx.app, Method::GET, "/npm//internalpkg", "").await;
        assert_eq!(
            leaked().await,
            0,
            "internal package name sent to the public upstream (alias answered {})",
            resp.status()
        );
    }

    /// Every tarball path form with an empty segment is refused with 400 before curation,
    /// storage or the upstream sees it.
    #[tokio::test]
    async fn every_tarball_path_with_an_empty_segment_never_reaches_upstream() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TARBALL".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.internal_namespaces = vec!["internal*".to_string()];
        });
        for alias in [
            "/npm//internalpkg/-/internalpkg-1.0.0.tgz",
            "/npm/internalpkg//-/internalpkg-1.0.0.tgz",
            "/npm/lodash/-/lodash-4.17.21.tgz/",
            "/npm/lodash/-/",
        ] {
            let resp = send(&ctx.app, Method::GET, alias, "").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{alias}");
        }
        let reqs: Vec<String> = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert!(reqs.is_empty(), "sent upstream: {reqs:?}");
        // Legit tarball path still proxies.
        super::mount_listing(
            &upstream,
            "lodash",
            &[("4.17.21", "lodash/-/lodash-4.17.21.tgz")],
        )
        .await;
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/lodash/-/lodash-4.17.21.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "control");
    }
}

/// An npm version is the version npm publishes it as: `semver.clean` drops white space, leading
/// `=` and `v`, and build metadata, so a rule or an allowlist entry holds however it spells its
/// version — `v1.3.0`, `=1.3.0` and `1.3.0+build` are `1.3.0`.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod npm_version_curation {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec()))
            .mount(&upstream)
            .await;
        upstream
    }

    fn write(dir: &tempfile::TempDir, file: &str, body: &str) -> String {
        let path = dir.path().join(file);
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn a_rule_holds_however_it_spells_its_version() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = write(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [
                {"registry": "npm", "name": "left-pad", "version": "v1.3.0", "reason": "r"},
                {"registry": "npm", "name": "left-pad", "version": "=1.4.0", "reason": "r"},
                {"registry": "npm", "name": "left-pad", "version": "1.5.0+build.1", "reason": "r"}
            ]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        for version in ["1.3.0", "1.4.0", "1.5.0"] {
            let path = format!("/npm/left-pad/-/left-pad-{version}.tgz");
            let resp = send(&ctx.app, Method::GET, &path, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{version}");
        }
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/left-pad/-/left-pad-1.3.1.tgz",
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_allowlist_entry_admits_its_version_however_spelled() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = write(
            &dir,
            "allowlist.json",
            r#"{"version": 1, "entries": [{"registry": "npm", "name": "left-pad", "version": "v1.3.0"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/left-pad/-/left-pad-1.3.0.tgz",
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/left-pad/-/left-pad-1.3.1.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// #1098: `[curation.npm] min_release_age` without a global value holds a
    /// tarball younger than it, and serves it once it is older.
    #[tokio::test]
    async fn a_per_registry_minimum_age_alone_holds_a_young_tarball() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = None;
            cfg.server.trust_upstream_dates = false;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.npm.min_release_age = Some("3d".to_string());
        });
        let packument = br#"{"name": "left-pad", "versions": {"1.3.0": {}}}"#;
        ctx.state
            .storage
            .put("npm/left-pad/metadata.json", packument)
            .await
            .unwrap();
        ctx.state
            .storage
            .put("npm/left-pad/tarballs/left-pad-1.3.0.tgz", b"TGZ")
            .await
            .unwrap();
        let path = "/npm/left-pad/-/left-pad-1.3.0.tgz";
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("min-release-age"),
            "{}",
            String::from_utf8_lossy(&body)
        );

        // Without trusted upstream dates the release date is NORA's own: when it
        // first stored the packument. Four days later the tarball is served.
        let four_days_ago =
            std::time::SystemTime::now() - std::time::Duration::from_secs(4 * 86_400);
        std::fs::File::options()
            .write(true)
            .open(ctx._tempdir.path().join("npm/left-pad/metadata.json"))
            .unwrap()
            .set_modified(four_days_ago)
            .unwrap();
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

/// Without trusted upstream dates a release is as old as NORA's first sight of it in an
/// upstream packument. A packument refetch — 200 or 304 — does not make it younger, a
/// version the upstream adds later starts at zero, and the ages are read back from storage
/// after a restart; the same on the local backend and on the object store.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod release_age_first_seen {
    use super::{first_seen_key, FirstSeen};
    use crate::registry::{write_validators, Validators};
    use crate::storage::Storage;
    use crate::test_helpers::{
        body_bytes, create_test_context_with_storage_and_config, send, TestContext,
    };
    use axum::http::{Method, StatusCode};
    use std::time::{Duration, SystemTime};
    use wiremock::matchers::{header_exists, method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Where 1.4.0 caches the upstream packument; `LEGACY` is where an older release did.
    const KEY: &str = "npm/agepkg/upstream/packument.json";
    const LEGACY: &str = "npm/agepkg/metadata.json";
    const HOUR: i64 = 3600;

    /// Where a test keeps its packages: a directory whose file times it can set, or an
    /// in-process object store (the S3 code path), whose times it cannot.
    enum Backend {
        Local(tempfile::TempDir),
        Object,
    }

    impl Backend {
        fn both() -> [Backend; 2] {
            [
                Backend::Local(tempfile::tempdir().unwrap()),
                Backend::Object,
            ]
        }

        fn storage(&self) -> Storage {
            match self {
                Backend::Local(dir) => Storage::new_local(dir.path().to_str().unwrap()),
                Backend::Object => Storage::from_backend(std::sync::Arc::new(
                    crate::storage::ObjectStorage::in_memory(),
                )),
            }
        }

        /// The storage as a restarted process opens it: the directory anew, or the same bucket.
        fn reopen(&self, storage: &Storage) -> Storage {
            match self {
                Backend::Local(_) => self.storage(),
                Backend::Object => storage.clone(),
            }
        }

        /// Set the packument's file time `secs` into the past (local backend only).
        fn age_packument(&self, secs: i64) {
            if let Backend::Local(dir) = self {
                std::fs::File::options()
                    .write(true)
                    .open(dir.path().join(KEY))
                    .unwrap()
                    .set_modified(SystemTime::now() - Duration::from_secs(secs as u64))
                    .unwrap();
            }
        }

        fn name(&self) -> &'static str {
            match self {
                Backend::Local(_) => "local",
                Backend::Object => "object store",
            }
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn packument(upstream: &str, versions: &[&str]) -> String {
        let versions: serde_json::Map<String, serde_json::Value> = versions
            .iter()
            .map(|v| {
                let tarball = format!("{upstream}/agepkg/-/agepkg-{v}.tgz");
                (
                    v.to_string(),
                    serde_json::json!({ "name": "agepkg", "version": v, "dist": { "tarball": tarball } }),
                )
            })
            .collect();
        serde_json::json!({ "name": "agepkg", "versions": versions }).to_string()
    }

    /// The upstream lists `versions`; with `not_modified` it answers only a conditional
    /// request, with 304 — a full fetch finds nothing, so the 304 path is the one taken.
    async fn upstream(versions: &[&str], not_modified: bool) -> MockServer {
        let server = MockServer::start().await;
        let listing = if not_modified {
            Mock::given(method("GET"))
                .and(path("/agepkg"))
                .and(header_exists("if-none-match"))
                .respond_with(ResponseTemplate::new(304))
        } else {
            Mock::given(method("GET"))
                .and(path("/agepkg"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("etag", "\"v2\"")
                        .set_body_string(packument(&server.uri(), versions)),
                )
        };
        listing.mount(&server).await;
        Mock::given(method("GET"))
            .and(path_regex("^/agepkg/-/"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec()))
            .mount(&server)
            .await;
        server
    }

    /// The field configuration: 3 days globally and 1 hour for npm, the quarantine
    /// observing, upstream dates not trusted. TTL 0 makes every packument request a refetch.
    fn context(upstream: &MockServer, storage: Storage) -> TestContext {
        let uri = upstream.uri();
        create_test_context_with_storage_and_config(storage, move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.npm.metadata_ttl = 0;
            cfg.npm.revalidate = true;
            cfg.server.trust_upstream_dates = false;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("3d".to_string());
            cfg.curation.npm.min_release_age = Some("1h".to_string());
            cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Observe);
        })
    }

    /// The cache as NORA left it two hours ago: the packument listing 1.0.0 with its
    /// validators, and 1.0.0 first seen then.
    async fn seen_two_hours_ago(backend: &Backend, storage: &Storage, upstream: &MockServer) {
        storage
            .put(KEY, packument(&upstream.uri(), &["1.0.0"]).as_bytes())
            .await
            .unwrap();
        write_validators(
            storage,
            KEY,
            &Validators {
                etag: Some("\"v1\"".to_string()),
                last_modified: None,
            },
        )
        .await;
        let ledger: FirstSeen = [("1.0.0".to_string(), now() - 2 * HOUR)].into();
        storage
            .put(&first_seen_key(KEY), &serde_json::to_vec(&ledger).unwrap())
            .await
            .unwrap();
        backend.age_packument(2 * HOUR);
    }

    /// Ask for the packument and wait until the refetch has rewritten it — the write that
    /// used to reset the age.
    async fn refetch(ctx: &TestContext, storage: &Storage) {
        let resp = send(&ctx.app, Method::GET, "/npm/agepkg", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "packument");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while storage
            .stat(KEY)
            .await
            .is_none_or(|m| now() - (m.modified as i64) >= 60)
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the refetch never rewrote the packument"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn tarball(ctx: &TestContext, version: &str) -> (StatusCode, String) {
        let uri = format!("/npm/agepkg/-/agepkg-{version}.tgz");
        let resp = send(&ctx.app, Method::GET, &uri, "").await;
        let status = resp.status();
        let body = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
        (status, body)
    }

    async fn a_refetch_keeps_the_age(not_modified: bool) {
        for backend in Backend::both() {
            let storage = backend.storage();
            let upstream = upstream(&["1.0.0"], not_modified).await;
            seen_two_hours_ago(&backend, &storage, &upstream).await;
            let ctx = context(&upstream, storage.clone());

            refetch(&ctx, &storage).await;

            let (status, body) = tarball(&ctx, "1.0.0").await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{}: seen 2h ago, minimum 1h — {body}",
                backend.name()
            );
        }
    }

    #[tokio::test]
    async fn a_200_refetch_does_not_make_a_release_younger() {
        a_refetch_keeps_the_age(false).await;
    }

    #[tokio::test]
    async fn a_304_refetch_does_not_make_a_release_younger() {
        a_refetch_keeps_the_age(true).await;
    }

    #[tokio::test]
    async fn a_version_the_refetch_adds_starts_at_zero() {
        for backend in Backend::both() {
            let storage = backend.storage();
            let upstream = upstream(&["1.0.0", "2.0.0"], false).await;
            seen_two_hours_ago(&backend, &storage, &upstream).await;
            let ctx = context(&upstream, storage.clone());

            refetch(&ctx, &storage).await;
            // Its age is its own, not the packument file's: an old file time changes nothing.
            backend.age_packument(3 * HOUR);

            let (status, body) = tarball(&ctx, "2.0.0").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{}: {body}", backend.name());
            assert!(body.contains("0h old"), "{}: {body}", backend.name());
            let (status, body) = tarball(&ctx, "1.0.0").await;
            assert_eq!(status, StatusCode::OK, "{}: {body}", backend.name());
        }
    }

    /// A ledger whose bytes no longer match their pin is rewritten at the next refetch, so it
    /// is read again and records new versions; its releases start young, which holds more.
    #[tokio::test]
    async fn a_ledger_that_fails_its_pin_is_rewritten() {
        let backend = Backend::Local(tempfile::tempdir().unwrap());
        let Backend::Local(dir) = &backend else {
            unreachable!()
        };
        let storage = backend.storage();
        let upstream = upstream(&["1.0.0", "2.0.0"], false).await;
        seen_two_hours_ago(&backend, &storage, &upstream).await;
        let on_disk = dir.path().join(first_seen_key(KEY));
        let mut bytes = std::fs::read(&on_disk).unwrap();
        bytes.push(b' ');
        std::fs::write(&on_disk, &bytes).unwrap();
        assert!(storage.get(&first_seen_key(KEY)).await.is_err(), "tampered");
        let ctx = context(&upstream, storage.clone());

        refetch(&ctx, &storage).await;
        let ledger: FirstSeen =
            serde_json::from_slice(&storage.get(&first_seen_key(KEY)).await.unwrap()).unwrap();
        assert!(
            ledger.contains_key("1.0.0") && ledger.contains_key("2.0.0"),
            "{ledger:?}"
        );
        assert!(
            ledger.values().all(|t| now() - t < 60),
            "started again: {ledger:?}"
        );
    }

    #[tokio::test]
    async fn the_age_survives_a_restart() {
        for backend in Backend::both() {
            let storage = backend.storage();
            let upstream = upstream(&["1.0.0", "2.0.0"], false).await;
            seen_two_hours_ago(&backend, &storage, &upstream).await;
            let first = context(&upstream, storage.clone());
            refetch(&first, &storage).await;
            drop(first);

            // A new process over the same storage; the packument was just rewritten.
            let ctx = context(&upstream, backend.reopen(&storage));
            let (status, body) = tarball(&ctx, "1.0.0").await;
            assert_eq!(status, StatusCode::OK, "{}: {body}", backend.name());
            let (status, body) = tarball(&ctx, "2.0.0").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{}: {body}", backend.name());
        }
    }

    /// A version no packument NORA fetched has listed has no first-seen time, and the
    /// ledger does not make it older than the cached packument it is missing from.
    #[tokio::test]
    async fn an_unlisted_version_is_no_older_than_the_cache() {
        for backend in Backend::both() {
            let storage = backend.storage();
            let upstream = upstream(&["1.0.0"], false).await;
            seen_two_hours_ago(&backend, &storage, &upstream).await;
            let ctx = context(&upstream, storage.clone());

            refetch(&ctx, &storage).await;

            let (status, body) = tarball(&ctx, "3.0.0").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{}: {body}", backend.name());
            assert!(body.contains("0h old"), "{}: {body}", backend.name());
        }
    }

    /// A packument cached before NORA kept first-seen times: the versions it already
    /// listed start at its file time — when NORA last wrote it — and a version only the
    /// refetch brings starts at zero.
    async fn a_cache_from_before_the_ledger(not_modified: bool) {
        let backend = Backend::Local(tempfile::tempdir().unwrap());
        let storage = backend.storage();
        let upstream = upstream(&["1.0.0", "2.0.0"], not_modified).await;
        storage
            .put(KEY, packument(&upstream.uri(), &["1.0.0"]).as_bytes())
            .await
            .unwrap();
        write_validators(
            &storage,
            KEY,
            &Validators {
                etag: Some("\"v1\"".to_string()),
                last_modified: None,
            },
        )
        .await;
        backend.age_packument(2 * HOUR);
        let ctx = context(&upstream, storage.clone());

        refetch(&ctx, &storage).await;

        let (status, body) = tarball(&ctx, "1.0.0").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        if !not_modified {
            let (status, body) = tarball(&ctx, "2.0.0").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        }
    }

    #[tokio::test]
    async fn a_cache_from_before_the_ledger_keeps_its_age_on_200() {
        a_cache_from_before_the_ledger(false).await;
    }

    /// A packument an older release cached (at the old key, with no ledger): its versions keep
    /// its file time, a version only the refetch brings starts at zero, and the old copy is
    /// left byte for byte, so a rollback still reads it.
    #[tokio::test]
    async fn a_cache_from_an_older_release_keeps_its_age_and_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().to_str().unwrap());
        let upstream = upstream(&["1.0.0", "2.0.0"], false).await;
        let old = packument(&upstream.uri(), &["1.0.0"]);
        storage.put(LEGACY, old.as_bytes()).await.unwrap();
        std::fs::File::options()
            .write(true)
            .open(dir.path().join(LEGACY))
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(2 * HOUR as u64))
            .unwrap();
        let ctx = context(&upstream, storage.clone());

        refetch(&ctx, &storage).await;

        let (status, body) = tarball(&ctx, "1.0.0").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = tarball(&ctx, "2.0.0").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(
            storage.get(LEGACY).await.unwrap(),
            old.as_bytes(),
            "left alone"
        );
    }

    #[tokio::test]
    async fn a_cache_from_before_the_ledger_keeps_its_age_on_304() {
        a_cache_from_before_the_ledger(true).await;
    }

    /// The first fetch of a packument starts every version it lists now, and the ledger
    /// stays outside the npm key space that listings, retention and GC walk.
    #[tokio::test]
    async fn a_first_fetch_starts_every_version_at_zero() {
        for backend in Backend::both() {
            let storage = backend.storage();
            let upstream = upstream(&["1.0.0"], false).await;
            let ctx = context(&upstream, storage.clone());

            refetch(&ctx, &storage).await;
            backend.age_packument(3 * HOUR);

            let (status, body) = tarball(&ctx, "1.0.0").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{}: {body}", backend.name());
            assert!(body.contains("0h old"), "{}: {body}", backend.name());
            assert_eq!(
                storage
                    .list_internal(super::FIRST_SEEN_PREFIX)
                    .await
                    .unwrap(),
                vec![first_seen_key(KEY)],
                "{}",
                backend.name()
            );
            assert!(first_seen_key(KEY).starts_with(".nora-"));
        }
    }

    /// Concurrent fetches of one packument each add what they saw: the read-modify-write
    /// of the ledger is serialized, so no version is lost.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_records_lose_no_version() {
        let backend = Backend::Local(tempfile::tempdir().unwrap());
        let storage = backend.storage();
        let upstream = upstream(&[], false).await;
        let ctx = context(&upstream, storage.clone());
        let mut records = tokio::task::JoinSet::new();
        for i in 0..16 {
            let state = ctx.state.clone();
            let body = packument(&upstream.uri(), &[format!("1.0.{i}").as_str()]);
            records.spawn(async move {
                super::record_first_seen(&state, KEY, body.as_bytes(), None).await;
            });
        }
        while let Some(done) = records.join_next().await {
            done.unwrap();
        }
        let ledger: FirstSeen =
            serde_json::from_slice(&storage.get(&first_seen_key(KEY)).await.unwrap()).unwrap();
        assert_eq!(ledger.len(), 16, "{ledger:?}");
    }

    /// Nothing is kept where nothing reads it: with curation off, or with trusted
    /// upstream dates, a packument fetch writes no first-seen ledger.
    #[tokio::test]
    async fn no_ledger_without_untrusted_curation() {
        for (curation, trust) in [(false, false), (true, true)] {
            let backend = Backend::Object;
            let storage = backend.storage();
            let upstream = upstream(&["1.0.0"], false).await;
            let uri = upstream.uri();
            let ctx = create_test_context_with_storage_and_config(storage.clone(), move |cfg| {
                cfg.npm.proxy = Some(uri);
                cfg.server.trust_upstream_dates = trust;
                if curation {
                    cfg.curation.mode = crate::config::CurationMode::Enforce;
                    cfg.curation.min_release_age = Some("1h".to_string());
                }
            });
            let resp = send(&ctx.app, Method::GET, "/npm/agepkg", "").await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert!(
                storage.get(&first_seen_key(KEY)).await.is_err(),
                "curation {curation}, trust {trust}"
            );
        }
    }
}

/// Published and upstream metadata in separate keys: a published package's packument and
/// version manifests come from its own keys and never from an upstream, whatever its TTL,
/// whatever an older release left in the store; an unpublished package's are cached under
/// `upstream/` and never at the published key.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod published_and_upstream_keys {
    use super::{classify_metadata_path, put_with_origin, MetadataPath};
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
    use axum::http::{Method, StatusCode};
    use std::time::Duration;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn doc(name: &str, versions: &[&str]) -> serde_json::Value {
        let versions: serde_json::Map<String, serde_json::Value> = versions
            .iter()
            .map(|v| {
                (
                    v.to_string(),
                    serde_json::json!({ "name": name, "version": v, "dist": {} }),
                )
            })
            .collect();
        let latest = versions.keys().next_back().cloned().unwrap_or_default();
        serde_json::json!({ "name": name, "dist-tags": { "latest": latest }, "versions": versions })
    }

    /// An upstream that serves `versions` of `name` (packument and version manifests) to
    /// anyone who asks: a squatter on a published name.
    async fn upstream(name: &str, versions: &[&str]) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc(name, versions)))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(format!("^/{name}/[^-]")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "name": name, "version": "9.9.9" })),
            )
            .mount(&server)
            .await;
        server
    }

    async fn asked(server: &MockServer, name: &str) -> usize {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| {
                r.url.path().starts_with(&format!("/{name}")) && !r.url.path().contains("/-/")
            })
            .count()
    }

    fn context(server: &MockServer, ttl: i64) -> TestContext {
        let uri = server.uri();
        create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.npm.metadata_ttl = ttl;
            cfg.npm.revalidate = true;
        })
    }

    async fn publish(ctx: &TestContext, name: &str, version: &str) {
        use base64::Engine;
        let payload = serde_json::json!({
            "name": name,
            "versions": { version: { "name": name, "version": version, "dist": {} } },
            "dist-tags": { "latest": version },
            "_attachments": { format!("{name}-{version}.tgz"): {
                "data": base64::engine::general_purpose::STANDARD.encode(b"local-tarball"),
            } }
        });
        let resp = send(
            &ctx.app,
            Method::PUT,
            &format!("/npm/{name}"),
            axum::body::Body::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "publish {name}@{version}"
        );
    }

    async fn versions(ctx: &TestContext, uri: &str) -> Vec<String> {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        doc["versions"]
            .as_object()
            .map(|v| v.keys().cloned().collect())
            .unwrap_or_default()
    }

    async fn wait_for(ctx: &TestContext, key: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while ctx.state.storage.stat(key).await.is_none() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{key} never written"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};

    /// An object store whose `versions/` listing or published-packument writes fail on demand.
    struct Faulty {
        inner: ObjectStorage,
        versions_listing_fails: bool,
        published_put_fails: bool,
        versions_listing_empty: bool,
    }

    #[async_trait::async_trait]
    impl StorageBackend for Faulty {
        async fn get(
            &self,
            k: &str,
        ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
            self.inner.get(k).await
        }
        async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
            if self.published_put_fails && k.ends_with("/metadata.json") {
                return Err(crate::storage::StorageError::Network("put failed".into()));
            }
            self.inner.put(k, d, sha256).await
        }
        async fn pin(&self, k: &str) -> Option<String> {
            self.inner.pin(k).await
        }
        async fn delete(&self, k: &str) -> crate::storage::Result<()> {
            self.inner.delete(k).await
        }
        async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
            if self.versions_listing_empty && prefix.ends_with("/versions/") {
                return Ok(Vec::new());
            }
            if self.versions_listing_fails && prefix.ends_with("/versions/") {
                return Err(crate::storage::StorageError::Network(
                    "listing failed".into(),
                ));
            }
            self.inner.list(prefix).await
        }
        async fn list_with_meta(&self, p: &str) -> crate::storage::Result<Vec<(String, FileMeta)>> {
            self.inner.list_with_meta(p).await
        }
        async fn stat(&self, k: &str) -> Option<FileMeta> {
            self.inner.stat(k).await
        }
        async fn health_check(&self) -> bool {
            self.inner.health_check().await
        }
        async fn total_size(&self) -> u64 {
            self.inner.total_size().await
        }
        fn backend_name(&self) -> &'static str {
            "faulty-test-store"
        }
        async fn put_from_path(
            &self,
            k: &str,
            src: &std::path::Path,
            sha256: Option<&str>,
        ) -> crate::storage::Result<()> {
            self.inner.put_from_path(k, src, sha256).await
        }
        async fn copy(&self, s: &str, d: &str, sha256: Option<&str>) -> crate::storage::Result<()> {
            self.inner.copy(s, d, sha256).await
        }
        async fn get_reader(
            &self,
            k: &str,
        ) -> crate::storage::Result<(
            u64,
            Option<String>,
            std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
        )> {
            self.inner.get_reader(k).await
        }
    }

    fn faulty(versions_listing_fails: bool, published_put_fails: bool) -> Storage {
        Storage::from_backend(std::sync::Arc::new(Faulty {
            inner: ObjectStorage::in_memory(),
            versions_listing_fails,
            published_put_fails,
            versions_listing_empty: false,
        }))
    }

    /// A store whose `versions/` listing answers "nothing here" for files it holds, as a local
    /// store did for a directory it could not read.
    fn listing_lies() -> Storage {
        Storage::from_backend(std::sync::Arc::new(Faulty {
            inner: ObjectStorage::in_memory(),
            versions_listing_fails: false,
            published_put_fails: false,
            versions_listing_empty: true,
        }))
    }

    /// Seed a published package directly in the store, its packument as NORA assembles it.
    async fn seed_published(storage: &Storage, name: &str) {
        storage
            .put(
                &format!("npm/{name}/versions/1.0.0.json"),
                serde_json::json!({ "name": name, "version": "1.0.0" })
                    .to_string()
                    .as_bytes(),
            )
            .await
            .unwrap();
        let own = doc(name, &["1.0.0"]);
        super::store_assembled_packument(storage, name, own.to_string().as_bytes())
            .await
            .unwrap();
    }

    #[test]
    fn metadata_paths_name_their_package() {
        use MetadataPath::*;
        assert_eq!(classify_metadata_path("pkg"), Packument { name: "pkg" });
        assert_eq!(
            classify_metadata_path("@s/pkg"),
            Packument { name: "@s/pkg" }
        );
        assert_eq!(classify_metadata_path("-pkg"), Packument { name: "-pkg" });
        assert_eq!(
            classify_metadata_path("pkg/1.0.0"),
            VersionManifest {
                name: "pkg",
                spec: "1.0.0"
            }
        );
        assert_eq!(
            classify_metadata_path("@s/pkg/latest"),
            VersionManifest {
                name: "@s/pkg",
                spec: "latest"
            }
        );
        for other in ["-/v1/search", "pkg/a/b", "@s", "pkg//1.0.0", ""] {
            assert_eq!(classify_metadata_path(other), Other, "{other:?}");
        }
    }

    /// The reported case: a published name, its metadata TTL expired, an upstream package of
    /// the same name. The packument stays the published one and the upstream is never asked.
    #[tokio::test]
    async fn a_published_packument_never_reaches_the_upstream() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let ctx = context(&server, 0);
        publish(&ctx, "corp-lib", "1.0.0").await;
        for _ in 0..3 {
            assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
        }
        assert_eq!(asked(&server, "corp-lib").await, 0);
        assert!(ctx
            .state
            .storage
            .stat("npm/corp-lib/upstream/packument.json")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn a_published_version_manifest_is_answered_from_its_own_keys() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let ctx = context(&server, 0);
        publish(&ctx, "corp-lib", "1.0.0").await;
        for spec in ["1.0.0", "latest"] {
            let resp = send(&ctx.app, Method::GET, &format!("/npm/corp-lib/{spec}"), "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{spec}");
            let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
            assert_eq!(doc["version"], "1.0.0", "{spec}");
        }
        let resp = send(&ctx.app, Method::GET, "/npm/corp-lib/9.9.9", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(asked(&server, "corp-lib").await, 0);
    }

    /// An older release (or another replica running one) cached an upstream packument over a
    /// published one. It is rebuilt from the published keys, never served.
    #[tokio::test]
    async fn a_published_packument_an_older_release_replaced_is_rebuilt() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let ctx = context(&server, 3600);
        publish(&ctx, "corp-lib", "1.0.0").await;
        let key = "npm/corp-lib/metadata.json";
        // With its provenance record (1.3.4 to 1.3.6), and without one (an older release).
        let squatted = serde_json::to_vec(&doc("corp-lib", &["9.9.9"])).unwrap();
        put_with_origin(&ctx.state.storage, key, &squatted, "npm|http://upstream")
            .await
            .unwrap();
        assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
        let same_names = serde_json::to_vec(&doc("corp-lib", &["1.0.0"])).unwrap();
        put_with_origin(&ctx.state.storage, key, &same_names, "npm|http://upstream")
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/npm/corp-lib", "").await;
        let served: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert!(
            served["versions"]["1.0.0"]["dist"]["tarball"].is_string(),
            "rebuilt (publish set the tarball URL), not the copy: {served}"
        );
        assert!(
            !super::is_upstream_copy(&ctx.state.storage, key).await,
            "the copy is replaced"
        );
        ctx.state
            .storage
            .delete(&super::origin_key(key))
            .await
            .unwrap();
        ctx.state.storage.put(key, &squatted).await.unwrap();
        assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
        assert_eq!(asked(&server, "corp-lib").await, 0);
    }

    /// With the versions listing failing, a packument NORA assembled is served as it is (and a
    /// version from its own keys); the upstream is asked only when there is none, or an upstream
    /// copy sits in its place.
    #[tokio::test]
    async fn a_failed_listing_keeps_a_published_packument_local() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let uri = server.uri();
        let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
            faulty(true, false),
            move |cfg| cfg.npm.proxy = Some(uri),
        );
        let own = doc("corp-lib", &["1.0.0"]);
        for (key, body) in [
            (
                "npm/corp-lib/metadata.json",
                serde_json::to_string(&own).unwrap(),
            ),
            (
                "npm/corp-lib/versions/1.0.0.json",
                r#"{"name":"corp-lib","version":"1.0.0"}"#.to_string(),
            ),
        ] {
            ctx.state.storage.put(key, body.as_bytes()).await.unwrap();
        }
        // As 1.4.0 assembled and stored it, with its record.
        super::store_assembled_packument(
            &ctx.state.storage,
            "corp-lib",
            serde_json::to_string(&own).unwrap().as_bytes(),
        )
        .await
        .unwrap();
        assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
        let resp = send(&ctx.app, Method::GET, "/npm/corp-lib/1.0.0", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(asked(&server, "corp-lib").await, 0);
        // An upstream copy in its place is not taken for NORA's own, and NORA cannot tell whether
        // the package is published: unavailable, the upstream not asked.
        let copy = serde_json::to_vec(&doc("corp-lib", &["9.9.9"])).unwrap();
        put_with_origin(
            &ctx.state.storage,
            "npm/corp-lib/metadata.json",
            &copy,
            "npm|http://up",
        )
        .await
        .unwrap();
        let resp = send(&ctx.app, Method::GET, "/npm/corp-lib", "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(asked(&server, "corp-lib").await, 0);
    }

    /// Round 1 fixture (M02): with the versions listing failing and the assembled packument
    /// gone, a tarball download with trusted dates fetches and caches no upstream packument for
    /// a published package.
    #[tokio::test]
    async fn a_failed_listing_primes_nothing_for_a_published_package() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let uri = server.uri();
        let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
            faulty(true, false),
            move |cfg| {
                cfg.npm.proxy = Some(uri);
                cfg.server.trust_upstream_dates = true;
            },
        );
        for (key, body) in [
            (
                "npm/corp-lib/versions/1.0.0.json",
                &br#"{"name":"corp-lib","version":"1.0.0"}"#[..],
            ),
            (
                "npm/corp-lib/tarballs/corp-lib-1.0.0.tgz",
                &b"local-tarball"[..],
            ),
        ] {
            ctx.state.storage.put(key, body).await.unwrap();
        }
        let _ = send(
            &ctx.app,
            Method::GET,
            "/npm/corp-lib/-/corp-lib-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(asked(&server, "corp-lib").await, 0);
        assert!(ctx
            .state
            .storage
            .stat("npm/corp-lib/upstream/packument.json")
            .await
            .is_none());
    }

    /// With the versions listing failing, a published package's release date is read from its
    /// own packument, not from an upstream copy cached before it was published.
    #[tokio::test]
    async fn a_failed_listing_reads_the_release_date_from_the_published_packument() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let uri = server.uri();
        let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
            faulty(true, false),
            move |cfg| {
                cfg.npm.proxy = Some(uri);
                cfg.server.trust_upstream_dates = true;
                cfg.curation.mode = crate::config::CurationMode::Enforce;
                cfg.curation.min_release_age = Some("1h".to_string());
                cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Observe);
            },
        );
        let own = serde_json::json!({ "name": "corp-lib", "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": { "name": "corp-lib", "version": "1.0.0" } },
            "time": { "1.0.0": "2020-01-01T00:00:00.000Z" } });
        let squatted = serde_json::json!({ "name": "corp-lib",
            "versions": { "1.0.0": { "name": "corp-lib", "version": "1.0.0" } },
            "time": { "1.0.0": chrono::Utc::now().to_rfc3339() } });
        for (key, body) in [
            ("npm/corp-lib/metadata.json", own.to_string()),
            ("npm/corp-lib/upstream/packument.json", squatted.to_string()),
            (
                "npm/corp-lib/versions/1.0.0.json",
                r#"{"name":"corp-lib","version":"1.0.0"}"#.to_string(),
            ),
            (
                "npm/corp-lib/tarballs/corp-lib-1.0.0.tgz",
                "local-tarball".to_string(),
            ),
        ] {
            ctx.state.storage.put(key, body.as_bytes()).await.unwrap();
        }
        super::store_assembled_packument(
            &ctx.state.storage,
            "corp-lib",
            own.to_string().as_bytes(),
        )
        .await
        .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/corp-lib/-/corp-lib-1.0.0.tgz",
            "",
        )
        .await;
        let status = resp.status();
        let body = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// The whole decision on a stored published packument: served only when its record names
    /// NORA and the digest of the bytes stored now.
    #[test]
    fn only_a_packument_nora_assembled_is_served_as_it_is() {
        let d = "aa11";
        let cases: [(Option<&str>, &str, bool); 9] = [
            (Some("nora-published\naa11"), d, true),
            (Some("nora-published\nbb22"), d, false),
            (Some("nora-published\naa11"), "bb22", false),
            (Some("npm|https://registry.npmjs.org\naa11"), d, false),
            (Some("nora-published"), d, false),
            (Some("nora-published\n"), "", false),
            (Some("NORA-published\naa11"), d, false),
            (Some(""), d, false),
            (None, d, false),
        ];
        for (record, digest, want) in cases {
            assert_eq!(
                super::assembled_by_nora(record, digest),
                want,
                "{record:?} {digest}"
            );
        }
    }

    /// Round 2 finding (G1): an upstream copy an older release cached over the published
    /// packument with no record, naming exactly the published versions (here with a dependency
    /// of its own), is rebuilt, not served; with the listing failing it is not taken for NORA's.
    #[tokio::test]
    async fn an_old_copy_with_the_published_version_set_is_rebuilt() {
        let server = upstream("corp-lib", &["1.0.0"]).await;
        let ctx = context(&server, 3600);
        publish(&ctx, "corp-lib", "1.0.0").await;
        let mut copy = doc("corp-lib", &["1.0.0"]);
        copy["versions"]["1.0.0"]["dependencies"] = serde_json::json!({ "evil-dep": "*" });
        ctx.state
            .storage
            .put("npm/corp-lib/metadata.json", copy.to_string().as_bytes())
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/npm/corp-lib", "").await;
        let served = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
        assert!(!served.contains("evil-dep"), "{served}");
        assert_eq!(asked(&server, "corp-lib").await, 0);

        let uri = server.uri();
        let failing = crate::test_helpers::create_test_context_with_storage_and_config(
            faulty(true, false),
            move |cfg| cfg.npm.proxy = Some(uri),
        );
        failing
            .state
            .storage
            .put("npm/corp-lib/metadata.json", copy.to_string().as_bytes())
            .await
            .unwrap();
        let resp = send(&failing.app, Method::GET, "/npm/corp-lib", "").await;
        let served = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
        assert!(
            !served.contains("evil-dep"),
            "the old copy is not taken for NORA's: {served}"
        );
    }

    /// Round 2 fixture (m06): a published name with capitals, as npm allowed before 2017.
    #[tokio::test]
    async fn a_published_name_with_capitals_stays_local() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc("Corp-Lib", &["9.9.9"])))
            .mount(&server)
            .await;
        let ctx = context(&server, 0);
        seed_published(&ctx.state.storage, "Corp-Lib").await;
        assert_eq!(versions(&ctx, "/npm/Corp-Lib").await, ["1.0.0"]);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// Round 2 fixture (m08): with the listing failing, a published package's dist-tags come from
    /// the packument NORA assembled; an upstream copy in its place is not NORA's.
    #[tokio::test]
    async fn dist_tags_with_a_failed_listing_stay_local() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/package/corp-lib/dist-tags"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"latest": "9.9.9"})),
            )
            .mount(&server)
            .await;
        let uri = server.uri();
        let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
            faulty(true, false),
            move |cfg| cfg.npm.proxy = Some(uri),
        );
        seed_published(&ctx.state.storage, "corp-lib").await;
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/-/package/corp-lib/dist-tags",
            "",
        )
        .await;
        let tags: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(tags["latest"], "1.0.0");
        assert!(server.received_requests().await.unwrap().is_empty());
        let copy = serde_json::to_vec(&doc("corp-lib", &["9.9.9"])).unwrap();
        put_with_origin(
            &ctx.state.storage,
            "npm/corp-lib/metadata.json",
            &copy,
            "npm|http://up",
        )
        .await
        .unwrap();
        // With an upstream copy in its place NORA cannot tell whether the tags are its own.
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/-/package/corp-lib/dist-tags",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// R9 finding: a store that lists no versions for a published package (a local directory it
    /// could not read) does not make the package unpublished while NORA's assembled packument is
    /// there: it is served, and no upstream is asked or cached.
    #[tokio::test]
    async fn an_empty_listing_beside_an_assembled_packument_stays_local() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let uri = server.uri();
        let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
            listing_lies(),
            move |cfg| {
                cfg.npm.proxy = Some(uri);
                cfg.npm.metadata_ttl = 0;
            },
        );
        seed_published(&ctx.state.storage, "corp-lib").await;
        assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
        assert_eq!(asked(&server, "corp-lib").await, 0);
        assert!(ctx
            .state
            .storage
            .stat("npm/corp-lib/upstream/packument.json")
            .await
            .is_none());
    }

    /// Table row 2.2: a version manifest of a published package, with a listing that answers
    /// "nothing here" beside NORA's assembled packument, comes from the package's own keys.
    #[tokio::test]
    async fn a_version_manifest_with_an_empty_listing_stays_local() {
        let server = upstream("corp-lib", &["1.0.0"]).await;
        let uri = server.uri();
        let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
            listing_lies(),
            move |cfg| cfg.npm.proxy = Some(uri),
        );
        seed_published(&ctx.state.storage, "corp-lib").await;
        let resp = send(&ctx.app, Method::GET, "/npm/corp-lib/1.0.0", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let manifest: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(manifest["version"], "1.0.0");
        assert!(
            manifest.get("dist").is_none(),
            "the stored manifest, not the upstream's: {manifest}"
        );
        assert_eq!(asked(&server, "corp-lib").await, 0);
    }

    /// Table row 2.5: with the listing failing and no packument NORA assembled, NORA cannot tell
    /// whether the package is published: its version manifest is unavailable (503), as cargo
    /// answers a crate it cannot tell is published. A published name is never an upstream's to
    /// answer for, so the upstream is not asked, and nothing is cached on a guess.
    #[tokio::test]
    async fn a_version_manifest_with_a_failed_listing_is_unavailable() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let uri = server.uri();
        let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
            faulty(true, false),
            move |cfg| cfg.npm.proxy = Some(uri),
        );
        let resp = send(&ctx.app, Method::GET, "/npm/corp-lib/9.9.9", "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let written = ctx.state.storage.list("npm/").await.unwrap();
        assert!(written.is_empty(), "nothing cached on a guess: {written:?}");
    }

    /// The same for the packument, the dist-tags and a tarball of a package whose published
    /// versions cannot be listed.
    #[tokio::test]
    async fn a_failed_versions_listing_makes_the_package_unavailable() {
        let server = upstream("left-pad", &["1.3.0"]).await;
        Mock::given(method("GET"))
            .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"upstream".to_vec()))
            .mount(&server)
            .await;
        let uri = server.uri();
        let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
            faulty(true, false),
            move |cfg| cfg.npm.proxy = Some(uri),
        );
        let mut wrong = Vec::new();
        for path in [
            "/npm/left-pad",
            "/npm/-/package/left-pad/dist-tags",
            "/npm/left-pad/-/left-pad-1.3.0.tgz",
        ] {
            let status = send(&ctx.app, Method::GET, path, "").await.status();
            if status != StatusCode::SERVICE_UNAVAILABLE {
                wrong.push(format!("{path} -> {status}"));
            }
        }
        assert!(wrong.is_empty(), "answered other than 503: {wrong:?}");
        let asked: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert!(asked.is_empty(), "upstream asked: {asked:?}");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let written = ctx.state.storage.list("npm/").await.unwrap();
        assert!(written.is_empty(), "nothing cached on a guess: {written:?}");
    }

    /// Second control: a package the listing shows is not published here is proxied as before.
    #[tokio::test]
    async fn a_package_the_listing_shows_unpublished_is_still_proxied() {
        let server = upstream("left-pad", &["1.3.0"]).await;
        super::mount_listing(
            &server,
            "left-pad",
            &[("1.3.0", "left-pad/-/left-pad-1.3.0.tgz")],
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"upstream".to_vec()))
            .mount(&server)
            .await;
        let uri = server.uri();
        let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
            faulty(false, false),
            move |cfg| cfg.npm.proxy = Some(uri),
        );
        assert_eq!(versions(&ctx, "/npm/left-pad").await, ["1.3.0"]);
        let tarball = send(
            &ctx.app,
            Method::GET,
            "/npm/left-pad/-/left-pad-1.3.0.tgz",
            "",
        )
        .await;
        assert_eq!(tarball.status(), StatusCode::OK);
        assert_eq!(&body_bytes(tarball).await[..], b"upstream");
    }

    /// Table row 3.2: dist-tags of a published package, with a listing that answers "nothing
    /// here" beside NORA's assembled packument, are the packument's own.
    #[tokio::test]
    async fn dist_tags_with_an_empty_listing_stay_local() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"latest": "9.9.9"})),
            )
            .mount(&server)
            .await;
        let uri = server.uri();
        let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
            listing_lies(),
            move |cfg| cfg.npm.proxy = Some(uri),
        );
        seed_published(&ctx.state.storage, "corp-lib").await;
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/-/package/corp-lib/dist-tags",
            "",
        )
        .await;
        let tags: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(tags["latest"], "1.0.0");
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// Round 1 fixture (M10): a published scoped package, in both forms of its path.
    #[tokio::test]
    async fn a_published_scoped_packument_never_reaches_the_upstream() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc("@s/pkg", &["9.9.9"])))
            .mount(&server)
            .await;
        let ctx = context(&server, 0);
        for (key, body) in [
            (
                "npm/@s/pkg/versions/1.0.0.json",
                r#"{"name":"@s/pkg","version":"1.0.0"}"#,
            ),
            ("npm/@s/pkg/dist-tags/latest", "1.0.0"),
        ] {
            ctx.state.storage.put(key, body.as_bytes()).await.unwrap();
        }
        for uri in ["/npm/@s%2fpkg", "/npm/@s/pkg"] {
            assert_eq!(versions(&ctx, uri).await, ["1.0.0"], "{uri}");
        }
        let resp = send(&ctx.app, Method::GET, "/npm/@s/pkg/latest", "").await;
        let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(doc["version"], "1.0.0");
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// Round 1 finding (H3): versions published while a read waited for the lock are not taken
    /// for unreadable ones: the set is listed again under the lock.
    #[tokio::test]
    async fn a_publish_during_a_read_is_not_a_503() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let ctx = context(&server, 3600);
        publish(&ctx, "corp-lib", "1.0.0").await;
        publish(&ctx, "corp-lib", "1.1.0").await;
        ctx.state
            .storage
            .delete("npm/corp-lib/metadata.json")
            .await
            .unwrap();
        // The set the read took before the lock: 1.1.0 not yet in it.
        let stale: std::collections::BTreeSet<String> = ["1.0.0".to_string()].into();
        let resp = super::published_packument_response(
            &ctx.state,
            &axum::http::HeaderMap::new(),
            "corp-lib",
            &stale,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let listed: Vec<&String> = doc["versions"].as_object().unwrap().keys().collect();
        assert_eq!(listed, ["1.0.0", "1.1.0"]);
    }

    /// Round 1 finding (H4): `npm dist-tag ls` of a published package reads its own tags; an
    /// unpublished one's come from the upstream, uncached.
    #[tokio::test]
    async fn dist_tags_of_a_published_package_are_its_own() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        Mock::given(method("GET"))
            .and(path("/-/package/left-pad/dist-tags"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"latest": "1.3.0"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/-/package/corp-lib/dist-tags"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"latest": "9.9.9"})),
            )
            .mount(&server)
            .await;
        let ctx = context(&server, 0);
        publish(&ctx, "corp-lib", "1.0.0").await;
        let tags = |uri: &'static str| {
            let app = ctx.app.clone();
            async move {
                let resp = send(&app, Method::GET, uri, "").await;
                assert_eq!(resp.status(), StatusCode::OK, "{uri}");
                serde_json::from_slice::<serde_json::Value>(&body_bytes(resp).await).unwrap()
            }
        };
        assert_eq!(
            tags("/npm/-/package/corp-lib/dist-tags").await["latest"],
            "1.0.0"
        );
        assert_eq!(
            tags("/npm/-/package/left-pad/dist-tags").await["latest"],
            "1.3.0"
        );
        let asked_corp = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().contains("corp-lib"))
            .count();
        assert_eq!(asked_corp, 0);
    }

    /// Any other metadata path (search, registry endpoints) is answered by the upstream and not
    /// cached: no request reaches a key under `npm/` that a packument could share.
    #[tokio::test]
    async fn other_metadata_paths_are_not_cached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"objects": []})),
            )
            .mount(&server)
            .await;
        let ctx = context(&server, 3600);
        for _ in 0..2 {
            let resp = send(&ctx.app, Method::GET, "/npm/-/v1/search?text=x", "").await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(ctx.state.storage.list("npm/").await.unwrap().is_empty());
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    /// #1148: a search reaches the upstream with the query the client sent, encoding kept, so
    /// `npm search` through NORA returns what the upstream finds; a request without a query is
    /// sent without one.
    #[tokio::test]
    async fn a_search_reaches_the_upstream_with_its_query() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .and(query_param("text", "@types/node"))
            .and(query_param("size", "20"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"objects": [{"package": {"name": "@types/node"}}], "total": 1}),
            ))
            .mount(&server)
            .await;
        // registry.npmjs.org without `text`: 400 'text' query parameter is required
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        let ctx = context(&server, 3600);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/-/v1/search?text=%40types%2Fnode&size=20",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("@types/node"));
        let asked = server.received_requests().await.unwrap();
        assert_eq!(asked[0].url.query(), Some("text=%40types%2Fnode&size=20"));
        let resp = send(&ctx.app, Method::GET, "/npm/-/v1/search", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let asked = server.received_requests().await.unwrap();
        assert_eq!(asked[1].url.query(), None);
    }

    /// #1148, ADR-8: a search that names an internal package or a scope owned by a private
    /// upstream is refused with the reason and never sent to the upstream, as an audit that
    /// carries such names is; any other search is sent.
    #[tokio::test]
    async fn a_search_naming_a_private_package_is_refused_and_not_sent() {
        use crate::config::NpmConfig;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"objects": []})),
            )
            .mount(&server)
            .await;
        let uri = server.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            let npm: NpmConfig = toml::from_str(&format!(
                r#"proxies = ["{uri}", {{ url = "{uri}/private", scopes = ["@vendor"] }}]"#
            ))
            .unwrap();
            cfg.npm.proxies = npm.proxies;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces =
                vec!["@internal/*".to_string(), "corp-*".to_string()];
        });
        // (query, refused)
        let rows: [(&str, bool); 11] = [
            ("text=%40internal%2Fsecret", true),
            ("text=react+%40internal%2Fsecret", true),
            ("text=corp-billing", true),
            ("text=scope%3Ainternal", true),
            ("text=%40vendor%2Ftool", true),
            ("text=scope%3Avendor+cli", true),
            ("text=%40vendor", true),
            ("text=lodash&size=20", false),
            ("text=corporate", false),
            ("text=keywords%3Acorp-billing", true),
            // cannot be decoded, so cannot be checked
            ("text=%FF", true),
        ];
        for (query, refused) in rows {
            let before = server.received_requests().await.unwrap().len();
            let resp = send(
                &ctx.app,
                Method::GET,
                &format!("/npm/-/v1/search?{query}"),
                "",
            )
            .await;
            let status = resp.status();
            let body = String::from_utf8_lossy(&body_bytes(resp).await).to_string();
            let sent = server.received_requests().await.unwrap().len() - before;
            if refused {
                assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{query}");
                assert!(body.contains("\"error\""), "{query}: {body}");
                assert_eq!(sent, 0, "{query} reached the upstream");
            } else {
                assert_eq!(status, StatusCode::OK, "{query}");
                assert_eq!(sent, 1, "{query}");
            }
        }
    }

    /// A published version whose document cannot be read is neither dropped from the packument
    /// nor rebuilt at every read: the packument is 503 until it is repaired, and no upstream is
    /// asked in its place.
    #[tokio::test]
    async fn an_unreadable_published_version_is_not_dropped() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let ctx = context(&server, 0);
        publish(&ctx, "corp-lib", "1.0.0").await;
        publish(&ctx, "corp-lib", "1.1.0").await;
        ctx.state
            .storage
            .put("npm/corp-lib/versions/1.1.0.json", b"not json")
            .await
            .unwrap();
        ctx.state
            .storage
            .delete("npm/corp-lib/metadata.json")
            .await
            .unwrap();
        for _ in 0..2 {
            let resp = send(&ctx.app, Method::GET, "/npm/corp-lib", "").await;
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        assert!(ctx
            .state
            .storage
            .stat("npm/corp-lib/metadata.json")
            .await
            .is_none());
        assert_eq!(asked(&server, "corp-lib").await, 0);
    }

    /// A rebuilt packument is served even when it cannot be stored: 503 is only for one that
    /// cannot be assembled.
    #[tokio::test]
    async fn a_rebuilt_packument_is_served_when_it_cannot_be_stored() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let uri = server.uri();
        let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
            faulty(false, true),
            move |cfg| cfg.npm.proxy = Some(uri),
        );
        for (key, body) in [
            (
                "npm/corp-lib/versions/1.0.0.json",
                r#"{"name":"corp-lib","version":"1.0.0"}"#,
            ),
            ("npm/corp-lib/dist-tags/latest", "1.0.0"),
        ] {
            ctx.state.storage.put(key, body.as_bytes()).await.unwrap();
        }
        assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
        assert!(ctx
            .state
            .storage
            .stat("npm/corp-lib/metadata.json")
            .await
            .is_none());
        assert_eq!(asked(&server, "corp-lib").await, 0);
    }

    #[tokio::test]
    async fn an_unpublished_package_is_cached_under_the_upstream_key_only() {
        let server = upstream("left-pad", &["1.3.0"]).await;
        let ctx = context(&server, 3600);
        assert_eq!(versions(&ctx, "/npm/left-pad").await, ["1.3.0"]);
        wait_for(&ctx, "npm/left-pad/upstream/packument.json").await;
        let resp = send(&ctx.app, Method::GET, "/npm/left-pad/1.3.0", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        wait_for(&ctx, "npm/left-pad/upstream/manifests/1.3.0.json").await;
        for key in [
            "npm/left-pad/metadata.json",
            "npm/left-pad/1.3.0/metadata.json",
        ] {
            assert!(ctx.state.storage.stat(key).await.is_none(), "{key}");
        }
    }

    /// What 1.3.6 cached at `metadata.json` is served while fresh, revalidated into the new key
    /// once stale, and never written: a rollback reads it as it was.
    #[tokio::test]
    async fn an_older_releases_cache_is_read_and_left_alone() {
        let server = upstream("left-pad", &["1.3.0", "1.4.0"]).await;
        let legacy = serde_json::to_vec(&doc("left-pad", &["1.3.0"])).unwrap();
        let fresh = context(&server, 3600);
        fresh
            .state
            .storage
            .put("npm/left-pad/metadata.json", &legacy)
            .await
            .unwrap();
        assert_eq!(versions(&fresh, "/npm/left-pad").await, ["1.3.0"]);
        assert_eq!(
            asked(&server, "left-pad").await,
            0,
            "a fresh old cache is served"
        );

        let stale = {
            let uri = server.uri();
            crate::test_helpers::create_test_context_with_storage_and_config(
                fresh.state.storage.clone(),
                move |cfg| {
                    cfg.npm.proxy = Some(uri);
                    cfg.npm.metadata_ttl = 0;
                },
            )
        };
        assert_eq!(versions(&stale, "/npm/left-pad").await, ["1.3.0", "1.4.0"]);
        wait_for(&stale, "npm/left-pad/upstream/packument.json").await;
        assert_eq!(
            stale
                .state
                .storage
                .get("npm/left-pad/metadata.json")
                .await
                .unwrap(),
            legacy
        );
    }

    /// A publish over an upstream copy an older release cached at the published key: its
    /// versions are not imported as published ones, and do not block the publish.
    #[tokio::test]
    async fn a_publish_over_an_upstream_copy_imports_none_of_it() {
        let server = upstream("corp-lib", &["1.0.0", "9.9.9"]).await;
        let ctx = context(&server, 3600);
        let copy = serde_json::to_vec(&doc("corp-lib", &["1.0.0", "9.9.9"])).unwrap();
        put_with_origin(
            &ctx.state.storage,
            "npm/corp-lib/metadata.json",
            &copy,
            "npm|http://up",
        )
        .await
        .unwrap();
        publish(&ctx, "corp-lib", "1.0.0").await;
        assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
        let published = ctx
            .state
            .storage
            .list("npm/corp-lib/versions/")
            .await
            .unwrap();
        assert_eq!(published, ["npm/corp-lib/versions/1.0.0.json"]);
    }

    /// Round 1 finding (H2): a packument with no record of where it came from, on a package with
    /// no per-version keys, is an upstream cache of NORA 1.3.3 or older or a package published to
    /// NORA 0.9.3 or older. A publish over it is refused, naming the key, until the operator says
    /// which: delete it, or list the name in `import_embedded`.
    #[tokio::test]
    async fn a_publish_over_a_packument_of_unknown_origin_waits_for_the_operator() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let unknown = serde_json::to_vec(&doc("corp-lib", &["9.9.9"])).unwrap();
        let ctx = context(&server, 3600);
        ctx.state
            .storage
            .put("npm/corp-lib/metadata.json", &unknown)
            .await
            .unwrap();
        let payload = serde_json::json!({
            "name": "corp-lib",
            "versions": { "1.0.0": { "name": "corp-lib", "version": "1.0.0", "dist": {} } },
            "_attachments": { "corp-lib-1.0.0.tgz": { "data": "dGFy" } }
        });
        let put = |ctx: &TestContext| {
            let app = ctx.app.clone();
            let body = serde_json::to_vec(&payload).unwrap();
            async move {
                send(
                    &app,
                    Method::PUT,
                    "/npm/corp-lib",
                    axum::body::Body::from(body),
                )
                .await
            }
        };
        let resp = put(&ctx).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let text = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
        assert!(
            text.contains("npm/corp-lib/metadata.json")
                && text.contains("NORA_NPM_IMPORT_EMBEDDED=corp-lib"),
            "{text}"
        );
        assert!(ctx
            .state
            .storage
            .list("npm/corp-lib/versions/")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            ctx.state
                .storage
                .get("npm/corp-lib/metadata.json")
                .await
                .unwrap(),
            unknown
        );

        // A name is matched whole: `corp` does not allow `corp-lib`.
        let uri = server.uri();
        let prefix = crate::test_helpers::create_test_context_with_storage_and_config(
            ctx.state.storage.clone(),
            move |cfg| {
                cfg.npm.proxy = Some(uri);
                cfg.npm.import_embedded = vec!["corp".to_string()];
            },
        );
        assert_eq!(put(&prefix).await.status(), StatusCode::CONFLICT);
        // A provenance record written for other bytes does not make it NORA's own either.
        ctx.state
            .storage
            .put(
                &super::origin_key("npm/corp-lib/metadata.json"),
                b"npm|http://up\ndeadbeef",
            )
            .await
            .unwrap();
        assert_eq!(put(&ctx).await.status(), StatusCode::CONFLICT);
        ctx.state
            .storage
            .delete(&super::origin_key("npm/corp-lib/metadata.json"))
            .await
            .unwrap();

        // The operator says it is their own (a package published to NORA 0.9.3 or older).
        let uri = server.uri();
        let allowed = crate::test_helpers::create_test_context_with_storage_and_config(
            ctx.state.storage.clone(),
            move |cfg| {
                cfg.npm.proxy = Some(uri);
                cfg.npm.import_embedded = vec!["corp-lib".to_string()];
            },
        );
        assert_eq!(put(&allowed).await.status(), StatusCode::CREATED);
        assert_eq!(
            versions(&allowed, "/npm/corp-lib").await,
            ["1.0.0", "9.9.9"]
        );
    }

    /// With trusted dates a tarball download primes the packument for its release date. A
    /// published package's dates are its own: nothing is fetched or cached for it.
    #[tokio::test]
    async fn a_tarball_download_primes_nothing_for_a_published_package() {
        let server = upstream("corp-lib", &["9.9.9"]).await;
        let uri = server.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
        });
        publish(&ctx, "corp-lib", "1.0.0").await;
        // Its assembled packument is derived state; with it gone, the name still goes nowhere.
        ctx.state
            .storage
            .delete("npm/corp-lib/metadata.json")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/corp-lib/-/corp-lib-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"local-tarball");
        assert_eq!(asked(&server, "corp-lib").await, 0);
        assert!(ctx
            .state
            .storage
            .stat("npm/corp-lib/upstream/packument.json")
            .await
            .is_none());
        assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
    }

    /// The published packument key is named in one function, and only publish, the rebuild,
    /// the published-packument answer, the readers that pick a key, and retention's lock call
    /// it; the legacy key is named in one function, called only where a cache is read and
    /// where a non-package path is proxied. A new path that writes a published packument has
    /// to name one of them, here.
    #[test]
    fn the_published_key_is_reached_only_from_the_published_side() {
        let source = include_str!("npm.rs");
        let production = &source[..source.find("\n#[cfg(test)]").unwrap()];
        let mut current = "";
        let mut literal_in: Vec<String> = Vec::new();
        let mut published_callers = std::collections::BTreeSet::new();
        let mut legacy_callers = std::collections::BTreeSet::new();
        for line in production.lines() {
            let trimmed = line.trim_start();
            if !line.starts_with(' ') {
                for prefix in [
                    "pub(crate) async fn ",
                    "pub(crate) fn ",
                    "pub async fn ",
                    "pub fn ",
                    "async fn ",
                    "fn ",
                ] {
                    if let Some(rest) = trimmed.strip_prefix(prefix) {
                        current = rest.split(['(', '<']).next().unwrap();
                    }
                }
            }
            if trimmed.starts_with("//") {
                continue;
            }
            if line.contains("metadata.json\"") {
                literal_in.push(current.to_string());
            }
            if line.contains("published_packument_key(")
                && !line.contains("fn published_packument_key")
            {
                published_callers.insert(current.to_string());
            }
            if line.contains("legacy_cache_key(") && !line.contains("fn legacy_cache_key") {
                legacy_callers.insert(current.to_string());
            }
        }
        assert_eq!(literal_in, ["published_packument_key", "legacy_cache_key"]);
        assert_eq!(
            published_callers.into_iter().collect::<Vec<_>>(),
            [
                "handle_publish",
                "packument_key_for_reading",
                "published_packument_response",
                "published_state",
                "serve_dist_tags",
                "serve_metadata",
                "store_assembled_packument",
            ]
        );
        assert_eq!(
            legacy_callers.into_iter().collect::<Vec<_>>(),
            [
                "ensure_npm_metadata_cached",
                "handle_request",
                "packument_key_for_reading",
                "trusted_copy",
                "upstream_metadata",
            ]
        );
    }
}

/// Without trusted upstream dates the quarantine counts from NORA's own first fetch of an
/// artifact's bytes: metadata cached a month ago says when NORA last wrote it, not when it first
/// fetched this file, and its age would let a file first fetched now pass as mature. With trusted
/// dates the release date seeds it (#750), so an old release is not held as new to this mirror.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod quarantine_first_seen {
    use crate::test_helpers::{
        create_test_context_with_config, put_written_days_ago, quarantine_7d, send, TestContext,
    };
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn serve(up: &MockServer, at: &str, body: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(up)
            .await;
    }

    async fn status(ctx: &TestContext, uri: &str) -> StatusCode {
        send(&ctx.app, Method::GET, uri, "").await.status()
    }

    const DOWNLOAD: &str = "/npm/oldpkg/-/oldpkg-1.0.0.tgz";

    fn packument(up: &MockServer) -> Vec<u8> {
        serde_json::json!({
            "name": "oldpkg",
            "versions": {"1.0.0": {"name": "oldpkg", "version": "1.0.0",
                "dist": {"tarball": format!("{}/oldpkg/-/oldpkg-1.0.0.tgz", up.uri())}}},
            "time": {"1.0.0": "2019-01-01T00:00:00.000Z"}
        })
        .to_string()
        .into_bytes()
    }

    async fn upstream() -> MockServer {
        let up = MockServer::start().await;
        serve(&up, "/oldpkg", packument(&up)).await;
        serve(&up, "/oldpkg/-/oldpkg-1.0.0.tgz", b"TGZ".to_vec()).await;
        up
    }

    fn context(up: &MockServer, trust: bool) -> TestContext {
        let uri = up.uri();
        create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.server.trust_upstream_dates = trust;
            quarantine_7d(cfg);
        })
    }

    #[tokio::test]
    async fn without_trusted_dates_a_cached_packument_does_not_date_the_quarantine() {
        let up = upstream().await;
        let ctx = context(&up, false);
        let body = packument(&up);
        put_written_days_ago(&ctx, "npm/oldpkg/upstream/packument.json", &body, 30).await;
        assert_eq!(status(&ctx, DOWNLOAD).await, StatusCode::FORBIDDEN);
    }

    /// A tarball cached before the quarantine recorded it is counted from now on the cache path.
    #[tokio::test]
    async fn a_file_cached_before_the_quarantine_saw_it_counts_from_now() {
        let up = upstream().await;
        let ctx = context(&up, false);
        let body = packument(&up);
        put_written_days_ago(&ctx, "npm/oldpkg/upstream/packument.json", &body, 30).await;
        put_written_days_ago(&ctx, "npm/oldpkg/tarballs/oldpkg-1.0.0.tgz", b"TGZ", 30).await;
        assert_eq!(status(&ctx, DOWNLOAD).await, StatusCode::FORBIDDEN);
        assert!(!crate::test_helpers::upstream_paths(&up)
            .await
            .iter()
            .any(|p| p.ends_with(".tgz")));
    }

    #[tokio::test]
    async fn with_trusted_dates_an_old_release_matures_in_the_quarantine() {
        let up = upstream().await;
        let ctx = context(&up, true);
        assert_eq!(status(&ctx, DOWNLOAD).await, StatusCode::OK);
    }
}

/// A publish stores the tarballs of the versions it publishes, and nothing else. An
/// attachment named for another version — one already published included — or for a key beside
/// a tarball would replace bytes clients already installed, and the pin NORA checks them against.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod publish_attachments {
    use crate::test_helpers::{create_test_context, send, TestContext};
    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use base64::Engine;
    use sha2::Digest;
    use std::collections::BTreeMap;

    /// PUT a publish of `name` carrying `versions` and `attachments` (file name, bytes).
    async fn publish(
        ctx: &TestContext,
        name: &str,
        versions: &[&str],
        attachments: &[(&str, &[u8])],
    ) -> StatusCode {
        let versions: serde_json::Map<String, serde_json::Value> = versions
            .iter()
            .map(|v| {
                (
                    v.to_string(),
                    serde_json::json!({ "name": name, "version": v, "dist": {} }),
                )
            })
            .collect();
        let attachments: serde_json::Map<String, serde_json::Value> = attachments
            .iter()
            .map(|(file, data)| {
                (
                    file.to_string(),
                    serde_json::json!({
                        "data": base64::engine::general_purpose::STANDARD.encode(data)
                    }),
                )
            })
            .collect();
        let payload = serde_json::json!({
            "name": name,
            "versions": versions,
            "_attachments": attachments,
        });
        send(
            &ctx.app,
            Method::PUT,
            &format!("/npm/{name}"),
            Body::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await
        .status()
    }

    /// Every object stored for `name`, and its bytes.
    async fn stored(ctx: &TestContext, name: &str) -> BTreeMap<String, Vec<u8>> {
        let mut objects = BTreeMap::new();
        for key in ctx
            .state
            .storage
            .list(&format!("npm/{name}/"))
            .await
            .unwrap()
        {
            let data = ctx.state.storage.get(&key).await.unwrap();
            objects.insert(key, data.to_vec());
        }
        objects
    }

    #[tokio::test]
    async fn a_publish_cannot_replace_a_published_tarball_or_its_pin() {
        let ctx = create_test_context();
        assert_eq!(
            publish(&ctx, "foo", &["1.0.0"], &[("foo-1.0.0.tgz", b"good")]).await,
            StatusCode::CREATED
        );
        let before = stored(&ctx, "foo").await;
        assert_eq!(before["npm/foo/tarballs/foo-1.0.0.tgz"], b"good");
        let evil_pin = hex::encode(sha2::Sha256::digest(b"evil"));
        let refused: [&[(&str, &[u8])]; 6] = [
            // The tarball of a version already published, beside the one being published.
            &[("foo-1.0.1.tgz", b"next"), ("foo-1.0.0.tgz", b"evil")],
            // The pin beside a published tarball.
            &[
                ("foo-1.0.1.tgz", b"next"),
                ("foo-1.0.0.tgz.sha256", evil_pin.as_bytes()),
            ],
            // Another package's tarball.
            &[("foo-1.0.1.tgz", b"next"), ("bar-1.0.1.tgz", b"bar")],
            // A key beside the tarball being published.
            &[("foo-1.0.1.tgz", b"next"), ("foo-1.0.1.tgz.sha256", b"pin")],
            // Only a published version's tarball.
            &[("foo-1.0.0.tgz", b"evil")],
            // A version's tarball under another name.
            &[("foo-1.0.1.tar.gz", b"next")],
        ];
        for attachments in refused {
            let names: Vec<&str> = attachments.iter().map(|(file, _)| *file).collect();
            assert_eq!(
                publish(&ctx, "foo", &["1.0.1"], attachments).await,
                StatusCode::BAD_REQUEST,
                "{names:?}"
            );
            assert_eq!(
                stored(&ctx, "foo").await,
                before,
                "a refused publish stored something: {names:?}"
            );
        }
        // An attachment that does not decode refuses the publish before its other tarballs are
        // stored.
        let payload = serde_json::json!({
            "name": "foo",
            "versions": {
                "1.0.1": { "name": "foo", "version": "1.0.1", "dist": {} },
                "1.0.2": { "name": "foo", "version": "1.0.2", "dist": {} },
            },
            "_attachments": {
                "foo-1.0.1.tgz": { "data": base64::engine::general_purpose::STANDARD.encode(b"next") },
                "foo-1.0.2.tgz": { "data": "not base64!" },
            },
        });
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/npm/foo",
            Body::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(stored(&ctx, "foo").await, before);
        // The tarball of the version it publishes is all a publish needs.
        assert_eq!(
            publish(&ctx, "foo", &["1.0.1"], &[("foo-1.0.1.tgz", b"next")]).await,
            StatusCode::CREATED
        );
        let after = stored(&ctx, "foo").await;
        assert_eq!(after["npm/foo/tarballs/foo-1.0.0.tgz"], b"good");
        assert_eq!(after["npm/foo/tarballs/foo-1.0.1.tgz"], b"next");
    }

    /// Which attachments a publish stores, each case with its bytes and without them: only the
    /// tarball (`<name>-<version>.tgz`, the name with its scope or without it) of a version the
    /// payload publishes. Anything else refuses the whole publish, whether or not it carries
    /// bytes, and beside a tarball that would be stored.
    #[test]
    fn an_attachment_is_stored_only_as_a_tarball_of_this_publish() {
        use super::publish_tarballs;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"bytes");
        let cases: [(&str, &str, Option<&str>); 24] = [
            (
                "foo",
                "foo-1.0.1.tgz",
                Some("npm/foo/tarballs/foo-1.0.1.tgz"),
            ),
            (
                "@s/pkg",
                "@s/pkg-1.0.1.tgz",
                Some("npm/@s/pkg/tarballs/pkg-1.0.1.tgz"),
            ),
            (
                "@s/pkg",
                "pkg-1.0.1.tgz",
                Some("npm/@s/pkg/tarballs/pkg-1.0.1.tgz"),
            ),
            // Another version's tarball, or a key beside a tarball.
            ("foo", "foo-1.0.0.tgz", None),
            ("foo", "foo-1.0.1.tgz.sha256", None),
            ("foo", "foo-1.0.0.tgz.sha256", None),
            ("foo", "foo-1.0.1.tar.gz", None),
            // Another package's tarball, under any scope or path.
            ("foo", "bar-1.0.1.tgz", None),
            ("foo", "@s/foo-1.0.1.tgz", None),
            ("foo", "x/foo-1.0.1.tgz", None),
            ("foo", "../foo-1.0.1.tgz", None),
            ("foo", "FOO-1.0.1.tgz", None),
            ("foo", "", None),
            ("@s/pkg", "@other/pkg-1.0.1.tgz", None),
            ("@s/pkg", "x/pkg-1.0.1.tgz", None),
            ("@s/pkg", "s/pkg-1.0.1.tgz", None),
            ("@s/pkg", "@s/x/pkg-1.0.1.tgz", None),
            ("@s/pkg", "@s/@s/pkg-1.0.1.tgz", None),
            ("@s/pkg", "@s/../pkg-1.0.1.tgz", None),
            ("@s/pkg", "@spkg-1.0.1.tgz", None),
            ("@s/pkg", "@s-pkg-1.0.1.tgz", None),
            ("@s/pkg", "@s/pkg-1.0.0.tgz", None),
            ("@s/pkg", "@s/pkg-1.0.1.tgz.sha256", None),
            ("@s/pkg", "other-1.0.1.tgz", None),
        ];
        let versions: serde_json::Map<String, serde_json::Value> =
            [("1.0.1".to_string(), serde_json::json!({}))]
                .into_iter()
                .collect();
        let attachments = |entries: &[(&str, serde_json::Value)]| {
            entries
                .iter()
                .map(|(file, attachment)| (file.to_string(), attachment.clone()))
                .collect::<serde_json::Map<String, serde_json::Value>>()
        };
        let with_data = serde_json::json!({ "data": encoded });
        let without_data = serde_json::json!({ "length": 5 });
        for (package, file, stored_as) in cases {
            let own = format!("{}-1.0.1.tgz", package.rsplit('/').next().unwrap());
            for attachment in [&with_data, &without_data] {
                let alone = publish_tarballs(
                    package,
                    &attachments(&[(file, attachment.clone())]),
                    &versions,
                );
                let beside_own = publish_tarballs(
                    package,
                    &attachments(&[(&own, with_data.clone()), (file, attachment.clone())]),
                    &versions,
                );
                let has_data = attachment.get("data").is_some();
                match stored_as {
                    Some(key) => {
                        let expected: Vec<(String, Vec<u8>)> = if has_data {
                            vec![(key.to_string(), b"bytes".to_vec())]
                        } else {
                            Vec::new()
                        };
                        assert_eq!(alone.unwrap(), expected, "{package}: {file:?}");
                        assert!(beside_own.is_ok(), "{package}: {file:?} beside its own");
                    }
                    None => {
                        assert!(alone.is_err(), "{package}: {file:?}, data: {has_data}");
                        assert!(
                            beside_own.is_err(),
                            "{package}: {file:?} beside its own, data: {has_data}"
                        );
                    }
                }
            }
        }
    }

    /// Through the endpoint: a scoped publish carrying another scope's tarball, or a refused
    /// attachment without bytes, is refused and stores nothing.
    #[tokio::test]
    async fn a_publish_with_a_foreign_attachment_stores_nothing() {
        let ctx = create_test_context();
        for file in [
            "@other/pkg-1.0.0.tgz",
            "x/pkg-1.0.0.tgz",
            "@s/x/pkg-1.0.0.tgz",
        ] {
            assert_eq!(
                publish(&ctx, "@s/pkg", &["1.0.0"], &[(file, b"evil")]).await,
                StatusCode::BAD_REQUEST,
                "{file}"
            );
            assert!(stored(&ctx, "@s/pkg").await.is_empty(), "{file} stored");
        }
        let payload = serde_json::json!({
            "name": "foo",
            "versions": { "1.0.1": { "name": "foo", "version": "1.0.1", "dist": {} } },
            "_attachments": {
                "foo-1.0.1.tgz": { "data": base64::engine::general_purpose::STANDARD.encode(b"next") },
                "foo-1.0.0.tgz.sha256": { "length": 64 },
            },
        });
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/npm/foo",
            Body::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(stored(&ctx, "foo").await.is_empty());
    }

    #[tokio::test]
    async fn a_scoped_publish_carries_its_own_tarball_only() {
        let ctx = create_test_context();
        assert_eq!(
            publish(&ctx, "@s/pkg", &["1.0.0"], &[("@s/pkg-1.0.0.tgz", b"good")]).await,
            StatusCode::CREATED
        );
        let before = stored(&ctx, "@s/pkg").await;
        assert_eq!(
            publish(
                &ctx,
                "@s/pkg",
                &["1.0.1"],
                &[("@s/pkg-1.0.1.tgz", b"next"), ("@s/pkg-1.0.0.tgz", b"evil")]
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(stored(&ctx, "@s/pkg").await, before);
        // The attachment may name the package with its scope or without it.
        assert_eq!(
            publish(&ctx, "@s/pkg", &["1.0.1"], &[("pkg-1.0.1.tgz", b"next")]).await,
            StatusCode::CREATED
        );
        assert_eq!(
            stored(&ctx, "@s/pkg").await["npm/@s/pkg/tarballs/pkg-1.0.1.tgz"],
            b"next"
        );
    }
}

/// A package published here is NORA's: its name is never an upstream's to answer for. A
/// tarball of it that NORA does not store is no version of it — the upstream is not asked, so a
/// squatter's bytes are neither served nor stored beside the published ones — and a bulk audit
/// does not hand its name to the upstream.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod published_names_stay_local {
    use crate::test_helpers::{
        body_bytes, create_test_context_with_config, create_test_context_with_storage_and_config,
        outage_storage, send, send_with_headers, TestContext,
    };
    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use base64::Engine;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const BULK: &str = "/npm/-/npm/v1/security/advisories/bulk";

    async fn recording_upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&upstream)
            .await;
        upstream
    }

    async fn publish(ctx: &TestContext, name: &str, version: &str) {
        let short = name.rsplit('/').next().unwrap();
        let payload = serde_json::json!({
            "name": name,
            "versions": { version: { "name": name, "version": version, "dist": {} } },
            "_attachments": { format!("{short}-{version}.tgz"): {
                "data": base64::engine::general_purpose::STANDARD.encode(b"published"),
            } },
        });
        let resp = send(
            &ctx.app,
            Method::PUT,
            &format!("/npm/{name}"),
            Body::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
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

    /// A published package's tag or package fields the store cannot read are not left out: the
    /// packument rebuilt without a stored one and the tags answer 503 (500 for a copy that fails
    /// its integrity check) rather than a document without them — a `latest` derived from the
    /// versions names another version than the one tagged — and a publish stores no packument
    /// without them, so the tag is there once the store reads again.
    #[tokio::test]
    async fn a_published_tag_that_cannot_be_read_is_unavailable_not_left_out() {
        use crate::test_helpers::ReadFault;
        async fn latest(ctx: &TestContext) -> (StatusCode, serde_json::Value) {
            let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
            let status = resp.status();
            let doc: serde_json::Value =
                serde_json::from_slice(&body_bytes(resp).await).unwrap_or_default();
            (status, doc["dist-tags"]["latest"].clone())
        }
        let mut wrong = Vec::new();
        for (fault, expected) in [
            (ReadFault::Network, StatusCode::SERVICE_UNAVAILABLE),
            (ReadFault::Tampered, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            for unreadable in ["npm/pkg/dist-tags/latest", "npm/pkg/pkg.json"] {
                let upstream = recording_upstream().await;
                let uri = upstream.uri();
                let (storage, outage) = outage_storage();
                let ctx = create_test_context_with_storage_and_config(storage, move |c| {
                    c.npm.proxy = Some(uri);
                });
                publish(&ctx, "pkg", "1.0.0").await;
                publish(&ctx, "pkg", "1.0.1").await;
                // The older version is the one tagged.
                ctx.state
                    .storage
                    .put("npm/pkg/dist-tags/latest", b"1.0.0")
                    .await
                    .unwrap();
                ctx.state
                    .storage
                    .delete("npm/pkg/metadata.json")
                    .await
                    .unwrap();
                let (status, tagged) = latest(&ctx).await;
                if (status, tagged.as_str()) != (StatusCode::OK, Some("1.0.0")) {
                    wrong.push(format!("with the store up: {status} latest {tagged}"));
                }
                ctx.state
                    .storage
                    .delete("npm/pkg/metadata.json")
                    .await
                    .unwrap();
                outage.fault_reads_of(unreadable, fault);
                for path in ["/npm/pkg", "/npm/-/package/pkg/dist-tags"] {
                    let status = send(&ctx.app, Method::GET, path, "").await.status();
                    if status != expected {
                        wrong.push(format!("{path}, {unreadable} {fault:?} -> {status}"));
                    }
                }
                // A publish while the tag cannot be read.
                let payload = serde_json::json!({
                    "name": "pkg",
                    "versions": { "1.0.2": { "name": "pkg", "version": "1.0.2", "dist": {} } },
                    "_attachments": { "pkg-1.0.2.tgz": {
                        "data": base64::engine::general_purpose::STANDARD.encode(b"published"),
                    } },
                });
                let published = send(
                    &ctx.app,
                    Method::PUT,
                    "/npm/pkg",
                    Body::from(serde_json::to_vec(&payload).unwrap()),
                )
                .await
                .status();
                outage.end();
                let (status, tagged) = latest(&ctx).await;
                if (status, tagged.as_str()) != (StatusCode::OK, Some("1.0.0")) {
                    wrong.push(format!(
                        "after a publish ({published}) with {unreadable} {fault:?}: {status} latest {tagged}"
                    ));
                }
                let asked = asked(&upstream).await;
                if !asked.is_empty() {
                    wrong.push(format!("upstream asked, {unreadable} {fault:?}: {asked:?}"));
                }
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// A listing of a published package's tags that fails is not taken for no tags: the
    /// packument rebuilt without a stored one answers 503 rather than a `latest` derived from
    /// the versions.
    #[tokio::test]
    async fn a_published_package_whose_tags_cannot_be_listed_is_unavailable() {
        let (storage, outage) = outage_storage();
        let ctx = create_test_context_with_storage_and_config(storage, |_| {});
        publish(&ctx, "pkg", "1.0.0").await;
        publish(&ctx, "pkg", "1.0.1").await;
        ctx.state
            .storage
            .put("npm/pkg/dist-tags/latest", b"1.0.0")
            .await
            .unwrap();
        ctx.state
            .storage
            .delete("npm/pkg/metadata.json")
            .await
            .unwrap();
        outage.fail_listings_of("npm/pkg/dist-tags/");
        for path in ["/npm/pkg", "/npm/-/package/pkg/dist-tags"] {
            let status = send(&ctx.app, Method::GET, path, "").await.status();
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        }
        outage.end();
        let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
        let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(doc["dist-tags"]["latest"], "1.0.0");
    }

    /// A published version whose document the store cannot read is unavailable, not absent and
    /// not left out: its manifest (by version or by tag), the packument rebuilt without a stored
    /// one and the tags answer 503 for a store that cannot be asked and 500 for a copy that fails
    /// its integrity check — never 404 or a document without the version — and the upstream is
    /// not asked. Another version still reads.
    #[tokio::test]
    async fn a_published_version_whose_document_cannot_be_read_is_unavailable_not_absent() {
        use crate::test_helpers::ReadFault;
        let mut wrong = Vec::new();
        for (fault, expected) in [
            (ReadFault::Network, StatusCode::SERVICE_UNAVAILABLE),
            (ReadFault::Tampered, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            for (unreadable, paths) in [
                (
                    "npm/pkg/versions/1.0.0.json",
                    &["/npm/pkg/1.0.0", "/npm/pkg", "/npm/-/package/pkg/dist-tags"][..],
                ),
                ("npm/pkg/dist-tags/latest", &["/npm/pkg/latest"][..]),
            ] {
                let upstream = recording_upstream().await;
                let uri = upstream.uri();
                let (storage, outage) = outage_storage();
                let ctx = create_test_context_with_storage_and_config(storage, move |c| {
                    c.npm.proxy = Some(uri);
                });
                publish(&ctx, "pkg", "1.0.0").await;
                publish(&ctx, "pkg", "1.0.1").await;
                // The tag a client's publish sets.
                ctx.state
                    .storage
                    .put("npm/pkg/dist-tags/latest", b"1.0.1")
                    .await
                    .unwrap();
                // No stored packument: it is rebuilt from the published keys.
                ctx.state
                    .storage
                    .delete("npm/pkg/metadata.json")
                    .await
                    .unwrap();
                for path in paths {
                    let status = send(&ctx.app, Method::GET, path, "").await.status();
                    if status != StatusCode::OK {
                        wrong.push(format!("{path} with the store up -> {status}"));
                    }
                }
                // Rebuilt and stored again where the reads above read the packument.
                let _ = ctx.state.storage.delete("npm/pkg/metadata.json").await;
                outage.fault_reads_of(unreadable, fault);
                for path in paths {
                    let status = send(&ctx.app, Method::GET, path, "").await.status();
                    if status != expected {
                        wrong.push(format!("{path}, {unreadable} {fault:?} -> {status}"));
                    }
                }
                let other = send(&ctx.app, Method::GET, "/npm/pkg/1.0.1", "").await;
                if other.status() != StatusCode::OK {
                    wrong.push(format!(
                        "/npm/pkg/1.0.1, {unreadable} {fault:?} -> {}",
                        other.status()
                    ));
                }
                let asked = asked(&upstream).await;
                if !asked.is_empty() {
                    wrong.push(format!("upstream asked, {unreadable} {fault:?}: {asked:?}"));
                }
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    #[tokio::test]
    async fn a_tarball_a_published_package_does_not_store_is_not_fetched() {
        let upstream = recording_upstream().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxy = Some(uri));
        publish(&ctx, "corp-lib", "1.0.0").await;
        publish(&ctx, "@corp/lib", "1.0.0").await;

        for path in [
            "/npm/corp-lib/-/corp-lib-9.9.9.tgz",
            "/npm/@corp/lib/-/lib-9.9.9.tgz",
            "/npm/download/@corp/lib/9.9.9/0123abcd",
        ] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
        }
        assert_eq!(asked(&upstream).await, Vec::<String>::new());
        let tarballs = ctx
            .state
            .storage
            .list("npm/corp-lib/tarballs/")
            .await
            .unwrap();
        assert!(
            tarballs.iter().all(|key| !key.contains("9.9.9")),
            "{tarballs:?}"
        );

        // Controls: the published version is served from its own bytes, and a package that is
        // not published is still fetched from the upstream.
        let own = send(
            &ctx.app,
            Method::GET,
            "/npm/corp-lib/-/corp-lib-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(own.status(), StatusCode::OK);
        assert_eq!(&body_bytes(own).await[..], b"published");
        super::mount_listing(&upstream, "other", &[("1.0.0", "other/-/other-1.0.0.tgz")]).await;
        let other = send(&ctx.app, Method::GET, "/npm/other/-/other-1.0.0.tgz", "").await;
        assert_eq!(other.status(), StatusCode::OK);
        assert!(asked(&upstream)
            .await
            .contains(&"/other/-/other-1.0.0.tgz".to_string()));
    }

    /// The JSON object the upstream received as the bulk audit body.
    async fn forwarded(upstream: &MockServer) -> serde_json::Value {
        let requests = upstream.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "one audit forwarded");
        serde_json::from_slice(&requests[0].body).unwrap()
    }

    #[tokio::test]
    async fn a_bulk_audit_does_not_name_a_published_package_to_the_upstream() {
        let body = serde_json::json!({
            "corp-lib": ["1.0.0"],
            "@corp/lib": ["1.0.0"],
            "plain-pkg": ["1.0.0"],
        });
        let gzipped = {
            use std::io::Write;
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(body.to_string().as_bytes()).unwrap();
            gz.finish().unwrap()
        };
        // Without a namespace filter, and with one that does not cover the published names.
        for filter in [vec![], vec!["@internal/*".to_string()]] {
            for gzip in [false, true] {
                let upstream = recording_upstream().await;
                let uri = upstream.uri();
                let namespaces = filter.clone();
                let ctx = create_test_context_with_config(move |cfg| {
                    cfg.npm.proxy = Some(uri);
                    cfg.curation.internal_namespaces = namespaces;
                });
                publish(&ctx, "corp-lib", "1.0.0").await;
                publish(&ctx, "@corp/lib", "1.0.0").await;
                let resp = if gzip {
                    send_with_headers(
                        &ctx.app,
                        Method::POST,
                        BULK,
                        vec![("content-encoding", "gzip")],
                        gzipped.clone(),
                    )
                    .await
                } else {
                    send(&ctx.app, Method::POST, BULK, body.to_string()).await
                };
                assert_eq!(
                    resp.status(),
                    StatusCode::OK,
                    "filter {filter:?} gzip {gzip}"
                );
                assert_eq!(
                    forwarded(&upstream).await,
                    serde_json::json!({ "plain-pkg": ["1.0.0"] }),
                    "filter {filter:?} gzip {gzip}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_bulk_audit_naming_no_published_package_is_forwarded_as_sent() {
        let upstream = recording_upstream().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxy = Some(uri));
        publish(&ctx, "corp-lib", "1.0.0").await;
        let sent = r#"{"plain-pkg":["1.0.0"],"lodash":["4.17.0"]}"#;
        let resp = send(&ctx.app, Method::POST, BULK, sent).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let requests = upstream.received_requests().await.unwrap();
        assert_eq!(&requests[0].body[..], sent.as_bytes());
    }

    #[tokio::test]
    async fn a_bulk_audit_is_refused_while_the_store_cannot_tell_what_is_published() {
        let upstream = recording_upstream().await;
        let uri = upstream.uri();
        let (storage, outage) = outage_storage();
        let ctx = create_test_context_with_storage_and_config(storage, move |cfg| {
            cfg.npm.proxy = Some(uri)
        });
        publish(&ctx, "corp-lib", "1.0.0").await;
        outage.begin();
        let resp = send(
            &ctx.app,
            Method::POST,
            BULK,
            r#"{"corp-lib":["1.0.0"],"plain-pkg":["1.0.0"]}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(asked(&upstream).await, Vec::<String>::new());
    }
}

/// A packument from an upstream may name its tarballs under the other scheme of the upstream's
/// own host (an https registry behind a TLS terminator writes `http://` links). Those links are the
/// upstream's too: left as they are, the client fetches the tarball past NORA.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod rewrite_both_schemes {
    use super::{replace_upstream_bytes, rewrite_tarball_urls};
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn packument(links: &[(&str, &str)]) -> Vec<u8> {
        let versions: serde_json::Map<String, serde_json::Value> = links
            .iter()
            .map(|(version, link)| {
                (
                    version.to_string(),
                    serde_json::json!({ "version": version, "dist": { "tarball": link } }),
                )
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({ "name": "pkg", "versions": versions })).unwrap()
    }

    fn tarballs(doc: &[u8]) -> Vec<String> {
        let doc: serde_json::Value = serde_json::from_slice(doc).unwrap();
        doc["versions"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v["dist"]["tarball"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn a_link_under_either_scheme_of_the_upstream_host_is_rewritten() {
        for (upstream, own, twin) in [
            (
                "https://registry.example.com",
                "https://registry.example.com",
                "http://registry.example.com",
            ),
            (
                "http://registry.example.com",
                "http://registry.example.com",
                "https://registry.example.com",
            ),
            (
                "https://registry.example.com/api/npm/repo/",
                "https://registry.example.com/api/npm/repo",
                "http://registry.example.com/api/npm/repo",
            ),
        ] {
            let doc = packument(&[
                ("1.0.0", &format!("{own}/pkg/-/pkg-1.0.0.tgz")),
                ("1.0.1", &format!("{twin}/pkg/-/pkg-1.0.1.tgz")),
                ("1.0.2", "http://other.example.com/pkg/-/pkg-1.0.2.tgz"),
            ]);
            let rewritten = rewrite_tarball_urls(&doc, "http://nora:5000", upstream).unwrap();
            assert_eq!(
                tarballs(&rewritten),
                // Another host is not the upstream's to rewrite: its version is left out.
                vec![
                    "http://nora:5000/npm/pkg/-/pkg-1.0.0.tgz",
                    "http://nora:5000/npm/pkg/-/pkg-1.0.1.tgz",
                ],
                "{upstream}"
            );
            // The byte-level rewrite, for a document that does not parse, does the same.
            let raw = format!("not json {twin}/pkg/-/pkg-1.0.1.tgz {own}/pkg/-/pkg-1.0.0.tgz");
            let rewritten = replace_upstream_bytes(
                raw.as_bytes(),
                upstream.trim_end_matches('/'),
                "http://nora:5000/npm",
            );
            assert_eq!(
                String::from_utf8(rewritten).unwrap(),
                "not json http://nora:5000/npm/pkg/-/pkg-1.0.1.tgz http://nora:5000/npm/pkg/-/pkg-1.0.0.tgz",
                "{upstream}"
            );
        }
    }

    /// A link is the upstream's only where the upstream URL ends: at a `/`, `?`, `#`, the end of
    /// the JSON string, a `\` (a JSON escape such as `\/`), or the end of the text. A longer host,
    /// a port, or credentials before another host name somewhere else, under either scheme: the
    /// byte-level rewrite leaves them as they are, and the targeted one leaves out the version
    /// whose tarball such a link is. A longer last path segment is still the upstream's origin:
    /// the byte-level rewrite leaves it too, and the targeted one serves it on NORA when it is
    /// under the upstream's own scheme.
    #[test]
    fn a_host_or_path_that_only_starts_like_the_upstream_is_not_rewritten() {
        let nora = "http://nora:5000/npm";
        for (upstream, links) in [
            (
                "https://registry.example.com",
                [
                    "https://registry.example.com.evil.org/pkg/-/pkg-1.0.0.tgz",
                    "http://registry.example.com.evil.org/pkg/-/pkg-1.0.0.tgz",
                    "https://registry.example.com:8443/pkg/-/pkg-1.0.0.tgz",
                    "https://registry.example.com@evil.org/pkg/-/pkg-1.0.0.tgz",
                    "http://registry.example.com-mirror.org/pkg/-/pkg-1.0.0.tgz",
                    "https://registry.example.company/pkg/-/pkg-1.0.0.tgz",
                ],
            ),
            (
                "https://registry.example.com/api/npm/repo/",
                [
                    "https://registry.example.com/api/npm/repo-other/pkg/-/pkg-1.0.0.tgz",
                    "http://registry.example.com/api/npm/repo2/pkg/-/pkg-1.0.0.tgz",
                    "https://registry.example.com/api/npm/repo.evil/pkg/-/pkg-1.0.0.tgz",
                    "https://registry.example.com/api/npm/repo:x/pkg/-/pkg-1.0.0.tgz",
                    "https://registry.example.com/api/npm/repo%2Fx/pkg/-/pkg-1.0.0.tgz",
                    "https://registry.example.com/api/npm/repository/pkg/-/pkg-1.0.0.tgz",
                ],
            ),
        ] {
            let trimmed = upstream.trim_end_matches('/');
            let same_origin = upstream.contains("/api/");
            for link in links {
                let doc = packument(&[("1.0.0", link)]);
                let rewritten = rewrite_tarball_urls(&doc, "http://nora:5000", upstream).unwrap();
                let expected: &[&str] = if same_origin && link.starts_with("https://") {
                    &["http://nora:5000/npm/pkg/-/pkg-1.0.0.tgz"]
                } else {
                    &[]
                };
                assert_eq!(tarballs(&rewritten), expected, "{upstream}: {link}");
                let raw = format!("not json {link} {link}");
                let rewritten = replace_upstream_bytes(raw.as_bytes(), trimmed, nora);
                assert_eq!(String::from_utf8(rewritten).unwrap(), raw, "{upstream}");
            }
            // The upstream's own links, wherever its URL ends, under either scheme.
            let twin = trimmed.replacen("https://", "http://", 1);
            for own in [trimmed, twin.as_str()] {
                for (text, expected) in [
                    (
                        format!("{own}/pkg/-/pkg-1.0.0.tgz"),
                        format!("{nora}/pkg/-/pkg-1.0.0.tgz"),
                    ),
                    (format!("{own}?q=pkg"), format!("{nora}?q=pkg")),
                    (format!("{own}#pkg"), format!("{nora}#pkg")),
                    (format!("\"{own}\""), format!("\"{nora}\"")),
                    (format!("\\\"{own}\\\""), format!("\\\"{nora}\\\"")),
                    (own.to_string(), nora.to_string()),
                ] {
                    let rewritten = replace_upstream_bytes(text.as_bytes(), trimmed, nora);
                    assert_eq!(
                        String::from_utf8(rewritten).unwrap(),
                        expected,
                        "{upstream}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn a_served_packument_names_no_tarball_of_the_upstream_host_under_either_scheme() {
        let upstream = MockServer::start().await;
        let host = upstream.uri().replacen("http://", "", 1);
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(packument(&[
                ("1.0.0", &format!("http://{host}/pkg/-/pkg-1.0.0.tgz")),
                ("1.0.1", &format!("https://{host}/pkg/-/pkg-1.0.1.tgz")),
            ])))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.server.public_url = Some("http://nora.example".to_string());
        });
        let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(
            tarballs(&body),
            vec![
                "http://nora.example/npm/pkg/-/pkg-1.0.0.tgz",
                "http://nora.example/npm/pkg/-/pkg-1.0.1.tgz",
            ]
        );
    }
}

/// A cached tarball whose `.sha256` sidecar the store cannot read is not served unchecked. NORA's
/// own copy (an internal or published package, or any package without an upstream) has nowhere
/// else to come from: unavailable (503), its bytes not sent. A proxied copy is fetched again and
/// checked as on its first download; an upstream that fails then answers as on a cache miss.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unreadable_sidecar {
    use crate::test_helpers::{
        body_bytes, create_test_context_with_storage_and_config, outage_storage, send, ReadFault,
        StorageOutage, TestContext,
    };
    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use base64::Engine;
    use sha2::Digest;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn upstream(status: u16) -> MockServer {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(status).set_body_bytes(b"UPSTREAM".to_vec()))
            .mount(&up)
            .await;
        up
    }

    fn context(up: Option<&MockServer>) -> (TestContext, StorageOutage) {
        let uri = up.map(MockServer::uri);
        let (storage, outage) = outage_storage();
        let ctx = create_test_context_with_storage_and_config(storage, move |c| {
            c.npm.proxy = uri;
            c.curation.internal_namespaces = vec!["internal*".to_string()];
        });
        (ctx, outage)
    }

    async fn cache(ctx: &TestContext, name: &str, bytes: &[u8]) {
        let key = format!("npm/{name}/tarballs/{name}-1.0.0.tgz");
        ctx.state.storage.put(&key, bytes).await.unwrap();
        let pin = hex::encode(sha2::Sha256::digest(bytes));
        let sidecar = format!("{key}.sha256");
        ctx.state
            .storage
            .put(&sidecar, pin.as_bytes())
            .await
            .unwrap();
    }

    async fn publish(ctx: &TestContext, name: &str) {
        let payload = serde_json::json!({
            "name": name,
            "versions": { "1.0.0": { "name": name, "version": "1.0.0", "dist": {} } },
            "_attachments": { format!("{name}-1.0.0.tgz"): {
                "data": base64::engine::general_purpose::STANDARD.encode(b"CACHED"),
            } },
        });
        let body = Body::from(serde_json::to_vec(&payload).unwrap());
        let resp = send(&ctx.app, Method::PUT, &format!("/npm/{name}"), body).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    async fn get(ctx: &TestContext, name: &str) -> (StatusCode, Vec<u8>) {
        let uri = format!("/npm/{name}/-/{name}-1.0.0.tgz");
        let resp = send(&ctx.app, Method::GET, &uri, "").await;
        let status = resp.status();
        (status, body_bytes(resp).await.to_vec())
    }

    /// Tarball requests the upstream received (a tarball download may also ask for the packument,
    /// for its release dates).
    async fn asked(up: &MockServer) -> usize {
        let requests = up.received_requests().await.unwrap();
        requests
            .iter()
            .filter(|r| r.url.path().ends_with(".tgz"))
            .count()
    }

    #[tokio::test]
    async fn own_copies_whose_sidecar_cannot_be_read_are_unavailable() {
        let up = upstream(200).await;
        let mut wrong = Vec::new();
        for (case, name, upstream) in [
            ("internal", "internal-pkg", Some(&up)),
            ("published", "pkg", Some(&up)),
            ("no upstream", "pkg", None),
        ] {
            let (ctx, outage) = context(upstream);
            if case == "published" {
                publish(&ctx, name).await;
            } else {
                cache(&ctx, name, b"CACHED").await;
            }
            // The copy and its sidecar read: served.
            if get(&ctx, name).await != (StatusCode::OK, b"CACHED".to_vec()) {
                wrong.push(format!("{case}: not served with the store up"));
            }
            outage.fault_reads_of(".tgz.sha256", ReadFault::Network);
            let (status, body) = get(&ctx, name).await;
            if status != StatusCode::SERVICE_UNAVAILABLE || body.windows(6).any(|w| w == b"CACHED")
            {
                wrong.push(format!(
                    "{case}: {status} {:?}",
                    String::from_utf8_lossy(&body)
                ));
            }
        }
        assert_eq!(asked(&up).await, 0, "an own package's upstream was asked");
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    #[tokio::test]
    async fn a_proxied_copy_whose_sidecar_cannot_be_read_is_fetched_again() {
        let up = upstream(200).await;
        let (ctx, outage) = context(Some(&up));
        cache(&ctx, "pkg", b"CACHED").await;
        assert_eq!(get(&ctx, "pkg").await, (StatusCode::OK, b"CACHED".to_vec()));
        assert_eq!(
            asked(&up).await,
            0,
            "a checked copy is served from the cache"
        );
        super::mount_listing(&up, "pkg", &[("1.0.0", "pkg/-/pkg-1.0.0.tgz")]).await;
        outage.fault_reads_of(".tgz.sha256", ReadFault::Network);
        assert_eq!(
            get(&ctx, "pkg").await,
            (StatusCode::OK, b"UPSTREAM".to_vec())
        );
        let paths: Vec<String> = up
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .filter(|p| p.ends_with(".tgz"))
            .collect();
        assert_eq!(paths, vec!["/pkg/-/pkg-1.0.0.tgz"]);
    }

    /// The upstream fails while the copy cannot be checked: the answer a cache miss gets, never
    /// the unchecked bytes.
    #[tokio::test]
    async fn a_failing_upstream_answers_as_on_a_cache_miss() {
        for status in [500, 404] {
            let up = upstream(status).await;
            let (ctx, outage) = context(Some(&up));
            let (miss, _) = get(&ctx, "other").await;
            cache(&ctx, "pkg", b"CACHED").await;
            outage.fault_reads_of(".tgz.sha256", ReadFault::Network);
            let (got, body) = get(&ctx, "pkg").await;
            assert_eq!(got, miss, "upstream {status}");
            assert!(
                !body.windows(6).any(|w| w == b"CACHED"),
                "upstream {status}"
            );
        }
    }
}

/// A version whose tarball an upstream document places outside that upstream (another host, or
/// a URL that only starts like the upstream's) is no version NORA serves: npm would download it
/// from there, past NORA. It is left out of the packument — `versions`, `time` and the tags — and
/// its manifest is not found; a tarball on the upstream under either scheme, on NORA or at a
/// relative path is served as before. No document NORA serves for an upstream package sends the
/// client anywhere but NORA, however it was cached.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod off_upstream_versions {
    use super::rewrite_tarball_urls;
    use crate::test_helpers::{
        body_bytes, create_test_context_with_config, send, send_with_headers, LogCapture,
    };
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const NORA: &str = "http://nora:5000";

    /// Links outside the upstream `https://registry.example.com/repo` or NORA `http://nora:5000`.
    const OUTSIDE: &[&str] = &[
        "https://evil.example/pkg/-/pkg-2.0.0.tgz",
        "https://registry.example.com.evil.example/repo/pkg/-/pkg-2.0.0.tgz",
        "https://registry.example.com:8443/repo/pkg/-/pkg-2.0.0.tgz",
        "https://registry.example.com@evil.example/repo/pkg/-/pkg-2.0.0.tgz",
        // The upstream's origin, but not this package's tarball, or not a link NORA can serve.
        "https://registry.example.com/repo-other/other/-/other-2.0.0.tgz",
        "https://registry.example.com/pkg/-/pkg-2.0.0.tgz?token=x",
        "HTTPS://evil.example/pkg/-/pkg-2.0.0.tgz",
        " https://evil.example/pkg/-/pkg-2.0.0.tgz",
        "//evil.example/pkg/-/pkg-2.0.0.tgz",
        "/\\evil.example/pkg/-/pkg-2.0.0.tgz",
        "\\\\evil.example/pkg/-/pkg-2.0.0.tgz",
        "ftp://evil.example/pkg-2.0.0.tgz",
        "http://nora:5000.evil.example/npm/pkg/-/pkg-2.0.0.tgz",
        "http://nora:5000@evil.example/npm/pkg/-/pkg-2.0.0.tgz",
        "http://nora:5001/npm/pkg/-/pkg-2.0.0.tgz",
        // Another host on NORA's own scheme and port.
        "http://evil.example:5000/npm/pkg/-/pkg-2.0.0.tgz",
        "//evil.example:5000/npm/pkg/-/pkg-2.0.0.tgz",
    ];

    fn packument(versions: &[(&str, &str)], tags: serde_json::Value) -> Vec<u8> {
        let mut docs = serde_json::Map::new();
        let mut time = serde_json::Map::new();
        time.insert("created".into(), "2020-01-01T00:00:00.000Z".into());
        for (version, link) in versions {
            docs.insert(
                version.to_string(),
                serde_json::json!({ "name": "pkg", "version": version, "dist": { "tarball": link } }),
            );
            time.insert(version.to_string(), "2020-01-02T00:00:00.000Z".into());
        }
        serde_json::to_vec(&serde_json::json!({
            "name": "pkg", "dist-tags": tags, "versions": docs, "time": time,
        }))
        .unwrap()
    }

    fn served(versions_kept: &[(&str, &str)], last: (&str, &str)) -> Vec<u8> {
        let mut all = versions_kept.to_vec();
        all.push(last);
        packument(
            &all,
            serde_json::json!({ "latest": last.0, "next": last.0, "beta": "1.1.0-beta.1" }),
        )
    }

    fn keys(doc: &serde_json::Value, field: &str) -> Vec<String> {
        let mut keys: Vec<String> = doc[field].as_object().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    }

    const KEPT: &[(&str, &str)] = &[
        (
            "1.0.0",
            "https://registry.example.com/repo/pkg/-/pkg-1.0.0.tgz",
        ),
        (
            "1.0.1",
            "http://registry.example.com/repo/pkg/-/pkg-1.0.1.tgz",
        ),
        ("1.0.2", "/npm/pkg/-/pkg-1.0.2.tgz"),
        ("1.0.3", "http://nora:5000/npm/pkg/-/pkg-1.0.3.tgz"),
        (
            "1.1.0-beta.1",
            "https://registry.example.com/repo/pkg/-/pkg-1.1.0-beta.1.tgz",
        ),
    ];

    #[test]
    fn a_version_whose_tarball_is_outside_the_upstream_is_left_out() {
        let mut wrong = Vec::new();
        for link in OUTSIDE {
            let doc = served(KEPT, ("2.0.0", link));
            let out =
                rewrite_tarball_urls(&doc, NORA, "https://registry.example.com/repo/").unwrap();
            let text = String::from_utf8_lossy(&out).to_string();
            let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
            let versions = keys(&doc, "versions");
            let mut time = keys(&doc, "time");
            time.retain(|k| k != "created");
            let expected = ["1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.1.0-beta.1"];
            if versions != expected || time != expected {
                wrong.push(format!("{link}: versions {versions:?} time {time:?}"));
            }
            // `latest` falls back to the highest release below the one left out; a tag naming
            // only that version goes; the others stay.
            let tags = &doc["dist-tags"];
            if *tags != serde_json::json!({ "latest": "1.0.3", "beta": "1.1.0-beta.1" }) {
                wrong.push(format!("{link}: tags {tags}"));
            }
            if text.contains("evil") || text.contains(":8443") || text.contains("2.0.0") {
                wrong.push(format!("{link}: {text}"));
            }
            // The kept links: the upstream's under either scheme on NORA, the others as they were.
            let links: Vec<&str> = expected
                .iter()
                .map(|v| doc["versions"][v]["dist"]["tarball"].as_str().unwrap())
                .collect();
            if links
                != [
                    "http://nora:5000/npm/pkg/-/pkg-1.0.0.tgz",
                    "http://nora:5000/npm/pkg/-/pkg-1.0.1.tgz",
                    "/npm/pkg/-/pkg-1.0.2.tgz",
                    "http://nora:5000/npm/pkg/-/pkg-1.0.3.tgz",
                    "http://nora:5000/npm/pkg/-/pkg-1.1.0-beta.1.tgz",
                ]
            {
                wrong.push(format!("{link}: kept {links:?}"));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// `latest` on a version left out, with no release below it left: the tag goes.
    #[test]
    fn latest_without_a_release_below_it_goes() {
        let doc = packument(
            &[
                ("2.0.0", "https://evil.example/pkg-2.0.0.tgz"),
                (
                    "3.0.0",
                    "https://registry.example.com/repo/pkg/-/pkg-3.0.0.tgz",
                ),
                (
                    "1.0.0-rc.1",
                    "https://registry.example.com/repo/pkg/-/pkg-1.0.0-rc.1.tgz",
                ),
            ],
            serde_json::json!({ "latest": "2.0.0", "next": "3.0.0" }),
        );
        let out = rewrite_tarball_urls(&doc, NORA, "https://registry.example.com/repo").unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(doc["dist-tags"], serde_json::json!({ "next": "3.0.0" }));
        assert_eq!(keys(&doc, "versions"), ["1.0.0-rc.1", "3.0.0"]);
    }

    fn upstream_packument(up: &MockServer, last: &str) -> Vec<u8> {
        let base = up.uri();
        let link = |v: &str| format!("{base}/pkg/-/pkg-{v}.tgz");
        packument(
            &[
                ("1.0.0", &link("1.0.0")),
                ("1.1.0", &link("1.1.0")),
                ("2.0.0", last),
            ],
            serde_json::json!({ "latest": "2.0.0" }),
        )
    }

    async fn upstream() -> MockServer {
        let up = MockServer::start().await;
        let doc = upstream_packument(&up, "https://evil.example/pkg/-/pkg-2.0.0.tgz");
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(doc.clone()))
            .mount(&up)
            .await;
        let manifest = |v: &str, link: String| {
            serde_json::to_vec(
                &serde_json::json!({ "name": "pkg", "version": v, "dist": { "tarball": link } }),
            )
            .unwrap()
        };
        for (spec, version, link) in [
            (
                "2.0.0",
                "2.0.0",
                "https://evil.example/pkg/-/pkg-2.0.0.tgz".to_string(),
            ),
            (
                "latest",
                "2.0.0",
                "https://evil.example/pkg/-/pkg-2.0.0.tgz".to_string(),
            ),
            (
                "1.1.0",
                "1.1.0",
                format!("{}/pkg/-/pkg-1.1.0.tgz", up.uri()),
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/pkg/{spec}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(manifest(version, link)))
                .mount(&up)
                .await;
        }
        up
    }

    #[tokio::test]
    async fn no_served_document_sends_the_client_past_nora() {
        let up = upstream().await;
        let uri = up.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.server.public_url = Some("http://nora.example".to_string());
        });
        let mut wrong = Vec::new();
        for accept in ["application/json", "application/vnd.npm.install-v1+json"] {
            let resp = send_with_headers(
                &ctx.app,
                Method::GET,
                "/npm/pkg",
                vec![("accept", accept)],
                "",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_bytes(resp).await;
            let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if keys(&doc, "versions") != ["1.0.0", "1.1.0"]
                || doc["dist-tags"]["latest"] != "1.1.0"
                || String::from_utf8_lossy(&body).contains("evil")
            {
                wrong.push(format!("{accept}: {}", String::from_utf8_lossy(&body)));
            }
        }
        for spec in ["2.0.0", "latest"] {
            let resp = send(&ctx.app, Method::GET, &format!("/npm/pkg/{spec}"), "").await;
            let status = resp.status();
            let body = body_bytes(resp).await;
            if status != StatusCode::NOT_FOUND || String::from_utf8_lossy(&body).contains("evil") {
                wrong.push(format!(
                    "/npm/pkg/{spec}: {status} {}",
                    String::from_utf8_lossy(&body)
                ));
            }
        }
        let resp = send(&ctx.app, Method::GET, "/npm/pkg/1.1.0", "").await;
        let body = body_bytes(resp).await;
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        if doc["dist"]["tarball"] != "http://nora.example/npm/pkg/-/pkg-1.1.0.tgz" {
            wrong.push(format!(
                "/npm/pkg/1.1.0: {}",
                String::from_utf8_lossy(&body)
            ));
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// A packument cached with such a link (by a release that kept it) is not served with it.
    /// It is fetched again in full whatever its age — a 304 would keep it — and, with the
    /// upstream down, served stale without the version.
    #[tokio::test]
    async fn a_cached_link_past_nora_is_not_served() {
        use crate::registry::{write_validators, Validators};
        for (case, ttl, up_status) in [
            ("fresh", 3600, 200),
            ("expired", 0, 200),
            ("upstream down", 0, 500),
        ] {
            let up = MockServer::start().await;
            let fresh = upstream_packument(&up, &format!("{}/pkg/-/pkg-2.0.0.tgz", up.uri()));
            Mock::given(method("GET"))
                .and(header_exists("if-none-match"))
                .respond_with(ResponseTemplate::new(304))
                .mount(&up)
                .await;
            Mock::given(method("GET"))
                .and(path("/pkg"))
                .respond_with(ResponseTemplate::new(up_status).set_body_bytes(fresh))
                .mount(&up)
                .await;
            let uri = up.uri();
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.npm.proxy = Some(uri);
                cfg.npm.metadata_ttl = ttl;
                cfg.npm.serve_stale = true;
                cfg.server.public_url = Some("http://nora.example".to_string());
            });
            let key = "npm/pkg/upstream/packument.json";
            let cached = packument(
                &[
                    ("1.0.0", "http://nora.example/npm/pkg/-/pkg-1.0.0.tgz"),
                    ("2.0.0", "https://evil.example/pkg/-/pkg-2.0.0.tgz"),
                ],
                serde_json::json!({ "latest": "2.0.0" }),
            );
            ctx.state.storage.put(key, &cached).await.unwrap();
            let validators = Validators {
                etag: Some("\"v1\"".to_string()),
                last_modified: None,
            };
            write_validators(&ctx.state.storage, key, &validators).await;
            let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{case}");
            let body = body_bytes(resp).await;
            let text = String::from_utf8_lossy(&body);
            assert!(!text.contains("evil"), "{case}: {text}");
            let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let expected: &[&str] = if up_status == 200 {
                &["1.0.0", "1.1.0", "2.0.0"]
            } else {
                &["1.0.0"]
            };
            assert_eq!(keys(&doc, "versions"), expected, "{case}");
            if up_status == 200 {
                let conditional = up
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .filter(|r| r.headers.contains_key("if-none-match"))
                    .count();
                assert_eq!(conditional, 0, "{case}: the copy was revalidated");
            }
        }
    }

    /// Each version left out is logged once, by package and version and the host only — not
    /// the link, which may carry a token.
    #[tokio::test]
    async fn a_version_left_out_is_warned_about_once() {
        let up = MockServer::start().await;
        let doc = packument(
            &[
                ("1.0.0", &format!("{}/warned/-/warned-1.0.0.tgz", up.uri())),
                (
                    "2.0.0",
                    "https://evil.example/secret-token/warned-2.0.0.tgz",
                ),
            ],
            serde_json::json!({ "latest": "2.0.0" }),
        );
        let doc = String::from_utf8(doc)
            .unwrap()
            .replace("\"pkg\"", "\"warned\"");
        Mock::given(method("GET"))
            .and(path("/warned"))
            .respond_with(ResponseTemplate::new(200).set_body_string(doc))
            .mount(&up)
            .await;
        let uri = up.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.npm.metadata_ttl = 0;
        });
        let (log, _guard) = LogCapture::start();
        for _ in 0..3 {
            let resp = send(&ctx.app, Method::GET, "/npm/warned", "").await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let text = log.text();
        let lines: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("WARN") && l.contains("warned") && l.contains("2.0.0"))
            .collect();
        assert_eq!(lines.len(), 1, "{text}");
        assert!(lines[0].contains("evil.example"), "{text}");
        assert!(!text.contains("secret-token"), "{text}");
    }
}

/// A tarball link on the upstream's own origin but outside its path — GitLab's instance-level
/// npm endpoint names each tarball under the project that holds it — is the upstream's: served on
/// NORA, and fetched by NORA from exactly that link with the upstream's credential. A link on any
/// other origin, another upstream's included, is left out and never asked.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod upstream_origin_tarballs {
    use super::rewrite_tarball_urls;
    use crate::config::{NpmConfig, NpmProxyEntry};
    use crate::secrets::ProtectedString;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{any, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TOKEN: &str = "vendor-tok";
    const NORA: &str = "http://nora.example";
    const NAME: &str = "@vendor/pkg";
    const PROJECT: &str = "/api/v4/projects/7/packages/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz";
    const ON_NORA: &str = "http://nora.example/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz";

    fn instance(gitlab: &MockServer) -> String {
        format!("{}/api/v4/packages/npm", gitlab.uri())
    }

    fn packument(name: &str, link: &str) -> String {
        serde_json::json!({
            "name": name,
            "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": {
                "name": name, "version": "1.0.0", "dist": { "tarball": link },
            } },
            "time": { "1.0.0": "2020-01-02T00:00:00.000Z" },
        })
        .to_string()
    }

    const VERSIONS: &[&str] = &["1.0.0", "1.1.0", "1.2.0", "1.3.0"];

    /// Where the project keeps the tarball of `version`.
    fn project(version: &str) -> String {
        format!("/api/v4/projects/7/packages/npm/@vendor/pkg/-/@vendor/pkg-{version}.tgz")
    }

    /// What the project's tarball of `version` holds.
    fn tgz(version: &str) -> Vec<u8> {
        match version {
            "1.0.0" => b"GITLAB-TGZ".to_vec(),
            other => format!("GITLAB-TGZ {other}").into_bytes(),
        }
    }

    fn packument_of(name: &str, links: &[(&str, String)]) -> String {
        let versions: serde_json::Map<String, serde_json::Value> = links
            .iter()
            .map(|(v, link)| {
                let doc = serde_json::json!({
                    "name": name, "version": v, "dist": { "tarball": link },
                });
                (v.to_string(), doc)
            })
            .collect();
        let time: serde_json::Map<String, serde_json::Value> = links
            .iter()
            .map(|(v, _)| (v.to_string(), "2020-01-02T00:00:00.000Z".into()))
            .collect();
        serde_json::json!({
            "name": name,
            "dist-tags": { "latest": links.last().map(|(v, _)| *v) },
            "versions": versions,
            "time": time,
        })
        .to_string()
    }

    /// A GitLab instance-level endpoint for `@vendor`, answering only with the token: the
    /// packument and version manifests (naming each tarball on the origin `origin` gives) at the
    /// instance level, the tarballs under the project.
    async fn gitlab(origin: impl FnOnce(&MockServer) -> String) -> MockServer {
        let gitlab = MockServer::start().await;
        let origin = origin(&gitlab);
        let links: Vec<(&str, String)> = VERSIONS
            .iter()
            .map(|v| (*v, format!("{origin}{}", project(v))))
            .collect();
        Mock::given(method("GET"))
            .and(path("/api/v4/packages/npm/@vendor/pkg"))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument_of(NAME, &links)))
            .mount(&gitlab)
            .await;
        for (version, link) in &links {
            let manifest = serde_json::json!({
                "name": NAME, "version": version, "dist": { "tarball": link },
            });
            Mock::given(method("GET"))
                .and(path(format!("/api/v4/packages/npm/@vendor/pkg/{version}")))
                .and(header("authorization", "Bearer vendor-tok"))
                .respond_with(ResponseTemplate::new(200).set_body_string(manifest.to_string()))
                .mount(&gitlab)
                .await;
            Mock::given(method("GET"))
                .and(path(project(version)))
                .and(header("authorization", "Bearer vendor-tok"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz(version)))
                .mount(&gitlab)
                .await;
        }
        gitlab
    }

    /// 200 to anything, so only its request log tells.
    async fn open_server() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ELSEWHERE".to_vec()))
            .mount(&server)
            .await;
        server
    }

    fn context(public: &str, private: &str) -> TestContext {
        context_with_ttl(public, private, 3600)
    }

    fn context_with_ttl(public: &str, private: &str, ttl: i64) -> TestContext {
        context_with(public, private, ttl, true)
    }

    /// `trust`: whether upstream release dates are trusted — then a tarball download caches its
    /// packument first, for the date.
    fn context_with(public: &str, private: &str, ttl: i64, trust: bool) -> TestContext {
        let mut npm: NpmConfig = toml::from_str(&format!(
            r#"proxies = ["{public}", {{ url = "{private}", scopes = ["@vendor"], auth_bearer_env = "NORA_NPM_VENDOR_TOKEN" }}]"#
        ))
        .unwrap();
        if let NpmProxyEntry::Full(p) = &mut npm.proxies[1] {
            p.auth_bearer = Some(ProtectedString::from(TOKEN));
        }
        let proxies = npm.proxies;
        create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.npm.metadata_ttl = ttl;
            cfg.server.trust_upstream_dates = trust;
            cfg.server.public_url = Some(NORA.to_string());
        })
    }

    async fn get(ctx: &TestContext, uri: &str) -> (StatusCode, Vec<u8>) {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        let status = resp.status();
        (status, body_bytes(resp).await.to_vec())
    }

    async fn versions(ctx: &TestContext) -> serde_json::Value {
        let (status, body) = get(ctx, "/npm/@vendor%2fpkg").await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        doc["versions"].clone()
    }

    /// Requests a server received, by path, with whether each carried a credential.
    async fn log(server: &MockServer) -> Vec<(String, bool)> {
        let requests = server.received_requests().await.unwrap();
        requests
            .iter()
            .map(|r| {
                (
                    r.url.path().to_string(),
                    r.headers.contains_key("authorization"),
                )
            })
            .collect()
    }

    async fn settle() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    /// Each version's tarball from its own link, whether the packument served was fetched first
    /// or fetched again (an expired copy).
    #[tokio::test]
    async fn a_tarball_on_the_upstream_origin_is_fetched_from_its_own_link() {
        for ttl in [3600, 0] {
            let public = open_server().await;
            let gitlab = gitlab(MockServer::uri).await;
            let ctx = context_with_ttl(&public.uri(), &instance(&gitlab), ttl);
            for _ in 0..2 {
                let versions = versions(&ctx).await;
                assert_eq!(
                    versions["1.0.0"]["dist"]["tarball"], ON_NORA,
                    "{ttl}: {versions}"
                );
                settle().await;
            }
            let (status, manifest) = get(&ctx, "/npm/@vendor%2fpkg/1.0.0").await;
            assert_eq!(status, StatusCode::OK, "{ttl}");
            let doc: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
            assert_eq!(doc["dist"]["tarball"], ON_NORA, "{ttl}: {doc}");
            let mut expected = Vec::new();
            for version in VERSIONS {
                let uri = format!("/npm/@vendor/pkg/-/@vendor/pkg-{version}.tgz");
                let (status, body) = get(&ctx, &uri).await;
                assert_eq!(
                    (status, body),
                    (StatusCode::OK, tgz(version)),
                    "{ttl}: {version}"
                );
                expected.push((project(version), true));
            }
            let tarballs: Vec<(String, bool)> = log(&gitlab)
                .await
                .into_iter()
                .filter(|(p, _)| p.ends_with(".tgz"))
                .collect();
            assert_eq!(tarballs, expected, "{ttl}");
            assert!(
                log(&public).await.is_empty(),
                "{ttl}: {:?}",
                log(&public).await
            );
        }
    }

    /// A lockfile install asks for the tarball first, with nothing cached: NORA reads the
    /// packument to find where the upstream keeps it.
    #[tokio::test]
    async fn a_tarball_asked_before_its_packument_is_found_on_the_upstream_origin() {
        for trust in [true, false] {
            let public = open_server().await;
            let gitlab = gitlab(MockServer::uri).await;
            let ctx = context_with(&public.uri(), &instance(&gitlab), 3600, trust);
            let (status, body) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
            assert_eq!(
                (status, body.as_slice()),
                (StatusCode::OK, b"GITLAB-TGZ".as_slice()),
                "trust {trust}: {}",
                String::from_utf8_lossy(&body)
            );
            assert!(log(&public).await.is_empty(), "{:?}", log(&public).await);
        }
    }

    /// GitLab answers its instance-level tarball path by forwarding to the public registry (302,
    /// measured on 19.5). A tarball asked before its packument is cached — a lockfile install, or
    /// npm asking for it before the packument NORA just served is written — is looked up in the
    /// packument first: neither that path nor the public registry is asked.
    #[tokio::test]
    async fn a_tarball_asked_first_does_not_follow_the_upstream_to_the_public_registry() {
        let public = open_server().await;
        let gitlab = gitlab(MockServer::uri).await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/packages/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz",
            ))
            .respond_with(ResponseTemplate::new(302).insert_header(
                "location",
                format!("{}/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz", public.uri()).as_str(),
            ))
            .mount(&gitlab)
            .await;
        let ctx = context_with(&public.uri(), &instance(&gitlab), 3600, false);
        let (status, body) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
        assert_eq!(
            (status, body.as_slice()),
            (StatusCode::OK, b"GITLAB-TGZ".as_slice())
        );
        let tarballs: Vec<(String, bool)> = log(&gitlab)
            .await
            .into_iter()
            .filter(|(p, _)| p.ends_with(".tgz"))
            .collect();
        assert_eq!(tarballs, vec![(PROJECT.to_string(), true)]);
        assert!(log(&public).await.is_empty(), "{:?}", log(&public).await);
    }

    /// The same project path on another origin — the other upstream's, or one no upstream has —
    /// is left out, and nothing is asked of it.
    #[tokio::test]
    async fn the_same_path_on_another_origin_is_left_out() {
        let elsewhere = open_server().await;
        for (case, on_public) in [("another upstream", true), ("no upstream", false)] {
            let public = open_server().await;
            let target = if on_public {
                public.uri()
            } else {
                elsewhere.uri()
            };
            let gitlab = gitlab(|_| target.clone()).await;
            let ctx = context(&public.uri(), &instance(&gitlab));
            let versions = versions(&ctx).await;
            assert!(
                versions.as_object().unwrap().is_empty(),
                "{case}: {versions}"
            );
            settle().await;
            let (status, _) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
            assert_ne!(status, StatusCode::OK, "{case}");
            assert!(
                log(&public).await.is_empty(),
                "{case}: {:?}",
                log(&public).await
            );
            assert!(
                log(&elsewhere).await.is_empty(),
                "{case}: {:?}",
                log(&elsewhere).await
            );
        }
    }

    /// The default upstream's packument naming the private upstream's origin: left out, and the
    /// private upstream is never asked (with or without its token).
    #[tokio::test]
    async fn a_packument_from_one_upstream_cannot_name_the_origin_of_another() {
        let gitlab = gitlab(MockServer::uri).await;
        let public = MockServer::start().await;
        let link = format!(
            "{}/api/v4/projects/7/packages/npm/pkg/-/pkg-1.0.0.tgz",
            gitlab.uri()
        );
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument("pkg", &link)))
            .mount(&public)
            .await;
        let ctx = context(&public.uri(), &instance(&gitlab));
        let (status, body) = get(&ctx, "/npm/pkg").await;
        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(doc["versions"].as_object().unwrap().is_empty(), "{doc}");
        settle().await;
        let (status, _) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
        assert_ne!(status, StatusCode::OK);
        assert!(log(&gitlab).await.is_empty(), "{:?}", log(&gitlab).await);
    }

    /// A packument cached with the upstream's own link as it is (by the release before this
    /// one, which kept every link it did not recognise; under the key an older release still
    /// wrote, too) is served on NORA, and its tarball fetched from that link.
    #[tokio::test]
    async fn a_copy_cached_with_the_link_as_it_is_is_served_on_nora() {
        for key in [
            super::upstream_packument_key(NAME),
            super::legacy_cache_key(NAME),
        ] {
            let public = open_server().await;
            let gitlab = gitlab(MockServer::uri).await;
            let upstream = instance(&gitlab);
            let ctx = context(&public.uri(), &upstream);
            let cached = packument(NAME, &format!("{}{PROJECT}", gitlab.uri()));
            super::put_with_origin(
                &ctx.state.storage,
                &key,
                cached.as_bytes(),
                &super::origin_of(&upstream),
            )
            .await
            .unwrap();
            let versions = versions(&ctx).await;
            assert_eq!(
                versions["1.0.0"]["dist"]["tarball"], ON_NORA,
                "{key}: {versions}"
            );
            let (status, body) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
            assert_eq!(
                (status, body.as_slice()),
                (StatusCode::OK, b"GITLAB-TGZ".as_slice()),
                "{key}"
            );
            let packuments = log(&gitlab)
                .await
                .into_iter()
                .filter(|(p, _)| !p.ends_with(".tgz"))
                .count();
            assert_eq!(packuments, 0, "{key}: a fresh copy was asked for again");
        }
    }

    /// A copy cached as it is with the project path on another origin (by the release before
    /// this one): a download of that tarball never asks that origin.
    #[tokio::test]
    async fn a_cached_link_on_another_origin_is_never_asked() {
        let public = open_server().await;
        let elsewhere = open_server().await;
        let gitlab = gitlab(MockServer::uri).await;
        let upstream = instance(&gitlab);
        let ctx = context(&public.uri(), &upstream);
        let cached = packument(NAME, &format!("{}{PROJECT}", elsewhere.uri()));
        super::put_with_origin(
            &ctx.state.storage,
            &super::upstream_packument_key(NAME),
            cached.as_bytes(),
            &super::origin_of(&upstream),
        )
        .await
        .unwrap();
        let _ = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
        assert!(
            log(&elsewhere).await.is_empty(),
            "{:?}",
            log(&elsewhere).await
        );
        assert!(log(&public).await.is_empty(), "{:?}", log(&public).await);
    }

    /// A scope's copy cached before its upstream owned it (no record of that owner) names a link
    /// on the owner's origin: NORA does not follow it with the owner's token — it asks the owner
    /// for the packument and follows the link that names.
    #[tokio::test]
    async fn a_copy_the_owner_did_not_deliver_does_not_say_where_to_fetch() {
        for trust in [true, false] {
            the_owner_is_asked_instead(trust).await;
        }
    }

    async fn the_owner_is_asked_instead(trust: bool) {
        let public = open_server().await;
        let gitlab = gitlab(MockServer::uri).await;
        let squatted = "/api/v4/projects/666/packages/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz";
        Mock::given(method("GET"))
            .and(path(squatted))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SQUATTED".to_vec()))
            .mount(&gitlab)
            .await;
        let ctx = context_with(&public.uri(), &instance(&gitlab), 3600, trust);
        let cached = packument(NAME, &format!("{}{squatted}", gitlab.uri()));
        ctx.state
            .storage
            .put(&super::upstream_packument_key(NAME), cached.as_bytes())
            .await
            .unwrap();
        let (status, body) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
        assert_eq!(
            (status, body.as_slice()),
            (StatusCode::OK, b"GITLAB-TGZ".as_slice()),
            "trust {trust}: {}",
            String::from_utf8_lossy(&body)
        );
        let asked: Vec<String> = log(&gitlab).await.into_iter().map(|(p, _)| p).collect();
        assert!(
            !asked.iter().any(|p| p == squatted),
            "trust {trust}: {asked:?}"
        );
    }

    /// After the upstream moved, a copy cached from the old one keeps no link to it: with the
    /// new upstream down, the version is served stale without it, and the old origin is never
    /// asked — the new upstream's credential does not go there.
    #[tokio::test]
    async fn after_the_upstream_moved_the_old_origin_is_not_asked() {
        let old = open_server().await;
        let moved = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&moved)
            .await;
        let upstream = format!("{}/api/v4/packages/npm", moved.uri());
        let ctx = create_test_context_with_config({
            let upstream = upstream.clone();
            move |cfg| {
                cfg.npm.proxy = Some(upstream);
                cfg.npm.proxy_auth = Some(ProtectedString::from("user:pass"));
                cfg.npm.metadata_ttl = 3600;
                cfg.npm.serve_stale = true;
                cfg.server.public_url = Some(NORA.to_string());
            }
        });
        let cached = packument(
            "pkg",
            &format!(
                "{}/api/v4/projects/7/packages/npm/pkg/-/pkg-1.0.0.tgz",
                old.uri()
            ),
        );
        ctx.state
            .storage
            .put(&super::upstream_packument_key("pkg"), cached.as_bytes())
            .await
            .unwrap();
        let (status, body) = get(&ctx, "/npm/pkg").await;
        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(doc["versions"].as_object().unwrap().is_empty(), "{doc}");
        let (status, _) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
        assert_ne!(status, StatusCode::OK);
        assert!(log(&old).await.is_empty(), "{:?}", log(&old).await);
    }

    /// After `NORA_PUBLIC_URL` moved, with the upstream down: a cached packument is served
    /// without the versions it names at the old address, or not at all without `serve_stale` —
    /// the limit the deploy guide states, with its workaround.
    #[tokio::test]
    async fn after_nora_moved_with_the_upstream_down_its_old_links_are_left_out() {
        for serve_stale in [true, false] {
            let down = MockServer::start().await;
            Mock::given(any())
                .respond_with(ResponseTemplate::new(503))
                .mount(&down)
                .await;
            let uri = down.uri();
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.npm.proxy = Some(uri);
                cfg.npm.serve_stale = serve_stale;
                cfg.server.public_url = Some(NORA.to_string());
            });
            let cached = packument("pkg", "http://old-nora.example/npm/pkg/-/pkg-1.0.0.tgz");
            ctx.state
                .storage
                .put(&super::upstream_packument_key("pkg"), cached.as_bytes())
                .await
                .unwrap();
            let (status, body) = get(&ctx, "/npm/pkg").await;
            if serve_stale {
                assert_eq!(status, StatusCode::OK);
                let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert!(doc["versions"].as_object().unwrap().is_empty(), "{doc}");
            } else {
                assert_eq!(status, StatusCode::BAD_GATEWAY);
            }
        }
    }

    /// An upstream whose credential is the userinfo of its URL: the link it names is asked with
    /// the same userinfo, which is the upstream's credential (sent as Basic).
    #[tokio::test]
    async fn the_credential_in_the_upstream_url_goes_with_its_link() {
        let gitlab = MockServer::start().await;
        let basic = format!(
            "Basic {}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "u:p")
        );
        let link = format!(
            "{}/api/v4/projects/7/packages/npm/pkg/-/pkg-1.0.0.tgz",
            gitlab.uri()
        );
        Mock::given(method("GET"))
            .and(path("/api/v4/packages/npm/pkg"))
            .and(header("authorization", basic.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument("pkg", &link)))
            .mount(&gitlab)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/7/packages/npm/pkg/-/pkg-1.0.0.tgz"))
            .and(header("authorization", basic.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"GITLAB-TGZ".to_vec()))
            .mount(&gitlab)
            .await;
        let upstream = gitlab.uri().replacen("http://", "http://u:p@", 1) + "/api/v4/packages/npm";
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(upstream);
            cfg.server.public_url = Some(NORA.to_string());
        });
        let (status, body) = get(&ctx, "/npm/pkg").await;
        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            doc["versions"]["1.0.0"]["dist"]["tarball"],
            "http://nora.example/npm/pkg/-/pkg-1.0.0.tgz"
        );
        settle().await;
        let (status, body) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
        assert_eq!(
            (status, body.as_slice()),
            (StatusCode::OK, b"GITLAB-TGZ".as_slice())
        );
    }

    /// Which links on the upstream's origin are its own: an absolute link as a URL parser writes
    /// it, without userinfo, query or fragment, on the upstream's scheme, host and port (the
    /// credential goes there with it), naming this package and one of its tarballs. Anything
    /// else is left out.
    #[test]
    fn which_links_on_the_upstream_origin_are_its_own() {
        let upstream = "https://gitlab.example/api/v4/packages/npm";
        let project = "/api/v4/projects/7/packages/npm";
        let doc = |link: &str| packument(NAME, link).into_bytes();
        let mut wrong = Vec::new();
        for (link, served) in [
            (format!("https://gitlab.example{PROJECT}"), Some(ON_NORA)),
            (format!("http://gitlab.example{PROJECT}"), None),
            (
                format!("https://gitlab.example{project}/@vendor%2fpkg/-/@vendor/pkg-1.0.0.tgz"),
                Some(ON_NORA),
            ),
            (
                format!("https://gitlab.example{project}/@vendor/pkg/-/@vendor%2Fpkg-1.0.0.tgz"),
                Some("http://nora.example/npm/@vendor/pkg/-/@vendor%2Fpkg-1.0.0.tgz"),
            ),
            (format!("https://gitlab.example:8443{PROJECT}"), None),
            (
                format!("https://gitlab.example.evil.example{PROJECT}"),
                None,
            ),
            (format!("https://user@gitlab.example{PROJECT}"), None),
            (format!("https://gitlab.example{PROJECT}?x=1"), None),
            (format!("https://gitlab.example{PROJECT}#x"), None),
            (format!("//gitlab.example{PROJECT}"), None),
            (format!(" https://gitlab.example{PROJECT}"), None),
            (format!("HTTPS://gitlab.example{PROJECT}"), None),
            (
                format!("https://gitlab.example{project}/other/-/other-1.0.0.tgz"),
                None,
            ),
            (
                format!("https://gitlab.example{project}/other/-/@vendor/pkg-1.0.0.tgz"),
                None,
            ),
            (
                format!("https://gitlab.example{project}/@vendor/pkgx/-/@vendor/pkg-1.0.0.tgz"),
                None,
            ),
            (
                format!("https://gitlab.example{project}/@vendor/pkg/-/other-1.0.0.tgz"),
                None,
            ),
            (
                format!("https://gitlab.example{project}/@vendor/pkg/-/"),
                None,
            ),
            (
                format!("https://gitlab.example{project}/@vendor/pkg/-/README.md"),
                None,
            ),
            (
                format!(
                    "https://gitlab.example{project}/@vendor/pkg/-/../../@vendor/pkg-1.0.0.tgz"
                ),
                None,
            ),
            (
                format!(
                    "https://gitlab.example{project}/@vendor/pkg/-/%2e%2e/@vendor/pkg-1.0.0.tgz"
                ),
                None,
            ),
            (format!("https://gitlab.example{project}/@vendor/pkg"), None),
            (format!("ftp://gitlab.example{PROJECT}"), None),
        ] {
            let out = rewrite_tarball_urls(&doc(&link), NORA, upstream).unwrap();
            let out: serde_json::Value = serde_json::from_slice(&out).unwrap();
            let got = out["versions"]["1.0.0"]["dist"]["tarball"].as_str();
            if got != served {
                wrong.push(format!("{link}: {got:?}, expected {served:?}"));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// A path whose last segments only end like the package — a longer name before `@`, or an
    /// encoded `@` after one — holds another package: its link is left out.
    #[test]
    fn a_holder_that_only_ends_like_the_package_is_not_its_own() {
        let upstream = "https://gitlab.example/api/v4/packages/npm";
        for link in [
            "https://gitlab.example/api/v4/projects/7/packages/npm/evil@vendor/pkg/-/@vendor/pkg-1.0.0.tgz",
            "https://gitlab.example/api/v4/projects/7/packages/npm/x%40vendor/pkg/-/@vendor/pkg-1.0.0.tgz",
            "https://gitlab.example/api/v4/projects/7/packages/npm/x%2F@vendor/pkg/-/@vendor/pkg-1.0.0.tgz",
        ] {
            let out =
                rewrite_tarball_urls(packument(NAME, link).as_bytes(), NORA, upstream).unwrap();
            let out: serde_json::Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(
                out["versions"]["1.0.0"]["dist"]["tarball"].as_str(),
                None,
                "{link}"
            );
        }
    }

    /// An upstream with a credential in its URL and no path of its own: a link on its origin is
    /// still fetched exactly as the packument names it, with that credential, never at
    /// `<upstream>/<path>`.
    #[tokio::test]
    async fn an_upstream_with_userinfo_and_no_path_fetches_from_its_link() {
        let gitlab = MockServer::start().await;
        let basic = format!(
            "Basic {}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "u:p")
        );
        let link = format!(
            "{}/api/v4/projects/7/packages/npm/pkg/-/pkg-1.0.0.tgz",
            gitlab.uri()
        );
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument("pkg", &link)))
            .mount(&gitlab)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/7/packages/npm/pkg/-/pkg-1.0.0.tgz"))
            .and(header("authorization", basic.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"GITLAB-TGZ".to_vec()))
            .mount(&gitlab)
            .await;
        Mock::given(method("GET"))
            .and(path("/pkg/-/pkg-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ELSEWHERE".to_vec()))
            .mount(&gitlab)
            .await;
        let upstream = gitlab.uri().replacen("http://", "http://u:p@", 1);
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(upstream);
            cfg.server.public_url = Some(NORA.to_string());
        });
        let (status, body) = get(&ctx, "/npm/pkg").await;
        assert_eq!(status, StatusCode::OK);
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            doc["versions"]["1.0.0"]["dist"]["tarball"],
            "http://nora.example/npm/pkg/-/pkg-1.0.0.tgz"
        );
        settle().await;
        let (status, body) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
        assert_eq!(
            (status, String::from_utf8_lossy(&body).into_owned()),
            (StatusCode::OK, "GITLAB-TGZ".to_string())
        );
    }

    /// A copy an older release cached under the legacy key, not delivered by the scope's owner,
    /// does not say where to fetch either: the owner's own listing does, with its token.
    #[tokio::test]
    async fn a_legacy_copy_the_owner_did_not_deliver_does_not_say_where_to_fetch() {
        let public = open_server().await;
        let gitlab = gitlab(MockServer::uri).await;
        let squatted = "/api/v4/projects/666/packages/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz";
        Mock::given(method("GET"))
            .and(path(squatted))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SQUATTED".to_vec()))
            .mount(&gitlab)
            .await;
        let ctx = context_with(&public.uri(), &instance(&gitlab), 3600, false);
        let cached = packument(NAME, &format!("{}{squatted}", gitlab.uri()));
        ctx.state
            .storage
            .put(&super::legacy_cache_key(NAME), cached.as_bytes())
            .await
            .unwrap();
        let (status, body) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
        assert_eq!(
            (status, body.as_slice()),
            (StatusCode::OK, b"GITLAB-TGZ".as_slice()),
            "{}",
            String::from_utf8_lossy(&body)
        );
        let asked: Vec<String> = log(&gitlab).await.into_iter().map(|(p, _)| p).collect();
        assert!(!asked.iter().any(|p| p == squatted), "{asked:?}");
    }

    /// The public upstream at the root of the owner's host is another upstream: a copy it
    /// delivered (its provenance names `npm:http://host:port`, a prefix of the owner's
    /// `…/api/v4/packages/npm`) is not the owner's.
    #[tokio::test]
    async fn a_copy_from_an_upstream_whose_url_prefixes_the_owners_is_not_trusted() {
        let gitlab = gitlab(MockServer::uri).await;
        let squatted = "/api/v4/projects/666/packages/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz";
        Mock::given(method("GET"))
            .and(path(squatted))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SQUATTED".to_vec()))
            .mount(&gitlab)
            .await;
        let ctx = context_with(&gitlab.uri(), &instance(&gitlab), 3600, false);
        let cached = packument(NAME, &format!("{}{squatted}", gitlab.uri()));
        super::put_with_origin(
            &ctx.state.storage,
            &super::upstream_packument_key(NAME),
            cached.as_bytes(),
            &super::origin_of(&gitlab.uri()),
        )
        .await
        .unwrap();
        let (status, body) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
        assert_eq!(
            (status, body.as_slice()),
            (StatusCode::OK, b"GITLAB-TGZ".as_slice()),
            "{}",
            String::from_utf8_lossy(&body)
        );
        let asked: Vec<String> = log(&gitlab).await.into_iter().map(|(p, _)| p).collect();
        assert!(!asked.iter().any(|p| p == squatted), "{asked:?}");
    }
}

/// A tarball is fetched only for a version the upstream's trusted packument lists, from the link
/// it names. A redirect on the upstream's origin is followed with the upstream's credential; one
/// to another origin (a registry keeping its files on a storage host) is followed without it, on
/// that hop and every later one. A version the packument does not list, even once fetched again,
/// is not asked for at all.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tarball_redirects {
    use crate::config::{NpmConfig, NpmProxyEntry};
    use crate::secrets::ProtectedString;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{any, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TARBALL: &str = "/pkg/-/pkg-1.0.0.tgz";
    const SCOPED: &str = "/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz";

    /// 200 to anything, so only its request log tells.
    async fn open_server() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ELSEWHERE".to_vec()))
            .mount(&server)
            .await;
        server
    }

    fn packument(name: &str, link: &str) -> String {
        serde_json::json!({
            "name": name,
            "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": {
                "name": name, "version": "1.0.0", "dist": { "tarball": link },
            } },
            "time": { "1.0.0": "2020-01-02T00:00:00.000Z" },
        })
        .to_string()
    }

    /// A registry at the root of its origin with `pkg` and `@vendor/pkg` 1.0.0, whose tarball
    /// paths answer what `answer` makes of the registry.
    async fn registry(answer: impl Fn(&MockServer) -> ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        for (name, file) in [("pkg", TARBALL), ("@vendor/pkg", SCOPED)] {
            Mock::given(method("GET"))
                .and(path(format!("/{name}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_string(packument(name, &format!("{}{file}", server.uri()))),
                )
                .mount(&server)
                .await;
            let answer = answer(&server);
            Mock::given(method("GET"))
                .and(path(file))
                .respond_with(answer)
                .mount(&server)
                .await;
        }
        server
    }

    fn redirect(to: &str) -> ResponseTemplate {
        ResponseTemplate::new(302).insert_header("location", to)
    }

    fn port_of(server: &MockServer) -> u16 {
        reqwest::Url::parse(&server.uri()).unwrap().port().unwrap()
    }

    /// The default upstream `public` (its URL may carry userinfo) and `@vendor`'s `private`,
    /// with a Bearer token. The upstream's circuit breaker is on, at its default threshold.
    fn context(public: &str, private: &str) -> TestContext {
        let mut npm: NpmConfig = toml::from_str(&format!(
            r#"proxies = ["{public}", {{ url = "{private}", scopes = ["@vendor"], auth_bearer_env = "NORA_NPM_VENDOR_TOKEN" }}]"#
        ))
        .unwrap();
        if let NpmProxyEntry::Full(p) = &mut npm.proxies[1] {
            p.auth_bearer = Some(ProtectedString::from("vendor-tok"));
        }
        let proxies = npm.proxies;
        create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.server.public_url = Some("http://nora.example".to_string());
            cfg.circuit_breaker.enabled = true;
        })
    }

    fn with_userinfo(server: &MockServer) -> String {
        server
            .uri()
            .replacen("http://", "http://nora-user:s3cret@", 1)
    }

    async fn get(ctx: &TestContext, uri: &str) -> (StatusCode, Vec<u8>) {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        let status = resp.status();
        (status, body_bytes(resp).await.to_vec())
    }

    /// Requests a server received, by path, with whether each carried a credential.
    async fn asked(server: &MockServer) -> Vec<(String, bool)> {
        let requests = server.received_requests().await.unwrap();
        requests
            .iter()
            .map(|r| {
                (
                    r.url.path().to_string(),
                    r.headers.contains_key("authorization"),
                )
            })
            .collect()
    }

    async fn asks_of(server: &MockServer, file: &str) -> usize {
        asked(server)
            .await
            .iter()
            .filter(|(p, _)| p == file)
            .count()
    }

    /// Tarballs and their digests NORA keeps.
    async fn cached_tarballs(ctx: &TestContext) -> Vec<String> {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let keys = ctx.state.storage.list("npm/").await.unwrap();
        keys.into_iter().filter(|k| k.contains(".tgz")).collect()
    }

    /// The tarballs cached once the background write lands, within a deadline: a full test run
    /// can delay the spawned write past any fixed wait.
    async fn cached_tarballs_eventually(ctx: &TestContext) -> Vec<String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let cached = cached_tarballs(ctx).await;
            if !cached.is_empty() || std::time::Instant::now() > deadline {
                return cached;
            }
        }
    }

    /// A file storage on another origin: `/a` forwards to `/b` on the same host, which answers.
    async fn storage_host() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/a"))
            .respond_with(redirect(&format!("{}/b", server.uri())))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/b"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"STORED-TGZ".to_vec()))
            .mount(&server)
            .await;
        server
    }

    /// A listed version whose upstream keeps the file on a storage host: downloaded from there,
    /// and no hop on the storage host — the first or the one after — gets the upstream's
    /// credential, the userinfo of the default upstream or the scope's token alike.
    #[tokio::test]
    async fn a_listed_tarball_on_another_origin_is_fetched_without_the_credential() {
        for (uri, file) in [
            ("/npm/pkg/-/pkg-1.0.0.tgz", TARBALL),
            ("/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz", SCOPED),
        ] {
            let storage = storage_host().await;
            let to = format!("{}/a", storage.uri());
            let upstream = registry(|_| redirect(&to)).await;
            let ctx = context(&with_userinfo(&upstream), &upstream.uri());
            let (status, body) = get(&ctx, uri).await;
            assert_eq!(
                (status, String::from_utf8_lossy(&body).into_owned()),
                (StatusCode::OK, "STORED-TGZ".to_string()),
                "{uri}"
            );
            let tarball_asks: Vec<_> = asked(&upstream)
                .await
                .into_iter()
                .filter(|(p, _)| p == file)
                .collect();
            assert_eq!(tarball_asks, vec![(file.to_string(), true)], "{uri}");
            assert_eq!(
                asked(&storage).await,
                vec![("/a".to_string(), false), ("/b".to_string(), false)],
                "{uri}"
            );
            assert!(!cached_tarballs_eventually(&ctx).await.is_empty(), "{uri}");
        }
    }

    /// The same host on another port, or the same port under another scheme, is another origin:
    /// the credential stays behind there too.
    #[tokio::test]
    async fn another_host_or_port_is_another_origin_for_the_credential() {
        let storage = storage_host().await;
        let port = port_of(&storage);
        for to in [
            format!("http://localhost:{port}/a"),
            format!("http://127.0.0.1:{port}/a"),
        ] {
            let upstream = registry(|_| redirect(&to)).await;
            let ctx = context(&with_userinfo(&upstream), &upstream.uri());
            let (status, _) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
            assert_eq!(status, StatusCode::OK, "{to}");
        }
        assert!(
            asked(&storage)
                .await
                .iter()
                .all(|(_, credential)| !credential),
            "{:?}",
            asked(&storage).await
        );
    }

    /// On the upstream's own origin the credential goes along, relative Location or absolute.
    #[tokio::test]
    async fn a_redirect_on_the_same_origin_keeps_the_credential() {
        for to in [
            "/files/pkg-1.0.0.tgz".to_string(),
            "http://127.0.0.1:{port}/files/pkg-1.0.0.tgz".to_string(),
        ] {
            let upstream =
                registry(|server| redirect(&to.replace("{port}", &port_of(server).to_string())))
                    .await;
            Mock::given(method("GET"))
                .and(path("/files/pkg-1.0.0.tgz"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(b"UPSTREAM-TGZ".to_vec()))
                .mount(&upstream)
                .await;
            let ctx = context(&with_userinfo(&upstream), &open_server().await.uri());
            let (status, body) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
            assert_eq!(
                (status, body.as_slice()),
                (StatusCode::OK, b"UPSTREAM-TGZ".as_slice()),
                "{to}"
            );
            let hop: Vec<_> = asked(&upstream)
                .await
                .into_iter()
                .filter(|(p, _)| p == "/files/pkg-1.0.0.tgz")
                .collect();
            assert_eq!(
                hop,
                vec![("/files/pkg-1.0.0.tgz".to_string(), true)],
                "{to}"
            );
        }
    }

    /// A walk on the origin is cut off after ten hops, as any chain of a download is.
    #[tokio::test]
    async fn a_walk_on_the_origin_ends() {
        let upstream = registry(|_| redirect(TARBALL)).await;
        let ctx = context(&upstream.uri(), &open_server().await.uri());
        let (status, _) = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz"),
        )
        .await
        .expect("a redirect loop never ends");
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(asks_of(&upstream, TARBALL).await <= 2 * 11);
    }

    /// A version the packument does not list is not asked for, wherever its path would lead —
    /// GitLab forwards it to the public registry (302, measured on 19.5): 404, the packument
    /// asked once more for a version published since, nothing cached. The breaker sees no
    /// failure, however often it is asked.
    #[tokio::test]
    async fn a_version_the_packument_does_not_list_is_not_asked_for() {
        let public = open_server().await;
        let gitlab =
            registry(|_| ResponseTemplate::new(200).set_body_bytes(b"GITLAB-TGZ".to_vec())).await;
        Mock::given(any())
            .respond_with(redirect(&format!("{}/forwarded", public.uri())))
            .mount(&gitlab)
            .await;
        let ctx = context(&public.uri(), &gitlab.uri());
        let downloads = crate::config::CircuitBreakerConfig::default().failure_threshold + 1;
        for _ in 0..downloads {
            let (status, _) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-9.9.9.tgz").await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
        let gitlab_asks = asked(&gitlab).await;
        assert!(
            gitlab_asks.iter().all(|(p, _)| p == "/@vendor/pkg"),
            "{gitlab_asks:?}"
        );
        assert!(
            gitlab_asks.len() <= 2 * downloads as usize,
            "{gitlab_asks:?}"
        );
        assert!(
            asked(&public).await.is_empty(),
            "{:?}",
            asked(&public).await
        );
        assert!(cached_tarballs(&ctx).await.is_empty());
        // The breaker is closed: the listed version still downloads.
        let (status, _) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
        assert_eq!(status, StatusCode::OK);
    }

    /// A version published after the packument was cached is found in the packument fetched
    /// again, once.
    #[tokio::test]
    async fn a_version_published_since_the_packument_was_cached_is_found() {
        let upstream = MockServer::start().await;
        let link = |v: &str| format!("{}/pkg/-/pkg-{v}.tgz", upstream.uri());
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(packument("pkg", &link("1.0.0"))),
            )
            .up_to_n_times(1)
            .mount(&upstream)
            .await;
        let later = serde_json::json!({
            "name": "pkg",
            "dist-tags": { "latest": "1.1.0" },
            "versions": {
                "1.0.0": { "name": "pkg", "version": "1.0.0", "dist": { "tarball": link("1.0.0") } },
                "1.1.0": { "name": "pkg", "version": "1.1.0", "dist": { "tarball": link("1.1.0") } },
            },
            "time": { "1.0.0": "2020-01-02T00:00:00.000Z", "1.1.0": "2020-02-02T00:00:00.000Z" },
        });
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_string(later.to_string()))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/pkg/-/pkg-1.1.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"NEW-TGZ".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = context(&upstream.uri(), &open_server().await.uri());
        let (status, _) = get(&ctx, "/npm/pkg").await;
        assert_eq!(status, StatusCode::OK);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let (status, body) = get(&ctx, "/npm/pkg/-/pkg-1.1.0.tgz").await;
        assert_eq!(
            (status, body.as_slice()),
            (StatusCode::OK, b"NEW-TGZ".as_slice())
        );
        let packument_asks = asked(&upstream)
            .await
            .iter()
            .filter(|(p, _)| p == "/pkg")
            .count();
        assert_eq!(packument_asks, 2);
    }

    /// GitHub Packages' tarball path (`download/<@scope/name>/<version>/<sha1>`), listed and
    /// forwarded to a storage host: downloaded from there without the scope's token.
    #[tokio::test]
    async fn a_github_packages_tarball_on_a_storage_host_is_fetched_without_the_token() {
        const SHA: &str = "04fef883382f5a7c9b9ac2015dcc419009e2a858";
        let storage = storage_host().await;
        let ghp = MockServer::start().await;
        let file = format!("/download/@vendor/pkg/1.0.0/{SHA}");
        Mock::given(method("GET"))
            .and(path("/@vendor/pkg"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(packument("@vendor/pkg", &format!("{}{file}", ghp.uri()))),
            )
            .mount(&ghp)
            .await;
        Mock::given(method("GET"))
            .and(path(file.as_str()))
            .respond_with(redirect(&format!("{}/a", storage.uri())))
            .mount(&ghp)
            .await;
        let ctx = context(&open_server().await.uri(), &ghp.uri());
        let (status, body) = get(&ctx, &format!("/npm{file}")).await;
        assert_eq!(
            (status, String::from_utf8_lossy(&body).into_owned()),
            (StatusCode::OK, "STORED-TGZ".to_string())
        );
        assert_eq!(
            asked(&storage).await,
            vec![("/a".to_string(), false), ("/b".to_string(), false)]
        );
        let tarball_asks: Vec<_> = asked(&ghp)
            .await
            .into_iter()
            .filter(|(p, _)| *p == file)
            .collect();
        assert_eq!(tarball_asks, vec![(file.clone(), true)]);
    }

    /// Invariant 2: the whole redirect chain of a tarball download is bounded (≤10 hops) → 502.
    /// 8 hops on the upstream's origin, one to a storage host, 8 more there: 17 hops in all.
    #[tokio::test]
    async fn a_chain_longer_than_ten_hops_across_origins_is_502() {
        let storage = MockServer::start().await;
        for i in 0..8 {
            Mock::given(method("GET"))
                .and(path(format!("/h{i}")))
                .respond_with(redirect(&format!("{}/h{}", storage.uri(), i + 1)))
                .mount(&storage)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/h8"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"FAR-TGZ".to_vec()))
            .mount(&storage)
            .await;
        let s = storage.uri();
        let upstream = registry(|_| redirect("/r1")).await;
        for i in 1..8 {
            Mock::given(method("GET"))
                .and(path(format!("/r{i}")))
                .respond_with(redirect(&format!("/r{}", i + 1)))
                .mount(&upstream)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/r8"))
            .respond_with(redirect(&format!("{s}/h0")))
            .mount(&upstream)
            .await;
        let ctx = context(&upstream.uri(), &open_server().await.uri());
        let (status, body) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
        assert_eq!(
            (status, String::from_utf8_lossy(&body).into_owned()),
            (StatusCode::BAD_GATEWAY, String::new()),
            "17 redirects were followed"
        );
    }

    /// Invariant 2: the hops on the storage host count too — a chain that goes on there past ten
    /// hops ends in 502, it is not walked to its end.
    #[tokio::test]
    async fn a_walk_on_the_storage_host_ends() {
        let storage = MockServer::start().await;
        for i in 0..30 {
            Mock::given(method("GET"))
                .and(path(format!("/h{i}")))
                .respond_with(redirect(&format!("{}/h{}", storage.uri(), i + 1)))
                .mount(&storage)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/h30"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"FAR-TGZ".to_vec()))
            .mount(&storage)
            .await;
        let to = format!("{}/h0", storage.uri());
        let upstream = registry(|_| redirect(&to)).await;
        let ctx = context(&upstream.uri(), &open_server().await.uri());
        let (status, _) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    /// A download whose first `on` redirects stay on the upstream's origin (`/r1`…) and whose
    /// next `off` go to a storage host (`/h1`…), the last URL answering the file: what NORA
    /// answers, with the requests each server received.
    async fn walk(on: usize, off: usize) -> (StatusCode, Vec<(String, bool)>, Vec<(String, bool)>) {
        let storage = MockServer::start().await;
        let s = storage.uri();
        let first = match (on, off) {
            (0, 0) => ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec()),
            (0, _) => redirect(&format!("{s}/h1")),
            _ => redirect("/r1"),
        };
        let upstream = registry(|_| first.clone()).await;
        for i in 1..=on {
            let answer = if i < on {
                redirect(&format!("/r{}", i + 1))
            } else if off > 0 {
                redirect(&format!("{s}/h1"))
            } else {
                ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec())
            };
            Mock::given(method("GET"))
                .and(path(format!("/r{i}")))
                .respond_with(answer)
                .mount(&upstream)
                .await;
        }
        for j in 1..=off {
            let answer = if j < off {
                redirect(&format!("{s}/h{}", j + 1))
            } else {
                ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec())
            };
            Mock::given(method("GET"))
                .and(path(format!("/h{j}")))
                .respond_with(answer)
                .mount(&storage)
                .await;
        }
        let ctx = context(&with_userinfo(&upstream), &open_server().await.uri());
        let (status, _) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
        (status, asked(&upstream).await, asked(&storage).await)
    }

    /// Invariant 2: ten redirects of one download pass and the eleventh is 502, however the
    /// chain is split between the upstream's origin and a storage host; the credential goes on
    /// each hop on the origin and on none on the storage host.
    #[tokio::test]
    async fn ten_redirects_pass_and_the_eleventh_is_502_across_origins() {
        for (on, off, expected) in [
            (10, 0, StatusCode::OK),
            (11, 0, StatusCode::BAD_GATEWAY),
            (0, 10, StatusCode::OK),
            (0, 11, StatusCode::BAD_GATEWAY),
            (4, 6, StatusCode::OK),
            (4, 7, StatusCode::BAD_GATEWAY),
            (9, 1, StatusCode::OK),
            (10, 1, StatusCode::BAD_GATEWAY),
        ] {
            let (status, upstream, storage) = walk(on, off).await;
            assert_eq!(status, expected, "{on} on the origin, {off} off it");
            let hops: Vec<_> = upstream
                .iter()
                .filter(|(p, _)| p.starts_with("/r"))
                .collect();
            assert!(hops.iter().all(|(_, credential)| *credential), "{hops:?}");
            assert!(
                storage.iter().all(|(_, credential)| !credential),
                "{storage:?}"
            );
            if expected == StatusCode::BAD_GATEWAY {
                // The eleventh redirect is not followed.
                assert_eq!(
                    hops.len() + storage.len(),
                    10,
                    "{on} {off}: {upstream:?} {storage:?}"
                );
            }
        }
    }

    /// A chain that leaves the upstream's origin and comes back to it goes on without the
    /// credential: the hop back is asked on behalf of the storage host's answer.
    #[tokio::test]
    async fn a_hop_back_to_the_origin_goes_without_the_credential() {
        for (uri, file) in [
            ("/npm/pkg/-/pkg-1.0.0.tgz", TARBALL),
            ("/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz", SCOPED),
        ] {
            let storage = MockServer::start().await;
            let upstream = registry(|_| redirect(&format!("{}/a", storage.uri()))).await;
            Mock::given(method("GET"))
                .and(path("/a"))
                .respond_with(redirect(&format!("{}/back", upstream.uri())))
                .mount(&storage)
                .await;
            Mock::given(method("GET"))
                .and(path("/back"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(b"BACK-TGZ".to_vec()))
                .mount(&upstream)
                .await;
            let ctx = context(&with_userinfo(&upstream), &upstream.uri());
            let (status, body) = get(&ctx, uri).await;
            assert_eq!(
                (status, body.as_slice()),
                (StatusCode::OK, b"BACK-TGZ".as_slice()),
                "{uri}"
            );
            let hops: Vec<_> = asked(&upstream)
                .await
                .into_iter()
                .filter(|(p, _)| p == file || p == "/back")
                .collect();
            assert_eq!(
                hops,
                vec![(file.to_string(), true), ("/back".to_string(), false)],
                "{uri}"
            );
        }
    }

    /// An upstream that has no packument for the package lists no version of it: the tarball
    /// is not asked for, 404, nothing cached.
    #[tokio::test]
    async fn a_package_without_a_packument_upstream_is_not_asked_for_a_tarball() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg/-/pkg-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"UNLISTED".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = context(&upstream.uri(), &open_server().await.uri());
        let (status, _) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(asks_of(&upstream, "/pkg/-/pkg-1.0.0.tgz").await, 0);
        assert!(cached_tarballs(&ctx).await.is_empty());
    }
}

/// An upstream bound to a scope answers that scope's metadata from its own origin only: a
/// redirect off it is not followed — 502, nothing asked of the other origin, nothing cached —
/// for a packument, a version manifest, any other metadata path and the packument a tarball
/// download reads. The default upstream follows redirects as before.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod scoped_metadata_origin {
    use crate::config::{NpmConfig, NpmProxyEntry};
    use crate::secrets::ProtectedString;
    use crate::test_helpers::{create_test_context_with_config, send, TestContext};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A server that sends every request to `to` + its path.
    async fn redirecting(to: &str) -> MockServer {
        let server = MockServer::start().await;
        let to = to.to_string();
        Mock::given(any())
            .respond_with(move |req: &wiremock::Request| {
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{to}{}", req.url.path()).as_str())
            })
            .mount(&server)
            .await;
        server
    }

    /// A server that answers anything with a packument listing `@vendor/pkg@1.0.0` and `pkg`'s.
    async fn elsewhere() -> MockServer {
        let server = MockServer::start().await;
        let doc = |name: &str| {
            serde_json::json!({
                "name": name,
                "versions": {"1.0.0": {"name": name, "version": "1.0.0", "dist": {}}},
                "dist-tags": {"latest": "1.0.0"},
            })
        };
        Mock::given(any())
            .respond_with(move |req: &wiremock::Request| {
                let name = if req.url.path().contains("@vendor") {
                    "@vendor/pkg"
                } else {
                    "pkg"
                };
                ResponseTemplate::new(200).set_body_json(doc(name))
            })
            .mount(&server)
            .await;
        server
    }

    fn context(public: &str, private: &str) -> TestContext {
        let mut npm: NpmConfig = toml::from_str(&format!(
            r#"proxies = ["{public}", {{ url = "{private}", scopes = ["@vendor"], auth_bearer_env = "NORA_NPM_VENDOR_TOKEN" }}]"#
        ))
        .unwrap();
        if let NpmProxyEntry::Full(p) = &mut npm.proxies[1] {
            p.auth_bearer = Some(ProtectedString::from("vendor-tok"));
        }
        let proxies = npm.proxies;
        create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.server.trust_upstream_dates = true;
        })
    }

    #[tokio::test]
    async fn a_scoped_upstream_redirecting_metadata_elsewhere_is_502() {
        let foreign = elsewhere().await;
        let private = redirecting(&foreign.uri()).await;
        let public = MockServer::start().await;
        let ctx = context(&public.uri(), &private.uri());
        let mut wrong = Vec::new();
        for (uri, expected) in [
            ("/npm/@vendor%2fpkg", StatusCode::BAD_GATEWAY),
            ("/npm/@vendor/pkg", StatusCode::BAD_GATEWAY),
            ("/npm/@vendor/pkg/1.0.0", StatusCode::BAD_GATEWAY),
            ("/npm/@vendor/pkg/a/b", StatusCode::BAD_GATEWAY),
            (
                "/npm/-/package/@vendor/pkg/dist-tags",
                StatusCode::BAD_GATEWAY,
            ),
            ("/npm/@vendor/pkg/-/pkg-1.0.0.tgz", StatusCode::BAD_GATEWAY),
        ] {
            let status = send(&ctx.app, Method::GET, uri, "").await.status();
            if status != expected {
                wrong.push(format!("{uri}: {status}, expected {expected}"));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
        let asked = foreign.received_requests().await.unwrap();
        assert!(asked.is_empty(), "the other origin was asked: {asked:?}");
        assert!(public.received_requests().await.unwrap().is_empty());
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let written = ctx.state.storage.list("npm/").await.unwrap();
        assert!(written.is_empty(), "cached: {written:?}");
    }

    /// A scoped upstream that answers its packument after `hops` redirects on its own origin
    /// (`/hop/1/…`, `/hop/2/…`, …).
    async fn walking(hops: usize) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(move |req: &wiremock::Request| {
                let p = req.url.path();
                let (n, rest) = match p.strip_prefix("/hop/").and_then(|r| r.split_once('/')) {
                    Some((n, rest)) => (n.parse::<usize>().unwrap(), format!("/{rest}")),
                    None => (0, p.to_string()),
                };
                if n < hops {
                    ResponseTemplate::new(302)
                        .insert_header("location", format!("/hop/{}{rest}", n + 1).as_str())
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "name": "@vendor/pkg",
                        "versions": {"1.0.0": {"name": "@vendor/pkg", "version": "1.0.0", "dist": {}}},
                        "dist-tags": {"latest": "1.0.0"},
                    }))
                }
            })
            .mount(&server)
            .await;
        server
    }

    /// On its own origin a scoped upstream's metadata follows ten redirects, each with the
    /// token, and the eleventh is 502.
    #[tokio::test]
    async fn a_scoped_upstreams_metadata_follows_ten_redirects_on_its_origin() {
        for (hops, expected) in [(10, StatusCode::OK), (11, StatusCode::BAD_GATEWAY)] {
            let private = walking(hops).await;
            let public = MockServer::start().await;
            let ctx = context(&public.uri(), &private.uri());
            let status = send(&ctx.app, Method::GET, "/npm/@vendor/pkg", "")
                .await
                .status();
            assert_eq!(status, expected, "{hops} redirects");
            let asked = private.received_requests().await.unwrap();
            assert!(
                asked
                    .iter()
                    .all(|r| r.headers.contains_key("authorization")),
                "{asked:?}"
            );
            if expected == StatusCode::OK {
                assert_eq!(asked.len(), hops + 1, "{asked:?}");
            }
        }
    }

    /// Control: the default upstream's redirect is followed, as before.
    #[tokio::test]
    async fn the_default_upstream_still_follows_a_redirect() {
        let foreign = elsewhere().await;
        let public = redirecting(&foreign.uri()).await;
        let private = MockServer::start().await;
        let ctx = context(&public.uri(), &private.uri());
        let status = send(&ctx.app, Method::GET, "/npm/pkg", "").await.status();
        assert_eq!(status, StatusCode::OK);
        assert!(!foreign.received_requests().await.unwrap().is_empty());
    }

    /// The audit endpoints name no scope, so they go to the default upstream — never one bound
    /// to a scope, whose redirects are not followed.
    #[test]
    fn the_audit_endpoints_go_to_the_default_upstream() {
        let ctx = context("https://registry.example", "https://vendor.example");
        for path in [
            "-/npm/v1/security/advisories/bulk",
            "-/npm/v1/security/audits/quick",
            "-/npm/v1/security/audits",
        ] {
            let upstream = ctx.state.config.npm.route(path).unwrap();
            assert_eq!(upstream.url, "https://registry.example", "{path}");
            assert!(!upstream.scoped, "{path}");
        }
        assert!(ctx.state.config.npm.route("@vendor/pkg").unwrap().scoped);
    }
}

/// `trust_upstream_dates` decides whose clock judges an upstream release: trusted, a direct
/// tarball download reads the date in the upstream's packument, which it caches first (#748) so
/// the date is there on the same request; untrusted, the date is NORA's own (when NORA cached
/// the packument), never the upstream's, and a download does not fetch the packument for a date.
/// Judged by the min-release-age verdict on the first download of a version.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod upstream_dates_gate {
    use crate::test_helpers::{create_test_context_with_config, send, TestContext};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// An upstream listing `agepkg` 1.0.0, released in 2020, and 2.0.0, released an hour ago.
    async fn upstream() -> MockServer {
        let server = MockServer::start().await;
        let fresh = (chrono::Utc::now() - chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let link = |v: &str| format!("{}/agepkg/-/agepkg-{v}.tgz", server.uri());
        let doc = serde_json::json!({
            "name": "agepkg",
            "versions": {
                "1.0.0": {"name": "agepkg", "version": "1.0.0", "dist": {"tarball": link("1.0.0")}},
                "2.0.0": {"name": "agepkg", "version": "2.0.0", "dist": {"tarball": link("2.0.0")}},
            },
            "time": {"1.0.0": "2020-01-15T10:30:00.000Z", "2.0.0": fresh},
            "dist-tags": {"latest": "2.0.0"},
        });
        Mock::given(method("GET"))
            .and(path("/agepkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc))
            .mount(&server)
            .await;
        for v in ["1.0.0", "2.0.0"] {
            Mock::given(method("GET"))
                .and(path(format!("/agepkg/-/agepkg-{v}.tgz")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec()))
                .mount(&server)
                .await;
        }
        server
    }

    /// What NORA holds of the package before its first tarball download.
    #[derive(Clone, Copy, Debug)]
    enum Before {
        Nothing,
        /// A client read the packument.
        Packument,
        /// A packument an older release cached.
        OlderCopy,
    }

    fn context(server: &MockServer, trust: bool) -> TestContext {
        let uri = server.uri();
        create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.server.trust_upstream_dates = trust;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
        })
    }

    #[tokio::test]
    async fn whose_clock_judges_a_release_follows_the_trust_in_upstream_dates() {
        let mut wrong = Vec::new();
        // (trust, what NORA holds before the download, version, verdict, why)
        for (trust, before, version, expected, why) in [
            (
                true,
                Before::Nothing,
                "1.0.0",
                StatusCode::OK,
                "upstream says 2020",
            ),
            (
                true,
                Before::Nothing,
                "2.0.0",
                StatusCode::FORBIDDEN,
                "upstream says an hour ago",
            ),
            (
                true,
                Before::Packument,
                "1.0.0",
                StatusCode::OK,
                "upstream says 2020, cached",
            ),
            (
                false,
                Before::Nothing,
                "2.0.0",
                StatusCode::OK,
                "no date of NORA's own yet",
            ),
            (
                false,
                Before::Packument,
                "1.0.0",
                StatusCode::FORBIDDEN,
                "NORA first saw it now",
            ),
            (
                false,
                Before::OlderCopy,
                "1.0.0",
                StatusCode::FORBIDDEN,
                "NORA wrote that copy now",
            ),
        ] {
            let server = upstream().await;
            let ctx = context(&server, trust);
            match before {
                Before::Nothing => {}
                Before::Packument => {
                    let resp = send(&ctx.app, Method::GET, "/npm/agepkg", "").await;
                    assert_eq!(resp.status(), StatusCode::OK);
                }
                // What an older release cached, with the upstream's dates and no first-seen
                // ledger: a release is as old as NORA's copy, not as the upstream says.
                Before::OlderCopy => {
                    let doc = serde_json::json!({
                        "name": "agepkg",
                        "versions": {"1.0.0": {"name": "agepkg", "version": "1.0.0", "dist": {}}},
                        "time": {"1.0.0": "2020-01-15T10:30:00.000Z"},
                    });
                    ctx.state
                        .storage
                        .put(
                            "npm/agepkg/metadata.json",
                            &serde_json::to_vec(&doc).unwrap(),
                        )
                        .await
                        .unwrap();
                }
            }
            let uri = format!("/npm/agepkg/-/agepkg-{version}.tgz");
            let status = send(&ctx.app, Method::GET, &uri, "").await.status();
            if status != expected {
                wrong.push(format!(
                    "trust {trust}, {before:?}, {version}: {status}, expected {expected} ({why})"
                ));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }
}
