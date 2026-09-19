// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! CPAN (Perl Archive) proxy registry.
//!
//! Caching proxy for www.cpan.org:
//!   GET /cpan/modules/02packages.details.txt.gz  — package index (mutable, TTL)
//!   GET /cpan/modules/03modlist.data.gz          — module list (mutable, TTL)
//!   GET /cpan/authors/01mailrc.txt.gz            — author dir (mutable, TTL)
//!   GET /cpan/authors/id/{path}                  — distribution (immutable)
//!
//! Client:
//!   cpanm --from http://nora:4000/cpan Module::Name

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::registry::{circuit_open_response, proxy_fetch, ProxyError};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::time::Duration;

const UPSTREAM_DEFAULT: &str = "https://www.cpan.org";

/// Prefix under which CPAN distributions are stored, and a suffix filter
/// (empty — CPAN distributions have multiple extensions: .tar.gz, .tar.bz2,
/// .zip, .tgz — so we let all through).
pub const INDEX_PATTERN: (&str, &str) = ("cpan/authors/id/", "");

pub fn routes() -> Router<AppState> {
    Router::new()
        // Index files (mutable, TTL-cached)
        .route(
            "/cpan/modules/02packages.details.txt.gz",
            get(packages_index),
        )
        .route("/cpan/modules/03modlist.data.gz", get(modlist_index))
        .route("/cpan/authors/01mailrc.txt.gz", get(mailrc_index))
        // Distribution files (immutable cache)
        .route("/cpan/authors/id/{*path}", get(distribution_proxy))
}

use crate::cache_ttl::is_within_ttl;

// ── Index endpoints (mutable, TTL cached) ─────────────────────────────

async fn packages_index(State(state): State<AppState>) -> Response {
    fetch_index(&state, "modules/02packages.details.txt.gz").await
}

async fn modlist_index(State(state): State<AppState>) -> Response {
    fetch_index(&state, "modules/03modlist.data.gz").await
}

async fn mailrc_index(State(state): State<AppState>) -> Response {
    fetch_index(&state, "authors/01mailrc.txt.gz").await
}

async fn fetch_index(state: &AppState, filename: &str) -> Response {
    let storage_key = format!("cpan/{}", filename);
    let cached_data = state.storage.get(&storage_key).await.ok();
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            if is_within_ttl(meta.modified, state.config.cpan.metadata_ttl) {
                state.metrics.record_download("cpan");
                state.metrics.record_cache_hit("cpan");
                state.activity.push(ActivityEntry::new(
                    ActionType::CacheHit,
                    filename.to_string(),
                    RegistryType::Cpan,
                    "CACHE",
                ));
                return with_index_response(data.to_vec());
            }
        }
    }

    let proxy_url = upstream_url(state);
    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), filename);

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.cpan.proxy_timeout),
        expose_opt(&state.config.cpan.proxy_auth),
        &state.circuit_breaker,
        RegistryType::Cpan,
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("cpan");
            state.metrics.record_cache_miss("cpan");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                filename.to_string(),
                RegistryType::Cpan,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "cpan", ""));
            state.spawn_cache("cpan", storage_key, Bytes::from(bytes.clone()));
            with_index_response(bytes)
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            if let Some(ref data) = cached_data {
                if state.config.cpan.serve_stale {
                    tracing::warn!(
                        registry = "cpan",
                        filename,
                        error = ?e,
                        "CPAN upstream error, serving stale index"
                    );
                    return (
                        StatusCode::OK,
                        [
                            (
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("application/gzip"),
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
                        data.to_vec(),
                    )
                        .into_response();
                }
            }
            tracing::debug!(filename, error = ?e, "CPAN upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Distribution download (immutable) ───────────────────────────────────

async fn distribution_proxy(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let dist_path = path.strip_prefix('/').unwrap_or(&path);
    if !is_valid_dist_path(dist_path) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!("cpan/authors/id/{}", dist_path);
    let filename = dist_path.rsplit('/').next().unwrap_or(dist_path);

    // Eager cache read — preserve data for serve-stale fallback
    let cached_data = state.storage.get(&storage_key).await.ok();

    // Curation check — extract name and optional version from dist filename
    let (dist_name, dist_version) = parse_dist_filename(filename);
    if let Some(response) = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        crate::curation::RegistryType::Cpan,
        dist_name,
        dist_version,
        None,
    ) {
        return response;
    }

    let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
        state.config.curation.cpan.quarantine.as_ref().or(state
            .config
            .curation
            .quarantine
            .as_ref()),
        state
            .config
            .curation
            .cpan
            .quarantine_ttl
            .as_deref()
            .or(state.config.curation.quarantine_ttl.as_deref()),
    );

    // Verified-cache fast path — serve with integrity guarantee
    if let Ok(outcome) = state.storage.get_verified(&storage_key).await {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Cpan,
            dist_name,
            dist_version,
            &data,
        ) {
            return response;
        }
        state.metrics.record_download("cpan");
        state.metrics.record_cache_hit("cpan");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            dist_path.to_string(),
            RegistryType::Cpan,
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "proxy", "", "cpan", ""));
        if let Some(resp) = crate::digest_quarantine::proxy_gate(
            &state.digest_store,
            "cpan",
            &data,
            &q_mode,
            q_secs,
            "cache",
        ) {
            return resp;
        }
        return with_binary(data.to_vec(), "application/octet-stream");
    }

    // Internal namespace check
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Cpan,
        dist_path,
    ) {
        return response;
    }

    // Fetch from upstream
    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/authors/id/{}",
        proxy_url.trim_end_matches('/'),
        dist_path
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.cpan.proxy_timeout),
        expose_opt(&state.config.cpan.proxy_auth),
        &state.circuit_breaker,
        RegistryType::Cpan,
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("cpan");
            state.metrics.record_cache_miss("cpan");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                dist_path.to_string(),
                RegistryType::Cpan,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "cpan", ""));
            state.spawn_cache_immutable("cpan", storage_key, Bytes::from(bytes.clone()));
            if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                &state.digest_store,
                "cpan",
                &bytes,
                &q_mode,
                q_secs,
                &url,
                None,
            ) {
                return resp;
            }
            with_binary(bytes, "application/octet-stream")
        }
        Err(ProxyError::NotFound) => {
            // Upstream returned 404 — serve cached copy if we have one
            if let Some(ref data) = cached_data {
                state.metrics.record_download("cpan");
                state.metrics.record_cache_hit("cpan");
                state.activity.push(ActivityEntry::new(
                    ActionType::CacheHit,
                    dist_path.to_string(),
                    RegistryType::Cpan,
                    "CACHE",
                ));
                return with_binary(data.to_vec(), "application/octet-stream");
            }
            StatusCode::NOT_FOUND.into_response()
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            if let Some(ref data) = cached_data {
                if state.config.cpan.serve_stale {
                    tracing::warn!(
                        registry = "cpan",
                        dist_path,
                        error = ?e,
                        "CPAN upstream error, serving stale distribution"
                    );
                    return (
                        StatusCode::OK,
                        [
                            (
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("application/octet-stream"),
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
                        data.to_vec(),
                    )
                        .into_response();
                }
            }
            tracing::debug!(error = ?e, "CPAN download error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────

fn upstream_url(state: &AppState) -> String {
    state
        .config
        .cpan
        .proxy
        .clone()
        .unwrap_or_else(|| UPSTREAM_DEFAULT.to_string())
}

fn with_binary(data: Vec<u8>, content_type: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
        ],
        data,
    )
        .into_response()
}

/// Response for mutable index files — prevents CDN/browser caching.
fn with_index_response(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/gzip"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=0, must-revalidate"),
            ),
        ],
        data,
    )
        .into_response()
}

/// Extract a distribution name and version from a CPAN archive filename.
///
/// Returns `None` for sidecars, non-archives, and legacy archives from which no
/// version can be inferred.
pub(crate) fn parse_dist_archive_filename(filename: &str) -> Option<(&str, &str)> {
    let mut stem = cpan_archive_stem(filename)?;

    // Port of the useful grouping heuristics from CPAN::DistnameInfo. Old CPAN
    // uploads predate the modern Dist-1.23 convention and use '_', '.', or no
    // separator at all. Keep this local and deterministic; UI browsing must not
    // depend on Perl being installed or on another upstream request.
    stem = stem.strip_suffix("-withoutworldwriteables").unwrap_or(stem);

    // An underscore following a non-digit is an old version separator (for
    // example finance-quote_0.18). An underscore between digits remains part
    // of a name/version, as in Task-Deprecations5_14-1.00 and 0_06.
    for (pos, _) in stem.rmatch_indices('_') {
        let before = &stem[..pos];
        let version = &stem[pos + 1..];
        if before
            .chars()
            .next_back()
            .is_some_and(|c| !c.is_ascii_digit())
            && looks_like_cpan_version(version)
        {
            return Some((normalize_cpan_dist(before), version));
        }
    }

    // Prefer the rightmost plausible hyphen. This naturally retains release
    // suffixes such as 1.0-TRIAL and numeric components inside dist names.
    for (pos, _) in stem.rmatch_indices('-') {
        let name = &stem[..pos];
        let version = &stem[pos + 1..];
        if !name.is_empty() && looks_like_cpan_version(version) {
            return Some((normalize_cpan_dist(name), version));
        }
    }

    // Very old releases also used Dist.1.23 or glued the version directly to
    // the final word (Tk800.025, File-Remove0.20).
    for (pos, _) in stem.rmatch_indices('.') {
        let name = &stem[..pos];
        let version = &stem[pos + 1..];
        if !name.is_empty()
            && name
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphabetic())
            && looks_like_cpan_version(version)
        {
            return Some((normalize_cpan_dist(name), version));
        }
    }
    for (pos, ch) in stem.char_indices().rev() {
        if !ch.is_ascii_digit() || pos == 0 {
            continue;
        }
        let name = &stem[..pos];
        if name
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphabetic())
        {
            return Some((normalize_cpan_dist(name), &stem[pos..]));
        }
    }

    None
}

fn cpan_archive_stem(filename: &str) -> Option<&str> {
    filename
        .strip_suffix(".tar.gz")
        .or_else(|| filename.strip_suffix(".tar.bz2"))
        .or_else(|| filename.strip_suffix(".tar.xz"))
        .or_else(|| filename.strip_suffix(".zip"))
        .or_else(|| filename.strip_suffix(".tgz"))
}

fn normalize_cpan_dist(name: &str) -> &str {
    name.strip_suffix(".pm").unwrap_or(name)
}

fn looks_like_cpan_version(value: &str) -> bool {
    let Some(first) = value.chars().next() else {
        return false;
    };
    if first.is_ascii_digit() {
        return true;
    }
    if matches!(first, 'v' | 'V') {
        return value[1..]
            .trim_start_matches('.')
            .starts_with(|c: char| c.is_ascii_digit());
    }

    // CPAN::DistnameInfo recognises several historical non-numeric forms.
    let lower = value.to_ascii_lowercase();
    ["alpha", "beta", "pre", "rc", "oct", "ye"]
        .iter()
        .any(|prefix| {
            lower
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
        })
        || (first.is_ascii_alphabetic() && value[1..].starts_with(|c: char| c.is_ascii_digit()))
}

fn parse_dist_filename(filename: &str) -> (&str, Option<&str>) {
    if let Some((name, version)) = parse_dist_archive_filename(filename) {
        (name, Some(version))
    } else {
        let stem = cpan_archive_stem(filename)
            .or_else(|| filename.strip_suffix(".meta"))
            .or_else(|| filename.strip_suffix(".readme"))
            .unwrap_or(filename);
        (stem, None)
    }
}

/// Validate distribution path: no path traversal, no null bytes.
fn is_valid_dist_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.contains('\0')
        && !path.contains("..")
        && path.chars().all(|c| c.is_ascii() && c != '\0')
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_dist_paths() {
        assert!(is_valid_dist_path("F/FO/FOO/Foo-Bar-1.0.tar.gz"));
        assert!(is_valid_dist_path("A/AB/ABIGAIL/Test-123.tar.gz"));
        assert!(is_valid_dist_path("M/MA/MALLEN/App-1.0.0.tar.gz"));
    }

    #[test]
    fn test_invalid_dist_paths() {
        assert!(!is_valid_dist_path(""));
        assert!(!is_valid_dist_path("../evil"));
        assert!(!is_valid_dist_path("foo/../../bar"));
        assert!(!is_valid_dist_path("foo\0bar"));
    }

    #[test]
    fn parses_distribution_archive_name_and_version() {
        assert_eq!(
            parse_dist_archive_filename("Module-Build-XSUtil-0.19.tar.gz"),
            Some(("Module-Build-XSUtil", "0.19"))
        );
        assert_eq!(
            parse_dist_archive_filename("Acme-123-Widget-v1.2-TRIAL.tar.xz"),
            Some(("Acme-123-Widget", "v1.2-TRIAL"))
        );
        // Representative legacy cases from CPAN::DistnameInfo's own suite.
        assert_eq!(
            parse_dist_archive_filename("finance-quote_0.18.tar.gz"),
            Some(("finance-quote", "0.18"))
        );
        assert_eq!(
            parse_dist_archive_filename("CGI.pm-2.34.tar.gz"),
            Some(("CGI", "2.34"))
        );
        assert_eq!(
            parse_dist_archive_filename("Tk800.025.tar.gz"),
            Some(("Tk", "800.025"))
        );
        assert_eq!(
            parse_dist_archive_filename("Dist-Zilla-2.100860-TRIAL.tar.gz"),
            Some(("Dist-Zilla", "2.100860-TRIAL"))
        );
        assert_eq!(
            parse_dist_archive_filename("Unicode-Collate-Standard-V3_1_1-0.1.tar.gz"),
            Some(("Unicode-Collate-Standard-V3_1_1", "0.1"))
        );
        assert_eq!(
            parse_dist_archive_filename("Bio-ASN1-EntrezGene-1.10-withoutworldwriteables.tar.gz"),
            Some(("Bio-ASN1-EntrezGene", "1.10"))
        );
        assert_eq!(parse_dist_archive_filename("CHECKSUMS"), None);
        assert_eq!(
            parse_dist_archive_filename("Module-Build-XSUtil-0.19.meta"),
            None
        );
        assert_eq!(
            parse_dist_filename("plain-name.tar.gz"),
            ("plain-name", None)
        );
    }
}

#[cfg(test)]
mod integration_tests {
    use crate::test_helpers::*;
    use axum::http::{header, Method, StatusCode};

    #[tokio::test]
    async fn test_cpan_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = false;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cpan/modules/02packages.details.txt.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_cpan_invalid_dist_path_returns_400() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
        });
        let resp = send(&ctx.app, Method::GET, "/cpan/authors/id/../evil", "").await;
        // Route won't match .. since axum rejects path traversal in wildcard
        assert!(resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_cpan_cached_dist_served() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
        });
        ctx.state
            .storage
            .put("cpan/authors/id/F/FO/FOO/Foo-1.0.tar.gz", b"dist-data")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cpan/authors/id/F/FO/FOO/Foo-1.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await.as_ref(), b"dist-data");
    }

    #[tokio::test]
    async fn test_cpan_ui_groups_cached_releases_by_distribution() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
        });
        for (filename, data) in [
            ("Module-Build-XSUtil-0.18.tar.gz", b"old".as_slice()),
            ("Module-Build-XSUtil-0.19.tar.gz", b"new".as_slice()),
            (
                "Module-Build-XSUtil-0.20-OpenSource.tar.gz",
                b"labelled".as_slice(),
            ),
            (
                "Module-Build-XSUtil-0.21-TRIAL.tar.gz",
                b"developer".as_slice(),
            ),
            ("Module-Build-XSUtil-0.19.meta", b"{}".as_slice()),
            ("CHECKSUMS", b"checksums".as_slice()),
        ] {
            ctx.state
                .storage
                .put(&format!("cpan/authors/id/H/HI/HIDEAKIO/{filename}"), data)
                .await
                .unwrap();
        }

        let author = send(&ctx.app, Method::GET, "/ui/cpan/H/HI/HIDEAKIO", "").await;
        assert_eq!(author.status(), StatusCode::OK);
        let author_html = String::from_utf8(body_bytes(author).await.to_vec()).unwrap();
        assert!(author_html.contains("/ui/cpan/H/HI/HIDEAKIO/Module-Build-XSUtil"));
        assert!(!author_html.contains("Module-Build-XSUtil-0.19.tar.gz"));
        assert!(!author_html.contains("CHECKSUMS"));

        let detail = send(
            &ctx.app,
            Method::GET,
            "/ui/cpan/H/HI/HIDEAKIO/Module-Build-XSUtil",
            "",
        )
        .await;
        assert_eq!(detail.status(), StatusCode::OK);
        let detail_html = String::from_utf8(body_bytes(detail).await.to_vec()).unwrap();
        assert!(detail_html.contains("data-version=\"0.18\""));
        assert!(detail_html.contains("data-version=\"0.19\""));
        assert!(detail_html.contains("data-version=\"0.20-OpenSource\""));
        assert!(!detail_html.contains("data-version=\"0.21-TRIAL\""));
        assert!(detail_html.contains("+ 1 pre-release"));

        let prereleases = send(
            &ctx.app,
            Method::GET,
            "/ui/cpan/H/HI/HIDEAKIO/Module-Build-XSUtil?prerelease=true",
            "",
        )
        .await;
        let prerelease_html = String::from_utf8(body_bytes(prereleases).await.to_vec()).unwrap();
        assert!(prerelease_html.contains("data-version=\"0.21-TRIAL\""));

        let old_url = send(
            &ctx.app,
            Method::GET,
            "/ui/cpan/H/HI/HIDEAKIO/Module-Build-XSUtil-0.19.tar.gz",
            "",
        )
        .await;
        assert_eq!(old_url.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            old_url.headers().get(header::LOCATION).unwrap(),
            "/ui/cpan/H/HI/HIDEAKIO/Module-Build-XSUtil"
        );
    }

    #[tokio::test]
    async fn test_cpan_cached_index_served() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
            cfg.cpan.metadata_ttl = 3600;
        });
        ctx.state
            .storage
            .put("cpan/modules/02packages.details.txt.gz", b"gzip-data")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cpan/modules/02packages.details.txt.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert!(body.starts_with(b"gzip"));
    }

    #[tokio::test]
    async fn test_cpan_cached_dist_served_despite_upstream_down() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
            cfg.cpan.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.cpan.proxy_timeout = 1;
            cfg.cpan.serve_stale = true;
        });
        // Pre-populate cache
        ctx.state
            .storage
            .put("cpan/authors/id/F/FO/FOO/stale-1.0.tar.gz", b"stale-data")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cpan/authors/id/F/FO/FOO/stale-1.0.tar.gz",
            "",
        )
        .await;
        // Cached data is served fresh via get_verified fast path (no stale header)
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await.as_ref(), b"stale-data");
    }

    #[tokio::test]
    async fn test_cpan_unreachable_proxy_no_stale_returns_bad_gateway() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
            cfg.cpan.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.cpan.proxy_timeout = 1;
            cfg.cpan.serve_stale = false;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cpan/authors/id/X/XX/XXX/Nonexistent-0.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_cpan_curation_enforce_blocks() {
        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{"registry": "cpan", "name": "evil-module", "version": "*", "reason": "malware"}]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();
        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.cpan.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl_path);
        });
        ctx.state
            .storage
            .put("cpan/authors/id/E/EV/EVIL/evil-module-1.0.tar.gz", b"evil")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cpan/authors/id/E/EV/EVIL/evil-module-1.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
