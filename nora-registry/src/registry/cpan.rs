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
use crate::config::UpstreamAuth;
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

/// Prefix under which CPAN distributions are stored, and an empty suffix: the CPAN index
/// (`repo_index::build_cpan_index`) reads archives by their file name with
/// [`parse_dist_archive_filename`], not by a suffix — distributions come as .tar.gz,
/// .tar.bz2, .tar.xz, .zip and .tgz, beside .meta/.readme files and the author's CHECKSUMS.
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
        expose_opt(&state.config.cpan.proxy_auth).map(UpstreamAuth::Basic),
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
    // The wildcard holds the path after `id/` as sent; a leading `/` is an empty segment
    // (`id//F/...`), refused below like any other, not a second name for the same archive.
    let dist_path = path.as_str();
    if !is_valid_dist_path(dist_path) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!("cpan/authors/id/{}", dist_path);
    // An empty segment (`A//B`, a trailing `/`) names another file, and leaves curation an
    // empty file name: refuse it before curation, storage or the upstream see it.
    if crate::validation::validate_storage_key(&storage_key).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let filename = dist_path.rsplit('/').next().unwrap_or(dist_path);

    // Eager cache read — preserve data for serve-stale fallback
    let cached_data = state.storage.get(&storage_key).await.ok();

    // Curation check — extract name and optional version from dist filename
    let (dist_name, dist_version) = parse_dist_filename(filename);
    let dist_name = dist_name.as_str();
    // A distribution archive carries its version in its name; `.meta`, `.readme`
    // and other files name none.
    let request_version = match dist_version {
        Some(ref v) => crate::curation::RequestVersion::Known(v.to_string()),
        None if cpan_archive_stem(filename).is_some() => {
            crate::curation::RequestVersion::Unrecognised
        }
        None => crate::curation::RequestVersion::Unspecified,
    };
    if let Some(response) = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        crate::curation::RegistryType::Cpan,
        dist_name,
        request_version,
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
            dist_version.as_deref(),
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
        expose_opt(&state.config.cpan.proxy_auth).map(UpstreamAuth::Basic),
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

/// CPAN::DistnameInfo 0.12's `distname_info` (`lib/CPAN/DistnameInfo.pm`), the reading PAUSE
/// indexes and cpanm resolves by: the distribution name and version of an archive's name without
/// its extension. The name is the longest run of "units" — separators, then letters, digits and
/// underscores (an underscore between two digits is not one), ending in a letter that no letter
/// follows or a digit that `-` follows, but not in `v` after a separator — and the version is the
/// rest, after the module's fix-ups.
pub(crate) fn distname_info(distvname: &str) -> (String, Option<String>) {
    let b = distvname.as_bytes();
    // One unit from `start`, its end if one matches there (the regex's greedy `[-+.]*`, word
    // characters, then the last position its final character may take).
    let unit_end = |start: usize| -> Option<usize> {
        let mut p = start;
        while p < b.len() && matches!(b[p], b'-' | b'+' | b'.') {
            p += 1;
        }
        let word_start = p;
        let mut e = p;
        while e < b.len() {
            let ok = b[e].is_ascii_alphanumeric()
                || (b[e] == b'_'
                    && ((e > 0 && !b[e - 1].is_ascii_digit())
                        || (e + 1 < b.len() && !b[e + 1].is_ascii_digit())));
            if !ok {
                break;
            }
            e += 1;
        }
        (word_start..e).rev().find_map(|c| {
            let ch = b[c];
            let last = if ch.is_ascii_alphabetic() {
                c + 1 == b.len() || !b[c + 1].is_ascii_alphabetic()
            } else {
                ch.is_ascii_digit() && b.get(c + 1) == Some(&b'-')
            };
            let v_after_separator =
                matches!(ch, b'v' | b'V') && c >= 1 && matches!(b[c - 1], b'.' | b'_' | b'-');
            (last && !v_after_separator).then_some(c + 1)
        })
    };
    let mut end = 0;
    while let Some(next) = unit_end(end) {
        end = next;
    }
    if end == 0 {
        return (distvname.to_string(), None);
    }
    let mut dist = distvname[..end].to_string();
    let mut version = distvname[end..].to_string();

    if version.is_empty() && dist.ends_with("-undef") {
        dist.truncate(dist.len() - "-undef".len());
    }
    if let Some(stripped) = version.strip_suffix("-withoutworldwriteables") {
        version = stripped.to_string();
    }
    // `^(-[Vv].*)-(\d.*)`: a `-V…` part belongs to the name, up to the last `-` before a digit.
    if version.starts_with("-V") || version.starts_with("-v") {
        if let Some(at) = version
            .match_indices('-')
            .map(|(at, _)| at)
            .rfind(|&at| at >= 2 && version[at + 1..].starts_with(|c: char| c.is_ascii_digit()))
        {
            dist.push_str(&version[..at]);
            version = version[at + 1..].to_string();
        }
    }
    // `(.+_.*)-(\d.*)`: a part with an underscore before the last `-digit` belongs to the name.
    if let Some(at) = version.match_indices('-').map(|(at, _)| at).rfind(|&at| {
        version[at + 1..].starts_with(|c: char| c.is_ascii_digit())
            && version[..at]
                .char_indices()
                .any(|(i, c)| c == '_' && i >= 1)
    }) {
        dist.push_str(&version[..at]);
        version = version[at + 1..].to_string();
    }
    if let Some(stripped) = dist.strip_suffix(".pm") {
        dist = stripped.to_string();
    }
    // `-(\d+\w)$` on the name, when no version is left.
    if version.is_empty() {
        if let Some(dash) = dist.rfind('-') {
            let tail = &dist[dash + 1..];
            let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
            let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
            if digits >= 1 && tail.len() >= 2 && tail.bytes().all(word) && digits >= tail.len() - 1
            {
                version = tail.to_string();
                dist.truncate(dash);
            }
        }
    }
    // An all-digit version takes the name's last `-word` in front of it.
    if !version.is_empty() && version.bytes().all(|c| c.is_ascii_digit()) {
        if let Some(dash) = dist.rfind('-') {
            let tail = &dist[dash + 1..];
            if !tail.is_empty() && tail.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
                version = format!("{tail}{version}");
                dist.truncate(dash);
            }
        }
    }
    let dotted = version
        .as_bytes()
        .windows(3)
        .any(|w| w[0].is_ascii_digit() && w[1] == b'.' && w[2].is_ascii_digit());
    let lead: &[char] = if dotted {
        &['-', '_', '.']
    } else {
        &['-', '_']
    };
    let version = version.trim_start_matches(lead).to_string();
    (dist, (!version.is_empty()).then_some(version))
}

/// The distribution name and version of a CPAN archive, as CPAN::DistnameInfo reads them
/// ([`distname_info`]). `None` for a file that is no archive, or an archive without a version.
pub(crate) fn parse_dist_archive_filename(filename: &str) -> Option<(String, String)> {
    let (dist, version) = distname_info(cpan_archive_stem(filename)?);
    Some((dist, version?))
}

/// An archive's name without its extension: the extensions CPAN::DistnameInfo reads (`tar.gz`,
/// `tar.z`, `tar.bz2`, `zip`, `tgz`, in any case), and `.tar.xz`, which NORA serves as well.
fn cpan_archive_stem(filename: &str) -> Option<&str> {
    [".tar.gz", ".tar.z", ".tar.bz2", ".tar.xz", ".zip", ".tgz"]
        .iter()
        .find(|ext| crate::validation::ends_with_ci(filename, ext))
        .map(|ext| &filename[..filename.len() - ext.len()])
}

fn parse_dist_filename(filename: &str) -> (String, Option<String>) {
    if let Some(stem) = cpan_archive_stem(filename) {
        return distname_info(stem);
    }
    let stem = filename
        .strip_suffix(".meta")
        .or_else(|| filename.strip_suffix(".readme"))
        .unwrap_or(filename);
    (stem.to_string(), None)
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
            Some(("Module-Build-XSUtil".to_string(), "0.19".to_string()))
        );
        assert_eq!(
            parse_dist_archive_filename("Acme-123-Widget-v1.2-TRIAL.tar.xz"),
            Some(("Acme-123-Widget".to_string(), "v1.2-TRIAL".to_string()))
        );
        // Representative legacy cases from CPAN::DistnameInfo's own suite.
        assert_eq!(
            parse_dist_archive_filename("finance-quote_0.18.tar.gz"),
            Some(("finance-quote".to_string(), "0.18".to_string()))
        );
        assert_eq!(
            parse_dist_archive_filename("CGI.pm-2.34.tar.gz"),
            Some(("CGI".to_string(), "2.34".to_string()))
        );
        assert_eq!(
            parse_dist_archive_filename("Tk800.025.tar.gz"),
            Some(("Tk".to_string(), "800.025".to_string()))
        );
        assert_eq!(
            parse_dist_archive_filename("Dist-Zilla-2.100860-TRIAL.tar.gz"),
            Some(("Dist-Zilla".to_string(), "2.100860-TRIAL".to_string()))
        );
        assert_eq!(
            parse_dist_archive_filename("Unicode-Collate-Standard-V3_1_1-0.1.tar.gz"),
            Some((
                "Unicode-Collate-Standard-V3_1_1".to_string(),
                "0.1".to_string()
            ))
        );
        assert_eq!(
            parse_dist_archive_filename("Bio-ASN1-EntrezGene-1.10-withoutworldwriteables.tar.gz"),
            Some(("Bio-ASN1-EntrezGene".to_string(), "1.10".to_string()))
        );
        assert_eq!(parse_dist_archive_filename("CHECKSUMS"), None);
        assert_eq!(
            parse_dist_archive_filename("Module-Build-XSUtil-0.19.meta"),
            None
        );
        assert_eq!(
            parse_dist_filename("plain-name.tar.gz"),
            ("plain-name".to_string(), None)
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

    /// A distribution archive whose version cannot be read from its name is refused
    /// by the allowlist; a `.meta` file names no version and passes.
    #[tokio::test]
    async fn allowlist_refuses_an_archive_whose_version_it_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"version": 1, "entries": [{"registry": "cpan", "name": "Foo-Bar", "version": "1.0"}]}"#).unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.cpan.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        for key in ["Foo-Bar.tar.gz", "Foo-Bar-1.0.meta"] {
            ctx.state
                .storage
                .put(&format!("cpan/authors/id/A/AU/AUTHOR/{key}"), b"x")
                .await
                .unwrap();
        }
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cpan/authors/id/A/AU/AUTHOR/Foo-Bar.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/cpan/authors/id/A/AU/AUTHOR/Foo-Bar-1.0.meta",
            "",
        )
        .await;
        assert_ne!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "control: .meta passes"
        );
    }

    /// The dashboard card, `/api/ui/stats` and `nora_artifacts_total{registry="cpan"}` count
    /// distributions: one author with two, each beside the `.meta` and `.readme` a CPAN
    /// mirror keeps, plus the author's `CHECKSUMS` — seven files, two distributions.
    #[tokio::test]
    async fn every_count_is_the_number_of_stored_distributions() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
        });
        for file in [
            "Foo-Bar-1.0.tar.gz",
            "Foo-Bar-1.0.meta",
            "Foo-Bar-1.0.readme",
            "Baz-Qux-2.0.tar.gz",
            "Baz-Qux-2.0.meta",
            "Baz-Qux-2.0.readme",
            "CHECKSUMS",
        ] {
            ctx.state
                .storage
                .put(&format!("cpan/authors/id/A/AU/AUTHOR/{file}"), b"x")
                .await
                .unwrap();
        }
        // The mirror-wide package index lives outside authors/id/ and is no artifact.
        ctx.state
            .storage
            .put("cpan/modules/02packages.details.txt.gz", b"gz")
            .await
            .unwrap();
        assert_eq!(
            artifact_counts(&ctx, "cpan").await,
            ArtifactCounts {
                dashboard: 2,
                stats: 2,
                metric: 2
            }
        );
    }

    /// Control: one archive, no sidecars — the three numbers agree on 1.
    #[tokio::test]
    async fn a_single_archive_counts_once() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
        });
        ctx.state
            .storage
            .put("cpan/authors/id/A/AU/AUTHOR/Foo-Bar-1.0.tar.gz", b"x")
            .await
            .unwrap();
        assert_eq!(
            artifact_counts(&ctx, "cpan").await,
            ArtifactCounts {
                dashboard: 1,
                stats: 1,
                metric: 1
            }
        );
    }

    /// The listing names a distribution by its author path, as its UI page does: two
    /// releases of one distribution are one package with two versions; the same name from
    /// another author, or in an author's subdirectory, is another package.
    #[tokio::test]
    async fn the_listing_names_each_distribution_by_its_author_path() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
        });
        for key in [
            "A/AU/AUTHOR/Foo-Bar-1.0.tar.gz",
            "A/AU/AUTHOR/Foo-Bar-1.1.tar.gz",
            "A/AU/AUTHOR/Foo-Bar-1.1.meta",
            "A/AU/AUTHOR/sub/Foo-Bar-0.9.zip",
            "O/OT/OTHER/Foo-Bar-1.0.tar.gz",
            "O/OT/OTHER/CHECKSUMS",
        ] {
            ctx.state
                .storage
                .put(&format!("cpan/authors/id/{key}"), b"x")
                .await
                .unwrap();
        }
        let resp = send(&ctx.app, Method::GET, "/api/ui/cpan/list", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let list: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let mut got: Vec<(String, u64)> = list
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["name"].as_str().unwrap().to_string(),
                    r["versions"].as_u64().unwrap(),
                )
            })
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("A/AU/AUTHOR/Foo-Bar".to_string(), 2),
                ("A/AU/AUTHOR/sub/Foo-Bar".to_string(), 1),
                ("O/OT/OTHER/Foo-Bar".to_string(), 1),
            ]
        );
        // The search links a name to its distribution page, which lists both releases.
        let resp = send(&ctx.app, Method::GET, "/api/ui/cpan/search?q=foo", "").await;
        let html = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        let link = "/ui/cpan/A%2FAU%2FAUTHOR%2FFoo-Bar";
        assert!(html.contains(link), "{html}");
        let resp = send(&ctx.app, Method::GET, link, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let page = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        assert!(page.contains(">1.0<") && page.contains(">1.1<"), "{page}");
        assert!(
            !page.contains(">0.9<"),
            "the subdirectory release is another package"
        );
    }
    /// Every archive form the CPAN parser reads is a release, named as
    /// the parser names it — `.tar.bz2`, `.tar.xz`, and an old `name_version` upload.
    #[tokio::test]
    async fn every_archive_form_the_parser_reads_counts() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
        });
        for file in [
            "Foo-Bar-1.0.tar.bz2",
            "Baz-Qux-2.0.tar.xz",
            "finance-quote_0.18.tar.gz",
        ] {
            ctx.state
                .storage
                .put(&format!("cpan/authors/id/A/AU/AUTHOR/{file}"), b"x")
                .await
                .unwrap();
        }
        assert_eq!(
            artifact_counts(&ctx, "cpan").await,
            ArtifactCounts {
                dashboard: 3,
                stats: 3,
                metric: 3
            }
        );
        let resp = send(&ctx.app, Method::GET, "/api/ui/cpan/list", "").await;
        let list: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let mut names: Vec<String> = list
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "A/AU/AUTHOR/Baz-Qux".to_string(),
                "A/AU/AUTHOR/Foo-Bar".to_string(),
                "A/AU/AUTHOR/finance-quote".to_string(),
            ]
        );
    }

    /// `.../Foo-1.0.tar.gz/` is refused: its file name is the empty last segment, which no
    /// rule matches, and on an object store the key is the cached archive itself (the local
    /// backend answers ENOTDIR — the control).
    #[tokio::test]
    async fn a_trailing_slash_distribution_is_refused_before_curation() {
        use crate::storage::{ObjectStorage, Storage};
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "cpan", "name": "Foo", "version": "*", "reason": "malware"}]}"#,
        )
        .unwrap();
        let bp = blocklist.to_string_lossy().into_owned();
        let configure = |cfg: &mut crate::config::Config| {
            cfg.cpan.enabled = true;
            cfg.cpan.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bp.clone());
        };
        let key = "cpan/authors/id/F/FO/FOO/Foo-1.0.tar.gz";
        let canonical = "/cpan/authors/id/F/FO/FOO/Foo-1.0.tar.gz";

        let local = create_test_context_with_config(configure);
        local.state.storage.put(key, b"MALWARE").await.unwrap();
        let resp = send(&local.app, Method::GET, &format!("{canonical}/"), "").await;
        assert_ne!(resp.status(), StatusCode::OK, "control: local backend");
        let resp = send(
            &local.app,
            Method::GET,
            "/cpan/authors/id/F/FO/FOO//Foo-1.0.tar.gz",
            "",
        )
        .await;
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "control: `//` keeps the filename"
        );

        let object = create_test_context_with_storage_and_config(
            Storage::from_backend(std::sync::Arc::new(ObjectStorage::in_memory())),
            configure,
        );
        object.state.storage.put(key, b"MALWARE").await.unwrap();
        let resp = send(&object.app, Method::GET, canonical, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control: canonical");
        let resp = send(&object.app, Method::GET, &format!("{canonical}/"), "").await;
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "blocklisted distribution served: {:?}",
            body_bytes(resp).await
        );
    }
}

/// Archive forms and author subdirectories in the CPAN counts.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod cpan_counts_archive_forms {
    use crate::test_helpers::{
        artifact_counts, body_bytes, create_test_context_with_config, send, ArtifactCounts,
    };
    use axum::http::{Method, StatusCode};

    async fn names(ctx: &crate::test_helpers::TestContext) -> Vec<(String, u64)> {
        let resp = send(&ctx.app, Method::GET, "/api/ui/cpan/list", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let list: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let mut got: Vec<(String, u64)> = list
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["name"].as_str().unwrap().to_string(),
                    r["versions"].as_u64().unwrap(),
                )
            })
            .collect();
        got.sort();
        got
    }

    // `.tgz` and a top-level `.zip` are archive forms the parser reads: each is a release.
    #[tokio::test]
    async fn tgz_and_zip_archives_count() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
        });
        for file in ["Foo-Bar-1.0.tgz", "Baz-Qux-2.0.zip"] {
            ctx.state
                .storage
                .put(&format!("cpan/authors/id/A/AU/AUTHOR/{file}"), b"x")
                .await
                .unwrap();
        }
        assert_eq!(
            artifact_counts(&ctx, "cpan").await,
            ArtifactCounts {
                dashboard: 2,
                stats: 2,
                metric: 2
            }
        );
    }

    // The parser reads the file name, not the path: an author subdirectory whose name
    // looks like `name_version` does not swallow the distributions inside it.
    #[tokio::test]
    async fn a_subdirectory_name_is_not_parsed_as_a_distribution() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
        });
        for file in ["old_2019/Foo-Bar-1.0.tar.gz", "old_2019/Baz-Qux-2.0.tar.gz"] {
            ctx.state
                .storage
                .put(&format!("cpan/authors/id/A/AU/AUTHOR/{file}"), b"x")
                .await
                .unwrap();
        }
        assert_eq!(
            names(&ctx).await,
            vec![
                ("A/AU/AUTHOR/old_2019/Baz-Qux".to_string(), 1),
                ("A/AU/AUTHOR/old_2019/Foo-Bar".to_string(), 1),
            ]
        );
        assert_eq!(artifact_counts(&ctx, "cpan").await.stats, 2);
    }
}

/// A name or path with an empty segment (or, where the name is one segment, any `/`) never
/// reaches curation, storage or an upstream: it would name another artifact's files, and an
/// upstream that normalises paths would answer for that other artifact.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod empty_segment_requests {
    use crate::test_helpers::{
        blocklist_file, create_test_context_with_config, send, upstream_paths,
    };
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // `.../Foo-1.0.tar.gz/` would leave curation an empty file name, and `F/FO//FOO` and
    // `id//F` name the same archive under another path.
    #[tokio::test]
    async fn a_distribution_path_with_an_empty_segment_never_reaches_upstream() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"EVIL-TGZ".to_vec()))
            .mount(&up)
            .await;
        let (_dir, blocklist) = blocklist_file("cpan", "Foo");
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
            cfg.cpan.proxy = Some(up.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        let control = "/cpan/authors/id/F/FO/FOO/Foo-1.0.tar.gz";
        let resp = send(&ctx.app, Method::GET, control, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        for uri in [
            "/cpan/authors/id/F/FO/FOO/Foo-1.0.tar.gz/",
            "/cpan/authors/id/F/FO//FOO/Foo-1.0.tar.gz",
            "/cpan/authors/id//F/FO/FOO/Foo-1.0.tar.gz",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
        let sent = upstream_paths(&up).await;
        assert!(sent.is_empty(), "sent upstream: {sent:?}");
    }
}

/// CPAN distribution paths as CPAN::DistnameInfo reads them and cpanm requests them
/// (testdata/cpan, regenerated by the scripts there).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod per_cpan_distnameinfo {
    use super::parse_dist_filename;
    use crate::storage::{ObjectStorage, Storage};
    use crate::test_helpers::{create_test_context_with_storage_and_config, send, upstream_paths};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn corpus(file: &str) -> Vec<Vec<String>> {
        let path = format!("{}/testdata/cpan/{file}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|row| !row.starts_with('#'))
            .map(|row| row.split('\t').map(String::from).collect())
            .collect()
    }

    // Every archive's distribution name and version, as CPAN::DistnameInfo reads them (the
    // reading PAUSE indexes and cpanm resolves by).
    #[test]
    fn archives_read_as_cpan_distnameinfo_reads_them_are_counted() {
        let rows = corpus("distnames.tsv");
        assert_eq!(rows.len(), 982);
        let archives: Vec<&Vec<String>> = rows.iter().filter(|row| row[3] != "UNDEF").collect();
        assert_eq!(archives.len(), 890);
        let agreeing = archives
            .iter()
            .filter(|row| {
                let filename = row[0].rsplit('/').next().unwrap();
                let (dist, version) = parse_dist_filename(filename);
                (dist.as_str(), version.as_deref().unwrap_or("UNDEF"))
                    == (row[1].as_str(), row[2].as_str())
            })
            .count();
        assert_eq!(agreeing, 890);
        // `.tar.xz`, which CPAN::DistnameInfo does not read but NORA serves, reads as the same
        // archive under `.tar.gz` does: a rule on a distribution holds for both.
        let xz: Vec<&Vec<String>> = rows
            .iter()
            .filter(|row| row[0].ends_with(".tar.xz"))
            .collect();
        assert_eq!(xz.len(), 30);
        for row in xz {
            let filename = row[0].rsplit('/').next().unwrap();
            let gz = format!("{}.tar.gz", filename.strip_suffix(".tar.xz").unwrap());
            assert_eq!(
                parse_dist_filename(filename),
                parse_dist_filename(&gz),
                "{filename}"
            );
        }
    }

    // Every request cpanm sends to a mirror at NORA's mount reaches upstream at the path it sent.
    #[tokio::test]
    async fn every_request_cpanm_sends_is_asked_upstream_as_sent() {
        let rows = corpus("client-requests.tsv");
        assert_eq!(rows.len(), 21);
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tgz".to_vec()))
            .mount(&up)
            .await;
        let proxy = up.uri();
        let storage = Storage::from_backend(std::sync::Arc::new(ObjectStorage::in_memory()));
        let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.cpan.enabled = true;
            cfg.cpan.proxy = Some(proxy);
        });
        for row in rows {
            let (installed, path) = (&row[0], &row[2]);
            assert_eq!(row[1], "GET");
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{installed}: {path}");
            let asked = path.strip_prefix("/cpan").unwrap().to_string();
            assert!(
                upstream_paths(&up).await.contains(&asked),
                "{installed}: {path}"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod cpan_rule_holds_for_every_archive_reading {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // PAUSE indexes and cpanm resolves a distribution by CPAN::DistnameInfo's reading
    // (PAUSE `lib/PAUSE/mldistwatch.pm:11,873`, `lib/PAUSE/dist.pm:853`; Menlo `CLI/Compat.pm:1658-1680`).
    // CPAN::DistnameInfo 0.12 (`DistnameInfo.pm:10-18,35-41,47-51`) reads these, measured in
    // testdata/cpan/distnames.tsv (the first three are real uploads from its own test data):
    // `Crypt-ECB-1.1-2` → `Crypt-ECB` 1.1-2, `perl-5.8.1-RC2` → `perl` 5.8.1-RC2,
    // `Win32-API-Prototype` → `Win32-API-Prototype` (no version), `Foo-Bar-1.23-RC1` → `Foo-Bar` 1.23-RC1.
    // A rule on a distribution holds for its archives.
    #[tokio::test]
    async fn a_rule_holds_for_the_distribution_cpan_distnameinfo_reads() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tgz".to_vec()))
            .mount(&up)
            .await;
        let dir = tempfile::TempDir::new().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        let rules: Vec<serde_json::Value> = ["Crypt-ECB", "perl", "Win32-API-Prototype", "Foo-Bar"]
            .iter()
            .map(|name| serde_json::json!({"registry": "cpan", "name": name, "version": "*", "reason": "test"}))
            .collect();
        std::fs::write(
            &blocklist,
            serde_json::json!({"version": 1, "rules": rules}).to_string(),
        )
        .unwrap();
        let proxy = up.uri();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
            cfg.cpan.proxy = Some(proxy);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
        });
        let control = "/cpan/authors/id/A/AU/AUTHOR/Foo-Bar-1.23.tar.gz";
        let resp = send(&ctx.app, Method::GET, control, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        for path in [
            "/cpan/authors/id/D/DE/DESTRUCT/Crypt-ECB-1.1-2.tar.gz",
            "/cpan/authors/id/J/JH/JHI/perl-5.8.1-RC2.tar.gz",
            "/cpan/authors/id/A/AU/AUTHOR/Win32-API-Prototype.tar.gz",
            "/cpan/authors/id/A/AU/AUTHOR/Foo-Bar-1.23-RC1.tar.gz",
        ] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod cpan_every_archive_extension {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // PAUSE takes `.tar.Z` archives as Perl distributions (`lib/PAUSE/dist.pm:247`), and
    // CPAN::DistnameInfo 0.12 reads `tar.(g?z|bz2)|zip|tgz` without case (`DistnameInfo.pm:87`):
    // `A/AU/AUTHOR/Foo-Bar-1.23.tar.Z` is `Foo-Bar` 1.23 (testdata/cpan/distnames.tsv).
    #[tokio::test]
    async fn a_rule_holds_for_a_tar_z_archive_of_its_distribution() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"compressed".to_vec()))
            .mount(&up)
            .await;
        let (_dir, blocklist) = crate::test_helpers::blocklist_file("cpan", "Foo-Bar");
        let proxy = up.uri();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.cpan.enabled = true;
            cfg.cpan.proxy = Some(proxy);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        let control = "/cpan/authors/id/A/AU/AUTHOR/Foo-Bar-1.23.tar.gz";
        let resp = send(&ctx.app, Method::GET, control, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        let path = "/cpan/authors/id/A/AU/AUTHOR/Foo-Bar-1.23.tar.Z";
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
    }
}
