// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Composer (PHP) registry: hosted packages and a pull-through cache of Composer 2
//! repositories (Packagist by default).
//!
//! Routes (Composer 2 repository protocol):
//!   GET  /composer/packages.json                                    — repository root (NORA's own)
//!   GET  /composer/p2/{vendor}/{package}.json                       — tagged versions
//!   GET  /composer/p2/{vendor}/{package}~dev.json                   — branch (dev) versions
//!   GET  /composer/dists/{vendor}/{package}/{version}/{ref}.{type}  — archive download
//!   GET|POST /composer/api/security-advisories/                     — `composer audit`
//!   PUT  /composer/packages/upload/{vendor}/{package}/{version}     — upload a zip (Nexus shape)
//!
//! A package with versions uploaded here is served from them alone and never asked of an
//! upstream (dependency confusion). Any other package is the first upstream's that has it.
//! Its metadata is cached as the upstream sent it and every `dist.url` is rewritten to NORA
//! on the way out. An archive is fetched only from the URL the cached metadata lists for that
//! exact version and reference, so `/composer/dists/` is not an open proxy.
//!
//! Client config (`composer.json`):
//!   "repositories": [{"type": "composer", "url": "http://nora:4000/composer"}, {"packagist.org": false}]

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, AuthenticatedUser, NamespaceAuthority};
use crate::cache_ttl::is_within_ttl;
use crate::circuit_breaker::BreakerScope;
use crate::config::{ComposerProxyEntry, UpstreamAuth};
use crate::registry::{
    method_not_allowed, nora_base_url, proxy_fetch, proxy_fetch_conditional, proxy_fetch_hop,
    proxy_forward_post, read_validators, validators_key, write_validators, Hopped, ProxyError,
    Revalidation, UpstreamMiss, Validators,
};
use crate::registry_type::RegistryType;
use crate::AppState;
use axum::{
    body::{Body, Bytes},
    extract::{Path, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
    Extension, Router,
};
use nora_registry::npm_links::{self, Hop};
use serde_json::{Map, Value};
use sha2::Digest;
use std::time::Duration;

/// The registry name in metrics, logs, audit records and storage keys.
const REGISTRY: &str = "composer";

const JSON_CONTENT_TYPE: &str = "application/json";

/// Largest `composer.json` read out of an uploaded archive.
const MAX_COMPOSER_JSON: u64 = 1024 * 1024;

/// Largest security-advisories query accepted. Composer sends one name per package of the
/// lock file: far below this even for a large application.
const MAX_ADVISORY_QUERY: usize = 1024 * 1024;

/// The marker of a minified (`composer/2.0`) version list.
const MINIFIED: &str = "composer/2.0";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/composer/packages.json", get(repository_root))
        .route("/composer/p2/{vendor}/{file}", get(package_metadata))
        .route(
            "/composer/dists/{vendor}/{package}/{version}/{file}",
            get(download_dist),
        )
        .route(
            "/composer/api/security-advisories",
            get(security_advisories)
                .post(security_advisories)
                .fallback(|| async { method_not_allowed("GET, POST") }),
        )
        .route(
            "/composer/api/security-advisories/",
            get(security_advisories)
                .post(security_advisories)
                .fallback(|| async { method_not_allowed("GET, POST") }),
        )
        .route(
            "/composer/packages/upload/{vendor}/{package}/{version}",
            put(upload).fallback(|| async { method_not_allowed("PUT") }),
        )
}

// ============================================================================
// Names, versions and the path segments built from them
// ============================================================================

/// One part of a Composer package name as Composer's `ValidatingArrayLoader` takes it: the
/// vendor is `[a-z0-9]([_.-]?[a-z0-9]+)*`, the package also allows `--` between runs.
fn is_valid_name_part(part: &str, double_dash: bool) -> bool {
    if part.is_empty() || part.len() > 128 {
        return false;
    }
    let bytes = part.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !alnum(bytes[0]) || !alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if alnum(b) {
            i += 1;
            continue;
        }
        // A separator run: one of `_ . -`, or `--` in a package name, between two runs.
        let run = if double_dash && b == b'-' && bytes.get(i + 1) == Some(&b'-') {
            2
        } else if matches!(b, b'_' | b'.' | b'-') {
            1
        } else {
            return false;
        };
        i += run;
        if !bytes.get(i).copied().is_some_and(alnum) {
            return false;
        }
    }
    true
}

/// Whether `vendor/package` is a Composer package name (lowercase, as Composer asks for it).
pub(crate) fn is_valid_package_name(vendor: &str, package: &str) -> bool {
    is_valid_name_part(vendor, false) && is_valid_name_part(package, true)
}

/// `vendor/package` split and checked.
fn split_name(name: &str) -> Option<(&str, &str)> {
    let (vendor, package) = name.split_once('/')?;
    is_valid_package_name(vendor, package).then_some((vendor, package))
}

/// A Composer stability flag in its expanded spelling (`VersionParser::expandStability`).
fn expand_stability(word: &str) -> &'static str {
    match word {
        "a" | "alpha" => "alpha",
        "b" | "beta" => "beta",
        "p" | "pl" | "patch" => "patch",
        "rc" => "RC",
        _ => "stable",
    }
}

/// A version in Composer's normal form, as `VersionParser::normalize` writes it, for the
/// forms a release and a branch take: `v1.2` is `1.2.0.0`, `1.0.0-beta.2` is
/// `1.0.0.0-beta2`, `1.0-dev` is `1.0.0.0-dev`, `dev-main` stays `dev-main`; build
/// metadata (`+…`) is dropped. `None` for any other string, which Composer would refuse or
/// read as a date or a `.x` branch — forms NORA compares as written.
pub(crate) fn normalize_version(version: &str) -> Option<String> {
    let version = version.trim();
    if version.is_empty() || version.len() > 128 {
        return None;
    }
    let version = match version.split_once('+') {
        Some((head, meta)) if !head.is_empty() && !meta.is_empty() => head,
        Some(_) => return None,
        None => version,
    };
    if version.len() > 4 && version[..4].eq_ignore_ascii_case("dev-") {
        return Some(format!("dev-{}", &version[4..]));
    }
    let lower = version.to_ascii_lowercase();
    let rest = lower.strip_prefix('v').unwrap_or(&lower);

    // Up to four numbers: the first one to five digits, as Composer reads them.
    let mut numbers: Vec<&str> = Vec::with_capacity(4);
    let mut tail = rest;
    loop {
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 || (numbers.is_empty() && digits > 5) {
            break;
        }
        numbers.push(&tail[..digits]);
        tail = &tail[digits..];
        if numbers.len() == 4 || !tail.starts_with('.') {
            break;
        }
        let after = &tail[1..];
        if !after.starts_with(|c: char| c.is_ascii_digit()) {
            break;
        }
        tail = after;
    }
    if numbers.is_empty() {
        return None;
    }
    let mut normal = numbers.join(".");
    for _ in numbers.len()..4 {
        normal.push_str(".0");
    }

    // The modifier: `[._-]?(stability((?:[.-]?\d+)*)?)?([.-]?dev)?`.
    let body = tail.strip_prefix(['.', '_', '-']).unwrap_or(tail);
    let mut stability = None;
    let mut after_word = body;
    for word in [
        "stable", "beta", "b", "rc", "alpha", "a", "patch", "pl", "p",
    ] {
        if let Some(after) = body.strip_prefix(word) {
            stability = Some(word);
            after_word = after;
            break;
        }
    }
    let (number, rest) = match stability {
        Some(_) => {
            let mut consumed = 0;
            let mut probe = after_word;
            loop {
                let sep = usize::from(probe.starts_with(['.', '-']));
                let digits = probe[sep..].bytes().take_while(u8::is_ascii_digit).count();
                if digits == 0 {
                    break;
                }
                consumed += sep + digits;
                probe = &probe[sep + digits..];
            }
            (&after_word[..consumed], &after_word[consumed..])
        }
        None => ("", tail),
    };
    let dev = match rest {
        "" => false,
        r if r == "dev" || r == ".dev" || r == "-dev" => true,
        // `_dev` only right after the numbers, where `[._-]?` took the separator.
        "_dev" if stability.is_none() => true,
        _ => return None,
    };
    if let Some(word) = stability {
        let expanded = expand_stability(word);
        if expanded == "stable" {
            return Some(normal);
        }
        normal.push('-');
        normal.push_str(expanded);
        normal.push_str(number.trim_start_matches(['.', '-']));
    }
    if dev {
        normal.push_str("-dev");
    }
    Some(normal)
}

/// Whether a version is a branch (dev) version, which Composer lists in `~dev.json`.
fn is_dev_version(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    lower.starts_with("dev-") || lower.ends_with("-dev") || lower.ends_with(".dev")
}

/// The order of two normal-form versions, for listing hosted versions newest first.
fn version_order(a: &str, b: &str) -> std::cmp::Ordering {
    fn key(v: &str) -> (Vec<u64>, u8, u64) {
        let (numbers, modifier) = v.split_once('-').unwrap_or((v, ""));
        let numbers = numbers
            .split('.')
            .map(|n| n.parse::<u64>().unwrap_or(0))
            .collect();
        let (rank, rest) = if modifier.is_empty() {
            (4, "")
        } else if let Some(r) = modifier.strip_prefix("alpha") {
            (1, r)
        } else if let Some(r) = modifier.strip_prefix("beta") {
            (2, r)
        } else if let Some(r) = modifier.strip_prefix("RC") {
            (3, r)
        } else if let Some(r) = modifier.strip_prefix("patch") {
            (5, r)
        } else {
            (0, "")
        };
        (numbers, rank, rest.parse().unwrap_or(0))
    }
    key(a).cmp(&key(b))
}

/// The path segment and storage-key segment that stands for a version: the version as
/// written when it is plain (`v1.2.3`, `1.0.0-beta1`, `dev-main`), else `~` and a digest of
/// it (`dev-feature/x`, `1.0+build`) — never a `%` escape, which some object stores encode
/// a second time.
pub(crate) fn version_segment(version: &str) -> String {
    let plain = !version.is_empty()
        && version.len() <= 128
        && !version.starts_with('.')
        && !version.contains("..")
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if plain {
        version.to_string()
    } else {
        format!(
            "~{}",
            &hex::encode(sha2::Sha256::digest(version.as_bytes()))[..32]
        )
    }
}

/// Whether a path segment is one [`version_segment`] builds.
fn is_version_segment(segment: &str) -> bool {
    match segment.strip_prefix('~') {
        Some(digest) => digest.len() == 32 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        None => version_segment(segment) == segment,
    }
}

/// A reference that can stand in a path as it is: a commit hash, a hosted archive's sha1.
fn is_plain_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 128
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// The name a version's archive has in NORA's URL: its `dist.reference` when plain, else a
/// digest of its upstream URL. `None` for a `dist` with neither.
fn dist_token(dist: &Map<String, Value>) -> Option<String> {
    if let Some(reference) = dist
        .get("reference")
        .and_then(Value::as_str)
        .filter(|r| is_plain_token(r))
    {
        return Some(reference.to_string());
    }
    let url = dist.get("url").and_then(Value::as_str)?;
    Some(hex::encode(sha2::Sha256::digest(url.as_bytes()))[..40].to_string())
}

/// The extension of a version's archive in NORA's URL: its `dist.type` (`zip`, `tar`, …).
/// Composer picks the extractor by the type, never by the URL.
fn dist_ext(dist: &Map<String, Value>) -> String {
    match dist.get("type").and_then(Value::as_str) {
        Some(t)
            if !t.is_empty()
                && t.len() <= 10
                && t.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) =>
        {
            t.to_string()
        }
        _ => "bin".to_string(),
    }
}

// ============================================================================
// Minified metadata (Composer's `MetadataMinifier`)
// ============================================================================

/// The full version entries of a minified list: each entry after the first holds only the
/// keys that changed from the one before, and `"__unset"` for a key it drops.
fn expand(versions: &[Value]) -> Vec<Map<String, Value>> {
    let mut expanded = Vec::with_capacity(versions.len());
    let mut current: Option<Map<String, Value>> = None;
    for entry in versions {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        let next = match current.take() {
            None => entry.clone(),
            Some(mut previous) => {
                for (key, value) in entry {
                    if value.as_str() == Some("__unset") {
                        previous.remove(key);
                    } else {
                        previous.insert(key.clone(), value.clone());
                    }
                }
                previous
            }
        };
        expanded.push(next.clone());
        current = Some(next);
    }
    expanded
}

/// The minified list of full version entries: the inverse of [`expand`].
fn minify(versions: &[Map<String, Value>]) -> Vec<Value> {
    let mut minified = Vec::with_capacity(versions.len());
    let mut last: Option<&Map<String, Value>> = None;
    for version in versions {
        let entry = match last {
            None => version.clone(),
            Some(previous) => {
                let mut entry = Map::new();
                for (key, value) in version {
                    if previous.get(key) != Some(value) {
                        entry.insert(key.clone(), value.clone());
                    }
                }
                for key in previous.keys() {
                    if !version.contains_key(key) {
                        entry.insert(key.clone(), Value::String("__unset".to_string()));
                    }
                }
                entry
            }
        };
        minified.push(Value::Object(entry));
        last = Some(version);
    }
    minified
}

/// The version entries of `name` in a p2 document, expanded.
fn versions_of(doc: &Value, name: &str) -> Vec<Map<String, Value>> {
    let Some(list) = doc
        .get("packages")
        .and_then(|p| p.get(name))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    if doc.get("minified").and_then(Value::as_str) == Some(MINIFIED) {
        expand(list)
    } else {
        list.iter().filter_map(|v| v.as_object().cloned()).collect()
    }
}

/// Whether `body` is a Composer 2 metadata document (`{"packages": {...}}`).
fn is_metadata_document(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .is_some_and(|doc| doc.get("packages").is_some_and(Value::is_object))
}

/// The p2 document of `name` as NORA serves it: every version's `dist.url` points at NORA
/// (built from its version and [`dist_token`]), and, when `keep_source` is off, a version that
/// has such a dist loses its `source`, so a client can only install it through NORA. A minified
/// list stays minified. Hosted versions are addressed by their normal form. Only `name` is
/// served: another package an upstream puts in the document (an internal one, say) is dropped.
fn rewrite_document(
    body: &[u8],
    name: &str,
    nora_base: &str,
    hosted: bool,
    keep_source: bool,
) -> Option<Vec<u8>> {
    let mut doc: Value = serde_json::from_slice(body).ok()?;
    let minified = doc.get("minified").and_then(Value::as_str) == Some(MINIFIED);
    let packages = doc.get_mut("packages")?.as_object_mut()?;
    packages.retain(|listed, _| listed == name);
    for (name, list) in packages.iter_mut() {
        if split_name(name).is_none() {
            continue;
        }
        let Some(entries) = list.as_array() else {
            continue;
        };
        let mut versions = if minified {
            expand(entries)
        } else {
            entries
                .iter()
                .filter_map(|v| v.as_object().cloned())
                .collect()
        };
        for version in &mut versions {
            rewrite_version(version, name, nora_base, hosted, keep_source);
        }
        *list = Value::Array(if minified {
            minify(&versions)
        } else {
            versions.into_iter().map(Value::Object).collect()
        });
    }
    serde_json::to_vec(&doc).ok()
}

fn rewrite_version(
    version: &mut Map<String, Value>,
    name: &str,
    nora_base: &str,
    hosted: bool,
    keep_source: bool,
) {
    let Some(written) = version.get("version").and_then(Value::as_str) else {
        return;
    };
    let segment = if hosted {
        match normalize_version(written) {
            Some(normal) => normal,
            None => return,
        }
    } else {
        version_segment(written)
    };
    let Some(dist) = version.get_mut("dist").and_then(Value::as_object_mut) else {
        return;
    };
    let Some(token) = dist_token(dist) else {
        return;
    };
    let url = format!(
        "{}/composer/dists/{name}/{segment}/{token}.{}",
        nora_base.trim_end_matches('/'),
        dist_ext(dist)
    );
    dist.insert("url".to_string(), Value::String(url));
    // Mirrors would send the client past NORA.
    dist.remove("mirrors");
    if !keep_source {
        version.remove("source");
    }
}

// ============================================================================
// Storage layout
// ============================================================================

fn p2_key(name: &str, dev: bool) -> String {
    format!("composer/p2/{name}{}.json", if dev { "~dev" } else { "" })
}

fn origin_key(key: &str) -> String {
    format!("{key}.origin")
}

fn proxied_dist_key(name: &str, segment: &str, token: &str, ext: &str) -> String {
    format!("composer/dists/{name}/{segment}/{token}.{ext}")
}

fn hosted_prefix(name: &str) -> String {
    format!("composer/hosted/{name}/")
}

fn hosted_document_key(name: &str) -> String {
    format!("composer/hosted/{name}/p2.json")
}

fn hosted_version_key(name: &str, normal: &str) -> String {
    format!("composer/hosted/{name}/versions/{normal}.json")
}

fn hosted_dist_key(name: &str, normal: &str) -> String {
    format!("composer/hosted/{name}/dists/{normal}.zip")
}

/// Whether a package has versions uploaded to NORA.
enum Hosted {
    Yes,
    No,
    /// The store could not be asked: a package that may be NORA's own is not answered for by
    /// an upstream.
    Unknown(crate::storage::StorageError),
}

async fn hosted_state(state: &AppState, name: &str) -> Hosted {
    if state
        .storage
        .stat(&hosted_document_key(name))
        .await
        .is_some()
    {
        return Hosted::Yes;
    }
    match state
        .storage
        .list(&format!("composer/hosted/{name}/versions/"))
        .await
    {
        Ok(keys) if keys.iter().any(|k| k.ends_with(".json")) => Hosted::Yes,
        Ok(_) => Hosted::No,
        Err(e) => Hosted::Unknown(e),
    }
}

fn is_internal(state: &AppState, name: &str) -> bool {
    crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Composer,
        name,
    )
}

fn internal_refused(state: &AppState, name: &str) -> Response {
    crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Composer,
        name,
    )
    .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
}

// ============================================================================
// Responses
// ============================================================================

fn http_date(unix: u64) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .unwrap_or_default()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// A metadata document, or 304 when the client's `If-Modified-Since` names the very
/// `Last-Modified` it would get (Composer revalidates its own cache that way).
fn metadata_response(
    headers: &HeaderMap,
    body: Vec<u8>,
    last_modified: Option<String>,
    stale: bool,
) -> Response {
    let not_modified = last_modified.as_deref().is_some_and(|lm| {
        headers
            .get(header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok())
            == Some(lm)
    });
    let mut builder = axum::http::Response::builder()
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE);
    if let Some(lm) = last_modified.as_deref() {
        builder = builder.header(header::LAST_MODIFIED, lm);
    }
    if stale {
        builder = builder.header("x-nora-stale", "true");
    }
    let response = if not_modified {
        builder.status(StatusCode::NOT_MODIFIED).body(Body::empty())
    } else {
        builder.status(StatusCode::OK).body(Body::from(body))
    };
    response.unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, JSON_CONTENT_TYPE)],
        serde_json::json!({ "error": message }).to_string(),
    )
        .into_response()
}

fn archive_response(data: Bytes, ext: &str) -> Response {
    let content_type = if ext == "zip" {
        "application/zip"
    } else {
        "application/octet-stream"
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
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

// ============================================================================
// Upstreams
// ============================================================================

/// `scheme://host[:port]` of a URL.
fn origin_of(url: &str) -> Option<String> {
    let url = reqwest::Url::parse(url).ok()?;
    Some(url.origin().ascii_serialization())
}

fn same_origin(a: &str, b: &str) -> bool {
    matches!((origin_of(a), origin_of(b)), (Some(x), Some(y)) if x == y && x != "null")
}

/// The upstream's credential for `url`: only on the upstream's own origin.
fn auth_for<'a>(up: &'a ComposerProxyEntry, url: &str) -> Option<UpstreamAuth<'a>> {
    up.auth()
        .filter(|_| same_origin(url, up.url()))
        .map(UpstreamAuth::Basic)
}

fn timeout(state: &AppState) -> Duration {
    Duration::from_secs(state.config.composer.proxy_timeout)
}

/// What an upstream's `packages.json` says of where its documents are.
#[derive(Debug, PartialEq)]
struct UpstreamRoot {
    /// Absolute, with `%package%`.
    metadata_url: String,
    advisories_url: Option<String>,
}

impl UpstreamRoot {
    fn p2_url(&self, name: &str, dev: bool) -> String {
        let package = format!("{name}{}", if dev { "~dev" } else { "" });
        self.metadata_url.replace("%package%", &package)
    }
}

/// A URL of an upstream's root resolved as Composer resolves it: absolute as it is, one
/// starting with `/` on the upstream's origin.
fn resolve_root_url(base: &str, url: &str) -> Option<String> {
    if url.starts_with("https://") || url.starts_with("http://") {
        Some(url.to_string())
    } else if url.starts_with('/') && !url.starts_with("//") {
        Some(format!("{}{url}", origin_of(base)?))
    } else {
        None
    }
}

/// The root an upstream's `packages.json` describes; without one (unreachable and never
/// cached, or not a Composer 2 root) the layout of every Composer 2 repository NORA knows,
/// `{upstream}/p2/%package%.json`.
fn parse_root(base: &str, body: Option<&[u8]>) -> UpstreamRoot {
    let doc = body.and_then(|b| serde_json::from_slice::<Value>(b).ok());
    let metadata_url = doc
        .as_ref()
        .and_then(|d| d.get("metadata-url"))
        .and_then(Value::as_str)
        .and_then(|u| resolve_root_url(base, u))
        .filter(|u| u.contains("%package%"))
        .unwrap_or_else(|| format!("{base}/p2/%package%.json"));
    let advisories_url = doc
        .as_ref()
        .and_then(|d| d.get("security-advisories"))
        .and_then(|s| s.get("api-url"))
        .and_then(Value::as_str)
        .and_then(|u| resolve_root_url(base, u));
    UpstreamRoot {
        metadata_url,
        advisories_url,
    }
}

/// An upstream's root: its `packages.json`, cached for `metadata_ttl`, a stale copy when it
/// cannot be reached.
async fn upstream_root(state: &AppState, up: &ComposerProxyEntry) -> UpstreamRoot {
    let base = up.url().trim_end_matches('/');
    let key = format!(
        "composer/roots/{}.json",
        &hex::encode(sha2::Sha256::digest(base.as_bytes()))[..16]
    );
    let cached = state.storage.get(&key).await.ok();
    if let Some(data) = &cached {
        if let Some(meta) = state.storage.stat(&key).await {
            if is_within_ttl(meta.modified, state.config.composer.metadata_ttl) {
                return parse_root(base, Some(data));
            }
        }
    }
    let url = format!("{base}/packages.json");
    match proxy_fetch(
        &state.http_client,
        &url,
        timeout(state),
        auth_for(up, &url),
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Composer, up.url()),
    )
    .await
    {
        Ok(body) if serde_json::from_slice::<Value>(&body).is_ok() => {
            if let Err(e) = state.storage.put(&key, &body).await {
                tracing::warn!(registry = REGISTRY, key, error = %e, "failed to cache upstream root");
            }
            parse_root(base, Some(&body))
        }
        Ok(_) => {
            tracing::warn!(registry = REGISTRY, url, "upstream root is not JSON");
            parse_root(base, cached.as_deref())
        }
        Err(e) => {
            tracing::debug!(registry = REGISTRY, url, error = ?e, "upstream root unavailable");
            parse_root(base, cached.as_deref())
        }
    }
}

/// An upstream metadata document as cached.
struct UpstreamDocument {
    body: Bytes,
    /// The configured upstream that served it.
    origin: String,
    last_modified: Option<String>,
    stale: bool,
}

/// The cached copy of a p2 document and what is known of it.
struct CachedDocument {
    body: Bytes,
    origin: Option<String>,
    fresh: bool,
    last_modified: Option<String>,
}

async fn cached_document(state: &AppState, key: &str) -> Option<CachedDocument> {
    let body = state.storage.get(key).await.ok()?;
    let meta = state.storage.stat(key).await;
    let fresh = meta
        .as_ref()
        .is_some_and(|m| is_within_ttl(m.modified, state.config.composer.metadata_ttl));
    let origin = state
        .storage
        .get(&origin_key(key))
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o).into_owned());
    let last_modified = read_validators(&state.storage, key)
        .await
        .and_then(|v| v.last_modified)
        .or_else(|| meta.map(|m| http_date(m.modified)));
    Some(CachedDocument {
        body,
        origin,
        fresh,
        last_modified,
    })
}

/// Whether two spellings of an upstream URL name the same upstream (`…/` is `…`).
fn same_upstream(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Whether `origin` is one of the configured upstreams: a copy another upstream served (one
/// since removed from the configuration) is not trusted for what it lists.
fn is_configured(state: &AppState, origin: Option<&str>) -> bool {
    origin.is_some_and(|o| {
        state
            .config
            .composer
            .upstreams()
            .iter()
            .any(|up| same_upstream(up.url(), o))
    })
}

/// The upstream p2 document of `name`: the fresh cached copy, else the first upstream that
/// has it (a 304 keeps the cached copy), else the stale copy when every upstream that did
/// not say "not found" failed, else the miss as a response.
async fn upstream_document(
    state: &AppState,
    name: &str,
    dev: bool,
) -> Result<UpstreamDocument, Response> {
    let key = p2_key(name, dev);
    let cached = cached_document(state, &key).await;
    if let Some(c) = &cached {
        if c.fresh && is_configured(state, c.origin.as_deref()) {
            return Ok(UpstreamDocument {
                body: c.body.clone(),
                origin: c.origin.clone().unwrap_or_default(),
                last_modified: c.last_modified.clone(),
                stale: false,
            });
        }
    }
    let upstreams = state.config.composer.upstreams();
    let path = format!("/composer/p2/{name}{}.json", if dev { "~dev" } else { "" });
    let mut miss = UpstreamMiss::default();
    let mut failed = false;
    for up in &upstreams {
        let root = upstream_root(state, up).await;
        let url = root.p2_url(name, dev);
        let from_here = cached.as_ref().filter(|c| {
            c.origin
                .as_deref()
                .is_some_and(|o| same_upstream(o, up.url()))
        });
        let validators = match from_here {
            Some(_) if state.config.composer.revalidate => read_validators(&state.storage, &key)
                .await
                .unwrap_or_default(),
            _ => Validators::default(),
        };
        let had_validators = validators.is_some();
        match proxy_fetch_conditional(
            &state.http_client,
            &url,
            timeout(state),
            auth_for(up, &url),
            &validators,
            &state.circuit_breaker,
            BreakerScope::upstream(RegistryType::Composer, up.url()),
        )
        .await
        {
            Ok(Revalidation::NotModified) => {
                let Some(c) = from_here else {
                    // A 304 to a request without validators: not an answer to rely on.
                    failed = true;
                    miss.record(&ProxyError::Upstream(304));
                    continue;
                };
                crate::metrics::PROXY_UPSTREAM_304_TOTAL
                    .with_label_values(&[REGISTRY])
                    .inc();
                crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                    .with_label_values(&[REGISTRY])
                    .inc_by(c.body.len() as u64);
                // Rewrite the same bytes to restart the TTL.
                if let Err(e) = state.storage.put(&key, &c.body).await {
                    tracing::warn!(registry = REGISTRY, key, error = %e, "failed to refresh cached metadata");
                }
                return Ok(UpstreamDocument {
                    body: c.body.clone(),
                    origin: up.url().to_string(),
                    last_modified: c.last_modified.clone(),
                    stale: false,
                });
            }
            Ok(Revalidation::Modified { body, validators }) => {
                if !is_metadata_document(&body) {
                    tracing::warn!(
                        registry = REGISTRY,
                        url,
                        "upstream answered with something that is not Composer metadata"
                    );
                    failed = true;
                    miss.record(&ProxyError::Network("not Composer metadata".into()));
                    continue;
                }
                // Body first, then where it came from, then its validators: a sidecar never
                // describes bytes that are not there.
                if let Err(e) = state.storage.put(&key, &body).await {
                    tracing::warn!(registry = REGISTRY, key, error = %e, "failed to cache metadata");
                }
                if let Err(e) = state
                    .storage
                    .put(&origin_key(&key), up.url().as_bytes())
                    .await
                {
                    tracing::warn!(registry = REGISTRY, key, error = %e, "failed to record metadata origin");
                }
                if validators.is_some() {
                    write_validators(&state.storage, &key, &validators).await;
                } else {
                    let _ = state.storage.delete(&validators_key(&key)).await;
                }
                state.repo_index.invalidate(REGISTRY);
                let last_modified = validators
                    .last_modified
                    .clone()
                    .or_else(|| Some(http_date(chrono::Utc::now().timestamp() as u64)));
                return Ok(UpstreamDocument {
                    body: Bytes::from(body),
                    origin: up.url().to_string(),
                    last_modified,
                    stale: false,
                });
            }
            Err(e) => {
                if had_validators {
                    crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                        .with_label_values(&[REGISTRY])
                        .inc();
                }
                if !matches!(e, ProxyError::NotFound) {
                    failed = true;
                }
                tracing::debug!(registry = REGISTRY, url, error = ?e, "upstream metadata miss");
                miss.record(&e);
            }
        }
    }
    if let Some(c) = cached {
        if failed && state.config.composer.serve_stale && is_configured(state, c.origin.as_deref())
        {
            tracing::warn!(
                registry = REGISTRY,
                package = name,
                "upstream unavailable, serving stale metadata"
            );
            return Ok(UpstreamDocument {
                body: c.body,
                origin: c.origin.unwrap_or_default(),
                last_modified: c.last_modified,
                stale: true,
            });
        }
    }
    Err(miss.response(REGISTRY, &path))
}

// ============================================================================
// GET /composer/packages.json
// ============================================================================

async fn repository_root(State(state): State<AppState>) -> Response {
    let base = format!("{}/composer", nora_base_url(&state).trim_end_matches('/'));
    let mut root = serde_json::json!({
        "packages": [],
        "metadata-url": format!("{base}/p2/%package%.json"),
        "security-advisories": {
            "metadata": true,
            "api-url": format!("{base}/api/security-advisories/"),
        },
    });
    // Hosted only: name the packages there are, so Composer asks for no other.
    if state.config.composer.upstreams().is_empty() {
        if let Ok(keys) = state.storage.list("composer/hosted/").await {
            let mut names: Vec<String> = keys
                .iter()
                .filter_map(|k| k.strip_prefix("composer/hosted/"))
                .filter_map(|k| k.split_once("/versions/").map(|(name, _)| name))
                .filter(|name| split_name(name).is_some())
                .map(str::to_string)
                .collect();
            names.sort();
            names.dedup();
            root["available-packages"] = Value::from(names);
        }
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, JSON_CONTENT_TYPE),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        root.to_string(),
    )
        .into_response()
}

// ============================================================================
// GET /composer/p2/{vendor}/{package}.json
// ============================================================================

async fn package_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((vendor, file)): Path<(String, String)>,
) -> Response {
    let Some(stem) = file.strip_suffix(".json") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (package, dev) = match stem.strip_suffix("~dev") {
        Some(package) => (package, true),
        None => (stem, false),
    };
    if !is_valid_package_name(&vendor, package) {
        return json_error(StatusCode::BAD_REQUEST, "invalid package name");
    }
    let name = format!("{vendor}/{package}");
    let base = nora_base_url(&state);

    match hosted_state(&state, &name).await {
        Hosted::Yes => return hosted_metadata(&state, &headers, &name, dev, &base).await,
        Hosted::Unknown(e) => {
            return crate::registry::local_copy_unreadable(REGISTRY, &hosted_prefix(&name), &e)
        }
        Hosted::No => {}
    }

    // An internal package is NORA's own: with no uploaded version it is refused, never asked
    // of an upstream.
    if is_internal(&state, &name) {
        return internal_refused(&state, &name);
    }
    if let Some(response) = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        crate::curation::RegistryType::Composer,
        &name,
        crate::curation::RequestVersion::Unspecified,
        None,
    ) {
        return response;
    }

    let doc = match upstream_document(&state, &name, dev).await {
        Ok(doc) => doc,
        Err(response) => return response,
    };
    match rewrite_document(
        &doc.body,
        &name,
        &base,
        false,
        state.config.composer.keep_source,
    ) {
        Some(body) => metadata_response(&headers, body, doc.last_modified, doc.stale),
        None => {
            tracing::warn!(
                registry = REGISTRY,
                package = name,
                "cached metadata does not parse"
            );
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn hosted_metadata(
    state: &AppState,
    headers: &HeaderMap,
    name: &str,
    dev: bool,
    base: &str,
) -> Response {
    if dev {
        // Uploaded versions are releases: a hosted package has no branch versions, and its
        // `~dev` document is never an upstream's.
        let body = serde_json::json!({ "packages": { name: [] } }).to_string();
        return metadata_response(headers, body.into_bytes(), None, false);
    }
    let key = hosted_document_key(name);
    let body = match state.storage.get(&key).await {
        Ok(body) => body,
        Err(crate::storage::StorageError::NotFound) => {
            // Versions without the document: an upload stopped between the two. Build it.
            let lock = state.publish_lock(&key);
            let _guard = lock.lock().await;
            match regenerate_hosted(state, name).await {
                Ok(body) => Bytes::from(body),
                Err(response) => return response,
            }
        }
        Err(e) => return crate::registry::local_copy_unreadable(REGISTRY, &key, &e),
    };
    let last_modified = state
        .storage
        .stat(&key)
        .await
        .map(|m| http_date(m.modified));
    match rewrite_document(&body, name, base, true, true) {
        Some(body) => metadata_response(headers, body, last_modified, false),
        None => {
            tracing::error!(registry = REGISTRY, key, "hosted metadata does not parse");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Rebuild a hosted package's p2 document from its version documents, newest first, and
/// store it. Run under the package's publish lock.
async fn regenerate_hosted(state: &AppState, name: &str) -> Result<Vec<u8>, Response> {
    let prefix = format!("composer/hosted/{name}/versions/");
    let keys = state
        .storage
        .list(&prefix)
        .await
        .map_err(|e| crate::registry::local_copy_unreadable(REGISTRY, &prefix, &e))?;
    let mut versions: Vec<(String, Value)> = Vec::new();
    for key in keys.iter().filter(|k| k.ends_with(".json")) {
        let data = state
            .storage
            .get(key)
            .await
            .map_err(|e| crate::registry::local_copy_unreadable(REGISTRY, key, &e))?;
        let doc: Value = serde_json::from_slice(&data).map_err(|e| {
            tracing::error!(registry = REGISTRY, key, error = %e, "hosted version document is corrupt");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;
        let normal = doc
            .get("version")
            .and_then(Value::as_str)
            .and_then(normalize_version)
            .unwrap_or_default();
        versions.push((normal, doc));
    }
    versions.sort_by(|a, b| version_order(&b.0, &a.0));
    let list: Vec<Value> = versions.into_iter().map(|(_, doc)| doc).collect();
    let body = serde_json::to_vec(&serde_json::json!({ "packages": { name: list } }))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
    if let Err(e) = state.storage.put(&hosted_document_key(name), &body).await {
        // Served anyway; the next request builds it again.
        tracing::warn!(registry = REGISTRY, package = name, error = %e, "failed to store hosted metadata");
    }
    Ok(body)
}

// ============================================================================
// GET /composer/dists/{vendor}/{package}/{version}/{ref}.{type}
// ============================================================================

/// A version's archive as an upstream's metadata lists it.
#[derive(Debug, PartialEq)]
struct Listed {
    version: String,
    url: String,
    /// sha1, when the upstream gives one.
    shasum: Option<String>,
    time: Option<String>,
}

/// The archive of `name` that NORA's URL `segment/token.ext` stands for in the p2 document
/// `body`, as [`rewrite_version`] built that URL.
fn find_listed(body: &[u8], name: &str, segment: &str, token: &str, ext: &str) -> Option<Listed> {
    let doc: Value = serde_json::from_slice(body).ok()?;
    versions_of(&doc, name).into_iter().find_map(|version| {
        let written = version.get("version")?.as_str()?;
        if version_segment(written) != segment {
            return None;
        }
        let dist = version.get("dist")?.as_object()?;
        if dist_token(dist).as_deref() != Some(token) || dist_ext(dist) != ext {
            return None;
        }
        let url = dist.get("url")?.as_str()?;
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return None;
        }
        Some(Listed {
            version: written.to_string(),
            url: url.to_string(),
            shasum: dist
                .get("shasum")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_ascii_lowercase),
            time: version
                .get("time")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    })
}

/// The listing of an archive in the upstream metadata of `name`, the configured upstream
/// that listed it, and the key of the document that did. A version written in the path is
/// looked up in the document Composer lists it in (`~dev.json` for a branch); one there as a
/// digest in both. A cached document that does not list it is fetched again only once past
/// its TTL; a fresh one is believed, so a made-up URL costs no upstream request.
async fn listed_dist(
    state: &AppState,
    name: &str,
    segment: &str,
    token: &str,
    ext: &str,
) -> Result<(Listed, String, String), Response> {
    let expected = (!segment.starts_with('~')).then(|| is_dev_version(segment));
    let documents = match expected {
        Some(dev) => [dev, !dev],
        None => [false, true],
    };
    let mut refetch = Vec::new();
    for dev in documents {
        let key = p2_key(name, dev);
        let cached = cached_document(state, &key).await;
        let trusted = cached
            .as_ref()
            .filter(|c| is_configured(state, c.origin.as_deref()));
        if let Some(c) = trusted {
            if let Some(listed) = find_listed(&c.body, name, segment, token, ext) {
                return Ok((listed, c.origin.clone().unwrap_or_default(), key));
            }
        }
        let fresh = trusted.is_some_and(|c| c.fresh);
        if !fresh && expected.is_none_or(|e| e == dev) {
            refetch.push(dev);
        }
    }
    let mut miss = None;
    for dev in refetch {
        match upstream_document(state, name, dev).await {
            Ok(doc) => {
                if let Some(listed) = find_listed(&doc.body, name, segment, token, ext) {
                    return Ok((listed, doc.origin, p2_key(name, dev)));
                }
            }
            Err(response) if response.status() != StatusCode::NOT_FOUND => {
                miss.get_or_insert(response);
            }
            Err(_) => {}
        }
    }
    tracing::info!(
        registry = REGISTRY,
        package = name,
        version = segment,
        "archive not listed by the upstream's metadata, not asked for"
    );
    Err(miss.unwrap_or_else(|| StatusCode::NOT_FOUND.into_response()))
}

async fn download_dist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((vendor, package, segment, file)): Path<(String, String, String, String)>,
) -> Response {
    let Some((token, ext)) = file.rsplit_once('.') else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !is_valid_package_name(&vendor, &package)
        || !is_plain_token(token)
        || !is_version_segment(&segment)
        || ext.is_empty()
        || ext.len() > 10
        || !ext
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return json_error(StatusCode::BAD_REQUEST, "invalid archive path");
    }
    let name = format!("{vendor}/{package}");
    let internal = is_internal(&state, &name);
    match hosted_state(&state, &name).await {
        Hosted::Yes => {
            return hosted_dist(&state, &headers, &name, &segment, token, ext, internal).await
        }
        Hosted::Unknown(e) => {
            return crate::registry::local_copy_unreadable(REGISTRY, &hosted_prefix(&name), &e)
        }
        Hosted::No => {}
    }
    if internal {
        return internal_refused(&state, &name);
    }

    let (listed, origin, metadata_key) =
        match listed_dist(&state, &name, &segment, token, ext).await {
            Ok(found) => found,
            Err(response) => return response,
        };
    let publish_date = if state.config.server.trust_upstream_dates {
        listed
            .time
            .as_deref()
            .and_then(crate::curation::parse_iso8601_to_unix)
    } else {
        crate::curation::extract_mtime_as_publish_date(&state.storage, &metadata_key).await
    };
    if let Some(response) = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        &headers,
        crate::curation::RegistryType::Composer,
        &name,
        crate::curation::RequestVersion::Known(listed.version.clone()),
        publish_date,
    ) {
        return response;
    }

    let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
        state.config.curation.composer.quarantine.as_ref().or(state
            .config
            .curation
            .quarantine
            .as_ref()),
        state
            .config
            .curation
            .composer
            .quarantine_ttl
            .as_deref()
            .or(state.config.curation.quarantine_ttl.as_deref()),
    );
    let first_seen = crate::digest_quarantine::first_seen_seed(
        state.config.server.trust_upstream_dates,
        publish_date,
    );
    let display = format!("{name}@{}", listed.version);
    let key = proxied_dist_key(&name, &segment, token, ext);

    let (cached, _) = crate::registry::cached_read(state.storage.get_verified(&key).await);
    let cached = match cached {
        Some(outcome) => {
            use nora_registry::verified::{verified_body, GateOutcome};
            let data = match outcome {
                GateOutcome::Verified(blob) => verified_body(blob),
                GateOutcome::Unpinned(blob) => blob.into_inner(),
            };
            match crate::registry::check_sidecar(&state.storage, &key, &data).await {
                crate::registry::Sidecar::Holds => Some(data),
                crate::registry::Sidecar::Differs { .. } => {
                    tracing::error!(
                        registry = REGISTRY,
                        key,
                        "cached archive integrity check failed"
                    );
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                crate::registry::Sidecar::Unreadable(e) => {
                    tracing::warn!(registry = REGISTRY, key, error = %e, "archive sidecar unreadable, fetching the archive again");
                    None
                }
            }
        }
        None => None,
    };
    if let Some(data) = cached {
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Composer,
            &name,
            Some(&listed.version),
            &data,
        ) {
            return response;
        }
        if let Some(response) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            REGISTRY,
            &data,
            &q_mode,
            q_secs,
            "cache",
            first_seen,
        ) {
            return response;
        }
        state.metrics.record_download(REGISTRY);
        state.metrics.record_cache_hit(REGISTRY);
        if let Some(response) = crate::registry::range::range_response(
            &state.storage,
            &[&key],
            &headers,
            data.len() as u64,
            "application/octet-stream",
            &[],
        )
        .await
        {
            return response;
        }
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            display,
            RegistryType::Composer,
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "proxy", &name, REGISTRY, ""));
        return archive_response(data, ext);
    }

    let Some(up) = state
        .config
        .composer
        .upstreams()
        .into_iter()
        .find(|up| same_upstream(up.url(), &origin))
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let data = match fetch_dist(&state, &up, &listed.url).await {
        Ok(data) => data,
        Err(e) => {
            tracing::warn!(registry = REGISTRY, package = name, version = listed.version, error = ?e, "archive download failed");
            return UpstreamMiss::of(&e).response(REGISTRY, &key);
        }
    };
    if let Some(expected) = &listed.shasum {
        let computed = hex::encode(sha1::Sha1::digest(&data));
        if &computed != expected {
            tracing::error!(
                registry = REGISTRY,
                package = name,
                version = listed.version,
                expected,
                computed,
                "archive does not match the sha1 its metadata lists"
            );
            return StatusCode::BAD_GATEWAY.into_response();
        }
    }
    if let Some(response) = crate::curation::verify_integrity(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Composer,
        &name,
        Some(&listed.version),
        &data,
    ) {
        return response;
    }
    let data = Bytes::from(data);
    let hash = hex::encode(sha2::Sha256::digest(&data));
    if let Err(e) = state.storage.put(&key, &data).await {
        tracing::warn!(registry = REGISTRY, key, error = %e, "failed to cache archive");
    } else if let Err(e) = state
        .storage
        .put(&format!("{key}.sha256"), hash.as_bytes())
        .await
    {
        tracing::warn!(registry = REGISTRY, key, error = %e, "failed to store archive digest");
    }
    state.repo_index.invalidate(REGISTRY);
    state.metrics.record_download(REGISTRY);
    state.metrics.record_cache_miss(REGISTRY);
    state.activity.push(ActivityEntry::new(
        ActionType::ProxyFetch,
        display,
        RegistryType::Composer,
        "PROXY",
    ));
    state
        .audit
        .log(AuditEntry::new("proxy_fetch", "proxy", &name, REGISTRY, ""));
    if let Some(response) = crate::digest_quarantine::proxy_gate_dated(
        &state.digest_store,
        REGISTRY,
        &data,
        &q_mode,
        q_secs,
        &listed.url,
        first_seen,
    ) {
        return response;
    }
    archive_response(data, ext)
}

/// The credential for an archive URL: the upstream's own on its origin (a private repository
/// serving its archives itself), the GitHub token on GitHub's API host, none elsewhere.
fn dist_auth<'a>(
    state: &'a AppState,
    up: &'a ComposerProxyEntry,
    url: &str,
) -> Option<UpstreamAuth<'a>> {
    if let Some(auth) = auth_for(up, url) {
        return Some(auth);
    }
    let parsed = reqwest::Url::parse(url).ok()?;
    if parsed.scheme() == "https" && parsed.host_str() == Some("api.github.com") {
        return crate::secrets::expose_opt(&state.config.composer.github_token)
            .map(UpstreamAuth::Bearer);
    }
    None
}

/// Download an archive, following its redirects one at a time: the credential goes only while
/// the chain stays on the origin of the URL asked (GitHub's API host hands the archive to
/// `codeload.github.com`, which gets none), and the chain shares one `proxy_timeout`.
async fn fetch_dist(
    state: &AppState,
    up: &ComposerProxyEntry,
    asked: &str,
) -> Result<Vec<u8>, ProxyError> {
    let origin = reqwest::Url::parse(asked)
        .map_err(|e| ProxyError::Network(format!("archive URL not readable: {e}")))?;
    let deadline = std::time::Instant::now() + timeout(state);
    let mut auth = dist_auth(state, up, asked);
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
            BreakerScope::upstream(RegistryType::Composer, up.url()),
        )
        .await?
        {
            Hopped::Body(body) => return Ok(body),
            Hopped::Redirect(next) => next,
        };
        url = match npm_links::next_hop(hop, &origin, left_origin, &next) {
            Hop::WithCredential => next.into(),
            Hop::WithoutCredential => {
                left_origin = true;
                auth = None;
                next.into()
            }
            Hop::Refuse => {
                tracing::warn!(
                    registry = REGISTRY,
                    hop,
                    "archive redirect not followed: past the redirect limit or not http(s)"
                );
                return Err(ProxyError::Network("redirect not followed".to_string()));
            }
        };
    }
}

async fn hosted_dist(
    state: &AppState,
    headers: &HeaderMap,
    name: &str,
    segment: &str,
    token: &str,
    ext: &str,
    internal: bool,
) -> Response {
    let version_key = hosted_version_key(name, segment);
    let doc = match state.storage.get(&version_key).await {
        Ok(doc) => doc,
        Err(crate::storage::StorageError::NotFound) => {
            return StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => return crate::registry::local_copy_unreadable(REGISTRY, &version_key, &e),
    };
    let Ok(doc) = serde_json::from_slice::<Value>(&doc) else {
        tracing::error!(
            registry = REGISTRY,
            key = version_key,
            "hosted version document is corrupt"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let reference = doc
        .get("dist")
        .and_then(|d| d.get("reference"))
        .and_then(Value::as_str);
    if ext != "zip" || reference != Some(token) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let version = doc
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or(segment)
        .to_string();
    if !internal {
        let publish_date =
            crate::curation::extract_mtime_as_publish_date(&state.storage, &version_key).await;
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            headers,
            crate::curation::RegistryType::Composer,
            name,
            crate::curation::RequestVersion::Known(version.clone()),
            publish_date,
        ) {
            return response;
        }
    }
    let key = hosted_dist_key(name, segment);
    let data = match state.storage.get_verified(&key).await {
        Ok(outcome) => {
            use nora_registry::verified::{verified_body, GateOutcome};
            match outcome {
                GateOutcome::Verified(blob) => verified_body(blob),
                GateOutcome::Unpinned(blob) => blob.into_inner(),
            }
        }
        Err(crate::storage::StorageError::NotFound) => {
            return StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => return crate::registry::local_copy_unreadable(REGISTRY, &key, &e),
    };
    match crate::registry::check_sidecar(&state.storage, &key, &data).await {
        crate::registry::Sidecar::Holds => {}
        crate::registry::Sidecar::Differs { .. } => {
            tracing::error!(
                registry = REGISTRY,
                key,
                "hosted archive integrity check failed"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        crate::registry::Sidecar::Unreadable(e) => {
            return crate::registry::local_copy_unreadable(REGISTRY, &format!("{key}.sha256"), &e)
        }
    }
    if let Some(response) = crate::curation::verify_integrity(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Composer,
        name,
        Some(&version),
        &data,
    ) {
        return response;
    }
    state.metrics.record_download(REGISTRY);
    if let Some(response) = crate::registry::range::range_response(
        &state.storage,
        &[&key],
        headers,
        data.len() as u64,
        "application/zip",
        &[],
    )
    .await
    {
        return response;
    }
    state.activity.push(ActivityEntry::new(
        ActionType::Pull,
        format!("{name}@{version}"),
        RegistryType::Composer,
        "LOCAL",
    ));
    state
        .audit
        .log(AuditEntry::new("pull", "hosted", name, REGISTRY, ""));
    archive_response(data, "zip")
}

// ============================================================================
// GET|POST /composer/api/security-advisories/
// ============================================================================

/// `composer audit`: the advisories of the packages named in the query (`packages[]=…`, in
/// the URL or a form body), forwarded to the first upstream whose root names an advisories
/// API. Names NORA hosts or holds internal are never sent: they would tell an upstream what
/// the private packages are called.
async fn security_advisories(
    State(state): State<AppState>,
    method: Method,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let form = if method == Method::POST {
        if body.len() > MAX_ADVISORY_QUERY {
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        }
        String::from_utf8_lossy(&body).into_owned()
    } else {
        query.unwrap_or_default()
    };
    let Ok(parsed) = reqwest::Url::parse(&format!("http://query/?{form}")) else {
        return json_error(StatusCode::BAD_REQUEST, "unreadable query");
    };
    let mut names = Vec::new();
    let mut others = Vec::new();
    for (key, value) in parsed.query_pairs() {
        if key == "packages" || key.starts_with("packages[") {
            let name = value.to_ascii_lowercase();
            if split_name(&name).is_some() && !names.contains(&name) {
                names.push(name);
            }
        } else if key == "updatedSince" {
            others.push((key.into_owned(), value.into_owned()));
        }
    }
    let mut asked = Vec::with_capacity(names.len());
    for name in names {
        if is_internal(&state, &name) {
            continue;
        }
        match hosted_state(&state, &name).await {
            Hosted::No => asked.push(name),
            // Hosted, or it cannot be told: not an upstream's to answer.
            Hosted::Yes | Hosted::Unknown(_) => {}
        }
    }
    let empty = || {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, JSON_CONTENT_TYPE)],
            r#"{"advisories":{}}"#,
        )
            .into_response()
    };
    if asked.is_empty() {
        return empty();
    }
    let mut target = None;
    for up in state.config.composer.upstreams() {
        if let Some(url) = upstream_root(&state, &up).await.advisories_url {
            target = Some((up, url));
            break;
        }
    }
    let Some((up, url)) = target else {
        return empty();
    };
    let mut out = reqwest::Url::parse("http://query/").expect("static URL parses");
    {
        let mut pairs = out.query_pairs_mut();
        for name in &asked {
            pairs.append_pair("packages[]", name);
        }
        for (key, value) in &others {
            pairs.append_pair(key, value);
        }
    }
    let form = out.query().unwrap_or_default().to_string();
    match proxy_forward_post(
        &state.http_client,
        &url,
        timeout(&state),
        auth_for(&up, &url),
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", JSON_CONTENT_TYPE),
        ],
        form.as_bytes(),
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Composer, up.url()),
    )
    .await
    {
        Ok((code, body, content_type)) => {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY);
            let content_type = content_type.unwrap_or_else(|| JSON_CONTENT_TYPE.to_string());
            (status, [(header::CONTENT_TYPE, content_type)], body).into_response()
        }
        Err(e) => UpstreamMiss::of(&e).response(REGISTRY, "/composer/api/security-advisories/"),
    }
}

// ============================================================================
// PUT /composer/packages/upload/{vendor}/{package}/{version}
// ============================================================================

async fn upload(
    State(state): State<AppState>,
    Path((vendor, package, version)): Path<(String, String, String)>,
    Extension(authority): Extension<NamespaceAuthority>,
    user: Option<Extension<AuthenticatedUser>>,
    body: Bytes,
) -> Response {
    if !is_valid_package_name(&vendor, &package) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid package name: Composer names are lowercase `vendor/package`",
        );
    }
    let name = format!("{vendor}/{package}");
    if enforce_namespace_scope(&authority, &name).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(normal) = normalize_version(&version) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid version");
    };
    if is_dev_version(&normal) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "branch (dev) versions cannot be uploaded: upload a tagged release",
        );
    }

    let manifest = match zip::composer_json(&body) {
        Ok(manifest) => manifest,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("invalid archive: {e}")),
    };
    let mut doc = match serde_json::from_slice::<Value>(&manifest) {
        Ok(Value::Object(doc)) => doc,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "composer.json is not a JSON object",
            )
        }
    };
    match doc.get("name").and_then(Value::as_str) {
        Some(declared) if declared.eq_ignore_ascii_case(&name) => {}
        Some(declared) => {
            tracing::warn!(
                registry = REGISTRY,
                url_name = name,
                declared,
                "SECURITY: Composer upload name mismatch"
            );
            return json_error(
                StatusCode::BAD_REQUEST,
                "the name in composer.json does not match the upload path",
            );
        }
        None => return json_error(StatusCode::BAD_REQUEST, "composer.json has no name"),
    }
    if let Some(declared) = doc.get("version") {
        let matches = declared
            .as_str()
            .and_then(normalize_version)
            .is_some_and(|d| d == normal);
        if !matches {
            return json_error(
                StatusCode::BAD_REQUEST,
                "the version in composer.json does not match the upload path",
            );
        }
    }

    let sha1 = hex::encode(sha1::Sha1::digest(&body));
    let sha256 = hex::encode(sha2::Sha256::digest(&body));
    doc.insert("name".into(), Value::String(name.clone()));
    doc.insert("version".into(), Value::String(version.clone()));
    doc.insert(
        "dist".into(),
        serde_json::json!({ "type": "zip", "reference": sha1, "shasum": sha1 }),
    );
    doc.remove("source");
    if !doc.contains_key("time") {
        doc.insert(
            "time".into(),
            Value::String(
                chrono::Utc::now()
                    .format("%Y-%m-%dT%H:%M:%S+00:00")
                    .to_string(),
            ),
        );
    }
    let Ok(version_doc) = serde_json::to_vec(&Value::Object(doc)) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let document_key = hosted_document_key(&name);
    let version_key = hosted_version_key(&name, &normal);
    let dist_key = hosted_dist_key(&name, &normal);
    let lock = state.publish_lock(&document_key);
    let _guard = lock.lock().await;

    // Versions are immutable: `v1.0.0` and `1.0` are the same version to Composer.
    if state.storage.stat(&version_key).await.is_some() {
        return json_error(
            StatusCode::CONFLICT,
            &format!("{name} {version} already exists"),
        );
    }
    if let Err(e) = state.storage.put(&dist_key, &body).await {
        tracing::error!(registry = REGISTRY, key = dist_key, error = %e, "failed to store archive");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(e) = state
        .storage
        .put(&format!("{dist_key}.sha256"), sha256.as_bytes())
        .await
    {
        tracing::warn!(registry = REGISTRY, key = dist_key, error = %e, "failed to store archive digest");
    }
    if let Err(e) = state.storage.put(&version_key, &version_doc).await {
        tracing::error!(registry = REGISTRY, key = version_key, error = %e, "failed to store version");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let regenerated = match regenerate_hosted(&state, &name).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    // A 201 means the version is listed: read it back from what will be served.
    let listed = serde_json::from_slice::<Value>(&regenerated)
        .ok()
        .is_some_and(|doc| {
            versions_of(&doc, &name)
                .iter()
                .any(|v| v.get("version").and_then(Value::as_str) == Some(version.as_str()))
        });
    if !listed {
        tracing::error!(
            registry = REGISTRY,
            package = name,
            version,
            "uploaded version is not listed by the regenerated metadata"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    state.metrics.record_upload(REGISTRY);
    state.audit.log(AuditEntry::new(
        "push",
        crate::auth::audit_actor(&user),
        &name,
        REGISTRY,
        &version,
    ));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        format!("{name}@{version}"),
        RegistryType::Composer,
        "LOCAL",
    ));
    state.repo_index.invalidate(REGISTRY);

    let url = format!(
        "{}/composer/dists/{name}/{normal}/{sha1}.zip",
        nora_base_url(&state).trim_end_matches('/')
    );
    (
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, JSON_CONTENT_TYPE)],
        serde_json::json!({
            "name": name,
            "version": version,
            "dist": { "type": "zip", "url": url, "shasum": sha1 },
        })
        .to_string(),
    )
        .into_response()
}

// ============================================================================
// UI
// ============================================================================

/// One version of a package as NORA holds it, for the UI.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StoredVersion {
    pub version: String,
    pub size: u64,
    pub modified: u64,
    /// Uploaded to NORA (else cached from an upstream).
    pub hosted: bool,
}

/// The package a storage key under `composer/` belongs to, when the key is an archive.
pub(crate) fn package_of_archive(key: &str) -> Option<String> {
    if let Some(rest) = key.strip_prefix("composer/hosted/") {
        let (name, file) = rest.split_once("/dists/")?;
        return (file.ends_with(".zip") && split_name(name).is_some()).then(|| name.to_string());
    }
    let rest = key.strip_prefix("composer/dists/")?;
    let mut parts = rest.splitn(4, '/');
    let (vendor, package, _segment, file) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if file.contains('/') || file.ends_with(".sha256") || !is_valid_package_name(vendor, package) {
        return None;
    }
    Some(format!("{vendor}/{package}"))
}

/// The versions of `name` NORA holds an archive of, newest first: uploaded ones and cached
/// ones (whose version is read from the cached metadata, else shown as its path segment).
pub(crate) async fn stored_versions(storage: &crate::Storage, name: &str) -> Vec<StoredVersion> {
    let mut out = Vec::new();
    if split_name(name).is_none() {
        return out;
    }
    if let Ok(keys) = storage
        .list_with_meta(&format!("composer/hosted/{name}/dists/"))
        .await
    {
        for (key, meta) in keys {
            let Some(normal) = key.rsplit('/').next().and_then(|f| f.strip_suffix(".zip")) else {
                continue;
            };
            let version = match storage.get(&hosted_version_key(name, normal)).await {
                Ok(doc) => serde_json::from_slice::<Value>(&doc)
                    .ok()
                    .and_then(|d| d.get("version").and_then(Value::as_str).map(str::to_string))
                    .unwrap_or_else(|| normal.to_string()),
                Err(_) => continue,
            };
            out.push(StoredVersion {
                version,
                size: meta.size,
                modified: meta.modified,
                hosted: true,
            });
        }
    }
    if let Ok(keys) = storage
        .list_with_meta(&format!("composer/dists/{name}/"))
        .await
    {
        let mut written: std::collections::HashMap<String, String> = Default::default();
        for dev in [false, true] {
            if let Ok(body) = storage.get(&p2_key(name, dev)).await {
                if let Ok(doc) = serde_json::from_slice::<Value>(&body) {
                    for v in versions_of(&doc, name) {
                        if let Some(version) = v.get("version").and_then(Value::as_str) {
                            written.insert(version_segment(version), version.to_string());
                        }
                    }
                }
            }
        }
        for (key, meta) in keys {
            if key.ends_with(".sha256") {
                continue;
            }
            let Some(rest) = key.strip_prefix(&format!("composer/dists/{name}/")) else {
                continue;
            };
            let Some((segment, _file)) = rest.split_once('/') else {
                continue;
            };
            out.push(StoredVersion {
                version: written
                    .get(segment)
                    .cloned()
                    .unwrap_or_else(|| segment.to_string()),
                size: meta.size,
                modified: meta.modified,
                hosted: false,
            });
        }
    }
    out.sort_by(|a, b| {
        let key = |v: &StoredVersion| normalize_version(&v.version).unwrap_or_default();
        version_order(&key(b), &key(a))
    });
    out
}

// ============================================================================
// Reading composer.json out of an archive
// ============================================================================

mod zip {
    //! Just enough of the zip format to find and read one member: the end-of-central-directory
    //! record, the central directory, one local header, a stored or deflated body. Every
    //! offset and length is checked against the archive; zip64 and encrypted members are
    //! refused.

    use std::io::Read;

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum ZipError {
        NotAZip,
        Truncated,
        Zip64,
        NoComposerJson,
        SeveralTopLevelDirectories,
        Unsupported(&'static str),
        TooLarge,
        Corrupt,
    }

    impl std::fmt::Display for ZipError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                ZipError::NotAZip => "not a zip archive",
                ZipError::Truncated => "the archive is truncated",
                ZipError::Zip64 => "zip64 archives are not supported",
                ZipError::NoComposerJson => {
                    "no composer.json at the top level or in the single top-level directory"
                }
                ZipError::SeveralTopLevelDirectories => {
                    "no composer.json at the top level and more than one top-level directory"
                }
                ZipError::Unsupported(what) => what,
                ZipError::TooLarge => "composer.json is too large",
                ZipError::Corrupt => "composer.json could not be decompressed",
            })
        }
    }

    struct Entry {
        name: String,
        flags: u16,
        method: u16,
        compressed: u64,
        uncompressed: u64,
        offset: u64,
    }

    fn u16_at(data: &[u8], at: usize) -> Result<u16, ZipError> {
        let bytes = data.get(at..at + 2).ok_or(ZipError::Truncated)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32_at(data: &[u8], at: usize) -> Result<u32, ZipError> {
        let bytes = data.get(at..at + 4).ok_or(ZipError::Truncated)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn entries(data: &[u8]) -> Result<Vec<Entry>, ZipError> {
        const EOCD: u32 = 0x0605_4b50;
        const CENTRAL: u32 = 0x0201_4b50;
        if data.len() < 22 {
            return Err(ZipError::NotAZip);
        }
        // The record is the last 22 bytes and a comment of at most 64 KiB.
        let earliest = data.len().saturating_sub(22 + 0xFFFF);
        let eocd = (earliest..=data.len() - 22)
            .rev()
            .find(|&at| u32_at(data, at) == Ok(EOCD))
            .ok_or(ZipError::NotAZip)?;
        let count = u16_at(data, eocd + 10)?;
        let size = u32_at(data, eocd + 12)?;
        let start = u32_at(data, eocd + 16)?;
        if count == 0xFFFF || size == 0xFFFF_FFFF || start == 0xFFFF_FFFF {
            return Err(ZipError::Zip64);
        }
        let mut at = start as usize;
        let end = at.checked_add(size as usize).ok_or(ZipError::Truncated)?;
        if end > eocd {
            return Err(ZipError::Truncated);
        }
        let mut out = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            if u32_at(data, at)? != CENTRAL {
                return Err(ZipError::NotAZip);
            }
            let name_len = usize::from(u16_at(data, at + 28)?);
            let extra_len = usize::from(u16_at(data, at + 30)?);
            let comment_len = usize::from(u16_at(data, at + 32)?);
            let name = data
                .get(at + 46..at + 46 + name_len)
                .ok_or(ZipError::Truncated)?;
            let compressed = u32_at(data, at + 20)?;
            let uncompressed = u32_at(data, at + 24)?;
            let offset = u32_at(data, at + 42)?;
            if [compressed, uncompressed, offset].contains(&0xFFFF_FFFF) {
                return Err(ZipError::Zip64);
            }
            out.push(Entry {
                name: String::from_utf8_lossy(name).into_owned(),
                flags: u16_at(data, at + 8)?,
                method: u16_at(data, at + 10)?,
                compressed: u64::from(compressed),
                uncompressed: u64::from(uncompressed),
                offset: u64::from(offset),
            });
            at += 46 + name_len + extra_len + comment_len;
            if at > end {
                return Err(ZipError::Truncated);
            }
        }
        Ok(out)
    }

    /// PHP's `dirname` of a member name: `.` for one at the top (`a`, `a/`).
    fn dirname(name: &str) -> &str {
        let trimmed = name.trim_end_matches('/');
        match trimmed.rfind('/') {
            Some(at) => &trimmed[..at],
            None => ".",
        }
    }

    /// The member Composer reads `composer.json` from (`Composer\Util\Zip::locateFile`):
    /// `composer.json` at the top, else the one in the single top-level directory.
    fn locate(entries: &[Entry]) -> Result<usize, ZipError> {
        if let Some(at) = entries.iter().position(|e| e.name == "composer.json") {
            return Ok(at);
        }
        let mut top: Vec<String> = Vec::new();
        for entry in entries {
            if entry.name.contains("__MACOSX") {
                continue;
            }
            let dir = dirname(&entry.name);
            let path = if dir == "." {
                entry.name.clone()
            } else if !dir.contains('/') && !dir.contains('\\') {
                format!("{dir}/")
            } else {
                continue;
            };
            if !top.contains(&path) {
                top.push(path);
            }
            if top.len() > 1 {
                return Err(ZipError::SeveralTopLevelDirectories);
            }
        }
        let wanted = format!(
            "{}composer.json",
            top.first().ok_or(ZipError::NoComposerJson)?
        );
        entries
            .iter()
            .position(|e| e.name == wanted)
            .ok_or(ZipError::NoComposerJson)
    }

    /// The bytes of the archive's `composer.json`.
    pub(super) fn composer_json(data: &[u8]) -> Result<Vec<u8>, ZipError> {
        const LOCAL: u32 = 0x0403_4b50;
        let entries = entries(data)?;
        let entry = &entries[locate(&entries)?];
        if entry.flags & 1 != 0 {
            return Err(ZipError::Unsupported("composer.json is encrypted"));
        }
        if entry.uncompressed > super::MAX_COMPOSER_JSON {
            return Err(ZipError::TooLarge);
        }
        let at = usize::try_from(entry.offset).map_err(|_| ZipError::Truncated)?;
        if u32_at(data, at)? != LOCAL {
            return Err(ZipError::NotAZip);
        }
        let name_len = usize::from(u16_at(data, at + 26)?);
        let extra_len = usize::from(u16_at(data, at + 28)?);
        let body_at = at + 30 + name_len + extra_len;
        let compressed = usize::try_from(entry.compressed).map_err(|_| ZipError::Truncated)?;
        let body = data
            .get(body_at..body_at.checked_add(compressed).ok_or(ZipError::Truncated)?)
            .ok_or(ZipError::Truncated)?;
        let out = match entry.method {
            0 => body.to_vec(),
            8 => {
                let mut out = Vec::new();
                flate2::read::DeflateDecoder::new(body)
                    .take(super::MAX_COMPOSER_JSON + 1)
                    .read_to_end(&mut out)
                    .map_err(|_| ZipError::Corrupt)?;
                out
            }
            _ => {
                return Err(ZipError::Unsupported(
                    "composer.json uses an unsupported compression",
                ))
            }
        };
        if out.len() as u64 > super::MAX_COMPOSER_JSON {
            return Err(ZipError::TooLarge);
        }
        if out.len() as u64 != entry.uncompressed {
            return Err(ZipError::Corrupt);
        }
        Ok(out)
    }

    /// A zip of `(name, body, deflate)` members, for tests.
    #[cfg(test)]
    pub(crate) fn build(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
        use std::io::Write;
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, body, deflate) in members {
            let stored = if *deflate {
                let mut enc =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                enc.write_all(body).unwrap();
                enc.finish().unwrap()
            } else {
                body.to_vec()
            };
            let method: u16 = if *deflate { 8 } else { 0 };
            let crc = crc32(body);
            let offset = out.len() as u32;
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&stored);

            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            central.extend_from_slice(&(body.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let start = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&start.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[cfg(test)]
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn composer_json_at_the_top_is_read() {
            let zip = build(&[
                ("composer.json", br#"{"name":"acme/a"}"#, true),
                ("src/A.php", b"<?php", false),
            ]);
            assert_eq!(composer_json(&zip).unwrap(), br#"{"name":"acme/a"}"#);
        }

        #[test]
        fn composer_json_in_the_single_top_level_directory_is_read() {
            let zip = build(&[
                ("acme-a-1a2b3c/", b"", false),
                (
                    "acme-a-1a2b3c/composer.json",
                    br#"{"name":"acme/a"}"#,
                    false,
                ),
                ("acme-a-1a2b3c/src/A.php", b"<?php", true),
                ("__MACOSX/._x", b"", false),
            ]);
            assert_eq!(composer_json(&zip).unwrap(), br#"{"name":"acme/a"}"#);
        }

        #[test]
        fn a_nested_composer_json_alone_is_not_read() {
            let zip = build(&[
                ("a/composer.json", br#"{"name":"acme/a"}"#, false),
                ("b/x", b"", false),
            ]);
            assert_eq!(
                composer_json(&zip),
                Err(ZipError::SeveralTopLevelDirectories)
            );
            let zip = build(&[("a/b/composer.json", br#"{}"#, false)]);
            assert_eq!(composer_json(&zip), Err(ZipError::NoComposerJson));
        }

        #[test]
        fn not_a_zip_and_truncated_archives_are_refused() {
            assert_eq!(composer_json(b"hello"), Err(ZipError::NotAZip));
            assert_eq!(composer_json(&[0u8; 100]), Err(ZipError::NotAZip));
            let zip = build(&[("composer.json", br#"{"name":"acme/a"}"#, true)]);
            for cut in [10, zip.len() / 2] {
                let mut broken = zip[cut..].to_vec();
                broken.splice(0..0, std::iter::repeat_n(0u8, 3));
                assert!(composer_json(&broken).is_err(), "cut {cut}");
            }
            // Every truncation fails cleanly, never panics.
            for len in 0..zip.len() {
                let _ = composer_json(&zip[..len]);
            }
        }

        #[test]
        fn a_deflate_bomb_stops_at_the_cap() {
            let big = vec![b' '; (super::super::MAX_COMPOSER_JSON as usize) * 4];
            let mut zip = build(&[("composer.json", &big, true)]);
            assert_eq!(composer_json(&zip), Err(ZipError::TooLarge));
            // A central directory that understates the size: the cap still holds.
            let central = zip.len() - 22 - (46 + "composer.json".len());
            zip[central + 24..central + 28].copy_from_slice(&10u32.to_le_bytes());
            assert!(composer_json(&zip).is_err());
        }
    }
}

#[cfg(test)]
pub(crate) use zip::build as build_test_zip;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
