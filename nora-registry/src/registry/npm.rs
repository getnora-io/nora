// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! npm registry with explicit hosted, proxy and group repositories.
//!
//! Hosted and proxy state deliberately live in different namespaces. A group
//! owns no package metadata: its packument is synthesized using member order
//! as the conflict-resolution rule. Hosted authoritative state stays split by
//! responsibility; a rebuildable materialized packument avoids object-store
//! fan-out on every client metadata request.

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, AuthenticatedUser, NamespaceAuthority};
use crate::config::{NpmRepository, NpmWritePolicy};
use crate::registry::{
    circuit_open_response, method_not_allowed, proxy_fetch_conditional_with_validated_redirects,
    proxy_fetch_with_validated_redirects, proxy_fetch_with_validated_redirects_bounded,
    proxy_forward_post, read_validators, write_validators, ProxyError, Revalidation, Validators,
};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::storage::StorageError;
use crate::AppState;
use axum::{
    body::{Body, Bytes},
    extract::{OriginalUri, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use base64::Engine;
use futures::{stream, StreamExt};
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const NPM_AUDIT_BODY_CAP: usize = 8 * 1024 * 1024;
const NPM_SEARCH_BODY_CAP: usize = 8 * 1024 * 1024;
const NPM_SEARCH_SCAN_RESULT_CAP: usize = 10_000;
const NPM_SEARCH_SCAN_PAGE_CAP: usize = 40;
const NPM_SEARCH_SCAN_TIMEOUT: Duration = Duration::from_secs(30);
const PACKAGE_JSON_CAP: u64 = 2 * 1024 * 1024;
const TAR_SCAN_CAP: u64 = 64 * 1024 * 1024;
const MAX_NPM_PROXY_REDIRECTS: usize = 3;
const HOSTED_PACKUMENT_READ_CONCURRENCY: usize = 8;
const LEGACY_HOSTED: &str = "npm-private";
const LEGACY_PROXY: &str = "npm-registry";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/repository/{repository}/-/package/{package}/dist-tags",
            get(named_dist_tags_get).fallback(|| async { method_not_allowed("GET") }),
        )
        .route(
            "/repository/{repository}/-/package/{package}/dist-tags/{tag}",
            axum::routing::put(named_dist_tag_put)
                .delete(named_dist_tag_delete)
                .fallback(|| async { method_not_allowed("PUT, DELETE") }),
        )
        // Compatibility alias. It resolves to npm.default_repository when one
        // is configured. Otherwise it uses isolated synthetic hosted/proxy
        // namespaces; it never reads the pre-named `npm/<pkg>/metadata.json`
        // layout.
        .route(
            "/npm/-/package/{package}/dist-tags",
            get(alias_dist_tags_get).fallback(|| async { method_not_allowed("GET") }),
        )
        .route(
            "/npm/-/package/{package}/dist-tags/{tag}",
            axum::routing::put(alias_dist_tag_put)
                .delete(alias_dist_tag_delete)
                .fallback(|| async { method_not_allowed("PUT, DELETE") }),
        )
        .route(
            "/npm/{*path}",
            get(alias_get)
                .put(alias_put)
                .post(alias_post)
                .fallback(|| async { method_not_allowed("GET, PUT, POST") }),
        )
}

#[derive(Clone)]
enum RepositoryTarget {
    Named(NpmRepository),
    Legacy,
}

#[derive(Clone)]
struct ProxyRepository {
    name: String,
    url: String,
    auth: Option<crate::secrets::ProtectedString>,
    metadata_ttl: i64,
    negative_ttl: i64,
}

#[derive(Debug)]
enum ReadError {
    NotFound,
    Unavailable,
    CircuitOpen(String),
    Corrupt,
    SearchScanLimit,
}

struct PackumentRead {
    value: serde_json::Value,
    stale: bool,
}

impl PackumentRead {
    fn fresh(value: serde_json::Value) -> Self {
        Self {
            value,
            stale: false,
        }
    }
}

fn storage_read_error(error: StorageError) -> ReadError {
    match error {
        StorageError::NotFound => ReadError::NotFound,
        StorageError::IntegrityViolation => ReadError::Corrupt,
        _ => ReadError::Unavailable,
    }
}

async fn optional_storage_get(state: &AppState, key: &str) -> Result<Option<Bytes>, ReadError> {
    match state.storage.get(key).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(StorageError::NotFound) => Ok(None),
        Err(error) => Err(storage_read_error(error)),
    }
}

async fn invalidate_hosted_packument_cache(
    state: &AppState,
    repository: &str,
    package: &str,
) -> Result<(), StorageError> {
    let key = crate::npm_layout::hosted_packument_cache_key(repository, package);
    match state.storage.delete(&key).await {
        Ok(()) | Err(StorageError::NotFound) => Ok(()),
        Err(error) => Err(error),
    }
}

fn named_target(state: &AppState, repository: &str) -> Option<RepositoryTarget> {
    state
        .config
        .npm
        .repository(repository)
        .cloned()
        .map(RepositoryTarget::Named)
}

fn alias_target(state: &AppState) -> Option<RepositoryTarget> {
    match state.config.npm.default_repository.as_deref() {
        Some(name) => named_target(state, name),
        None if !state.config.npm.repositories.is_empty() => None,
        None => Some(RepositoryTarget::Legacy),
    }
}

fn public_base(state: &AppState, route_repository: Option<&str>) -> String {
    let server = state.config.server.public_base_url();
    match route_repository {
        Some(name) => format!("{}/repository/{name}", server.trim_end_matches('/')),
        None => format!("{}/npm", server.trim_end_matches('/')),
    }
}

fn repository_prefix(repository: &str) -> String {
    format!("npm/repositories/{repository}")
}

fn package_prefix(repository: &str, package: &str) -> String {
    format!("{}/{package}", repository_prefix(repository))
}

fn hosted_version_key(repository: &str, package: &str, version: &str) -> String {
    format!(
        "{}/versions/{version}.json",
        package_prefix(repository, package)
    )
}

fn hosted_publish_complete_key(repository: &str, package: &str, version: &str) -> String {
    format!(
        "{}/publish-complete/{version}",
        package_prefix(repository, package)
    )
}

fn hosted_publish_pending_prefix(repository: &str, package: &str) -> String {
    format!("{}/publish-pending/", package_prefix(repository, package))
}

fn hosted_publish_pending_key(repository: &str, package: &str, version: &str) -> String {
    format!(
        "{}{version}",
        hosted_publish_pending_prefix(repository, package)
    )
}

fn hosted_publish_pending_index_key(repository: &str, package: &str) -> String {
    format!(
        "{}/publish-pending-index-v1",
        package_prefix(repository, package)
    )
}

fn hosted_tag_key(repository: &str, package: &str, tag: &str) -> String {
    format!("{}/dist-tags/{tag}", package_prefix(repository, package))
}

fn hosted_deprecation_key(repository: &str, package: &str, version: &str) -> String {
    format!(
        "{}/deprecations/{version}",
        package_prefix(repository, package)
    )
}

fn hosted_package_key(repository: &str, package: &str) -> String {
    format!("{}/pkg.json", package_prefix(repository, package))
}

async fn pending_publish_versions(
    state: &AppState,
    repository: &str,
    package: &str,
) -> Result<HashSet<String>, StorageError> {
    let prefix = hosted_publish_pending_prefix(repository, package);
    let mut incomplete = HashSet::new();
    for pending_key in state.storage.list(&prefix).await? {
        let Some(version) = pending_key
            .strip_prefix(&prefix)
            .filter(|relative| !relative.contains('/'))
            .filter(|version| !version.is_empty())
        else {
            return Err(StorageError::IntegrityViolation);
        };
        let expected = state.storage.get(&pending_key).await?;
        let expected = std::str::from_utf8(&expected)
            .ok()
            .filter(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            .ok_or(StorageError::IntegrityViolation)?;
        let manifest = match state
            .storage
            .get(&hosted_version_key(repository, package, version))
            .await
        {
            Ok(manifest) => manifest,
            Err(StorageError::NotFound) => {
                incomplete.insert(version.to_string());
                continue;
            }
            Err(error) => return Err(error),
        };
        let manifest_digest = crate::npm_layout::hosted_manifest_digest(&manifest);
        if manifest_digest != expected {
            incomplete.insert(version.to_string());
            continue;
        }
        match state
            .storage
            .get(&hosted_publish_complete_key(repository, package, version))
            .await
        {
            Ok(completion) if completion.as_ref() == expected.as_bytes() => {
                match state.storage.delete(&pending_key).await {
                    Ok(()) | Err(StorageError::NotFound) => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(_) | Err(StorageError::NotFound) => {
                incomplete.insert(version.to_string());
            }
            Err(error) => return Err(error),
        }
    }
    Ok(incomplete)
}

async fn incomplete_publish_versions(
    state: &AppState,
    repository: &str,
    package: &str,
) -> Result<HashSet<String>, StorageError> {
    let index_key = hosted_publish_pending_index_key(repository, package);
    match state.storage.get(&index_key).await {
        Ok(index) if index.as_ref() == b"1" => {}
        Ok(_) => return Err(StorageError::IntegrityViolation),
        Err(StorageError::NotFound) => state.storage.put(&index_key, b"1").await?,
        Err(error) => return Err(error),
    }
    pending_publish_versions(state, repository, package).await
}

async fn restore_publish_pending(
    state: &AppState,
    pending_key: &str,
    previous: Option<&[u8]>,
) -> Result<(), StorageError> {
    match previous {
        Some(previous) => state.storage.put(pending_key, previous).await,
        None => match state.storage.delete(pending_key).await {
            Ok(()) | Err(StorageError::NotFound) => Ok(()),
            Err(error) => Err(error),
        },
    }
}

fn incomplete_publish_response() -> Response {
    (
        StatusCode::CONFLICT,
        "Package has an incomplete publish; retry that exact publish before mutating package metadata",
    )
        .into_response()
}

fn proxy_packument_key(repository: &str, package: &str) -> String {
    format!(
        "{}/proxy/packuments/{package}.json",
        repository_prefix(repository)
    )
}

fn proxy_negative_key(repository: &str, package: &str) -> String {
    format!("{}/proxy/negative/{package}", repository_prefix(repository))
}

fn proxy_tarball_key(repository: &str, package: &str, filename: &str) -> String {
    format!(
        "{}/proxy/tarballs/{package}/{filename}",
        repository_prefix(repository)
    )
}

fn legacy_proxy(state: &AppState) -> Option<ProxyRepository> {
    Some(ProxyRepository {
        name: LEGACY_PROXY.to_string(),
        url: state.config.npm.proxy.clone()?,
        auth: state.config.npm.proxy_auth.clone(),
        metadata_ttl: state.config.npm.metadata_ttl,
        negative_ttl: 300,
    })
}

fn configured_proxy(state: &AppState, repository: &NpmRepository) -> Option<ProxyRepository> {
    match repository {
        NpmRepository::Proxy {
            name,
            url,
            auth,
            metadata_ttl,
            negative_ttl,
        } => Some(ProxyRepository {
            name: name.clone(),
            url: url.clone(),
            auth: auth.clone(),
            metadata_ttl: metadata_ttl.unwrap_or(state.config.npm.metadata_ttl),
            negative_ttl: *negative_ttl,
        }),
        _ => None,
    }
}

/// Resolve an npm upstream reference only within the configured proxy origin
/// and base path. Every initial request and redirect target passes through this
/// boundary before a request (and its configured Authorization header) is
/// built.
fn validated_proxy_url(repository: &ProxyRepository, candidate: &str) -> Option<reqwest::Url> {
    let base = reqwest::Url::parse(&repository.url).ok()?;
    let mut join_base = base.clone();
    if !join_base.path().ends_with('/') {
        join_base.set_path(&format!("{}/", join_base.path()));
    }
    let target = join_base.join(candidate).ok()?;
    if !matches!(target.scheme(), "http" | "https") {
        return None;
    }
    if !target.username().is_empty() || target.password().is_some() {
        return None;
    }
    let same_origin = base.scheme() == target.scheme()
        && base.host_str() == target.host_str()
        && base.port_or_known_default() == target.port_or_known_default();
    if !same_origin {
        return None;
    }
    let base_path = base.path().trim_end_matches('/');
    if !base_path.is_empty()
        && base_path != "/"
        && target.path() != base_path
        && !target
            .path()
            .strip_prefix(base_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
    {
        return None;
    }
    Some(target)
}

fn is_internal(state: &AppState, package: &str) -> bool {
    crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        package,
    )
}

fn is_valid_npm_package_name(name: &str) -> bool {
    // A residual percent sign means the route was encoded more than once.
    // Reject it instead of decoding repeatedly: repeated decoding can turn an
    // apparently public name into an internal scoped package only after the
    // namespace-isolation decision.
    if name.is_empty() || name.len() > 214 || name.contains(['%', '\\', '\0']) {
        return false;
    }
    if let Some(scoped) = name.strip_prefix('@') {
        let Some((scope, package)) = scoped.split_once('/') else {
            return false;
        };
        !scope.is_empty()
            && !package.is_empty()
            && !matches!(scope, "." | "..")
            && !matches!(package, "." | "..")
            && !package.contains('/')
    } else {
        !matches!(name, "." | "..") && !name.contains('/')
    }
}

fn is_valid_dist_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 214
        && !matches!(tag, "." | "..")
        && !tag.contains(['/', '\\', '\0'])
        && semver::VersionReq::parse(tag).is_err()
        && semver::Version::parse(tag.trim_start_matches('v')).is_err()
}

fn is_valid_npm_version(version: &str) -> bool {
    semver::Version::parse(version.trim_start_matches('v')).is_ok()
}

fn is_valid_attachment_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && !name.contains(['/', '\\', '\0'])
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
}

fn normalize_attachment_name<'a>(package: &str, filename: &'a str) -> &'a str {
    if let Some(scope_end) = package.find('/') {
        filename
            .strip_prefix(&package[..=scope_end])
            .unwrap_or(filename)
    } else {
        filename
    }
}

fn decode_package_name(raw: &str) -> Option<String> {
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .ok()?
        .into_owned();
    is_valid_npm_package_name(&decoded).then_some(decoded)
}

fn parse_package_path(path: &str) -> Option<(String, Option<String>)> {
    if let Some((package, filename)) = path.split_once("/-/") {
        let package = decode_package_name(package)?;
        let filename = percent_encoding::percent_decode_str(filename)
            .decode_utf8()
            .ok()?
            .into_owned();
        is_valid_attachment_name(&filename).then_some((package, Some(filename)))
    } else {
        decode_package_name(path).map(|package| (package, None))
    }
}

fn upstream_package_path(package: &str) -> String {
    package.replace('/', "%2F")
}

fn canonical_tarball_filename(package: &str, version: &str) -> String {
    format!(
        "{}-{version}.tgz",
        package.split('/').next_back().unwrap_or(package)
    )
}

fn set_tarball_url(
    version_data: &mut serde_json::Value,
    public_base: &str,
    package: &str,
    version: &str,
) {
    let Some(object) = version_data.as_object_mut() else {
        return;
    };
    let dist = object
        .entry("dist")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(dist) = dist.as_object_mut() {
        dist.insert(
            "tarball".to_string(),
            serde_json::Value::String(format!(
                "{public_base}/{package}/-/{}",
                canonical_tarball_filename(package, version)
            )),
        );
    }
}

fn json_response(headers: &HeaderMap, value: &serde_json::Value) -> Response {
    let Ok(bytes) = serde_json::to_vec(value) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let etag = format!("\"{}\"", hex::encode(sha2::Sha256::digest(&bytes)));
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|candidate| candidate.trim() == etag))
    {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::CACHE_CONTROL, "no-cache".to_string()),
            (header::ETAG, etag),
        ],
        bytes,
    )
        .into_response()
}

fn json_response_with_stale(
    headers: &HeaderMap,
    value: &serde_json::Value,
    stale: bool,
) -> Response {
    let mut response = json_response(headers, value);
    if stale {
        response
            .headers_mut()
            .insert("x-nora-stale", HeaderValue::from_static("true"));
    }
    response
}

fn tarball_response(data: Bytes) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        data,
    )
        .into_response()
}

fn read_string(bytes: Bytes) -> Option<String> {
    String::from_utf8(bytes.to_vec()).ok()
}

fn npm_publish_date_from_packument(packument: &serde_json::Value, version: &str) -> Option<i64> {
    packument
        .get("time")
        .and_then(|value| value.get(version))
        .and_then(|value| value.as_str())
        .and_then(crate::curation::parse_iso8601_to_unix)
}

async fn cached_proxy_publish_date(
    state: &AppState,
    repository: &str,
    package: &str,
    version: &str,
    filename: &str,
) -> Option<i64> {
    if state.config.server.trust_upstream_dates {
        let packument = state
            .storage
            .get(&proxy_packument_key(repository, package))
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        if let Some(date) = packument
            .as_ref()
            .and_then(|value| npm_publish_date_from_packument(value, version))
        {
            return Some(date);
        }
    }
    crate::curation::extract_mtime_as_publish_date(
        &state.storage,
        &proxy_tarball_key(repository, package, filename),
    )
    .await
}

async fn hosted_blob_key_for_version(
    state: &AppState,
    repository: &str,
    package: &str,
    version: &str,
) -> Result<String, ReadError> {
    let manifest = state
        .storage
        .get(&hosted_version_key(repository, package, version))
        .await
        .map_err(storage_read_error)?;
    crate::npm_layout::hosted_blob_key_from_manifest(repository, package, &manifest)
        .ok_or(ReadError::Corrupt)
}

async fn target_publish_date(
    state: &AppState,
    target: &RepositoryTarget,
    package: &str,
    version: &str,
    filename: &str,
) -> Result<Option<i64>, ReadError> {
    match target {
        RepositoryTarget::Named(NpmRepository::Hosted { name, .. }) => {
            let blob_key = hosted_blob_key_for_version(state, name, package, version).await?;
            Ok(crate::curation::extract_mtime_as_publish_date(&state.storage, &blob_key).await)
        }
        RepositoryTarget::Named(NpmRepository::Proxy { name, .. }) => {
            Ok(cached_proxy_publish_date(state, name, package, version, filename).await)
        }
        RepositoryTarget::Named(NpmRepository::Group { members, .. }) => {
            for member in members {
                let Some(repository) = state.config.npm.repository(member) else {
                    continue;
                };
                match repository {
                    NpmRepository::Hosted { name, .. } => {
                        if hosted_has_version(state, name, package, version).await? {
                            let blob_key =
                                hosted_blob_key_for_version(state, name, package, version).await?;
                            return Ok(crate::curation::extract_mtime_as_publish_date(
                                &state.storage,
                                &blob_key,
                            )
                            .await);
                        }
                    }
                    NpmRepository::Proxy { name, .. } if !is_internal(state, package) => {
                        let packument =
                            optional_storage_get(state, &proxy_packument_key(name, package))
                                .await?
                                .map(|bytes| {
                                    serde_json::from_slice::<serde_json::Value>(&bytes)
                                        .map_err(|_| ReadError::Corrupt)
                                })
                                .transpose()?;
                        if packument.as_ref().is_some_and(|value| {
                            value
                                .get("versions")
                                .and_then(|versions| versions.get(version))
                                .is_some()
                        }) {
                            return Ok(cached_proxy_publish_date(
                                state, name, package, version, filename,
                            )
                            .await);
                        }
                    }
                    _ => {}
                }
            }
            Ok(None)
        }
        RepositoryTarget::Legacy => {
            if hosted_has_version(state, LEGACY_HOSTED, package, version).await? {
                let blob_key =
                    hosted_blob_key_for_version(state, LEGACY_HOSTED, package, version).await?;
                Ok(crate::curation::extract_mtime_as_publish_date(&state.storage, &blob_key).await)
            } else {
                Ok(
                    cached_proxy_publish_date(state, LEGACY_PROXY, package, version, filename)
                        .await,
                )
            }
        }
    }
}

fn curated_tarball_response(
    state: &AppState,
    package: &str,
    version: &str,
    data: Bytes,
    source: &str,
    publish_date: Option<i64>,
) -> Response {
    if let Some(response) = crate::curation::verify_integrity(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        package,
        Some(version),
        &data,
    ) {
        return response;
    }
    let (mode, ttl) =
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
    if let Some(response) = crate::digest_quarantine::proxy_gate_dated(
        &state.digest_store,
        "npm",
        &data,
        &mode,
        ttl,
        source,
        publish_date,
    ) {
        return response;
    }
    tarball_response(data)
}

fn valid_cached_hosted_packument(bytes: &[u8], package: &str) -> Option<serde_json::Value> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    let object = value.as_object()?;
    (object.get("name").and_then(|value| value.as_str()) == Some(package)
        && object
            .get("versions")
            .is_some_and(|value| value.is_object())
        && object
            .get("dist-tags")
            .is_some_and(|value| value.is_object()))
    .then_some(value)
}

fn hosted_packument_response(
    mut packument: serde_json::Value,
    package: &str,
    response_base: &str,
) -> serde_json::Value {
    if let Some(versions) = packument
        .get_mut("versions")
        .and_then(|value| value.as_object_mut())
    {
        for (version, manifest) in versions {
            set_tarball_url(manifest, response_base, package, version);
        }
    }
    packument
}

async fn read_hosted_packument_cache(
    state: &AppState,
    repository: &str,
    package: &str,
) -> Result<Option<serde_json::Value>, ReadError> {
    let key = crate::npm_layout::hosted_packument_cache_key(repository, package);
    let Some(bytes) = optional_storage_get(state, &key).await? else {
        return Ok(None);
    };
    match valid_cached_hosted_packument(&bytes, package) {
        Some(packument) => Ok(Some(packument)),
        None => {
            tracing::warn!(
                repository,
                package,
                key,
                "ignoring invalid rebuildable npm hosted packument cache"
            );
            Ok(None)
        }
    }
}

async fn build_hosted_packument(
    state: &AppState,
    repository: &str,
    package: &str,
) -> Result<serde_json::Value, ReadError> {
    let prefix = package_prefix(repository, package);
    let version_prefix = format!("{prefix}/versions/");
    let version_keys = state
        .storage
        .list(&version_prefix)
        .await
        .map_err(|_| ReadError::Unavailable)?;
    let deprecation_prefix = format!("{prefix}/deprecations/");
    let deprecation_keys = state
        .storage
        .list(&deprecation_prefix)
        .await
        .map_err(|_| ReadError::Unavailable)?
        .into_iter()
        .filter_map(|key| {
            let version = key.strip_prefix(&deprecation_prefix)?.to_string();
            (!version.is_empty() && !version.contains('/')).then_some((version, key))
        })
        .collect::<HashMap<_, _>>();

    let version_reads = stream::iter(version_keys.into_iter().filter_map(|key| {
        let version = key
            .strip_prefix(&version_prefix)?
            .strip_suffix(".json")?
            .to_string();
        (!version.is_empty() && !version.contains('/')).then_some((version, key))
    }))
    .map(|(version, key)| {
        let deprecation_key = deprecation_keys.get(&version).cloned();
        async move {
            let bytes = state.storage.get(&key).await.map_err(|error| {
                match storage_read_error(error) {
                    // LIST advertised this committed manifest. Disappearing between
                    // LIST and GET is an incomplete hosted read, not permission to
                    // let a lower-priority group member shadow the version.
                    ReadError::NotFound => ReadError::Unavailable,
                    other => other,
                }
            })?;
            let mut value = serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|_| {
                crate::metrics::METADATA_CORRUPT_TOTAL
                    .with_label_values(&["npm"])
                    .inc();
                ReadError::Corrupt
            })?;
            if let Some(deprecation_key) = deprecation_key {
                let deprecated = state
                    .storage
                    .get(&deprecation_key)
                    .await
                    .map_err(storage_read_error)?;
                let Some(message) = read_string(deprecated) else {
                    return Err(ReadError::Corrupt);
                };
                let Some(object) = value.as_object_mut() else {
                    return Err(ReadError::Corrupt);
                };
                object.insert("deprecated".to_string(), serde_json::Value::String(message));
            }
            Ok::<_, ReadError>((version, value))
        }
    })
    .buffered(HOSTED_PACKUMENT_READ_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;

    let mut versions = serde_json::Map::new();
    for result in version_reads {
        let (version, value) = result?;
        versions.insert(version, value);
    }

    let mut tags = serde_json::Map::new();
    let tag_prefix = format!("{prefix}/dist-tags/");
    for key in state
        .storage
        .list(&tag_prefix)
        .await
        .map_err(|_| ReadError::Unavailable)?
    {
        let Some(tag) = key.rsplit('/').next() else {
            continue;
        };
        let value =
            state
                .storage
                .get(&key)
                .await
                .map_err(|error| match storage_read_error(error) {
                    ReadError::NotFound => ReadError::Unavailable,
                    other => other,
                })?;
        let Some(version) = read_string(value) else {
            return Err(ReadError::Corrupt);
        };
        tags.insert(tag.to_string(), serde_json::Value::String(version));
    }

    let package_fields =
        match optional_storage_get(state, &hosted_package_key(repository, package)).await? {
            Some(bytes) => Some(serde_json::from_slice::<serde_json::Value>(&bytes).map_err(
                |_| {
                    crate::metrics::METADATA_CORRUPT_TOTAL
                        .with_label_values(&["npm"])
                        .inc();
                    ReadError::Corrupt
                },
            )?),
            None => None,
        };

    if versions.is_empty() && tags.is_empty() && package_fields.is_none() {
        return Err(ReadError::NotFound);
    }

    let mut packument = package_fields.unwrap_or_else(|| serde_json::json!({}));
    let Some(object) = packument.as_object_mut() else {
        return Err(ReadError::Corrupt);
    };
    object.insert(
        "name".to_string(),
        serde_json::Value::String(package.to_string()),
    );
    object.insert("versions".to_string(), serde_json::Value::Object(versions));
    object.insert("dist-tags".to_string(), serde_json::Value::Object(tags));
    Ok(packument)
}

async fn hosted_packument(
    state: &AppState,
    repository: &str,
    package: &str,
    response_base: &str,
) -> Result<serde_json::Value, ReadError> {
    if let Some(packument) = read_hosted_packument_cache(state, repository, package).await? {
        return Ok(hosted_packument_response(packument, package, response_base));
    }

    // A cold read shares the exact package lock used by hosted mutations.
    // This prevents a cache miss from materializing stale state after a
    // concurrent mutation invalidated the previous cache.
    let lock = state.publish_lock(&format!("npm:{repository}:{package}"));
    let _guard = lock.lock().await;
    if let Some(packument) = read_hosted_packument_cache(state, repository, package).await? {
        return Ok(hosted_packument_response(packument, package, response_base));
    }

    let packument = build_hosted_packument(state, repository, package).await?;
    let key = crate::npm_layout::hosted_packument_cache_key(repository, package);
    match serde_json::to_vec(&packument) {
        Ok(bytes) => {
            if let Err(error) = state.storage.put(&key, &bytes).await {
                // The cache is derived. A failed cache write must not turn a
                // complete authoritative read into an unavailable response.
                tracing::warn!(
                    repository,
                    package,
                    key,
                    ?error,
                    "failed to persist rebuildable npm hosted packument cache"
                );
            }
        }
        Err(error) => {
            tracing::error!(
                repository,
                package,
                ?error,
                "failed to serialize npm packument"
            );
            return Err(ReadError::Corrupt);
        }
    }
    Ok(hosted_packument_response(packument, package, response_base))
}

fn negative_fresh(modified: u64, ttl: i64) -> bool {
    if ttl <= 0 {
        return false;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(modified) < ttl as u64
}

async fn proxy_packument_raw(
    state: &AppState,
    repository: &ProxyRepository,
    package: &str,
) -> Result<PackumentRead, ReadError> {
    if is_internal(state, package) {
        return Err(ReadError::NotFound);
    }

    let key = proxy_packument_key(&repository.name, package);
    let negative_key = proxy_negative_key(&repository.name, package);
    if state
        .storage
        .stat(&negative_key)
        .await
        .is_some_and(|meta| negative_fresh(meta.modified, repository.negative_ttl))
    {
        return Err(ReadError::NotFound);
    }

    let cached = state.storage.get(&key).await.ok();
    let fresh = cached.is_some()
        && state
            .storage
            .stat(&key)
            .await
            .is_some_and(|meta| negative_fresh(meta.modified, repository.metadata_ttl));
    if fresh {
        return serde_json::from_slice(cached.as_ref().expect("cached when fresh"))
            .map(PackumentRead::fresh)
            .map_err(|_| ReadError::Corrupt);
    }

    // A singleton Nora still receives concurrent cold misses. Serialize the
    // refresh for this package so a slower, older upstream response cannot
    // overwrite a newer one.
    let refresh_lock = state.publish_lock(&format!("npm-proxy:{}:{package}", repository.name));
    let _refresh_guard = refresh_lock.lock().await;
    let cached = state.storage.get(&key).await.ok();
    let fresh = cached.is_some()
        && state
            .storage
            .stat(&key)
            .await
            .is_some_and(|meta| negative_fresh(meta.modified, repository.metadata_ttl));
    if fresh {
        return serde_json::from_slice(cached.as_ref().expect("cached when fresh"))
            .map(PackumentRead::fresh)
            .map_err(|_| ReadError::Corrupt);
    }

    let url = format!(
        "{}/{}",
        repository.url.trim_end_matches('/'),
        upstream_package_path(package)
    );
    let validators = if state.config.npm.revalidate {
        read_validators(&state.storage, &key)
            .await
            .unwrap_or_default()
    } else {
        Validators::default()
    };
    let had_validators = validators.is_some();
    let fetched = proxy_fetch_conditional_with_validated_redirects(
        &state.no_redirect_http_client,
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        expose_opt(&repository.auth),
        &validators,
        &state.circuit_breaker,
        RegistryType::Npm,
        MAX_NPM_PROXY_REDIRECTS,
        |next_url| validated_proxy_url(repository, next_url.as_str()).is_some(),
    )
    .await;

    match fetched {
        Ok(Revalidation::NotModified) => {
            let Some(data) = cached else {
                if had_validators {
                    crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                        .with_label_values(&["npm"])
                        .inc();
                }
                return Err(ReadError::Unavailable);
            };
            crate::metrics::PROXY_UPSTREAM_304_TOTAL
                .with_label_values(&["npm"])
                .inc();
            crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                .with_label_values(&["npm"])
                .inc_by(data.len() as u64);
            // Touching the body after 304 is intentional: its mtime is the
            // freshness marker, while the validator sidecar remains unchanged.
            state
                .storage
                .put(&key, &data)
                .await
                .map_err(|_| ReadError::Unavailable)?;
            serde_json::from_slice(&data)
                .map(PackumentRead::fresh)
                .map_err(|_| ReadError::Corrupt)
        }
        Ok(Revalidation::Modified { body, validators }) => {
            let value = serde_json::from_slice::<serde_json::Value>(&body)
                .map_err(|_| ReadError::Corrupt)?;
            state
                .storage
                .put(&key, &body)
                .await
                .map_err(|_| ReadError::Unavailable)?;
            write_validators(&state.storage, &key, &validators).await;
            state.repo_index.invalidate("npm");
            if state.storage.stat(&negative_key).await.is_some() {
                let _ = state.storage.delete(&negative_key).await;
            }
            Ok(PackumentRead::fresh(value))
        }
        Err(ProxyError::NotFound) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["npm"])
                    .inc();
            }
            if repository.negative_ttl > 0 {
                let _ = state.storage.put(&negative_key, b"not-found").await;
            }
            Err(ReadError::NotFound)
        }
        Err(ProxyError::CircuitOpen(name)) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["npm"])
                    .inc();
            }
            if state.config.npm.serve_stale {
                if let Some(data) = cached {
                    return serde_json::from_slice(&data)
                        .map(|value| PackumentRead { value, stale: true })
                        .map_err(|_| ReadError::Corrupt);
                }
            }
            Err(ReadError::CircuitOpen(name))
        }
        Err(_) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["npm"])
                    .inc();
            }
            if state.config.npm.serve_stale {
                if let Some(data) = cached {
                    return serde_json::from_slice(&data)
                        .map(|value| PackumentRead { value, stale: true })
                        .map_err(|_| ReadError::Corrupt);
                }
            }
            Err(ReadError::Unavailable)
        }
    }
}

fn rewrite_packument_urls(
    mut packument: serde_json::Value,
    response_base: &str,
    package: &str,
    upstream_base: &str,
) -> serde_json::Value {
    fn rewrite_upstream_values(value: &mut serde_json::Value, upstream: &str, public: &str) {
        match value {
            serde_json::Value::String(text) => {
                let upstream = upstream.trim_end_matches('/');
                if text == upstream {
                    *text = public.trim_end_matches('/').to_string();
                } else if let Some(suffix) = text.strip_prefix(upstream) {
                    if suffix.starts_with('/') || suffix.starts_with('?') || suffix.starts_with('#')
                    {
                        *text = format!("{}{}", public.trim_end_matches('/'), suffix);
                    }
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    rewrite_upstream_values(value, upstream, public);
                }
            }
            serde_json::Value::Object(object) => {
                for value in object.values_mut() {
                    rewrite_upstream_values(value, upstream, public);
                }
            }
            _ => {}
        }
    }

    // Proxy-specific custom fields can contain absolute Nexus/upstream URLs.
    // Rewrite complete string values with a path-boundary prefix; never byte
    // replace arbitrary substrings inside descriptions or scripts.
    rewrite_upstream_values(&mut packument, upstream_base, response_base);
    if let Some(versions) = packument
        .get_mut("versions")
        .and_then(serde_json::Value::as_object_mut)
    {
        for (version, data) in versions {
            set_tarball_url(data, response_base, package, version);
        }
    }
    packument
}

fn merge_packuments(
    package: &str,
    response_base: &str,
    packuments: Vec<serde_json::Value>,
) -> Result<serde_json::Value, ReadError> {
    let mut result = serde_json::Map::new();
    let mut versions = serde_json::Map::new();
    let mut tags = serde_json::Map::new();
    let mut any = false;

    for packument in packuments {
        let Some(mut object) = packument.as_object().cloned() else {
            return Err(ReadError::Corrupt);
        };
        any = true;
        if let Some(member_versions) = object
            .remove("versions")
            .and_then(|value| value.as_object().cloned())
        {
            for (version, mut data) in member_versions {
                if versions.contains_key(&version) {
                    continue;
                }
                set_tarball_url(&mut data, response_base, package, &version);
                versions.insert(version, data);
            }
        }
        if let Some(member_tags) = object
            .remove("dist-tags")
            .and_then(|value| value.as_object().cloned())
        {
            for (tag, target) in member_tags {
                tags.entry(tag).or_insert(target);
            }
        }
        for (field, value) in object {
            result.entry(field).or_insert(value);
        }
    }

    if !any {
        return Err(ReadError::NotFound);
    }
    result.insert(
        "name".to_string(),
        serde_json::Value::String(package.to_string()),
    );
    result.insert("versions".to_string(), serde_json::Value::Object(versions));
    result.insert("dist-tags".to_string(), serde_json::Value::Object(tags));
    Ok(serde_json::Value::Object(result))
}

async fn group_packument(
    state: &AppState,
    members: &[String],
    package: &str,
    response_base: &str,
) -> Result<PackumentRead, ReadError> {
    let mut packuments = Vec::new();
    let mut stale = false;
    for member in members {
        let Some(repository) = state.config.npm.repository(member).cloned() else {
            continue;
        };
        let result = match repository {
            NpmRepository::Hosted { name, .. } => {
                hosted_packument(state, &name, package, response_base)
                    .await
                    .map(PackumentRead::fresh)
            }
            NpmRepository::Proxy { .. } if is_internal(state, package) => Err(ReadError::NotFound),
            NpmRepository::Proxy { .. } => {
                let proxy = configured_proxy(state, &repository).expect("proxy config");
                proxy_packument_raw(state, &proxy, package)
                    .await
                    .map(|read| PackumentRead {
                        value: rewrite_packument_urls(
                            read.value,
                            response_base,
                            package,
                            &proxy.url,
                        ),
                        stale: read.stale,
                    })
            }
            NpmRepository::Group { .. } => continue,
        };
        match result {
            Ok(packument) => {
                stale |= packument.stale;
                packuments.push(packument.value);
            }
            Err(ReadError::NotFound) => {}
            Err(error) if packuments.is_empty() => return Err(error),
            // A later member cannot override data already selected from an
            // earlier member. Return the safe hosted/warm prefix rather than
            // turning a lower-priority proxy outage into hosted downtime.
            Err(_) => break,
        }
    }
    if packuments.is_empty() {
        return Err(ReadError::NotFound);
    }
    merge_packuments(package, response_base, packuments).map(|value| PackumentRead { value, stale })
}

async fn target_packument(
    state: &AppState,
    target: &RepositoryTarget,
    package: &str,
    response_base: &str,
) -> Result<PackumentRead, ReadError> {
    match target {
        RepositoryTarget::Named(NpmRepository::Hosted { name, .. }) => {
            hosted_packument(state, name, package, response_base)
                .await
                .map(PackumentRead::fresh)
        }
        RepositoryTarget::Named(repository @ NpmRepository::Proxy { .. }) => {
            let proxy = configured_proxy(state, repository).expect("proxy config");
            proxy_packument_raw(state, &proxy, package)
                .await
                .map(|read| PackumentRead {
                    value: rewrite_packument_urls(read.value, response_base, package, &proxy.url),
                    stale: read.stale,
                })
        }
        RepositoryTarget::Named(NpmRepository::Group { members, .. }) => {
            group_packument(state, members, package, response_base).await
        }
        RepositoryTarget::Legacy => {
            let mut packuments = Vec::new();
            let mut stale = false;
            match hosted_packument(state, LEGACY_HOSTED, package, response_base).await {
                Ok(hosted) => packuments.push(hosted),
                Err(ReadError::NotFound) => {}
                Err(error) => return Err(error),
            }
            if !is_internal(state, package) {
                if let Some(proxy) = legacy_proxy(state) {
                    match proxy_packument_raw(state, &proxy, package).await {
                        Ok(read) => {
                            stale |= read.stale;
                            packuments.push(rewrite_packument_urls(
                                read.value,
                                response_base,
                                package,
                                &proxy.url,
                            ))
                        }
                        Err(ReadError::NotFound) => {}
                        Err(error) if packuments.is_empty() => return Err(error),
                        Err(_) => {}
                    }
                }
            }
            if packuments.is_empty() {
                return Err(ReadError::NotFound);
            }
            merge_packuments(package, response_base, packuments)
                .map(|value| PackumentRead { value, stale })
        }
    }
}

fn read_error_response(error: ReadError) -> Response {
    match error {
        ReadError::NotFound => StatusCode::NOT_FOUND.into_response(),
        ReadError::CircuitOpen(name) => circuit_open_response(&name),
        ReadError::Unavailable => StatusCode::BAD_GATEWAY.into_response(),
        ReadError::Corrupt => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        ReadError::SearchScanLimit => (
            StatusCode::BAD_GATEWAY,
            "upstream npm search exceeded the bounded scan budget",
        )
            .into_response(),
    }
}

async fn hosted_has_version(
    state: &AppState,
    repository: &str,
    package: &str,
    version: &str,
) -> Result<bool, ReadError> {
    optional_storage_get(state, &hosted_version_key(repository, package, version))
        .await
        .map(|manifest| manifest.is_some())
}

fn dist_digest_matches(data: &[u8], version_data: &serde_json::Value) -> bool {
    let Some(dist) = version_data.get("dist") else {
        return false;
    };
    let mut verified = false;
    if let Some(shasum) = dist.get("shasum").and_then(|value| value.as_str()) {
        // SHA-1 is required by the npm packument protocol for legacy clients.
        if !shasum.eq_ignore_ascii_case(&hex::encode(sha1::Sha1::digest(data))) {
            return false;
        }
        verified = true;
    }
    if let Some(integrity) = dist.get("integrity").and_then(|value| value.as_str()) {
        let expected = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(data))
        );
        let has_sha512 = integrity
            .split_ascii_whitespace()
            .any(|candidate| candidate.starts_with("sha512-"));
        if has_sha512
            && !integrity
                .split_ascii_whitespace()
                .any(|candidate| candidate == expected)
        {
            return false;
        }
        verified |= has_sha512;
    }
    verified
}

async fn serve_hosted_tarball(
    state: &AppState,
    repository: &str,
    package: &str,
    filename: &str,
    publish_date: Option<i64>,
) -> Response {
    let Some(version) = crate::curation::parse_npm_tarball_version(package, filename) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let manifest = match state
        .storage
        .get(&hosted_version_key(repository, package, &version))
        .await
    {
        Ok(manifest) => manifest,
        Err(error) => return read_error_response(storage_read_error(error)),
    };
    let Ok(version_data) = serde_json::from_slice::<serde_json::Value>(&manifest) else {
        crate::metrics::METADATA_CORRUPT_TOTAL
            .with_label_values(&["npm"])
            .inc();
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Some(key) =
        crate::npm_layout::hosted_blob_key_from_manifest(repository, package, &manifest)
    else {
        crate::metrics::METADATA_CORRUPT_TOTAL
            .with_label_values(&["npm"])
            .inc();
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let data = match state.storage.get(&key).await {
        Ok(data) => data,
        Err(StorageError::IntegrityViolation) => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    if !dist_digest_matches(&data, &version_data) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    curated_tarball_response(state, package, &version, data, "hosted", publish_date)
}

async fn serve_proxy_tarball(
    state: &AppState,
    repository: &ProxyRepository,
    package: &str,
    filename: &str,
    publish_date: Option<i64>,
) -> Response {
    if is_internal(state, package) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(version) = crate::curation::parse_npm_tarball_version(package, filename) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let packument = match proxy_packument_raw(state, repository, package).await {
        Ok(value) => value,
        Err(error) => return read_error_response(error),
    };
    let Some(version_data) = packument
        .value
        .get("versions")
        .and_then(|value| value.get(&version))
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(candidate_url) = version_data
        .get("dist")
        .and_then(|value| value.get("tarball"))
        .and_then(|value| value.as_str())
    else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let Some(url) = validated_proxy_url(repository, candidate_url) else {
        tracing::warn!(
            repository = %repository.name,
            package,
            version,
            "npm proxy rejected tarball URL outside configured upstream origin/base path"
        );
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let key = proxy_tarball_key(&repository.name, package, filename);
    let cached = state.storage.get(&key).await.ok();
    if let Some(data) = &cached {
        if dist_digest_matches(data, version_data) {
            state.metrics.record_cache_hit("npm");
            state.activity.push(ActivityEntry::new(
                ActionType::CacheHit,
                package.to_string(),
                RegistryType::Npm,
                "CACHE",
            ));
            state.audit.log(AuditEntry::new(
                "cache_hit",
                "api",
                package,
                "npm",
                &repository.name,
            ));
            return curated_tarball_response(
                state,
                package,
                &version,
                data.clone(),
                "cache",
                publish_date,
            );
        }
    }

    // Packument refresh has its own package lock, but the immutable tarball is
    // a separate cold miss. Preserve the existing single-flight behavior so a
    // CI fan-out performs one upstream transfer and one cache create.
    let circuit_name = std::sync::Arc::new(parking_lot::Mutex::new(None::<String>));
    let observed_circuit = std::sync::Arc::clone(&circuit_name);
    let fetch = || async {
        match proxy_fetch_with_validated_redirects(
            &state.no_redirect_http_client,
            url.as_str(),
            Duration::from_secs(state.config.npm.proxy_timeout),
            expose_opt(&repository.auth),
            &state.circuit_breaker,
            RegistryType::Npm,
            MAX_NPM_PROXY_REDIRECTS,
            |next_url| validated_proxy_url(repository, next_url.as_str()).is_some(),
        )
        .await
        {
            Ok(data) if dist_digest_matches(&data, version_data) => {
                let bytes = Bytes::from(data);
                if state.storage.put(&key, &bytes).await.is_err() {
                    return None;
                }
                state.repo_index.invalidate("npm");
                state.metrics.record_cache_miss("npm");
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    package.to_string(),
                    RegistryType::Npm,
                    "PROXY",
                ));
                state.audit.log(AuditEntry::new(
                    "proxy_fetch",
                    "api",
                    package,
                    "npm",
                    &repository.name,
                ));
                Some(bytes)
            }
            Ok(_) => {
                tracing::warn!(
                    repository = %repository.name,
                    package,
                    version,
                    "npm proxy tarball digest mismatch"
                );
                None
            }
            Err(ProxyError::CircuitOpen(name)) => {
                *observed_circuit.lock() = Some(name);
                None
            }
            Err(error) => {
                tracing::debug!(
                    repository = %repository.name,
                    package,
                    version,
                    error = ?error,
                    "npm proxy tarball fetch failed"
                );
                None
            }
        }
    };
    let fetched = if state.config.server.proxy_coalesce {
        state
            .proxy_coalesce
            .coalesced(
                &key,
                "npm",
                crate::proxy_coalesce::follower_budget(state.config.npm.proxy_timeout),
                fetch,
            )
            .await
    } else {
        fetch().await
    };
    if let Some(data) = fetched {
        return curated_tarball_response(
            state,
            package,
            &version,
            data,
            url.as_str(),
            publish_date,
        );
    }
    let circuit_name = circuit_name.lock().clone();
    if let Some(name) = circuit_name {
        circuit_open_response(&name)
    } else {
        StatusCode::BAD_GATEWAY.into_response()
    }
}

async fn group_tarball(
    state: &AppState,
    members: &[String],
    package: &str,
    filename: &str,
    publish_date: Option<i64>,
) -> Response {
    let Some(version) = crate::curation::parse_npm_tarball_version(package, filename) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    for member in members {
        let Some(repository) = state.config.npm.repository(member).cloned() else {
            continue;
        };
        match repository {
            NpmRepository::Hosted { name, .. } => {
                match hosted_has_version(state, &name, package, &version).await {
                    Ok(true) => {
                        // Once a member claims the version, its tarball is the
                        // only legal origin. Do not fall through after an
                        // incomplete or corrupt member.
                        return serve_hosted_tarball(state, &name, package, filename, publish_date)
                            .await;
                    }
                    Ok(false) => {}
                    Err(error) => return read_error_response(error),
                }
            }
            NpmRepository::Proxy { .. } if !is_internal(state, package) => {
                let proxy = configured_proxy(state, &repository).expect("proxy config");
                match proxy_packument_raw(state, &proxy, package).await {
                    Ok(packument)
                        if packument
                            .value
                            .get("versions")
                            .and_then(|value| value.get(&version))
                            .is_some() =>
                    {
                        return serve_proxy_tarball(state, &proxy, package, filename, publish_date)
                            .await;
                    }
                    Ok(_) | Err(ReadError::NotFound) => {}
                    Err(error) => return read_error_response(error),
                }
            }
            _ => {}
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn target_tarball(
    state: &AppState,
    target: &RepositoryTarget,
    package: &str,
    filename: &str,
    publish_date: Option<i64>,
) -> Response {
    match target {
        RepositoryTarget::Named(NpmRepository::Hosted { name, .. }) => {
            serve_hosted_tarball(state, name, package, filename, publish_date).await
        }
        RepositoryTarget::Named(repository @ NpmRepository::Proxy { .. }) => {
            let proxy = configured_proxy(state, repository).expect("proxy config");
            serve_proxy_tarball(state, &proxy, package, filename, publish_date).await
        }
        RepositoryTarget::Named(NpmRepository::Group { members, .. }) => {
            group_tarball(state, members, package, filename, publish_date).await
        }
        RepositoryTarget::Legacy => {
            let Some(version) = crate::curation::parse_npm_tarball_version(package, filename)
            else {
                return StatusCode::NOT_FOUND.into_response();
            };
            match hosted_has_version(state, LEGACY_HOSTED, package, &version).await {
                Ok(true) => {
                    return serve_hosted_tarball(
                        state,
                        LEGACY_HOSTED,
                        package,
                        filename,
                        publish_date,
                    )
                    .await
                }
                Ok(false) => {}
                Err(error) => return read_error_response(error),
            }
            if let Some(proxy) = legacy_proxy(state) {
                serve_proxy_tarball(state, &proxy, package, filename, publish_date).await
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
    }
}

#[derive(Debug, Clone)]
struct SearchRequest {
    text: String,
    from: usize,
    size: usize,
}

fn parse_search_request(query: Option<&str>) -> SearchRequest {
    let mut request = SearchRequest {
        text: String::new(),
        from: 0,
        size: 20,
    };
    let Ok(url) = reqwest::Url::parse(&format!("http://localhost/?{}", query.unwrap_or_default()))
    else {
        return request;
    };
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "text" => request.text = value.into_owned(),
            "from" => request.from = value.parse().unwrap_or(0),
            "size" => request.size = value.parse().unwrap_or(20),
            _ => {}
        }
    }
    request.size = request.size.clamp(1, 250);
    request
}

fn search_query_with_window(query: Option<&str>, from: usize, size: usize) -> String {
    let mut url = reqwest::Url::parse("http://localhost/").expect("static URL");
    {
        let mut pairs = url.query_pairs_mut();
        if let Some(query) = query {
            if let Ok(source) = reqwest::Url::parse(&format!("http://localhost/?{query}")) {
                for (key, value) in source.query_pairs() {
                    if key != "from" && key != "size" {
                        pairs.append_pair(&key, &value);
                    }
                }
            }
        }
        pairs.append_pair("from", &from.to_string());
        pairs.append_pair("size", &size.clamp(1, 250).to_string());
    }
    url.query().unwrap_or_default().to_string()
}

fn search_matches(packument: &serde_json::Value, latest: &serde_json::Value, text: &str) -> bool {
    let terms: Vec<String> = text
        .split_whitespace()
        .map(|term| term.to_ascii_lowercase())
        .collect();
    if terms.is_empty() {
        return true;
    }
    let mut fields = Vec::new();
    for field in ["name", "description"] {
        if let Some(value) = packument
            .get(field)
            .or_else(|| latest.get(field))
            .and_then(|value| value.as_str())
        {
            fields.push(value.to_ascii_lowercase());
        }
    }
    for source in [packument, latest] {
        if let Some(keywords) = source.get("keywords") {
            match keywords {
                serde_json::Value::Array(values) => fields.extend(
                    values
                        .iter()
                        .filter_map(|value| value.as_str())
                        .map(str::to_ascii_lowercase),
                ),
                serde_json::Value::String(value) => fields.push(value.to_ascii_lowercase()),
                _ => {}
            }
        }
    }
    terms
        .iter()
        .all(|term| fields.iter().any(|field| field.contains(term)))
}

fn search_targets_internal(state: &AppState, text: &str) -> bool {
    let text = text.trim();
    if text.is_empty() {
        return false;
    }
    if text_contains_internal_package(text, &state.curation().curation_engine) {
        return true;
    }
    text.split_whitespace().any(|term| {
        let term = term.trim_matches(|character| {
            matches!(
                character,
                '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ','
            )
        });
        if is_internal(state, term) {
            return true;
        }
        let Some(scope) = term.strip_prefix("scope:") else {
            return false;
        };
        let scope = if scope.starts_with('@') {
            scope.to_string()
        } else {
            format!("@{scope}")
        };
        is_internal(state, &format!("{scope}/__nora_search__"))
    })
}

fn search_query_targets_internal(state: &AppState, query: Option<&str>) -> bool {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return false;
    };
    let Ok(url) = reqwest::Url::parse(&format!("http://localhost/?{query}")) else {
        // A query we cannot classify must never be forwarded: doing so would
        // turn parser disagreement into a namespace-isolation bypass.
        return true;
    };
    url.query_pairs().any(|(key, value)| {
        (key == "text" && search_targets_internal(state, &value))
            || text_contains_internal_package(&key, &state.curation().curation_engine)
            || text_contains_internal_package(&value, &state.curation().curation_engine)
    })
}

async fn hosted_search_object(
    state: &AppState,
    repository: &str,
    package: &str,
    response_base: &str,
    request: &SearchRequest,
) -> Result<Option<serde_json::Value>, ReadError> {
    let version_prefix = format!("{}/versions/", package_prefix(repository, package));
    let version_keys = state
        .storage
        .list(&version_prefix)
        .await
        .map_err(|_| ReadError::Unavailable)?;
    if version_keys.len() > NPM_SEARCH_SCAN_RESULT_CAP {
        return Err(ReadError::SearchScanLimit);
    }
    let versions: HashSet<String> = version_keys
        .iter()
        .filter_map(|key| {
            key.strip_prefix(&version_prefix)?
                .strip_suffix(".json")
                .filter(|version| !version.is_empty() && !version.contains('/'))
                .map(str::to_string)
        })
        .collect();
    if versions.is_empty() {
        return Ok(None);
    }
    let tagged_latest =
        match optional_storage_get(state, &hosted_tag_key(repository, package, "latest")).await? {
            Some(bytes) => Some(read_string(bytes).ok_or(ReadError::Corrupt)?),
            None => None,
        };
    let latest_version = tagged_latest
        .filter(|version| versions.contains(version))
        .or_else(|| {
            versions
                .iter()
                .filter_map(|version| {
                    semver::Version::parse(version.trim_start_matches('v'))
                        .ok()
                        .map(|parsed| (parsed, version.clone()))
                })
                .max_by(|left, right| left.0.cmp(&right.0))
                .map(|(_, version)| version)
        });
    let Some(version) = latest_version else {
        return Ok(None);
    };
    let manifest = state
        .storage
        .get(&hosted_version_key(repository, package, &version))
        .await
        .map_err(storage_read_error)?;
    let latest =
        serde_json::from_slice::<serde_json::Value>(&manifest).map_err(|_| ReadError::Corrupt)?;
    let packument =
        match optional_storage_get(state, &hosted_package_key(repository, package)).await? {
            Some(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
                .map_err(|_| ReadError::Corrupt)?,
            None => serde_json::json!({"name": package}),
        };
    if !search_matches(&packument, &latest, &request.text) {
        return Ok(None);
    }
    let mut package_data = serde_json::Map::new();
    package_data.insert(
        "name".to_string(),
        serde_json::Value::String(package.to_string()),
    );
    package_data.insert("version".to_string(), serde_json::Value::String(version));
    for field in ["description", "keywords", "publisher", "maintainers"] {
        if let Some(value) = packument.get(field).or_else(|| latest.get(field)) {
            package_data.insert(field.to_string(), value.clone());
        }
    }
    package_data
        .entry("maintainers".to_string())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    package_data.insert(
        "links".to_string(),
        serde_json::json!({"npm": format!("{response_base}/{package}")}),
    );
    Ok(Some(serde_json::json!({
        "package": package_data,
        "score": {
            "final": 1.0,
            "detail": {"quality": 1.0, "popularity": 0.0, "maintenance": 1.0}
        },
        "searchScore": 1.0
    })))
}

async fn hosted_search_objects(
    state: &AppState,
    repository: &str,
    response_base: &str,
    request: &SearchRequest,
    deadline: Instant,
) -> Result<Vec<serde_json::Value>, ReadError> {
    // Protocol search needs a strict index read: stale-on-error is useful for
    // the UI, but would silently turn a hosted member failure into an empty
    // successful protocol result.
    let index = tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        state.repo_index.get_strict("npm", &state.storage),
    )
    .await
    .map_err(|_| ReadError::SearchScanLimit)?
    .map_err(|_| ReadError::Unavailable)?;
    let prefix = format!("repositories/{repository}/");
    let packages: Vec<String> = index
        .iter()
        .filter_map(|entry| entry.name.strip_prefix(&prefix).map(str::to_string))
        .collect();
    if packages.len() > NPM_SEARCH_SCAN_RESULT_CAP {
        return Err(ReadError::SearchScanLimit);
    }
    let mut objects = Vec::new();
    for package in packages {
        let object = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            hosted_search_object(state, repository, &package, response_base, request),
        )
        .await
        .map_err(|_| ReadError::SearchScanLimit)??;
        if let Some(object) = object {
            objects.push(object);
        }
    }
    objects.sort_by(|left, right| {
        left["package"]["name"]
            .as_str()
            .cmp(&right["package"]["name"].as_str())
    });
    Ok(objects)
}

#[derive(Debug)]
struct ProxySearchPage {
    objects: Vec<serde_json::Value>,
    raw_count: usize,
    total: usize,
    total_is_approximate: bool,
}

fn public_proxy_search_page(
    state: &AppState,
    response: serde_json::Value,
) -> Result<ProxySearchPage, ReadError> {
    let Some(objects) = response.get("objects").and_then(|value| value.as_array()) else {
        return Err(ReadError::Corrupt);
    };
    let Some(total) = response
        .get("total")
        .and_then(|value| value.as_u64())
        .and_then(|value| usize::try_from(value).ok())
    else {
        return Err(ReadError::Corrupt);
    };
    let public = objects
        .iter()
        .filter(|object| {
            object
                .get("package")
                .and_then(|package| package.get("name"))
                .and_then(|value| value.as_str())
                .is_some_and(|package| !is_internal(state, package))
        })
        .cloned()
        .collect();
    Ok(ProxySearchPage {
        objects: public,
        raw_count: objects.len(),
        total,
        total_is_approximate: false,
    })
}

async fn proxy_search_page(
    state: &AppState,
    repository: &ProxyRepository,
    query: Option<&str>,
) -> Result<ProxySearchPage, ReadError> {
    let candidate = match query {
        Some(query) if !query.is_empty() => format!("-/v1/search?{query}"),
        _ => "-/v1/search".to_string(),
    };
    let Some(url) = validated_proxy_url(repository, &candidate) else {
        return Err(ReadError::Unavailable);
    };
    let body = proxy_fetch_with_validated_redirects_bounded(
        &state.no_redirect_http_client,
        url.as_str(),
        Duration::from_secs(state.config.npm.proxy_timeout),
        expose_opt(&repository.auth),
        &state.circuit_breaker,
        RegistryType::Npm,
        MAX_NPM_PROXY_REDIRECTS,
        NPM_SEARCH_BODY_CAP,
        |next_url| validated_proxy_url(repository, next_url.as_str()).is_some(),
    )
    .await
    .map_err(|error| match error {
        ProxyError::NotFound => ReadError::NotFound,
        ProxyError::CircuitOpen(name) => ReadError::CircuitOpen(name),
        _ => ReadError::Unavailable,
    })?;
    let response = serde_json::from_slice(&body).map_err(|_| ReadError::Corrupt)?;
    public_proxy_search_page(state, response)
}

async fn proxy_search_page_before(
    state: &AppState,
    repository: &ProxyRepository,
    query: Option<&str>,
    deadline: Instant,
) -> Result<ProxySearchPage, ReadError> {
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Err(ReadError::SearchScanLimit);
    };
    tokio::time::timeout(remaining, proxy_search_page(state, repository, query))
        .await
        .map_err(|_| ReadError::SearchScanLimit)?
}

async fn proxy_search_window(
    state: &AppState,
    repository: &ProxyRepository,
    query: Option<&str>,
    request: &SearchRequest,
    scan_deadline: Option<Instant>,
) -> Result<ProxySearchPage, ReadError> {
    let filter_active = crate::curation::namespace_filter_active(&state.curation().curation_engine);
    if !filter_active {
        let query = search_query_with_window(query, request.from, request.size);
        return proxy_search_page(state, repository, Some(&query)).await;
    }
    let deadline = scan_deadline.ok_or(ReadError::SearchScanLimit)?;
    let mut cursor = 0usize;
    let mut total = None;
    let needed = request.from.saturating_add(request.size);
    let mut objects = Vec::with_capacity(needed.min(250));
    let mut scanned = 0usize;
    let mut pages = 0usize;
    while objects.len() < needed {
        if pages >= NPM_SEARCH_SCAN_PAGE_CAP || scanned >= NPM_SEARCH_SCAN_RESULT_CAP {
            return Err(ReadError::SearchScanLimit);
        }
        let page_size = (NPM_SEARCH_SCAN_RESULT_CAP - scanned).min(250);
        let query = search_query_with_window(query, cursor, page_size);
        let page = proxy_search_page_before(state, repository, Some(&query), deadline).await?;
        pages = pages.saturating_add(1);
        let upstream_total = *total.get_or_insert(page.total);
        let raw_count = page.raw_count;
        scanned = scanned
            .checked_add(raw_count)
            .filter(|scanned| *scanned <= NPM_SEARCH_SCAN_RESULT_CAP)
            .ok_or(ReadError::SearchScanLimit)?;
        let remaining = needed - objects.len();
        objects.extend(page.objects.into_iter().take(remaining));
        if raw_count == 0 || cursor.saturating_add(raw_count) >= upstream_total {
            break;
        }
        cursor = cursor.saturating_add(raw_count);
    }
    let objects: Vec<serde_json::Value> = objects
        .into_iter()
        .skip(request.from)
        .take(request.size)
        .collect();
    Ok(ProxySearchPage {
        raw_count: objects.len(),
        objects,
        total: total.unwrap_or(0),
        total_is_approximate: filter_active,
    })
}

async fn proxy_search_group_prefix(
    state: &AppState,
    repository: &ProxyRepository,
    query: Option<&str>,
    already_seen: &HashSet<String>,
    already_collected: usize,
    needed: usize,
    deadline: Instant,
) -> Result<ProxySearchPage, ReadError> {
    let mut cursor = 0usize;
    let mut total = None;
    let mut objects = Vec::new();
    let mut seen = already_seen.clone();
    let mut scanned = 0usize;
    let mut pages = 0usize;
    loop {
        if pages >= NPM_SEARCH_SCAN_PAGE_CAP || scanned >= NPM_SEARCH_SCAN_RESULT_CAP {
            return Err(ReadError::SearchScanLimit);
        }
        let query = search_query_with_window(
            query,
            cursor,
            (NPM_SEARCH_SCAN_RESULT_CAP - scanned).min(250),
        );
        let page = proxy_search_page_before(state, repository, Some(&query), deadline).await?;
        pages = pages.saturating_add(1);
        let upstream_total = *total.get_or_insert(page.total);
        let raw_count = page.raw_count;
        scanned = scanned
            .checked_add(raw_count)
            .filter(|scanned| *scanned <= NPM_SEARCH_SCAN_RESULT_CAP)
            .ok_or(ReadError::SearchScanLimit)?;
        for object in page.objects {
            let Some(package) = object
                .get("package")
                .and_then(|package| package.get("name"))
                .and_then(|value| value.as_str())
            else {
                continue;
            };
            if seen.insert(package.to_string()) {
                objects.push(object);
            }
        }
        if already_collected.saturating_add(objects.len()) >= needed
            || cursor.saturating_add(raw_count) >= upstream_total
        {
            break;
        }
        if raw_count == 0 {
            return Err(ReadError::Corrupt);
        }
        cursor = cursor.saturating_add(raw_count);
    }
    Ok(ProxySearchPage {
        raw_count: objects.len(),
        objects,
        total: total.unwrap_or(0),
        total_is_approximate: true,
    })
}

fn search_response(
    headers: &HeaderMap,
    objects: Vec<serde_json::Value>,
    request: &SearchRequest,
    total: usize,
    already_paged: bool,
    total_is_approximate: bool,
) -> Response {
    let page = if already_paged {
        objects.into_iter().take(request.size).collect::<Vec<_>>()
    } else {
        objects
            .into_iter()
            .skip(request.from)
            .take(request.size)
            .collect::<Vec<_>>()
    };
    json_response(
        headers,
        &serde_json::json!({
            "objects": page,
            "total": total,
            "time": "0ms",
            "totalIsApproximate": total_is_approximate
        }),
    )
}

async fn handle_search(
    state: &AppState,
    target: &RepositoryTarget,
    response_base: &str,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Response {
    let request = parse_search_request(query);
    let internal_only = search_query_targets_internal(state, query);
    let needed = request.from.saturating_add(request.size);
    let filter_active = crate::curation::namespace_filter_active(&state.curation().curation_engine);
    let needs_bounded_proxy_scan = match target {
        RepositoryTarget::Named(NpmRepository::Proxy { .. }) => filter_active && !internal_only,
        RepositoryTarget::Named(NpmRepository::Group { members, .. }) => {
            !internal_only
                && members.iter().any(|member| {
                    matches!(
                        state.config.npm.repository(member),
                        Some(NpmRepository::Proxy { .. })
                    )
                })
        }
        RepositoryTarget::Legacy => !internal_only && legacy_proxy(state).is_some(),
        RepositoryTarget::Named(NpmRepository::Hosted { .. }) => false,
    };
    if needs_bounded_proxy_scan && needed > NPM_SEARCH_SCAN_RESULT_CAP {
        return (
            StatusCode::BAD_REQUEST,
            "npm search from + size exceeds the 10000-result group/filter scan window",
        )
            .into_response();
    }
    let scan_deadline = Instant::now() + NPM_SEARCH_SCAN_TIMEOUT;
    let result = match target {
        RepositoryTarget::Named(NpmRepository::Hosted { name, .. }) => {
            hosted_search_objects(state, name, response_base, &request, scan_deadline)
                .await
                .map(|objects| {
                    let total = objects.len();
                    (objects, total, false, false)
                })
        }
        RepositoryTarget::Named(repository @ NpmRepository::Proxy { .. }) => {
            if internal_only {
                Ok((Vec::new(), 0, true, false))
            } else {
                let proxy = configured_proxy(state, repository).expect("proxy config");
                proxy_search_window(
                    state,
                    &proxy,
                    query,
                    &request,
                    filter_active.then_some(scan_deadline),
                )
                .await
                .map(|page| (page.objects, page.total, true, page.total_is_approximate))
            }
        }
        RepositoryTarget::Named(NpmRepository::Group { members, .. }) => {
            let mut merged = Vec::new();
            let mut seen = HashSet::new();
            let mut first_error = None;
            let mut any_success = false;
            let mut total_upper_bound = 0usize;
            let mut has_proxy = false;
            let mut member_failed = false;
            for member in members {
                let Some(repository) = state.config.npm.repository(member).cloned() else {
                    continue;
                };
                let member_page = match repository {
                    NpmRepository::Hosted { name, .. } => {
                        hosted_search_objects(state, &name, response_base, &request, scan_deadline)
                            .await
                            .map(|objects| {
                                let total = objects.len();
                                (objects, total)
                            })
                    }
                    repository @ NpmRepository::Proxy { .. } if !internal_only => {
                        has_proxy = true;
                        let proxy = configured_proxy(state, &repository).expect("proxy config");
                        proxy_search_group_prefix(
                            state,
                            &proxy,
                            query,
                            &seen,
                            merged.len(),
                            needed,
                            scan_deadline,
                        )
                        .await
                        .map(|page| (page.objects, page.total))
                    }
                    NpmRepository::Proxy { .. } => continue,
                    NpmRepository::Group { .. } => continue,
                };
                match member_page {
                    Ok((objects, member_total)) => {
                        any_success = true;
                        total_upper_bound = total_upper_bound.saturating_add(member_total);
                        for object in objects {
                            let Some(package) = object
                                .get("package")
                                .and_then(|package| package.get("name"))
                                .and_then(|value| value.as_str())
                            else {
                                continue;
                            };
                            if seen.insert(package.to_string()) {
                                merged.push(object);
                            }
                        }
                    }
                    Err(error @ (ReadError::SearchScanLimit | ReadError::Corrupt)) => {
                        return read_error_response(error)
                    }
                    Err(error) if merged.is_empty() && first_error.is_none() => {
                        member_failed = true;
                        first_error = Some(error);
                    }
                    Err(_) => member_failed = true,
                }
            }
            if merged.is_empty() && (internal_only || any_success) {
                Ok((
                    Vec::new(),
                    total_upper_bound,
                    false,
                    has_proxy || member_failed,
                ))
            } else if merged.is_empty() {
                Err(first_error.unwrap_or(ReadError::NotFound))
            } else {
                let total = if has_proxy {
                    total_upper_bound.max(merged.len())
                } else {
                    merged.len()
                };
                Ok((merged, total, false, has_proxy || member_failed))
            }
        }
        RepositoryTarget::Legacy => {
            let hosted =
                hosted_search_objects(state, LEGACY_HOSTED, response_base, &request, scan_deadline)
                    .await;
            let mut any_success = hosted.is_ok();
            let mut member_failed = hosted.is_err();
            let mut merged = hosted.unwrap_or_default();
            let mut total_upper_bound = merged.len();
            let mut has_proxy = false;
            let mut seen: HashSet<String> = merged
                .iter()
                .filter_map(|object| object["package"]["name"].as_str().map(str::to_string))
                .collect();
            if !internal_only {
                if let Some(proxy) = legacy_proxy(state) {
                    has_proxy = true;
                    match proxy_search_group_prefix(
                        state,
                        &proxy,
                        query,
                        &seen,
                        merged.len(),
                        needed,
                        scan_deadline,
                    )
                    .await
                    {
                        Ok(page) => {
                            any_success = true;
                            total_upper_bound = total_upper_bound.saturating_add(page.total);
                            for object in page.objects {
                                if let Some(package) = object["package"]["name"].as_str() {
                                    if seen.insert(package.to_string()) {
                                        merged.push(object);
                                    }
                                }
                            }
                        }
                        Err(error @ (ReadError::SearchScanLimit | ReadError::Corrupt)) => {
                            return read_error_response(error)
                        }
                        Err(_) => member_failed = true,
                    }
                }
            }
            if merged.is_empty() && (internal_only || any_success) {
                Ok((
                    Vec::new(),
                    total_upper_bound,
                    false,
                    has_proxy || member_failed,
                ))
            } else if merged.is_empty() {
                Err(ReadError::NotFound)
            } else {
                let total = if has_proxy {
                    total_upper_bound.max(merged.len())
                } else {
                    merged.len()
                };
                Ok((merged, total, false, has_proxy || member_failed))
            }
        }
    };
    match result {
        Ok((objects, total, already_paged, total_is_approximate)) => search_response(
            headers,
            objects,
            &request,
            total,
            already_paged,
            total_is_approximate,
        ),
        Err(error) => read_error_response(error),
    }
}

async fn handle_get(
    state: AppState,
    target: RepositoryTarget,
    response_base: String,
    headers: HeaderMap,
    path: String,
    query: Option<String>,
    user: AuthenticatedUser,
) -> Response {
    if path == "-/ping" {
        return axum::Json(serde_json::json!({})).into_response();
    }
    if path == "-/whoami" {
        return axum::Json(serde_json::json!({ "username": user.0 })).into_response();
    }
    if path == "-/v1/search" {
        return handle_search(&state, &target, &response_base, &headers, query.as_deref()).await;
    }
    let Some((package, filename)) = parse_package_path(&path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let response = if let Some(filename) = filename {
        let Some(version) = crate::curation::parse_npm_tarball_version(&package, &filename) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let publish_date =
            match target_publish_date(&state, &target, &package, &version, &filename).await {
                Ok(date) => date,
                Err(error) => return read_error_response(error),
            };
        // Internal namespaces are operator-owned and may be served from hosted
        // storage; their no-proxy boundary is enforced by target resolution.
        // Preserve that behavior while applying normal policy to public
        // hosted/proxy/group tarball reads.
        if !is_internal(&state, &package) {
            if let Some(response) = crate::curation::check_download(
                &state.curation().curation_engine,
                state.bypass_token().as_deref(),
                &headers,
                crate::curation::RegistryType::Npm,
                &package,
                Some(&version),
                publish_date,
            ) {
                return response;
            }
        }
        target_tarball(&state, &target, &package, &filename, publish_date).await
    } else {
        match target_packument(&state, &target, &package, &response_base).await {
            Ok(packument) => json_response_with_stale(&headers, &packument.value, packument.stale),
            Err(error) => read_error_response(error),
        }
    };
    if response.status().is_success() {
        state.metrics.record_download("npm");
    }
    response
}

pub(crate) async fn named_get_request(
    state: AppState,
    repository: String,
    path: String,
    uri: Uri,
    headers: HeaderMap,
    user: AuthenticatedUser,
) -> Response {
    let Some(target) = named_target(&state, &repository) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_get(
        state.clone(),
        target,
        public_base(&state, Some(&repository)),
        headers,
        path,
        uri.query().map(str::to_string),
        user,
    )
    .await
}

async fn alias_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    OriginalUri(uri): OriginalUri,
    Extension(user): Extension<AuthenticatedUser>,
) -> Response {
    let Some(target) = alias_target(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_get(
        state.clone(),
        target,
        public_base(&state, None),
        headers,
        path,
        uri.query().map(str::to_string),
        user,
    )
    .await
}

struct WritableHosted {
    name: String,
    write_policy: NpmWritePolicy,
}

fn writable_hosted(
    state: &AppState,
    target: &RepositoryTarget,
    group_publish: bool,
) -> Result<WritableHosted, NpmHttpError> {
    let hosted = match target {
        RepositoryTarget::Legacy => WritableHosted {
            name: LEGACY_HOSTED.to_string(),
            write_policy: NpmWritePolicy::AllowOnce,
        },
        RepositoryTarget::Named(NpmRepository::Hosted { name, write_policy }) => WritableHosted {
            name: name.clone(),
            write_policy: *write_policy,
        },
        RepositoryTarget::Named(NpmRepository::Proxy { .. }) => Err(NpmHttpError::new(
            StatusCode::CONFLICT,
            "Repository is a pull-through proxy (read-only)",
        ))?,
        RepositoryTarget::Named(NpmRepository::Group {
            writable_member, ..
        }) if group_publish => {
            let Some(name) = writable_member else {
                return Err(NpmHttpError::new(
                    StatusCode::BAD_REQUEST,
                    "Group repository has no writable_member",
                ));
            };
            if let Some(NpmRepository::Hosted { name, write_policy }) =
                state.config.npm.repository(name)
            {
                WritableHosted {
                    name: name.clone(),
                    write_policy: *write_policy,
                }
            } else {
                return Err(NpmHttpError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid writable_member configuration",
                ));
            }
        }
        RepositoryTarget::Named(NpmRepository::Group { .. }) => {
            return Err(NpmHttpError::new(
                StatusCode::BAD_REQUEST,
                "Dist-tag mutations must target a hosted repository",
            ))
        }
    };
    if hosted.write_policy == NpmWritePolicy::Deny {
        Err(NpmHttpError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "Repository write policy denies mutations",
        ))
    } else {
        Ok(hosted)
    }
}

#[derive(Debug)]
struct NpmHttpError {
    status: StatusCode,
    message: &'static str,
}

impl NpmHttpError {
    const fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }
}

impl IntoResponse for NpmHttpError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ImmutableWrite {
    Created,
    ExistingSame,
    Conflict,
}

async fn put_immutable(
    state: &AppState,
    key: &str,
    data: &[u8],
) -> Result<ImmutableWrite, StorageError> {
    match state.storage.put_if_absent(key, data).await {
        Ok(()) => Ok(ImmutableWrite::Created),
        Err(StorageError::AlreadyExists) => match state.storage.get(key).await {
            Ok(existing) if existing.as_ref() == data => Ok(ImmutableWrite::ExistingSame),
            Ok(_) => Ok(ImmutableWrite::Conflict),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

struct ValidatedPublish {
    version: String,
    manifest: Vec<u8>,
    tarball: Vec<u8>,
    blob_digest: String,
    tags: Vec<(String, String)>,
    deprecation: Option<String>,
    package_fields: Vec<u8>,
}

fn inspect_tarball_package_json(tarball: &[u8]) -> Result<(String, String), &'static str> {
    // npm only needs package/package.json here. Bound decompression as well as
    // the file itself so a small gzip bomb cannot make validation consume an
    // unbounded amount of CPU or memory while searching the archive.
    let decoder = flate2::read::GzDecoder::new(tarball).take(TAR_SCAN_CAP);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|_| "Invalid npm tarball")?;
    for entry in entries {
        let mut entry = entry.map_err(|_| "Invalid npm tarball")?;
        let path = entry.path().map_err(|_| "Invalid npm tarball")?;
        if path.as_ref() != std::path::Path::new("package/package.json") {
            continue;
        }
        if entry.size() > PACKAGE_JSON_CAP {
            return Err("package.json is too large");
        }
        let mut body = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut body)
            .map_err(|_| "Invalid package.json")?;
        let json: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| "Invalid package.json")?;
        let name = json
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or("package.json is missing name")?;
        let version = json
            .get("version")
            .and_then(|value| value.as_str())
            .ok_or("package.json is missing version")?;
        return Ok((name.to_string(), version.to_string()));
    }
    Err("npm tarball is missing package/package.json")
}

fn validate_publish(
    package: &str,
    payload: &serde_json::Value,
) -> Result<ValidatedPublish, NpmHttpError> {
    if !is_valid_npm_package_name(package)
        || payload.get("name").and_then(|value| value.as_str()) != Some(package)
    {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Package name in URL does not match payload",
        ));
    }
    let Some(versions) = payload.get("versions").and_then(|value| value.as_object()) else {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Missing versions",
        ));
    };
    let Some(attachments) = payload
        .get("_attachments")
        .and_then(|value| value.as_object())
    else {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Missing _attachments",
        ));
    };
    if versions.len() != 1 || attachments.len() != 1 {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "npm publish must contain exactly one version and one attachment",
        ));
    }
    let (version, version_data) = versions.iter().next().expect("one version");
    if !is_valid_npm_version(version)
        || version_data.get("name").and_then(|value| value.as_str()) != Some(package)
        || version_data.get("version").and_then(|value| value.as_str()) != Some(version)
    {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Version metadata does not match the publish coordinate",
        ));
    }
    let (attachment_name, attachment) = attachments.iter().next().expect("one attachment");
    let normalized = normalize_attachment_name(package, attachment_name);
    let canonical = canonical_tarball_filename(package, version);
    if normalized != canonical || !is_valid_attachment_name(normalized) {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Attachment filename is not canonical",
        ));
    }
    let Some(encoded) = attachment.get("data").and_then(|value| value.as_str()) else {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Attachment is missing data",
        ));
    };
    let tarball = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| NpmHttpError::new(StatusCode::BAD_REQUEST, "Invalid attachment base64"))?;
    let Some(length) = attachment.get("length").and_then(|value| value.as_u64()) else {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Attachment is missing length",
        ));
    };
    if length != tarball.len() as u64 {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Attachment length mismatch",
        ));
    }
    let (tar_name, tar_version) = inspect_tarball_package_json(&tarball)
        .map_err(|message| NpmHttpError::new(StatusCode::BAD_REQUEST, message))?;
    if tar_name != package || tar_version != *version {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "package.json coordinate does not match publish coordinate",
        ));
    }

    let shasum = hex::encode(sha1::Sha1::digest(&tarball));
    let blob_digest = hex::encode(sha2::Sha512::digest(&tarball));
    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&tarball))
    );
    let supplied_dist = version_data.get("dist");
    if supplied_dist
        .and_then(|dist| dist.get("shasum"))
        .and_then(|value| value.as_str())
        .is_some_and(|value| !value.eq_ignore_ascii_case(&shasum))
    {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Tarball shasum mismatch",
        ));
    }
    if let Some(supplied) = supplied_dist
        .and_then(|dist| dist.get("integrity"))
        .and_then(|value| value.as_str())
    {
        let sha512_supplied = supplied
            .split_ascii_whitespace()
            .find(|candidate| candidate.starts_with("sha512-"));
        if sha512_supplied.is_some_and(|candidate| candidate != integrity) {
            return Err(NpmHttpError::new(
                StatusCode::BAD_REQUEST,
                "Tarball integrity mismatch",
            ));
        }
    }

    let mut manifest = version_data.clone();
    let Some(manifest_object) = manifest.as_object_mut() else {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Invalid version metadata",
        ));
    };
    // Deprecation is mutable npm metadata. Keep it out of the immutable
    // version manifest so a later explicit undeprecation cannot reveal the
    // original publish-time value again.
    let deprecation = match manifest_object.remove("deprecated") {
        Some(serde_json::Value::String(message)) => Some(message),
        Some(_) => {
            return Err(NpmHttpError::new(
                StatusCode::BAD_REQUEST,
                "Invalid deprecated message",
            ))
        }
        None => None,
    };
    let dist = manifest_object
        .entry("dist")
        .or_insert_with(|| serde_json::json!({}));
    let Some(dist) = dist.as_object_mut() else {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Invalid dist metadata",
        ));
    };
    dist.remove("tarball");
    dist.insert("shasum".to_string(), serde_json::Value::String(shasum));
    dist.insert(
        "integrity".to_string(),
        serde_json::Value::String(integrity),
    );
    let manifest = serde_json::to_vec(&manifest).map_err(|_| {
        NpmHttpError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to serialize version metadata",
        )
    })?;

    let mut tags = Vec::new();
    if let Some(dist_tags) = payload.get("dist-tags").and_then(|value| value.as_object()) {
        for (tag, target) in dist_tags {
            let Some(target) = target.as_str() else {
                return Err(NpmHttpError::new(
                    StatusCode::BAD_REQUEST,
                    "Invalid dist-tag target",
                ));
            };
            if !is_valid_dist_tag(tag) || target != version {
                return Err(NpmHttpError::new(
                    StatusCode::BAD_REQUEST,
                    "Invalid dist-tag",
                ));
            }
            tags.push((tag.clone(), target.to_string()));
        }
    }

    let mut package_fields = serde_json::Map::new();
    for field in ["name", "_id", "description", "readme", "license"] {
        if let Some(value) = payload.get(field) {
            package_fields.insert(field.to_string(), value.clone());
        }
    }
    let package_fields =
        serde_json::to_vec(&serde_json::Value::Object(package_fields)).map_err(|_| {
            NpmHttpError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to serialize package metadata",
            )
        })?;

    Ok(ValidatedPublish {
        version: version.clone(),
        manifest,
        tarball,
        blob_digest,
        tags,
        deprecation,
        package_fields,
    })
}

async fn publish(
    state: &AppState,
    repository: &str,
    write_policy: NpmWritePolicy,
    package: &str,
    payload: &serde_json::Value,
) -> Response {
    let validated = match validate_publish(package, payload) {
        Ok(validated) => validated,
        Err(error) => return error.into_response(),
    };
    let lock_key = format!("npm:{repository}:{package}");
    let lock = state.publish_lock(&lock_key);
    let _guard = lock.lock().await;
    match incomplete_publish_versions(state, repository, package).await {
        Ok(incomplete)
            if incomplete
                .iter()
                .any(|version| version != &validated.version) =>
        {
            return incomplete_publish_response()
        }
        Ok(_) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    if invalidate_hosted_packument_cache(state, repository, package)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let pending_key = hosted_publish_pending_key(repository, package, &validated.version);
    let completion_digest = crate::npm_layout::hosted_manifest_digest(&validated.manifest);
    let previous_pending = match state.storage.get(&pending_key).await {
        Ok(previous) if previous.as_ref() == completion_digest.as_bytes() => Some(previous),
        Ok(_) => return incomplete_publish_response(),
        Err(StorageError::NotFound) => None,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if state
        .storage
        .put(&pending_key, completion_digest.as_bytes())
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let blob_key =
        crate::npm_layout::hosted_blob_key_for_digest(repository, package, &validated.blob_digest);
    match put_immutable(state, &blob_key, &validated.tarball).await {
        Ok(ImmutableWrite::Created | ImmutableWrite::ExistingSame) => {}
        Ok(ImmutableWrite::Conflict) => {
            if restore_publish_pending(state, &pending_key, previous_pending.as_deref())
                .await
                .is_err()
            {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            tracing::error!(key = %blob_key, "npm content digest collision");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(error) => {
            if restore_publish_pending(state, &pending_key, previous_pending.as_deref())
                .await
                .is_err()
            {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            tracing::error!(key = %blob_key, error = ?error, "npm tarball blob create failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // The version manifest is the sole visibility/commit point. The referenced
    // tarball blob is content-addressed and is always durable before this write.
    let manifest_key = hosted_version_key(repository, package, &validated.version);
    let manifest_outcome =
        match commit_hosted_manifest(state, &manifest_key, &validated.manifest, write_policy).await
        {
            Ok(outcome) => outcome,
            Err(ManifestCommitError::Conflict) => {
                if restore_publish_pending(state, &pending_key, previous_pending.as_deref())
                    .await
                    .is_err()
                {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                return (
                    StatusCode::CONFLICT,
                    "Version already exists with other metadata or tarball bytes",
                )
                    .into_response();
            }
            Err(ManifestCommitError::Storage(error)) => {
                if restore_publish_pending(state, &pending_key, previous_pending.as_deref())
                    .await
                    .is_err()
                {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                tracing::error!(key = %manifest_key, error = ?error, "npm version commit failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    let completion_key = hosted_publish_complete_key(repository, package, &validated.version);
    let needs_completion = if manifest_outcome == ManifestCommit::ExistingSame
        && write_policy != NpmWritePolicy::Allow
    {
        match state.storage.get(&completion_key).await {
            Ok(existing) if existing.as_ref() == completion_digest.as_bytes() => false,
            Ok(_) => {
                tracing::error!(
                    key = %completion_key,
                    "npm publish completion marker does not match the committed manifest"
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            Err(StorageError::NotFound) => {
                // An allow-once retry must repair an interrupted first
                // publish without overwriting a newer explicit
                // tag/deprecation value.
                if fill_missing_retry_state(state, repository, package, &validated)
                    .await
                    .is_err()
                {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                true
            }
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    } else {
        // `allow` is a real redeploy even when the immutable version
        // manifest happens to be byte-identical: npm publish's selected
        // dist-tag and package fields are mutable payload state. Remove
        // the completion marker before touching that state so a failed
        // post-commit phase cannot be acknowledged as complete on retry.
        match state.storage.delete(&completion_key).await {
            Ok(()) | Err(StorageError::NotFound) => {}
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
        if replace_publish_state(state, repository, package, &validated)
            .await
            .is_err()
        {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        true
    };
    if needs_completion
        && state
            .storage
            .put(&completion_key, completion_digest.as_bytes())
            .await
            .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    match state.storage.delete(&pending_key).await {
        Ok(()) | Err(StorageError::NotFound) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }

    state.metrics.record_upload("npm");
    state
        .audit
        .log(AuditEntry::new("push", "api", package, "npm", repository));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        package.to_string(),
        RegistryType::Npm,
        "LOCAL",
    ));
    state.repo_index.invalidate("npm");
    StatusCode::CREATED.into_response()
}

async fn replace_publish_state(
    state: &AppState,
    repository: &str,
    package: &str,
    validated: &ValidatedPublish,
) -> Result<(), ()> {
    state
        .storage
        .put(
            &hosted_package_key(repository, package),
            &validated.package_fields,
        )
        .await
        .map_err(|_| ())?;
    for (tag, version) in &validated.tags {
        state
            .storage
            .put(
                &hosted_tag_key(repository, package, tag),
                version.as_bytes(),
            )
            .await
            .map_err(|_| ())?;
    }
    if let Some(message) = &validated.deprecation {
        let key = hosted_deprecation_key(repository, package, &validated.version);
        if message.is_empty() {
            match state.storage.delete(&key).await {
                Ok(()) | Err(StorageError::NotFound) => {}
                Err(_) => return Err(()),
            }
        } else {
            state
                .storage
                .put(&key, message.as_bytes())
                .await
                .map_err(|_| ())?;
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum ManifestCommit {
    Created,
    ExistingSame,
    Replaced,
}

#[derive(Debug)]
enum ManifestCommitError {
    Conflict,
    Storage(StorageError),
}

async fn commit_hosted_manifest(
    state: &AppState,
    key: &str,
    manifest: &[u8],
    write_policy: NpmWritePolicy,
) -> Result<ManifestCommit, ManifestCommitError> {
    match write_policy {
        NpmWritePolicy::Deny => Err(ManifestCommitError::Conflict),
        NpmWritePolicy::AllowOnce => match put_immutable(state, key, manifest)
            .await
            .map_err(ManifestCommitError::Storage)?
        {
            ImmutableWrite::Created => Ok(ManifestCommit::Created),
            ImmutableWrite::ExistingSame => Ok(ManifestCommit::ExistingSame),
            ImmutableWrite::Conflict => Err(ManifestCommitError::Conflict),
        },
        NpmWritePolicy::Allow => match state.storage.get(key).await {
            Ok(existing) if existing.as_ref() == manifest => Ok(ManifestCommit::ExistingSame),
            Ok(_) => {
                state
                    .storage
                    .put(key, manifest)
                    .await
                    .map_err(ManifestCommitError::Storage)?;
                Ok(ManifestCommit::Replaced)
            }
            Err(StorageError::NotFound) => {
                state
                    .storage
                    .put(key, manifest)
                    .await
                    .map_err(ManifestCommitError::Storage)?;
                Ok(ManifestCommit::Created)
            }
            Err(error) => Err(ManifestCommitError::Storage(error)),
        },
    }
}

async fn fill_missing_retry_state(
    state: &AppState,
    repository: &str,
    package: &str,
    validated: &ValidatedPublish,
) -> Result<(), ()> {
    let package_key = hosted_package_key(repository, package);
    match state.storage.get(&package_key).await {
        Ok(existing) => {
            let mut current =
                serde_json::from_slice::<serde_json::Value>(&existing).map_err(|_| ())?;
            let candidate = serde_json::from_slice::<serde_json::Value>(&validated.package_fields)
                .map_err(|_| ())?;
            let (Some(current), Some(candidate)) = (current.as_object_mut(), candidate.as_object())
            else {
                return Err(());
            };
            let mut changed = false;
            for (field, value) in candidate {
                if !current.contains_key(field) {
                    current.insert(field.clone(), value.clone());
                    changed = true;
                }
            }
            if changed {
                let merged = serde_json::to_vec(&serde_json::Value::Object(current.clone()))
                    .map_err(|_| ())?;
                state
                    .storage
                    .put(&package_key, &merged)
                    .await
                    .map_err(|_| ())?;
            }
        }
        Err(StorageError::NotFound) => state
            .storage
            .put(&package_key, &validated.package_fields)
            .await
            .map_err(|_| ())?,
        Err(_) => return Err(()),
    }

    for (tag, version) in &validated.tags {
        let key = hosted_tag_key(repository, package, tag);
        match state.storage.get(&key).await {
            Ok(_) => {}
            Err(StorageError::NotFound) => state
                .storage
                .put(&key, version.as_bytes())
                .await
                .map_err(|_| ())?,
            Err(_) => return Err(()),
        }
    }
    if let Some(message) = validated
        .deprecation
        .as_deref()
        .filter(|message| !message.is_empty())
    {
        let key = hosted_deprecation_key(repository, package, &validated.version);
        match state.storage.get(&key).await {
            Ok(_) => {}
            Err(StorageError::NotFound) => state
                .storage
                .put(&key, message.as_bytes())
                .await
                .map_err(|_| ())?,
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

async fn deprecate(
    state: &AppState,
    repository: &str,
    package: &str,
    payload: &serde_json::Value,
) -> Response {
    if payload.get("name").and_then(|value| value.as_str()) != Some(package) {
        return (StatusCode::BAD_REQUEST, "Package name mismatch").into_response();
    }
    let Some(versions) = payload.get("versions").and_then(|value| value.as_object()) else {
        return (StatusCode::BAD_REQUEST, "Missing versions").into_response();
    };
    let lock = state.publish_lock(&format!("npm:{repository}:{package}"));
    let _guard = lock.lock().await;
    match incomplete_publish_versions(state, repository, package).await {
        Ok(incomplete) if !incomplete.is_empty() => return incomplete_publish_response(),
        Ok(_) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    if invalidate_hosted_packument_cache(state, repository, package)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let mut changed = 0usize;
    for (version, data) in versions {
        match hosted_has_version(state, repository, package, version).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
        let Some(message) = data.get("deprecated").and_then(|value| value.as_str()) else {
            continue;
        };
        let key = hosted_deprecation_key(repository, package, version);
        let result = if message.is_empty() {
            match state.storage.delete(&key).await {
                Ok(()) | Err(StorageError::NotFound) => Ok(()),
                Err(error) => Err(error),
            }
        } else {
            state.storage.put(&key, message.as_bytes()).await
        };
        if result.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        changed += 1;
    }
    if changed == 0 {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.repo_index.invalidate("npm");
    StatusCode::CREATED.into_response()
}

async fn handle_put(
    state: AppState,
    target: RepositoryTarget,
    path: String,
    authority: NamespaceAuthority,
    body: Bytes,
) -> Response {
    let Some(package) = decode_package_name(&path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if enforce_namespace_scope(&authority, &package).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let hosted = match writable_hosted(&state, &target, true) {
        Ok(hosted) => hosted,
        Err(error) => return error.into_response(),
    };
    let payload = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(value) => value,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid JSON").into_response(),
    };
    if payload.get("_attachments").is_some() {
        publish(
            &state,
            &hosted.name,
            hosted.write_policy,
            &package,
            &payload,
        )
        .await
    } else {
        deprecate(&state, &hosted.name, &package, &payload).await
    }
}

pub(crate) async fn named_put_request(
    state: AppState,
    repository: String,
    path: String,
    authority: NamespaceAuthority,
    body: Bytes,
) -> Response {
    let Some(target) = named_target(&state, &repository) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_put(state, target, path, authority, body).await
}

async fn alias_put(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Extension(authority): Extension<NamespaceAuthority>,
    body: Bytes,
) -> Response {
    let Some(target) = alias_target(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_put(state, target, path, authority, body).await
}

async fn handle_dist_tags_get(
    state: AppState,
    target: RepositoryTarget,
    response_base: String,
    headers: HeaderMap,
    package: String,
) -> Response {
    let Some(package) = decode_package_name(&package) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match target_packument(&state, &target, &package, &response_base).await {
        Ok(packument) => {
            let tags = packument
                .value
                .get("dist-tags")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            json_response_with_stale(&headers, &tags, packument.stale)
        }
        Err(error) => read_error_response(error),
    }
}

async fn named_dist_tags_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((repository, package)): Path<(String, String)>,
) -> Response {
    let Some(target) = named_target(&state, &repository) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_dist_tags_get(
        state.clone(),
        target,
        public_base(&state, Some(&repository)),
        headers,
        package,
    )
    .await
}

async fn alias_dist_tags_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(package): Path<String>,
) -> Response {
    let Some(target) = alias_target(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_dist_tags_get(
        state.clone(),
        target,
        public_base(&state, None),
        headers,
        package,
    )
    .await
}

async fn handle_dist_tag_put(
    state: AppState,
    target: RepositoryTarget,
    package: String,
    tag: String,
    authority: NamespaceAuthority,
    body: Bytes,
) -> Response {
    let Some(package) = decode_package_name(&package) else {
        return (StatusCode::BAD_REQUEST, "Invalid package name or dist-tag").into_response();
    };
    if !is_valid_dist_tag(&tag) {
        return (StatusCode::BAD_REQUEST, "Invalid package name or dist-tag").into_response();
    }
    if enforce_namespace_scope(&authority, &package).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let repository = match writable_hosted(&state, &target, false) {
        Ok(hosted) => hosted.name,
        Err(error) => return error.into_response(),
    };
    let version = match serde_json::from_slice::<String>(&body) {
        Ok(version) if is_valid_npm_version(&version) => version,
        _ => return (StatusCode::BAD_REQUEST, "Invalid version").into_response(),
    };
    match hosted_has_version(&state, &repository, &package, &version).await {
        Ok(true) => {}
        Ok(false) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    let lock = state.publish_lock(&format!("npm:{repository}:{package}"));
    let _guard = lock.lock().await;
    match incomplete_publish_versions(&state, &repository, &package).await {
        Ok(incomplete) if !incomplete.is_empty() => return incomplete_publish_response(),
        Ok(_) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    match hosted_has_version(&state, &repository, &package, &version).await {
        Ok(true) => {}
        Ok(false) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    if invalidate_hosted_packument_cache(&state, &repository, &package)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if state
        .storage
        .put(
            &hosted_tag_key(&repository, &package, &tag),
            version.as_bytes(),
        )
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    state.repo_index.invalidate("npm");
    StatusCode::CREATED.into_response()
}

async fn named_dist_tag_put(
    State(state): State<AppState>,
    Path((repository, package, tag)): Path<(String, String, String)>,
    Extension(authority): Extension<NamespaceAuthority>,
    body: Bytes,
) -> Response {
    let Some(target) = named_target(&state, &repository) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_dist_tag_put(state, target, package, tag, authority, body).await
}

async fn alias_dist_tag_put(
    State(state): State<AppState>,
    Path((package, tag)): Path<(String, String)>,
    Extension(authority): Extension<NamespaceAuthority>,
    body: Bytes,
) -> Response {
    let Some(target) = alias_target(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_dist_tag_put(state, target, package, tag, authority, body).await
}

async fn handle_dist_tag_delete(
    state: AppState,
    target: RepositoryTarget,
    package: String,
    tag: String,
    authority: NamespaceAuthority,
) -> Response {
    let Some(package) = decode_package_name(&package) else {
        return (StatusCode::BAD_REQUEST, "Invalid package name or dist-tag").into_response();
    };
    if !is_valid_dist_tag(&tag) {
        return (StatusCode::BAD_REQUEST, "Invalid package name or dist-tag").into_response();
    }
    if tag == "latest" {
        return (
            StatusCode::BAD_REQUEST,
            "The latest dist-tag cannot be deleted",
        )
            .into_response();
    }
    if enforce_namespace_scope(&authority, &package).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let repository = match writable_hosted(&state, &target, false) {
        Ok(hosted) => hosted.name,
        Err(error) => return error.into_response(),
    };
    let lock = state.publish_lock(&format!("npm:{repository}:{package}"));
    let _guard = lock.lock().await;
    match incomplete_publish_versions(&state, &repository, &package).await {
        Ok(incomplete) if !incomplete.is_empty() => return incomplete_publish_response(),
        Ok(_) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    if invalidate_hosted_packument_cache(&state, &repository, &package)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let key = hosted_tag_key(&repository, &package, &tag);
    match state.storage.delete(&key).await {
        Ok(()) | Err(StorageError::NotFound) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    state.repo_index.invalidate("npm");
    StatusCode::NO_CONTENT.into_response()
}

async fn named_dist_tag_delete(
    State(state): State<AppState>,
    Path((repository, package, tag)): Path<(String, String, String)>,
    Extension(authority): Extension<NamespaceAuthority>,
) -> Response {
    let Some(target) = named_target(&state, &repository) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_dist_tag_delete(state, target, package, tag, authority).await
}

async fn alias_dist_tag_delete(
    State(state): State<AppState>,
    Path((package, tag)): Path<(String, String)>,
    Extension(authority): Extension<NamespaceAuthority>,
) -> Response {
    let Some(target) = alias_target(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_dist_tag_delete(state, target, package, tag, authority).await
}

fn proxy_for_audit(state: &AppState, target: &RepositoryTarget) -> Option<ProxyRepository> {
    match target {
        RepositoryTarget::Legacy => legacy_proxy(state),
        RepositoryTarget::Named(repository @ NpmRepository::Proxy { .. }) => {
            configured_proxy(state, repository)
        }
        RepositoryTarget::Named(NpmRepository::Hosted { .. }) => None,
        RepositoryTarget::Named(NpmRepository::Group { members, .. }) => members
            .iter()
            .filter_map(|name| state.config.npm.repository(name))
            .find_map(|repository| configured_proxy(state, repository)),
    }
}

fn npm_audit_error(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::to_vec(&serde_json::json!({"error": message}))
            .expect("static audit error JSON"),
    )
        .into_response()
}

#[derive(Debug, PartialEq, Eq)]
enum AuditBodyError {
    Invalid,
    TooLarge,
}

fn decode_audit_body(headers: &HeaderMap, body: &[u8]) -> Result<(Vec<u8>, bool), AuditBodyError> {
    let encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("identity")
        .trim();
    if encoding.eq_ignore_ascii_case("identity") || encoding.is_empty() {
        if body.is_empty() {
            return Err(AuditBodyError::Invalid);
        }
        return Ok((body.to_vec(), false));
    }
    if !encoding.eq_ignore_ascii_case("gzip") {
        return Err(AuditBodyError::Invalid);
    }
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(body)
        .take((NPM_AUDIT_BODY_CAP + 1) as u64)
        .read_to_end(&mut decoded)
        .map_err(|_| AuditBodyError::Invalid)?;
    if decoded.len() > NPM_AUDIT_BODY_CAP {
        return Err(AuditBodyError::TooLarge);
    }
    if decoded.is_empty() {
        return Err(AuditBodyError::Invalid);
    }
    Ok((decoded, true))
}

fn gzip_audit_body(body: &[u8]) -> Result<Vec<u8>, AuditBodyError> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(body)
        .map_err(|_| AuditBodyError::Invalid)?;
    encoder.finish().map_err(|_| AuditBodyError::Invalid)
}

fn retain_public_dependencies(
    value: &mut serde_json::Value,
    engine: &crate::curation::CurationEngine,
) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for field in ["dependencies", "requires"] {
        if let Some(dependencies) = object
            .get_mut(field)
            .and_then(serde_json::Value::as_object_mut)
        {
            dependencies.retain(|package, _| {
                !crate::curation::is_internal_namespace(
                    engine,
                    crate::curation::RegistryType::Npm,
                    package,
                )
            });
            for dependency in dependencies.values_mut() {
                retain_public_dependencies(dependency, engine);
            }
        }
    }
    if let Some(packages) = object
        .get_mut("packages")
        .and_then(serde_json::Value::as_object_mut)
    {
        packages.retain(|path, _| {
            let package = path
                .rsplit_once("node_modules/")
                .map(|(_, package)| package)
                .unwrap_or(path);
            package.is_empty()
                || !crate::curation::is_internal_namespace(
                    engine,
                    crate::curation::RegistryType::Npm,
                    package,
                )
        });
        for package in packages.values_mut() {
            retain_public_dependencies(package, engine);
        }
    }
    if object
        .get("name")
        .and_then(|value| value.as_str())
        .is_some_and(|package| {
            crate::curation::is_internal_namespace(
                engine,
                crate::curation::RegistryType::Npm,
                package,
            )
        })
    {
        object.remove("name");
    }
    for (field, child) in object {
        if field != "dependencies" && field != "requires" && field != "packages" {
            match child {
                serde_json::Value::Array(values) => {
                    for value in values {
                        retain_public_dependencies(value, engine);
                    }
                }
                serde_json::Value::Object(_) => retain_public_dependencies(child, engine),
                _ => {}
            }
        }
    }
}

fn text_contains_internal_package(text: &str, engine: &crate::curation::CurationEngine) -> bool {
    let decoded = percent_encoding::percent_decode_str(text)
        .decode_utf8_lossy()
        .into_owned();
    if crate::curation::is_internal_namespace(engine, crate::curation::RegistryType::Npm, &decoded)
    {
        return true;
    }
    let is_internal_candidate = |candidate: &str| {
        !candidate.is_empty()
            && crate::curation::is_internal_namespace(
                engine,
                crate::curation::RegistryType::Npm,
                candidate,
            )
    };
    for token in decoded.split(|character: char| {
        !(character.is_ascii_alphanumeric()
            || matches!(character, '@' | '/' | '.' | '_' | '-' | '~'))
    }) {
        let token = token.trim_matches('/');
        if is_internal_candidate(token) {
            return true;
        }
        let segments: Vec<&str> = token
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        for (index, segment) in segments.iter().enumerate() {
            if is_internal_candidate(segment) {
                return true;
            }
            if segment.starts_with('@')
                && index + 1 < segments.len()
                && is_internal_candidate(&format!("{segment}/{}", segments[index + 1]))
            {
                return true;
            }
        }
    }
    let bytes = decoded.as_bytes();
    for start in 0..bytes.len() {
        if bytes[start] != b'@' {
            continue;
        }
        let mut end = start + 1;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric()
                || matches!(bytes[end], b'@' | b'/' | b'.' | b'_' | b'-'))
        {
            end += 1;
        }
        if let Some(candidate) = decoded.get(start..end) {
            if crate::curation::is_internal_namespace(
                engine,
                crate::curation::RegistryType::Npm,
                candidate,
            ) {
                return true;
            }
        }
    }
    false
}

fn audit_json_contains_internal(
    value: &serde_json::Value,
    engine: &crate::curation::CurationEngine,
) -> bool {
    match value {
        serde_json::Value::String(text) => text_contains_internal_package(text, engine),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| audit_json_contains_internal(value, engine)),
        serde_json::Value::Object(object) => object.iter().any(|(key, value)| {
            text_contains_internal_package(key, engine)
                || audit_json_contains_internal(value, engine)
        }),
        _ => false,
    }
}

fn filter_audit_json(
    path: &str,
    body: &[u8],
    engine: &crate::curation::CurationEngine,
    filter_active: bool,
) -> Option<Vec<u8>> {
    if path == "-/npm/v1/security/advisories/bulk" {
        let mut map =
            serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(body).ok()?;
        if filter_active {
            map.retain(|package, _| {
                !crate::curation::is_internal_namespace(
                    engine,
                    crate::curation::RegistryType::Npm,
                    package,
                )
            });
        }
        if map.is_empty() {
            return None;
        }
        let value = serde_json::Value::Object(map);
        if filter_active && audit_json_contains_internal(&value, engine) {
            return None;
        }
        return serde_json::to_vec(&value).ok();
    }

    let mut value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    if !value.is_object() {
        return None;
    }
    if filter_active {
        retain_public_dependencies(&mut value, engine);
        if audit_json_contains_internal(&value, engine) {
            return None;
        }
    }
    serde_json::to_vec(&value).ok()
}

async fn handle_post(
    state: AppState,
    target: RepositoryTarget,
    path: String,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let is_bulk = path == "-/npm/v1/security/advisories/bulk";
    let is_quick = path == "-/npm/v1/security/audits/quick";
    let is_full = path == "-/npm/v1/security/audits";
    if !is_bulk && !is_quick && !is_full {
        return method_not_allowed("GET, PUT");
    }
    let body = match axum::body::to_bytes(body, NPM_AUDIT_BODY_CAP).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let Some(proxy) = proxy_for_audit(&state, &target) else {
        return npm_audit_error(
            StatusCode::BAD_REQUEST,
            "Audit requires a configured proxy repository",
        );
    };
    let engine = &state.curation().curation_engine;
    let filter_active = crate::curation::namespace_filter_active(engine);
    let (decoded, was_gzip) = match decode_audit_body(&headers, &body) {
        Ok(decoded) => decoded,
        Err(AuditBodyError::TooLarge) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Err(AuditBodyError::Invalid) => {
            return npm_audit_error(StatusCode::BAD_REQUEST, "Invalid audit request body")
        }
    };
    let Some(filtered) = filter_audit_json(&path, &decoded, engine, filter_active) else {
        return npm_audit_error(StatusCode::BAD_REQUEST, "Empty or invalid audit request");
    };
    let forward = if was_gzip {
        match gzip_audit_body(&filtered) {
            Ok(body) => body,
            Err(_) => {
                return npm_audit_error(StatusCode::BAD_REQUEST, "Invalid audit request body")
            }
        }
    } else {
        filtered
    };
    let mut forwarded_headers = Vec::new();
    if let Some(value) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        forwarded_headers.push(("content-type", value));
    }
    if let Some(value) = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
    {
        forwarded_headers.push(("content-encoding", value));
    }
    if let Some(value) = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
    {
        forwarded_headers.push(("accept", value));
    }
    let url = format!("{}/{}", proxy.url.trim_end_matches('/'), path);
    match proxy_forward_post(
        &state.no_redirect_http_client,
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        expose_opt(&proxy.auth),
        &forwarded_headers,
        &forward,
        &state.circuit_breaker,
        RegistryType::Npm,
        MAX_NPM_PROXY_REDIRECTS,
        |next_url| validated_proxy_url(&proxy, next_url.as_str()).is_some(),
    )
    .await
    {
        Ok((status, response_body, content_type)) => {
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "api", "", "npm", "audit"));
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            let content_type = content_type
                .as_deref()
                .and_then(|value| HeaderValue::from_str(value).ok())
                .unwrap_or_else(|| HeaderValue::from_static("application/json"));
            (
                status,
                [(header::CONTENT_TYPE, content_type)],
                response_body,
            )
                .into_response()
        }
        Err(ProxyError::CircuitOpen(name)) => circuit_open_response(&name),
        Err(error) => {
            tracing::warn!(error = ?error, "npm audit upstream forward failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

pub(crate) async fn named_post_request(
    state: AppState,
    repository: String,
    path: String,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(target) = named_target(&state, &repository) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_post(state, target, path, headers, body).await
}

async fn alias_post(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(target) = alias_target(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_post(state, target, path, headers, body).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_merge_is_member_ordered_and_latest_is_not_derived() {
        let first = serde_json::json!({
            "versions": {
                "1.0.0": {"name": "p", "version": "1.0.0"},
                "2.0.0": {"name": "hosted", "version": "2.0.0"}
            },
            "dist-tags": {"latest": "1.0.0"}
        });
        let second = serde_json::json!({
            "versions": {
                "2.0.0": {"name": "proxy", "version": "2.0.0"},
                "9.0.0": {"name": "p", "version": "9.0.0"}
            },
            "dist-tags": {"latest": "9.0.0", "next": "9.0.0"}
        });
        let merged = merge_packuments("p", "https://nora/repository/group", vec![first, second])
            .expect("merge");
        assert_eq!(merged["dist-tags"]["latest"], "1.0.0");
        assert_eq!(merged["dist-tags"]["next"], "9.0.0");
        assert_eq!(merged["versions"]["2.0.0"]["name"], "hosted");
    }

    #[test]
    fn attachment_validation_rejects_paths() {
        assert!(is_valid_attachment_name("pkg-1.0.0.tgz"));
        assert!(!is_valid_attachment_name("../pkg.tgz"));
        assert!(!is_valid_attachment_name("scope/pkg.tgz"));
    }

    #[test]
    fn dist_tags_reject_semver_like_names() {
        assert!(is_valid_dist_tag("latest"));
        assert!(!is_valid_dist_tag("1.2.3"));
        assert!(!is_valid_dist_tag("^1"));
    }

    #[cfg(test)]
    fn npm_tarball(package: &str, version: &str) -> Vec<u8> {
        npm_tarball_with_marker(package, version, "")
    }

    #[cfg(test)]
    fn npm_tarball_with_marker(package: &str, version: &str, marker: &str) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let encoder = GzEncoder::new(Vec::new(), Compression::fast());
        let mut archive = tar::Builder::new(encoder);
        let package_json = serde_json::to_vec(&serde_json::json!({
            "name": package,
            "version": version
        }))
        .unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_size(package_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "package/package.json", package_json.as_slice())
            .unwrap();
        if !marker.is_empty() {
            let mut marker_header = tar::Header::new_gnu();
            marker_header.set_size(marker.len() as u64);
            marker_header.set_mode(0o644);
            marker_header.set_cksum();
            archive
                .append_data(
                    &mut marker_header,
                    "package/republish-marker.txt",
                    marker.as_bytes(),
                )
                .unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    fn named_config(config: &mut crate::config::Config) {
        config.npm.proxy = None;
        config.npm.repositories = vec![
            NpmRepository::Hosted {
                name: "npm-private".into(),
                write_policy: NpmWritePolicy::AllowOnce,
            },
            NpmRepository::Proxy {
                name: "npm-registry".into(),
                url: "http://127.0.0.1:1".into(),
                auth: None,
                metadata_ttl: Some(300),
                negative_ttl: 0,
            },
            NpmRepository::Group {
                name: "npm-group".into(),
                members: vec!["npm-private".into(), "npm-registry".into()],
                writable_member: Some("npm-private".into()),
            },
        ];
        config.npm.default_repository = Some("npm-group".into());
    }

    #[test]
    fn invalid_named_config_without_default_never_falls_into_legacy_layout() {
        let ctx = crate::test_helpers::create_test_context_with_config(|config| {
            config.npm.repositories = vec![NpmRepository::Hosted {
                name: "packages".to_string(),
                write_policy: NpmWritePolicy::AllowOnce,
            }];
            config.npm.default_repository = None;
        });
        assert!(alias_target(&ctx.state).is_none());
    }

    fn publish_payload(package: &str, version: &str, tag: &str) -> Vec<u8> {
        let tgz = npm_tarball(package, version);
        serde_json::to_vec(&serde_json::json!({
            "name": package,
            "versions": {
                (version): {
                    "name": package,
                    "version": version,
                    "dist": {}
                }
            },
            "_attachments": {
                (canonical_tarball_filename(package, version)): {
                    "data": base64::engine::general_purpose::STANDARD.encode(&tgz),
                    "length": tgz.len()
                }
            },
            "dist-tags": {(tag): version}
        }))
        .unwrap()
    }

    fn publish_payload_with_tarball(
        package: &str,
        version: &str,
        tag: &str,
        marker: &str,
    ) -> Vec<u8> {
        let mut payload: serde_json::Value =
            serde_json::from_slice(&publish_payload(package, version, tag)).unwrap();
        let tarball = npm_tarball_with_marker(package, version, marker);
        let filename = canonical_tarball_filename(package, version);
        payload["_attachments"][&filename]["data"] =
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&tarball));
        payload["_attachments"][&filename]["length"] =
            serde_json::Value::Number(tarball.len().into());
        serde_json::to_vec(&payload).unwrap()
    }

    #[tokio::test]
    async fn publish_through_group_commits_only_hosted_and_exact_retry_repairs() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        let ctx = create_test_context_with_config(named_config);
        let body = publish_payload("pkg", "1.0.0", "latest");
        let first = send(
            &ctx.app,
            Method::PUT,
            "/repository/npm-group/pkg",
            body.clone(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::CREATED);
        // Model a crash after the version-manifest commit and before the
        // durable post-commit marker. Only this incomplete state is repairable.
        ctx.state
            .storage
            .delete(&hosted_tag_key("npm-private", "pkg", "latest"))
            .await
            .unwrap();
        ctx.state
            .storage
            .delete(&hosted_publish_complete_key("npm-private", "pkg", "1.0.0"))
            .await
            .unwrap();
        let manifest = ctx
            .state
            .storage
            .get(&hosted_version_key("npm-private", "pkg", "1.0.0"))
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                &hosted_publish_pending_key("npm-private", "pkg", "1.0.0"),
                crate::npm_layout::hosted_manifest_digest(&manifest).as_bytes(),
            )
            .await
            .unwrap();
        let retry = send(&ctx.app, Method::PUT, "/repository/npm-group/pkg", body).await;
        assert_eq!(retry.status(), StatusCode::CREATED);
        assert!(ctx
            .state
            .storage
            .stat("npm/repositories/npm-private/pkg/versions/1.0.0.json")
            .await
            .is_some());
        assert!(ctx
            .state
            .storage
            .stat("npm/repositories/npm-group/pkg/versions/1.0.0.json")
            .await
            .is_none());
        assert_eq!(
            ctx.state
                .storage
                .get(&hosted_tag_key("npm-private", "pkg", "latest"))
                .await
                .unwrap()
                .as_ref(),
            b"1.0.0"
        );
    }

    #[tokio::test]
    async fn fresh_publish_scans_only_pending_markers() {
        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let backend = crate::test_helpers::FaultInjectBackend::new(ctx.state.storage.clone());
        let list_attempts = backend.list_attempts();
        let mut state = ctx.state.clone();
        state.storage = crate::storage::Storage::from_backend(std::sync::Arc::new(backend));

        for version in ["1.0.0", "2.0.0"] {
            let payload: serde_json::Value =
                serde_json::from_slice(&publish_payload("pkg", version, "latest")).unwrap();
            assert_eq!(
                publish(
                    &state,
                    "npm-private",
                    NpmWritePolicy::AllowOnce,
                    "pkg",
                    &payload,
                )
                .await
                .status(),
                StatusCode::CREATED
            );
        }

        assert_eq!(
            list_attempts.lock().as_slice(),
            [
                "npm/repositories/npm-private/pkg/publish-pending/",
                "npm/repositories/npm-private/pkg/publish-pending/",
            ]
        );
        assert_eq!(
            state
                .storage
                .get(&hosted_publish_pending_index_key("npm-private", "pkg"))
                .await
                .unwrap()
                .as_ref(),
            b"1"
        );
        for version in ["1.0.0", "2.0.0"] {
            assert!(matches!(
                state
                    .storage
                    .get(&hosted_publish_pending_key("npm-private", "pkg", version))
                    .await,
                Err(StorageError::NotFound)
            ));
        }
    }

    #[tokio::test]
    async fn completed_pending_marker_is_cleaned_before_the_next_publish() {
        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let first: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "1.0.0", "latest")).unwrap();
        assert_eq!(
            publish(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &first,
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        let manifest = ctx
            .state
            .storage
            .get(&hosted_version_key("npm-private", "pkg", "1.0.0"))
            .await
            .unwrap();
        let pending_key = hosted_publish_pending_key("npm-private", "pkg", "1.0.0");
        ctx.state
            .storage
            .put(
                &pending_key,
                crate::npm_layout::hosted_manifest_digest(&manifest).as_bytes(),
            )
            .await
            .unwrap();

        let second: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "2.0.0", "latest")).unwrap();
        assert_eq!(
            publish(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &second,
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(matches!(
            ctx.state.storage.get(&pending_key).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn pending_publish_accepts_only_the_exact_manifest_retry() {
        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let exact: serde_json::Value = serde_json::from_slice(&publish_payload_with_tarball(
            "pkg", "1.0.0", "latest", "exact",
        ))
        .unwrap();
        let exact_publish = validate_publish("pkg", &exact).unwrap();
        let exact_digest = crate::npm_layout::hosted_manifest_digest(&exact_publish.manifest);
        let pending_key = hosted_publish_pending_key("npm-private", "pkg", "1.0.0");
        ctx.state
            .storage
            .put(
                &hosted_publish_pending_index_key("npm-private", "pkg"),
                b"1",
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(&pending_key, exact_digest.as_bytes())
            .await
            .unwrap();

        let different: serde_json::Value = serde_json::from_slice(&publish_payload_with_tarball(
            "pkg",
            "1.0.0",
            "latest",
            "different",
        ))
        .unwrap();
        assert_eq!(
            publish(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &different,
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            ctx.state.storage.get(&pending_key).await.unwrap().as_ref(),
            exact_digest.as_bytes()
        );
        assert_eq!(
            publish(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &exact,
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(matches!(
            ctx.state.storage.get(&pending_key).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn failed_pending_marker_cleanup_is_recovered_by_exact_retry() {
        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let pending_key = hosted_publish_pending_key("npm-private", "pkg", "1.0.0");
        let backend = crate::test_helpers::FaultInjectBackend::new(ctx.state.storage.clone())
            .fail_delete(&pending_key);
        let mut failing_state = ctx.state.clone();
        failing_state.storage = crate::storage::Storage::from_backend(std::sync::Arc::new(backend));
        let payload: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "1.0.0", "latest")).unwrap();

        assert_eq!(
            publish(
                &failing_state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &payload,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(ctx.state.storage.stat(&pending_key).await.is_some());

        assert_eq!(
            publish(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &payload,
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(matches!(
            ctx.state.storage.get(&pending_key).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn completed_publish_retry_does_not_resurrect_deleted_tag() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        let ctx = create_test_context_with_config(named_config);
        let body = publish_payload("pkg", "1.0.0", "next");
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                body.clone(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(ctx
            .state
            .storage
            .get(&hosted_publish_complete_key("npm-private", "pkg", "1.0.0",))
            .await
            .is_ok());
        ctx.state
            .storage
            .delete(&hosted_tag_key("npm-private", "pkg", "next"))
            .await
            .unwrap();

        assert_eq!(
            send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", body,)
                .await
                .status(),
            StatusCode::CREATED
        );
        assert!(matches!(
            ctx.state
                .storage
                .get(&hosted_tag_key("npm-private", "pkg", "next"))
                .await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn publish_deprecation_uses_overlay_and_completed_retry_does_not_resurrect_it() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(named_config);
        let mut payload: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "1.0.0", "latest")).unwrap();
        payload["versions"]["1.0.0"]["deprecated"] =
            serde_json::Value::String("do not use".to_string());
        let body = serde_json::to_vec(&payload).unwrap();

        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-group/pkg",
                body.clone(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        let manifest_key = hosted_version_key("npm-private", "pkg", "1.0.0");
        let deprecation_key = hosted_deprecation_key("npm-private", "pkg", "1.0.0");
        let completion_key = hosted_publish_complete_key("npm-private", "pkg", "1.0.0");
        let manifest: serde_json::Value =
            serde_json::from_slice(&ctx.state.storage.get(&manifest_key).await.unwrap()).unwrap();
        assert!(manifest.get("deprecated").is_none());
        assert_eq!(
            ctx.state
                .storage
                .get(&deprecation_key)
                .await
                .unwrap()
                .as_ref(),
            b"do not use"
        );

        // An exact retry repairs a publish that reached the manifest commit
        // but not the mutable overlay/completion phase.
        ctx.state.storage.delete(&deprecation_key).await.unwrap();
        ctx.state.storage.delete(&completion_key).await.unwrap();
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-group/pkg",
                body.clone(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            ctx.state
                .storage
                .get(&deprecation_key)
                .await
                .unwrap()
                .as_ref(),
            b"do not use"
        );
        let response = send(&ctx.app, Method::GET, "/repository/npm-group/pkg", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let packument: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(packument["versions"]["1.0.0"]["deprecated"], "do not use");

        let clear = serde_json::json!({
            "name": "pkg",
            "versions": {
                "1.0.0": {"deprecated": ""}
            }
        });
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-group/pkg",
                serde_json::to_vec(&clear).unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(matches!(
            ctx.state.storage.get(&deprecation_key).await,
            Err(StorageError::NotFound)
        ));

        let response = send(&ctx.app, Method::GET, "/repository/npm-group/pkg", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let packument: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert!(packument["versions"]["1.0.0"].get("deprecated").is_none());

        // Once the original publish completed, retrying that exact body must
        // not rewind the later mutable undeprecation.
        assert_eq!(
            send(&ctx.app, Method::PUT, "/repository/npm-group/pkg", body)
                .await
                .status(),
            StatusCode::CREATED
        );
        assert!(matches!(
            ctx.state.storage.get(&deprecation_key).await,
            Err(StorageError::NotFound)
        ));
        let response = send(&ctx.app, Method::GET, "/repository/npm-group/pkg", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let packument: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert!(packument["versions"]["1.0.0"].get("deprecated").is_none());
    }

    #[tokio::test]
    async fn incomplete_publish_must_be_retried_before_later_mutable_operations() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(named_config);
        let mut first: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "1.0.0", "next")).unwrap();
        first["description"] = serde_json::Value::String("old description".to_string());
        first["versions"]["1.0.0"]["deprecated"] =
            serde_json::Value::String("old deprecation".to_string());
        let first = serde_json::to_vec(&first).unwrap();
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                first.clone(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        // Model a process loss after the manifest became visible but before
        // the durable completion marker. No later mutable operation may race
        // the exact retry that repairs this state.
        ctx.state
            .storage
            .delete(&hosted_publish_complete_key("npm-private", "pkg", "1.0.0"))
            .await
            .unwrap();
        let manifest = ctx
            .state
            .storage
            .get(&hosted_version_key("npm-private", "pkg", "1.0.0"))
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                &hosted_publish_pending_key("npm-private", "pkg", "1.0.0"),
                crate::npm_layout::hosted_manifest_digest(&manifest).as_bytes(),
            )
            .await
            .unwrap();
        let clear = serde_json::json!({
            "name": "pkg",
            "versions": {"1.0.0": {"deprecated": ""}}
        });
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                serde_json::to_vec(&clear).unwrap(),
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(
                &ctx.app,
                Method::DELETE,
                "/repository/npm-private/-/package/pkg/dist-tags/next",
                "",
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let second = publish_payload("pkg", "2.0.0", "latest");
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                second.clone(),
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );

        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                first.clone(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                serde_json::to_vec(&clear).unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send(
                &ctx.app,
                Method::DELETE,
                "/repository/npm-private/-/package/pkg/dist-tags/next",
                "",
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", second,)
                .await
                .status(),
            StatusCode::CREATED
        );

        // A delayed exact retry is now read-only because the original publish
        // completed before the newer mutations were accepted.
        assert_eq!(
            send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", first,)
                .await
                .status(),
            StatusCode::CREATED
        );
        assert!(matches!(
            ctx.state
                .storage
                .get(&hosted_tag_key("npm-private", "pkg", "next"))
                .await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            ctx.state
                .storage
                .get(&hosted_deprecation_key("npm-private", "pkg", "1.0.0"))
                .await,
            Err(StorageError::NotFound)
        ));
        let package: serde_json::Value = serde_json::from_slice(
            &ctx.state
                .storage
                .get(&hosted_package_key("npm-private", "pkg"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(package.get("description").is_none());
    }

    #[tokio::test]
    async fn delayed_retry_cannot_rewind_newer_publish_mutable_state() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        let ctx = create_test_context_with_config(named_config);
        let mut first: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "1.0.0", "latest")).unwrap();
        first["description"] = serde_json::Value::String("old".to_string());
        let first = serde_json::to_vec(&first).unwrap();
        let mut second: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "2.0.0", "latest")).unwrap();
        second["description"] = serde_json::Value::String("new".to_string());
        let second = serde_json::to_vec(&second).unwrap();

        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                first.clone(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", second,)
                .await
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", first,)
                .await
                .status(),
            StatusCode::CREATED
        );

        assert_eq!(
            ctx.state
                .storage
                .get(&hosted_tag_key("npm-private", "pkg", "latest"))
                .await
                .unwrap()
                .as_ref(),
            b"2.0.0"
        );
        let package: serde_json::Value = serde_json::from_slice(
            &ctx.state
                .storage
                .get(&hosted_package_key("npm-private", "pkg"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(package["description"], "new");
    }

    #[tokio::test]
    async fn delayed_retry_cannot_undo_explicit_dist_tag_move() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        let ctx = create_test_context_with_config(named_config);
        let first = publish_payload("pkg", "1.0.0", "next");
        let second = publish_payload("pkg", "2.0.0", "latest");
        for body in [first.clone(), second] {
            assert_eq!(
                send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", body,)
                    .await
                    .status(),
                StatusCode::CREATED
            );
        }
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/-/package/pkg/dist-tags/next",
                br#""2.0.0""#.as_slice(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        assert_eq!(
            send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", first,)
                .await
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            ctx.state
                .storage
                .get(&hosted_tag_key("npm-private", "pkg", "next"))
                .await
                .unwrap()
                .as_ref(),
            b"2.0.0"
        );
    }

    #[tokio::test]
    async fn group_tarball_does_not_fall_through_on_hosted_manifest_read_error() {
        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let manifest = hosted_version_key("npm-private", "pkg", "1.0.0");
        ctx.state
            .storage
            .put(&manifest, br#"{"name":"pkg","version":"1.0.0"}"#)
            .await
            .unwrap();
        let mut state = ctx.state.clone();
        state.storage = crate::storage::Storage::from_backend(std::sync::Arc::new(
            crate::test_helpers::FaultInjectBackend::new(ctx.state.storage.clone())
                .fail_get(&manifest),
        ));

        let response = group_tarball(
            &state,
            &["npm-private".to_string(), "npm-registry".to_string()],
            "pkg",
            "pkg-1.0.0.tgz",
            None,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn hosted_optional_read_error_fails_group_packument_closed() {
        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let manifest = hosted_version_key("npm-private", "pkg", "1.0.0");
        let package_key = hosted_package_key("npm-private", "pkg");
        ctx.state
            .storage
            .put(&manifest, br#"{"name":"pkg","version":"1.0.0"}"#)
            .await
            .unwrap();
        ctx.state
            .storage
            .put(&package_key, br#"{"name":"pkg"}"#)
            .await
            .unwrap();
        let mut state = ctx.state.clone();
        state.storage = crate::storage::Storage::from_backend(std::sync::Arc::new(
            crate::test_helpers::FaultInjectBackend::new(ctx.state.storage.clone())
                .fail_get(&package_key),
        ));

        assert!(matches!(
            group_packument(
                &state,
                &["npm-private".to_string(), "npm-registry".to_string()],
                "pkg",
                "http://localhost/repository/npm-group",
            )
            .await,
            Err(ReadError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn deprecation_and_dist_tag_delete_are_idempotent_but_not_error_blind() {
        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let manifest = hosted_version_key("npm-private", "pkg", "1.0.0");
        let manifest_bytes = br#"{"name":"pkg","version":"1.0.0"}"#;
        let completion = hosted_publish_complete_key("npm-private", "pkg", "1.0.0");
        let deprecation = hosted_deprecation_key("npm-private", "pkg", "1.0.0");
        let tag = hosted_tag_key("npm-private", "pkg", "next");
        ctx.state
            .storage
            .put(&manifest, manifest_bytes)
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                &completion,
                crate::npm_layout::hosted_manifest_digest(manifest_bytes).as_bytes(),
            )
            .await
            .unwrap();
        ctx.state.storage.put(&deprecation, b"old").await.unwrap();
        ctx.state.storage.put(&tag, b"1.0.0").await.unwrap();
        let backend = crate::test_helpers::FaultInjectBackend::new(ctx.state.storage.clone())
            .fail_delete(&deprecation)
            .fail_delete(&tag);
        let mut state = ctx.state.clone();
        state.storage = crate::storage::Storage::from_backend(std::sync::Arc::new(backend));

        let payload = serde_json::json!({
            "name": "pkg",
            "versions": {"1.0.0": {"deprecated": ""}}
        });
        assert_eq!(
            deprecate(&state, "npm-private", "pkg", &payload)
                .await
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            handle_dist_tag_delete(
                state,
                RepositoryTarget::Named(NpmRepository::Hosted {
                    name: "npm-private".to_string(),
                    write_policy: NpmWritePolicy::AllowOnce,
                }),
                "pkg".to_string(),
                "next".to_string(),
                NamespaceAuthority::Unrestricted,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );

        let clean = crate::test_helpers::create_test_context_with_config(named_config);
        clean
            .state
            .storage
            .put(&manifest, manifest_bytes)
            .await
            .unwrap();
        clean
            .state
            .storage
            .put(
                &completion,
                crate::npm_layout::hosted_manifest_digest(manifest_bytes).as_bytes(),
            )
            .await
            .unwrap();
        assert_eq!(
            deprecate(&clean.state, "npm-private", "pkg", &payload)
                .await
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            handle_dist_tag_delete(
                clean.state,
                RepositoryTarget::Named(NpmRepository::Hosted {
                    name: "npm-private".to_string(),
                    write_policy: NpmWritePolicy::AllowOnce,
                }),
                "pkg".to_string(),
                "next".to_string(),
                NamespaceAuthority::Unrestricted,
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn retry_after_precommit_tarball_orphan_completes_publish() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(named_config);
        let body = publish_payload("pkg", "1.0.0", "latest");
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let encoded = payload["_attachments"]["pkg-1.0.0.tgz"]["data"]
            .as_str()
            .unwrap();
        let tarball = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let blob_key = crate::npm_layout::hosted_blob_key_for_digest(
            "npm-private",
            "pkg",
            &hex::encode(sha2::Sha512::digest(&tarball)),
        );
        ctx.state.storage.put(&blob_key, &tarball).await.unwrap();

        let response = send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", body).await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(ctx
            .state
            .storage
            .stat(&hosted_version_key("npm-private", "pkg", "1.0.0"))
            .await
            .is_some());
    }

    #[tokio::test]
    async fn conflicting_same_version_is_rejected() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        let ctx = create_test_context_with_config(named_config);
        let first = publish_payload("pkg", "1.0.0", "latest");
        assert_eq!(
            send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", first)
                .await
                .status(),
            StatusCode::CREATED
        );
        let mut conflicting: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "1.0.0", "latest")).unwrap();
        conflicting["versions"]["1.0.0"]["description"] = serde_json::json!("different");
        let response = send(
            &ctx.app,
            Method::PUT,
            "/repository/npm-private/pkg",
            serde_json::to_vec(&conflicting).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn hosted_packument_cache_removes_storage_fanout_and_rewrites_per_route() {
        use crate::test_helpers::{create_test_context_with_config, send, FaultInjectBackend};
        use axum::http::Method;
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                publish_payload("pkg", "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        let backend = FaultInjectBackend::new(ctx.state.storage.clone())
            .fail_get(hosted_deprecation_key("npm-private", "pkg", "1.0.0"));
        let list_attempts = backend.list_attempts();
        let mut state = ctx.state.clone();
        state.storage = crate::storage::Storage::from_backend(Arc::new(backend));

        let hosted = hosted_packument(
            &state,
            "npm-private",
            "pkg",
            "https://nora.example/repository/npm-private",
        )
        .await
        .expect("cold hosted packument");
        assert_eq!(
            hosted["versions"]["1.0.0"]["dist"]["tarball"],
            "https://nora.example/repository/npm-private/pkg/-/pkg-1.0.0.tgz"
        );
        assert_eq!(list_attempts.lock().len(), 3);

        let cache_key = crate::npm_layout::hosted_packument_cache_key("npm-private", "pkg");
        let cache: serde_json::Value = serde_json::from_slice(
            &state
                .storage
                .get(&cache_key)
                .await
                .expect("persisted cache"),
        )
        .unwrap();
        assert!(cache["versions"]["1.0.0"]["dist"].get("tarball").is_none());

        let grouped = hosted_packument(
            &state,
            "npm-private",
            "pkg",
            "https://nora.example/repository/npm-group",
        )
        .await
        .expect("warm hosted packument");
        assert_eq!(list_attempts.lock().len(), 3);
        assert_eq!(
            grouped["versions"]["1.0.0"]["dist"]["tarball"],
            "https://nora.example/repository/npm-group/pkg/-/pkg-1.0.0.tgz"
        );

        let second: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "2.0.0", "next")).unwrap();
        assert_eq!(
            publish(
                &state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &second,
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(state.storage.stat(&cache_key).await.is_none());
        let rebuilt = hosted_packument(
            &state,
            "npm-private",
            "pkg",
            "https://nora.example/repository/npm-private",
        )
        .await
        .expect("rebuilt hosted packument");
        assert_eq!(rebuilt["versions"].as_object().unwrap().len(), 2);
        assert_eq!(rebuilt["dist-tags"]["next"], "2.0.0");
    }

    #[tokio::test]
    async fn hosted_mutation_fails_closed_when_packument_cache_cannot_be_invalidated() {
        use crate::test_helpers::{create_test_context_with_config, send, FaultInjectBackend};
        use axum::http::Method;
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                publish_payload("pkg", "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        hosted_packument(
            &ctx.state,
            "npm-private",
            "pkg",
            "https://nora.example/repository/npm-private",
        )
        .await
        .expect("materialize hosted cache");

        let cache_key = crate::npm_layout::hosted_packument_cache_key("npm-private", "pkg");
        let mut failing_state = ctx.state.clone();
        failing_state.storage = crate::storage::Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_delete(&cache_key),
        ));
        let payload: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "2.0.0", "latest")).unwrap();
        assert_eq!(
            publish(
                &failing_state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &payload,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(ctx
            .state
            .storage
            .stat(&hosted_version_key("npm-private", "pkg", "2.0.0"))
            .await
            .is_none());
        assert!(ctx.state.storage.stat(&cache_key).await.is_some());
    }

    #[tokio::test]
    async fn hosted_overlays_invalidate_and_rebuild_packument_cache() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(named_config);
        let package_uri = "/repository/npm-private/pkg";
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                package_uri,
                publish_payload("pkg", "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let cache_key = crate::npm_layout::hosted_packument_cache_key("npm-private", "pkg");
        assert_eq!(
            send(&ctx.app, Method::GET, package_uri, "").await.status(),
            StatusCode::OK
        );
        assert!(ctx.state.storage.stat(&cache_key).await.is_some());

        let deprecation = serde_json::json!({
            "name": "pkg",
            "versions": {"1.0.0": {"deprecated": "do not use"}}
        });
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                package_uri,
                serde_json::to_vec(&deprecation).unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(ctx.state.storage.stat(&cache_key).await.is_none());
        let response = send(&ctx.app, Method::GET, package_uri, "").await;
        let packument: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(packument["versions"]["1.0.0"]["deprecated"], "do not use");

        let tag_uri = "/repository/npm-private/-/package/pkg/dist-tags/next";
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                tag_uri,
                serde_json::to_vec("1.0.0").unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(ctx.state.storage.stat(&cache_key).await.is_none());
        let response = send(&ctx.app, Method::GET, package_uri, "").await;
        let packument: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(packument["dist-tags"]["next"], "1.0.0");

        assert_eq!(
            send(&ctx.app, Method::DELETE, tag_uri, "").await.status(),
            StatusCode::NO_CONTENT
        );
        assert!(ctx.state.storage.stat(&cache_key).await.is_none());
        let response = send(&ctx.app, Method::GET, package_uri, "").await;
        let packument: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert!(packument["dist-tags"].get("next").is_none());
    }

    #[tokio::test]
    async fn allow_policy_republishes_same_version_via_new_blob_and_digest_bound_manifest() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(|config| {
            named_config(config);
            let NpmRepository::Hosted { write_policy, .. } = &mut config.npm.repositories[0] else {
                unreachable!()
            };
            *write_policy = NpmWritePolicy::Allow;
        });
        let mut first: serde_json::Value = serde_json::from_slice(&publish_payload_with_tarball(
            "pkg", "1.0.0", "latest", "first",
        ))
        .unwrap();
        first["versions"]["1.0.0"]["description"] = serde_json::json!("first");
        let first = serde_json::to_vec(&first).unwrap();
        let mut second: serde_json::Value = serde_json::from_slice(&publish_payload_with_tarball(
            "pkg", "1.0.0", "latest", "second",
        ))
        .unwrap();
        second["versions"]["1.0.0"]["description"] = serde_json::json!("second");
        let second_tarball = base64::engine::general_purpose::STANDARD
            .decode(
                second["_attachments"]["pkg-1.0.0.tgz"]["data"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        let second = serde_json::to_vec(&second).unwrap();

        for body in [first, second.clone(), second] {
            assert_eq!(
                send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", body,)
                    .await
                    .status(),
                StatusCode::CREATED
            );
        }
        let mut same_manifest_new_state: serde_json::Value = serde_json::from_slice(
            &publish_payload_with_tarball("pkg", "1.0.0", "next", "second"),
        )
        .unwrap();
        same_manifest_new_state["description"] = serde_json::json!("replacement package fields");
        same_manifest_new_state["versions"]["1.0.0"]["description"] = serde_json::json!("second");
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                serde_json::to_vec(&same_manifest_new_state).unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        let manifest = ctx
            .state
            .storage
            .get(&hosted_version_key("npm-private", "pkg", "1.0.0"))
            .await
            .unwrap();
        assert_eq!(
            ctx.state
                .storage
                .get(&hosted_publish_complete_key("npm-private", "pkg", "1.0.0"))
                .await
                .unwrap()
                .as_ref(),
            crate::npm_layout::hosted_manifest_digest(&manifest).as_bytes()
        );
        assert_eq!(
            ctx.state
                .storage
                .get(
                    &crate::npm_layout::hosted_blob_key_from_manifest(
                        "npm-private",
                        "pkg",
                        &manifest
                    )
                    .unwrap()
                )
                .await
                .unwrap()
                .as_ref(),
            second_tarball.as_slice()
        );

        let packument = send(&ctx.app, Method::GET, "/repository/npm-private/pkg", "").await;
        let packument: serde_json::Value =
            serde_json::from_slice(&body_bytes(packument).await).unwrap();
        assert_eq!(packument["versions"]["1.0.0"]["description"], "second");
        assert_eq!(packument["description"], "replacement package fields");
        assert_eq!(packument["dist-tags"]["latest"], "1.0.0");
        assert_eq!(packument["dist-tags"]["next"], "1.0.0");
        let tarball = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-private/pkg/-/pkg-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(tarball.status(), StatusCode::OK);
        assert_eq!(
            body_bytes(tarball).await.as_ref(),
            second_tarball.as_slice()
        );
    }

    #[tokio::test]
    async fn allow_redeploy_stale_completion_blocks_later_mutations_until_retry() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(|config| {
            named_config(config);
            let NpmRepository::Hosted { write_policy, .. } = &mut config.npm.repositories[0] else {
                unreachable!()
            };
            *write_policy = NpmWritePolicy::Allow;
        });
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                publish_payload_with_tarball("pkg", "1.0.0", "latest", "first"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        let second = publish_payload_with_tarball("pkg", "1.0.0", "latest", "second");
        let second_value: serde_json::Value = serde_json::from_slice(&second).unwrap();
        let validated = validate_publish("pkg", &second_value).unwrap();
        let blob_key = crate::npm_layout::hosted_blob_key_for_digest(
            "npm-private",
            "pkg",
            &validated.blob_digest,
        );
        ctx.state
            .storage
            .put(&blob_key, &validated.tarball)
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                &hosted_version_key("npm-private", "pkg", "1.0.0"),
                &validated.manifest,
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                &hosted_publish_pending_key("npm-private", "pkg", "1.0.0"),
                crate::npm_layout::hosted_manifest_digest(&validated.manifest).as_bytes(),
            )
            .await
            .unwrap();
        let stale_marker = ctx
            .state
            .storage
            .get(&hosted_publish_complete_key("npm-private", "pkg", "1.0.0"))
            .await
            .unwrap();
        assert_ne!(
            stale_marker.as_ref(),
            crate::npm_layout::hosted_manifest_digest(&validated.manifest).as_bytes()
        );

        let deprecation = serde_json::json!({
            "name": "pkg",
            "versions": {"1.0.0": {"deprecated": "later"}}
        });
        for response in [
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                publish_payload("pkg", "2.0.0", "latest"),
            )
            .await,
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/-/package/pkg/dist-tags/next",
                serde_json::to_vec("1.0.0").unwrap(),
            )
            .await,
            send(
                &ctx.app,
                Method::DELETE,
                "/repository/npm-private/-/package/pkg/dist-tags/next",
                "",
            )
            .await,
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                serde_json::to_vec(&deprecation).unwrap(),
            )
            .await,
        ] {
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }

        assert_eq!(
            send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", second,)
                .await
                .status(),
            StatusCode::CREATED
        );
        let manifest = ctx
            .state
            .storage
            .get(&hosted_version_key("npm-private", "pkg", "1.0.0"))
            .await
            .unwrap();
        assert_eq!(
            ctx.state
                .storage
                .get(&hosted_publish_complete_key("npm-private", "pkg", "1.0.0"))
                .await
                .unwrap()
                .as_ref(),
            crate::npm_layout::hosted_manifest_digest(&manifest).as_bytes()
        );
    }

    #[tokio::test]
    async fn group_package_put_routes_deprecation_to_hosted_overlay() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(named_config);
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                publish_payload("pkg", "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let deprecation = serde_json::json!({
            "name": "pkg",
            "versions": {
                "1.0.0": {"deprecated": "do not use"}
            }
        });
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-group/pkg",
                serde_json::to_vec(&deprecation).unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let response = send(&ctx.app, Method::GET, "/repository/npm-group/pkg", "").await;
        let packument: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(packument["versions"]["1.0.0"]["deprecated"], "do not use");
    }

    #[tokio::test]
    async fn group_dist_tag_mutation_is_rejected_but_hosted_delete_is_idempotent() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        let ctx = create_test_context_with_config(named_config);
        let response = send(
            &ctx.app,
            Method::PUT,
            "/repository/npm-group/-/package/pkg/dist-tags/next",
            r#""1.0.0""#,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        for _ in 0..2 {
            let response = send(
                &ctx.app,
                Method::DELETE,
                "/repository/npm-private/-/package/pkg/dist-tags/next",
                "",
            )
            .await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }
    }

    #[tokio::test]
    async fn group_packument_rewrites_tarballs_to_group_route() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;
        let ctx = create_test_context_with_config(named_config);
        let body = publish_payload("pkg", "1.0.0", "latest");
        assert_eq!(
            send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", body)
                .await
                .status(),
            StatusCode::CREATED
        );
        let response = send(&ctx.app, Method::GET, "/repository/npm-group/pkg", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let packument: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(packument["dist-tags"]["latest"], "1.0.0");
        assert_eq!(
            packument["versions"]["1.0.0"]["dist"]["tarball"],
            "http://127.0.0.1:0/repository/npm-group/pkg/-/pkg-1.0.0.tgz"
        );
    }

    #[tokio::test]
    async fn proxy_never_receives_internal_namespace_request() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        let ctx = create_test_context_with_config(|config| {
            named_config(config);
            config.curation.internal_namespaces = vec!["@internal/**".into()];
        });
        let response = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-group/@internal%2Fpkg",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Axum and the npm path decoder each consume one encoding layer. A
        // further residual `%` must be rejected instead of becoming a public
        // proxy coordinate that an upstream could decode again.
        let response = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-group/%252540internal%25252Fpkg",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn deleting_hosted_tag_reveals_lower_priority_proxy_tag() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(named_config);
        let proxy_packument = serde_json::json!({
            "name": "pkg",
            "versions": {
                "9.0.0": {
                    "name": "pkg",
                    "version": "9.0.0",
                    "dist": {
                        "shasum": "0000000000000000000000000000000000000000",
                        "tarball": "https://registry.npmjs.org/pkg/-/pkg-9.0.0.tgz"
                    }
                }
            },
            "dist-tags": {"next": "9.0.0"}
        });
        ctx.state
            .storage
            .put(
                &proxy_packument_key("npm-registry", "pkg"),
                &serde_json::to_vec(&proxy_packument).unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                publish_payload("pkg", "1.0.0", "next"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        let before = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-group/-/package/pkg/dist-tags",
            "",
        )
        .await;
        let before: serde_json::Value = serde_json::from_slice(&body_bytes(before).await).unwrap();
        assert_eq!(before["next"], "1.0.0");

        assert_eq!(
            send(
                &ctx.app,
                Method::DELETE,
                "/repository/npm-private/-/package/pkg/dist-tags/next",
                "",
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        let after = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-group/-/package/pkg/dist-tags",
            "",
        )
        .await;
        let after: serde_json::Value = serde_json::from_slice(&body_bytes(after).await).unwrap();
        assert_eq!(after["next"], "9.0.0");
    }

    #[tokio::test]
    async fn group_tarball_uses_the_same_first_member_as_version_metadata() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(named_config);
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                publish_payload("pkg", "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let hosted = ctx
            .state
            .storage
            .get(
                &crate::npm_layout::hosted_blob_key_from_manifest(
                    "npm-private",
                    "pkg",
                    &ctx.state
                        .storage
                        .get(&hosted_version_key("npm-private", "pkg", "1.0.0"))
                        .await
                        .unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let proxy_bytes = b"different-proxy-bytes";
        let proxy_packument = serde_json::json!({
            "name": "pkg",
            "versions": {
                "1.0.0": {
                    "name": "pkg",
                    "version": "1.0.0",
                    "dist": {
                        "shasum": hex::encode(sha1::Sha1::digest(proxy_bytes)),
                        "tarball": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
                    }
                }
            },
            "dist-tags": {"latest": "1.0.0"}
        });
        ctx.state
            .storage
            .put(
                &proxy_packument_key("npm-registry", "pkg"),
                &serde_json::to_vec(&proxy_packument).unwrap(),
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                &proxy_tarball_key("npm-registry", "pkg", "pkg-1.0.0.tgz"),
                proxy_bytes,
            )
            .await
            .unwrap();

        let response = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-group/pkg/-/pkg-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await.as_ref(), hosted.as_ref());
    }

    #[tokio::test]
    async fn curation_blocklist_gates_hosted_and_proxy_tarball_reads() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;

        let policy_dir = tempfile::TempDir::new().unwrap();
        let policy_path = policy_dir.path().join("blocklist.json");
        std::fs::write(
            &policy_path,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "rules": [{
                    "registry": "npm",
                    "name": "blocked",
                    "version": "*",
                    "reason": "test policy"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let policy_path = policy_path.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            config.curation.mode = crate::config::CurationMode::Enforce;
            config.curation.blocklist_path = Some(policy_path);
        });
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/blocked",
                publish_payload("blocked", "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        for repository in ["npm-private", "npm-registry"] {
            let response = send(
                &ctx.app,
                Method::GET,
                &format!("/repository/{repository}/blocked/-/blocked-1.0.0.tgz"),
                "",
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{repository}");
            assert_eq!(
                response
                    .headers()
                    .get("x-nora-rule")
                    .and_then(|value| value.to_str().ok()),
                Some("blocklist")
            );
        }
    }

    #[tokio::test]
    async fn curation_integrity_gates_hosted_and_cached_proxy_tarballs() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;

        let policy_dir = tempfile::TempDir::new().unwrap();
        let policy_path = policy_dir.path().join("allowlist.json");
        std::fs::write(
            &policy_path,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "entries": [{
                    "registry": "npm",
                    "name": "pkg",
                    "version": "1.0.0",
                    "integrity": format!("sha256:{}", "0".repeat(64)),
                    "integrity_source": "test"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let policy_path = policy_path.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            config.curation.mode = crate::config::CurationMode::Enforce;
            config.curation.allowlist_path = Some(policy_path);
            config.curation.require_integrity = true;
        });
        let tarball = npm_tarball("pkg", "1.0.0");
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                publish_payload("pkg", "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let proxy_packument = serde_json::json!({
            "name": "pkg",
            "versions": {
                "1.0.0": {
                    "name": "pkg",
                    "version": "1.0.0",
                    "dist": {
                        "shasum": hex::encode(sha1::Sha1::digest(&tarball)),
                        "integrity": format!(
                            "sha512-{}",
                            base64::engine::general_purpose::STANDARD
                                .encode(sha2::Sha512::digest(&tarball))
                        ),
                        "tarball": "http://127.0.0.1:1/pkg/-/pkg-1.0.0.tgz"
                    }
                }
            },
            "dist-tags": {"latest": "1.0.0"}
        });
        ctx.state
            .storage
            .put(
                &proxy_packument_key("npm-registry", "pkg"),
                &serde_json::to_vec(&proxy_packument).unwrap(),
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                &proxy_tarball_key("npm-registry", "pkg", "pkg-1.0.0.tgz"),
                &tarball,
            )
            .await
            .unwrap();

        for repository in ["npm-private", "npm-registry"] {
            let response = send(
                &ctx.app,
                Method::GET,
                &format!("/repository/{repository}/pkg/-/pkg-1.0.0.tgz"),
                "",
            )
            .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{repository}");
            assert_eq!(
                response
                    .headers()
                    .get("x-nora-rule")
                    .and_then(|value| value.to_str().ok()),
                Some("allowlist:integrity")
            );
        }
    }

    #[tokio::test]
    async fn concurrent_proxy_tarball_cold_miss_is_single_flight() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        use std::sync::Arc;
        use tokio::sync::Barrier;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let tarball = npm_tarball("pkg", "1.0.0");
        Mock::given(method("GET"))
            .and(path("/pkg/-/pkg-1.0.0.tgz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(100))
                    .set_body_bytes(tarball.clone()),
            )
            .expect(1)
            .mount(&upstream)
            .await;

        let upstream_url = upstream.uri();
        let configured_url = upstream_url.clone();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });
        let packument = serde_json::json!({
            "name": "pkg",
            "versions": {
                "1.0.0": {
                    "name": "pkg",
                    "version": "1.0.0",
                    "dist": {
                        "shasum": hex::encode(sha1::Sha1::digest(&tarball)),
                        "integrity": format!(
                            "sha512-{}",
                            base64::engine::general_purpose::STANDARD
                                .encode(sha2::Sha512::digest(&tarball))
                        ),
                        "tarball": format!("{upstream_url}/pkg/-/pkg-1.0.0.tgz")
                    }
                }
            },
            "dist-tags": {"latest": "1.0.0"}
        });
        ctx.state
            .storage
            .put(
                &proxy_packument_key("npm-registry", "pkg"),
                &serde_json::to_vec(&packument).unwrap(),
            )
            .await
            .unwrap();

        const CLIENTS: usize = 16;
        let barrier = Arc::new(Barrier::new(CLIENTS));
        let mut tasks = Vec::new();
        for _ in 0..CLIENTS {
            let app = ctx.app.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                send(
                    &app,
                    Method::GET,
                    "/repository/npm-registry/pkg/-/pkg-1.0.0.tgz",
                    "",
                )
                .await
                .status()
            }));
        }
        for result in futures::future::join_all(tasks).await {
            assert_eq!(result.unwrap(), StatusCode::OK);
        }
        upstream.verify().await;
    }

    #[tokio::test]
    async fn proxy_packument_validates_every_redirect_before_auth() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let attacker = MockServer::start().await;
        let credentials = "reader:secret";
        let authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials)
        );
        let upstream_base = format!("{}/repository/npm", upstream.uri());
        let cross_origin_location = format!("{}/steal", attacker.uri());

        Mock::given(method("GET"))
            .and(path("/repository/npm/cross"))
            .and(header("authorization", authorization.as_str()))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", cross_origin_location.as_str()),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/repository/npm/outside"))
            .and(header("authorization", authorization.as_str()))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/outside/steal"))
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/outside/steal"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/repository/npm/allowed"))
            .and(header("authorization", authorization.as_str()))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "/repository/npm/allowed-final"),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/repository/npm/allowed-final"))
            .and(header("authorization", authorization.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "allowed",
                "versions": {},
                "dist-tags": {}
            })))
            .expect(1)
            .mount(&upstream)
            .await;

        let configured_url = upstream_base.clone();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy {
                url,
                auth,
                metadata_ttl,
                ..
            } = &mut config.npm.repositories[1]
            {
                *url = configured_url;
                *auth = Some(crate::secrets::ProtectedString::new(
                    credentials.to_string(),
                ));
                *metadata_ttl = Some(0);
            }
        });

        for package in ["cross", "outside"] {
            let response = send(
                &ctx.app,
                Method::GET,
                &format!("/repository/npm-registry/{package}"),
                "",
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{package}");
        }
        assert!(
            attacker.received_requests().await.unwrap().is_empty(),
            "cross-origin redirect target must receive neither request nor auth"
        );
        assert!(
            upstream
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.url.path() != "/outside/steal"),
            "same-origin redirect outside the configured base path must not be requested"
        );

        let response = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-registry/allowed",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        upstream.verify().await;
    }

    #[tokio::test]
    async fn proxy_tarball_validates_initial_url_and_every_redirect_before_auth() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let attacker = MockServer::start().await;
        let tarball = npm_tarball("pkg", "1.0.0");
        let credentials = "reader:secret";
        let authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials)
        );
        let upstream_base = format!("{}/repository/npm", upstream.uri());
        let cross_origin_location = format!("{}/steal", attacker.uri());

        Mock::given(method("GET"))
            .and(path("/repository/npm/redirect-cross-origin"))
            .and(header("authorization", authorization.as_str()))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", cross_origin_location.as_str()),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/repository/npm/redirect-outside-base"))
            .and(header("authorization", authorization.as_str()))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/outside/steal"))
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/repository/npm/redirect-allowed"))
            .and(header("authorization", authorization.as_str()))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "/repository/npm/pkg/-/pkg-1.0.0.tgz"),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/repository/npm/pkg/-/pkg-1.0.0.tgz"))
            .and(header("authorization", authorization.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.clone()))
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/outside/steal"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&upstream)
            .await;

        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let repository = ProxyRepository {
            name: "npm-registry".to_string(),
            url: upstream_base.clone(),
            auth: Some(crate::secrets::ProtectedString::new(
                credentials.to_string(),
            )),
            metadata_ttl: 300,
            negative_ttl: 0,
        };
        assert!(ctx
            .state
            .repo_index
            .get("npm", &ctx.state.storage)
            .await
            .is_empty());
        let packument = |tarball_url: String| {
            serde_json::json!({
                "name": "pkg",
                "versions": {
                    "1.0.0": {
                        "name": "pkg",
                        "version": "1.0.0",
                        "dist": {
                            "shasum": hex::encode(sha1::Sha1::digest(&tarball)),
                            "tarball": tarball_url
                        }
                    }
                },
                "dist-tags": {"latest": "1.0.0"}
            })
        };
        let key = proxy_packument_key("npm-registry", "pkg");
        let misses_before = ctx.state.metrics.cache_misses();
        let hits_before = ctx.state.metrics.cache_hits();
        ctx.state
            .storage
            .put(
                &key,
                &serde_json::to_vec(&packument(format!("{}/steal", attacker.uri()))).unwrap(),
            )
            .await
            .unwrap();

        let rejected =
            serve_proxy_tarball(&ctx.state, &repository, "pkg", "pkg-1.0.0.tgz", None).await;
        assert_eq!(rejected.status(), StatusCode::BAD_GATEWAY);
        assert!(
            attacker.received_requests().await.unwrap().is_empty(),
            "cross-origin URL must be rejected without a request"
        );

        ctx.state
            .storage
            .put(
                &key,
                &serde_json::to_vec(&packument(format!("{upstream_base}/redirect-cross-origin")))
                    .unwrap(),
            )
            .await
            .unwrap();
        let rejected_redirect =
            serve_proxy_tarball(&ctx.state, &repository, "pkg", "pkg-1.0.0.tgz", None).await;
        assert_eq!(rejected_redirect.status(), StatusCode::BAD_GATEWAY);
        assert!(
            attacker.received_requests().await.unwrap().is_empty(),
            "cross-origin redirect target must receive neither request nor auth"
        );

        ctx.state
            .storage
            .put(
                &key,
                &serde_json::to_vec(&packument(format!("{upstream_base}/redirect-outside-base")))
                    .unwrap(),
            )
            .await
            .unwrap();
        let rejected_redirect =
            serve_proxy_tarball(&ctx.state, &repository, "pkg", "pkg-1.0.0.tgz", None).await;
        assert_eq!(rejected_redirect.status(), StatusCode::BAD_GATEWAY);
        assert!(
            upstream
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.url.path() != "/outside/steal"),
            "same-origin redirect outside the configured base path must not be requested"
        );

        ctx.state
            .storage
            .put(
                &key,
                &serde_json::to_vec(&packument(format!("{upstream_base}/redirect-allowed")))
                    .unwrap(),
            )
            .await
            .unwrap();
        let accepted =
            serve_proxy_tarball(&ctx.state, &repository, "pkg", "pkg-1.0.0.tgz", None).await;
        assert_eq!(accepted.status(), StatusCode::OK);
        assert!(ctx.state.metrics.cache_misses() >= misses_before + 1);
        let cached =
            serve_proxy_tarball(&ctx.state, &repository, "pkg", "pkg-1.0.0.tgz", None).await;
        assert_eq!(cached.status(), StatusCode::OK);
        assert!(ctx.state.metrics.cache_hits() >= hits_before + 1);
        assert!(ctx
            .state
            .repo_index
            .get("npm", &ctx.state.storage)
            .await
            .iter()
            .any(|entry| entry.name == "repositories/npm-registry/pkg"));
        upstream.verify().await;
    }

    #[tokio::test]
    async fn stale_proxy_packument_marks_response_and_rewrites_nested_upstream_urls() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&upstream)
            .await;
        let upstream_url = upstream.uri();
        let configured_url = upstream_url.clone();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy {
                url, metadata_ttl, ..
            } = &mut config.npm.repositories[1]
            {
                *url = configured_url;
                *metadata_ttl = Some(0);
            }
        });
        let cached = serde_json::json!({
            "name": "pkg",
            "custom": format!("{upstream_url}/custom"),
            "nested": [{"docs": format!("{upstream_url}/docs")}],
            "description": format!("do not replace embedded {upstream_url}/text"),
            "versions": {
                "1.0.0": {
                    "name": "pkg",
                    "version": "1.0.0",
                    "dist": {
                        "tarball": format!("{upstream_url}/pkg/-/pkg-1.0.0.tgz")
                    }
                }
            },
            "dist-tags": {"latest": "1.0.0"}
        });
        ctx.state
            .storage
            .put(
                &proxy_packument_key("npm-registry", "pkg"),
                &serde_json::to_vec(&cached).unwrap(),
            )
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/repository/npm-group/pkg", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-nora-stale")
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
        let body: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        let public = public_base(&ctx.state, Some("npm-group"));
        assert_eq!(body["custom"], format!("{public}/custom"));
        assert_eq!(body["nested"][0]["docs"], format!("{public}/docs"));
        assert_eq!(
            body["versions"]["1.0.0"]["dist"]["tarball"],
            format!("{public}/pkg/-/pkg-1.0.0.tgz")
        );
        assert_eq!(
            body["description"],
            format!("do not replace embedded {upstream_url}/text")
        );
        upstream.verify().await;
    }

    #[tokio::test]
    async fn proxy_packument_304_restores_revalidation_telemetry() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .and(header("if-none-match", "\"v1\""))
            .respond_with(ResponseTemplate::new(304))
            .expect(1)
            .mount(&upstream)
            .await;
        let configured_url = upstream.uri();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy {
                url, metadata_ttl, ..
            } = &mut config.npm.repositories[1]
            {
                *url = configured_url;
                *metadata_ttl = Some(0);
            }
        });
        let key = proxy_packument_key("npm-registry", "pkg");
        ctx.state
            .storage
            .put(&key, br#"{"name":"pkg","versions":{},"dist-tags":{}}"#)
            .await
            .unwrap();
        write_validators(
            &ctx.state.storage,
            &key,
            &Validators {
                etag: Some("\"v1\"".to_string()),
                last_modified: None,
            },
        )
        .await;
        let before_304 = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["npm"])
            .get();
        let before_bytes = crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
            .with_label_values(&["npm"])
            .get();

        let response = send(&ctx.app, Method::GET, "/repository/npm-registry/pkg", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            crate::metrics::PROXY_UPSTREAM_304_TOTAL
                .with_label_values(&["npm"])
                .get()
                > before_304
        );
        assert!(
            crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                .with_label_values(&["npm"])
                .get()
                > before_bytes
        );
        assert!(response.headers().get("x-nora-stale").is_none());
        upstream.verify().await;
    }

    #[tokio::test]
    async fn direct_proxy_search_forwards_query_once_and_applies_pagination_once() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;
        use std::collections::HashMap;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let objects = ["one", "two"]
            .into_iter()
            .map(|name| serde_json::json!({"package": {"name": name, "version": "1.0.0"}}))
            .collect::<Vec<_>>();
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": objects,
                "total": 3,
                "time": "1ms"
            })))
            .expect(1)
            .mount(&upstream)
            .await;
        let configured_url = upstream.uri();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });

        let response = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-registry/-/v1/search?text=pkg&from=1&size=2",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(response["objects"][0]["package"]["name"], "one");
        assert_eq!(response["objects"][1]["package"]["name"], "two");
        assert_eq!(response["total"], 3);
        assert_eq!(response["totalIsApproximate"], false);

        let requests = upstream.received_requests().await.unwrap();
        let query: HashMap<_, _> = requests[0].url.query_pairs().into_owned().collect();
        assert_eq!(query.get("text").map(String::as_str), Some("pkg"));
        assert_eq!(query.get("from").map(String::as_str), Some("1"));
        assert_eq!(query.get("size").map(String::as_str), Some("2"));
    }

    #[tokio::test]
    async fn direct_proxy_search_preserves_offsets_beyond_upstream_page_size() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .and(query_param("text", "pkg"))
            .and(query_param("from", "300"))
            .and(query_param("size", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": [
                    {"package": {"name": "item-300", "version": "1.0.0"}},
                    {"package": {"name": "item-301", "version": "1.0.0"}}
                ],
                "total": 1000,
                "time": "1ms"
            })))
            .expect(1)
            .mount(&upstream)
            .await;
        let configured_url = upstream.uri();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });

        let response = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-registry/-/v1/search?text=pkg&from=300&size=2",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(response["objects"][0]["package"]["name"], "item-300");
        assert_eq!(response["objects"][1]["package"]["name"], "item-301");
        assert_eq!(response["total"], 1000);
        assert_eq!(response["totalIsApproximate"], false);
        upstream.verify().await;
    }

    #[tokio::test]
    async fn direct_proxy_search_uses_hot_reloaded_namespace_filter_before_applying_offset() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .and(query_param("from", "0"))
            .and(query_param("size", "250"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": [
                    {"package": {"name": "@internal/pkg", "version": "1.0.0"}},
                    {"package": {"name": "public-one", "version": "1.0.0"}}
                ],
                "total": 3
            })))
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .and(query_param("from", "2"))
            .and(query_param("size", "250"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": [
                    {"package": {"name": "public-two", "version": "1.0.0"}}
                ],
                "total": 3
            })))
            .expect(1)
            .mount(&upstream)
            .await;
        let configured_url = upstream.uri();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });
        assert!(
            ctx.state.config.curation.internal_namespaces.is_empty(),
            "the immutable startup snapshot must remain empty in this reload regression"
        );
        let mut reloaded_config = ctx.state.config.curation.clone();
        reloaded_config.internal_namespaces = vec!["@internal/**".into()];
        let mut reloaded_engine = crate::curation::CurationEngine::new(reloaded_config);
        reloaded_engine.set_namespace_filter(Box::new(crate::curation::NamespaceFilter::new(
            vec!["@internal/**".into()],
        )));
        ctx.state
            .reloadable
            .store(std::sync::Arc::new(crate::ReloadableConfig {
                curation_engine: reloaded_engine,
                bypass_token: None,
            }));

        let response = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-registry/-/v1/search?text=public&from=1&size=1",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(response["objects"][0]["package"]["name"], "public-two");
        assert_eq!(response["objects"].as_array().unwrap().len(), 1);
        assert_eq!(response["total"], 3);
        assert_eq!(response["totalIsApproximate"], true);
        upstream.verify().await;
    }

    #[tokio::test]
    async fn group_search_pages_upstream_until_large_offset_is_satisfied() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let first = (0..250)
            .map(|index| {
                serde_json::json!({
                    "package": {"name": format!("item-{index:03}"), "version": "1.0.0"}
                })
            })
            .collect::<Vec<_>>();
        let second = (250..302)
            .map(|index| {
                serde_json::json!({
                    "package": {"name": format!("item-{index:03}"), "version": "1.0.0"}
                })
            })
            .collect::<Vec<_>>();
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .and(query_param("from", "0"))
            .and(query_param("size", "250"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": first,
                "total": 302
            })))
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .and(query_param("from", "250"))
            .and(query_param("size", "250"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": second,
                "total": 302
            })))
            .expect(1)
            .mount(&upstream)
            .await;
        let configured_url = upstream.uri();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });

        let response = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-group/-/v1/search?text=item&from=300&size=2",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(response["objects"][0]["package"]["name"], "item-300");
        assert_eq!(response["objects"][1]["package"]["name"], "item-301");
        assert_eq!(response["total"], 302);
        assert_eq!(response["totalIsApproximate"], true);
        upstream.verify().await;
    }

    #[tokio::test]
    async fn group_search_rejects_windows_beyond_the_scan_budget_without_upstream_io() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&upstream)
            .await;
        let configured_url = upstream.uri();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });

        let response = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-group/-/v1/search?text=pkg&from=10000&size=1",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        upstream.verify().await;
    }

    #[tokio::test]
    async fn group_search_stops_repeating_upstream_pages_at_the_page_and_result_budget() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let repeated = (0..250)
            .map(|index| {
                serde_json::json!({
                    "package": {"name": format!("same-{index:03}"), "version": "1.0.0"}
                })
            })
            .collect::<Vec<_>>();
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": repeated,
                "total": 10_001
            })))
            .expect(NPM_SEARCH_SCAN_PAGE_CAP as u64)
            .mount(&upstream)
            .await;
        let configured_url = upstream.uri();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });

        let response = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-group/-/v1/search?text=same&from=250&size=1",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        upstream.verify().await;
    }

    #[tokio::test]
    async fn proxy_search_scan_deadline_fails_before_upstream_io() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&upstream)
            .await;
        let configured_url = upstream.uri();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });
        let repository = configured_proxy(
            &ctx.state,
            ctx.state.config.npm.repository("npm-registry").unwrap(),
        )
        .unwrap();

        assert!(matches!(
            proxy_search_page_before(
                &ctx.state,
                &repository,
                Some("text=pkg"),
                Instant::now() - Duration::from_millis(1),
            )
            .await,
            Err(ReadError::SearchScanLimit)
        ));
        upstream.verify().await;
    }

    #[tokio::test]
    async fn group_search_returns_empty_success_and_never_proxies_mixed_internal_query() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": [],
                "total": 0,
                "time": "1ms"
            })))
            .expect(1)
            .mount(&upstream)
            .await;
        let configured_url = upstream.uri();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            config.curation.internal_namespaces = vec!["@internal/**".into()];
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });

        let empty = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-group/-/v1/search?text=no-match",
            "",
        )
        .await;
        assert_eq!(empty.status(), StatusCode::OK);
        let empty: serde_json::Value = serde_json::from_slice(&body_bytes(empty).await).unwrap();
        assert_eq!(empty["objects"], serde_json::json!([]));
        assert_eq!(empty["total"], 0);

        let internal = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-group/-/v1/search?text=foo%20%40internal%2Fpkg",
            "",
        )
        .await;
        assert_eq!(internal.status(), StatusCode::OK);
        let internal: serde_json::Value =
            serde_json::from_slice(&body_bytes(internal).await).unwrap();
        assert_eq!(internal["objects"], serde_json::json!([]));
        assert_eq!(
            upstream.received_requests().await.unwrap().len(),
            1,
            "the mixed internal query must not be sent upstream"
        );

        for query in ["text=not%3A%40internal%2Fpkg", "quality=%40internal%2Fpkg"] {
            let response = send(
                &ctx.app,
                Method::GET,
                &format!("/repository/npm-group/-/v1/search?{query}"),
                "",
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let response: serde_json::Value =
                serde_json::from_slice(&body_bytes(response).await).unwrap();
            assert_eq!(response["objects"], serde_json::json!([]));
        }
        assert_eq!(
            upstream.received_requests().await.unwrap().len(),
            1,
            "decoded internal package names in qualifiers or arbitrary parameters must not leak"
        );
    }

    #[tokio::test]
    async fn group_search_deduplicates_with_hosted_member_precedence() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": [
                    {"package": {"name": "pkg", "version": "9.0.0"}},
                    {"package": {"name": "pkg-public", "version": "2.0.0"}}
                ],
                "total": 2,
                "time": "1ms"
            })))
            .expect(1)
            .mount(&upstream)
            .await;
        let configured_url = upstream.uri();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                publish_payload("pkg", "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        let response = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-group/-/v1/search?text=pkg&size=20",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(response["objects"].as_array().unwrap().len(), 2);
        assert_eq!(response["objects"][0]["package"]["name"], "pkg");
        assert_eq!(response["objects"][0]["package"]["version"], "1.0.0");
        assert_eq!(
            response["objects"][0]["package"]["maintainers"],
            serde_json::json!([])
        );
        assert_eq!(response["objects"][1]["package"]["name"], "pkg-public");
    }

    #[tokio::test]
    async fn group_search_marks_healthy_member_results_approximate_when_proxy_fails() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .respond_with(ResponseTemplate::new(503))
            .expect(2)
            .mount(&upstream)
            .await;
        let configured_url = upstream.uri();
        let ctx = create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                publish_payload("pkg", "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        let response = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-group/-/v1/search?text=pkg&size=20",
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(response["objects"].as_array().unwrap().len(), 1);
        assert_eq!(response["objects"][0]["package"]["name"], "pkg");
        assert_eq!(response["total"], 1);
        assert_eq!(response["totalIsApproximate"], true);
        upstream.verify().await;
    }

    #[tokio::test]
    async fn hosted_only_group_search_marks_partial_results_approximate_on_member_read_error() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(|config| {
            config.npm.proxy = None;
            config.npm.repositories = vec![
                NpmRepository::Hosted {
                    name: "healthy-hosted".into(),
                    write_policy: NpmWritePolicy::AllowOnce,
                },
                NpmRepository::Hosted {
                    name: "broken-hosted".into(),
                    write_policy: NpmWritePolicy::AllowOnce,
                },
                NpmRepository::Group {
                    name: "npm-group".into(),
                    members: vec!["healthy-hosted".into(), "broken-hosted".into()],
                    writable_member: None,
                },
            ];
            config.npm.default_repository = Some("npm-group".into());
        });
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/healthy-hosted/healthy",
                publish_payload("healthy", "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/broken-hosted/broken",
                publish_payload("broken", "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        ctx.state
            .repo_index
            .get_strict("npm", &ctx.state.storage)
            .await
            .expect("prime a verified hosted package index before injecting a member read failure");

        let broken_manifest = hosted_version_key("broken-hosted", "broken", "1.0.0");
        let mut state = ctx.state.clone();
        state.storage = crate::storage::Storage::from_backend(std::sync::Arc::new(
            crate::test_helpers::FaultInjectBackend::new(ctx.state.storage.clone())
                .fail_get(&broken_manifest),
        ));
        let target = named_target(&state, "npm-group").unwrap();
        let response = handle_search(
            &state,
            &target,
            &public_base(&state, Some("npm-group")),
            &HeaderMap::new(),
            Some("text=&size=20"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(response["objects"].as_array().unwrap().len(), 1);
        assert_eq!(response["objects"][0]["package"]["name"], "healthy");
        assert_eq!(response["total"], 1);
        assert_eq!(response["totalIsApproximate"], true);
    }

    #[tokio::test]
    async fn successful_named_audit_forward_records_non_sensitive_audit_event() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/npm/v1/security/advisories/bulk"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&upstream)
            .await;
        let configured_url = upstream.uri();
        let ctx = crate::test_helpers::create_test_context_with_config(move |config| {
            named_config(config);
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });
        let audit_dir = tempfile::tempdir().unwrap();
        let mut state = ctx.state.clone();
        state.audit = std::sync::Arc::new(crate::audit::AuditLog::new(
            audit_dir.path().to_str().unwrap(),
            crate::audit::AuditMode::File,
        ));
        let target = named_target(&state, "npm-group").unwrap();

        let response = handle_post(
            state.clone(),
            target,
            "-/npm/v1/security/advisories/bulk".to_string(),
            HeaderMap::new(),
            Body::from(br#"{"pkg":["1.0.0"]}"#.as_slice()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        state.audit.shutdown().await;
        let line = std::fs::read_to_string(audit_dir.path().join("audit.jsonl")).unwrap();
        let event: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(event["action"], "proxy_fetch");
        assert_eq!(event["registry"], "npm");
        assert_eq!(event["detail"], "audit");
        assert!(
            !line.contains("1.0.0"),
            "audit event must not include request body contents"
        );
        upstream.verify().await;
    }

    #[tokio::test]
    async fn gzip_npm6_audit_paths_strip_internal_dependencies_and_lockfile_packages() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        for path_value in [
            "/-/npm/v1/security/audits",
            "/-/npm/v1/security/audits/quick",
        ] {
            Mock::given(method("POST"))
                .and(path(path_value))
                .respond_with(
                    ResponseTemplate::new(400)
                        .set_body_json(serde_json::json!({"error": "unsupported by upstream"})),
                )
                .expect(1)
                .mount(&upstream)
                .await;
        }
        let configured_url = upstream.uri();
        let ctx = crate::test_helpers::create_test_context_with_config(move |config| {
            named_config(config);
            config.curation.internal_namespaces = vec!["@internal/**".into()];
            if let NpmRepository::Proxy { url, .. } = &mut config.npm.repositories[1] {
                *url = configured_url;
            }
        });
        let payload = serde_json::to_vec(&serde_json::json!({
            "name": "application",
            "dependencies": {
                "public-package": {"version": "1.0.0"},
                "@internal/pkg": {"version": "2.0.0"}
            },
            "requires": {
                "public-package": "^1",
                "@internal/pkg": "^2"
            },
            "packages": {
                "": {"name": "application"},
                "node_modules/public-package": {"name": "public-package"},
                "node_modules/@internal/pkg": {"name": "@internal/pkg"}
            }
        }))
        .unwrap();
        let compressed = gzip_audit_body(&payload).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));

        for audit_path in ["-/npm/v1/security/audits", "-/npm/v1/security/audits/quick"] {
            let response = handle_post(
                ctx.state.clone(),
                named_target(&ctx.state, "npm-group").unwrap(),
                audit_path.to_string(),
                headers.clone(),
                Body::from(compressed.clone()),
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "upstream status must be relayed for {audit_path}"
            );
        }

        let requests = upstream.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests {
            let (decoded, was_gzip) = decode_audit_body(&headers, request.body.as_slice()).unwrap();
            assert!(was_gzip);
            let forwarded: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
            assert!(
                !String::from_utf8_lossy(&decoded).contains("@internal"),
                "internal package names must never leave Nora"
            );
            assert!(forwarded["dependencies"].get("public-package").is_some());
            assert!(forwarded["requires"].get("public-package").is_some());
            assert!(forwarded["packages"]
                .get("node_modules/public-package")
                .is_some());
            assert!(forwarded["dependencies"].get("@internal/pkg").is_none());
            assert!(forwarded["packages"]
                .get("node_modules/@internal/pkg")
                .is_none());
        }
        upstream.verify().await;
    }

    #[tokio::test]
    async fn audit_rejects_empty_unsafe_or_hosted_only_requests_instead_of_false_success() {
        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let hosted = named_target(&ctx.state, "npm-private").unwrap();
        let response = handle_post(
            ctx.state.clone(),
            hosted,
            "-/npm/v1/security/audits/quick".to_string(),
            HeaderMap::new(),
            Body::empty(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
        let response = handle_post(
            ctx.state.clone(),
            named_target(&ctx.state, "npm-group").unwrap(),
            "-/npm/v1/security/audits".to_string(),
            headers,
            Body::from(br#"{"name":"app"}"#.as_slice()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn audit_redirects_are_validated_before_replaying_auth_and_body() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let attacker = MockServer::start().await;
        let credentials = "reader:secret";
        let authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials)
        );
        let audit_path = "-/npm/v1/security/advisories/bulk";
        let request_body = br#"{"pkg":["1.0.0"]}"#;
        let cross_location = format!("{}/steal", attacker.uri());

        Mock::given(method("POST"))
            .and(path(
                "/repository/npm-cross/-/npm/v1/security/advisories/bulk",
            ))
            .and(header("authorization", authorization.as_str()))
            .respond_with(
                ResponseTemplate::new(307).insert_header("location", cross_location.as_str()),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/repository/npm-allowed/-/npm/v1/security/advisories/bulk",
            ))
            .and(header("authorization", authorization.as_str()))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", "/repository/npm-allowed/audit-final"),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("POST"))
            .and(path("/repository/npm-allowed/audit-final"))
            .and(header("authorization", authorization.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&upstream)
            .await;

        let context = |base_path: &'static str| {
            let configured_url = format!("{}{base_path}", upstream.uri());
            crate::test_helpers::create_test_context_with_config(move |config| {
                named_config(config);
                if let NpmRepository::Proxy { url, auth, .. } = &mut config.npm.repositories[1] {
                    *url = configured_url;
                    *auth = Some(crate::secrets::ProtectedString::new(
                        credentials.to_string(),
                    ));
                }
            })
        };

        let cross = context("/repository/npm-cross");
        let cross_target = named_target(&cross.state, "npm-group").unwrap();
        let response = handle_post(
            cross.state,
            cross_target,
            audit_path.to_string(),
            HeaderMap::new(),
            Body::from(request_body.as_slice()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(
            attacker.received_requests().await.unwrap().is_empty(),
            "rejected audit redirect must receive neither request, auth nor body"
        );

        let allowed = context("/repository/npm-allowed");
        let allowed_target = named_target(&allowed.state, "npm-group").unwrap();
        let response = handle_post(
            allowed.state,
            allowed_target,
            audit_path.to_string(),
            HeaderMap::new(),
            Body::from(request_body.as_slice()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let requests = upstream.received_requests().await.unwrap();
        let final_request = requests
            .iter()
            .find(|request| request.url.path() == "/repository/npm-allowed/audit-final")
            .expect("allowed redirect target request");
        assert_eq!(final_request.method.as_str(), "POST");
        assert_eq!(final_request.body.as_slice(), request_body);
        upstream.verify().await;
    }
}
