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
use crate::npm_layout::{
    HostedImportSession, HostedMaintenanceAction, HostedMaintenanceMarker,
    HostedMaintenanceOperation, HostedMaintenanceTarget, HostedPackumentPointer,
    HostedPublishPending, HostedPublishPendingTarget,
};
use crate::registry::{
    circuit_open_response, method_not_allowed, proxy_fetch_conditional_with_validated_redirects,
    proxy_fetch_with_validated_redirects, proxy_fetch_with_validated_redirects_bounded,
    proxy_forward_post, read_validators, write_validators, ProxyError, Revalidation, Validators,
};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::storage::{Storage, StorageError};
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
use std::collections::{BTreeMap, HashMap, HashSet};
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
const NPM_IMPORT_MUTATION_CONCURRENCY: usize = 32;
const NPM_IMPORT_PACKUMENT_HEADER: &str = "x-nora-import-packument-sha256";
const LEGACY_HOSTED: &str = "npm-private";
const LEGACY_PROXY: &str = "npm-registry";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/repository/{repository}/-/nora/import/{package}",
            axum::routing::put(named_import_finalize)
                .fallback(|| async { method_not_allowed("PUT") }),
        )
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
    MaterializationUnavailable,
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

async fn optional_hosted_materialization_get(
    state: &AppState,
    key: &str,
) -> Result<Option<Bytes>, ReadError> {
    match state.storage.get(key).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(StorageError::NotFound) => Ok(None),
        Err(_) => Err(ReadError::MaterializationUnavailable),
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

fn hosted_publish_pending_index_key(repository: &str, package: &str) -> String {
    crate::npm_layout::hosted_publish_pending_index_key(repository, package)
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
    crate::npm_layout::hosted_package_key(repository, package)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostedActiveTransactions {
    pub(crate) import: Option<HostedImportSession>,
    pub(crate) publish: Option<HostedPublishPending>,
}

fn parse_hosted_import_session(
    bytes: &[u8],
    repository: &str,
    package: &str,
) -> Result<HostedImportSession, StorageError> {
    let session: HostedImportSession =
        serde_json::from_slice(bytes).map_err(|_| StorageError::IntegrityViolation)?;
    if session.schema != crate::npm_layout::HOSTED_IMPORT_SESSION_SCHEMA_V1
        || session.repository != repository
        || session.package != package
        || !valid_sha256(&session.packument_sha256)
        || session
            .base
            .as_ref()
            .is_some_and(|base| !valid_hosted_packument_pointer(base))
        || session.versions.is_empty()
        || !session
            .versions
            .iter()
            .all(|(version, digest)| is_valid_npm_version(version) && valid_sha256(digest))
    {
        return Err(StorageError::IntegrityViolation);
    }
    Ok(session)
}

fn valid_sha512_hex(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn parse_hosted_publish_pending(
    bytes: &[u8],
    repository: &str,
    package: &str,
) -> Result<HostedPublishPending, StorageError> {
    let pending: HostedPublishPending =
        serde_json::from_slice(bytes).map_err(|_| StorageError::IntegrityViolation)?;
    let valid_target = match &pending.target {
        HostedPublishPendingTarget::Publish { base, target } => {
            base.as_ref().is_none_or(valid_hosted_packument_pointer)
                && valid_hosted_packument_pointer(target)
        }
        HostedPublishPendingTarget::Import { packument_sha256 } => valid_sha256(packument_sha256),
    };
    if pending.schema != crate::npm_layout::HOSTED_PUBLISH_PENDING_SCHEMA_V1
        || pending.repository != repository
        || pending.package != package
        || !is_valid_npm_version(&pending.version)
        || !valid_sha256(&pending.manifest_sha256)
        || !valid_sha512_hex(&pending.blob_sha512)
        || !valid_target
    {
        return Err(StorageError::IntegrityViolation);
    }
    Ok(pending)
}

async fn read_optional_import_session(
    storage: &Storage,
    repository: &str,
    package: &str,
) -> Result<Option<HostedImportSession>, StorageError> {
    match storage
        .get(&crate::npm_layout::hosted_import_pending_key(
            repository, package,
        ))
        .await
    {
        Ok(bytes) => parse_hosted_import_session(&bytes, repository, package).map(Some),
        Err(StorageError::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

async fn read_optional_publish_pending(
    storage: &Storage,
    repository: &str,
    package: &str,
) -> Result<Option<HostedPublishPending>, StorageError> {
    match storage
        .get(&hosted_publish_pending_index_key(repository, package))
        .await
    {
        Ok(bytes) => parse_hosted_publish_pending(&bytes, repository, package).map(Some),
        Err(StorageError::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Exact package transaction probe shared by mutation, retention and GC.
/// Malformed records are integrity errors rather than apparent quiescence.
pub(crate) async fn read_hosted_active_transactions(
    storage: &Storage,
    repository: &str,
    package: &str,
) -> Result<HostedActiveTransactions, StorageError> {
    let (import, publish) = tokio::join!(
        read_optional_import_session(storage, repository, package),
        read_optional_publish_pending(storage, repository, package),
    );
    Ok(HostedActiveTransactions {
        import: import?,
        publish: publish?,
    })
}

async fn incomplete_publish_versions(
    state: &AppState,
    repository: &str,
    package: &str,
) -> Result<HashSet<String>, StorageError> {
    Ok(
        read_optional_publish_pending(&state.storage, repository, package)
            .await?
            .into_iter()
            .map(|pending| pending.version)
            .collect(),
    )
}

async fn create_hosted_publish_pending(
    storage: &Storage,
    pending: &HostedPublishPending,
) -> Result<(), StorageError> {
    let bytes = serde_json::to_vec(pending).map_err(|_| StorageError::IntegrityViolation)?;
    put_immutable_storage(
        storage,
        &hosted_publish_pending_index_key(&pending.repository, &pending.package),
        &bytes,
    )
    .await
}

async fn clear_hosted_publish_pending(
    storage: &Storage,
    pending: &HostedPublishPending,
) -> Result<(), StorageError> {
    let bytes = serde_json::to_vec(pending).map_err(|_| StorageError::IntegrityViolation)?;
    delete_exact_with_readback(
        storage,
        &hosted_publish_pending_index_key(&pending.repository, &pending.package),
        &bytes,
    )
    .await
}

fn incomplete_publish_response() -> Response {
    (
        StatusCode::CONFLICT,
        "Package has an incomplete publish; retry that exact publish before mutating package metadata",
    )
        .into_response()
}

async fn current_full_for_mutation(
    state: &AppState,
    repository: &str,
    package: &str,
) -> Result<Option<serde_json::Value>, StorageError> {
    let pointer_key = crate::npm_layout::hosted_packument_current_key(repository, package);
    let pointer = match state.storage.get(&pointer_key).await {
        Ok(pointer) => pointer,
        Err(StorageError::NotFound) => {
            let package_exists = match state
                .storage
                .get(&hosted_package_key(repository, package))
                .await
            {
                Ok(_) => true,
                Err(StorageError::NotFound) => false,
                Err(error) => return Err(error),
            };
            if package_exists {
                return Err(StorageError::IntegrityViolation);
            }
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let pointer: HostedPackumentPointer =
        serde_json::from_slice(&pointer).map_err(|_| StorageError::IntegrityViolation)?;
    if !valid_sha256(&pointer.generation)
        || pointer.generation != pointer.full_sha256
        || !valid_sha256(&pointer.install_v1_sha256)
    {
        return Err(StorageError::IntegrityViolation);
    }
    let full = state
        .storage
        .get(&crate::npm_layout::hosted_packument_full_key(
            repository,
            package,
            &pointer.generation,
        ))
        .await?;
    if hex::encode(sha2::Sha256::digest(&full)) != pointer.full_sha256 {
        return Err(StorageError::IntegrityViolation);
    }
    valid_hosted_packument(&full, package)
        .map(Some)
        .ok_or(StorageError::IntegrityViolation)
}

async fn hosted_import_active(
    storage: &Storage,
    repository: &str,
    package: &str,
) -> Result<bool, StorageError> {
    read_optional_import_session(storage, repository, package)
        .await
        .map(|session| session.is_some())
}

fn packument_after_publish(
    package: &str,
    previous: Option<serde_json::Value>,
    validated: &ValidatedPublish,
) -> Result<serde_json::Value, StorageError> {
    let mut packument = previous
        .unwrap_or_else(|| serde_json::json!({"name": package, "versions": {}, "dist-tags": {}}));
    let object = packument
        .as_object_mut()
        .ok_or(StorageError::IntegrityViolation)?;
    for field in ["name", "_id", "description", "readme", "license"] {
        object.remove(field);
    }
    let package_fields: serde_json::Value = serde_json::from_slice(&validated.package_fields)
        .map_err(|_| StorageError::IntegrityViolation)?;
    for (field, value) in package_fields
        .as_object()
        .ok_or(StorageError::IntegrityViolation)?
    {
        object.insert(field.clone(), value.clone());
    }
    object.insert(
        "name".to_string(),
        serde_json::Value::String(package.to_string()),
    );

    let mut manifest: serde_json::Value = serde_json::from_slice(&validated.manifest)
        .map_err(|_| StorageError::IntegrityViolation)?;
    let previous_deprecation = object
        .get("versions")
        .and_then(serde_json::Value::as_object)
        .and_then(|versions| versions.get(&validated.version))
        .and_then(|manifest| manifest.get("deprecated"))
        .cloned();
    let manifest_object = manifest
        .as_object_mut()
        .ok_or(StorageError::IntegrityViolation)?;
    match validated.deprecation.as_deref() {
        Some("") => {
            manifest_object.remove("deprecated");
        }
        Some(message) => {
            manifest_object.insert(
                "deprecated".to_string(),
                serde_json::Value::String(message.to_string()),
            );
        }
        None => {
            if let Some(message) = previous_deprecation {
                manifest_object.insert("deprecated".to_string(), message);
            }
        }
    }
    object
        .entry("versions")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or(StorageError::IntegrityViolation)?
        .insert(validated.version.clone(), manifest);
    let tags = object
        .entry("dist-tags")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or(StorageError::IntegrityViolation)?;
    for (tag, target) in &validated.tags {
        tags.insert(tag.clone(), serde_json::Value::String(target.clone()));
    }
    Ok(packument)
}

fn hosted_packument_pointer_for_value(
    packument: &serde_json::Value,
) -> Result<(Vec<u8>, HostedPackumentPointer), StorageError> {
    let full = serde_json::to_vec(packument).map_err(|_| StorageError::IntegrityViolation)?;
    let install_v1 = install_v1_packument(packument)
        .map_err(|_| StorageError::IntegrityViolation)
        .and_then(|value| {
            serde_json::to_vec(&value).map_err(|_| StorageError::IntegrityViolation)
        })?;
    let full_sha256 = hex::encode(sha2::Sha256::digest(&full));
    Ok((
        full,
        HostedPackumentPointer {
            generation: full_sha256.clone(),
            full_sha256,
            install_v1_sha256: hex::encode(sha2::Sha256::digest(&install_v1)),
        },
    ))
}

async fn ensure_completed_publish_materialized(
    state: &AppState,
    repository: &str,
    package: &str,
    version: &str,
) -> Result<(), StorageError> {
    if current_full_for_mutation(state, repository, package)
        .await
        .ok()
        .flatten()
        .and_then(|packument| {
            packument
                .get("versions")
                .and_then(serde_json::Value::as_object)
                .map(|versions| versions.contains_key(version))
        })
        == Some(true)
    {
        return Ok(());
    }
    Err(StorageError::IntegrityViolation)
}

pub(crate) async fn read_hosted_packument_pointer(
    storage: &Storage,
    repository: &str,
    package: &str,
) -> Result<Option<HostedPackumentPointer>, StorageError> {
    let bytes = match storage
        .get(&crate::npm_layout::hosted_packument_current_key(
            repository, package,
        ))
        .await
    {
        Ok(bytes) => bytes,
        Err(StorageError::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    let pointer: HostedPackumentPointer =
        serde_json::from_slice(&bytes).map_err(|_| StorageError::IntegrityViolation)?;
    if !valid_hosted_packument_pointer(&pointer) {
        return Err(StorageError::IntegrityViolation);
    }
    Ok(Some(pointer))
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
    json_response_with_content_type(headers, value, "application/json")
}

fn json_response_with_content_type(
    headers: &HeaderMap,
    value: &serde_json::Value,
    content_type: &'static str,
) -> Response {
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
            (header::CONTENT_TYPE, content_type.to_string()),
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

fn packument_response(
    headers: &HeaderMap,
    value: &serde_json::Value,
    stale: bool,
    flavor: PackumentFlavor,
) -> Response {
    let mut response = json_response_with_content_type(headers, value, flavor.content_type());
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept"));
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
    let manifest = match hosted_version_from_current(state, repository, package, version).await? {
        HostedVersionResolution::Visible(manifest) => manifest,
        HostedVersionResolution::Absent | HostedVersionResolution::AuthoritativelyAbsent => {
            return Err(ReadError::NotFound)
        }
    };
    let manifest = serde_json::to_vec(&manifest).map_err(|_| ReadError::Corrupt)?;
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
                        match hosted_version_from_current(state, name, package, version).await? {
                            HostedVersionResolution::Visible(_) => {
                                let blob_key =
                                    hosted_blob_key_for_version(state, name, package, version)
                                        .await?;
                                return Ok(crate::curation::extract_mtime_as_publish_date(
                                    &state.storage,
                                    &blob_key,
                                )
                                .await);
                            }
                            HostedVersionResolution::AuthoritativelyAbsent => {
                                return Err(ReadError::NotFound)
                            }
                            HostedVersionResolution::Absent => {}
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
            match hosted_version_from_current(state, LEGACY_HOSTED, package, version).await? {
                HostedVersionResolution::Visible(_) => {
                    let blob_key =
                        hosted_blob_key_for_version(state, LEGACY_HOSTED, package, version).await?;
                    Ok(
                        crate::curation::extract_mtime_as_publish_date(&state.storage, &blob_key)
                            .await,
                    )
                }
                HostedVersionResolution::AuthoritativelyAbsent => Err(ReadError::NotFound),
                HostedVersionResolution::Absent => {
                    Ok(
                        cached_proxy_publish_date(state, LEGACY_PROXY, package, version, filename)
                            .await,
                    )
                }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PackumentFlavor {
    Full,
    InstallV1,
}

impl PackumentFlavor {
    fn from_headers(headers: &HeaderMap) -> Self {
        // Store the quality selected by the most-specific media range for
        // each representation. An exact q=0 must therefore override a more
        // permissive wildcard instead of being resurrected by it.
        let mut install_match = None::<(u8, f32)>;
        let mut full_match = None::<(u8, f32)>;
        let update_match = |current: &mut Option<(u8, f32)>, specificity, quality| match current {
            Some((current_specificity, current_quality)) if *current_specificity > specificity => {}
            Some((current_specificity, current_quality)) if *current_specificity == specificity => {
                *current_quality = current_quality.max(quality);
            }
            _ => *current = Some((specificity, quality)),
        };
        for range in headers
            .get_all(header::ACCEPT)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
        {
            let mut parts = range.split(';');
            let media_type = parts.next().unwrap_or_default().trim();
            let mut quality = 1.0f32;
            for parameter in parts {
                let Some((name, value)) = parameter.trim().split_once('=') else {
                    continue;
                };
                if name.trim().eq_ignore_ascii_case("q") {
                    quality = value
                        .trim()
                        .parse::<f32>()
                        .ok()
                        .filter(|quality| (0.0..=1.0).contains(quality))
                        .unwrap_or(0.0);
                }
            }
            if media_type.eq_ignore_ascii_case("application/vnd.npm.install-v1+json") {
                update_match(&mut install_match, 2, quality);
            } else if media_type.eq_ignore_ascii_case("application/json") {
                update_match(&mut full_match, 2, quality);
            } else if media_type.eq_ignore_ascii_case("application/*") {
                update_match(&mut install_match, 1, quality);
                update_match(&mut full_match, 1, quality);
            } else if media_type == "*/*" {
                update_match(&mut install_match, 0, quality);
                update_match(&mut full_match, 0, quality);
            }
        }
        let full_quality = full_match.map(|(_, quality)| quality).unwrap_or(0.0);
        if install_match.is_some_and(|(specificity, quality)| {
            quality > 0.0
                && (quality > full_quality || (quality == full_quality && specificity == 2))
        }) {
            Self::InstallV1
        } else {
            Self::Full
        }
    }

    const fn content_type(self) -> &'static str {
        match self {
            Self::Full => "application/json",
            Self::InstallV1 => "application/vnd.npm.install-v1+json",
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HostedImportReceipt {
    package: String,
    version_count: usize,
    full_sha256: String,
    install_v1_sha256: String,
    generation: String,
}

type WrittenPackumentGeneration = HostedPackumentPointer;

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_hosted_packument_pointer(pointer: &HostedPackumentPointer) -> bool {
    valid_sha256(&pointer.generation)
        && pointer.generation == pointer.full_sha256
        && valid_sha256(&pointer.install_v1_sha256)
}

fn valid_hosted_maintenance_operation(operation: &HostedMaintenanceOperation) -> bool {
    if operation.schema != crate::npm_layout::HOSTED_MAINTENANCE_SCHEMA_V1
        || operation.repository.is_empty()
        || operation.package.is_empty()
        || !valid_hosted_packument_pointer(&operation.base)
    {
        return false;
    }
    if let HostedMaintenanceTarget::Live { pointer } = &operation.target {
        if !valid_hosted_packument_pointer(pointer) {
            return false;
        }
    }
    match &operation.action {
        HostedMaintenanceAction::DistTag { tag, value } => {
            matches!(operation.target, HostedMaintenanceTarget::Live { .. })
                && is_valid_dist_tag(tag)
                && value.as_deref().is_none_or(is_valid_npm_version)
        }
        HostedMaintenanceAction::Deprecations { values } => {
            matches!(operation.target, HostedMaintenanceTarget::Live { .. })
                && !values.is_empty()
                && values.iter().all(|(version, message)| {
                    is_valid_npm_version(version)
                        && message.as_deref().is_none_or(|message| !message.is_empty())
                })
        }
        HostedMaintenanceAction::Retention {
            snapshot_guard,
            removed_versions,
            expected_authority,
        } => {
            if !valid_sha256(snapshot_guard)
                || removed_versions.is_empty()
                || !removed_versions
                    .iter()
                    .all(|(version, digest)| is_valid_npm_version(version) && valid_sha256(digest))
                || expected_authority.is_empty()
            {
                return false;
            }
            expected_authority.iter().all(|(key, digest)| {
                if !valid_sha256(digest) {
                    return false;
                }
                let Some(parsed) = crate::npm_layout::parse_npm_object_key(key) else {
                    return false;
                };
                parsed.repository == operation.repository
                    && parsed.package == operation.package
                    && matches!(
                        parsed.kind,
                        crate::npm_layout::NpmObjectKind::HostedPackage
                            | crate::npm_layout::NpmObjectKind::HostedVersion(_)
                            | crate::npm_layout::NpmObjectKind::HostedPublishComplete(_)
                            | crate::npm_layout::NpmObjectKind::HostedPublishPendingIndex
                            | crate::npm_layout::NpmObjectKind::HostedDistTag(_)
                            | crate::npm_layout::NpmObjectKind::HostedDeprecation(_)
                    )
            })
        }
    }
}

fn hosted_maintenance_marker_for_operation(
    operation: &HostedMaintenanceOperation,
) -> Result<HostedMaintenanceMarker, StorageError> {
    if !valid_hosted_maintenance_operation(operation) {
        return Err(StorageError::IntegrityViolation);
    }
    let operation_id = crate::npm_layout::hosted_maintenance_operation_id(operation)
        .map_err(|_| StorageError::IntegrityViolation)?;
    Ok(HostedMaintenanceMarker {
        schema: operation.schema,
        repository: operation.repository.clone(),
        package: operation.package.clone(),
        operation_id,
        base: operation.base.clone(),
        target: operation.target.clone(),
        action: operation.action.clone(),
    })
}

fn valid_hosted_maintenance_marker(
    marker: &HostedMaintenanceMarker,
    repository: &str,
    package: &str,
) -> bool {
    marker.repository == repository
        && marker.package == package
        && valid_sha256(&marker.operation_id)
        && valid_hosted_maintenance_operation(&marker.operation())
        && crate::npm_layout::hosted_maintenance_operation_id(&marker.operation())
            .is_ok_and(|operation_id| operation_id == marker.operation_id)
}

pub(crate) async fn read_hosted_maintenance_marker(
    storage: &Storage,
    repository: &str,
    package: &str,
) -> Result<Option<HostedMaintenanceMarker>, StorageError> {
    let key = crate::npm_layout::hosted_maintenance_active_key(repository, package);
    let bytes = match storage.get(&key).await {
        Ok(bytes) => bytes,
        Err(StorageError::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    let marker: HostedMaintenanceMarker =
        serde_json::from_slice(&bytes).map_err(|_| StorageError::IntegrityViolation)?;
    if !valid_hosted_maintenance_marker(&marker, repository, package) {
        return Err(StorageError::IntegrityViolation);
    }
    Ok(Some(marker))
}

pub(crate) async fn create_hosted_maintenance_marker(
    storage: &Storage,
    operation: &HostedMaintenanceOperation,
) -> Result<HostedMaintenanceMarker, StorageError> {
    let marker = hosted_maintenance_marker_for_operation(operation)?;
    let bytes = serde_json::to_vec(&marker).map_err(|_| StorageError::IntegrityViolation)?;
    let key =
        crate::npm_layout::hosted_maintenance_active_key(&operation.repository, &operation.package);
    let create = storage.put_if_absent(&key, &bytes).await;
    match storage.get(&key).await {
        Ok(stored) if stored.as_ref() == bytes.as_slice() => Ok(marker),
        Ok(_) => match create {
            Err(StorageError::AlreadyExists) => Err(StorageError::AlreadyExists),
            _ => Err(StorageError::IntegrityViolation),
        },
        Err(StorageError::NotFound) => match create {
            Ok(()) => Err(StorageError::IntegrityViolation),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

pub(crate) async fn clear_hosted_maintenance_marker(
    storage: &Storage,
    marker: &HostedMaintenanceMarker,
) -> Result<(), StorageError> {
    if !valid_hosted_maintenance_marker(marker, &marker.repository, &marker.package) {
        return Err(StorageError::IntegrityViolation);
    }
    let expected = serde_json::to_vec(marker).map_err(|_| StorageError::IntegrityViolation)?;
    let key = crate::npm_layout::hosted_maintenance_active_key(&marker.repository, &marker.package);
    match storage.get(&key).await {
        Ok(current) if current.as_ref() == expected.as_slice() => {}
        Ok(_) => return Err(StorageError::AlreadyExists),
        Err(StorageError::NotFound) => return Ok(()),
        Err(error) => return Err(error),
    }
    let deleted = storage.delete(&key).await;
    match storage.get(&key).await {
        Err(StorageError::NotFound) => Ok(()),
        Ok(current) if current.as_ref() == expected.as_slice() => match deleted {
            Ok(()) => Err(StorageError::IntegrityViolation),
            Err(error) => Err(error),
        },
        Ok(_) => Err(StorageError::AlreadyExists),
        Err(error) => Err(error),
    }
}

async fn hosted_packument_for_pointer(
    storage: &Storage,
    repository: &str,
    package: &str,
    pointer: &HostedPackumentPointer,
) -> Result<serde_json::Value, StorageError> {
    validate_hosted_packument_pointer(storage, repository, package, pointer).await?;
    let full = storage
        .get(&crate::npm_layout::hosted_packument_full_key(
            repository,
            package,
            &pointer.generation,
        ))
        .await?;
    valid_hosted_packument(&full, package).ok_or(StorageError::IntegrityViolation)
}

fn apply_hosted_maintenance_action(
    mut packument: serde_json::Value,
    action: &HostedMaintenanceAction,
) -> Result<serde_json::Value, StorageError> {
    match action {
        HostedMaintenanceAction::DistTag { tag, value } => {
            let tags = packument
                .get_mut("dist-tags")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or(StorageError::IntegrityViolation)?;
            match value {
                Some(version) => {
                    tags.insert(tag.clone(), serde_json::Value::String(version.clone()));
                }
                None => {
                    tags.remove(tag);
                }
            }
        }
        HostedMaintenanceAction::Deprecations { values } => {
            let versions = packument
                .get_mut("versions")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or(StorageError::IntegrityViolation)?;
            for (version, message) in values {
                let manifest = versions
                    .get_mut(version)
                    .and_then(serde_json::Value::as_object_mut)
                    .ok_or(StorageError::IntegrityViolation)?;
                match message {
                    Some(message) => {
                        manifest.insert(
                            "deprecated".to_string(),
                            serde_json::Value::String(message.clone()),
                        );
                    }
                    None => {
                        manifest.remove("deprecated");
                    }
                }
            }
        }
        HostedMaintenanceAction::Retention { .. } => return Err(StorageError::IntegrityViolation),
    }
    Ok(packument)
}

fn optional_packument_string(
    packument: &serde_json::Value,
    action: &HostedMaintenanceAction,
) -> Result<Vec<(String, Option<String>)>, StorageError> {
    match action {
        HostedMaintenanceAction::DistTag { tag, .. } => {
            let value = packument
                .get("dist-tags")
                .and_then(serde_json::Value::as_object)
                .ok_or(StorageError::IntegrityViolation)?
                .get(tag)
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .ok_or(StorageError::IntegrityViolation)
                })
                .transpose()?;
            Ok(vec![(tag.clone(), value)])
        }
        HostedMaintenanceAction::Deprecations { values } => {
            let versions = packument
                .get("versions")
                .and_then(serde_json::Value::as_object)
                .ok_or(StorageError::IntegrityViolation)?;
            values
                .keys()
                .map(|version| {
                    let manifest = versions
                        .get(version)
                        .and_then(serde_json::Value::as_object)
                        .ok_or(StorageError::IntegrityViolation)?;
                    let message = manifest
                        .get("deprecated")
                        .map(|value| {
                            value
                                .as_str()
                                .map(str::to_string)
                                .ok_or(StorageError::IntegrityViolation)
                        })
                        .transpose()?;
                    Ok((version.clone(), message))
                })
                .collect()
        }
        HostedMaintenanceAction::Retention { .. } => Err(StorageError::IntegrityViolation),
    }
}

async fn read_optional_string(
    storage: &Storage,
    key: &str,
) -> Result<Option<String>, StorageError> {
    match storage.get(key).await {
        Ok(bytes) => read_string(bytes)
            .map(Some)
            .ok_or(StorageError::IntegrityViolation),
        Err(StorageError::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

async fn commit_authority_value(
    storage: &Storage,
    key: &str,
    base: Option<&str>,
    target: Option<&str>,
) -> Result<(), StorageError> {
    let current = read_optional_string(storage, key).await?;
    if current.as_deref() == target {
        return Ok(());
    }
    if current.as_deref() != base {
        return Err(StorageError::AlreadyExists);
    }
    let mutation = match target {
        Some(value) => storage.put(key, value.as_bytes()).await,
        None => storage.delete(key).await,
    };
    let readback = read_optional_string(storage, key).await;
    match readback {
        Ok(value) if value.as_deref() == target => Ok(()),
        Ok(value) if value.as_deref() != base => Err(StorageError::AlreadyExists),
        Ok(_) => match mutation {
            Ok(()) => Err(StorageError::IntegrityViolation),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

async fn resume_hosted_metadata_maintenance(
    storage: &Storage,
    marker: &HostedMaintenanceMarker,
) -> Result<(), StorageError> {
    let HostedMaintenanceTarget::Live { pointer: target } = &marker.target else {
        return Err(StorageError::IntegrityViolation);
    };
    let base_packument =
        hosted_packument_for_pointer(storage, &marker.repository, &marker.package, &marker.base)
            .await?;
    let expected_packument =
        apply_hosted_maintenance_action(base_packument.clone(), &marker.action)?;
    let expected_full =
        serde_json::to_vec(&expected_packument).map_err(|_| StorageError::IntegrityViolation)?;
    if hex::encode(sha2::Sha256::digest(&expected_full)) != target.full_sha256 {
        return Err(StorageError::IntegrityViolation);
    }
    let expected_install = install_v1_packument(&expected_packument)
        .map_err(|_| StorageError::IntegrityViolation)
        .and_then(|value| {
            serde_json::to_vec(&value).map_err(|_| StorageError::IntegrityViolation)
        })?;
    if hex::encode(sha2::Sha256::digest(&expected_install)) != target.install_v1_sha256 {
        return Err(StorageError::IntegrityViolation);
    }
    validate_hosted_packument_pointer(storage, &marker.repository, &marker.package, target).await?;
    match read_hosted_packument_pointer(storage, &marker.repository, &marker.package).await? {
        Some(current) if current == marker.base || current == *target => {}
        _ => return Err(StorageError::AlreadyExists),
    }

    let base_values = optional_packument_string(&base_packument, &marker.action)?;
    match &marker.action {
        HostedMaintenanceAction::DistTag { tag, value } => {
            let (_, base) = base_values
                .first()
                .ok_or(StorageError::IntegrityViolation)?;
            commit_authority_value(
                storage,
                &hosted_tag_key(&marker.repository, &marker.package, tag),
                base.as_deref(),
                value.as_deref(),
            )
            .await?;
        }
        HostedMaintenanceAction::Deprecations { values } => {
            let base_values = base_values.into_iter().collect::<HashMap<_, _>>();
            for (version, target) in values {
                let base = base_values
                    .get(version)
                    .ok_or(StorageError::IntegrityViolation)?;
                commit_authority_value(
                    storage,
                    &hosted_deprecation_key(&marker.repository, &marker.package, version),
                    base.as_deref(),
                    target.as_deref(),
                )
                .await?;
            }
        }
        HostedMaintenanceAction::Retention { .. } => return Err(StorageError::IntegrityViolation),
    }
    commit_hosted_packument_pointer(storage, &marker.repository, &marker.package, target).await
}

pub(crate) async fn resume_hosted_maintenance_operation(
    storage: &Storage,
    repository: &str,
    package: &str,
) -> Result<bool, StorageError> {
    let Some(marker) = read_hosted_maintenance_marker(storage, repository, package).await? else {
        return Ok(false);
    };
    match &marker.action {
        HostedMaintenanceAction::DistTag { .. } | HostedMaintenanceAction::Deprecations { .. } => {
            resume_hosted_metadata_maintenance(storage, &marker).await?
        }
        HostedMaintenanceAction::Retention { .. } => {
            crate::retention::resume_npm_retention_operation(storage, &marker).await?
        }
    }
    clear_hosted_maintenance_marker(storage, &marker).await?;
    Ok(true)
}

async fn execute_hosted_metadata_maintenance(
    storage: &Storage,
    repository: &str,
    package: &str,
    base: HostedPackumentPointer,
    target_packument: &serde_json::Value,
    action: HostedMaintenanceAction,
) -> Result<(), StorageError> {
    let full =
        serde_json::to_vec(target_packument).map_err(|_| StorageError::IntegrityViolation)?;
    let target = write_hosted_packument_generation_documents(
        storage,
        repository,
        package,
        target_packument,
        &full,
    )
    .await?;
    let operation = HostedMaintenanceOperation {
        schema: crate::npm_layout::HOSTED_MAINTENANCE_SCHEMA_V1,
        repository: repository.to_string(),
        package: package.to_string(),
        base: base.clone(),
        target: HostedMaintenanceTarget::Live { pointer: target },
        action,
    };
    let marker = match create_hosted_maintenance_marker(storage, &operation).await {
        Ok(marker) => marker,
        Err(StorageError::AlreadyExists) => {
            resume_hosted_maintenance_operation(storage, repository, package).await?;
            return Err(StorageError::AlreadyExists);
        }
        Err(error) => return Err(error),
    };
    match read_hosted_packument_pointer(storage, repository, package).await? {
        Some(current) if current == base => {}
        Some(current)
            if matches!(
                &marker.target,
                HostedMaintenanceTarget::Live { pointer } if *pointer == current
            ) => {}
        _ => {
            clear_hosted_maintenance_marker(storage, &marker).await?;
            return Err(StorageError::AlreadyExists);
        }
    }
    if !resume_hosted_maintenance_operation(storage, repository, package).await? {
        return Err(StorageError::IntegrityViolation);
    }
    Ok(())
}

fn import_packument_sha256(headers: &HeaderMap) -> Result<Option<String>, NpmHttpError> {
    let values = headers
        .get_all(NPM_IMPORT_PACKUMENT_HEADER)
        .iter()
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(None);
    }
    if values.len() != 1 {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Exactly one npm import packument hash is required",
        ));
    }
    let value = values[0].to_str().ok().filter(|value| valid_sha256(value));
    value.map(|value| Some(value.to_string())).ok_or_else(|| {
        NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Invalid npm import packument SHA-256",
        )
    })
}

fn valid_hosted_packument(bytes: &[u8], package: &str) -> Option<serde_json::Value> {
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

fn install_v1_packument(packument: &serde_json::Value) -> Result<serde_json::Value, ReadError> {
    let object = packument.as_object().ok_or(ReadError::Corrupt)?;
    let mut abbreviated = serde_json::Map::new();
    for field in ["name", "modified", "dist-tags"] {
        if let Some(value) = object.get(field) {
            abbreviated.insert(field.to_string(), value.clone());
        }
    }
    let versions = object
        .get("versions")
        .and_then(serde_json::Value::as_object)
        .ok_or(ReadError::Corrupt)?;
    let allowed = [
        "name",
        "version",
        "dist",
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "peerDependenciesMeta",
        "devDependencies",
        "bundleDependencies",
        "engines",
        "funding",
        "os",
        "cpu",
        "deprecated",
        "bin",
        "directories",
        "acceptDependencies",
        "_hasShrinkwrap",
        "hasInstallScript",
    ];
    let mut abbreviated_versions = serde_json::Map::new();
    for (version, manifest) in versions {
        let manifest = manifest.as_object().ok_or(ReadError::Corrupt)?;
        let mut projected = serde_json::Map::new();
        for field in allowed {
            if let Some(value) = manifest.get(field) {
                projected.insert(field.to_string(), value.clone());
            }
        }
        abbreviated_versions.insert(version.clone(), serde_json::Value::Object(projected));
    }
    abbreviated.insert(
        "versions".to_string(),
        serde_json::Value::Object(abbreviated_versions),
    );
    Ok(serde_json::Value::Object(abbreviated))
}

fn project_packument(
    packument: serde_json::Value,
    flavor: PackumentFlavor,
) -> Result<serde_json::Value, ReadError> {
    match flavor {
        PackumentFlavor::Full => Ok(packument),
        PackumentFlavor::InstallV1 => install_v1_packument(&packument),
    }
}

async fn put_immutable_storage(
    storage: &Storage,
    key: &str,
    data: &[u8],
) -> Result<(), StorageError> {
    let created = storage.put_if_absent(key, data).await;
    match storage.get(key).await {
        Ok(existing) if existing.as_ref() == data => Ok(()),
        Ok(_) => Err(StorageError::IntegrityViolation),
        Err(StorageError::NotFound) => match created {
            Ok(()) => Err(StorageError::IntegrityViolation),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

async fn write_hosted_packument_generation_documents(
    storage: &Storage,
    repository: &str,
    package: &str,
    packument: &serde_json::Value,
    full: &[u8],
) -> Result<WrittenPackumentGeneration, StorageError> {
    let parsed = valid_hosted_packument(full, package).ok_or(StorageError::IntegrityViolation)?;
    if &parsed != packument {
        return Err(StorageError::IntegrityViolation);
    }
    let full_sha256 = hex::encode(sha2::Sha256::digest(full));
    let install_v1 = install_v1_packument(packument)
        .map_err(|_| StorageError::IntegrityViolation)
        .and_then(|value| {
            serde_json::to_vec(&value).map_err(|_| StorageError::IntegrityViolation)
        })?;
    let install_v1_sha256 = hex::encode(sha2::Sha256::digest(&install_v1));
    let generation = full_sha256.clone();
    let full_key = crate::npm_layout::hosted_packument_full_key(repository, package, &generation);
    let install_key =
        crate::npm_layout::hosted_packument_install_v1_key(repository, package, &generation);
    put_immutable_storage(storage, &full_key, full).await?;
    put_immutable_storage(storage, &install_key, &install_v1).await?;

    Ok(WrittenPackumentGeneration {
        generation,
        full_sha256,
        install_v1_sha256,
    })
}

pub(crate) async fn commit_hosted_packument_pointer(
    storage: &Storage,
    repository: &str,
    package: &str,
    generation: &HostedPackumentPointer,
) -> Result<(), StorageError> {
    // The mutable pointer is the sole read-model commit point and is written
    // only after both immutable documents (and, for imports, the receipt) are
    // durable.
    if !valid_hosted_packument_pointer(generation) {
        return Err(StorageError::IntegrityViolation);
    }
    validate_hosted_packument_pointer(storage, repository, package, generation).await?;
    let retired_key = crate::npm_layout::hosted_packument_retired_key(repository, package);
    match storage.get(&retired_key).await {
        Ok(marker) if marker.as_ref() == crate::npm_layout::HOSTED_PACKUMENT_RETIRED_V1 => {
            let deleted = storage.delete(&retired_key).await;
            match storage.get(&retired_key).await {
                Err(StorageError::NotFound) => {}
                Ok(current)
                    if current.as_ref() == crate::npm_layout::HOSTED_PACKUMENT_RETIRED_V1 =>
                {
                    return match deleted {
                        Ok(()) => Err(StorageError::IntegrityViolation),
                        Err(error) => Err(error),
                    }
                }
                Ok(_) => return Err(StorageError::IntegrityViolation),
                Err(error) => return Err(error),
            }
        }
        Ok(_) => return Err(StorageError::IntegrityViolation),
        Err(StorageError::NotFound) => {}
        Err(error) => return Err(error),
    }
    let pointer = serde_json::to_vec(generation).map_err(|_| StorageError::IntegrityViolation)?;
    let key = crate::npm_layout::hosted_packument_current_key(repository, package);
    let committed = storage.put(&key, &pointer).await;
    match storage.get(&key).await {
        Ok(stored) if stored.as_ref() == pointer.as_slice() => Ok(()),
        Ok(_) => Err(StorageError::IntegrityViolation),
        Err(StorageError::NotFound) => match committed {
            Ok(()) => Err(StorageError::IntegrityViolation),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

pub(crate) async fn validate_hosted_packument_pointer(
    storage: &Storage,
    repository: &str,
    package: &str,
    generation: &HostedPackumentPointer,
) -> Result<(), StorageError> {
    if !valid_hosted_packument_pointer(generation) {
        return Err(StorageError::IntegrityViolation);
    }
    let full = storage
        .get(&crate::npm_layout::hosted_packument_full_key(
            repository,
            package,
            &generation.generation,
        ))
        .await?;
    let install_v1 = storage
        .get(&crate::npm_layout::hosted_packument_install_v1_key(
            repository,
            package,
            &generation.generation,
        ))
        .await?;
    if hex::encode(sha2::Sha256::digest(&full)) != generation.full_sha256
        || hex::encode(sha2::Sha256::digest(&install_v1)) != generation.install_v1_sha256
        || valid_hosted_packument(&full, package).is_none()
    {
        return Err(StorageError::IntegrityViolation);
    }
    Ok(())
}

pub(crate) async fn prepare_hosted_packument_after_retention(
    storage: &Storage,
    repository: &str,
    package: &str,
    removed_versions: &HashSet<String>,
) -> Result<HostedMaintenanceTarget, StorageError> {
    // Retention derives its target from the exact developer-visible snapshot.
    // LIST is neither an authority source nor an availability dependency.
    let base = read_hosted_packument_pointer(storage, repository, package)
        .await?
        .ok_or(StorageError::NotFound)?;
    validate_hosted_packument_pointer(storage, repository, package, &base).await?;
    let mut packument = hosted_packument_for_pointer(storage, repository, package, &base).await?;
    let versions = packument
        .get_mut("versions")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(StorageError::IntegrityViolation)?;
    versions.retain(|version, _| !removed_versions.contains(version));
    if versions.is_empty() {
        return Ok(HostedMaintenanceTarget::Retired);
    }
    let tags = packument
        .get_mut("dist-tags")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(StorageError::IntegrityViolation)?;
    tags.retain(|_, target| {
        !target
            .as_str()
            .is_some_and(|version| removed_versions.contains(version))
    });
    let full = serde_json::to_vec(&packument).map_err(|_| StorageError::IntegrityViolation)?;
    let generation = write_hosted_packument_generation_documents(
        storage, repository, package, &packument, &full,
    )
    .await?;
    // The package-wide maintenance marker owns the eventual pointer swap.
    // Preparing immutable documents cannot change developer visibility.
    Ok(HostedMaintenanceTarget::Live {
        pointer: generation,
    })
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

async fn read_hosted_packument_generation(
    state: &AppState,
    repository: &str,
    package: &str,
    flavor: PackumentFlavor,
) -> Result<serde_json::Value, ReadError> {
    let pointer_key = crate::npm_layout::hosted_packument_current_key(repository, package);
    let pointer = match state.storage.get(&pointer_key).await {
        Ok(pointer) => pointer,
        Err(StorageError::NotFound) => {
            // Developer GET remains strictly read-only. Bounded intent probes
            // distinguish a quiescent absence/retirement from a live package
            // or crash-recoverable import/publish/maintenance whose pointer is
            // temporarily missing. No LIST or repair is allowed here.
            let package_key = hosted_package_key(repository, package);
            let import_key = crate::npm_layout::hosted_import_pending_key(repository, package);
            let pending_index_key = hosted_publish_pending_index_key(repository, package);
            let retired_key = crate::npm_layout::hosted_packument_retired_key(repository, package);
            let (maintenance, package_state, import, pending_index, retired) = tokio::join!(
                read_hosted_maintenance_marker(&state.storage, repository, package),
                optional_hosted_materialization_get(state, &package_key),
                optional_hosted_materialization_get(state, &import_key),
                optional_hosted_materialization_get(state, &pending_index_key),
                optional_hosted_materialization_get(state, &retired_key),
            );
            let maintenance = maintenance.map_err(|_| ReadError::MaterializationUnavailable)?;
            let package_state = package_state?;
            let import = import?;
            let pending_index = pending_index?;
            let retired = retired?;
            if import.as_ref().is_some_and(|marker| {
                parse_hosted_import_session(marker, repository, package).is_err()
            }) || pending_index.as_ref().is_some_and(|pending| {
                parse_hosted_publish_pending(pending, repository, package).is_err()
            }) {
                return Err(ReadError::MaterializationUnavailable);
            }
            if maintenance.is_some()
                || package_state.is_some()
                || import.is_some()
                || pending_index.is_some()
            {
                return Err(ReadError::MaterializationUnavailable);
            }
            return match retired {
                Some(marker)
                    if marker.as_ref() == crate::npm_layout::HOSTED_PACKUMENT_RETIRED_V1 =>
                {
                    Err(ReadError::NotFound)
                }
                Some(_) => Err(ReadError::MaterializationUnavailable),
                None => Err(ReadError::NotFound),
            };
        }
        Err(_) => return Err(ReadError::MaterializationUnavailable),
    };
    let pointer: HostedPackumentPointer =
        serde_json::from_slice(&pointer).map_err(|_| ReadError::MaterializationUnavailable)?;
    if !valid_sha256(&pointer.generation)
        || !valid_sha256(&pointer.full_sha256)
        || !valid_sha256(&pointer.install_v1_sha256)
        || pointer.generation != pointer.full_sha256
    {
        return Err(ReadError::MaterializationUnavailable);
    }
    let (key, expected) = match flavor {
        PackumentFlavor::Full => (
            crate::npm_layout::hosted_packument_full_key(repository, package, &pointer.generation),
            pointer.full_sha256,
        ),
        PackumentFlavor::InstallV1 => (
            crate::npm_layout::hosted_packument_install_v1_key(
                repository,
                package,
                &pointer.generation,
            ),
            pointer.install_v1_sha256,
        ),
    };
    let bytes = state
        .storage
        .get(&key)
        .await
        .map_err(|_| ReadError::MaterializationUnavailable)?;
    if hex::encode(sha2::Sha256::digest(&bytes)) != expected {
        return Err(ReadError::MaterializationUnavailable);
    }
    valid_hosted_packument(&bytes, package).ok_or(ReadError::MaterializationUnavailable)
}

async fn hosted_packument(
    state: &AppState,
    repository: &str,
    package: &str,
    response_base: &str,
    flavor: PackumentFlavor,
) -> Result<serde_json::Value, ReadError> {
    let packument = read_hosted_packument_generation(state, repository, package, flavor).await?;
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
    flavor: PackumentFlavor,
) -> Result<PackumentRead, ReadError> {
    let mut packuments = Vec::new();
    let mut stale = false;
    for member in members {
        let Some(repository) = state.config.npm.repository(member).cloned() else {
            continue;
        };
        let result = match repository {
            NpmRepository::Hosted { name, .. } => {
                hosted_packument(state, &name, package, response_base, flavor)
                    .await
                    .map(PackumentRead::fresh)
            }
            NpmRepository::Proxy { .. } if is_internal(state, package) => Err(ReadError::NotFound),
            NpmRepository::Proxy { .. } => {
                let proxy = configured_proxy(state, &repository).expect("proxy config");
                match proxy_packument_raw(state, &proxy, package).await {
                    Ok(read) => project_packument(
                        rewrite_packument_urls(read.value, response_base, package, &proxy.url),
                        flavor,
                    )
                    .map(|value| PackumentRead {
                        value,
                        stale: read.stale,
                    }),
                    Err(error) => Err(error),
                }
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
    flavor: PackumentFlavor,
) -> Result<PackumentRead, ReadError> {
    match target {
        RepositoryTarget::Named(NpmRepository::Hosted { name, .. }) => {
            hosted_packument(state, name, package, response_base, flavor)
                .await
                .map(PackumentRead::fresh)
        }
        RepositoryTarget::Named(repository @ NpmRepository::Proxy { .. }) => {
            let proxy = configured_proxy(state, repository).expect("proxy config");
            let read = proxy_packument_raw(state, &proxy, package).await?;
            Ok(PackumentRead {
                value: project_packument(
                    rewrite_packument_urls(read.value, response_base, package, &proxy.url),
                    flavor,
                )?,
                stale: read.stale,
            })
        }
        RepositoryTarget::Named(NpmRepository::Group { members, .. }) => {
            group_packument(state, members, package, response_base, flavor).await
        }
        RepositoryTarget::Legacy => {
            let mut packuments = Vec::new();
            let mut stale = false;
            match hosted_packument(state, LEGACY_HOSTED, package, response_base, flavor).await {
                Ok(hosted) => packuments.push(hosted),
                Err(ReadError::NotFound) => {}
                Err(error) => return Err(error),
            }
            if !is_internal(state, package) {
                if let Some(proxy) = legacy_proxy(state) {
                    match proxy_packument_raw(state, &proxy, package).await {
                        Ok(read) => {
                            stale |= read.stale;
                            packuments.push(project_packument(
                                rewrite_packument_urls(
                                    read.value,
                                    response_base,
                                    package,
                                    &proxy.url,
                                ),
                                flavor,
                            )?)
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
        ReadError::MaterializationUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "1")],
            "Hosted npm packument is not ready; retry after package repair/finalize",
        )
            .into_response(),
        ReadError::Corrupt => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        ReadError::SearchScanLimit => (
            StatusCode::BAD_GATEWAY,
            "upstream npm search exceeded the bounded scan budget",
        )
            .into_response(),
    }
}

enum HostedVersionResolution {
    Absent,
    AuthoritativelyAbsent,
    Visible(serde_json::Value),
}

async fn hosted_version_from_current(
    state: &AppState,
    repository: &str,
    package: &str,
    version: &str,
) -> Result<HostedVersionResolution, ReadError> {
    match read_hosted_packument_generation(state, repository, package, PackumentFlavor::Full).await
    {
        Ok(packument) => {
            if let Some(manifest) = packument
                .get("versions")
                .and_then(serde_json::Value::as_object)
                .and_then(|versions| versions.get(version))
                .cloned()
            {
                return Ok(HostedVersionResolution::Visible(manifest));
            }
            // A leftover exact split manifest is a bounded tombstone probe
            // for a version removed from the committed generation. It must
            // not be served or bypassed through a later group member.
            return match state
                .storage
                .get(&hosted_version_key(repository, package, version))
                .await
            {
                Ok(_) => Ok(HostedVersionResolution::AuthoritativelyAbsent),
                Err(StorageError::NotFound) => Ok(HostedVersionResolution::Absent),
                Err(error) => Err(storage_read_error(error)),
            };
        }
        Err(ReadError::NotFound) => {
            // A valid retired marker is an explicit absence authority even
            // while best-effort split cleanup is still pending.
            let retired_key = crate::npm_layout::hosted_packument_retired_key(repository, package);
            match state.storage.get(&retired_key).await {
                Ok(marker) if marker.as_ref() == crate::npm_layout::HOSTED_PACKUMENT_RETIRED_V1 => {
                    return Ok(HostedVersionResolution::AuthoritativelyAbsent)
                }
                Ok(_) => return Err(ReadError::MaterializationUnavailable),
                Err(StorageError::NotFound) => {}
                Err(error) => return Err(storage_read_error(error)),
            }
            // The requested exact split key is only an intent/corruption
            // probe when current is absent; it can never make a version
            // visible or cause group/legacy fallthrough.
            match state
                .storage
                .get(&hosted_version_key(repository, package, version))
                .await
            {
                Ok(_) => Err(ReadError::MaterializationUnavailable),
                Err(StorageError::NotFound) => Ok(HostedVersionResolution::Absent),
                Err(error) => Err(storage_read_error(error)),
            }
        }
        Err(error) => Err(error),
    }
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
    let version_data = match hosted_version_from_current(state, repository, package, &version).await
    {
        Ok(HostedVersionResolution::Visible(version_data)) => version_data,
        Ok(HostedVersionResolution::Absent | HostedVersionResolution::AuthoritativelyAbsent) => {
            return StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => return read_error_response(error),
    };
    serve_hosted_tarball_version(
        state,
        repository,
        package,
        &version,
        version_data,
        publish_date,
    )
    .await
}

async fn serve_hosted_tarball_version(
    state: &AppState,
    repository: &str,
    package: &str,
    version: &str,
    version_data: serde_json::Value,
    publish_date: Option<i64>,
) -> Response {
    let manifest = match serde_json::to_vec(&version_data) {
        Ok(manifest) => manifest,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let Some(key) =
        crate::npm_layout::hosted_blob_key_from_manifest(repository, package, manifest.as_slice())
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
    curated_tarball_response(state, package, version, data, "hosted", publish_date)
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
                match hosted_version_from_current(state, &name, package, &version).await {
                    Ok(HostedVersionResolution::Visible(version_data)) => {
                        // Once a member claims the version, its tarball is the
                        // only legal origin. Do not fall through after an
                        // incomplete or corrupt member.
                        return serve_hosted_tarball_version(
                            state,
                            &name,
                            package,
                            &version,
                            version_data,
                            publish_date,
                        )
                        .await;
                    }
                    Ok(HostedVersionResolution::AuthoritativelyAbsent) => {
                        return StatusCode::NOT_FOUND.into_response()
                    }
                    Ok(HostedVersionResolution::Absent) => {}
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
            match hosted_version_from_current(state, LEGACY_HOSTED, package, &version).await {
                Ok(HostedVersionResolution::Visible(version_data)) => {
                    return serve_hosted_tarball_version(
                        state,
                        LEGACY_HOSTED,
                        package,
                        &version,
                        version_data,
                        publish_date,
                    )
                    .await
                }
                Ok(HostedVersionResolution::AuthoritativelyAbsent) => {
                    return StatusCode::NOT_FOUND.into_response()
                }
                Ok(HostedVersionResolution::Absent) => {}
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
    let packument_flavor = PackumentFlavor::from_headers(&headers);
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
        match target_packument(&state, &target, &package, &response_base, packument_flavor).await {
            Ok(packument) => packument_response(
                &headers,
                &packument.value,
                packument.stale,
                packument_flavor,
            ),
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

#[derive(Debug)]
struct ImportVersionPreflight {
    completed_receipt: bool,
    session: Option<HostedImportSession>,
    pending_present: bool,
    blob_present: bool,
    manifest_present: bool,
    completion_present: bool,
    evidence_present: bool,
}

async fn import_version_preflight(
    state: &AppState,
    repository: &str,
    package: &str,
    expected_packument_sha256: &str,
    validated: &ValidatedPublish,
) -> Result<ImportVersionPreflight, StorageError> {
    let manifest_digest = crate::npm_layout::hosted_manifest_digest(&validated.manifest);
    let receipt_key = crate::npm_layout::hosted_import_receipt_key(
        repository,
        package,
        expected_packument_sha256,
    );
    let receipt = match state.storage.get(&receipt_key).await {
        Ok(bytes) => {
            let receipt: HostedImportReceipt =
                serde_json::from_slice(&bytes).map_err(|_| StorageError::IntegrityViolation)?;
            if receipt.package != package
                || receipt.generation != expected_packument_sha256
                || receipt.full_sha256 != expected_packument_sha256
                || !valid_sha256(&receipt.install_v1_sha256)
            {
                return Err(StorageError::IntegrityViolation);
            }
            Some(receipt)
        }
        Err(StorageError::NotFound) => None,
        Err(error) => return Err(error),
    };

    let session = read_optional_import_session(&state.storage, repository, package).await?;
    if session
        .as_ref()
        .is_some_and(|session| session.packument_sha256 != expected_packument_sha256)
        || session
            .as_ref()
            .and_then(|session| session.versions.get(&validated.version))
            .is_some_and(|digest| digest != &manifest_digest)
    {
        return Err(StorageError::AlreadyExists);
    }

    let pending_present =
        match read_optional_publish_pending(&state.storage, repository, package).await? {
            Some(pending)
                if pending.version == validated.version
                    && pending.manifest_sha256 == manifest_digest
                    && pending.blob_sha512 == validated.blob_digest
                    && pending.target
                        == (HostedPublishPendingTarget::Import {
                            packument_sha256: expected_packument_sha256.to_string(),
                        }) =>
            {
                true
            }
            Some(_) => return Err(StorageError::AlreadyExists),
            None => false,
        };

    let manifest_key = hosted_version_key(repository, package, &validated.version);
    let manifest_present = match state.storage.get(&manifest_key).await {
        Ok(manifest) if manifest.as_ref() == validated.manifest.as_slice() => true,
        Ok(_) => return Err(StorageError::AlreadyExists),
        Err(StorageError::NotFound) => false,
        Err(error) => return Err(error),
    };
    let completion_key = hosted_publish_complete_key(repository, package, &validated.version);
    let completion_present = match state.storage.get(&completion_key).await {
        Ok(completion) if completion.as_ref() == manifest_digest.as_bytes() => true,
        Ok(_) => return Err(StorageError::AlreadyExists),
        Err(StorageError::NotFound) => false,
        Err(error) => return Err(error),
    };

    let blob_key =
        crate::npm_layout::hosted_blob_key_for_digest(repository, package, &validated.blob_digest);
    let blob_present = match state.storage.get(&blob_key).await {
        Ok(blob) if blob.as_ref() == validated.tarball.as_slice() => true,
        Ok(_) => return Err(StorageError::AlreadyExists),
        Err(StorageError::NotFound) => false,
        Err(error) => return Err(error),
    };

    let evidence_key = crate::npm_layout::hosted_import_evidence_key(
        repository,
        package,
        expected_packument_sha256,
        &validated.version,
        &manifest_digest,
    );
    let evidence_present = match state.storage.get(&evidence_key).await {
        Ok(value) if value.as_ref() == b"1" => true,
        Ok(_) => return Err(StorageError::AlreadyExists),
        Err(StorageError::NotFound) => false,
        Err(error) => return Err(error),
    };

    if let Some(receipt) = &receipt {
        if pending_present
            || !(manifest_present && completion_present && blob_present && evidence_present)
        {
            return Err(StorageError::AlreadyExists);
        }
        let generation = HostedPackumentPointer {
            generation: receipt.generation.clone(),
            full_sha256: receipt.full_sha256.clone(),
            install_v1_sha256: receipt.install_v1_sha256.clone(),
        };
        match validate_hosted_packument_pointer(&state.storage, repository, package, &generation)
            .await
        {
            Ok(()) => {}
            Err(StorageError::NotFound | StorageError::IntegrityViolation) => {
                return Err(StorageError::AlreadyExists)
            }
            Err(error) => return Err(error),
        }
        let full = match state
            .storage
            .get(&crate::npm_layout::hosted_packument_full_key(
                repository,
                package,
                &receipt.generation,
            ))
            .await
        {
            Ok(full) => full,
            Err(StorageError::NotFound | StorageError::IntegrityViolation) => {
                return Err(StorageError::AlreadyExists)
            }
            Err(error) => return Err(error),
        };
        let full = valid_hosted_packument(&full, package).ok_or(StorageError::AlreadyExists)?;
        let versions = full
            .get("versions")
            .and_then(serde_json::Value::as_object)
            .ok_or(StorageError::AlreadyExists)?;
        if versions.len() != receipt.version_count {
            return Err(StorageError::AlreadyExists);
        }
        let mut receipt_manifest = versions
            .get(&validated.version)
            .cloned()
            .ok_or(StorageError::AlreadyExists)?;
        receipt_manifest
            .as_object_mut()
            .ok_or(StorageError::AlreadyExists)?
            .remove("deprecated");
        let expected_manifest: serde_json::Value = serde_json::from_slice(&validated.manifest)
            .map_err(|_| StorageError::IntegrityViolation)?;
        if receipt_manifest != expected_manifest {
            return Err(StorageError::AlreadyExists);
        }
    } else if manifest_present {
        // A missing completion is resumable only behind this exact pending
        // digest. The tarball blob was ordered before the manifest, so its
        // absence is corruption rather than permission to recreate history.
        if !blob_present
            || (!completion_present && !pending_present)
            || (!completion_present && evidence_present)
            || (evidence_present
                && session
                    .as_ref()
                    .and_then(|session| session.versions.get(&validated.version))
                    != Some(&manifest_digest))
        {
            return Err(StorageError::AlreadyExists);
        }
    } else if completion_present || evidence_present {
        return Err(StorageError::AlreadyExists);
    }

    Ok(ImportVersionPreflight {
        completed_receipt: receipt.is_some(),
        session,
        pending_present,
        blob_present,
        manifest_present,
        completion_present,
        evidence_present,
    })
}

async fn put_exact_with_readback(
    storage: &Storage,
    key: &str,
    value: &[u8],
) -> Result<(), StorageError> {
    let written = storage.put(key, value).await;
    match storage.get(key).await {
        Ok(current) if current.as_ref() == value => Ok(()),
        Ok(_) => Err(StorageError::AlreadyExists),
        Err(StorageError::NotFound) => match written {
            Ok(()) => Err(StorageError::IntegrityViolation),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

async fn ensure_import_session_version(
    state: &AppState,
    repository: &str,
    package: &str,
    packument_sha256: &str,
    version: &str,
    manifest_sha256: &str,
    existing: Option<HostedImportSession>,
) -> Result<HostedImportSession, StorageError> {
    let marker_key = crate::npm_layout::hosted_import_pending_key(repository, package);
    let expected_previous = existing
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| StorageError::IntegrityViolation)?;
    let mut session = if let Some(session) = existing {
        session
    } else {
        let base = read_hosted_packument_pointer(&state.storage, repository, package).await?;
        if let Some(base) = &base {
            validate_hosted_packument_pointer(&state.storage, repository, package, base).await?;
        } else {
            match state
                .storage
                .get(&hosted_package_key(repository, package))
                .await
            {
                Err(StorageError::NotFound) => {}
                Ok(_) => return Err(StorageError::IntegrityViolation),
                Err(error) => return Err(error),
            }
        }
        HostedImportSession {
            schema: crate::npm_layout::HOSTED_IMPORT_SESSION_SCHEMA_V1,
            repository: repository.to_string(),
            package: package.to_string(),
            packument_sha256: packument_sha256.to_string(),
            base,
            versions: BTreeMap::new(),
        }
    };
    if session.packument_sha256 != packument_sha256 {
        return Err(StorageError::AlreadyExists);
    }
    match session.versions.get(version) {
        Some(existing) if existing == manifest_sha256 => return Ok(session),
        Some(_) => return Err(StorageError::AlreadyExists),
        None => {
            session
                .versions
                .insert(version.to_string(), manifest_sha256.to_string());
        }
    }
    let bytes = serde_json::to_vec(&session).map_err(|_| StorageError::IntegrityViolation)?;
    match (state.storage.get(&marker_key).await, expected_previous) {
        (Ok(current), Some(previous)) if current.as_ref() == previous.as_slice() => {
            put_exact_with_readback(&state.storage, &marker_key, &bytes).await?
        }
        (Ok(_), _) => return Err(StorageError::AlreadyExists),
        (Err(StorageError::NotFound), None) => {
            put_immutable_storage(&state.storage, &marker_key, &bytes).await?
        }
        (Err(StorageError::NotFound), Some(_)) => return Err(StorageError::AlreadyExists),
        (Err(error), _) => return Err(error),
    }
    let stored = state.storage.get(&marker_key).await?;
    let stored = parse_hosted_import_session(&stored, repository, package)?;
    if stored != session {
        return Err(StorageError::AlreadyExists);
    }
    Ok(session)
}

async fn delete_exact_with_readback(
    storage: &Storage,
    key: &str,
    expected: &[u8],
) -> Result<(), StorageError> {
    match storage.get(key).await {
        Ok(current) if current.as_ref() == expected => {}
        Ok(_) => return Err(StorageError::AlreadyExists),
        Err(StorageError::NotFound) => return Ok(()),
        Err(error) => return Err(error),
    }
    let deleted = storage.delete(key).await;
    match storage.get(key).await {
        Err(StorageError::NotFound) => Ok(()),
        Ok(current) if current.as_ref() == expected => match deleted {
            Ok(()) => Err(StorageError::IntegrityViolation),
            Err(error) => Err(error),
        },
        Ok(_) => Err(StorageError::AlreadyExists),
        Err(error) => Err(error),
    }
}

async fn publish_import_version_locked(
    state: &AppState,
    repository: &str,
    package: &str,
    expected_packument_sha256: &str,
    validated: &ValidatedPublish,
) -> Response {
    fn immutable_write_error(error: StorageError) -> Response {
        match error {
            StorageError::AlreadyExists | StorageError::IntegrityViolation => (
                StatusCode::CONFLICT,
                "Imported npm version state changed during exact preflight",
            )
                .into_response(),
            _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
    let preflight = match import_version_preflight(
        state,
        repository,
        package,
        expected_packument_sha256,
        validated,
    )
    .await
    {
        Ok(preflight) => preflight,
        Err(StorageError::AlreadyExists) => {
            return (
                StatusCode::CONFLICT,
                "Imported npm version state differs from the exact import payload",
            )
                .into_response()
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if preflight.completed_receipt {
        // A delayed version PUT from an already completed import is an exact,
        // read-only acknowledgement. Never rewind package metadata, tags,
        // deprecations or a later packument pointer.
        return StatusCode::CREATED.into_response();
    }
    let active_pending =
        match read_optional_publish_pending(&state.storage, repository, package).await {
            Ok(pending) => pending,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
    if active_pending
        .as_ref()
        .is_some_and(|pending| pending.version != validated.version)
    {
        return incomplete_publish_response();
    }

    let manifest_digest = crate::npm_layout::hosted_manifest_digest(&validated.manifest);
    if let Err(error) = ensure_import_session_version(
        state,
        repository,
        package,
        expected_packument_sha256,
        &validated.version,
        &manifest_digest,
        preflight.session.clone(),
    )
    .await
    {
        return immutable_write_error(error);
    }
    let pending = HostedPublishPending {
        schema: crate::npm_layout::HOSTED_PUBLISH_PENDING_SCHEMA_V1,
        repository: repository.to_string(),
        package: package.to_string(),
        version: validated.version.clone(),
        manifest_sha256: manifest_digest.clone(),
        blob_sha512: validated.blob_digest.clone(),
        target: HostedPublishPendingTarget::Import {
            packument_sha256: expected_packument_sha256.to_string(),
        },
    };
    if !preflight.pending_present {
        if let Err(error) = create_hosted_publish_pending(&state.storage, &pending).await {
            return immutable_write_error(error);
        }
    }
    let blob_key =
        crate::npm_layout::hosted_blob_key_for_digest(repository, package, &validated.blob_digest);
    if !preflight.blob_present {
        if let Err(error) =
            put_immutable_storage(&state.storage, &blob_key, &validated.tarball).await
        {
            return immutable_write_error(error);
        }
    }
    let manifest_key = hosted_version_key(repository, package, &validated.version);
    if !preflight.manifest_present {
        if let Err(error) =
            put_immutable_storage(&state.storage, &manifest_key, &validated.manifest).await
        {
            return immutable_write_error(error);
        }
    }
    let completion_key = hosted_publish_complete_key(repository, package, &validated.version);
    if !preflight.completion_present {
        if let Err(error) =
            put_immutable_storage(&state.storage, &completion_key, manifest_digest.as_bytes()).await
        {
            return immutable_write_error(error);
        }
    }
    let evidence_key = crate::npm_layout::hosted_import_evidence_key(
        repository,
        package,
        expected_packument_sha256,
        &validated.version,
        &manifest_digest,
    );
    if !preflight.evidence_present {
        if let Err(error) = put_immutable_storage(&state.storage, &evidence_key, b"1").await {
            return immutable_write_error(error);
        }
    }
    if clear_hosted_publish_pending(&state.storage, &pending)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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

async fn publish_with_import(
    state: &AppState,
    repository: &str,
    write_policy: NpmWritePolicy,
    package: &str,
    payload: &serde_json::Value,
    import_packument_sha256: Option<&str>,
) -> Response {
    let validated = match validate_publish(package, payload) {
        Ok(validated) => validated,
        Err(error) => return error.into_response(),
    };
    let lock_key = format!("npm:{repository}:{package}");
    let lock = state.publish_lock(&lock_key);
    let _guard = lock.lock().await;
    match resume_hosted_maintenance_operation(&state.storage, repository, package).await {
        Ok(true) => state.repo_index.invalidate("npm"),
        Ok(false) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    if let Some(expected) = import_packument_sha256 {
        return publish_import_version_locked(state, repository, package, expected, &validated)
            .await;
    }
    match hosted_import_active(&state.storage, repository, package).await {
        Ok(true) => {
            return (
                StatusCode::CONFLICT,
                "Package has an active bulk import; finalize it before normal mutation",
            )
                .into_response()
        }
        Ok(false) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    let active_pending =
        match read_optional_publish_pending(&state.storage, repository, package).await {
            Ok(pending) => pending,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
    if active_pending
        .as_ref()
        .is_some_and(|pending| pending.version != validated.version)
    {
        return incomplete_publish_response();
    }

    let manifest_key = hosted_version_key(repository, package, &validated.version);
    let completion_key = hosted_publish_complete_key(repository, package, &validated.version);
    let completion_digest = crate::npm_layout::hosted_manifest_digest(&validated.manifest);
    let (completed_exact_allow_once, missing_completion_allow_once) =
        if write_policy == NpmWritePolicy::AllowOnce {
            match state.storage.get(&manifest_key).await {
                Ok(existing) if existing.as_ref() == validated.manifest.as_slice() => {
                    match state.storage.get(&completion_key).await {
                        Ok(completion) if completion.as_ref() == completion_digest.as_bytes() => {
                            (true, false)
                        }
                        Ok(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                        Err(StorageError::NotFound) => (false, true),
                        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    }
                }
                Ok(_) => {
                    return (
                        StatusCode::CONFLICT,
                        "Version already exists with other metadata or tarball bytes",
                    )
                        .into_response()
                }
                Err(StorageError::NotFound) => (false, false),
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        } else {
            (false, false)
        };

    if completed_exact_allow_once && active_pending.is_none() {
        // An accepted exact retry is a no-op. In particular, do not rewind a
        // dist-tag/deprecation changed after the original publish. The
        // committed current generation must already contain this version.
        if ensure_completed_publish_materialized(state, repository, package, &validated.version)
            .await
            .is_err()
        {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        return StatusCode::CREATED.into_response();
    }

    if missing_completion_allow_once && active_pending.is_none() {
        // Completion is committed before the current pointer and pending is
        // cleared only after both verify exactly. No legitimate crash can
        // therefore leave an exact manifest with missing completion and no
        // pending intent, regardless of whether current exists. Treat it as
        // corruption and never manufacture recovery state from visibility.
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let (base, previous_packument, recorded_target) = match active_pending.as_ref() {
        Some(HostedPublishPending {
            target: HostedPublishPendingTarget::Publish { base, target },
            ..
        }) => {
            let previous = match base {
                Some(base) => {
                    match hosted_packument_for_pointer(&state.storage, repository, package, base)
                        .await
                    {
                        Ok(packument) => Some(packument),
                        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    }
                }
                None => None,
            };
            let current =
                match read_hosted_packument_pointer(&state.storage, repository, package).await {
                    Ok(current) => current,
                    Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                };
            if current.as_ref() != base.as_ref() && current.as_ref() != Some(target) {
                return incomplete_publish_response();
            }
            (base.clone(), previous, Some(target.clone()))
        }
        Some(_) => return incomplete_publish_response(),
        None => {
            let base =
                match read_hosted_packument_pointer(&state.storage, repository, package).await {
                    Ok(base) => base,
                    Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                };
            let previous = match &base {
                Some(base) => {
                    match hosted_packument_for_pointer(&state.storage, repository, package, base)
                        .await
                    {
                        Ok(packument) => Some(packument),
                        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    }
                }
                None => {
                    match state
                        .storage
                        .get(&hosted_package_key(repository, package))
                        .await
                    {
                        Err(StorageError::NotFound) => None,
                        Ok(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
                        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    }
                }
            };
            (base, previous, None)
        }
    };
    let target_packument =
        match packument_after_publish(package, previous_packument.clone(), &validated) {
            Ok(packument) => packument,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
    let (target_full, target_pointer) = match hosted_packument_pointer_for_value(&target_packument)
    {
        Ok(target) => target,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if recorded_target
        .as_ref()
        .is_some_and(|recorded| recorded != &target_pointer)
    {
        return incomplete_publish_response();
    }
    let base_mutable = match hosted_mutable_state_from_packument(previous_packument.as_ref()) {
        Ok(state) => state,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let target_mutable = match hosted_mutable_state_from_packument(Some(&target_packument)) {
        Ok(state) => state,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let mutable_authorities =
        hosted_mutable_authorities(repository, package, &base_mutable, &target_mutable);
    let pending = HostedPublishPending {
        schema: crate::npm_layout::HOSTED_PUBLISH_PENDING_SCHEMA_V1,
        repository: repository.to_string(),
        package: package.to_string(),
        version: validated.version.clone(),
        manifest_sha256: completion_digest.clone(),
        blob_sha512: validated.blob_digest.clone(),
        target: HostedPublishPendingTarget::Publish {
            base,
            target: target_pointer.clone(),
        },
    };
    if active_pending
        .as_ref()
        .is_some_and(|active| active != &pending)
    {
        return incomplete_publish_response();
    }
    if active_pending.is_none()
        && create_hosted_publish_pending(&state.storage, &pending)
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
            tracing::error!(key = %blob_key, "npm content digest collision");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(error) => {
            tracing::error!(key = %blob_key, error = ?error, "npm tarball blob create failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // Split objects are prepared behind the immutable current-generation
    // pointer. The referenced tarball blob is content-addressed and durable
    // before the version manifest changes.
    let manifest_outcome =
        match commit_hosted_manifest(state, &manifest_key, &validated.manifest, write_policy).await
        {
            Ok(outcome) => outcome,
            Err(ManifestCommitError::Conflict) => {
                return (
                    StatusCode::CONFLICT,
                    "Version already exists with other metadata or tarball bytes",
                )
                    .into_response();
            }
            Err(ManifestCommitError::Storage(error)) => {
                tracing::error!(key = %manifest_key, error = ?error, "npm version commit failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

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
            Err(StorageError::NotFound) => true,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    } else {
        // `allow` is a real redeploy even when the immutable version
        // manifest happens to be byte-identical: npm publish's selected
        // dist-tag and package fields are mutable payload state. Remove
        // the completion marker before touching that state so a failed
        // post-commit phase cannot be acknowledged as complete on retry.
        match read_optional_exact(&state.storage, &completion_key).await {
            Ok(Some(current)) => {
                if delete_exact_with_readback(&state.storage, &completion_key, &current)
                    .await
                    .is_err()
                {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
            Ok(None) => {}
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
        true
    };
    if converge_hosted_mutable_target(&state.storage, &mutable_authorities)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if needs_completion
        && put_exact_with_readback(
            &state.storage,
            &completion_key,
            completion_digest.as_bytes(),
        )
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let written_target = match write_hosted_packument_generation_documents(
        &state.storage,
        repository,
        package,
        &target_packument,
        &target_full,
    )
    .await
    {
        Ok(target) if target == target_pointer => target,
        Ok(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let verification = HostedPublishVerification {
        manifest_key: &manifest_key,
        manifest: &validated.manifest,
        blob_key: &blob_key,
        blob: &validated.tarball,
        completion_key: &completion_key,
        completion_digest: &completion_digest,
        mutable_authorities: &mutable_authorities,
    };
    if verify_publish_target_state(&state.storage, &verification)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if commit_hosted_packument_pointer(&state.storage, repository, package, &written_target)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    // The pending marker is the crash-recovery boundary. Remove it only after
    // the developer-visible generation pointer and every exact target have
    // committed successfully.
    let pointer_matches = matches!(
        read_hosted_packument_pointer(&state.storage, repository, package).await,
        Ok(Some(current)) if current == written_target
    );
    if !pointer_matches
        || verify_publish_target_state(&state.storage, &verification)
            .await
            .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if clear_hosted_publish_pending(&state.storage, &pending)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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

#[cfg(test)]
async fn publish(
    state: &AppState,
    repository: &str,
    write_policy: NpmWritePolicy,
    package: &str,
    payload: &serde_json::Value,
) -> Response {
    publish_with_import(state, repository, write_policy, package, payload, None).await
}

struct DesiredImportVersion {
    manifest: serde_json::Value,
    manifest_sha256: String,
    deprecation: Option<String>,
}

struct ValidatedHostedImport {
    versions: std::collections::BTreeMap<String, DesiredImportVersion>,
    tags: std::collections::BTreeMap<String, String>,
    package_fields: serde_json::Value,
}

fn validate_hosted_import(
    package: &str,
    packument: &serde_json::Value,
) -> Result<ValidatedHostedImport, NpmHttpError> {
    let object = packument.as_object().ok_or_else(|| {
        NpmHttpError::new(StatusCode::BAD_REQUEST, "Invalid npm import packument")
    })?;
    if object.get("name").and_then(serde_json::Value::as_str) != Some(package) {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Imported npm package name does not match the route",
        ));
    }
    let allowed_top = [
        "name",
        "_id",
        "description",
        "readme",
        "license",
        "versions",
        "dist-tags",
    ];
    if object
        .keys()
        .any(|field| !allowed_top.contains(&field.as_str()))
    {
        return Err(NpmHttpError::new(
            StatusCode::BAD_REQUEST,
            "Imported npm packument has unsupported package fields",
        ));
    }
    let desired_versions = object
        .get("versions")
        .and_then(serde_json::Value::as_object)
        .filter(|versions| !versions.is_empty())
        .ok_or_else(|| {
            NpmHttpError::new(
                StatusCode::BAD_REQUEST,
                "Imported npm packument has no versions",
            )
        })?;
    let mut versions = std::collections::BTreeMap::new();
    for (version, desired) in desired_versions {
        if !is_valid_npm_version(version)
            || desired.get("name").and_then(serde_json::Value::as_str) != Some(package)
            || desired.get("version").and_then(serde_json::Value::as_str) != Some(version.as_str())
        {
            return Err(NpmHttpError::new(
                StatusCode::BAD_REQUEST,
                "Imported npm version metadata has an invalid coordinate",
            ));
        }
        let mut manifest = desired.clone();
        let manifest_object = manifest.as_object_mut().ok_or_else(|| {
            NpmHttpError::new(
                StatusCode::BAD_REQUEST,
                "Imported npm version metadata is not an object",
            )
        })?;
        let deprecation = match manifest_object.remove("deprecated") {
            Some(serde_json::Value::String(message)) => Some(message),
            Some(_) => {
                return Err(NpmHttpError::new(
                    StatusCode::BAD_REQUEST,
                    "Imported npm deprecation is invalid",
                ))
            }
            None => None,
        };
        let dist = manifest_object
            .get("dist")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                NpmHttpError::new(
                    StatusCode::BAD_REQUEST,
                    "Imported npm version has invalid dist metadata",
                )
            })?;
        if dist.contains_key("tarball")
            || !dist
                .get("shasum")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|digest| {
                    digest.len() == 40 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            || crate::npm_layout::hosted_blob_digest_from_manifest(
                &serde_json::to_vec(&manifest).unwrap_or_default(),
            )
            .is_none()
        {
            return Err(NpmHttpError::new(
                StatusCode::BAD_REQUEST,
                "Imported npm dist checksums are invalid or include a route URL",
            ));
        }
        let manifest_bytes = serde_json::to_vec(&manifest).map_err(|_| {
            NpmHttpError::new(
                StatusCode::BAD_REQUEST,
                "Imported npm version metadata is not serializable",
            )
        })?;
        versions.insert(
            version.clone(),
            DesiredImportVersion {
                manifest,
                manifest_sha256: crate::npm_layout::hosted_manifest_digest(&manifest_bytes),
                deprecation,
            },
        );
    }

    let desired_tags = object
        .get("dist-tags")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            NpmHttpError::new(
                StatusCode::BAD_REQUEST,
                "Imported npm dist-tags are invalid",
            )
        })?;
    let mut tags = std::collections::BTreeMap::new();
    for (tag, target) in desired_tags {
        let target = target.as_str().ok_or_else(|| {
            NpmHttpError::new(
                StatusCode::BAD_REQUEST,
                "Imported npm dist-tag target is invalid",
            )
        })?;
        if !is_valid_dist_tag(tag) || !versions.contains_key(target) {
            return Err(NpmHttpError::new(
                StatusCode::BAD_REQUEST,
                "Imported npm dist-tag references a missing version",
            ));
        }
        tags.insert(tag.clone(), target.to_string());
    }

    let mut package_fields = serde_json::Map::new();
    for field in ["name", "_id", "description", "readme", "license"] {
        if let Some(value) = object.get(field) {
            package_fields.insert(field.to_string(), value.clone());
        }
    }
    Ok(ValidatedHostedImport {
        versions,
        tags,
        package_fields: serde_json::Value::Object(package_fields),
    })
}

async fn validate_import_version_state(
    state: &AppState,
    repository: &str,
    package: &str,
    full_sha256: &str,
    desired: &ValidatedHostedImport,
    session: &HostedImportSession,
) -> Result<(), StorageError> {
    let desired_roster = desired
        .versions
        .iter()
        .map(|(version, desired)| (version.clone(), desired.manifest_sha256.clone()))
        .collect::<BTreeMap<_, _>>();
    if session.repository != repository
        || session.package != package
        || session.packument_sha256 != full_sha256
        || session.versions != desired_roster
    {
        return Err(StorageError::AlreadyExists);
    }

    if let Some(base) = &session.base {
        let base_packument =
            hosted_packument_for_pointer(&state.storage, repository, package, base).await?;
        let base_versions = base_packument
            .get("versions")
            .and_then(serde_json::Value::as_object)
            .ok_or(StorageError::IntegrityViolation)?;
        if !base_versions
            .keys()
            .all(|version| desired.versions.contains_key(version))
        {
            return Err(StorageError::AlreadyExists);
        }
    }

    let desired_checks = desired
        .versions
        .iter()
        .map(|(version, desired)| {
            (
                version.clone(),
                desired.manifest.clone(),
                desired.manifest_sha256.clone(),
            )
        })
        .collect::<Vec<_>>();
    let checks = stream::iter(desired_checks)
        .map(
            |(version, desired_manifest, desired_manifest_sha256)| async move {
                let manifest = state
                    .storage
                    .get(&hosted_version_key(repository, package, &version))
                    .await?;
                let desired_manifest_bytes = serde_json::to_vec(&desired_manifest)
                    .map_err(|_| StorageError::IntegrityViolation)?;
                if manifest.as_ref() != desired_manifest_bytes.as_slice() {
                    return Err(StorageError::AlreadyExists);
                }
                let completion = state
                    .storage
                    .get(&hosted_publish_complete_key(repository, package, &version))
                    .await?;
                if completion.as_ref() != desired_manifest_sha256.as_bytes() {
                    return Err(StorageError::IntegrityViolation);
                }
                let blob_key = crate::npm_layout::hosted_blob_key_from_manifest(
                    repository,
                    package,
                    &desired_manifest_bytes,
                )
                .ok_or(StorageError::IntegrityViolation)?;
                let blob = state.storage.get(&blob_key).await?;
                let actual_blob_digest = hex::encode(sha2::Sha512::digest(&blob));
                if !blob_key.ends_with(&format!("/{actual_blob_digest}.tgz")) {
                    return Err(StorageError::IntegrityViolation);
                }
                let evidence_key = crate::npm_layout::hosted_import_evidence_key(
                    repository,
                    package,
                    full_sha256,
                    &version,
                    &desired_manifest_sha256,
                );
                let evidence = state.storage.get(&evidence_key).await?;
                if evidence.as_ref() != b"1" {
                    return Err(StorageError::IntegrityViolation);
                }
                Ok::<(), StorageError>(())
            },
        )
        .buffer_unordered(32)
        .collect::<Vec<_>>()
        .await;
    for check in checks {
        check?;
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
struct HostedMutableState {
    package: Option<Vec<u8>>,
    tags: BTreeMap<String, Vec<u8>>,
    deprecations: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone)]
struct HostedMutableAuthority {
    key: String,
    base: Option<Vec<u8>>,
    target: Option<Vec<u8>>,
}

fn package_fields_from_packument(packument: &serde_json::Value) -> serde_json::Value {
    let mut fields = serde_json::Map::new();
    for field in ["name", "_id", "description", "readme", "license"] {
        if let Some(value) = packument.get(field) {
            fields.insert(field.to_string(), value.clone());
        }
    }
    serde_json::Value::Object(fields)
}

fn hosted_mutable_state_from_packument(
    packument: Option<&serde_json::Value>,
) -> Result<HostedMutableState, StorageError> {
    let Some(packument) = packument else {
        return Ok(HostedMutableState::default());
    };
    let package = Some(
        serde_json::to_vec(&package_fields_from_packument(packument))
            .map_err(|_| StorageError::IntegrityViolation)?,
    );
    let tags = packument
        .get("dist-tags")
        .and_then(serde_json::Value::as_object)
        .ok_or(StorageError::IntegrityViolation)?
        .iter()
        .map(|(tag, target)| {
            target
                .as_str()
                .map(|target| (tag.clone(), target.as_bytes().to_vec()))
                .ok_or(StorageError::IntegrityViolation)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let deprecations = packument
        .get("versions")
        .and_then(serde_json::Value::as_object)
        .ok_or(StorageError::IntegrityViolation)?
        .iter()
        .filter_map(|(version, manifest)| {
            manifest
                .get("deprecated")
                .and_then(serde_json::Value::as_str)
                .filter(|message| !message.is_empty())
                .map(|message| (version.clone(), message.as_bytes().to_vec()))
        })
        .collect();
    Ok(HostedMutableState {
        package,
        tags,
        deprecations,
    })
}

fn hosted_mutable_state_from_import(
    desired: &ValidatedHostedImport,
) -> Result<HostedMutableState, StorageError> {
    let package = Some(
        serde_json::to_vec(&desired.package_fields)
            .map_err(|_| StorageError::IntegrityViolation)?,
    );
    let tags = desired
        .tags
        .iter()
        .map(|(tag, target)| (tag.clone(), target.as_bytes().to_vec()))
        .collect();
    let deprecations = desired
        .versions
        .iter()
        .filter_map(|(version, desired)| {
            desired
                .deprecation
                .as_deref()
                .filter(|message| !message.is_empty())
                .map(|message| (version.clone(), message.as_bytes().to_vec()))
        })
        .collect();
    Ok(HostedMutableState {
        package,
        tags,
        deprecations,
    })
}

fn hosted_mutable_authorities(
    repository: &str,
    package: &str,
    base: &HostedMutableState,
    target: &HostedMutableState,
) -> Vec<HostedMutableAuthority> {
    let mut authorities = BTreeMap::<String, (Option<Vec<u8>>, Option<Vec<u8>>)>::new();
    authorities.insert(
        hosted_package_key(repository, package),
        (base.package.clone(), target.package.clone()),
    );
    for tag in base.tags.keys().chain(target.tags.keys()) {
        authorities
            .entry(hosted_tag_key(repository, package, tag))
            .or_insert_with(|| (base.tags.get(tag).cloned(), target.tags.get(tag).cloned()));
    }
    for version in base.deprecations.keys().chain(target.deprecations.keys()) {
        authorities
            .entry(hosted_deprecation_key(repository, package, version))
            .or_insert_with(|| {
                (
                    base.deprecations.get(version).cloned(),
                    target.deprecations.get(version).cloned(),
                )
            });
    }
    authorities
        .into_iter()
        .map(|(key, (base, target))| HostedMutableAuthority { key, base, target })
        .collect()
}

async fn read_optional_exact(
    storage: &Storage,
    key: &str,
) -> Result<Option<Vec<u8>>, StorageError> {
    match storage.get(key).await {
        Ok(value) => Ok(Some(value.to_vec())),
        Err(StorageError::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

async fn verify_hosted_mutable_target(
    storage: &Storage,
    authorities: &[HostedMutableAuthority],
) -> Result<(), StorageError> {
    let reads = stream::iter(authorities.iter().cloned())
        .map(|authority| async move {
            let current = read_optional_exact(storage, &authority.key).await?;
            if current.as_deref() == authority.target.as_deref() {
                Ok(())
            } else {
                Err(StorageError::AlreadyExists)
            }
        })
        .buffer_unordered(NPM_IMPORT_MUTATION_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    for read in reads {
        read?;
    }
    Ok(())
}

async fn converge_hosted_mutable_target(
    storage: &Storage,
    authorities: &[HostedMutableAuthority],
) -> Result<(), StorageError> {
    #[derive(Debug)]
    enum Mutation {
        Put { key: String, value: Vec<u8> },
        Delete { key: String, expected: Vec<u8> },
    }

    // Exact preflight is the recovery fence: every authority must still be at
    // the recorded base or target before the first retry write.
    let reads = stream::iter(authorities.iter().cloned())
        .map(|authority| async move {
            let current = read_optional_exact(storage, &authority.key).await?;
            if current.as_deref() == authority.target.as_deref() {
                return Ok(None);
            }
            if current.as_deref() != authority.base.as_deref() {
                return Err(StorageError::AlreadyExists);
            }
            Ok(match (&current, &authority.target) {
                (_, Some(value)) => Some(Mutation::Put {
                    key: authority.key.clone(),
                    value: value.clone(),
                }),
                (Some(expected), None) => Some(Mutation::Delete {
                    key: authority.key.clone(),
                    expected: expected.clone(),
                }),
                (None, None) => None,
            })
        })
        .buffer_unordered(NPM_IMPORT_MUTATION_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut mutations = Vec::new();
    for read in reads {
        if let Some(mutation) = read? {
            mutations.push(mutation);
        }
    }
    let writes = stream::iter(mutations)
        .map(|mutation| async move {
            match mutation {
                Mutation::Put { key, value } => {
                    put_exact_with_readback(storage, &key, &value).await
                }
                Mutation::Delete { key, expected } => {
                    delete_exact_with_readback(storage, &key, &expected).await
                }
            }
        })
        .buffer_unordered(NPM_IMPORT_MUTATION_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    for write in writes {
        write?;
    }
    verify_hosted_mutable_target(storage, authorities).await
}

struct HostedPublishVerification<'a> {
    manifest_key: &'a str,
    manifest: &'a [u8],
    blob_key: &'a str,
    blob: &'a [u8],
    completion_key: &'a str,
    completion_digest: &'a str,
    mutable_authorities: &'a [HostedMutableAuthority],
}

async fn verify_publish_target_state(
    storage: &Storage,
    verification: &HostedPublishVerification<'_>,
) -> Result<(), StorageError> {
    let (stored_manifest, stored_blob, stored_completion, mutable) = tokio::join!(
        storage.get(verification.manifest_key),
        storage.get(verification.blob_key),
        storage.get(verification.completion_key),
        verify_hosted_mutable_target(storage, verification.mutable_authorities),
    );
    if stored_manifest?.as_ref() != verification.manifest
        || stored_blob?.as_ref() != verification.blob
        || stored_completion?.as_ref() != verification.completion_digest.as_bytes()
    {
        return Err(StorageError::AlreadyExists);
    }
    mutable
}

async fn replace_import_mutable_state(
    state: &AppState,
    repository: &str,
    package: &str,
    desired: &ValidatedHostedImport,
    base_packument: Option<&serde_json::Value>,
) -> Result<(), StorageError> {
    let base = hosted_mutable_state_from_packument(base_packument)?;
    let target = hosted_mutable_state_from_import(desired)?;
    let authorities = hosted_mutable_authorities(repository, package, &base, &target);
    converge_hosted_mutable_target(&state.storage, &authorities).await
}

fn import_receipt_response(receipt: HostedImportReceipt, status: StatusCode) -> Response {
    let mut response = axum::Json(receipt).into_response();
    *response.status_mut() = status;
    response
}

async fn named_import_finalize(
    State(state): State<AppState>,
    Path((repository, encoded_package)): Path<(String, String)>,
    headers: HeaderMap,
    Extension(authority): Extension<NamespaceAuthority>,
    body: Bytes,
) -> Response {
    let Some(package) = decode_package_name(&encoded_package) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if enforce_namespace_scope(&authority, &package).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(NpmRepository::Hosted { write_policy, .. }) = state.config.npm.repository(&repository)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "npm import finalize must target a named hosted repository",
        )
            .into_response();
    };
    if *write_policy == NpmWritePolicy::Deny {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let expected = match import_packument_sha256(&headers) {
        Ok(Some(expected)) => expected,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                "npm import finalize requires a packument SHA-256",
            )
                .into_response()
        }
        Err(error) => return error.into_response(),
    };
    if hex::encode(sha2::Sha256::digest(&body)) != expected {
        return (
            StatusCode::CONFLICT,
            "npm import packument body does not match its SHA-256 header",
        )
            .into_response();
    }
    let packument = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(packument) => packument,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid JSON").into_response(),
    };
    let desired = match validate_hosted_import(&package, &packument) {
        Ok(desired) => desired,
        Err(error) => return error.into_response(),
    };

    let lock = state.publish_lock(&format!("npm:{repository}:{package}"));
    let _guard = lock.lock().await;
    match resume_hosted_maintenance_operation(&state.storage, &repository, &package).await {
        Ok(true) => state.repo_index.invalidate("npm"),
        Ok(false) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    let receipt_key =
        crate::npm_layout::hosted_import_receipt_key(&repository, &package, &expected);
    let marker_key = crate::npm_layout::hosted_import_pending_key(&repository, &package);
    let session = match read_optional_import_session(&state.storage, &repository, &package).await {
        Ok(Some(session)) if session.packument_sha256 == expected => Some(session),
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                "Package bulk import is bound to a different packument",
            )
                .into_response()
        }
        Ok(None) => None,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let receipt = match state.storage.get(&receipt_key).await {
        Ok(receipt) => Some(receipt),
        Err(StorageError::NotFound) => None,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if let Some(receipt) = receipt {
        let receipt: HostedImportReceipt = match serde_json::from_slice(&receipt) {
            Ok(receipt) => receipt,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        if receipt.package != package
            || receipt.full_sha256 != expected
            || receipt.generation != expected
            || receipt.version_count != desired.versions.len()
            || !valid_sha256(&receipt.install_v1_sha256)
        {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        let generation = WrittenPackumentGeneration {
            generation: receipt.generation.clone(),
            full_sha256: receipt.full_sha256.clone(),
            install_v1_sha256: receipt.install_v1_sha256.clone(),
        };
        if validate_hosted_packument_pointer(&state.storage, &repository, &package, &generation)
            .await
            .is_err()
        {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        let Some(session) = session.as_ref() else {
            // A fully completed receipt is immutable history, not a request to
            // restore its generation. Later versions, tags, deprecations and
            // pointer generations are deliberately ignored on replay.
            return import_receipt_response(receipt, StatusCode::OK);
        };
        if let Err(error) = validate_import_version_state(
            &state,
            &repository,
            &package,
            &expected,
            &desired,
            session,
        )
        .await
        {
            return match error {
                StorageError::AlreadyExists => (
                    StatusCode::CONFLICT,
                    "Imported npm version state no longer matches the completed receipt",
                )
                    .into_response(),
                _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
        }
        let base_packument = match &session.base {
            Some(base) => {
                match hosted_packument_for_pointer(&state.storage, &repository, &package, base)
                    .await
                {
                    Ok(packument) => Some(packument),
                    Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            }
            None => None,
        };
        if replace_import_mutable_state(
            &state,
            &repository,
            &package,
            &desired,
            base_packument.as_ref(),
        )
        .await
        .is_err()
        {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        match read_hosted_packument_pointer(&state.storage, &repository, &package).await {
            Ok(current) if current.as_ref() == session.base.as_ref() => {
                if commit_hosted_packument_pointer(
                    &state.storage,
                    &repository,
                    &package,
                    &generation,
                )
                .await
                .is_err()
                {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
            Ok(Some(current)) if current == generation => {}
            Ok(_) => {
                return (
                    StatusCode::CONFLICT,
                    "Completed npm import cannot replace a later package generation",
                )
                    .into_response()
            }
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
        let session_bytes = match serde_json::to_vec(session) {
            Ok(bytes) => bytes,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        if delete_exact_with_readback(&state.storage, &marker_key, &session_bytes)
            .await
            .is_err()
        {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        return import_receipt_response(receipt, StatusCode::OK);
    }

    // Fresh-install imports must have an exact journal written by version PUTs;
    // adopting unjournaled pre-existing objects would make omitted LIST keys
    // indistinguishable from absence.
    let Some(session) = session.as_ref() else {
        return (
            StatusCode::CONFLICT,
            "Package bulk import has no exact version journal",
        )
            .into_response();
    };
    match incomplete_publish_versions(&state, &repository, &package).await {
        Ok(incomplete) if !incomplete.is_empty() => return incomplete_publish_response(),
        Ok(_) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    if let Err(error) =
        validate_import_version_state(&state, &repository, &package, &expected, &desired, session)
            .await
    {
        return match error {
            StorageError::AlreadyExists => (
                StatusCode::CONFLICT,
                "Imported npm version set or metadata does not match committed hosted state",
            )
                .into_response(),
            _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
    }
    match read_hosted_packument_pointer(&state.storage, &repository, &package).await {
        Ok(current) if current.as_ref() == session.base.as_ref() => {}
        Ok(_) => {
            return (
                StatusCode::CONFLICT,
                "Package generation changed after bulk import started",
            )
                .into_response()
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    let base_packument = match &session.base {
        Some(base) => {
            match hosted_packument_for_pointer(&state.storage, &repository, &package, base).await {
                Ok(packument) => Some(packument),
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
        None => None,
    };
    if replace_import_mutable_state(
        &state,
        &repository,
        &package,
        &desired,
        base_packument.as_ref(),
    )
    .await
    .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let generation = match write_hosted_packument_generation_documents(
        &state.storage,
        &repository,
        &package,
        &packument,
        &body,
    )
    .await
    {
        Ok(generation) if generation.full_sha256 == expected => generation,
        Ok(_) => return StatusCode::CONFLICT.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let receipt = HostedImportReceipt {
        package: package.clone(),
        version_count: desired.versions.len(),
        full_sha256: generation.full_sha256.clone(),
        install_v1_sha256: generation.install_v1_sha256.clone(),
        generation: generation.generation.clone(),
    };
    let receipt_bytes = match serde_json::to_vec(&receipt) {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if put_immutable_storage(&state.storage, &receipt_key, &receipt_bytes)
        .await
        .is_err()
        || commit_hosted_packument_pointer(&state.storage, &repository, &package, &generation)
            .await
            .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let session_bytes = match serde_json::to_vec(session) {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if delete_exact_with_readback(&state.storage, &marker_key, &session_bytes)
        .await
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    state.repo_index.invalidate("npm");
    import_receipt_response(receipt, StatusCode::CREATED)
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
    match resume_hosted_maintenance_operation(&state.storage, repository, package).await {
        Ok(true) => state.repo_index.invalidate("npm"),
        Ok(false) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    match state
        .storage
        .get(&crate::npm_layout::hosted_import_pending_key(
            repository, package,
        ))
        .await
    {
        Ok(_) => {
            return (
                StatusCode::CONFLICT,
                "Package has an active bulk import; finalize it before normal mutation",
            )
                .into_response()
        }
        Err(StorageError::NotFound) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    match incomplete_publish_versions(state, repository, package).await {
        Ok(incomplete) if !incomplete.is_empty() => return incomplete_publish_response(),
        Ok(_) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    for attempt in 0..2 {
        let base = match read_hosted_packument_pointer(&state.storage, repository, package).await {
            Ok(Some(pointer)) => pointer,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        let base_packument =
            match hosted_packument_for_pointer(&state.storage, repository, package, &base).await {
                Ok(packument) => packument,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
        let Some(committed_versions) = base_packument
            .get("versions")
            .and_then(serde_json::Value::as_object)
        else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        let mut matched = 0usize;
        let mut changes = std::collections::BTreeMap::new();
        for (version, data) in versions {
            let Some(manifest) = committed_versions
                .get(version)
                .and_then(serde_json::Value::as_object)
            else {
                continue;
            };
            let Some(message) = data.get("deprecated").and_then(serde_json::Value::as_str) else {
                continue;
            };
            matched += 1;
            let current = match manifest.get("deprecated") {
                Some(value) => match value.as_str() {
                    Some(value) => Some(value.to_string()),
                    None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                },
                None => None,
            };
            let desired = (!message.is_empty()).then(|| message.to_string());
            let key = hosted_deprecation_key(repository, package, version);
            match read_optional_string(&state.storage, &key).await {
                Ok(authoritative) if authoritative == current => {}
                _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
            if current != desired {
                changes.insert(version.clone(), desired);
            }
        }
        if matched == 0 {
            return StatusCode::NOT_FOUND.into_response();
        }
        if changes.is_empty() {
            return StatusCode::CREATED.into_response();
        }
        let action = HostedMaintenanceAction::Deprecations { values: changes };
        let target_packument = match apply_hosted_maintenance_action(base_packument, &action) {
            Ok(packument) => packument,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        match execute_hosted_metadata_maintenance(
            &state.storage,
            repository,
            package,
            base,
            &target_packument,
            action,
        )
        .await
        {
            Ok(()) => {
                state.repo_index.invalidate("npm");
                return StatusCode::CREATED.into_response();
            }
            Err(StorageError::AlreadyExists) if attempt == 0 => continue,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

async fn handle_put<F>(
    state: AppState,
    target: RepositoryTarget,
    path: String,
    headers: HeaderMap,
    body: Bytes,
    authorize: F,
) -> Response
where
    F: FnOnce(&str) -> bool,
{
    let Some(package) = decode_package_name(&path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !authorize(&package) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let import_hash = match import_packument_sha256(&headers) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if import_hash.is_some()
        && !matches!(
            target,
            RepositoryTarget::Named(NpmRepository::Hosted { .. })
        )
    {
        return (
            StatusCode::BAD_REQUEST,
            "Bulk import version PUT must target a named hosted npm repository",
        )
            .into_response();
    }
    let hosted = if import_hash.is_some() {
        match &target {
            RepositoryTarget::Named(NpmRepository::Hosted { name, write_policy })
                if *write_policy != NpmWritePolicy::Deny =>
            {
                // Bulk import is exact-only. Repository `allow` must not turn
                // a delayed or conflicting import PUT into a redeploy.
                WritableHosted {
                    name: name.clone(),
                    write_policy: NpmWritePolicy::AllowOnce,
                }
            }
            RepositoryTarget::Named(NpmRepository::Hosted { .. }) => {
                return StatusCode::METHOD_NOT_ALLOWED.into_response()
            }
            _ => unreachable!("import target shape was validated above"),
        }
    } else {
        match writable_hosted(&state, &target, true) {
            Ok(hosted) => hosted,
            Err(error) => return error.into_response(),
        }
    };
    let payload = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(value) => value,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid JSON").into_response(),
    };
    if payload.get("_attachments").is_some() {
        publish_with_import(
            &state,
            &hosted.name,
            hosted.write_policy,
            &package,
            &payload,
            import_hash.as_deref(),
        )
        .await
    } else if import_hash.is_some() {
        (
            StatusCode::BAD_REQUEST,
            "npm import hash is valid only for a version publish PUT",
        )
            .into_response()
    } else {
        deprecate(&state, &hosted.name, &package, &payload).await
    }
}

pub(crate) async fn named_put_request<F>(
    state: AppState,
    repository: String,
    path: String,
    headers: HeaderMap,
    body: Bytes,
    authorize: F,
) -> Response
where
    F: FnOnce(&str) -> bool,
{
    let Some(target) = named_target(&state, &repository) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    handle_put(state, target, path, headers, body, authorize).await
}

async fn alias_put(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    Extension(authority): Extension<NamespaceAuthority>,
    body: Bytes,
) -> Response {
    let Some(target) = alias_target(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let authorize = move |package: &str| enforce_namespace_scope(&authority, package).is_ok();
    handle_put(state, target, path, headers, body, authorize).await
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
    match target_packument(
        &state,
        &target,
        &package,
        &response_base,
        PackumentFlavor::Full,
    )
    .await
    {
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
    let lock = state.publish_lock(&format!("npm:{repository}:{package}"));
    let _guard = lock.lock().await;
    match resume_hosted_maintenance_operation(&state.storage, &repository, &package).await {
        Ok(true) => state.repo_index.invalidate("npm"),
        Ok(false) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    match hosted_import_active(&state.storage, &repository, &package).await {
        Ok(true) => {
            return (
                StatusCode::CONFLICT,
                "Package has an active bulk import; finalize it before normal mutation",
            )
                .into_response()
        }
        Ok(false) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    match incomplete_publish_versions(&state, &repository, &package).await {
        Ok(incomplete) if !incomplete.is_empty() => return incomplete_publish_response(),
        Ok(_) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    for attempt in 0..2 {
        let base = match read_hosted_packument_pointer(&state.storage, &repository, &package).await
        {
            Ok(Some(pointer)) => pointer,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        let base_packument = match hosted_packument_for_pointer(
            &state.storage,
            &repository,
            &package,
            &base,
        )
        .await
        {
            Ok(packument) => packument,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        if !base_packument
            .get("versions")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|versions| versions.contains_key(&version))
        {
            return StatusCode::NOT_FOUND.into_response();
        }
        let current = match base_packument
            .get("dist-tags")
            .and_then(serde_json::Value::as_object)
            .and_then(|tags| tags.get(&tag))
        {
            Some(value) => match value.as_str() {
                Some(value) => Some(value.to_string()),
                None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            },
            None => None,
        };
        let tag_key = hosted_tag_key(&repository, &package, &tag);
        match read_optional_string(&state.storage, &tag_key).await {
            Ok(authoritative) if authoritative == current => {}
            _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
        if current.as_deref() == Some(version.as_str()) {
            return StatusCode::CREATED.into_response();
        }
        let action = HostedMaintenanceAction::DistTag {
            tag: tag.clone(),
            value: Some(version.clone()),
        };
        let target_packument = match apply_hosted_maintenance_action(base_packument, &action) {
            Ok(packument) => packument,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        match execute_hosted_metadata_maintenance(
            &state.storage,
            &repository,
            &package,
            base,
            &target_packument,
            action,
        )
        .await
        {
            Ok(()) => {
                state.repo_index.invalidate("npm");
                return StatusCode::CREATED.into_response();
            }
            Err(StorageError::AlreadyExists) if attempt == 0 => continue,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
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
    match resume_hosted_maintenance_operation(&state.storage, &repository, &package).await {
        Ok(true) => state.repo_index.invalidate("npm"),
        Ok(false) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    match hosted_import_active(&state.storage, &repository, &package).await {
        Ok(true) => {
            return (
                StatusCode::CONFLICT,
                "Package has an active bulk import; finalize it before normal mutation",
            )
                .into_response()
        }
        Ok(false) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    match incomplete_publish_versions(&state, &repository, &package).await {
        Ok(incomplete) if !incomplete.is_empty() => return incomplete_publish_response(),
        Ok(_) => {}
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    for attempt in 0..2 {
        let base = match read_hosted_packument_pointer(&state.storage, &repository, &package).await
        {
            Ok(Some(pointer)) => pointer,
            Ok(None) => return StatusCode::NO_CONTENT.into_response(),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        let base_packument = match hosted_packument_for_pointer(
            &state.storage,
            &repository,
            &package,
            &base,
        )
        .await
        {
            Ok(packument) => packument,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        let current = match base_packument
            .get("dist-tags")
            .and_then(serde_json::Value::as_object)
            .and_then(|tags| tags.get(&tag))
        {
            Some(value) => match value.as_str() {
                Some(value) => Some(value.to_string()),
                None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            },
            None => None,
        };
        let key = hosted_tag_key(&repository, &package, &tag);
        match read_optional_string(&state.storage, &key).await {
            Ok(authoritative) if authoritative == current => {}
            _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
        if current.is_none() {
            return StatusCode::NO_CONTENT.into_response();
        }
        let action = HostedMaintenanceAction::DistTag {
            tag: tag.clone(),
            value: None,
        };
        let target_packument = match apply_hosted_maintenance_action(base_packument, &action) {
            Ok(packument) => packument,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        match execute_hosted_metadata_maintenance(
            &state.storage,
            &repository,
            &package,
            base,
            &target_packument,
            action,
        )
        .await
        {
            Ok(()) => {
                state.repo_index.invalidate("npm");
                return StatusCode::NO_CONTENT.into_response();
            }
            Err(StorageError::AlreadyExists) if attempt == 0 => continue,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
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

    #[tokio::test]
    async fn maintenance_marker_and_pointer_ambiguous_results_use_exact_readback() {
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
        let base = read_hosted_packument_pointer(&ctx.state.storage, "npm-private", "pkg")
            .await
            .unwrap()
            .unwrap();
        let base_packument =
            hosted_packument_for_pointer(&ctx.state.storage, "npm-private", "pkg", &base)
                .await
                .unwrap();
        let action = HostedMaintenanceAction::DistTag {
            tag: "next".to_string(),
            value: Some("1.0.0".to_string()),
        };
        let target_packument = apply_hosted_maintenance_action(base_packument, &action).unwrap();
        let full = serde_json::to_vec(&target_packument).unwrap();
        let target = write_hosted_packument_generation_documents(
            &ctx.state.storage,
            "npm-private",
            "pkg",
            &target_packument,
            &full,
        )
        .await
        .unwrap();
        let operation = HostedMaintenanceOperation {
            schema: crate::npm_layout::HOSTED_MAINTENANCE_SCHEMA_V1,
            repository: "npm-private".to_string(),
            package: "pkg".to_string(),
            base,
            target: HostedMaintenanceTarget::Live {
                pointer: target.clone(),
            },
            action,
        };
        let marker_key = crate::npm_layout::hosted_maintenance_active_key("npm-private", "pkg");

        let create_backend =
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_create_after(&marker_key);
        let create_storage = Storage::from_backend(Arc::new(create_backend));
        let marker = create_hosted_maintenance_marker(&create_storage, &operation)
            .await
            .expect("post-commit create error is resolved by exact readback");

        let delete_backend =
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_delete_after(&marker_key);
        let delete_storage = Storage::from_backend(Arc::new(delete_backend));
        clear_hosted_maintenance_marker(&delete_storage, &marker)
            .await
            .expect("post-commit delete error is resolved by NotFound readback");
        assert!(ctx.state.storage.stat(&marker_key).await.is_none());

        let create_backend =
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_create(&marker_key);
        let create_storage = Storage::from_backend(Arc::new(create_backend));
        assert!(
            create_hosted_maintenance_marker(&create_storage, &operation)
                .await
                .is_err()
        );
        assert!(ctx.state.storage.stat(&marker_key).await.is_none());

        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let pointer_backend =
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_put_after(&pointer_key);
        let pointer_storage = Storage::from_backend(Arc::new(pointer_backend));
        commit_hosted_packument_pointer(&pointer_storage, "npm-private", "pkg", &target)
            .await
            .expect("post-commit pointer error is resolved by exact readback");
        assert_eq!(
            read_hosted_packument_pointer(&ctx.state.storage, "npm-private", "pkg")
                .await
                .unwrap(),
            Some(target)
        );
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

    fn import_fixture(
        package: &str,
        version: &str,
        tag: &str,
        marker: &str,
    ) -> (serde_json::Value, Vec<u8>, String) {
        let payload: serde_json::Value =
            serde_json::from_slice(&publish_payload_with_tarball(package, version, tag, marker))
                .unwrap();
        let validated = validate_publish(package, &payload).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&validated.manifest).unwrap();
        let body = serde_json::to_vec(&serde_json::json!({
            "name": package,
            "versions": {(version): manifest},
            "dist-tags": {(tag): version},
        }))
        .unwrap();
        let sha256 = hex::encode(sha2::Sha256::digest(&body));
        (payload, body, sha256)
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

    #[test]
    fn install_v1_accept_requires_a_positive_quality() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(
                "application/vnd.npm.install-v1+json;q=0, application/json;q=1",
            ),
        );
        assert_eq!(
            PackumentFlavor::from_headers(&headers),
            PackumentFlavor::Full
        );
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(
                "application/vnd.npm.install-v1+json;q=1, application/json;q=0.8, */*",
            ),
        );
        assert_eq!(
            PackumentFlavor::from_headers(&headers),
            PackumentFlavor::InstallV1
        );
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(
                "application/vnd.npm.install-v1+json;q=0.9, application/json;q=0.8, */*",
            ),
        );
        assert_eq!(
            PackumentFlavor::from_headers(&headers),
            PackumentFlavor::InstallV1
        );
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/vnd.npm.install-v1+json;q=0, */*;q=1"),
        );
        assert_eq!(
            PackumentFlavor::from_headers(&headers),
            PackumentFlavor::Full
        );
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(
                "application/vnd.npm.install-v1+json;q=1, application/json;q=1",
            ),
        );
        assert_eq!(
            PackumentFlavor::from_headers(&headers),
            PackumentFlavor::InstallV1
        );
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/vnd.npm.install-v1+json; q=0.5"),
        );
        assert_eq!(
            PackumentFlavor::from_headers(&headers),
            PackumentFlavor::InstallV1
        );
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(
                "application/json;q=1, application/vnd.npm.install-v1+json;q=0.9",
            ),
        );
        assert_eq!(
            PackumentFlavor::from_headers(&headers),
            PackumentFlavor::Full
        );
    }

    #[tokio::test]
    async fn bulk_import_withholds_until_finalize_and_serves_both_packuments() {
        use crate::test_helpers::{
            body_bytes, create_test_context_with_config, send, send_with_headers,
        };
        use axum::http::Method;

        let ctx = create_test_context_with_config(named_config);
        let (payload, full, sha256) = import_fixture("pkg", "1.0.0", "latest", "");
        let response = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/repository/npm-private/pkg",
            vec![(NPM_IMPORT_PACKUMENT_HEADER, sha256.as_str())],
            serde_json::to_vec(&payload).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(ctx
            .state
            .storage
            .stat(&crate::npm_layout::hosted_packument_current_key(
                "npm-private",
                "pkg"
            ))
            .await
            .is_none());
        let hidden = send(&ctx.app, Method::GET, "/repository/npm-private/pkg", "").await;
        assert_eq!(hidden.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(hidden.headers().get(header::RETRY_AFTER).unwrap(), "1");

        let finalized = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/repository/npm-private/-/nora/import/pkg",
            vec![(NPM_IMPORT_PACKUMENT_HEADER, sha256.as_str())],
            full.clone(),
        )
        .await;
        assert_eq!(finalized.status(), StatusCode::CREATED);
        let receipt: serde_json::Value =
            serde_json::from_slice(&body_bytes(finalized).await).unwrap();
        assert_eq!(receipt.as_object().unwrap().len(), 5);
        assert_eq!(receipt["generation"], sha256);

        let full_response = send(&ctx.app, Method::GET, "/repository/npm-private/pkg", "").await;
        assert_eq!(full_response.status(), StatusCode::OK);
        let install = send_with_headers(
            &ctx.app,
            Method::GET,
            "/repository/npm-private/pkg",
            vec![(
                "accept",
                "application/vnd.npm.install-v1+json, application/json;q=0.5",
            )],
            "",
        )
        .await;
        assert_eq!(install.status(), StatusCode::OK);
        assert_eq!(
            install.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/vnd.npm.install-v1+json"
        );
        assert_eq!(install.headers().get(header::VARY).unwrap(), "Accept");
        let etag = install
            .headers()
            .get(header::ETAG)
            .unwrap()
            .to_str()
            .unwrap();
        let not_modified = send_with_headers(
            &ctx.app,
            Method::GET,
            "/repository/npm-private/pkg",
            vec![
                (
                    "accept",
                    "application/vnd.npm.install-v1+json, application/json;q=0.5",
                ),
                ("if-none-match", etag),
            ],
            "",
        )
        .await;
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(not_modified.headers().get(header::VARY).unwrap(), "Accept");

        assert_eq!(
            send_with_headers(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/-/nora/import/pkg",
                vec![(NPM_IMPORT_PACKUMENT_HEADER, sha256.as_str())],
                full.clone(),
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/-/package/pkg/dist-tags/next",
                serde_json::to_vec("1.0.0").unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send_with_headers(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/-/nora/import/pkg",
                vec![(NPM_IMPORT_PACKUMENT_HEADER, sha256.as_str())],
                full,
            )
            .await
            .status(),
            StatusCode::OK
        );
        let after_replay = send(&ctx.app, Method::GET, "/repository/npm-private/pkg", "").await;
        assert_eq!(after_replay.status(), StatusCode::OK);
        let after_replay: serde_json::Value =
            serde_json::from_slice(&body_bytes(after_replay).await).unwrap();
        assert_eq!(after_replay["dist-tags"]["next"], "1.0.0");
    }

    #[tokio::test]
    async fn deferred_version_evidence_is_last_and_get_is_two_reads_without_list() {
        use crate::test_helpers::{create_test_context_with_config, FaultInjectBackend};
        use axum::http::HeaderName;
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
        let (payload, full, sha256) = import_fixture("pkg", "1.0.0", "latest", "");
        let backend = FaultInjectBackend::new(ctx.state.storage.clone());
        let writes = backend.write_attempts();
        let mut state = ctx.state.clone();
        state.storage = crate::storage::Storage::from_backend(Arc::new(backend));
        assert_eq!(
            publish_with_import(
                &state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &payload,
                Some(&sha256),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let writes = writes.lock().clone();
        let evidence = writes
            .iter()
            .position(|entry| entry.contains("/import/generations/"))
            .unwrap();
        for needle in [
            "/blobs/sha512/",
            "/versions/1.0.0.json",
            "/publish-complete/1.0.0",
        ] {
            assert!(
                writes
                    .iter()
                    .position(|entry| entry.contains(needle))
                    .unwrap()
                    < evidence
            );
        }
        assert!(
            writes
                .iter()
                .all(|entry| !entry.contains("/hosted-packuments/")),
            "deferred version PUT must not build any package generation"
        );
        assert!(state
            .storage
            .stat(&crate::npm_layout::hosted_packument_current_key(
                "npm-private",
                "pkg"
            ))
            .await
            .is_none());

        let response = named_import_finalize(
            State(state.clone()),
            Path(("npm-private".to_string(), "pkg".to_string())),
            HeaderMap::from_iter([(
                HeaderName::from_static(NPM_IMPORT_PACKUMENT_HEADER),
                HeaderValue::from_str(&sha256).unwrap(),
            )]),
            Extension(NamespaceAuthority::Unrestricted),
            Bytes::from(full),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let backend = FaultInjectBackend::new(state.storage.clone());
        let gets = backend.get_attempts();
        let lists = backend.list_attempts();
        let mut read_state = state;
        read_state.storage = crate::storage::Storage::from_backend(Arc::new(backend));
        hosted_packument(
            &read_state,
            "npm-private",
            "pkg",
            "https://nora.example/repository/npm-private",
            PackumentFlavor::Full,
        )
        .await
        .unwrap();
        assert_eq!(gets.lock().len(), 2);
        assert!(lists.lock().is_empty());
    }

    #[tokio::test]
    async fn import_finalize_rejects_omitted_roster_entries_without_list() {
        use crate::test_helpers::{create_test_context_with_config, FaultInjectBackend};
        use axum::http::HeaderName;
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
        let (first, full, sha256) = import_fixture("pkg", "1.0.0", "latest", "");
        let (second, _, _) = import_fixture("pkg", "2.0.0", "latest", "");
        for payload in [&first, &second] {
            assert_eq!(
                publish_with_import(
                    &ctx.state,
                    "npm-private",
                    NpmWritePolicy::AllowOnce,
                    "pkg",
                    payload,
                    Some(&sha256),
                )
                .await
                .status(),
                StatusCode::CREATED
            );
        }

        let second_manifest = validate_publish("pkg", &second).unwrap();
        let second_digest = crate::npm_layout::hosted_manifest_digest(&second_manifest.manifest);
        let omitted_manifest = hosted_version_key("npm-private", "pkg", "2.0.0");
        let omitted_evidence = crate::npm_layout::hosted_import_evidence_key(
            "npm-private",
            "pkg",
            &sha256,
            "2.0.0",
            &second_digest,
        );
        let backend = FaultInjectBackend::new(ctx.state.storage.clone())
            .omit_from_list(omitted_manifest)
            .omit_from_list(omitted_evidence);
        let lists = backend.list_attempts();
        let mut state = ctx.state.clone();
        state.storage = Storage::from_backend(Arc::new(backend));
        let response = named_import_finalize(
            State(state),
            Path(("npm-private".to_string(), "pkg".to_string())),
            HeaderMap::from_iter([(
                HeaderName::from_static(NPM_IMPORT_PACKUMENT_HEADER),
                HeaderValue::from_str(&sha256).unwrap(),
            )]),
            Extension(NamespaceAuthority::Unrestricted),
            Bytes::from(full),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(lists.lock().is_empty());
        assert!(ctx
            .state
            .storage
            .stat(&crate::npm_layout::hosted_import_pending_key(
                "npm-private",
                "pkg"
            ))
            .await
            .is_some());
        assert!(ctx
            .state
            .storage
            .stat(&crate::npm_layout::hosted_packument_current_key(
                "npm-private",
                "pkg"
            ))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn import_finalize_exactly_removes_base_authority_when_list_omits_it() {
        use crate::test_helpers::{
            create_test_context_with_config, send, send_with_headers, FaultInjectBackend,
        };
        use axum::http::{HeaderName, Method};
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
        let (payload, full, sha256) = import_fixture("pkg", "1.0.0", "latest", "");
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                serde_json::to_vec(&payload).unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/-/package/pkg/dist-tags/next",
                serde_json::to_vec("1.0.0").unwrap(),
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
                serde_json::to_vec(&serde_json::json!({
                    "name": "pkg",
                    "versions": {"1.0.0": {"deprecated": "superseded"}}
                }))
                .unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send_with_headers(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                vec![(NPM_IMPORT_PACKUMENT_HEADER, sha256.as_str())],
                serde_json::to_vec(&payload).unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        let stale_tag = hosted_tag_key("npm-private", "pkg", "next");
        let stale_deprecation = hosted_deprecation_key("npm-private", "pkg", "1.0.0");
        let backend = FaultInjectBackend::new(ctx.state.storage.clone())
            .omit_from_list(stale_tag.clone())
            .omit_from_list(stale_deprecation.clone());
        let lists = backend.list_attempts();
        let mut state = ctx.state.clone();
        state.storage = Storage::from_backend(Arc::new(backend));
        let response = named_import_finalize(
            State(state),
            Path(("npm-private".to_string(), "pkg".to_string())),
            HeaderMap::from_iter([(
                HeaderName::from_static(NPM_IMPORT_PACKUMENT_HEADER),
                HeaderValue::from_str(&sha256).unwrap(),
            )]),
            Extension(NamespaceAuthority::Unrestricted),
            Bytes::from(full),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(lists.lock().is_empty());
        assert!(matches!(
            ctx.state.storage.get(&stale_tag).await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            ctx.state.storage.get(&stale_deprecation).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn omitted_publish_intent_blocks_other_publish_and_exact_retry_recovers_without_list() {
        use crate::test_helpers::{create_test_context_with_config, FaultInjectBackend};
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
        let base: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "1.0.0", "latest")).unwrap();
        assert_eq!(
            publish(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &base,
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let second: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "2.0.0", "latest")).unwrap();
        let base_version = hosted_version_key("npm-private", "pkg", "1.0.0");
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let pending_key = hosted_publish_pending_index_key("npm-private", "pkg");
        let failing_backend = FaultInjectBackend::new(ctx.state.storage.clone())
            .omit_from_list(base_version.clone())
            .fail_put(&pointer_key);
        let failing_lists = failing_backend.list_attempts();
        let mut failing = ctx.state.clone();
        failing.storage = Storage::from_backend(Arc::new(failing_backend));
        assert_eq!(
            publish(
                &failing,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &second,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(ctx.state.storage.stat(&pending_key).await.is_some());

        let backend = FaultInjectBackend::new(ctx.state.storage.clone())
            .omit_from_list(base_version)
            .omit_from_list(pending_key.clone());
        let lists = backend.list_attempts();
        let mut retry = ctx.state.clone();
        retry.storage = Storage::from_backend(Arc::new(backend));
        let other: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "3.0.0", "latest")).unwrap();
        assert_eq!(
            publish(
                &retry,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &other,
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            publish(
                &retry,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &second,
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(failing_lists.lock().is_empty());
        assert!(lists.lock().is_empty());
        assert!(ctx.state.storage.stat(&pending_key).await.is_none());
        let current = current_full_for_mutation(&ctx.state, "npm-private", "pkg")
            .await
            .unwrap()
            .unwrap();
        assert!(current["versions"].get("1.0.0").is_some());
        assert!(current["versions"].get("2.0.0").is_some());
    }

    #[tokio::test]
    async fn retention_target_uses_exact_pointer_when_list_omits_authority() {
        use crate::test_helpers::{create_test_context_with_config, FaultInjectBackend};
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
        let payload: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "1.0.0", "latest")).unwrap();
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
        let omitted_version = hosted_version_key("npm-private", "pkg", "1.0.0");
        let backend =
            FaultInjectBackend::new(ctx.state.storage.clone()).omit_from_list(omitted_version);
        let lists = backend.list_attempts();
        let storage = Storage::from_backend(Arc::new(backend));
        let target = prepare_hosted_packument_after_retention(
            &storage,
            "npm-private",
            "pkg",
            &HashSet::new(),
        )
        .await
        .unwrap();
        assert!(matches!(target, HostedMaintenanceTarget::Live { .. }));
        assert!(lists.lock().is_empty());
    }

    #[tokio::test]
    async fn completed_receipt_delayed_put_is_read_only_and_exact_only() {
        use crate::test_helpers::{
            create_test_context_with_config, send, send_with_headers, FaultInjectBackend,
        };
        use axum::http::Method;
        use std::sync::Arc;

        let ctx = create_test_context_with_config(|config| {
            named_config(config);
            let NpmRepository::Hosted { write_policy, .. } = &mut config.npm.repositories[0] else {
                unreachable!()
            };
            *write_policy = NpmWritePolicy::Allow;
        });
        let (first, full, sha256) = import_fixture("pkg", "1.0.0", "latest", "first");
        assert_eq!(
            send_with_headers(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                vec![(NPM_IMPORT_PACKUMENT_HEADER, sha256.as_str())],
                serde_json::to_vec(&first).unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send_with_headers(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/-/nora/import/pkg",
                vec![(NPM_IMPORT_PACKUMENT_HEADER, sha256.as_str())],
                full.clone(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/-/package/pkg/dist-tags/next",
                serde_json::to_vec("1.0.0").unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        let backend = FaultInjectBackend::new(ctx.state.storage.clone());
        let writes = backend.write_attempts();
        let deletes = backend.delete_attempts();
        let mut delayed_state = ctx.state.clone();
        delayed_state.storage = Storage::from_backend(Arc::new(backend));
        assert_eq!(
            publish_with_import(
                &delayed_state,
                "npm-private",
                NpmWritePolicy::Allow,
                "pkg",
                &first,
                Some(&sha256),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(writes.lock().is_empty());
        assert!(deletes.lock().is_empty());

        let (changed, _, _) = import_fixture("pkg", "1.0.0", "latest", "changed");
        assert_eq!(
            publish_with_import(
                &delayed_state,
                "npm-private",
                NpmWritePolicy::Allow,
                "pkg",
                &changed,
                Some(&sha256),
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert!(writes.lock().is_empty());
        assert!(deletes.lock().is_empty());

        assert_eq!(
            send(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                publish_payload("pkg", "2.0.0", "latest"),
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
                serde_json::to_vec(&serde_json::json!({
                    "name": "pkg",
                    "versions": {"1.0.0": {"deprecated": "superseded"}}
                }))
                .unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );

        let replay = named_import_finalize(
            State(delayed_state),
            Path(("npm-private".to_string(), "pkg".to_string())),
            HeaderMap::from_iter([(
                header::HeaderName::from_static(NPM_IMPORT_PACKUMENT_HEADER),
                HeaderValue::from_str(&sha256).unwrap(),
            )]),
            Extension(NamespaceAuthority::Unrestricted),
            Bytes::from(full),
        )
        .await;
        assert_eq!(replay.status(), StatusCode::OK);
        assert!(writes.lock().is_empty());
        assert!(deletes.lock().is_empty());
    }

    #[tokio::test]
    async fn interrupted_finalize_receipt_resumes_only_the_missing_target_pointer() {
        use crate::test_helpers::{create_test_context_with_config, FaultInjectBackend};
        use axum::http::HeaderName;
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
        let (payload, full, sha256) = import_fixture("pkg", "1.0.0", "latest", "");
        assert_eq!(
            publish_with_import(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &payload,
                Some(&sha256),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let headers = || {
            HeaderMap::from_iter([(
                HeaderName::from_static(NPM_IMPORT_PACKUMENT_HEADER),
                HeaderValue::from_str(&sha256).unwrap(),
            )])
        };
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let marker_key = crate::npm_layout::hosted_import_pending_key("npm-private", "pkg");
        let receipt_key =
            crate::npm_layout::hosted_import_receipt_key("npm-private", "pkg", &sha256);
        let mut failing_state = ctx.state.clone();
        failing_state.storage = Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_put(&pointer_key),
        ));
        let failed = named_import_finalize(
            State(failing_state),
            Path(("npm-private".to_string(), "pkg".to_string())),
            headers(),
            Extension(NamespaceAuthority::Unrestricted),
            Bytes::from(full.clone()),
        )
        .await;
        assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(ctx.state.storage.stat(&pointer_key).await.is_none());
        assert!(ctx.state.storage.stat(&marker_key).await.is_some());
        assert!(ctx.state.storage.stat(&receipt_key).await.is_some());

        let resumed = named_import_finalize(
            State(ctx.state.clone()),
            Path(("npm-private".to_string(), "pkg".to_string())),
            headers(),
            Extension(NamespaceAuthority::Unrestricted),
            Bytes::from(full),
        )
        .await;
        assert_eq!(resumed.status(), StatusCode::OK);
        assert!(ctx.state.storage.stat(&pointer_key).await.is_some());
        assert!(ctx.state.storage.stat(&marker_key).await.is_none());
    }

    #[tokio::test]
    async fn import_preflight_rejects_blob_collision_before_any_mutation() {
        use crate::test_helpers::{create_test_context_with_config, FaultInjectBackend};
        use std::sync::Arc;

        let ctx = create_test_context_with_config(|config| {
            named_config(config);
            let NpmRepository::Hosted { write_policy, .. } = &mut config.npm.repositories[0] else {
                unreachable!()
            };
            *write_policy = NpmWritePolicy::Allow;
        });
        let (payload, _, sha256) = import_fixture("pkg", "1.0.0", "latest", "");
        let validated = validate_publish("pkg", &payload).unwrap();
        let blob_key = crate::npm_layout::hosted_blob_key_for_digest(
            "npm-private",
            "pkg",
            &validated.blob_digest,
        );
        ctx.state
            .storage
            .put(&blob_key, b"digest-key collision")
            .await
            .unwrap();

        let backend = FaultInjectBackend::new(ctx.state.storage.clone());
        let writes = backend.write_attempts();
        let deletes = backend.delete_attempts();
        let mut state = ctx.state.clone();
        state.storage = Storage::from_backend(Arc::new(backend));
        assert_eq!(
            publish_with_import(
                &state,
                "npm-private",
                NpmWritePolicy::Allow,
                "pkg",
                &payload,
                Some(&sha256),
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        assert!(writes.lock().is_empty());
        assert!(deletes.lock().is_empty());
        assert!(ctx
            .state
            .storage
            .stat(&crate::npm_layout::hosted_import_pending_key(
                "npm-private",
                "pkg"
            ))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn finalize_rejects_an_unjournaled_prepopulated_package() {
        use crate::test_helpers::{create_test_context_with_config, send, send_with_headers};
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
        let pointer: HostedPackumentPointer = serde_json::from_slice(
            &ctx.state
                .storage
                .get(&crate::npm_layout::hosted_packument_current_key(
                    "npm-private",
                    "pkg",
                ))
                .await
                .unwrap(),
        )
        .unwrap();
        let full = ctx
            .state
            .storage
            .get(&crate::npm_layout::hosted_packument_full_key(
                "npm-private",
                "pkg",
                &pointer.generation,
            ))
            .await
            .unwrap();
        let sha256 = hex::encode(sha2::Sha256::digest(&full));
        assert_eq!(
            send_with_headers(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/-/nora/import/pkg",
                vec![(NPM_IMPORT_PACKUMENT_HEADER, sha256.as_str())],
                full,
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn allow_publish_retry_repairs_a_failed_first_pointer_commit() {
        use crate::test_helpers::{create_test_context_with_config, FaultInjectBackend};
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let mut failing = ctx.state.clone();
        failing.storage = crate::storage::Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_put(&pointer_key),
        ));
        let payload: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "1.0.0", "latest")).unwrap();
        assert_eq!(
            publish(
                &failing,
                "npm-private",
                NpmWritePolicy::Allow,
                "pkg",
                &payload,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(ctx.state.storage.stat(&pointer_key).await.is_none());
        assert_eq!(
            publish(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::Allow,
                "pkg",
                &payload,
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(ctx.state.storage.stat(&pointer_key).await.is_some());
    }

    #[tokio::test]
    async fn additive_publish_pointer_failure_blocks_later_publish_until_exact_retry() {
        use crate::test_helpers::{create_test_context_with_config, FaultInjectBackend};
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
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

        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let second: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "2.0.0", "latest")).unwrap();
        let mut failing = ctx.state.clone();
        failing.storage = crate::storage::Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_put(&pointer_key),
        ));
        assert_eq!(
            publish(
                &failing,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &second,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(ctx
            .state
            .storage
            .stat(&hosted_publish_pending_index_key("npm-private", "pkg"))
            .await
            .is_some());
        let visible = current_full_for_mutation(&ctx.state, "npm-private", "pkg")
            .await
            .unwrap()
            .unwrap();
        assert!(visible["versions"].get("1.0.0").is_some());
        assert!(visible["versions"].get("2.0.0").is_none());

        let third: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "3.0.0", "latest")).unwrap();
        assert_eq!(
            publish(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &third,
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
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
        assert!(ctx
            .state
            .storage
            .stat(&hosted_publish_pending_index_key("npm-private", "pkg"))
            .await
            .is_none());
        assert_eq!(
            publish(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &third,
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let visible = current_full_for_mutation(&ctx.state, "npm-private", "pkg")
            .await
            .unwrap()
            .unwrap();
        for version in ["1.0.0", "2.0.0", "3.0.0"] {
            assert!(visible["versions"].get(version).is_some(), "{version}");
        }
    }

    #[tokio::test]
    async fn import_header_is_rejected_outside_named_hosted_version_publish() {
        use crate::test_helpers::{create_test_context_with_config, send_with_headers};
        use axum::http::Method;

        let ctx = create_test_context_with_config(named_config);
        let (payload, _, sha256) = import_fixture("pkg", "1.0.0", "latest", "");
        let payload = serde_json::to_vec(&payload).unwrap();
        for uri in ["/repository/npm-group/pkg", "/repository/npm-registry/pkg"] {
            assert_eq!(
                send_with_headers(
                    &ctx.app,
                    Method::PUT,
                    uri,
                    vec![(NPM_IMPORT_PACKUMENT_HEADER, sha256.as_str())],
                    payload.clone(),
                )
                .await
                .status(),
                StatusCode::BAD_REQUEST,
                "{uri}"
            );
        }
        assert_eq!(
            send_with_headers(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                vec![(NPM_IMPORT_PACKUMENT_HEADER, sha256.as_str())],
                serde_json::to_vec(&serde_json::json!({
                    "name": "pkg",
                    "versions": {"1.0.0": {"deprecated": "old"}},
                }))
                .unwrap(),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn bulk_import_finalize_supports_scoped_packages() {
        use crate::test_helpers::{create_test_context_with_config, send_with_headers};
        use axum::http::Method;

        let ctx = create_test_context_with_config(named_config);
        let (payload, full, sha256) = import_fixture("@scope/pkg", "1.0.0", "latest", "");
        assert_eq!(
            send_with_headers(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/%40scope%2Fpkg",
                vec![(NPM_IMPORT_PACKUMENT_HEADER, sha256.as_str())],
                serde_json::to_vec(&payload).unwrap(),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send_with_headers(
                &ctx.app,
                Method::PUT,
                "/repository/npm-private/-/nora/import/%40scope%2Fpkg",
                vec![(NPM_IMPORT_PACKUMENT_HEADER, sha256.as_str())],
                full,
            )
            .await
            .status(),
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn publish_through_group_commits_only_hosted_and_exact_retry_repairs() {
        use crate::test_helpers::{create_test_context_with_config, send, FaultInjectBackend};
        use axum::http::Method;
        use std::sync::Arc;
        let ctx = create_test_context_with_config(named_config);
        let body = publish_payload("pkg", "1.0.0", "latest");
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let mut failing = ctx.state.clone();
        failing.storage = Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_put(&pointer_key),
        ));
        assert_eq!(
            publish(
                &failing,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &payload,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
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
    async fn fresh_publish_uses_only_the_exact_pending_intent() {
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

        assert!(list_attempts.lock().is_empty());
        assert!(matches!(
            state
                .storage
                .get(&hosted_publish_pending_index_key("npm-private", "pkg"))
                .await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn completed_pending_marker_blocks_until_the_exact_cleanup_retry() {
        use crate::test_helpers::FaultInjectBackend;
        use std::sync::Arc;

        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let first: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "1.0.0", "latest")).unwrap();
        let pending_key = hosted_publish_pending_index_key("npm-private", "pkg");
        let mut failing = ctx.state.clone();
        failing.storage = Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_delete(&pending_key),
        ));
        assert_eq!(
            publish(
                &failing,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &first,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(ctx.state.storage.stat(&pending_key).await.is_some());

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
            StatusCode::CONFLICT
        );
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
        assert!(matches!(
            ctx.state.storage.get(&pending_key).await,
            Err(StorageError::NotFound)
        ));
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
    }

    #[tokio::test]
    async fn pending_publish_accepts_only_the_exact_manifest_retry() {
        use crate::test_helpers::FaultInjectBackend;
        use std::sync::Arc;

        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let exact: serde_json::Value = serde_json::from_slice(&publish_payload_with_tarball(
            "pkg", "1.0.0", "latest", "exact",
        ))
        .unwrap();
        let pending_key = hosted_publish_pending_index_key("npm-private", "pkg");
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let mut failing = ctx.state.clone();
        failing.storage = Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_put(&pointer_key),
        ));
        assert_eq!(
            publish(
                &failing,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &exact,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let exact_pending = ctx.state.storage.get(&pending_key).await.unwrap();

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
            ctx.state.storage.get(&pending_key).await.unwrap(),
            exact_pending
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
        let pending_key = hosted_publish_pending_index_key("npm-private", "pkg");
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
    async fn import_evidence_commits_before_pending_cleanup_and_exact_retry_cleans_it() {
        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let (payload, _, sha256) = import_fixture("pkg", "1.0.0", "latest", "");
        let pending_key = hosted_publish_pending_index_key("npm-private", "pkg");
        let backend = crate::test_helpers::FaultInjectBackend::new(ctx.state.storage.clone())
            .fail_delete(&pending_key);
        let mut failing_state = ctx.state.clone();
        failing_state.storage = crate::storage::Storage::from_backend(std::sync::Arc::new(backend));

        assert_eq!(
            publish_with_import(
                &failing_state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &payload,
                Some(&sha256),
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(ctx.state.storage.stat(&pending_key).await.is_some());
        assert_eq!(
            publish_with_import(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &payload,
                Some(&sha256),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(ctx.state.storage.stat(&pending_key).await.is_none());
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
    async fn publish_deprecation_markerless_corruption_fails_closed_without_repair() {
        use crate::test_helpers::{
            body_bytes, create_test_context_with_config, send, FaultInjectBackend,
        };
        use axum::http::Method;
        use std::sync::Arc;

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

        // Completion precedes pointer and pending cleanup, so deleting both a
        // completed overlay and completion marker is corruption rather than a
        // reachable crash state. An exact body must not manufacture repairs.
        ctx.state.storage.delete(&deprecation_key).await.unwrap();
        ctx.state.storage.delete(&completion_key).await.unwrap();
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let pointer_before = ctx.state.storage.get(&pointer_key).await.unwrap();
        let pending_key = hosted_publish_pending_index_key("npm-private", "pkg");
        let backend = FaultInjectBackend::new(ctx.state.storage.clone());
        let write_attempts = backend.write_attempts();
        let mut corrupt = ctx.state.clone();
        corrupt.storage = Storage::from_backend(Arc::new(backend));
        assert_eq!(
            publish(
                &corrupt,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &payload,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(write_attempts.lock().is_empty());
        assert!(matches!(
            ctx.state.storage.get(&deprecation_key).await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            ctx.state.storage.get(&completion_key).await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            ctx.state.storage.get(&pending_key).await,
            Err(StorageError::NotFound)
        ));
        assert_eq!(
            ctx.state.storage.get(&pointer_key).await.unwrap(),
            pointer_before
        );
        let response = send(&ctx.app, Method::GET, "/repository/npm-group/pkg", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let packument: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(packument["versions"]["1.0.0"]["deprecated"], "do not use");
    }

    #[tokio::test]
    async fn incomplete_publish_must_be_retried_before_later_mutable_operations() {
        use crate::test_helpers::{create_test_context_with_config, send, FaultInjectBackend};
        use axum::http::Method;
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
        let mut first: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "1.0.0", "next")).unwrap();
        first["description"] = serde_json::Value::String("old description".to_string());
        first["versions"]["1.0.0"]["deprecated"] =
            serde_json::Value::String("old deprecation".to_string());
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let mut failing = ctx.state.clone();
        failing.storage = Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_put(&pointer_key),
        ));
        assert_eq!(
            publish(
                &failing,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &first,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let first = serde_json::to_vec(&first).unwrap();
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
    async fn allow_once_retry_converges_the_exact_recorded_mutable_target() {
        use crate::test_helpers::{create_test_context_with_config, FaultInjectBackend};
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
        let mut first: serde_json::Value = serde_json::from_slice(&publish_payload_with_tarball(
            "pkg", "1.0.0", "latest", "first",
        ))
        .unwrap();
        first["description"] = serde_json::json!("old package");
        first["versions"]["1.0.0"]["deprecated"] = serde_json::json!("old version");
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

        let mut second: serde_json::Value = serde_json::from_slice(&publish_payload_with_tarball(
            "pkg", "2.0.0", "latest", "second",
        ))
        .unwrap();
        second["description"] = serde_json::json!("new package");
        second["versions"]["2.0.0"]["deprecated"] = serde_json::json!("new version");
        let package_key = hosted_package_key("npm-private", "pkg");
        let pending_key = hosted_publish_pending_index_key("npm-private", "pkg");
        let backend = FaultInjectBackend::new(ctx.state.storage.clone()).fail_put(&package_key);
        let interrupted_lists = backend.list_attempts();
        let mut interrupted = ctx.state.clone();
        interrupted.storage = Storage::from_backend(Arc::new(backend));
        assert_eq!(
            publish(
                &interrupted,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &second,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(ctx.state.storage.stat(&pending_key).await.is_some());
        assert!(ctx
            .state
            .storage
            .stat(&hosted_version_key("npm-private", "pkg", "2.0.0"))
            .await
            .is_some());

        let retry_backend = FaultInjectBackend::new(ctx.state.storage.clone())
            .omit_from_list(package_key.clone())
            .omit_from_list(hosted_tag_key("npm-private", "pkg", "latest"))
            .omit_from_list(hosted_deprecation_key("npm-private", "pkg", "2.0.0"));
        let retry_lists = retry_backend.list_attempts();
        let mut retry = ctx.state.clone();
        retry.storage = Storage::from_backend(Arc::new(retry_backend));
        assert_eq!(
            publish(
                &retry,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &second,
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        assert!(interrupted_lists.lock().is_empty());
        assert!(retry_lists.lock().is_empty());
        assert!(ctx.state.storage.stat(&pending_key).await.is_none());
        let package: serde_json::Value =
            serde_json::from_slice(&ctx.state.storage.get(&package_key).await.unwrap()).unwrap();
        assert_eq!(package["description"], "new package");
        assert_eq!(
            ctx.state
                .storage
                .get(&hosted_tag_key("npm-private", "pkg", "latest"))
                .await
                .unwrap()
                .as_ref(),
            b"2.0.0"
        );
        assert_eq!(
            ctx.state
                .storage
                .get(&hosted_deprecation_key("npm-private", "pkg", "2.0.0"))
                .await
                .unwrap()
                .as_ref(),
            b"new version"
        );
        let visible = current_full_for_mutation(&ctx.state, "npm-private", "pkg")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(visible["description"], "new package");
        assert_eq!(visible["dist-tags"]["latest"], "2.0.0");
        assert_eq!(visible["versions"]["1.0.0"]["deprecated"], "old version");
        assert_eq!(visible["versions"]["2.0.0"]["deprecated"], "new version");
    }

    #[tokio::test]
    async fn markerless_fresh_allow_once_manifest_fails_closed() {
        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let payload: serde_json::Value = serde_json::from_slice(&publish_payload_with_tarball(
            "pkg", "1.0.0", "latest", "orphan",
        ))
        .unwrap();
        let validated = validate_publish("pkg", &payload).unwrap();
        let manifest_key = hosted_version_key("npm-private", "pkg", "1.0.0");
        ctx.state
            .storage
            .put(&manifest_key, &validated.manifest)
            .await
            .unwrap();

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
            StatusCode::INTERNAL_SERVER_ERROR
        );
        for key in [
            hosted_publish_pending_index_key("npm-private", "pkg"),
            hosted_publish_complete_key("npm-private", "pkg", "1.0.0"),
            hosted_package_key("npm-private", "pkg"),
            crate::npm_layout::hosted_packument_current_key("npm-private", "pkg"),
        ] {
            assert!(ctx.state.storage.stat(&key).await.is_none(), "{key}");
        }
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
                PackumentFlavor::Full,
            )
            .await,
            Err(ReadError::MaterializationUnavailable)
        ));
    }

    #[tokio::test]
    async fn deprecation_and_dist_tag_delete_are_idempotent_but_not_error_blind() {
        use crate::test_helpers::send;
        use axum::http::Method;

        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
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
        let deprecation = hosted_deprecation_key("npm-private", "pkg", "1.0.0");
        let tag = hosted_tag_key("npm-private", "pkg", "next");
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
        assert_eq!(
            send(
                &clean.app,
                Method::PUT,
                "/repository/npm-private/pkg",
                publish_payload("pkg", "1.0.0", "latest"),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
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
    async fn overlay_pointer_failures_resume_from_immutable_maintenance_marker() {
        use crate::test_helpers::{create_test_context_with_config, FaultInjectBackend};
        use std::sync::Arc;

        let ctx = create_test_context_with_config(named_config);
        let initial: serde_json::Value =
            serde_json::from_slice(&publish_payload("pkg", "1.0.0", "latest")).unwrap();
        assert_eq!(
            publish(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::AllowOnce,
                "pkg",
                &initial,
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let target = || {
            RepositoryTarget::Named(NpmRepository::Hosted {
                name: "npm-private".to_string(),
                write_policy: NpmWritePolicy::AllowOnce,
            })
        };
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let marker_key = crate::npm_layout::hosted_maintenance_active_key("npm-private", "pkg");

        let mut failing_deprecation = ctx.state.clone();
        failing_deprecation.storage = crate::storage::Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_put(&pointer_key),
        ));
        let deprecated = serde_json::json!({
            "name": "pkg",
            "versions": {"1.0.0": {"deprecated": "old"}}
        });
        assert_eq!(
            deprecate(&failing_deprecation, "npm-private", "pkg", &deprecated,)
                .await
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(ctx.state.storage.stat(&pointer_key).await.is_some());
        assert!(ctx.state.storage.stat(&marker_key).await.is_some());
        let still_visible = current_full_for_mutation(&ctx.state, "npm-private", "pkg")
            .await
            .unwrap()
            .unwrap();
        assert!(still_visible["versions"]["1.0.0"]
            .get("deprecated")
            .is_none());
        assert_eq!(
            handle_dist_tag_put(
                ctx.state.clone(),
                target(),
                "pkg".to_string(),
                "next".to_string(),
                NamespaceAuthority::Unrestricted,
                Bytes::from(serde_json::to_vec("1.0.0").unwrap()),
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let visible = current_full_for_mutation(&ctx.state, "npm-private", "pkg")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(visible["versions"]["1.0.0"]["deprecated"], "old");
        assert_eq!(visible["dist-tags"]["next"], "1.0.0");
        assert!(ctx.state.storage.stat(&marker_key).await.is_none());

        let mut failing_tag_put = ctx.state.clone();
        failing_tag_put.storage = crate::storage::Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_put(&pointer_key),
        ));
        assert_eq!(
            handle_dist_tag_put(
                failing_tag_put,
                target(),
                "pkg".to_string(),
                "beta".to_string(),
                NamespaceAuthority::Unrestricted,
                Bytes::from(serde_json::to_vec("1.0.0").unwrap()),
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(ctx.state.storage.stat(&pointer_key).await.is_some());
        assert!(ctx.state.storage.stat(&marker_key).await.is_some());
        let newer = serde_json::json!({
            "name": "pkg",
            "versions": {"1.0.0": {"deprecated": "newer"}}
        });
        assert_eq!(
            deprecate(&ctx.state, "npm-private", "pkg", &newer)
                .await
                .status(),
            StatusCode::CREATED
        );
        let visible = current_full_for_mutation(&ctx.state, "npm-private", "pkg")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(visible["versions"]["1.0.0"]["deprecated"], "newer");
        assert_eq!(visible["dist-tags"]["beta"], "1.0.0");

        let mut failing_tag_delete = ctx.state.clone();
        failing_tag_delete.storage = crate::storage::Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_put(&pointer_key),
        ));
        assert_eq!(
            handle_dist_tag_delete(
                failing_tag_delete,
                target(),
                "pkg".to_string(),
                "next".to_string(),
                NamespaceAuthority::Unrestricted,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(ctx.state.storage.stat(&pointer_key).await.is_some());
        assert!(ctx.state.storage.stat(&marker_key).await.is_some());
        assert_eq!(
            deprecate(&ctx.state, "npm-private", "pkg", &newer)
                .await
                .status(),
            StatusCode::CREATED
        );
        let visible = current_full_for_mutation(&ctx.state, "npm-private", "pkg")
            .await
            .unwrap()
            .unwrap();
        assert!(visible["dist-tags"].get("next").is_none());
        assert_eq!(visible["dist-tags"]["beta"], "1.0.0");
        assert_eq!(visible["versions"]["1.0.0"]["deprecated"], "newer");
        assert!(ctx.state.storage.stat(&marker_key).await.is_none());
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
    async fn hosted_packument_generation_removes_storage_fanout_and_rewrites_per_route() {
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
            PackumentFlavor::Full,
        )
        .await
        .expect("hosted packument");
        assert_eq!(
            hosted["versions"]["1.0.0"]["dist"]["tarball"],
            "https://nora.example/repository/npm-private/pkg/-/pkg-1.0.0.tgz"
        );
        assert!(list_attempts.lock().is_empty());
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let pointer_before = state.storage.get(&pointer_key).await.unwrap();
        let pointer: HostedPackumentPointer = serde_json::from_slice(&pointer_before).unwrap();
        let stored: serde_json::Value = serde_json::from_slice(
            &state
                .storage
                .get(&crate::npm_layout::hosted_packument_full_key(
                    "npm-private",
                    "pkg",
                    &pointer.generation,
                ))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(stored["versions"]["1.0.0"]["dist"].get("tarball").is_none());

        let grouped = hosted_packument(
            &state,
            "npm-private",
            "pkg",
            "https://nora.example/repository/npm-group",
            PackumentFlavor::Full,
        )
        .await
        .expect("group-route hosted packument");
        assert!(list_attempts.lock().is_empty());
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
        assert_ne!(
            state.storage.get(&pointer_key).await.unwrap(),
            pointer_before
        );
        let rebuilt = hosted_packument(
            &state,
            "npm-private",
            "pkg",
            "https://nora.example/repository/npm-private",
            PackumentFlavor::Full,
        )
        .await
        .expect("next hosted generation");
        assert_eq!(rebuilt["versions"].as_object().unwrap().len(), 2);
        assert_eq!(rebuilt["dist-tags"]["next"], "2.0.0");
    }

    #[tokio::test]
    async fn hosted_mutation_fails_closed_when_retired_marker_cannot_be_cleared() {
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
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let pointer_before = ctx.state.storage.get(&pointer_key).await.unwrap();
        let retired_key = crate::npm_layout::hosted_packument_retired_key("npm-private", "pkg");
        ctx.state
            .storage
            .put(&retired_key, crate::npm_layout::HOSTED_PACKUMENT_RETIRED_V1)
            .await
            .unwrap();
        let mut failing_state = ctx.state.clone();
        failing_state.storage = crate::storage::Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_delete(&retired_key),
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
        assert_eq!(
            ctx.state.storage.get(&pointer_key).await.unwrap(),
            pointer_before
        );
        assert!(ctx.state.storage.stat(&retired_key).await.is_some());
    }

    #[tokio::test]
    async fn retired_marker_returns_not_found_only_after_resumable_state_is_gone() {
        let ctx = crate::test_helpers::create_test_context_with_config(named_config);
        let retired_key = crate::npm_layout::hosted_packument_retired_key("npm-private", "pkg");
        let pending_index =
            crate::npm_layout::hosted_publish_pending_index_key("npm-private", "pkg");
        ctx.state
            .storage
            .put(&retired_key, crate::npm_layout::HOSTED_PACKUMENT_RETIRED_V1)
            .await
            .unwrap();
        ctx.state.storage.put(&pending_index, b"1").await.unwrap();
        assert!(matches!(
            hosted_packument(
                &ctx.state,
                "npm-private",
                "pkg",
                "https://nora.example/repository/npm-private",
                PackumentFlavor::Full,
            )
            .await,
            Err(ReadError::MaterializationUnavailable)
        ));
        ctx.state.storage.delete(&pending_index).await.unwrap();
        assert!(matches!(
            hosted_packument(
                &ctx.state,
                "npm-private",
                "pkg",
                "https://nora.example/repository/npm-private",
                PackumentFlavor::Full,
            )
            .await,
            Err(ReadError::NotFound)
        ));
    }

    #[tokio::test]
    async fn hosted_overlays_commit_new_packument_generations() {
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
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let initial_pointer = ctx.state.storage.get(&pointer_key).await.unwrap();

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
        let deprecated_pointer = ctx.state.storage.get(&pointer_key).await.unwrap();
        assert_ne!(deprecated_pointer, initial_pointer);
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
        let tagged_pointer = ctx.state.storage.get(&pointer_key).await.unwrap();
        assert_ne!(tagged_pointer, deprecated_pointer);
        let response = send(&ctx.app, Method::GET, package_uri, "").await;
        let packument: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(packument["dist-tags"]["next"], "1.0.0");

        assert_eq!(
            send(&ctx.app, Method::DELETE, tag_uri, "").await.status(),
            StatusCode::NO_CONTENT
        );
        let untagged_pointer = ctx.state.storage.get(&pointer_key).await.unwrap();
        assert_ne!(untagged_pointer, tagged_pointer);
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
    async fn allow_redeploy_pointer_failure_blocks_later_mutations_until_retry() {
        use crate::test_helpers::{create_test_context_with_config, send, FaultInjectBackend};
        use axum::http::Method;
        use std::sync::Arc;

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
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let mut failing = ctx.state.clone();
        failing.storage = Storage::from_backend(Arc::new(
            FaultInjectBackend::new(ctx.state.storage.clone()).fail_put(&pointer_key),
        ));
        assert_eq!(
            publish(
                &failing,
                "npm-private",
                NpmWritePolicy::Allow,
                "pkg",
                &second_value,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
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
    async fn allow_redeploy_pointer_failure_keeps_tarball_on_the_visible_generation() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;
        use std::sync::Arc;

        let ctx = create_test_context_with_config(|config| {
            named_config(config);
            let NpmRepository::Hosted { write_policy, .. } = &mut config.npm.repositories[0] else {
                unreachable!()
            };
            *write_policy = NpmWritePolicy::Allow;
        });
        let first = publish_payload_with_tarball("pkg", "1.0.0", "latest", "first");
        let first_value: serde_json::Value = serde_json::from_slice(&first).unwrap();
        let first_tarball = base64::engine::general_purpose::STANDARD
            .decode(
                first_value["_attachments"]["pkg-1.0.0.tgz"]["data"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            send(&ctx.app, Method::PUT, "/repository/npm-private/pkg", first,)
                .await
                .status(),
            StatusCode::CREATED
        );

        let second = publish_payload_with_tarball("pkg", "1.0.0", "latest", "second");
        let second_value: serde_json::Value = serde_json::from_slice(&second).unwrap();
        let second_tarball = base64::engine::general_purpose::STANDARD
            .decode(
                second_value["_attachments"]["pkg-1.0.0.tgz"]["data"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        let pointer_key = crate::npm_layout::hosted_packument_current_key("npm-private", "pkg");
        let mut interrupted = ctx.state.clone();
        interrupted.storage = Storage::from_backend(Arc::new(
            crate::test_helpers::FaultInjectBackend::new(ctx.state.storage.clone())
                .fail_put(&pointer_key),
        ));
        assert_eq!(
            publish(
                &interrupted,
                "npm-private",
                NpmWritePolicy::Allow,
                "pkg",
                &second_value,
            )
            .await
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );

        let visible = send(&ctx.app, Method::GET, "/repository/npm-private/pkg", "").await;
        assert_eq!(visible.status(), StatusCode::OK);
        let visible: serde_json::Value =
            serde_json::from_slice(&body_bytes(visible).await).unwrap();
        assert_eq!(
            visible["versions"]["1.0.0"]["dist"]["integrity"],
            format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD
                    .encode(sha2::Sha512::digest(&first_tarball))
            )
        );
        let tarball = send(
            &ctx.app,
            Method::GET,
            "/repository/npm-private/pkg/-/pkg-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(tarball.status(), StatusCode::OK);
        assert_eq!(body_bytes(tarball).await.as_ref(), first_tarball.as_slice());

        assert_eq!(
            publish(
                &ctx.state,
                "npm-private",
                NpmWritePolicy::Allow,
                "pkg",
                &second_value,
            )
            .await
            .status(),
            StatusCode::CREATED
        );
        let visible = send(&ctx.app, Method::GET, "/repository/npm-private/pkg", "").await;
        let visible: serde_json::Value =
            serde_json::from_slice(&body_bytes(visible).await).unwrap();
        assert_eq!(
            visible["versions"]["1.0.0"]["dist"]["integrity"],
            format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD
                    .encode(sha2::Sha512::digest(&second_tarball))
            )
        );
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
    async fn retention_removed_version_is_not_served_from_leftover_split_state() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(named_config);
        for version in ["1.0.0", "2.0.0"] {
            assert_eq!(
                send(
                    &ctx.app,
                    Method::PUT,
                    "/repository/npm-private/pkg",
                    publish_payload_with_tarball("pkg", version, "latest", version),
                )
                .await
                .status(),
                StatusCode::CREATED
            );
        }
        let removed_manifest = hosted_version_key("npm-private", "pkg", "1.0.0");
        let target = prepare_hosted_packument_after_retention(
            &ctx.state.storage,
            "npm-private",
            "pkg",
            &HashSet::from(["1.0.0".to_string()]),
        )
        .await
        .unwrap();
        let HostedMaintenanceTarget::Live { pointer } = target else {
            panic!("one retained version must keep the package live")
        };
        commit_hosted_packument_pointer(&ctx.state.storage, "npm-private", "pkg", &pointer)
            .await
            .unwrap();
        assert!(ctx.state.storage.stat(&removed_manifest).await.is_some());

        for uri in [
            "/repository/npm-private/pkg/-/pkg-1.0.0.tgz",
            "/repository/npm-group/pkg/-/pkg-1.0.0.tgz",
        ] {
            let response = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        }
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
