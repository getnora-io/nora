// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Hugging Face Hub pull-through proxy (#579).
//!
//!   GET       /hf/api/models/{...}                  — metadata: model info, revision, tree
//!                                                     listing, passed through without Xet
//!   HEAD, GET /hf/{repo}/resolve/{rev}/{file}        — one file, streamed through every
//!                                                     redirect the Hub gives, and cached
//! Datasets answer 501: only models are in scope for the first release.
//!
//! Xet is never proxied and never advertised. `huggingface_hub` takes the Xet path only when
//! a response hands it a Xet hash: `X-Xet-Hash` beside `Link rel="xet-auth"` on `resolve`, or
//! `xetHash` on a tree-listing entry it has cached — with that, it skips the HEAD call and
//! asks for a Xet read token, which would send it to the Xet storage around NORA. Metadata
//! therefore loses those keys at any depth, and only listed headers reach the client.
//!
//! Files are cached per repo by the digest the Hub names them by (`X-Linked-Etag`: the sha256
//! of an LFS file, the git blob sha1 of a regular one), so a weight file unchanged across
//! commits is one object. The first hop of every GET still goes upstream — it names the commit
//! and the digest — and the bytes come from the cache when they are there. On the way in they
//! are checked against that digest, with the last chunk held back until it matches.
//!
//! The client's own credentials are never sent upstream: the first release serves public
//! repositories only.
//!
//! Client:
//!   HF_ENDPOINT=http://nora:4000/hf hf download org/model

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::circuit_breaker::BreakerScope;
use crate::curation::RequestVersion;
use crate::registry::{
    circuit_open_response, nora_base_url, proxy_fetch_with_headers, ProxyError, TempFileGuard,
};
use crate::registry_type::RegistryType;
use crate::storage::Storage;
use crate::AppState;
use axum::body::Bytes;
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use futures::{FutureExt, StreamExt};
use nora_registry::verified::{stream_body, verify_while_streaming, VerifiedByteStream};
use serde_json::Value;
use sha2::Digest as _;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

/// `huggingface_hub` reads the reason for a failed request from this header when the
/// response has no body, which is the case for the HEAD it sends first for every file.
const ERROR_MESSAGE_HEADER: HeaderName = HeaderName::from_static("x-error-message");
const REPO_COMMIT_HEADER: HeaderName = HeaderName::from_static("x-repo-commit");
const LINKED_ETAG_HEADER: HeaderName = HeaderName::from_static("x-linked-etag");
const LINKED_SIZE_HEADER: HeaderName = HeaderName::from_static("x-linked-size");
const ERROR_CODE_HEADER: HeaderName = HeaderName::from_static("x-error-code");

const NOT_A_FILE_PATH: &str = "Not a Hugging Face file path NORA forwards.";
const FILE_UPSTREAM_FAILED: &str = "The Hugging Face upstream did not deliver the file.";
const DATASETS_NOT_IMPLEMENTED: &str =
    "Hugging Face datasets are not implemented in this NORA build: only models are in scope.";
const XET_NOT_SERVED: &str = "NORA does not serve Xet; files come over plain HTTP.";
const BAD_PATH: &str = "Not a Hugging Face metadata path NORA forwards.";
const NO_UPSTREAM: &str = "No Hugging Face upstream is configured.";
const NOT_ON_UPSTREAM: &str = "Not found on the Hugging Face upstream, or not a public repository.";
const UPSTREAM_FAILED: &str = "The Hugging Face upstream did not answer.";
const UNREADABLE: &str = "The Hugging Face upstream answered with metadata NORA cannot read.";
const LINK_LEAVES_NORA: &str =
    "The Hugging Face upstream pointed the next page outside itself; NORA does not follow it.";
const LINK_UNREADABLE: &str = "The Hugging Face upstream sent a Link header NORA cannot hand on.";

/// The relations a client follows to page through a listing: the only `Link` entries handed
/// on (`huggingface_hub` follows `next`).
const PAGINATION_RELS: &[&str] = &["next", "prev", "first", "last"];

/// The Xet token routes: `api/{type}s/{repo}/xet-{read|write}-token/{rev}` in
/// `huggingface_hub` (`utils/_xet.py`), and the `xet-auth` link of the live Hub points at
/// `xet-read-token`. Matched whole, after the first segment, so a repo whose id merely starts
/// with `xet-` (`xet-team/...`, `celinah/xet-experiments` on the live Hub) is served.
const XET_TOKEN_ROUTES: &[&str] = &["xet-read-token", "xet-write-token"];

/// The key removed from metadata at any depth. Without it no client takes the Xet path:
/// the shortcut that skips the HEAD call needs the Xet hash beside the LFS block, and
/// `HfFileSystem` reads only the hash. The LFS block stays: it carries the sha256 other
/// consumers verify with.
const XET_BODY_KEY: &str = "xetHash";

const MAX_PATH: usize = 2048;
const MAX_QUERY: usize = 2048;

/// Cached files live under `hf/models/{repo}/blobs/{digest}`.
const CACHE_PREFIX: &str = "hf/models";
/// Fills in progress, under the storage path as docker's proxy temp files are.
const FILL_TEMP_DIR: &str = "tmp/hf-proxy";
/// A temp file untouched this long belongs to a fill that will not finish.
const FILL_TEMP_MAX_AGE: Duration = Duration::from_secs(4 * 60 * 60);
const CACHED_CONTENT_TYPE: &str = "application/octet-stream";

/// How long the canonical id the Hub named for an id is trusted; renames are rare.
const CANONICAL_TTL: Duration = Duration::from_secs(60 * 60);
/// Bound on remembered ids; past it the memory starts over.
const CANONICAL_MAX: usize = 4096;
const CANONICAL_UNKNOWN: &str =
    "NORA could not learn this repository's canonical id from the Hugging Face upstream, which curation needs.";

/// Canonical ids the Hub named, per upstream and id as the client spelled it (lower case),
/// with when they were learned. Held by the application state, one per instance.
#[derive(Default)]
pub struct CanonicalIds(
    tokio::sync::Mutex<std::collections::HashMap<(String, String), (String, std::time::Instant)>>,
);

impl CanonicalIds {
    /// The canonical id learned for `asked`, while it is fresh.
    async fn get(&self, asked: &(String, String)) -> Option<String> {
        let ids = self.0.lock().await;
        ids.get(asked)
            .filter(|(_, learned)| learned.elapsed() < CANONICAL_TTL)
            .map(|(id, _)| id.clone())
    }

    async fn remember(&self, asked: (String, String), id: String) {
        let mut ids = self.0.lock().await;
        if ids.len() >= CANONICAL_MAX {
            ids.clear();
        }
        ids.insert(asked, (id, std::time::Instant::now()));
    }
}

pub fn routes() -> Router<AppState> {
    // `get` answers HEAD as well; anything else is 405.
    Router::new()
        .route("/hf/api/models/{*rest}", get(models_api))
        .route("/hf/{*path}", get(files))
        .route("/hf/api/datasets/{*rest}", get(datasets))
        .route("/hf/datasets/{*rest}", get(datasets))
}

/// `GET /hf/api/models/{...}`: forwarded as the client encoded it, answered without Xet.
async fn models_api(State(state): State<AppState>, uri: Uri) -> Response {
    let Some(upstream) = upstream_base(&state) else {
        return error_response(StatusCode::NOT_FOUND, NO_UPSTREAM);
    };
    let rest = uri
        .path()
        .strip_prefix("/hf/api/models/")
        .unwrap_or_default();
    let url = match models_api_upstream(upstream, rest, uri.query()) {
        Ok(url) => url,
        Err(Refusal::XetRoute) => {
            // NORA never advertises Xet, so a token request means Xet metadata reached the
            // client some other way (a cached listing from the Hub itself, or a leak).
            tracing::warn!(
                registry = "hf",
                path = uri.path(),
                "client asked for a Xet token; refused"
            );
            return error_response(StatusCode::NOT_FOUND, XET_NOT_SERVED);
        }
        Err(Refusal::BadPath) => return error_response(StatusCode::BAD_REQUEST, BAD_PATH),
    };
    let fetched = proxy_fetch_with_headers(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.hf.proxy_timeout),
        None,
        &state.circuit_breaker,
        RegistryType::HuggingFace,
    )
    .await;
    match fetched {
        Ok((headers, body)) => metadata_response(upstream, &nora_hf_base(&state), &headers, &body),
        Err(ProxyError::NotFound) => error_response(StatusCode::NOT_FOUND, NOT_ON_UPSTREAM),
        Err(ProxyError::CircuitOpen(registry)) => circuit_open_response(&registry),
        Err(e) => {
            tracing::warn!(registry = "hf", error = ?e, "metadata request failed upstream");
            error_response(StatusCode::BAD_GATEWAY, UPSTREAM_FAILED)
        }
    }
}

/// Redirects one file request may take: the resolve answer, the resolve cache or the CDN,
/// and slack for a renamed repo.
const MAX_HOPS: usize = 5;

/// `HEAD|GET /hf/{repo}/resolve/{revision}/{file}`. The request goes upstream as the client
/// encoded it, and NORA follows the Hub's redirects itself — a relative 307 to the resolve
/// cache, a 302 to the CDN for an LFS file — so no `Location` reaches the client and the
/// bytes come through NORA. The commit, etag and size come from the hop that carries them
/// (on a 302 to the CDN they ride on the redirect only). Curation holds the repo before
/// anything is fetched and the commit as soon as a hop names it.
///
/// A GET looks for the file in the cache at the first hop that names its digest, after that
/// hop's commit has passed curation and before the next hop is asked; a full GET that misses
/// fills it. A HEAD is answered from the hops and neither reads nor fills the cache.
async fn files(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let rest = uri.path().strip_prefix("/hf/").unwrap_or_default();
    let Some(file) = parse_file_request(rest) else {
        return error_response(StatusCode::NOT_FOUND, NOT_A_FILE_PATH);
    };
    let Some(upstream) = upstream_base(&state) else {
        return error_response(StatusCode::NOT_FOUND, NO_UPSTREAM);
    };
    let repo = percent_encoding::percent_decode_str(file.repo)
        .decode_utf8_lossy()
        .into_owned();
    if let Some(refused) = curation_check(&state, &headers, &repo, RequestVersion::Unspecified) {
        return refused;
    }
    // An alias — a legacy one-segment id, a renamed repo — is answered by the Hub as its
    // canonical repo, so a rule on the canonical id must hold for it too: when curation can
    // refuse by name, both names are checked, on the repo and on the commit.
    let mut names = vec![repo.clone()];
    if state.curation().curation_engine.can_refuse_names() {
        match canonical_id(&state, upstream, file.repo).await {
            Canonical::Id(id) => {
                if !id.eq_ignore_ascii_case(&repo) {
                    if let Some(refused) =
                        curation_check(&state, &headers, &id, RequestVersion::Unspecified)
                    {
                        return refused;
                    }
                    names.push(id);
                }
            }
            Canonical::Refused {
                status,
                code,
                message,
            } => return upstream_refusal(status, code, message),
            Canonical::CircuitOpen(registry) => return circuit_open_response(&registry),
            Canonical::Failed(why) => {
                tracing::warn!(registry = "hf", why, repo = %repo, "canonical repo id unknown; refused for curation");
                return error_response(StatusCode::BAD_GATEWAY, CANONICAL_UNKNOWN);
            }
        }
    }
    let url = format!(
        "{upstream}/{}/resolve/{}/{}",
        file.repo, file.revision, file.file
    );
    let range = headers.get(header::RANGE).cloned();
    let check_commit = |commit: Option<&str>| {
        let version = commit.map_or(RequestVersion::Unrecognised, |c| {
            RequestVersion::Known(c.to_string())
        });
        names
            .iter()
            .find_map(|name| curation_check(&state, &headers, name, version.clone()))
    };
    let cache_repo = (method == Method::GET).then_some(repo.as_str());
    let mut fetched = fetch_file(
        &state,
        &method,
        &url,
        range.clone(),
        &check_commit,
        cache_repo,
    )
    .await;
    if let FileFetch::Cached { meta, key, size } = &fetched {
        if let Some(response) = cached_response(&state, &headers, meta, key, *size).await {
            state.metrics.record_download("hf");
            state.metrics.record_cache_hit("hf");
            state.activity.push(ActivityEntry::new(
                ActionType::CacheHit,
                format!("{repo}/{}", file.file),
                RegistryType::HuggingFace,
                "CACHE",
            ));
            return response;
        }
        // The stored copy cannot be read: fetch the file again, as on a miss; its fill
        // replaces the copy.
        fetched = fetch_file(&state, &method, &url, range.clone(), &check_commit, None).await;
    }
    let stall = Duration::from_secs(state.config.hf.proxy_timeout);
    match fetched {
        FileFetch::File { status, meta, body } => {
            let mut fill = None;
            if method == Method::GET && status.is_success() {
                state.metrics.record_download("hf");
                state.metrics.record_cache_miss("hf");
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{repo}/{}", file.file),
                    RegistryType::HuggingFace,
                    "PROXY",
                ));
                state
                    .audit
                    .log(AuditEntry::new("proxy_fetch", "proxy", "", "hf", ""));
                // A range is part of a file: passed through, never stored.
                if status == StatusCode::OK && range.is_none() {
                    fill = plan_fill(&state, &repo, &meta, body.as_ref()).await;
                }
            }
            file_response(status, &meta, body, stall, fill)
        }
        FileFetch::Refused(response) => response,
        FileFetch::UpstreamRefused {
            status,
            code,
            message,
        } => upstream_refusal(status, code, message),
        FileFetch::CircuitOpen(registry) => circuit_open_response(&registry),
        FileFetch::Failed(why) => {
            tracing::warn!(registry = "hf", why, "file request failed upstream");
            error_response(StatusCode::BAD_GATEWAY, FILE_UPSTREAM_FAILED)
        }
        // A fetch without a cache lookup never answers from the cache; reaching this means
        // the stored copy went unreadable twice in one request.
        FileFetch::Cached { .. } => error_response(StatusCode::BAD_GATEWAY, FILE_UPSTREAM_FAILED),
    }
}

/// A Hub refusal handed on: its status, its error code, and its message (or ours).
fn upstream_refusal(
    status: StatusCode,
    code: Option<HeaderValue>,
    message: Option<HeaderValue>,
) -> Response {
    let mut response = (
        status,
        Json(serde_json::json!({ "error": message.as_ref().and_then(|m| m.to_str().ok()).unwrap_or(NOT_ON_UPSTREAM) })),
    )
        .into_response();
    let h = response.headers_mut();
    if let Some(code) = code {
        h.insert(ERROR_CODE_HEADER, code);
    }
    h.insert(
        ERROR_MESSAGE_HEADER,
        message.unwrap_or(HeaderValue::from_static(NOT_ON_UPSTREAM)),
    );
    response
}

fn curation_check(
    state: &AppState,
    headers: &HeaderMap,
    repo: &str,
    version: RequestVersion,
) -> Option<Response> {
    crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        headers,
        RegistryType::HuggingFace,
        repo,
        version,
        None,
    )
}

/// What the Hub calls a repo id.
enum Canonical {
    Id(String),
    /// The Hub refused the id (4xx): handed on, as a file refusal is.
    Refused {
        status: StatusCode,
        code: Option<HeaderValue>,
        message: Option<HeaderValue>,
    },
    CircuitOpen(String),
    Failed(&'static str),
}

/// The canonical id of `encoded` (the id as the client encoded it), for curation. The Hub
/// answers an alias on `api/models` — a legacy one-segment id, another case, a renamed repo —
/// with a relative redirect to the canonical id, and the canonical id with 200 (measured on
/// the live Hub); a HEAD asks without the model-info body. Only a redirect within the
/// upstream's origin to another `api/models` path is followed. Remembered for
/// [`CANONICAL_TTL`].
async fn canonical_id(state: &AppState, upstream: &str, encoded: &str) -> Canonical {
    let remembered = (upstream.to_string(), encoded.to_ascii_lowercase());
    if let Some(id) = state.hf_canonical_ids.get(&remembered).await {
        return Canonical::Id(id);
    }
    let scope = BreakerScope::from(RegistryType::HuggingFace);
    let key = scope.key();
    let probe = match state.circuit_breaker.check(&key) {
        Ok(probe) => probe,
        Err(ProxyError::CircuitOpen(registry)) => return Canonical::CircuitOpen(registry),
        Err(_) => return Canonical::Failed("breaker"),
    };
    let timeout = Duration::from_secs(state.config.hf.proxy_timeout);
    let Ok(mut url) = reqwest::Url::parse(&format!("{upstream}/api/models/{encoded}")) else {
        state.circuit_breaker.record_alive(&key, probe);
        return Canonical::Failed("bad upstream url");
    };
    let start = origin(&url);
    let mut hops = 0;
    let outcome = loop {
        if hops > MAX_HOPS {
            break Err("too many redirects");
        }
        // CANCEL-SAFETY: a timed-out send drops its own connection and nothing else; no
        // state outlives it.
        let response = match tokio::time::timeout(
            timeout,
            state.http_client_no_redirect.head(url.clone()).send(),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => break Err("upstream unreachable"),
        };
        let status = response.status();
        if status.is_success() {
            let id = url.path().split_once("/api/models/").map(|(_, id)| {
                percent_encoding::percent_decode_str(id)
                    .decode_utf8_lossy()
                    .into_owned()
            });
            break id
                .filter(|id| !id.is_empty())
                .map(Canonical::Id)
                .ok_or("no id in the path");
        }
        if status.is_redirection() {
            let next = response
                .headers()
                .get(header::LOCATION)
                .and_then(|l| l.to_str().ok())
                .and_then(|l| url.join(l).ok())
                .filter(|next| origin(next) == start && next.path().contains("/api/models/"));
            let Some(next) = next else {
                break Err("redirect away from the upstream's api/models");
            };
            url = next;
            hops += 1;
            continue;
        }
        if status.is_client_error() {
            break Ok(Canonical::Refused {
                status,
                code: response.headers().get(&ERROR_CODE_HEADER).cloned(),
                message: response.headers().get(&ERROR_MESSAGE_HEADER).cloned(),
            });
        }
        break Err("upstream error");
    };
    match outcome {
        Ok(Canonical::Refused { .. })
        | Err("too many redirects")
        | Err("redirect away from the upstream's api/models")
        | Err("no id in the path") => state.circuit_breaker.record_alive(&key, probe),
        Ok(_) => state.circuit_breaker.record_success(&key, probe),
        Err(_) => state.circuit_breaker.record_failure(&key, probe),
    }
    if let Ok(Canonical::Id(id)) = &outcome {
        state
            .hf_canonical_ids
            .remember(remembered, id.clone())
            .await;
    }
    outcome.unwrap_or_else(Canonical::Failed)
}

/// What the Hub said about a file across the hops of one request.
#[derive(Debug, Default, PartialEq)]
struct FileMeta {
    commit: Option<HeaderValue>,
    etag: Option<HeaderValue>,
    size: Option<HeaderValue>,
}

/// The first hop that names each field wins: the commit, the linked etag and the linked size
/// are on the resolve answer, and a CDN answer carries none of them. Without a linked etag
/// or size, the final answer's `ETag` and `Content-Length` stand in (a regular file).
fn file_meta(hops: &[HeaderMap], last: Option<&HeaderMap>) -> FileMeta {
    let all = || hops.iter().chain(last);
    let first = |name: &HeaderName| all().find_map(|h| h.get(name).cloned());
    FileMeta {
        commit: first(&REPO_COMMIT_HEADER),
        etag: first(&LINKED_ETAG_HEADER)
            .or_else(|| last.and_then(|h| h.get(header::ETAG).cloned())),
        size: first(&LINKED_SIZE_HEADER)
            .or_else(|| last.and_then(|h| h.get(header::CONTENT_LENGTH).cloned())),
    }
}

/// The outcome of one file request upstream.
enum FileFetch {
    /// The file: its status (200, or 206 for a range), what the hops said, and the body to
    /// stream — `None` for a HEAD, answered from its headers.
    File {
        status: StatusCode,
        meta: FileMeta,
        body: Option<reqwest::Response>,
    },
    /// The cache holds the file a hop named by its digest: what the hops said, its key and its
    /// stored size. The hops after that one were not asked.
    Cached {
        meta: FileMeta,
        key: String,
        size: u64,
    },
    /// Curation refused the commit a hop named, before the bytes were asked for.
    Refused(Response),
    /// The Hub refused (4xx): its status, error code and message are handed on.
    UpstreamRefused {
        status: StatusCode,
        code: Option<HeaderValue>,
        message: Option<HeaderValue>,
    },
    CircuitOpen(String),
    Failed(&'static str),
}

/// Scheme, host and port: a redirect within one origin is the Hub's own, one to another
/// origin leaves it (the CDN).
fn origin(url: &reqwest::Url) -> (String, Option<String>, Option<u16>) {
    (
        url.scheme().to_string(),
        url.host_str().map(str::to_string),
        url.port_or_known_default(),
    )
}

/// Requests `url` and follows its redirects by hand, up to [`MAX_HOPS`]. A GET follows them
/// all; a HEAD stops at a redirect to another origin, as `huggingface_hub` does, and is
/// answered from that hop — a signed CDN link is issued for GET. `check_commit` runs once,
/// on the first hop that names a commit (or, when none does, on the final answer).
///
/// With `cache_repo`, the first hop that names an etag — `X-Linked-Etag` on any hop, or the
/// final answer's `ETag` when none does, the same one [`file_meta`] reports — is looked up in
/// the cache of that repo; a stored copy ends the walk there.
async fn fetch_file<F>(
    state: &AppState,
    method: &Method,
    url: &str,
    range: Option<HeaderValue>,
    check_commit: F,
    cache_repo: Option<&str>,
) -> FileFetch
where
    F: Fn(Option<&str>) -> Option<Response>,
{
    let scope = BreakerScope::from(RegistryType::HuggingFace);
    let key = scope.key();
    let probe = match state.circuit_breaker.check(&key) {
        Ok(probe) => probe,
        Err(ProxyError::CircuitOpen(registry)) => return FileFetch::CircuitOpen(registry),
        Err(_) => return FileFetch::Failed("breaker"),
    };
    let timeout = Duration::from_secs(state.config.hf.proxy_timeout);
    let Ok(mut url) = reqwest::Url::parse(url) else {
        state.circuit_breaker.record_alive(&key, probe);
        return FileFetch::Failed("bad upstream url");
    };
    let mut hops: Vec<HeaderMap> = Vec::new();
    let mut commit_checked = false;
    let mut looked_up = false;
    let outcome = loop {
        if hops.len() > MAX_HOPS {
            break Err("too many redirects");
        }
        let mut request = state
            .http_client_no_redirect
            .request(method.clone(), url.clone())
            .header(header::ACCEPT_ENCODING, "identity");
        if let Some(range) = &range {
            request = request.header(header::RANGE, range.clone());
        }
        // CANCEL-SAFETY: a timed-out send drops its own connection and nothing else; no
        // state outlives it.
        let response = match tokio::time::timeout(timeout, request.send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => break Err("upstream unreachable"),
        };
        if !commit_checked {
            if let Some(commit) = response
                .headers()
                .get(&REPO_COMMIT_HEADER)
                .and_then(|v| v.to_str().ok())
            {
                commit_checked = true;
                if let Some(refused) = check_commit(Some(commit)) {
                    break Ok(FileFetch::Refused(refused));
                }
            }
        }
        let status = response.status();
        if let Some(repo) = cache_repo.filter(|_| !looked_up) {
            let named = response.headers().get(&LINKED_ETAG_HEADER).or_else(|| {
                status
                    .is_success()
                    .then(|| response.headers().get(header::ETAG))
                    .flatten()
            });
            if let Some(named) = named {
                looked_up = true;
                let key = hub_digest(named).and_then(|digest| cache_key(repo, &digest));
                let stored = match &key {
                    Some(key) => state.storage.stat(key).await,
                    None => None,
                };
                if let (Some(key), Some(stored)) = (key, stored) {
                    if !commit_checked {
                        if let Some(refused) = check_commit(None) {
                            break Ok(FileFetch::Refused(refused));
                        }
                    }
                    let meta = if status.is_success() {
                        file_meta(&hops, Some(response.headers()))
                    } else {
                        hops.push(response.headers().clone());
                        file_meta(&hops, None)
                    };
                    break Ok(FileFetch::Cached {
                        meta,
                        key,
                        size: stored.size,
                    });
                }
            }
        }
        if status.is_redirection() {
            let next = response
                .headers()
                .get(header::LOCATION)
                .and_then(|l| l.to_str().ok())
                .and_then(|l| url.join(l).ok());
            let Some(next) = next.filter(|n| matches!(n.scheme(), "http" | "https")) else {
                break Err("redirect without a usable location");
            };
            hops.push(response.headers().clone());
            if *method == Method::HEAD && origin(&next) != origin(&url) {
                if !commit_checked {
                    if let Some(refused) = check_commit(None) {
                        break Ok(FileFetch::Refused(refused));
                    }
                }
                break Ok(FileFetch::File {
                    status: StatusCode::OK,
                    meta: file_meta(&hops, None),
                    body: None,
                });
            }
            url = next;
            continue;
        }
        if status.is_success() {
            if !commit_checked {
                if let Some(refused) = check_commit(None) {
                    break Ok(FileFetch::Refused(refused));
                }
            }
            let meta = file_meta(&hops, Some(response.headers()));
            let body = (*method != Method::HEAD).then_some(response);
            break Ok(FileFetch::File { status, meta, body });
        }
        if status.is_client_error() {
            break Ok(FileFetch::UpstreamRefused {
                status,
                code: response.headers().get(&ERROR_CODE_HEADER).cloned(),
                message: response.headers().get(&ERROR_MESSAGE_HEADER).cloned(),
            });
        }
        break Err("upstream error");
    };
    match outcome {
        Ok(FileFetch::UpstreamRefused { .. })
        | Err("too many redirects")
        | Err("redirect without a usable location") => {
            state.circuit_breaker.record_alive(&key, probe)
        }
        Ok(_) => state.circuit_breaker.record_success(&key, probe),
        Err(_) => state.circuit_breaker.record_failure(&key, probe),
    }
    outcome.unwrap_or_else(FileFetch::Failed)
}

/// The answer to a file request: only listed headers, and the body streamed with a stall
/// limit per read. With a [`Fill`] the body is checked against the digest the Hub named the
/// file by on its way through (and stored when it matches); without one it goes through the
/// open-world sink (`verified.rs`) — a range, or an etag NORA cannot check.
fn file_response(
    status: StatusCode,
    meta: &FileMeta,
    body: Option<reqwest::Response>,
    stall: Duration,
    fill: Option<Fill>,
) -> Response {
    let mut headers = HeaderMap::new();
    if let Some(commit) = &meta.commit {
        headers.insert(REPO_COMMIT_HEADER, commit.clone());
    }
    if let Some(etag) = &meta.etag {
        headers.insert(header::ETAG, etag.clone());
        headers.insert(LINKED_ETAG_HEADER, etag.clone());
    }
    if let Some(size) = &meta.size {
        headers.insert(LINKED_SIZE_HEADER, size.clone());
    }
    let Some(upstream) = body else {
        if let Some(size) = &meta.size {
            headers.insert(header::CONTENT_LENGTH, size.clone());
        }
        return (status, headers, Body::empty()).into_response();
    };
    for name in [
        header::CONTENT_LENGTH,
        header::CONTENT_RANGE,
        header::ACCEPT_RANGES,
        header::CONTENT_TYPE,
    ] {
        if let Some(v) = upstream.headers().get(&name) {
            headers.insert(name, v.clone());
        }
    }
    let chunks = upstream_chunks(upstream, stall);
    let body = match fill {
        Some(fill) => stream_body(fill_stream(chunks, fill)),
        // Open world, and said so: upstream bytes passed through with no digest to check
        // them against.
        None => nora_registry::verified::open_world_stream_body(chunks),
    };
    (status, headers, body).into_response()
}

type Chunks = Pin<Box<dyn futures::Stream<Item = Result<Bytes, std::io::Error>> + Send>>;

/// The upstream body, a stalled read ending it with an error.
fn upstream_chunks(upstream: reqwest::Response, stall: Duration) -> Chunks {
    Box::pin(futures::stream::unfold(
        Some(Box::pin(upstream.bytes_stream())),
        move |chunks| async move {
            let mut chunks = chunks?;
            // CANCEL-SAFETY: a stalled read is dropped and the stream ends with an error; the
            // client sees a short body, which it resumes with a range request.
            match tokio::time::timeout(stall, chunks.next()).await {
                Ok(Some(Ok(chunk))) => Some((Ok(chunk), Some(chunks))),
                Ok(None) => None,
                Ok(Some(Err(e))) => Some((Err(std::io::Error::other(e)), None)),
                Err(_) => Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "upstream stalled",
                    )),
                    None,
                )),
            }
        },
    ))
}

/// The digest the Hub names a file by in its etag (measured on the live Hub: `X-Linked-Etag`
/// on the resolve answer, quoted lower-case hex): the sha256 of an LFS file's bytes, or the git
/// blob sha1 of a regular file's.
#[derive(Debug, Clone, PartialEq)]
enum HubDigest {
    Sha256(String),
    GitBlob(String),
}

impl HubDigest {
    fn hex(&self) -> &str {
        match self {
            Self::Sha256(hex) | Self::GitBlob(hex) => hex,
        }
    }
}

/// A strong etag of 64 hex digits is a sha256, of 40 a git blob sha1; anything else — a weak
/// etag, an unquoted one, another length — names nothing NORA can check.
fn hub_digest(etag: &HeaderValue) -> Option<HubDigest> {
    let hex = etag.to_str().ok()?.strip_prefix('"')?.strip_suffix('"')?;
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let hex = hex.to_ascii_lowercase();
    match hex.len() {
        64 => Some(HubDigest::Sha256(hex)),
        40 => Some(HubDigest::GitBlob(hex)),
        _ => None,
    }
}

/// The storage key of a file: per repo, by its digest, so a file unchanged across commits is
/// one object. The id is compared in lower case, as the Hub routes it; only an id the Hub could
/// serve makes a key — one or two segments of ASCII letters, digits, `-`, `_` and `.`, each
/// starting with a letter or digit, no `..`. The digest is the last segment and `blobs` the one
/// before it, so a one-segment (legacy) id and a two-segment one never share a key.
fn cache_key(repo: &str, digest: &HubDigest) -> Option<String> {
    let segments: Vec<&str> = repo.split('/').collect();
    let id_ok = (1..=2).contains(&segments.len())
        && segments.iter().all(|segment| {
            segment
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric())
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                && !segment.contains("..")
        });
    id_ok.then(|| {
        format!(
            "{CACHE_PREFIX}/{}/blobs/{}",
            repo.to_ascii_lowercase(),
            digest.hex()
        )
    })
}

/// A file's bytes on their way to the client: hashed against the digest the Hub named it by
/// and, when there is somewhere to keep them, written to a temp file that a verified end
/// commits to the cache.
struct Fill {
    expected: HubDigest,
    sha256: sha2::Sha256,
    /// Running only for a regular file: its git blob digest, primed with the blob header.
    git: Option<sha1::Sha1>,
    /// `None` when there is nowhere to keep the bytes, or a write failed: the client is
    /// served and checked all the same, the cache is not filled.
    store: Option<FillStore>,
}

struct FillStore {
    storage: Storage,
    key: String,
    file: tokio::fs::File,
    path: PathBuf,
    /// Removes the temp file on every path but a committed fill.
    guard: TempFileGuard,
}

/// Plans the check (and the fill) of a full GET. `None` — the file is passed through unchecked
/// — when the etag names no digest NORA can check, or a regular file came without its length
/// (the git blob digest needs it up front). The cache is left out, the check kept, when the
/// repo id makes no key or the temp file cannot be created.
async fn plan_fill(
    state: &AppState,
    repo: &str,
    meta: &FileMeta,
    body: Option<&reqwest::Response>,
) -> Option<Fill> {
    let body = body?;
    let expected = hub_digest(meta.etag.as_ref()?)?;
    let git = match expected {
        HubDigest::Sha256(_) => None,
        HubDigest::GitBlob(_) => {
            let len: u64 = body
                .headers()
                .get(header::CONTENT_LENGTH)?
                .to_str()
                .ok()?
                .parse()
                .ok()?;
            let mut git = sha1::Sha1::new();
            git.update(format!("blob {len}\0").as_bytes());
            Some(git)
        }
    };
    let store = match cache_key(repo, &expected) {
        Some(key) => fill_store(state, key).await,
        None => None,
    };
    Some(Fill {
        expected,
        sha256: sha2::Sha256::new(),
        git,
        store,
    })
}

async fn fill_store(state: &AppState, key: String) -> Option<FillStore> {
    let dir = std::path::Path::new(&state.config.storage.path).join(FILL_TEMP_DIR);
    let path = dir.join(format!("{}.part", uuid::Uuid::new_v4()));
    let created = async {
        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::File::create(&path).await
    }
    .await;
    match created {
        Ok(file) => Some(FillStore {
            storage: state.storage.clone(),
            key,
            file,
            guard: TempFileGuard::new(path.clone()),
            path,
        }),
        Err(e) => {
            tracing::warn!(registry = "hf", path = %path.display(), error = %e, "no temp file for the cache fill; serving uncached");
            None
        }
    }
}

impl Fill {
    async fn take(&mut self, chunk: &Bytes) {
        self.sha256.update(chunk);
        if let Some(git) = self.git.as_mut() {
            git.update(chunk);
        }
        if let Some(store) = self.store.as_mut() {
            use tokio::io::AsyncWriteExt;
            if let Err(e) = store.file.write_all(chunk).await {
                tracing::warn!(registry = "hf", key = %store.key, error = %e, "cache fill write failed; serving uncached");
                self.store = None;
            }
        }
    }

    /// At the end of the body: the digest the Hub named, or an error that ends the body before
    /// its last chunk. A match commits the fill in the background.
    fn finish(&mut self) -> Result<(), std::io::Error> {
        let sha256 = hex::encode(std::mem::take(&mut self.sha256).finalize());
        let computed = match (&self.expected, self.git.take()) {
            (HubDigest::GitBlob(_), Some(git)) => hex::encode(git.finalize()),
            _ => sha256.clone(),
        };
        if computed != self.expected.hex() {
            tracing::error!(
                registry = "hf",
                expected = %self.expected.hex(),
                computed = %computed,
                "upstream file does not match the digest the Hub named it by; body aborted, not cached"
            );
            self.store = None;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "hf file integrity verification failed",
            ));
        }
        if let Some(store) = self.store.take() {
            commit_fill(store, sha256);
        }
        Ok(())
    }
}

/// The upstream body through a [`Fill`]: every chunk is hashed (and written) before it is
/// sent, and the last one is held back until the digest matches — a file that does not match
/// ends one chunk short, so it never arrives as a complete download and is never stored.
struct FillStream(Chunks);

impl futures::Stream for FillStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx)
    }
}

// An EOF-verifying stream like raw's `VerifyingStream`, so it may be served through the
// `stream_body` sole sink; only `fill_stream` builds one.
impl nora_registry::verified::stream_sealed::Sealed for FillStream {}
impl VerifiedByteStream for FillStream {}

fn fill_stream(chunks: Chunks, fill: Fill) -> FillStream {
    struct Through {
        chunks: Chunks,
        fill: Fill,
        held: Option<Bytes>,
        done: bool,
    }
    let through = Through {
        chunks,
        fill,
        held: None,
        done: false,
    };
    FillStream(Box::pin(futures::stream::unfold(
        through,
        |mut t| async move {
            if t.done {
                return None;
            }
            loop {
                match t.chunks.next().await {
                    Some(Ok(chunk)) => {
                        t.fill.take(&chunk).await;
                        if let Some(previous) = t.held.replace(chunk) {
                            return Some((Ok(previous), t));
                        }
                    }
                    Some(Err(e)) => {
                        t.done = true;
                        return Some((Err(e), t));
                    }
                    None => {
                        t.done = true;
                        if let Err(e) = t.fill.finish() {
                            return Some((Err(e), t));
                        }
                        let last = t.held.take();
                        return last.map(|last| (Ok(last), t));
                    }
                }
            }
        },
    )))
}

/// Commits a verified fill under its key, pinned to its sha256, in a task of its own: the
/// client already has its bytes, and a client gone at the last moment must not cancel the
/// commit halfway. A failure leaves the file uncached (the guard removes the temp file).
fn commit_fill(store: FillStore, sha256: String) {
    use std::panic::AssertUnwindSafe;
    let task = async move {
        let FillStore {
            storage,
            key,
            mut file,
            path,
            mut guard,
        } = store;
        // Durability: put_from_path renames the temp file into place, so its bytes must be
        // on disk before it does (#846).
        let synced = async {
            use tokio::io::AsyncWriteExt;
            file.flush().await?;
            file.sync_all().await
        }
        .await;
        drop(file);
        if let Err(e) = synced {
            tracing::warn!(registry = "hf", key = %key, error = %e, "cache fill not committed: temp file not synced");
            return;
        }
        match storage.put_from_path(&key, &path, Some(&sha256)).await {
            Ok(()) => guard.disarm(),
            Err(e) => {
                tracing::warn!(registry = "hf", key = %key, error = %e, "cache fill not committed")
            }
        }
    };
    tokio::spawn(AssertUnwindSafe(task).catch_unwind().map(|done| {
        if let Err(panic) = done {
            tracing::error!(panic = ?panic, "hf cache fill task panicked");
        }
    }));
}

/// A file served from the cache, with the commit and digest the hops named. A range is read
/// straight from storage — open world, as every ranged serve: a part cannot be rehashed — and a
/// full read goes through `verify_while_streaming`, which checks the pin before the last frame.
/// `None` when the stored copy cannot be read or carries no pin: the caller fetches the file
/// again.
async fn cached_response(
    state: &AppState,
    headers: &HeaderMap,
    meta: &FileMeta,
    key: &str,
    size: u64,
) -> Option<Response> {
    let mut extra: Vec<(HeaderName, String)> = Vec::new();
    let text = |v: &HeaderValue| v.to_str().ok().map(str::to_string);
    if let Some(commit) = meta.commit.as_ref().and_then(text) {
        extra.push((REPO_COMMIT_HEADER, commit));
    }
    if let Some(etag) = meta.etag.as_ref().and_then(text) {
        extra.push((header::ETAG, etag.clone()));
        extra.push((LINKED_ETAG_HEADER, etag));
    }
    let linked_size = meta
        .size
        .as_ref()
        .and_then(text)
        .unwrap_or_else(|| size.to_string());
    extra.push((LINKED_SIZE_HEADER, linked_size));
    if headers.contains_key(header::RANGE) {
        if let Some(response) = crate::registry::range::range_response(
            &state.storage,
            &[key],
            headers,
            size,
            CACHED_CONTENT_TYPE,
            &extra,
        )
        .await
        {
            return Some(response);
        }
    }
    let (len, pin, reader) = match state.storage.get_reader(key).await {
        Ok(stored) => stored,
        Err(e) => {
            tracing::warn!(registry = "hf", key = %key, error = %e, "cached file unreadable; fetching it again");
            return None;
        }
    };
    let Some(pin) = pin else {
        tracing::warn!(registry = "hf", key = %key, "cached file has no pin; fetching it again");
        return None;
    };
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, CACHED_CONTENT_TYPE)
        .header(header::CONTENT_LENGTH, len)
        .header(header::ACCEPT_RANGES, "bytes");
    for (name, value) in &extra {
        response = response.header(name, value.as_str());
    }
    response
        .body(stream_body(verify_while_streaming(
            reader,
            Some(pin),
            key.to_string(),
        )))
        .ok()
}

/// Removes temp files of cache fills that will not finish (a crash, a kill), at start and
/// on the periodic sweep, as docker does for its proxy temp files.
pub fn cleanup_fill_temp_dir(data_dir: &str) {
    let dir = std::path::Path::new(data_dir).join(FILL_TEMP_DIR);
    let removed = super::remove_stale_temp_files(&dir, FILL_TEMP_MAX_AGE);
    if removed > 0 {
        tracing::info!(removed, dir = %dir.display(), "Cleaned up stale hf cache fill temp files");
    }
}

async fn datasets() -> Response {
    error_response(StatusCode::NOT_IMPLEMENTED, DATASETS_NOT_IMPLEMENTED)
}

/// The configured upstream without a trailing slash; `None` when the operator configured
/// none, and then NORA contacts no one.
fn upstream_base(state: &AppState) -> Option<&str> {
    state
        .config
        .hf
        .proxy
        .as_deref()
        .map(|u| u.trim_end_matches('/'))
        .filter(|u| !u.is_empty())
}

fn nora_hf_base(state: &AppState) -> String {
    format!("{}/hf", nora_base_url(state).trim_end_matches('/'))
}

/// The answer to a metadata request: the upstream's JSON without Xet, with only
/// `Content-Type`, `X-Repo-Commit` and a rewritten `Link` beside it. A body NORA cannot
/// parse as JSON is refused rather than handed on unfiltered.
fn metadata_response(upstream: &str, nora_hf: &str, headers: &HeaderMap, body: &[u8]) -> Response {
    let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
        return error_response(StatusCode::BAD_GATEWAY, UNREADABLE);
    };
    strip_xet_metadata(&mut value);

    // Every `Link` line, not the first: one line could carry the pagination and another
    // the Xet relations.
    let mut lines = Vec::new();
    for v in headers.get_all(header::LINK) {
        match v.to_str() {
            Ok(line) => lines.push(line),
            Err(_) => return error_response(StatusCode::BAD_GATEWAY, LINK_UNREADABLE),
        }
    }
    let link = if lines.is_empty() {
        None
    } else {
        match rewrite_link(&lines.join(", "), upstream, nora_hf) {
            Ok(link) => link,
            Err(LinkRefusal::Foreign) => {
                return error_response(StatusCode::BAD_GATEWAY, LINK_LEAVES_NORA)
            }
            Err(LinkRefusal::Unreadable) => {
                return error_response(StatusCode::BAD_GATEWAY, LINK_UNREADABLE)
            }
        }
    };

    let mut response = Json(value).into_response();
    if let Some(commit) = headers.get(&REPO_COMMIT_HEADER) {
        response
            .headers_mut()
            .insert(REPO_COMMIT_HEADER, commit.clone());
    }
    if let Some(link) = link {
        match HeaderValue::from_str(&link) {
            Ok(v) => {
                response.headers_mut().insert(header::LINK, v);
            }
            Err(_) => return error_response(StatusCode::BAD_GATEWAY, LINK_UNREADABLE),
        }
    }
    response
}

/// A file request, every part exactly as the client encoded it.
#[derive(Debug, PartialEq)]
struct FileRequest<'a> {
    repo: &'a str,
    revision: &'a str,
    file: &'a str,
}

/// Reads `{repo}/resolve/{revision}/{file}` the way the Hub routes it: `org/name` when
/// `resolve` is the third segment (five or more), else a legacy one-segment id when it is the
/// second (four or more) — so a repo named `resolve` under an org stays canonical. Every
/// segment is a plain path segment; parts keep the client's encoding.
fn parse_file_request(rest: &str) -> Option<FileRequest<'_>> {
    if rest.is_empty() || rest.len() > MAX_PATH {
        return None;
    }
    let segments: Vec<&str> = rest.split('/').collect();
    for segment in &segments {
        let decoded = decode_segment(segment)?;
        if decoded.is_empty() || decoded == "." || decoded == ".." {
            return None;
        }
    }
    let start = |i: usize| -> usize { segments[..i].iter().map(|s| s.len() + 1).sum() };
    let (repo_end, revision) = if segments.len() >= 5 && segments[2] == "resolve" {
        (2, 3)
    } else if segments.len() >= 4 && segments[1] == "resolve" {
        (1, 2)
    } else {
        return None;
    };
    Some(FileRequest {
        repo: &rest[..start(repo_end) - 1],
        revision: segments[revision],
        file: &rest[start(revision + 1)..],
    })
}

/// Why a metadata path is not forwarded.
#[derive(Debug, PartialEq)]
enum Refusal {
    /// A Xet token route: answering it would hand the client the way around NORA.
    XetRoute,
    /// Not a plain path: an empty or dot segment, a byte outside RFC 3986, a broken
    /// percent-escape, or longer than any metadata path.
    BadPath,
}

/// The upstream URL for `GET /hf/api/models/{rest}?{query}`. The path goes exactly as the
/// client encoded it, so a revision like `refs/pr/1`, sent as `refs%2Fpr%2F1`, stays one
/// segment — decoded and joined, it would name a path the Hub does not serve.
fn models_api_upstream(base: &str, rest: &str, query: Option<&str>) -> Result<String, Refusal> {
    if rest.is_empty() || rest.len() > MAX_PATH {
        return Err(Refusal::BadPath);
    }
    for (i, segment) in rest.split('/').enumerate() {
        let decoded = decode_segment(segment).ok_or(Refusal::BadPath)?;
        if decoded.is_empty() || decoded == "." || decoded == ".." {
            return Err(Refusal::BadPath);
        }
        if i > 0
            && XET_TOKEN_ROUTES
                .iter()
                .any(|route| decoded.eq_ignore_ascii_case(route))
        {
            return Err(Refusal::XetRoute);
        }
    }
    let mut url = format!("{}/api/models/{rest}", base.trim_end_matches('/'));
    if let Some(query) = query {
        if query.len() > MAX_QUERY
            || !query.bytes().all(|b| is_pchar(b) || b == b'/' || b == b'?')
            || !escapes_are_whole(query)
        {
            return Err(Refusal::BadPath);
        }
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }
    }
    Ok(url)
}

/// RFC 3986 `pchar` bytes, with `%` standing for the start of an escape.
fn is_pchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@%".contains(&b)
}

/// Whether every `%` in `s` starts a two-hex-digit escape.
fn escapes_are_whole(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.iter().enumerate().all(|(i, &b)| {
        b != b'%'
            || bytes
                .get(i + 1..i + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
    })
}

/// A path segment decoded, or `None` when it holds a byte outside RFC 3986, a broken
/// percent-escape, or bytes that are not UTF-8.
fn decode_segment(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !is_pchar(bytes[i]) {
            return None;
        }
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    percent_encoding::percent_decode_str(segment)
        .decode_utf8()
        .ok()
        .map(|s| s.into_owned())
}

/// Removes [`XET_BODY_KEY`] from every object at any depth. Shape-independent on purpose:
/// the key is dropped wherever the Hub puts it, today or after a change of shape.
fn strip_xet_metadata(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove(XET_BODY_KEY);
            for v in map.values_mut() {
                strip_xet_metadata(v);
            }
        }
        Value::Array(items) => {
            for v in items {
                strip_xet_metadata(v);
            }
        }
        _ => {}
    }
}

/// Why a `Link` header is not handed on.
#[derive(Debug, PartialEq)]
enum LinkRefusal {
    /// A page outside the upstream: handed on, it sends the client around NORA; dropped, it
    /// leaves the client with part of a listing.
    Foreign,
    /// An entry NORA cannot read, or one that mixes a page with another relation — it can be
    /// neither handed on nor dropped whole.
    Unreadable,
}

/// Rewrites a `Link` header value for the client, by a white list of relations. An entry
/// whose relations are all [`PAGINATION_RELS`] moves under NORA's mount when its target is on
/// the upstream (absolute, or relative to its root); the Hub pages a tree listing with an
/// absolute `rel="next"` that the client requests as it is, so a page anywhere else is
/// refused rather than handed on or dropped. An entry with no pagination relation — Xet's
/// `xet-auth` and `xet-reconstruction-info`, or anything else — is dropped: a client of the
/// proxy needs none of them. Relations are read the way the most liberal reader does: every
/// `rel` parameter (RFC 8288 takes the first, requests and httpx keep the last), every
/// space-separated type, whitespace and quotes around the value removed. `None` when no
/// entry remains.
fn rewrite_link(value: &str, upstream: &str, nora_hf: &str) -> Result<Option<String>, LinkRefusal> {
    let upstream = upstream.trim_end_matches('/');
    let mut kept = Vec::new();
    for entry in split_link_entries(value) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (target, params) = entry
            .strip_prefix('<')
            .and_then(|e| e.split_once('>'))
            .ok_or(LinkRefusal::Unreadable)?;
        let rels: Vec<String> = link_rels(params).map(str::to_ascii_lowercase).collect();
        let pages = rels
            .iter()
            .filter(|rel| PAGINATION_RELS.contains(&rel.as_str()))
            .count();
        if pages == 0 {
            continue;
        }
        if pages != rels.len() {
            return Err(LinkRefusal::Unreadable);
        }
        let path = match target.strip_prefix(upstream) {
            Some(rest) if rest.is_empty() || rest.starts_with('/') || rest.starts_with('?') => rest,
            Some(_) => return Err(LinkRefusal::Foreign),
            None if target.starts_with('/') && !target.starts_with("//") => target,
            None => return Err(LinkRefusal::Foreign),
        };
        kept.push(format!("<{nora_hf}{path}>{params}"));
    }
    Ok((!kept.is_empty()).then(|| kept.join(", ")))
}

/// The entries of a `Link` value: split on commas outside `<…>` and outside quotes.
fn split_link_entries(value: &str) -> Vec<&str> {
    let mut entries = Vec::new();
    let (mut start, mut in_target, mut in_quotes) = (0, false, false);
    for (i, c) in value.char_indices() {
        match c {
            '<' if !in_quotes => in_target = true,
            '>' if !in_quotes => in_target = false,
            '"' if !in_target => in_quotes = !in_quotes,
            ',' if !in_target && !in_quotes => {
                entries.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    entries.push(&value[start..]);
    entries
}

/// The relation types named by the `rel` parameters of one `Link` entry.
fn link_rels(params: &str) -> impl Iterator<Item = &str> {
    params
        .split(';')
        .filter_map(|p| p.split_once('='))
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case("rel"))
        .flat_map(|(_, v)| {
            v.trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .split_ascii_whitespace()
        })
}

fn error_response(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        [(ERROR_MESSAGE_HEADER, HeaderValue::from_static(message))],
        Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{
        body_bytes, create_test_context_with_config, send, send_with_headers, upstream_paths,
        TestContext,
    };
    use axum::http::Method;
    use serde_json::{json, Value};
    use wiremock::matchers::{any, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn hf_enabled() -> TestContext {
        create_test_context_with_config(|cfg| cfg.hf.enabled = true)
    }

    fn hf_with_upstream(up: &MockServer) -> TestContext {
        let uri = up.uri();
        create_test_context_with_config(move |cfg| {
            cfg.hf.enabled = true;
            cfg.hf.proxy = Some(uri);
        })
    }

    fn header(resp: &Response, name: &str) -> String {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    /// The reason a 501 gives in `X-Error-Message`, and in the JSON body for a GET (HEAD has
    /// no body; the header alone is checked twice then).
    async fn reason_of(resp: Response, m: &str) -> (String, String) {
        let h = header(&resp, "x-error-message");
        if m == "HEAD" {
            return (h.clone(), h);
        }
        let body: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap_or_default();
        (h, body["error"].as_str().unwrap_or_default().to_string())
    }

    /// The reason a client reads, as text: compared with the constant, an aliased or
    /// swapped constant would pass.
    const DATASETS_REASON: &str =
        "Hugging Face datasets are not implemented in this NORA build: only models are in scope.";

    async fn json_of(resp: Response) -> Value {
        serde_json::from_slice(&body_bytes(resp).await).expect("JSON body")
    }

    /// The metadata requests a model download makes, in the shapes the real client sends.
    const METADATA_REQUESTS: &[&str] = &[
        "/hf/api/models/org/model",
        "/hf/api/models/org/model/revision/main",
        "/hf/api/models/org/model/tree/0123456789abcdef0123456789abcdef01234567?recursive=true&expand=false",
        "/hf/api/models/org/model/tree/main/sub/dir",
        "/hf/api/models/org/model/revision/refs%2Fconvert%2Fparquet",
    ];

    /// The file requests, still unimplemented in this slice.
    const RESOLVE_REQUESTS: &[(&str, &str)] = &[
        ("HEAD", "/hf/org/model/resolve/main/config.json"),
        ("GET", "/hf/org/model/resolve/main/config.json"),
        (
            "GET",
            "/hf/org/model/resolve/main/sub/dir/model.safetensors",
        ),
        ("HEAD", "/hf/org/model/resolve/refs%2Fpr%2F1/config.json"),
    ];

    fn verb(m: &str) -> Method {
        Method::from_bytes(m.as_bytes()).unwrap()
    }

    /// A listing in the live Hub's shape: a regular file, and an LFS file of a Xet-backed
    /// repo carrying both `lfs` and `xetHash`; only the Xet hash is removed on the way through.
    fn live_tree() -> Value {
        json!([
            {"type": "file", "oid": "cce185ba30383db0a5a2a2483cd3dedfb1abe46d", "size": 44, "path": "config.json"},
            {"type": "file", "oid": "44b36d6e32d13c8fb28b0feab0ac8bfefa7efeda", "size": 4112, "path": "model.safetensors",
             "lfs": {"oid": "248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707", "size": 4112, "pointerSize": 134},
             "xetHash": "63bed80836ee0758c8fd4f8975d59bb0b864263ee2753547c358e8a37cde8758"}
        ])
    }

    /// A moved `main` is never served from a cache: the same metadata request asked twice
    /// reaches the upstream twice.
    #[tokio::test]
    async fn metadata_is_fetched_on_every_request() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"sha": "a"})))
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        for _ in 0..2 {
            let resp = send(
                &ctx.app,
                Method::GET,
                "/hf/api/models/org/model/revision/main",
                "",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        assert_eq!(upstream_paths(&up).await.len(), 2);
    }

    #[tokio::test]
    async fn datasets_answer_501_with_their_own_reason() {
        let ctx = hf_enabled();
        for (m, uri) in [
            ("GET", "/hf/api/datasets/org/data/revision/main"),
            ("HEAD", "/hf/datasets/org/data/resolve/main/train.parquet"),
            ("GET", "/hf/datasets/org/data/resolve/main/train.parquet"),
        ] {
            let resp = send(&ctx.app, verb(m), uri, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED, "{m} {uri}");
            assert_eq!(
                reason_of(resp, m).await,
                (DATASETS_REASON.to_string(), DATASETS_REASON.to_string()),
                "{m} {uri}"
            );
        }
    }

    #[tokio::test]
    async fn disabled_by_default_and_then_not_mounted() {
        let ctx = create_test_context_with_config(|_| {});
        assert!(!ctx.state.config.hf.enabled, "hf must be opt-in");
        let all = METADATA_REQUESTS
            .iter()
            .map(|u| ("GET", *u))
            .chain(RESOLVE_REQUESTS.iter().copied());
        for (m, uri) in all {
            let resp = send(&ctx.app, verb(m), uri, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{m} {uri}");
        }
    }

    #[tokio::test]
    async fn health_lists_hf_only_when_enabled() {
        let registries = |ctx: TestContext| async move {
            let resp = send(&ctx.app, Method::GET, "/health", "").await;
            json_of(resp).await["registries"]
                .as_object()
                .cloned()
                .unwrap_or_default()
        };
        assert!(registries(hf_enabled()).await.contains_key("hf"));
        assert!(!registries(create_test_context_with_config(|_| {}))
            .await
            .contains_key("hf"));
    }

    // ── metadata ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn every_metadata_request_reaches_the_upstream_as_the_client_encoded_it() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        for uri in METADATA_REQUESTS {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        }
        let sent: Vec<String> = up
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| match r.url.query() {
                Some(q) => format!("{}?{q}", r.url.path()),
                None => r.url.path().to_string(),
            })
            .collect();
        let expected: Vec<String> = METADATA_REQUESTS
            .iter()
            .map(|u| u.strip_prefix("/hf").unwrap().to_string())
            .collect();
        // `refs%2Fconvert%2Fparquet` stays one segment: decoded, it names a path the Hub
        // does not serve.
        assert_eq!(sent, expected);
    }

    #[tokio::test]
    async fn the_tree_listing_reaches_the_client_without_xet() {
        let up = MockServer::start().await;
        Mock::given(path("/api/models/org/model/tree/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(live_tree()))
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/api/models/org/model/tree/main",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            json_of(resp).await,
            json!([
                {"type": "file", "oid": "cce185ba30383db0a5a2a2483cd3dedfb1abe46d", "size": 44, "path": "config.json"},
                {"type": "file", "oid": "44b36d6e32d13c8fb28b0feab0ac8bfefa7efeda", "size": 4112, "path": "model.safetensors",
                 "lfs": {"oid": "248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707", "size": 4112, "pointerSize": 134}}
            ])
        );
    }

    #[tokio::test]
    async fn model_info_loses_xet_and_keeps_the_rest() {
        let up = MockServer::start().await;
        let info = json!({
            "id": "org/model", "sha": "0123456789abcdef0123456789abcdef01234567", "private": false,
            "siblings": [
                {"rfilename": "config.json", "blobId": "cce1", "size": 44},
                {"rfilename": "model.safetensors", "blobId": "44b3", "size": 4112,
                 "lfs": {"sha256": "248d", "size": 4112, "pointerSize": 134}, "xetHash": "63be"}
            ],
            "cardData": {"nested": [{"xetHash": "63be", "license": "mit"}]}
        });
        Mock::given(path("/api/models/org/model/revision/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(info))
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/api/models/org/model/revision/main?blobs=true",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            json_of(resp).await,
            json!({
                "id": "org/model", "sha": "0123456789abcdef0123456789abcdef01234567", "private": false,
                "siblings": [
                    {"rfilename": "config.json", "blobId": "cce1", "size": 44},
                    {"rfilename": "model.safetensors", "blobId": "44b3", "size": 4112,
                     "lfs": {"sha256": "248d", "size": 4112, "pointerSize": 134}}
                ],
                "cardData": {"nested": [{"license": "mit"}]}
            })
        );
    }

    #[tokio::test]
    async fn the_next_page_points_back_at_nora_and_xet_relations_are_gone() {
        let up = MockServer::start().await;
        let link = format!(
            "<{u}/api/models/org/model/tree/main?recursive=true&cursor=1>; rel=\"next\", \
             <{u}/api/models/org/model/xet-read-token/main>; rel=\"xet-auth\"",
            u = up.uri()
        );
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([]))
                    .insert_header("link", link.as_str()),
            )
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let nora = crate::registry::nora_base_url(&ctx.state);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/api/models/org/model/tree/main?recursive=true",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            header(&resp, "link"),
            format!(
                "<{nora}/hf/api/models/org/model/tree/main?recursive=true&cursor=1>; rel=\"next\""
            )
        );
    }

    #[tokio::test]
    async fn every_link_line_is_read_not_only_the_first() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([]))
                    .append_header(
                        "link",
                        format!(
                            "<{}/api/models/org/model/xet-read-token/main>; rel=xet-auth",
                            up.uri()
                        )
                        .as_str(),
                    )
                    .append_header(
                        "link",
                        format!(
                            "<{}/api/models/org/model/tree/main?cursor=1>; rel=\"next\"",
                            up.uri()
                        )
                        .as_str(),
                    ),
            )
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let nora = crate::registry::nora_base_url(&ctx.state);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/api/models/org/model/tree/main",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let lines: Vec<String> = resp
            .headers()
            .get_all("link")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            lines,
            vec![format!(
                "<{nora}/hf/api/models/org/model/tree/main?cursor=1>; rel=\"next\""
            )]
        );
    }

    #[tokio::test]
    async fn a_next_page_on_another_host_is_a_gateway_error_not_a_short_listing() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([]))
                    .insert_header("link", "<http://elsewhere.example/api/models/org/model/tree/main?cursor=1>; rel=\"next\""),
            )
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/api/models/org/model/tree/main",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn only_listed_headers_reach_the_client() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"id": "org/model"}))
                    .insert_header("x-repo-commit", "0123456789abcdef0123456789abcdef01234567")
                    .insert_header(
                        "x-xet-hash",
                        "63bed80836ee0758c8fd4f8975d59bb0b864263ee2753547c358e8a37cde8758",
                    )
                    .insert_header(
                        "x-xet-refresh-route",
                        "/api/models/org/model/xet-read-token/main",
                    )
                    .insert_header(
                        "link",
                        "</api/models/org/model/xet-read-token/main>; rel=\"xet-auth\"",
                    )
                    .insert_header("etag", "\"abc\"")
                    .insert_header("set-cookie", "token=upstream")
                    .insert_header("x-repo-commit-signature", "upstream")
                    .insert_header("x-repo-type", "model")
                    .insert_header("x-request-id", "upstream"),
            )
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let resp = send(&ctx.app, Method::GET, "/hf/api/models/org/model", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            header(&resp, "x-repo-commit"),
            "0123456789abcdef0123456789abcdef01234567"
        );
        // A white list, by exact name: whatever else the upstream sent stays with NORA.
        // `x-request-id` is NORA's own (its request-id middleware), never the upstream's.
        for name in resp.headers().keys() {
            assert!(
                [
                    "content-type",
                    "content-length",
                    "x-repo-commit",
                    "link",
                    "x-request-id"
                ]
                .contains(&name.as_str()),
                "{name} reached the client"
            );
        }
        assert_ne!(header(&resp, "x-request-id"), "upstream");
        assert!(
            !resp.headers().contains_key("link"),
            "a Xet-only Link reached the client"
        );
        assert!(header(&resp, "content-type").starts_with("application/json"));
    }

    #[tokio::test]
    async fn a_xet_token_request_never_reaches_the_upstream() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accessToken": "t"})))
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        for uri in [
            "/hf/api/models/org/model/xet-read-token/main",
            "/hf/api/models/org/model/xet%2Dread-token/main",
            "/hf/api/models/org/model/XET-READ-TOKEN/main",
            "/hf/api/models/org/model/xet-write-token/main",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
            assert!(header(&resp, "x-error-message").contains("Xet"), "{uri}");
        }
        assert!(upstream_paths(&up).await.is_empty());
    }

    #[tokio::test]
    async fn a_path_that_is_not_plain_metadata_never_reaches_the_upstream() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        for uri in [
            "/hf/api/models/org/%2e%2e/secret",
            // First position: the HTTP client folds `%2e%2e`, so this would reach
            // /api/datasets/... through the models route.
            "/hf/api/models/%2e%2e/datasets/org/data/revision/main",
            "/hf/api/models/./org/model",
            "/hf/api/models/org/model/..",
            "/hf/api/models/org//model",
            "/hf/api/models/org/model/",
            "/hf/api/models/org/model%",
            "/hf/api/models/org/model%zz",
            "/hf/api/models/org/model%4z",
            "/hf/api/models/org/model%z4",
            "/hf/api/models/org/model?recursive=%zz",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
        assert!(upstream_paths(&up).await.is_empty());
    }

    #[tokio::test]
    async fn the_clients_credentials_stay_with_nora() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/hf/api/models/org/model/revision/main",
            vec![
                ("authorization", "Bearer hf_clienttoken"),
                ("cookie", "token=client"),
            ],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let received = up.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let h = &received[0].headers;
        assert!(
            h.get("authorization").is_none() && h.get("cookie").is_none(),
            "{h:?}"
        );
    }

    #[tokio::test]
    async fn with_no_upstream_configured_nothing_is_contacted() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.hf.enabled = true;
            cfg.hf.proxy = None;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/api/models/org/model/revision/main",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(header(&resp, "x-error-message").contains("No Hugging Face upstream"));
    }

    #[tokio::test]
    async fn a_legacy_repo_id_is_followed_inside() {
        let up = MockServer::start().await;
        Mock::given(path("/api/models/gpt2/revision/main"))
            .respond_with(ResponseTemplate::new(307).insert_header(
                "location",
                "/api/models/openai-community/gpt2/revision/main",
            ))
            .mount(&up)
            .await;
        Mock::given(path("/api/models/openai-community/gpt2/revision/main"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"id": "openai-community/gpt2"})),
            )
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/api/models/gpt2/revision/main",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(header(&resp, "location").is_empty());
        assert_eq!(json_of(resp).await["id"], "openai-community/gpt2");
    }

    #[tokio::test]
    async fn upstream_failures_are_answered_with_their_kind() {
        let up = MockServer::start().await;
        Mock::given(path("/api/models/org/missing"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({"error": "Repository not found"})),
            )
            .mount(&up)
            .await;
        Mock::given(path("/api/models/org/broken"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&up)
            .await;
        Mock::given(path("/api/models/org/html"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("<html>login</html>")
                    .insert_header("content-type", "text/html"),
            )
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        // Each kind says its own reason, compared with the text a client reads.
        for (uri, status, reason) in [
            (
                "/hf/api/models/org/missing",
                StatusCode::NOT_FOUND,
                "Not found on the Hugging Face upstream, or not a public repository.",
            ),
            (
                "/hf/api/models/org/broken",
                StatusCode::BAD_GATEWAY,
                "The Hugging Face upstream did not answer.",
            ),
            // A metadata answer NORA cannot read is not handed on unfiltered.
            (
                "/hf/api/models/org/html",
                StatusCode::BAD_GATEWAY,
                "The Hugging Face upstream answered with metadata NORA cannot read.",
            ),
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), status, "{uri}");
            assert_eq!(
                reason_of(resp, "GET").await,
                (reason.into(), reason.into()),
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn metadata_is_read_only() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            let resp = send(
                &ctx.app,
                m.clone(),
                "/hf/api/models/org/model/paths-info/main",
                "",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "{m}");
        }
        assert!(upstream_paths(&up).await.is_empty());
    }

    /// A Link line NORA cannot read is refused, not skipped: skipped, its `next` would go
    /// missing and the client would keep page one only.
    #[tokio::test]
    async fn an_unreadable_link_line_is_a_gateway_error() {
        let up = MockServer::start().await;
        let mut line = format!(
            "<{}/api/models/org/model/tree/main?cursor=1>; rel=\"next\"; title=\"",
            up.uri()
        )
        .into_bytes();
        line.extend_from_slice(b"\xe9\"");
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([]))
                    .insert_header("link", HeaderValue::from_bytes(&line).unwrap()),
            )
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/api/models/org/model/tree/main",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let reason = "The Hugging Face upstream sent a Link header NORA cannot hand on.";
        assert_eq!(reason_of(resp, "GET").await, (reason.into(), reason.into()));
    }

    /// Metadata leaves nothing behind in storage — no cache anywhere on its path, called
    /// directly or from a helper — so a moved `main` cannot be served from one.
    #[tokio::test]
    async fn metadata_leaves_nothing_in_storage() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(live_tree()))
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let before = ctx.state.storage.list("").await.unwrap();
        for uri in METADATA_REQUESTS {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        }
        assert_eq!(ctx.state.storage.list("").await.unwrap(), before);
    }

    // ── files (resolve) ────────────────────────────────────────────────────────

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    /// The sha256 of [`weights`]: the digest the fixture Hub names the LFS file by.
    const SHA256: &str = "140ce67f4f40ccd0e877eab619ca490a5dd700411b23b4bb19ea5952c7b6d603";
    /// The git blob sha1 of [`CONFIG`]: the etag of the regular file, as on the live Hub.
    const CONFIG_BLOB: &str = "302193440cfbfa05b83201c696ca7f96b95dbf75";
    const CONFIG: &[u8] = b"{\"model_type\": \"fixture\"}\n";

    /// An upstream in the live Hub's shape: a regular file answers a relative 307 to the
    /// resolve cache; an LFS file answers a 302 to `cdn` — another host — with the commit,
    /// etag and size on that hop only and Xet advertised beside them.
    async fn live_hub(cdn: &MockServer) -> MockServer {
        let up = MockServer::start().await;
        // The canonical id answers its own `api/models` with 200, as on the live Hub.
        Mock::given(path("/api/models/org/model"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&up)
            .await;
        Mock::given(path("/org/model/resolve/main/config.json"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header(
                        "location",
                        format!("/api/resolve-cache/models/org/model/{COMMIT}/config.json?x=1")
                            .as_str(),
                    )
                    .insert_header("x-repo-commit", COMMIT)
                    .insert_header("x-linked-etag", format!("\"{CONFIG_BLOB}\"").as_str()),
            )
            .mount(&up)
            .await;
        Mock::given(path(
            format!("/api/resolve-cache/models/org/model/{COMMIT}/config.json").as_str(),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(CONFIG.to_vec())
                .insert_header("etag", format!("\"{CONFIG_BLOB}\"").as_str())
                .insert_header("x-repo-commit", COMMIT)
                .insert_header("set-cookie", "hub=1"),
        )
        .mount(&up)
        .await;
        Mock::given(path("/org/model/resolve/main/model.safetensors"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/xet-bridge/model.safetensors?sig=1", cdn.uri()).as_str())
                    .insert_header("x-repo-commit", COMMIT)
                    .insert_header("x-linked-etag", format!("\"{SHA256}\"").as_str())
                    .insert_header("x-linked-size", "4112")
                    .insert_header("x-xet-hash", "63bed80836ee0758c8fd4f8975d59bb0b864263ee2753547c358e8a37cde8758")
                    .insert_header("link", "<https://huggingface.co/api/models/org/model/xet-read-token/main>; rel=\"xet-auth\""),
            )
            .mount(&up)
            .await;
        up
    }

    async fn cdn_with_weights() -> MockServer {
        let cdn = MockServer::start().await;
        Mock::given(path("/xet-bridge/model.safetensors"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(weights())
                    .insert_header("etag", "\"cdn-etag\"")
                    .insert_header("x-amz-request-id", "abc"),
            )
            .mount(&cdn)
            .await;
        cdn
    }

    fn weights() -> Vec<u8> {
        let mut w = b"FIXTURE-WEIGHTS-".to_vec();
        w.resize(4112, 0);
        w
    }

    /// No header that could send a client to Xet, and no upstream cookie or storage header.
    fn assert_no_leaked_headers(resp: &Response) {
        for (name, _) in resp.headers() {
            let n = name.as_str();
            assert!(
                !n.starts_with("x-xet-")
                    && n != "link"
                    && n != "set-cookie"
                    && !n.starts_with("x-amz-")
                    && n != "location",
                "{n} reached the client"
            );
        }
    }

    #[tokio::test]
    async fn a_regular_file_comes_through_the_relative_redirect() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/config.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, "x-repo-commit"), COMMIT);
        assert_eq!(header(&resp, "etag"), format!("\"{CONFIG_BLOB}\""));
        assert_no_leaked_headers(&resp);
        assert_eq!(&body_bytes(resp).await[..], CONFIG);
    }

    #[tokio::test]
    async fn an_lfs_file_comes_through_the_cdn_with_the_commit_of_the_redirect() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/model.safetensors",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // The CDN's answer has no commit: it comes from the redirect hop.
        assert_eq!(header(&resp, "x-repo-commit"), COMMIT);
        assert_eq!(header(&resp, "etag"), format!("\"{SHA256}\""));
        assert_eq!(header(&resp, "x-linked-size"), "4112");
        assert_no_leaked_headers(&resp);
        assert_eq!(body_bytes(resp).await.to_vec(), weights());
    }

    #[tokio::test]
    async fn head_stops_at_the_cdn_like_the_client_does() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        let resp = send(
            &ctx.app,
            Method::HEAD,
            "/hf/org/model/resolve/main/model.safetensors",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, "x-repo-commit"), COMMIT);
        assert_eq!(header(&resp, "etag"), format!("\"{SHA256}\""));
        assert_eq!(header(&resp, "content-length"), "4112");
        assert_no_leaked_headers(&resp);
        // A signed CDN link is for GET; HEAD answers from the redirect hop.
        assert!(upstream_paths(&cdn).await.is_empty());
    }

    #[tokio::test]
    async fn head_on_a_regular_file_follows_the_same_host_redirect() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        let resp = send(
            &ctx.app,
            Method::HEAD,
            "/hf/org/model/resolve/main/config.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, "x-repo-commit"), COMMIT);
        assert_eq!(header(&resp, "etag"), format!("\"{CONFIG_BLOB}\""));
        assert_eq!(header(&resp, "content-length"), "26");
        assert_no_leaked_headers(&resp);
    }

    #[tokio::test]
    async fn a_range_request_resumes_at_the_cdn() {
        let up = MockServer::start().await;
        let cdn = MockServer::start().await;
        Mock::given(path("/org/model/resolve/main/model.safetensors"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/w", cdn.uri()).as_str())
                    .insert_header("x-repo-commit", COMMIT)
                    .insert_header("x-linked-etag", format!("\"{SHA256}\"").as_str())
                    .insert_header("x-linked-size", "4112"),
            )
            .mount(&up)
            .await;
        Mock::given(path("/w"))
            .and(wiremock::matchers::header("range", "bytes=4100-"))
            .respond_with(
                ResponseTemplate::new(206)
                    .set_body_bytes(weights()[4100..].to_vec())
                    .insert_header("content-range", "bytes 4100-4111/4112"),
            )
            .mount(&cdn)
            .await;
        let ctx = hf_with_upstream(&up);
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/model.safetensors",
            vec![("range", "bytes=4100-")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(header(&resp, "content-range"), "bytes 4100-4111/4112");
        assert_eq!(body_bytes(resp).await.to_vec(), weights()[4100..].to_vec());
    }

    /// Every hop asks for the bytes as stored: a compressed answer would be decompressed by
    /// the HTTP client while its Content-Length still counted the compressed size.
    #[tokio::test]
    async fn every_hop_asks_for_identity_encoding() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/model.safetensors",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        for server in [&up, &cdn] {
            for r in server.received_requests().await.unwrap() {
                let ae = r
                    .headers
                    .get("accept-encoding")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                assert_eq!(ae, "identity", "{}", r.url.path());
            }
        }
    }

    #[tokio::test]
    async fn files_go_upstream_as_the_client_encoded_them() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(b"x".to_vec())
                    .insert_header("x-repo-commit", COMMIT),
            )
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        for uri in [
            "/hf/org/model/resolve/refs%2Fpr%2F1/config.json",
            "/hf/org/model/resolve/main/sub/dir/model.safetensors",
            "/hf/gpt2/resolve/main/config.json",
            "/hf/org/resolve/resolve/main/config.json",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        }
        assert_eq!(
            upstream_paths(&up).await,
            vec![
                "/org/model/resolve/refs%2Fpr%2F1/config.json",
                "/org/model/resolve/main/sub/dir/model.safetensors",
                "/gpt2/resolve/main/config.json",
                "/org/resolve/resolve/main/config.json",
            ]
        );
    }

    #[tokio::test]
    async fn a_path_that_is_not_a_file_request_never_reaches_the_upstream() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        for uri in [
            "/hf/org/model/blob/main/config.json",
            "/hf/org/model/resolve/main",
            "/hf/org/model/resolve/main/../x",
            "/hf/org//model/resolve/main/x",
            "/hf/org/model/resolve/main/x%zz",
            "/hf/api/spaces/org/space",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert!(resp.status().is_client_error(), "{uri}: {}", resp.status());
        }
        assert!(upstream_paths(&up).await.is_empty());
    }

    #[tokio::test]
    async fn file_refusals_keep_their_code_and_failures_are_a_gateway_error() {
        let up = MockServer::start().await;
        Mock::given(path("/org/model/resolve/main/missing.bin"))
            .respond_with(
                ResponseTemplate::new(404)
                    .insert_header("x-error-code", "EntryNotFound")
                    .insert_header("x-error-message", "Entry not found"),
            )
            .mount(&up)
            .await;
        Mock::given(path("/org/gated/resolve/main/config.json"))
            .respond_with(ResponseTemplate::new(401).insert_header("x-error-code", "GatedRepo"))
            .mount(&up)
            .await;
        Mock::given(path("/org/model/resolve/main/broken.bin"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&up)
            .await;
        Mock::given(path("/org/model/resolve/main/loop.bin"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "/org/model/resolve/main/loop.bin"),
            )
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/missing.bin",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(header(&resp, "x-error-code"), "EntryNotFound");
        assert_eq!(header(&resp, "x-error-message"), "Entry not found");
        let resp = send(
            &ctx.app,
            Method::HEAD,
            "/hf/org/gated/resolve/main/config.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(header(&resp, "x-error-code"), "GatedRepo");
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/broken.bin",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/loop.bin",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn the_clients_credentials_stay_with_nora_on_every_hop() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/model.safetensors",
            vec![
                ("authorization", "Bearer hf_clienttoken"),
                ("cookie", "token=client"),
            ],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        for server in [&up, &cdn] {
            for r in server.received_requests().await.unwrap() {
                assert!(
                    r.headers.get("authorization").is_none() && r.headers.get("cookie").is_none()
                );
            }
        }
    }

    fn curated(up: &MockServer, rules: &str, mode: &str) -> (TestContext, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("list.json");
        std::fs::write(&file, rules).unwrap();
        let uri = up.uri();
        let file = file.to_string_lossy().into_owned();
        let mode = mode.to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.hf.enabled = true;
            cfg.hf.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            if mode == "allow" {
                cfg.curation.allowlist_path = Some(file);
            } else {
                cfg.curation.blocklist_path = Some(file);
            }
        });
        (ctx, dir)
    }

    #[tokio::test]
    async fn a_repo_rule_refuses_before_the_upstream_in_any_spelling() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        for rule_name in ["org/model", "ORG/Model"] {
            let rules = format!(
                r#"{{"version": 1, "rules": [{{"registry": "hf", "name": "{rule_name}", "version": "*", "reason": "r"}}]}}"#
            );
            let (ctx, _dir) = curated(&up, &rules, "block");
            for uri in [
                "/hf/org/model/resolve/main/config.json",
                "/hf/Org/MODEL/resolve/main/config.json",
            ] {
                let resp = send(&ctx.app, Method::GET, uri, "").await;
                assert_eq!(
                    resp.status(),
                    StatusCode::FORBIDDEN,
                    "rule {rule_name}, {uri}"
                );
            }
        }
        assert!(
            upstream_paths(&up).await.is_empty(),
            "a refused repo was fetched"
        );
    }

    #[tokio::test]
    async fn a_commit_rule_holds_for_the_branch_that_resolves_to_it() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let rules = format!(
            r#"{{"version": 1, "rules": [{{"registry": "hf", "name": "org/model", "version": "{COMMIT}", "reason": "r"}}]}}"#
        );
        let (ctx, _dir) = curated(&up, &rules, "block");
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/model.safetensors",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // Refused on the hop that names the commit, before the bytes are asked for.
        assert!(
            upstream_paths(&cdn).await.is_empty(),
            "bytes fetched for a refused commit"
        );
    }

    const ALIAS_PATH: &str = "/hf/gpt2/resolve/main/config.json";

    /// The Hub in the live shape for an alias: `api/models/gpt2` answers a relative redirect
    /// to the canonical id, which answers 200; the alias's file is answered directly.
    async fn hub_with_alias() -> MockServer {
        let up = MockServer::start().await;
        Mock::given(path("/api/models/gpt2"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", "/api/models/openai-community/gpt2"),
            )
            .mount(&up)
            .await;
        Mock::given(path("/api/models/openai-community/gpt2"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&up)
            .await;
        Mock::given(path("/gpt2/resolve/main/config.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(CONFIG.to_vec())
                    .insert_header("x-repo-commit", COMMIT)
                    .insert_header("etag", format!("\"{CONFIG_BLOB}\"").as_str()),
            )
            .mount(&up)
            .await;
        up
    }

    /// The methods of the canonical-id requests the upstream saw.
    async fn canonical_asks(up: &MockServer) -> Vec<String> {
        up.received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().starts_with("/api/models/"))
            .map(|r| r.method.to_string())
            .collect()
    }

    #[tokio::test]
    async fn a_rule_on_the_canonical_id_holds_for_an_alias() {
        let up = hub_with_alias().await;
        let rules = r#"{"version": 1, "rules": [{"registry": "hf", "name": "openai-community/gpt2", "version": "*", "reason": "r"}]}"#;
        let (ctx, _dir) = curated(&up, rules, "block");
        let resp = send(&ctx.app, Method::GET, ALIAS_PATH, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            hits(&up, "/resolve/main/config.json").await,
            0,
            "file asked for a refused repo"
        );
        let asks = canonical_asks(&up).await;
        assert!(
            !asks.is_empty() && asks.iter().all(|m| m == "HEAD"),
            "{asks:?}"
        );
    }

    #[tokio::test]
    async fn a_commit_rule_on_the_canonical_id_holds_for_an_alias() {
        let up = hub_with_alias().await;
        let rules = format!(
            r#"{{"version": 1, "rules": [{{"registry": "hf", "name": "openai-community/gpt2", "version": "{COMMIT}", "reason": "r"}}]}}"#
        );
        let (ctx, _dir) = curated(&up, &rules, "block");
        let resp = send(&ctx.app, Method::GET, ALIAS_PATH, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        settle().await;
        assert!(hf_keys(&ctx).await.is_empty());
    }

    /// An internal namespace refuses even with curation off, so the canonical id is asked then
    /// too.
    #[tokio::test]
    async fn an_internal_namespace_holds_for_an_alias_with_curation_off() {
        let up = hub_with_alias().await;
        let uri = up.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.hf.enabled = true;
            cfg.hf.proxy = Some(uri);
            cfg.curation.internal_namespaces = vec!["openai-community/gpt2".to_string()];
        });
        assert!(!ctx.state.curation().curation_engine.is_active());
        let resp = send(&ctx.app, Method::GET, ALIAS_PATH, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(hits(&up, "/resolve/main/config.json").await, 0);
    }

    /// With no rule that could refuse a name, no request is spent on the canonical id.
    #[tokio::test]
    async fn without_a_rule_to_read_no_canonical_id_is_asked() {
        let up = hub_with_alias().await;
        let ctx = hf_with_upstream(&up);
        let resp = send(&ctx.app, Method::GET, ALIAS_PATH, "").await;
        assert_eq!(received(resp).await, (CONFIG.to_vec(), true));
        assert!(canonical_asks(&up).await.is_empty());
    }

    #[tokio::test]
    async fn the_canonical_id_is_remembered() {
        let up = hub_with_alias().await;
        let rules = r#"{"version": 1, "rules": [{"registry": "hf", "name": "org/other", "version": "*", "reason": "r"}]}"#;
        let (ctx, _dir) = curated(&up, rules, "block");
        for _ in 0..2 {
            let resp = send(&ctx.app, Method::GET, ALIAS_PATH, "").await;
            assert_eq!(received(resp).await, (CONFIG.to_vec(), true));
        }
        assert_eq!(
            canonical_asks(&up).await.len(),
            2,
            "the alias and its target, once"
        );
    }

    /// Curation fails closed: without the canonical id the alias is refused, and a Hub refusal
    /// of the id is handed on; the file is never asked for.
    #[tokio::test]
    async fn without_the_canonical_id_the_alias_is_refused() {
        let other = MockServer::start().await;
        let cases: Vec<(ResponseTemplate, StatusCode)> = vec![
            (ResponseTemplate::new(500), StatusCode::BAD_GATEWAY),
            (
                ResponseTemplate::new(307).insert_header(
                    "location",
                    format!("{}/api/models/openai-community/gpt2", other.uri()).as_str(),
                ),
                StatusCode::BAD_GATEWAY,
            ),
            (
                ResponseTemplate::new(307).insert_header("location", "/elsewhere/gpt2"),
                StatusCode::BAD_GATEWAY,
            ),
            (
                ResponseTemplate::new(401)
                    .insert_header("x-error-code", "RepoNotFound")
                    .insert_header("x-error-message", "Repository not found"),
                StatusCode::UNAUTHORIZED,
            ),
        ];
        for (answer, expected) in cases {
            let up = MockServer::start().await;
            Mock::given(path("/api/models/gpt2"))
                .respond_with(answer)
                .mount(&up)
                .await;
            Mock::given(any())
                .respond_with(ResponseTemplate::new(200).set_body_bytes(CONFIG.to_vec()))
                .mount(&up)
                .await;
            let rules = r#"{"version": 1, "rules": [{"registry": "hf", "name": "org/other", "version": "*", "reason": "r"}]}"#;
            let (ctx, _dir) = curated(&up, rules, "block");
            let resp = send(&ctx.app, Method::GET, ALIAS_PATH, "").await;
            assert_eq!(resp.status(), expected);
            if expected == StatusCode::UNAUTHORIZED {
                assert_eq!(header(&resp, "x-error-code"), "RepoNotFound");
            } else {
                assert_eq!(header(&resp, "x-error-message"), CANONICAL_UNKNOWN);
            }
            assert_eq!(hits(&up, "/resolve/main/config.json").await, 0);
            assert!(upstream_paths(&other).await.is_empty());
        }
    }

    #[tokio::test]
    async fn an_allowlist_lets_through_only_the_listed_commit() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let allowed = format!(
            r#"{{"version": 1, "entries": [{{"registry": "hf", "name": "org/model", "version": "{COMMIT}"}}]}}"#
        );
        let (ctx, _dir) = curated(&up, &allowed, "allow");
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/config.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let other = r#"{"version": 1, "entries": [{"registry": "hf", "name": "org/model", "version": "ffffffffffffffffffffffffffffffffffffffff"}]}"#;
        let (ctx, _dir) = curated(&up, other, "allow");
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/config.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Nothing is cached in this slice: the same file asked twice is fetched twice, so a
    /// moved `main` is never served stale.
    const WEIGHTS_PATH: &str = "/hf/org/model/resolve/main/model.safetensors";
    const CONFIG_PATH: &str = "/hf/org/model/resolve/main/config.json";

    fn weights_key() -> String {
        format!("hf/models/org/model/blobs/{SHA256}")
    }

    fn config_key() -> String {
        format!("hf/models/org/model/blobs/{CONFIG_BLOB}")
    }

    /// A fill is committed by a task of its own once the body ends: wait for it, with a deadline.
    /// Committed means pinned — the object is visible a moment before its pin is recorded, and
    /// a copy without a pin is not served.
    async fn wait_stored(ctx: &TestContext, key: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !matches!(ctx.state.storage.get_reader(key).await, Ok((_, Some(_), _))) {
            assert!(tokio::time::Instant::now() < deadline, "{key} never stored");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A failed commit removes its temp file from its own task: wait for it, with a deadline.
    async fn wait_no_fill_temps(ctx: &TestContext) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while fill_temps(ctx) != 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "a fill temp file stayed behind"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Long enough for a fill task that should not exist to have run.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    /// What reached the client, and whether the body ended cleanly.
    async fn received(resp: Response) -> (Vec<u8>, bool) {
        let mut frames = resp.into_body().into_data_stream();
        let mut got = Vec::new();
        while let Some(frame) = frames.next().await {
            match frame {
                Ok(bytes) => got.extend_from_slice(&bytes),
                Err(_) => return (got, false),
            }
        }
        (got, true)
    }

    async fn hf_keys(ctx: &TestContext) -> Vec<String> {
        ctx.state.storage.list("hf/").await.unwrap_or_default()
    }

    /// Temp files of fills, finished or not.
    fn fill_temps(ctx: &TestContext) -> usize {
        std::fs::read_dir(std::path::Path::new(&ctx.state.config.storage.path).join(FILL_TEMP_DIR))
            .map(|dir| dir.count())
            .unwrap_or(0)
    }

    async fn hits(server: &MockServer, suffix: &str) -> usize {
        upstream_paths(server)
            .await
            .iter()
            .filter(|p| p.ends_with(suffix))
            .count()
    }

    /// The resolve answer goes upstream on every request — it names the commit and the digest,
    /// and curation reads the commit there — while the bytes of a cached file do not.
    #[tokio::test]
    async fn the_resolve_answer_is_asked_on_every_request() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        for round in 0..2 {
            let resp = send(&ctx.app, Method::GET, CONFIG_PATH, "").await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(body_bytes(resp).await.to_vec(), CONFIG);
            if round == 0 {
                wait_stored(&ctx, &config_key()).await;
            }
        }
        assert_eq!(hits(&up, "/resolve/main/config.json").await, 2);
        assert_eq!(hits(&up, &format!("/{COMMIT}/config.json")).await, 1);
    }

    #[tokio::test]
    async fn a_second_download_of_weights_comes_from_the_cache_not_the_cdn() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        let first = send(&ctx.app, Method::GET, WEIGHTS_PATH, "").await;
        assert_eq!(body_bytes(first).await.to_vec(), weights());
        wait_stored(&ctx, &weights_key()).await;

        let resp = send(&ctx.app, Method::GET, WEIGHTS_PATH, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, "x-repo-commit"), COMMIT);
        assert_eq!(header(&resp, "etag"), format!("\"{SHA256}\""));
        assert_eq!(header(&resp, "x-linked-etag"), format!("\"{SHA256}\""));
        assert_eq!(header(&resp, "x-linked-size"), "4112");
        assert_eq!(header(&resp, "content-length"), "4112");
        assert_no_leaked_headers(&resp);
        assert_eq!(received(resp).await, (weights(), true));
        assert_eq!(upstream_paths(&cdn).await.len(), 1, "the CDN is asked once");
        assert_eq!(hits(&up, "/resolve/main/model.safetensors").await, 2);
        assert_eq!(fill_temps(&ctx), 0);
    }

    #[tokio::test]
    async fn a_second_download_of_a_regular_file_comes_from_the_cache() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        let first = send(&ctx.app, Method::GET, CONFIG_PATH, "").await;
        assert_eq!(body_bytes(first).await.to_vec(), CONFIG);
        wait_stored(&ctx, &config_key()).await;

        let resp = send(&ctx.app, Method::GET, CONFIG_PATH, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, "x-repo-commit"), COMMIT);
        assert_eq!(header(&resp, "etag"), format!("\"{CONFIG_BLOB}\""));
        assert_eq!(header(&resp, "x-linked-size"), CONFIG.len().to_string());
        assert_eq!(received(resp).await, (CONFIG.to_vec(), true));
        assert_eq!(hits(&up, &format!("/{COMMIT}/config.json")).await, 1);
    }

    /// An upstream that answers the resolve request like the live Hub but sends `body` for
    /// the bytes: through the CDN for an LFS file, through the resolve cache for a regular one.
    async fn hub_sending(body: Vec<u8>) -> (MockServer, MockServer) {
        let cdn = MockServer::start().await;
        Mock::given(path("/xet-bridge/model.safetensors"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&cdn)
            .await;
        let up = live_hub(&cdn).await;
        Mock::given(path(
            format!("/api/resolve-cache/models/org/model/{COMMIT}/config.json").as_str(),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(body[..CONFIG.len()].to_vec())
                .insert_header("etag", format!("\"{CONFIG_BLOB}\"").as_str()),
        )
        .with_priority(1)
        .mount(&up)
        .await;
        (up, cdn)
    }

    /// One byte off, same length: the digest the Hub named does not match. The client gets
    /// the body one chunk short — never a complete download — and nothing is stored.
    #[tokio::test]
    async fn a_file_that_does_not_match_its_digest_ends_short_and_is_not_stored() {
        let mut corrupt = weights();
        corrupt[1] ^= 0x01;
        let (up, cdn) = hub_sending(corrupt).await;
        let ctx = hf_with_upstream(&up);
        for (route, len) in [(WEIGHTS_PATH, weights().len()), (CONFIG_PATH, CONFIG.len())] {
            let resp = send(&ctx.app, Method::GET, route, "").await;
            assert_eq!(resp.status(), StatusCode::OK);
            let (got, clean) = received(resp).await;
            assert!(!clean, "{route}: a corrupt file ended cleanly");
            assert!(
                got.len() < len,
                "{route}: all {len} bytes reached the client"
            );
        }
        settle().await;
        assert!(hf_keys(&ctx).await.is_empty(), "{:?}", hf_keys(&ctx).await);
        assert_eq!(fill_temps(&ctx), 0);
        // Nothing was kept, so the next download asks the CDN again.
        let _ = received(send(&ctx.app, Method::GET, WEIGHTS_PATH, "").await).await;
        assert_eq!(upstream_paths(&cdn).await.len(), 2);
    }

    /// A stored copy changed on disk under its pin ends one frame short, like raw's.
    #[tokio::test]
    async fn a_tampered_cached_copy_ends_short() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        let _ = body_bytes(send(&ctx.app, Method::GET, WEIGHTS_PATH, "").await).await;
        wait_stored(&ctx, &weights_key()).await;
        let mut tampered = weights();
        tampered[1] ^= 0x01;
        std::fs::write(
            std::path::Path::new(&ctx.state.config.storage.path).join(weights_key()),
            &tampered,
        )
        .unwrap();
        let resp = send(&ctx.app, Method::GET, WEIGHTS_PATH, "").await;
        let (got, clean) = received(resp).await;
        assert!(!clean, "a tampered copy ended cleanly");
        assert!(got.len() < weights().len());
        assert_eq!(upstream_paths(&cdn).await.len(), 1);
    }

    /// A client gone halfway leaves no stored copy and no temp file.
    #[tokio::test]
    async fn a_client_gone_mid_download_leaves_nothing_behind() {
        let mut big = b"FIXTURE-WEIGHTS-".to_vec();
        big.resize(8 << 20, 7);
        let digest = hex::encode(sha2::Sha256::digest(&big));
        let up = MockServer::start().await;
        let cdn = MockServer::start().await;
        Mock::given(path("/org/model/resolve/main/big.safetensors"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/big", cdn.uri()).as_str())
                    .insert_header("x-repo-commit", COMMIT)
                    .insert_header("x-linked-etag", format!("\"{digest}\"").as_str()),
            )
            .mount(&up)
            .await;
        Mock::given(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(big))
            .mount(&cdn)
            .await;
        let ctx = hf_with_upstream(&up);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/big.safetensors",
            "",
        )
        .await;
        let mut frames = resp.into_body().into_data_stream();
        assert!(matches!(frames.next().await, Some(Ok(_))));
        assert_eq!(fill_temps(&ctx), 1, "the fill was under way");
        drop(frames);
        settle().await;
        assert!(hf_keys(&ctx).await.is_empty());
        assert_eq!(fill_temps(&ctx), 0);
    }

    #[tokio::test]
    async fn a_range_on_a_cached_file_is_read_from_storage() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        let _ = body_bytes(send(&ctx.app, Method::GET, WEIGHTS_PATH, "").await).await;
        wait_stored(&ctx, &weights_key()).await;
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            WEIGHTS_PATH,
            vec![("range", "bytes=4100-")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(header(&resp, "content-range"), "bytes 4100-4111/4112");
        assert_eq!(header(&resp, "x-repo-commit"), COMMIT);
        assert_eq!(header(&resp, "etag"), format!("\"{SHA256}\""));
        assert_eq!(body_bytes(resp).await.to_vec(), weights()[4100..].to_vec());
        assert_eq!(upstream_paths(&cdn).await.len(), 1);
    }

    /// A range is part of a file, and a HEAD has no body: neither is stored.
    #[tokio::test]
    async fn a_range_or_a_head_never_fills_the_cache() {
        let up = MockServer::start().await;
        let cdn = MockServer::start().await;
        Mock::given(path("/org/model/resolve/main/model.safetensors"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/w", cdn.uri()).as_str())
                    .insert_header("x-repo-commit", COMMIT)
                    .insert_header("x-linked-etag", format!("\"{SHA256}\"").as_str())
                    .insert_header("x-linked-size", "4112"),
            )
            .mount(&up)
            .await;
        // A CDN that ignores the range and sends the whole file, as a 200: still not stored,
        // since the client asked for a part.
        Mock::given(path("/w"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(weights()))
            .mount(&cdn)
            .await;
        let ctx = hf_with_upstream(&up);
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            WEIGHTS_PATH,
            vec![("range", "bytes=0-")],
            "",
        )
        .await;
        let _ = body_bytes(resp).await;
        let resp = send(&ctx.app, Method::HEAD, WEIGHTS_PATH, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        settle().await;
        assert!(hf_keys(&ctx).await.is_empty());
        assert_eq!(fill_temps(&ctx), 0);
    }

    /// An etag that names no digest NORA can check: the file is passed through, unstored.
    #[tokio::test]
    async fn an_etag_that_names_no_digest_is_passed_through_unstored() {
        for etag in [
            "\"cce1\"",
            "W/\"302193440cfbfa05b83201c696ca7f96b95dbf75\"",
            "302193440cfbfa05b83201c696ca7f96b95dbf75",
        ] {
            let up = MockServer::start().await;
            Mock::given(path("/org/model/resolve/main/config.json"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_bytes(CONFIG.to_vec())
                        .insert_header("x-repo-commit", COMMIT)
                        .insert_header("etag", etag),
                )
                .mount(&up)
                .await;
            let ctx = hf_with_upstream(&up);
            for _ in 0..2 {
                let resp = send(&ctx.app, Method::GET, CONFIG_PATH, "").await;
                assert_eq!(received(resp).await, (CONFIG.to_vec(), true), "{etag}");
            }
            settle().await;
            assert!(hf_keys(&ctx).await.is_empty(), "{etag}");
            assert_eq!(hits(&up, "/config.json").await, 2, "{etag}");
        }
    }

    /// Storage that refuses the fill does not cost the client its file.
    #[tokio::test]
    async fn a_failed_store_still_serves_the_client() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        // A file where the key's directory would go: the commit fails.
        let blocked =
            std::path::Path::new(&ctx.state.config.storage.path).join("hf/models/org/model");
        std::fs::create_dir_all(&blocked).unwrap();
        std::fs::write(blocked.join("blobs"), b"in the way").unwrap();
        for _ in 0..2 {
            let resp = send(&ctx.app, Method::GET, WEIGHTS_PATH, "").await;
            assert_eq!(received(resp).await, (weights(), true));
        }
        wait_no_fill_temps(&ctx).await;
        assert_eq!(upstream_paths(&cdn).await.len(), 2);
    }

    /// The cache is per repo: the same digest in another repo is fetched for that repo.
    #[tokio::test]
    async fn the_cache_is_per_repo() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        Mock::given(path("/org/other/resolve/main/model.safetensors"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header(
                        "location",
                        format!("{}/xet-bridge/model.safetensors", cdn.uri()).as_str(),
                    )
                    .insert_header("x-repo-commit", COMMIT)
                    .insert_header("x-linked-etag", format!("\"{SHA256}\"").as_str()),
            )
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let _ = body_bytes(send(&ctx.app, Method::GET, WEIGHTS_PATH, "").await).await;
        wait_stored(&ctx, &weights_key()).await;
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/org/other/resolve/main/model.safetensors",
            "",
        )
        .await;
        assert_eq!(body_bytes(resp).await.to_vec(), weights());
        assert_eq!(upstream_paths(&cdn).await.len(), 2);
        wait_stored(&ctx, &format!("hf/models/org/other/blobs/{SHA256}")).await;
    }

    /// Curation reads the commit on the resolve answer before the cache is looked at: a rule
    /// on the commit refuses a file NORA already holds.
    #[tokio::test]
    async fn a_commit_rule_holds_for_a_cached_file() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let rules = format!(
            r#"{{"version": 1, "rules": [{{"registry": "hf", "name": "org/model", "version": "{COMMIT}", "reason": "r"}}]}}"#
        );
        let (ctx, _dir) = curated(&up, &rules, "block");
        let staged = std::path::Path::new(&ctx.state.config.storage.path).join("staged");
        std::fs::write(&staged, weights()).unwrap();
        ctx.state
            .storage
            .put_from_path(&weights_key(), &staged, Some(SHA256))
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, WEIGHTS_PATH, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(upstream_paths(&cdn).await.is_empty());
    }

    /// The Hub answers a legacy id's file directly, without a redirect; its etag names the
    /// file all the same, and the second download comes from the cache.
    #[tokio::test]
    async fn a_file_answered_without_a_redirect_is_cached_too() {
        let up = MockServer::start().await;
        Mock::given(path("/gpt2/resolve/main/config.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(CONFIG.to_vec())
                    .insert_header("x-repo-commit", COMMIT)
                    .insert_header("etag", format!("\"{CONFIG_BLOB}\"").as_str()),
            )
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        let route = "/hf/gpt2/resolve/main/config.json";
        let _ = body_bytes(send(&ctx.app, Method::GET, route, "").await).await;
        wait_stored(&ctx, &format!("hf/models/gpt2/blobs/{CONFIG_BLOB}")).await;
        let resp = send(&ctx.app, Method::GET, route, "").await;
        assert_eq!(header(&resp, "x-repo-commit"), COMMIT);
        assert_eq!(header(&resp, "accept-ranges"), "bytes");
        assert_eq!(received(resp).await, (CONFIG.to_vec(), true));
    }

    /// A stored copy without a pin cannot be checked, so it is not served: the file is fetched
    /// again and its fill replaces the copy with a pinned one.
    #[tokio::test]
    async fn an_unpinned_stored_copy_is_fetched_again_and_replaced() {
        let cdn = cdn_with_weights().await;
        let up = live_hub(&cdn).await;
        let ctx = hf_with_upstream(&up);
        let staged = std::path::Path::new(&ctx.state.config.storage.path).join("staged");
        std::fs::write(&staged, b"unpinned, unchecked").unwrap();
        ctx.state
            .storage
            .put_from_path(&weights_key(), &staged, None)
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, WEIGHTS_PATH, "").await;
        assert_eq!(received(resp).await, (weights(), true));
        assert_eq!(upstream_paths(&cdn).await.len(), 1);
        wait_stored(&ctx, &weights_key()).await;
        let (_, pin, _) = ctx.state.storage.get_reader(&weights_key()).await.unwrap();
        assert_eq!(pin.as_deref(), Some(SHA256));
    }

    /// The lookup settles on the first hop that names an etag, the one the response reports:
    /// an etag NORA cannot check there means no lookup, even if a later answer names a digest
    /// the cache holds.
    #[tokio::test]
    async fn the_first_named_etag_settles_the_lookup() {
        let up = MockServer::start().await;
        Mock::given(path("/org/model/resolve/main/config.json"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", "/cache/config.json")
                    .insert_header("x-repo-commit", COMMIT)
                    .insert_header("x-linked-etag", "\"cce1\""),
            )
            .mount(&up)
            .await;
        Mock::given(path("/cache/config.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(CONFIG.to_vec())
                    .insert_header("etag", format!("\"{CONFIG_BLOB}\"").as_str()),
            )
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        // Other bytes under the key the final answer names, pinned to themselves: served,
        // they would show that the lookup went past the hop that settled it.
        let other = b"not what the upstream sends";
        let staged = std::path::Path::new(&ctx.state.config.storage.path).join("staged");
        std::fs::write(&staged, other).unwrap();
        ctx.state
            .storage
            .put_from_path(
                &config_key(),
                &staged,
                Some(&hex::encode(sha2::Sha256::digest(other))),
            )
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, CONFIG_PATH, "").await;
        assert_eq!(header(&resp, "etag"), "\"cce1\"");
        assert_eq!(
            received(resp).await,
            (CONFIG.to_vec(), true),
            "served from a key the response does not name"
        );
    }

    /// The periodic sweep and the start remove fills that will not finish, and only those.
    #[test]
    fn stale_fill_temp_files_are_removed_and_fresh_ones_kept() {
        let dir = tempfile::tempdir().unwrap();
        let temps = dir.path().join(FILL_TEMP_DIR);
        std::fs::create_dir_all(&temps).unwrap();
        let stale = temps.join("stale.part");
        let fresh = temps.join("fresh.part");
        std::fs::write(&stale, b"cut off").unwrap();
        std::fs::write(&fresh, b"under way").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(
                std::time::SystemTime::now() - FILL_TEMP_MAX_AGE - Duration::from_secs(60),
            )
            .unwrap();
        cleanup_fill_temp_dir(dir.path().to_str().unwrap());
        assert!(!stale.exists());
        assert!(fresh.exists());
    }

    #[test]
    fn hub_digests_are_strong_hex_of_a_known_length() {
        let digest = |s: &str| hub_digest(&HeaderValue::from_str(s).unwrap());
        assert_eq!(
            digest(&format!("\"{SHA256}\"")),
            Some(HubDigest::Sha256(SHA256.into()))
        );
        assert_eq!(
            digest(&format!("\"{}\"", SHA256.to_uppercase())),
            Some(HubDigest::Sha256(SHA256.into()))
        );
        assert_eq!(
            digest(&format!("\"{CONFIG_BLOB}\"")),
            Some(HubDigest::GitBlob(CONFIG_BLOB.into()))
        );
        for refused in [
            SHA256.to_string(),
            format!("W/\"{SHA256}\""),
            format!("\"{}\"", &SHA256[..63]),
            format!("\"{}g\"", &SHA256[..63]),
            format!("\"{CONFIG_BLOB}0\""),
            "\"\"".to_string(),
            "\"cce1\"".to_string(),
        ] {
            assert_eq!(digest(&refused), None, "{refused}");
        }
    }

    #[test]
    fn cache_keys_take_only_ids_the_hub_serves() {
        let d = HubDigest::Sha256(SHA256.into());
        assert_eq!(
            cache_key("org/model", &d),
            Some(format!("hf/models/org/model/blobs/{SHA256}"))
        );
        assert_eq!(
            cache_key("Org/Model", &d),
            Some(format!("hf/models/org/model/blobs/{SHA256}"))
        );
        assert_eq!(
            cache_key("gpt2", &d),
            Some(format!("hf/models/gpt2/blobs/{SHA256}"))
        );
        assert_eq!(
            cache_key("o-r_g.1/m-o_d.2", &d),
            Some(format!("hf/models/o-r_g.1/m-o_d.2/blobs/{SHA256}"))
        );
        for refused in [
            "",
            "a/b/c",
            "/model",
            "org/",
            "org/.model",
            "org/-model",
            "org/mo..del",
            "org/mo del",
            "org/mödel",
            "org/mo%2Fdel",
            ".nora-meta/x",
        ] {
            assert_eq!(cache_key(refused, &d), None, "{refused:?}");
        }
    }

    /// The git blob digest of a regular file, as git and the Hub compute it.
    #[tokio::test]
    async fn a_regular_file_is_checked_by_its_git_blob_digest() {
        let ctx = hf_enabled();
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello\n".to_vec()))
            .mount(&up)
            .await;
        let body = reqwest::get(up.uri()).await.unwrap();
        let meta = FileMeta {
            etag: Some(HeaderValue::from_static(
                "\"ce013625030ba8dba906f756967f9e9ca394464a\"",
            )),
            ..FileMeta::default()
        };
        let fill = plan_fill(&ctx.state, "org/model", &meta, Some(&body))
            .await
            .unwrap();
        let resp = file_response(
            StatusCode::OK,
            &meta,
            Some(body),
            Duration::from_secs(5),
            Some(fill),
        );
        assert_eq!(received(resp).await, (b"hello\n".to_vec(), true));
        wait_stored(
            &ctx,
            "hf/models/org/model/blobs/ce013625030ba8dba906f756967f9e9ca394464a",
        )
        .await;
    }

    #[test]
    fn file_requests_are_read_as_the_hub_routes_them() {
        fn ok(rest: &str) -> Option<(&str, &str, &str)> {
            parse_file_request(rest).map(|r| (r.repo, r.revision, r.file))
        }
        assert_eq!(
            ok("org/model/resolve/main/config.json"),
            Some(("org/model", "main", "config.json"))
        );
        assert_eq!(
            ok("org/model/resolve/refs%2Fpr%2F1/a/b.bin"),
            Some(("org/model", "refs%2Fpr%2F1", "a/b.bin"))
        );
        assert_eq!(
            ok("gpt2/resolve/main/config.json"),
            Some(("gpt2", "main", "config.json"))
        );
        // A repo named `resolve` under an org is the canonical form, not a legacy id.
        assert_eq!(
            ok("org/resolve/resolve/main/f"),
            Some(("org/resolve", "main", "f"))
        );
        assert_eq!(ok("gpt2/resolve/resolve/f"), Some(("gpt2", "resolve", "f")));
        for bad in [
            "org/model/blob/main/f",
            "org/model/resolve/main",
            "org/model/resolve/main/",
            "org//model/resolve/main/f",
            "org/model/resolve/main/../f",
            "org/model/resolve/main/%2e%2e/f",
            "org/model/resolve/main/f%zz",
            "",
            "org/model/resolve/main/f g",
        ] {
            assert_eq!(ok(bad), None, "{bad:?}");
        }
    }

    // ── the pure rules ─────────────────────────────────────────────────────────

    #[test]
    fn xet_keys_go_at_any_depth_and_nothing_else_does() {
        let mut v = json!({"a": 1, "xetHash": "h", "xetEnabled": true, "lfs": {}, "b": [{"xetHash": "h", "c": {"lfs": 1, "d": 2, "xetSize": 3}}], "e": "xetHash"});
        strip_xet_metadata(&mut v);
        assert_eq!(
            v,
            json!({"a": 1, "xetEnabled": true, "lfs": {}, "b": [{"c": {"lfs": 1, "d": 2, "xetSize": 3}}], "e": "xetHash"})
        );
        let mut nested = json!([[{"xetHash": "h", "k": 1}], [[[{"xetHash": "h"}]]], {"a": [[{"xetHash": "h"}]]}]);
        strip_xet_metadata(&mut nested);
        assert_eq!(nested, json!([[{"k": 1}], [[[{}]]], {"a": [[{}]]}]));
    }

    /// Every shape up to depth five, objects and arrays in every order: no `xetHash` is left
    /// anywhere, and everything else is kept.
    #[test]
    fn xet_keys_go_from_every_shape() {
        fn build(depth: u32, seed: u32) -> Value {
            if depth == 0 {
                return json!(seed);
            }
            let child = |n: u32| build(depth - 1, seed.wrapping_mul(31).wrapping_add(n));
            if seed.is_multiple_of(2) {
                json!([child(1), child(2), {"xetHash": "h", "inner": child(3)}])
            } else {
                json!({"xetHash": "h", "keep": child(1), "list": [child(2), [child(3)]]})
            }
        }
        fn has_xet(v: &Value) -> bool {
            match v {
                Value::Object(m) => m.contains_key(XET_BODY_KEY) || m.values().any(has_xet),
                Value::Array(a) => a.iter().any(has_xet),
                _ => false,
            }
        }
        fn without_xet(v: &Value) -> Value {
            match v {
                Value::Object(m) => Value::Object(
                    m.iter()
                        .filter(|(k, _)| k.as_str() != XET_BODY_KEY)
                        .map(|(k, v)| (k.clone(), without_xet(v)))
                        .collect(),
                ),
                Value::Array(a) => Value::Array(a.iter().map(without_xet).collect()),
                other => other.clone(),
            }
        }
        for depth in 1..=5 {
            for seed in 0..8 {
                let original = build(depth, seed);
                let mut stripped = original.clone();
                strip_xet_metadata(&mut stripped);
                assert!(!has_xet(&stripped), "depth {depth} seed {seed}");
                assert_eq!(
                    stripped,
                    without_xet(&original),
                    "depth {depth} seed {seed}"
                );
            }
        }
    }

    const UP: &str = "https://huggingface.co";
    const NORA_HF: &str = "http://nora:4000/hf";

    #[test]
    fn links_are_moved_under_the_mount_by_relation() {
        let cases: &[(&str, Option<&str>)] = &[
            ("<https://huggingface.co/api/x?c=1>; rel=\"next\"", Some("<http://nora:4000/hf/api/x?c=1>; rel=\"next\"")),
            ("</api/x?c=1>; rel=\"next\"", Some("<http://nora:4000/hf/api/x?c=1>; rel=\"next\"")),
            ("<https://huggingface.co/api/x>; rel=next", Some("<http://nora:4000/hf/api/x>; rel=next")),
            ("<https://huggingface.co/api/t>; rel=\"xet-auth\"", None),
            ("<https://huggingface.co/api/t>; rel=xet-auth", None),
            ("<https://huggingface.co/api/t>; rel='xet-auth'", None),
            ("<https://huggingface.co/api/t>; REL=\"Xet-Auth\"", None),
            ("<https://cas.example/r>; rel=\"xet-reconstruction-info\"", None),
            // White list: only pages are handed on, everything else is dropped.
            ("<https://huggingface.co/api/x>", None),
            ("<https://huggingface.co/api/x>; rel=\"alternate\"", None),
            ("<https://elsewhere.example/x>; rel=\"describedby\"", None),
            ("<https://huggingface.co/api/x>; rel = \"next\"", Some("<http://nora:4000/hf/api/x>; rel = \"next\"")),
            ("<https://huggingface.co/api/x>; rel=\" next \"", Some("<http://nora:4000/hf/api/x>; rel=\" next \"")),
            ("<https://huggingface.co/api/x>; rel=\"NEXT\"", Some("<http://nora:4000/hf/api/x>; rel=\"NEXT\"")),
            ("<https://huggingface.co/api/x>; rel=\"next prev\"", Some("<http://nora:4000/hf/api/x>; rel=\"next prev\"")),
            ("<https://huggingface.co/api/x>; type=\"a\"; rel=\"last\"", Some("<http://nora:4000/hf/api/x>; type=\"a\"; rel=\"last\"")),
            (
                "<https://huggingface.co/api/t>; rel=\"xet-auth\", <https://huggingface.co/api/x?a=1,2>; rel=\"next\"",
                Some("<http://nora:4000/hf/api/x?a=1,2>; rel=\"next\""),
            ),
        ];
        for (input, want) in cases {
            assert_eq!(
                rewrite_link(input, UP, NORA_HF),
                Ok(want.map(str::to_string)),
                "{input}"
            );
        }
        assert_eq!(
            rewrite_link(
                "<https://huggingface.co/api/x>; rel=\"next\"",
                "https://huggingface.co/",
                NORA_HF
            ),
            Ok(Some("<http://nora:4000/hf/api/x>; rel=\"next\"".into()))
        );
    }

    /// A page beside another relation in one entry can be neither handed on (an RFC reader
    /// sees the other relation; requests and httpx keep the last `rel`) nor dropped (the
    /// listing would stop short).
    #[test]
    fn a_page_mixed_with_another_relation_is_refused() {
        for input in [
            "<https://huggingface.co/api/x>; rel=\"next xet-auth\"",
            "<https://huggingface.co/api/x>; rel=\"next\"; rel=\"xet-auth\"",
            "<https://huggingface.co/api/x>; rel=\"xet-auth\"; rel=\"next\"",
            "<https://huggingface.co/api/x>; rel=next; REL = 'alternate'",
            "garbage",
            "<https://huggingface.co/api/x; rel=\"next\"",
        ] {
            assert_eq!(
                rewrite_link(input, UP, NORA_HF),
                Err(LinkRefusal::Unreadable),
                "{input}"
            );
        }
    }

    #[test]
    fn a_link_that_would_leave_nora_is_refused() {
        for input in [
            "<https://elsewhere.example/api/x>; rel=\"next\"",
            "<//elsewhere.example/api/x>; rel=\"next\"",
            "<https://huggingface.co.evil.example/api/x>; rel=\"next\"",
            "<https://huggingface.coffee/api/x>; rel=\"next\"",
            "<http://huggingface.co/api/x>; rel=\"next\"",
            "<https://elsewhere.example/api/x>; rel=\"prev\"",
        ] {
            assert_eq!(
                rewrite_link(input, UP, NORA_HF),
                Err(LinkRefusal::Foreign),
                "{input}"
            );
        }
    }

    #[test]
    fn metadata_paths_go_upstream_verbatim_or_not_at_all() {
        let ok = |rest: &str, q: Option<&str>| models_api_upstream(UP, rest, q);
        assert_eq!(
            ok("org/m/revision/refs%2Fpr%2F1", None),
            Ok(format!("{UP}/api/models/org/m/revision/refs%2Fpr%2F1"))
        );
        assert_eq!(
            ok("org/m/tree/main", Some("recursive=true&expand=false")),
            Ok(format!(
                "{UP}/api/models/org/m/tree/main?recursive=true&expand=false"
            ))
        );
        assert_eq!(ok("gpt2", None), Ok(format!("{UP}/api/models/gpt2")));
        for rest in [
            "org/m/xet-read-token/main",
            "org/m/Xet-Read-Token/main",
            "org/m/xet%2dread-token/main",
            "org/m/%78et-read-token/main",
            "org/m/xet-write-token/main",
            "org/m/xet-write-token",
            "gpt2/xet-read-token/main",
        ] {
            assert_eq!(ok(rest, None), Err(Refusal::XetRoute), "{rest}");
        }
        // Repos on the live Hub whose id starts with or holds `xet-` are plain repos.
        for rest in [
            "xet-team/SmolVLM-256M-Instruct-test",
            "xet-team/SmolVLM-256M-Instruct-test/tree/main",
            "celinah/xet-experiments/revision/main",
            "julien-c/xet-feb14",
            "org/pixet-model",
            "org/m/tree/main/xet-notes",
            "xet-read-token",
        ] {
            assert_eq!(
                ok(rest, None),
                Ok(format!("{UP}/api/models/{rest}")),
                "{rest}"
            );
        }
        for rest in [
            "",
            "org//m",
            "org/m/",
            "org/./m",
            "org/%2E%2E/m",
            "org/m%",
            "org/m%4",
            "org/m%zz",
            "org/m n",
            "org/m\\x",
            "org/m\"x",
            &"a".repeat(3000),
        ] {
            assert_eq!(ok(rest, None), Err(Refusal::BadPath), "{rest:?}");
        }
        assert_eq!(ok("org/m", Some("a=b c")), Err(Refusal::BadPath));
        for q in ["a=%zz", "a=%4", "a=%"] {
            assert_eq!(ok("org/m", Some(q)), Err(Refusal::BadPath), "{q}");
        }
        assert_eq!(
            ok("org/m", Some("a=%41")),
            Ok(format!("{UP}/api/models/org/m?a=%41"))
        );
        assert_eq!(ok("org/m", Some(&"a".repeat(3000))), Err(Refusal::BadPath));
    }

    /// Every ASCII byte, in a segment and in a query, against RFC 3986 written out here rather
    /// than read from the code under test: `pchar` in a segment, `pchar` and `/` `?` in a
    /// query, `%` only as the start of an escape. Non-ASCII is refused too.
    #[test]
    fn every_byte_is_judged_by_rfc_3986() {
        const PCHAR: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@";
        for b in 0u8..128 {
            let c = (b as char).to_string();
            if b == b'/' || b == b'%' {
                continue;
            }
            let segment_ok = PCHAR.contains(&b);
            assert_eq!(
                models_api_upstream(UP, &format!("org/a{c}b"), None).is_ok(),
                segment_ok,
                "segment byte {b:#04x}"
            );
            let query_ok = segment_ok || b == b'?';
            assert_eq!(
                models_api_upstream(UP, "org/m", Some(&format!("a=x{c}y"))).is_ok(),
                query_ok,
                "query byte {b:#04x}"
            );
        }
        assert!(models_api_upstream(UP, "org/m", Some("a=x/y")).is_ok());
        for bad in [
            "a=%", "a=%4", "a=%4z", "a=%z4", "a=%zz", "a=%%41", "a=é", "a=%41%",
        ] {
            assert_eq!(
                models_api_upstream(UP, "org/m", Some(bad)),
                Err(Refusal::BadPath),
                "{bad}"
            );
        }
        for bad in ["org/%", "org/%4", "org/%4z", "org/%z4", "org/é"] {
            assert_eq!(
                models_api_upstream(UP, bad, None),
                Err(Refusal::BadPath),
                "{bad}"
            );
        }
        for good in ["a=%41", "a=%4a%4A", "a=x&b=%2F"] {
            assert!(
                models_api_upstream(UP, "org/m", Some(good)).is_ok(),
                "{good}"
            );
        }
    }
}
