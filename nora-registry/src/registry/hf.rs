// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Hugging Face Hub pull-through proxy (#579).
//!
//!   GET       /hf/api/models/{...}                  — metadata: model info, revision, tree
//!                                                     listing, passed through without Xet
//!   HEAD, GET /hf/{org}/{name}/resolve/{rev}/{file}  — one file; 501 until the download
//!                                                     path lands
//! Datasets answer 501: only models are in scope for the first release.
//!
//! Xet is never proxied and never advertised. `huggingface_hub` takes the Xet path only when
//! a response hands it a Xet hash: `X-Xet-Hash` beside `Link rel="xet-auth"` on `resolve`, or
//! `xetHash` on a tree-listing entry it has cached — with that, it skips the HEAD call and
//! asks for a Xet read token, which would send it to the Xet storage around NORA. Metadata
//! therefore loses those keys at any depth, and only listed headers reach the client.
//!
//! The client's own credentials are never sent upstream: the first release serves public
//! repositories only.
//!
//! Client:
//!   HF_ENDPOINT=http://nora:4000/hf hf download org/model

use crate::registry::{circuit_open_response, nora_base_url, proxy_fetch_with_headers, ProxyError};
use crate::registry_type::RegistryType;
use crate::AppState;
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::Value;
use std::time::Duration;

/// `huggingface_hub` reads the reason for a failed request from this header when the
/// response has no body, which is the case for the HEAD it sends first for every file.
const ERROR_MESSAGE_HEADER: HeaderName = HeaderName::from_static("x-error-message");
const REPO_COMMIT_HEADER: HeaderName = HeaderName::from_static("x-repo-commit");

const FILES_NOT_IMPLEMENTED: &str =
    "Downloading files through the Hugging Face proxy is not implemented in this NORA build yet.";
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

pub fn routes() -> Router<AppState> {
    // `get` answers HEAD as well; anything else is 405.
    Router::new()
        .route("/hf/api/models/{*rest}", get(models_api))
        .route("/hf/{org}/{name}/resolve/{revision}/{*file}", get(resolve))
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

async fn resolve() -> Response {
    error_response(StatusCode::NOT_IMPLEMENTED, FILES_NOT_IMPLEMENTED)
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

    /// The reasons a client reads, as text: compared with the constants, an aliased or
    /// swapped constant would pass.
    const FILES_REASON: &str =
        "Downloading files through the Hugging Face proxy is not implemented in this NORA build yet.";
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

    // ── the file routes stay a skeleton in this slice ──────────────────────────

    #[tokio::test]
    async fn every_resolve_route_answers_501_not_404() {
        let ctx = hf_enabled();
        for (m, uri) in RESOLVE_REQUESTS {
            let resp = send(&ctx.app, verb(m), uri, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED, "{m} {uri}");
            // Exactly the file reason, in the header and in the body: a model path given
            // the datasets answer would tell the client its model is out of scope.
            assert_eq!(
                reason_of(resp, m).await,
                (FILES_REASON.to_string(), FILES_REASON.to_string()),
                "{m} {uri}"
            );
        }
    }

    /// Files are not served yet, and nothing about them is fetched, whatever form an
    /// upstream call would take.
    #[tokio::test]
    async fn the_file_routes_contact_no_upstream() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&up)
            .await;
        let ctx = hf_with_upstream(&up);
        for (m, uri) in RESOLVE_REQUESTS {
            send(&ctx.app, verb(m), uri, "").await;
        }
        let sent = upstream_paths(&up).await;
        assert!(sent.is_empty(), "a file route went upstream: {sent:?}");
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
    async fn the_501_says_why_in_the_body_and_in_a_header() {
        let ctx = hf_enabled();
        // HEAD carries no body, and HEAD is what the client sends first for every file, so
        // the reason also travels in the header the client reads for its error message.
        let resp = send(
            &ctx.app,
            Method::HEAD,
            "/hf/org/model/resolve/main/config.json",
            "",
        )
        .await;
        assert!(header(&resp, "x-error-message").contains("not implemented"));
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/org/model/resolve/main/config.json",
            "",
        )
        .await;
        let body = json_of(resp).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("not implemented"),
            "{body}"
        );
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
