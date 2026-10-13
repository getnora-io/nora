// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Hugging Face Hub pull-through proxy (#579), skeleton.
//!
//! The routes are the part of the Hub's HTTP surface that `huggingface_hub` uses to
//! download a model:
//!   GET       /hf/api/models/{org}/{name}[/revision/{rev}]   — commit and file list
//!   GET       /hf/api/models/{org}/{name}/tree/{rev}[/{path}] — listing on a cold client cache
//!   HEAD, GET /hf/{org}/{name}/resolve/{rev}/{file}            — one file
//! Every route answers 501 until the download path lands. Datasets answer 501 as well:
//! only models are in scope for the first release.
//!
//! Client:
//!   HF_ENDPOINT=http://nora:4000/hf hf download org/model

use crate::AppState;
use axum::{
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};

/// `huggingface_hub` reads the reason for a failed request from this header when the
/// response has no body, which is the case for the HEAD it sends first for every file.
const ERROR_MESSAGE_HEADER: HeaderName = HeaderName::from_static("x-error-message");

const MODELS_NOT_IMPLEMENTED: &str =
    "The Hugging Face proxy is not implemented in this NORA build yet.";
const DATASETS_NOT_IMPLEMENTED: &str =
    "Hugging Face datasets are not implemented in this NORA build: only models are in scope.";

pub fn routes() -> Router<AppState> {
    // `get` answers HEAD as well.
    Router::new()
        .route("/hf/api/models/{org}/{name}", get(models))
        .route(
            "/hf/api/models/{org}/{name}/revision/{revision}",
            get(models),
        )
        .route("/hf/api/models/{org}/{name}/tree/{revision}", get(models))
        .route(
            "/hf/api/models/{org}/{name}/tree/{revision}/{*path}",
            get(models),
        )
        .route("/hf/{org}/{name}/resolve/{revision}/{*file}", get(models))
        .route("/hf/api/datasets/{*rest}", get(datasets))
        .route("/hf/datasets/{*rest}", get(datasets))
}

async fn models() -> Response {
    not_implemented(MODELS_NOT_IMPLEMENTED)
}

async fn datasets() -> Response {
    not_implemented(DATASETS_NOT_IMPLEMENTED)
}

fn not_implemented(message: &'static str) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        [(ERROR_MESSAGE_HEADER, HeaderValue::from_static(message))],
        Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{DATASETS_NOT_IMPLEMENTED, MODELS_NOT_IMPLEMENTED};
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    fn hf_enabled() -> crate::test_helpers::TestContext {
        create_test_context_with_config(|cfg| cfg.hf.enabled = true)
    }

    /// Every request a model download makes, in the shapes the real client sends them.
    const MODEL_DOWNLOAD_REQUESTS: &[(&str, &str)] = &[
        ("GET", "/hf/api/models/org/model"),
        ("GET", "/hf/api/models/org/model/revision/main"),
        (
            "GET",
            "/hf/api/models/org/model/tree/0123456789abcdef0123456789abcdef01234567?recursive=true&expand=false",
        ),
        ("GET", "/hf/api/models/org/model/tree/main/sub/dir"),
        ("HEAD", "/hf/org/model/resolve/main/config.json"),
        ("GET", "/hf/org/model/resolve/main/config.json"),
        ("GET", "/hf/org/model/resolve/main/sub/dir/model.safetensors"),
        // `--revision refs/pr/1` arrives percent-encoded. Only reachability is asserted
        // here: a decoded path would also land on the resolve route.
        ("HEAD", "/hf/org/model/resolve/refs%2Fpr%2F1/config.json"),
        ("GET", "/hf/api/models/org/model/revision/refs%2Fconvert%2Fparquet"),
    ];

    fn method(m: &str) -> Method {
        Method::from_bytes(m.as_bytes()).unwrap()
    }

    #[tokio::test]
    async fn every_model_download_route_answers_501_not_404() {
        let ctx = hf_enabled();
        for (m, uri) in MODEL_DOWNLOAD_REQUESTS {
            let resp = send(&ctx.app, method(m), uri, "").await;
            assert_eq!(
                resp.status(),
                StatusCode::NOT_IMPLEMENTED,
                "{m} {uri} must reach the hf skeleton"
            );
            // Exactly the model reason, in the header and in the body: a model path given
            // the datasets answer would tell the client its model is out of scope.
            assert_eq!(
                reason_of(resp, m).await,
                (
                    MODELS_NOT_IMPLEMENTED.to_string(),
                    MODELS_NOT_IMPLEMENTED.to_string()
                ),
                "{m} {uri}"
            );
        }
    }

    /// The reason a 501 gives in `X-Error-Message`, and in the JSON body for a GET (HEAD has
    /// no body; the header alone is checked twice then).
    async fn reason_of(resp: axum::response::Response, m: &str) -> (String, String) {
        let header = resp
            .headers()
            .get("x-error-message")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        if m == "HEAD" {
            return (header.clone(), header);
        }
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes(resp).await).unwrap_or_default();
        (
            header,
            body["error"].as_str().unwrap_or_default().to_string(),
        )
    }

    /// The skeleton fetches and caches nothing, whatever form an upstream call would take.
    #[tokio::test]
    async fn the_skeleton_contacts_no_upstream() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&up)
            .await;
        let uri = up.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.hf.enabled = true;
            cfg.hf.proxy = Some(uri);
        });
        for (m, uri) in MODEL_DOWNLOAD_REQUESTS {
            send(&ctx.app, method(m), uri, "").await;
        }
        let sent = crate::test_helpers::upstream_paths(&up).await;
        assert!(sent.is_empty(), "the skeleton went upstream: {sent:?}");
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
        let header = resp
            .headers()
            .get("x-error-message")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(header.contains("not implemented"), "header: {header:?}");

        let resp = send(
            &ctx.app,
            Method::GET,
            "/hf/api/models/org/model/revision/main",
            "",
        )
        .await;
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes(resp).await).expect("JSON body");
        let error = body["error"].as_str().unwrap_or_default();
        assert!(error.contains("not implemented"), "body: {body}");
    }

    #[tokio::test]
    async fn datasets_answer_501_with_their_own_reason() {
        let ctx = hf_enabled();
        for (m, uri) in [
            ("GET", "/hf/api/datasets/org/data/revision/main"),
            ("HEAD", "/hf/datasets/org/data/resolve/main/train.parquet"),
            ("GET", "/hf/datasets/org/data/resolve/main/train.parquet"),
        ] {
            let resp = send(&ctx.app, method(m), uri, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED, "{m} {uri}");
            assert_eq!(
                reason_of(resp, m).await,
                (
                    DATASETS_NOT_IMPLEMENTED.to_string(),
                    DATASETS_NOT_IMPLEMENTED.to_string()
                ),
                "{m} {uri}"
            );
        }
    }

    #[tokio::test]
    async fn disabled_by_default_and_then_not_mounted() {
        let ctx = create_test_context_with_config(|_| {});
        assert!(!ctx.state.config.hf.enabled, "hf must be opt-in");
        for (m, uri) in MODEL_DOWNLOAD_REQUESTS {
            let resp = send(&ctx.app, method(m), uri, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{m} {uri}");
        }
    }

    #[tokio::test]
    async fn health_lists_hf_only_when_enabled() {
        let registries = |ctx: crate::test_helpers::TestContext| async move {
            let resp = send(&ctx.app, Method::GET, "/health", "").await;
            let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
            body["registries"].as_object().cloned().unwrap_or_default()
        };
        assert!(registries(hf_enabled()).await.contains_key("hf"));
        assert!(!registries(create_test_context_with_config(|_| {}))
            .await
            .contains_key("hf"));
    }
}
