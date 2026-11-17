// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! A request the object store left unanswered is answered "storage unavailable" (#1182).
//!
//! The storage layer notes on the request when the store did not answer a read in time or
//! failed in transport (see `storage::answer`). Handlers make of such a failure what they make
//! of any: a 404 when a lookup came back empty, a 500 or 502 when a read failed. Here, once the
//! handler has answered, such a response is replaced by 503 with `Retry-After`: a client must
//! not take a store that did not answer for an artifact that is not there, and retries.
//! Every other status passes, so an upstream answer a proxy served (2xx), a redirect, an auth
//! refusal, a conflict or a rate limit stays what it was. A handler that never needed the
//! store is never affected.

use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The statuses a handler gives a store that did not answer: an empty lookup, a failed read.
const REPLACED: [StatusCode; 3] = [
    StatusCode::NOT_FOUND,
    StatusCode::INTERNAL_SERVER_ERROR,
    StatusCode::BAD_GATEWAY,
];

/// Seconds a client is asked to wait before it retries.
const RETRY_AFTER_SECS: &str = "30";

/// The answer to a request the store left unanswered. It names neither the object nor the
/// store.
fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, RETRY_AFTER_SECS)],
        "storage unavailable, retry later\n",
    )
        .into_response()
}

/// Runs the request with its note of the store's answers, and answers 503 for it when the
/// store left it unanswered and the handler answered 404, 500 or 502. One warning per such
/// request.
pub(crate) async fn unanswered_store_middleware(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let (response, unanswered) = crate::storage::answer::scope(next.run(request)).await;
    if !unanswered || !REPLACED.contains(&response.status()) {
        return response;
    }
    tracing::warn!(
        %method,
        %path,
        status = response.status().as_u16(),
        "object store did not answer; answered 503"
    );
    unavailable()
}

#[cfg(test)]
mod tests {
    use crate::storage::Storage;
    use crate::test_helpers::*;
    use axum::http::{header, Method, StatusCode};
    use std::time::Duration;
    use wiremock::matchers::{any, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The answer timeout of these tests.
    const ANSWER: Duration = Duration::from_millis(500);
    /// Well inside what a request takes against a store that does not answer, were it waited
    /// for: the client retries a stalled request for an hour.
    const PROMPTLY: Duration = Duration::from_secs(5);

    /// An S3 store that takes every request and does not answer within any test.
    async fn stalled_store() -> MockServer {
        let store = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(600)))
            .mount(&store)
            .await;
        store
    }

    /// An S3 store that answers every read "no such key" and every listing with an empty page.
    async fn empty_store() -> MockServer {
        let store = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wiremock::matchers::query_param("list-type", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>b</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>",
            ))
            .mount(&store)
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404).set_body_string(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code></Error>",
            ))
            .mount(&store)
            .await;
        store
    }

    fn s3(store: &MockServer, answer: Option<Duration>) -> Storage {
        let storage = Storage::new_s3(&store.uri(), "b", "us-east-1", None, None, false, &[]);
        storage.set_answer_timeout(answer);
        storage
    }

    /// `send`, failing the test when the answer takes longer than a store left unanswered may.
    async fn ask(
        app: &axum::Router,
        verb: Method,
        path: &str,
    ) -> axum::http::Response<axum::body::Body> {
        // CANCEL-SAFETY: a request of a test; dropped at the deadline, the test fails anyway.
        tokio::time::timeout(PROMPTLY, send(app, verb.clone(), path, ""))
            .await
            .unwrap_or_else(|_| panic!("{verb} {path} waited for the store"))
    }

    async fn writes_to(store: &MockServer) -> usize {
        store
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| {
                r.method == wiremock::http::Method::PUT || r.method == wiremock::http::Method::POST
            })
            .count()
    }

    /// A hosted artifact of a store that does not answer is "storage unavailable", promptly,
    /// with `Retry-After`, and the answer names neither the artifact nor the store: never the
    /// 404 a client would take as "there is no such artifact".
    #[tokio::test]
    async fn a_hosted_artifact_of_a_store_that_does_not_answer_is_503_not_404() {
        let store = stalled_store().await;
        let ctx = create_test_context_with_storage(s3(&store, Some(ANSWER)));
        for (verb, path) in [
            (Method::GET, "/raw/team/report-2026.txt"),
            (Method::HEAD, "/raw/team/report-2026.txt"),
            (Method::GET, "/npm/internal-pkg"),
            (Method::GET, "/simple/internal-pkg/"),
            (
                Method::HEAD,
                "/v2/team/app/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            // CANCEL-SAFETY: reads only.
            let resp = tokio::time::timeout(PROMPTLY, send(&ctx.app, verb.clone(), path, ""))
                .await
                .unwrap_or_else(|_| panic!("{verb} {path} waited for the store"));
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{verb} {path}");
            assert_eq!(resp.headers()[header::RETRY_AFTER], "30", "{verb} {path}");
            let body = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
            for named in ["report-2026", "internal-pkg", "team", "127.0.0.1", &store.uri()] {
                assert!(!body.contains(named), "{verb} {path}: {body}");
            }
        }
    }

    /// The control: an artifact a store that answers does not hold is still 404.
    #[tokio::test]
    async fn a_hosted_artifact_a_store_answers_it_does_not_hold_is_404() {
        let store = empty_store().await;
        let ctx = create_test_context_with_storage(s3(&store, Some(ANSWER)));
        for path in ["/raw/team/report-2026.txt", "/npm/internal-pkg"] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    /// A publish to a store that does not answer is 503 too, and its body is taken in: the
    /// client gets its answer instead of a broken connection.
    #[tokio::test]
    async fn a_publish_to_a_store_that_does_not_answer_is_503() {
        let store = stalled_store().await;
        let ctx = create_test_context_with_storage(s3(&store, Some(ANSWER)));
        // CANCEL-SAFETY: a publish to a store that never answers; nothing lands. The deadline
        // turns a publish that waits for the store into a failure.
        let resp = tokio::time::timeout(
            PROMPTLY * 2,
            send(
                &ctx.app,
                Method::PUT,
                "/raw/team/new-2026.bin",
                vec![7u8; 256 * 1024],
            ),
        )
        .await
        .expect("the publish waited for the store");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers()[header::RETRY_AFTER], "30");
    }

    /// A proxy whose upstream answers serves the upstream's answer while the store does not
    /// answer, and does not queue a write behind the store. An upstream that has no such
    /// artifact cannot be told from a store that could not say: 503 (known edge, #1182).
    #[tokio::test]
    async fn a_proxy_serves_its_upstream_while_the_store_does_not_answer() {
        use crate::config::MavenProxyEntry;
        let store = stalled_store().await;
        let upstream = MockServer::start().await;
        Mock::given(wiremock::matchers::path("/com/ex/lib/1.0/lib-1.0.jar"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"JAR".to_vec()))
            .mount(&upstream)
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&upstream)
            .await;
        let url = upstream.uri();
        let ctx = create_test_context_with_storage_and_config(s3(&store, Some(ANSWER)), move |c| {
            c.maven.proxies = vec![MavenProxyEntry::Simple(url)];
        });
        let resp = ask(&ctx.app, Method::GET, "/maven2/com/ex/lib/1.0/lib-1.0.jar").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"JAR");
        tokio::time::sleep(ANSWER).await;
        assert_eq!(writes_to(&store).await, 0, "a write went to the store");

        let resp = ask(&ctx.app, Method::GET, "/maven2/com/ex/lib/2.0/lib-2.0.jar").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// `answer_timeout_secs = 0`: a request waits for the store as long as the client retries,
    /// as before #1182.
    #[tokio::test]
    async fn without_an_answer_timeout_a_request_waits_for_the_store() {
        let store = stalled_store().await;
        let ctx = create_test_context_with_storage(s3(&store, None));
        // CANCEL-SAFETY: a read of a key; dropped at the deadline, it leaves nothing behind.
        let waited = tokio::time::timeout(
            PROMPTLY,
            send(&ctx.app, Method::GET, "/raw/team/report-2026.txt", ""),
        )
        .await;
        assert!(waited.is_err(), "answered within {PROMPTLY:?}");
    }

    /// Outside a request (a background task, a scheduler, the CLI) a read is waited for as
    /// before and notes nothing: no panic, no limit.
    #[tokio::test]
    async fn outside_a_request_a_read_is_waited_for_and_notes_nothing() {
        let store = stalled_store().await;
        let storage = s3(&store, Some(ANSWER));
        // CANCEL-SAFETY: a read of a key; dropped at the deadline, it leaves nothing behind.
        let waited = tokio::time::timeout(PROMPTLY, storage.get("raw/team/report-2026.txt")).await;
        assert!(waited.is_err(), "answered within {PROMPTLY:?}");
        assert!(!crate::storage::answer::unanswered_in_this_request());
    }

    /// The statuses passed through as the handler gave them, though the store did not answer
    /// the request, and the three replaced.
    #[tokio::test]
    async fn only_404_500_and_502_are_replaced() {
        use axum::routing::get;
        let store = stalled_store().await;
        let storage = s3(&store, Some(ANSWER));
        let app = axum::Router::new()
            .route(
                "/{code}",
                get(move |axum::extract::Path(code): axum::extract::Path<u16>| {
                    let storage = storage.clone();
                    async move {
                        let _ = storage.get("raw/any.txt").await;
                        StatusCode::from_u16(code).unwrap()
                    }
                }),
            )
            .layer(axum::middleware::from_fn(
                super::unanswered_store_middleware,
            ));
        for code in [
            200u16, 204, 206, 301, 304, 401, 403, 409, 412, 416, 429, 503,
        ] {
            let resp = ask(&app, Method::GET, &format!("/{code}")).await;
            assert_eq!(resp.status().as_u16(), code);
            assert!(resp.headers().get(header::RETRY_AFTER).is_none(), "{code}");
        }
        for code in [404u16, 500, 502] {
            let resp = ask(&app, Method::GET, &format!("/{code}")).await;
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{code}");
        }
    }
}
