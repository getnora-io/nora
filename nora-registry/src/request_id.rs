// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Request ID middleware for request tracking and correlation
//!
//! Generates a unique ID for each request that can be used for:
//! - Log correlation across services
//! - Debugging production issues
//! - Client error reporting

use axum::{
    body::Body,
    http::{header::HeaderName, HeaderValue, Request},
    middleware::Next,
    response::Response,
};
use tracing::{info_span, Instrument};
use uuid::Uuid;

/// Header name for request ID
pub static REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Request ID wrapper type for extraction from request extensions
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

impl std::ops::Deref for RequestId {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Maximum length for an externally-provided request ID.
/// UUID is 36 chars; 128 is generous for any legitimate correlation ID.
const MAX_REQUEST_ID_LEN: usize = 128;

/// Validate an external request ID: printable ASCII only, bounded length.
/// Returns `None` if the value is unsafe for log inclusion (#539).
fn sanitize_request_id(raw: &str) -> Option<&str> {
    if raw.is_empty() || raw.len() > MAX_REQUEST_ID_LEN {
        return None;
    }
    // Only allow printable ASCII (0x21..=0x7E). Reject space (0x20) to prevent
    // log field splitting, and control chars (0x00..=0x1F, 0x7F) to prevent
    // log injection.
    if raw.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        Some(raw)
    } else {
        None
    }
}

/// Middleware that adds a unique request ID to each request.
///
/// The request ID is:
/// 1. Taken from incoming `X-Request-ID` header if present (for upstream tracing)
/// 2. Generated as a new UUID v4 if not present
///
/// The ID is:
/// - Stored in request extensions for handlers to access
/// - Added to the response `X-Request-ID` header
/// - Included in the tracing span for log correlation
pub async fn request_id_middleware(mut request: Request<Body>, next: Next) -> Response {
    // Check if request already has an ID (from upstream proxy/gateway).
    // Sanitize to prevent log injection via control chars or oversized values (#539).
    let request_id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(sanitize_request_id)
        .map(String::from)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    debug_assert!(
        request_id.len() <= MAX_REQUEST_ID_LEN && request_id.is_ascii(),
        "request_id postcondition violated"
    );

    // Store in request extensions for handlers to access
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    // Create tracing span with request metadata
    let span = info_span!(
        "request",
        request_id = %request_id,
        method = %request.method(),
        uri = %request.uri().path(),
    );

    // Run the request handler within the span
    let mut response = next.run(request).instrument(span).await;

    // Add request ID to response headers
    if let Ok(header_value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(&REQUEST_ID_HEADER, header_value);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_id_deref() {
        let id = RequestId("test-123".to_string());
        assert_eq!(&*id, "test-123");
    }

    #[test]
    fn test_request_id_clone() {
        let id = RequestId("test-123".to_string());
        let cloned = id.clone();
        assert_eq!(id.0, cloned.0);
    }

    #[test]
    fn test_request_id_debug() {
        let id = RequestId("abc-def".to_string());
        let debug = format!("{:?}", id);
        assert!(debug.contains("abc-def"));
    }

    #[test]
    fn test_request_id_header_name() {
        assert_eq!(REQUEST_ID_HEADER.as_str(), "x-request-id");
    }

    #[test]
    fn test_request_id_deref_string_methods() {
        let id = RequestId("req-12345".to_string());
        assert!(id.starts_with("req-"));
        assert_eq!(id.len(), 9);
    }

    // --- sanitize_request_id tests (#539) ---

    #[test]
    fn test_sanitize_valid_uuid() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(sanitize_request_id(uuid), Some(uuid));
    }

    #[test]
    fn test_sanitize_rejects_empty() {
        assert_eq!(sanitize_request_id(""), None);
    }

    #[test]
    fn test_sanitize_rejects_too_long() {
        let long = "a".repeat(MAX_REQUEST_ID_LEN + 1);
        assert_eq!(sanitize_request_id(&long), None);
    }

    #[test]
    fn test_sanitize_max_length_accepted() {
        let exact = "a".repeat(MAX_REQUEST_ID_LEN);
        assert_eq!(sanitize_request_id(&exact), Some(exact.as_str()));
    }

    #[test]
    fn test_sanitize_rejects_newline() {
        assert_eq!(sanitize_request_id("real-id\nfake-log-line"), None);
    }

    #[test]
    fn test_sanitize_rejects_tab() {
        assert_eq!(sanitize_request_id("id\twith-tab"), None);
    }

    #[test]
    fn test_sanitize_rejects_null_byte() {
        assert_eq!(sanitize_request_id("id\0null"), None);
    }

    #[test]
    fn test_sanitize_rejects_space() {
        assert_eq!(sanitize_request_id("id with space"), None);
    }

    #[test]
    fn test_sanitize_allows_printable_ascii() {
        assert_eq!(
            sanitize_request_id("req-123_abc.XYZ~!@#"),
            Some("req-123_abc.XYZ~!@#")
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{create_test_context, send, send_with_headers};
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_response_has_request_id() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/health", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let request_id = response.headers().get("x-request-id");
        assert!(
            request_id.is_some(),
            "Response must have X-Request-ID header"
        );
        let value = request_id.unwrap().to_str().unwrap();
        assert!(!value.is_empty(), "X-Request-ID must not be empty");
    }

    #[tokio::test]
    async fn test_preserves_incoming_request_id() {
        let ctx = create_test_context();
        let custom_id = "custom-123";

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/health",
            vec![("x-request-id", custom_id)],
            "",
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let returned_id = response
            .headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(returned_id, custom_id);
    }
}
