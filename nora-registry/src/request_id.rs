// Copyright (c) 2026 Volkov Pavel | DevITWay
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
    // Check if request already has an ID (from upstream proxy/gateway)
    let request_id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

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
}
