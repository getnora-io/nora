// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Application error handling with HTTP response conversion
//!
//! Provides a unified error type that can be converted to HTTP responses
//! with appropriate status codes and JSON error bodies.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

use crate::storage::StorageError;
use crate::validation::ValidationError;

#[allow(dead_code)] // Handler integration tracked in backlog
/// Application-level errors with HTTP response conversion
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
}

#[allow(dead_code)]
/// JSON error response body
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            AppError::Storage(e) => match e {
                StorageError::NotFound => (StatusCode::NOT_FOUND, "Resource not found".to_string()),
                StorageError::Validation(v) => (StatusCode::BAD_REQUEST, v.to_string()),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            },
            AppError::Validation(e) => (StatusCode::BAD_REQUEST, e.to_string()),
        };

        (
            status,
            Json(ErrorResponse {
                error: message,
                request_id: None,
            }),
        )
            .into_response()
    }
}

#[allow(dead_code)]
impl AppError {
    /// Create a not found error
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    /// Create a bad request error
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    /// Create an unauthorized error
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }

    /// Create an internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_error_from_storage_error() {
        let storage_err = StorageError::NotFound;
        let app_err: AppError = storage_err.into();
        assert!(matches!(app_err, AppError::Storage(StorageError::NotFound)));
    }

    #[test]
    fn test_app_error_from_validation_error() {
        let val_err = ValidationError::EmptyInput;
        let app_err: AppError = val_err.into();
        assert!(matches!(
            app_err,
            AppError::Validation(ValidationError::EmptyInput)
        ));
    }

    #[test]
    fn test_error_display() {
        let err = AppError::NotFound("image not found".to_string());
        assert_eq!(err.to_string(), "Not found: image not found");
    }

    #[test]
    fn test_error_constructors() {
        let err = AppError::not_found("missing");
        assert!(matches!(err, AppError::NotFound(_)));
        assert_eq!(err.to_string(), "Not found: missing");

        let err = AppError::bad_request("invalid input");
        assert!(matches!(err, AppError::BadRequest(_)));
        assert_eq!(err.to_string(), "Bad request: invalid input");

        let err = AppError::unauthorized("no token");
        assert!(matches!(err, AppError::Unauthorized(_)));
        assert_eq!(err.to_string(), "Unauthorized: no token");

        let err = AppError::internal("db crashed");
        assert!(matches!(err, AppError::Internal(_)));
        assert_eq!(err.to_string(), "Internal error: db crashed");
    }

    #[test]
    fn test_error_display_storage() {
        let err = AppError::Storage(StorageError::NotFound);
        assert!(err.to_string().contains("Storage error"));
    }

    #[test]
    fn test_error_display_validation() {
        let err = AppError::Validation(ValidationError::PathTraversal);
        assert!(err.to_string().contains("Validation error"));
    }

    #[test]
    fn test_error_into_response_not_found() {
        let err = AppError::NotFound("gone".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_error_into_response_bad_request() {
        let err = AppError::BadRequest("bad".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_error_into_response_unauthorized() {
        let err = AppError::Unauthorized("nope".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_error_into_response_internal() {
        let err = AppError::Internal("boom".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_error_into_response_storage_not_found() {
        let err = AppError::Storage(StorageError::NotFound);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_error_into_response_validation() {
        let err = AppError::Validation(ValidationError::EmptyInput);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
