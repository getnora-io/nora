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

/// JSON error response body
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
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
}
