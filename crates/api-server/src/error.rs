use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use shared_types::ErrorEnvelope;
use thiserror::Error;
use uuid::Uuid;

use infra::InfraError;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Unauthorized ({code}): {message}")]
    Unauthorized { code: String, message: String },

    #[error("Forbidden ({code}): {message}")]
    Forbidden { code: String, message: String },

    #[error("Not Found ({code}): {message}")]
    NotFound { code: String, message: String },

    #[error("Bad Request ({code}): {message}")]
    BadRequest { code: String, message: String },

    #[error("Conflict ({code}): {message}")]
    Conflict { code: String, message: String },

    #[error("Internal Error ({code}): {message}")]
    Internal { code: String, message: String },
}

impl AppError {
    pub fn unauthorized(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Unauthorized {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn forbidden(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Forbidden {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn not_found(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::NotFound {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::BadRequest {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn conflict(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Conflict {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn internal(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Internal {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Forbidden { .. } => StatusCode::FORBIDDEN,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Unauthorized { code, .. }
            | Self::Forbidden { code, .. }
            | Self::NotFound { code, .. }
            | Self::BadRequest { code, .. }
            | Self::Conflict { code, .. }
            | Self::Internal { code, .. } => code.as_str(),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Unauthorized { message, .. }
            | Self::Forbidden { message, .. }
            | Self::NotFound { message, .. }
            | Self::BadRequest { message, .. }
            | Self::Conflict { message, .. }
            | Self::Internal { message, .. } => message.as_str(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let req_id = format!("req_{}", Uuid::new_v4().simple());
        let env = ErrorEnvelope::new(self.code(), self.message(), req_id);
        (status, Json(env)).into_response()
    }
}

impl From<InfraError> for AppError {
    fn from(err: InfraError) -> Self {
        match err {
            InfraError::NotFound(msg) => AppError::not_found("NOT_FOUND", msg),
            InfraError::Conflict(msg) => AppError::conflict("CONFLICT", msg),
            InfraError::Validation(msg) => AppError::bad_request("VALIDATION_ERROR", msg),
            InfraError::InvalidInput(msg) => AppError::bad_request("INVALID_INPUT", msg),
            InfraError::Auth(msg) => AppError::unauthorized("INVALID_TOKEN", msg),
            InfraError::UnauthorizedTarget(msg) => {
                AppError::bad_request("UNAUTHORIZED_TARGET", msg)
            }
            other => AppError::internal("INTERNAL_SERVER_ERROR", other.to_string()),
        }
    }
}
