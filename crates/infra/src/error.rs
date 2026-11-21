use thiserror::Error;

#[derive(Debug, Error)]
pub enum InfraError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Resource conflict: {0}")]
    Conflict(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Unauthorized target application: {0}")]
    UnauthorizedTarget(String),

    #[error("OWASP ZAP client error: {0}")]
    Zap(String),

    #[error("Pub/Sub error: {0}")]
    PubSub(String),

    #[error("PDF generation error: {0}")]
    Pdf(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Internal infrastructure error: {0}")]
    Internal(String),
}

impl From<redis::RedisError> for InfraError {
    fn from(err: redis::RedisError) -> Self {
        InfraError::PubSub(err.to_string())
    }
}
