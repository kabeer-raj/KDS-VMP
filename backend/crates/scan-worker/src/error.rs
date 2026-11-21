use infra::InfraError;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum ScanWorkerError {
    #[error("Infra error: {0}")]
    Infra(#[from] InfraError),

    #[error("Application not found: {0}")]
    ApplicationNotFound(Uuid),

    #[error("Scan not found: {0}")]
    ScanNotFound(Uuid),

    #[error("Invalid state transition: {0}")]
    InvalidState(String),

    #[error("Scan was cancelled: {0}")]
    Cancelled(Uuid),

    #[error("Cron error: {0}")]
    Cron(String),

    #[error("ZAP error: {0}")]
    Zap(String),

    #[error("Worker error: {0}")]
    Other(String),
}
