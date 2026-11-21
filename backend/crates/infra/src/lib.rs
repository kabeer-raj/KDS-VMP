pub mod db;
pub mod error;
pub mod memory;
pub mod pdf;
pub mod pubsub;
pub mod traits;
pub mod zap;

// Common re-exports
pub use error::InfraError;
pub use traits::{
    AppRepository, AuditLogRepository, FindingIngestionInput, PdfGenerator, PubSubPort,
    ScanRepository, UserRepository, VulnFilter, VulnRepository, ZapAlert, ZapClient,
    ZapContextConfig,
};

pub fn init() {}
