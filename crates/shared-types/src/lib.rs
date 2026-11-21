pub mod app;
pub mod auth;
pub mod common;
pub mod cvss;
pub mod enums;
pub mod events;
pub mod scan;
pub mod vuln;

// Re-export common enums
pub use enums::{
    AppCriticality, AppEnvironment, DiffClassification, RemediationStatus, ScanStatus, ScanType,
    SeverityLevel, UserRole,
};

// Re-export app DTOs
pub use app::{
    AppTrendPoint, AppTrendsResponse, ApplicationResponse, ConfigureAuthRequest,
    CreateApplicationRequest, UpdateApplicationRequest,
};

// Re-export scan DTOs
pub use scan::{
    ScanComparisonResponse, ScanDiffSummary, ScanResponse, SeverityCounts, TriggerScanRequest,
};

// Re-export vuln DTOs
pub use vuln::{
    AddCommentRequest, BulkUpdateResponse, BulkUpdateVulnsRequest, HttpEvidence,
    RemediationAuditLogResponse, UpdateVulnerabilityRequest, VulnerabilityDetail,
    VulnerabilitySummary,
};

// Re-export auth DTOs
pub use auth::{
    ApiKeyResponse, CreateApiKeyRequest, CreateApiKeyResponse, LoginRequest, RefreshTokenRequest,
    TokenResponse, UserProfile,
};

// Re-export CVSS types
pub use cvss::{
    AttackComplexity, AttackVector, CiaImpact, CvssMetrics, CvssParseError, CvssVector,
    PrivilegesRequired, Scope, UserInteraction,
};

// Re-export event types
pub use events::{ScanCompletedEvent, ScanFailedEvent, ScanProgressEvent, WsServerEvent};

// Re-export common types
pub use common::{ErrorDetail, ErrorEnvelope, PaginatedResponse};
