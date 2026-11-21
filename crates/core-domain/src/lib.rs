//! Core Domain Logic & Algorithms
//!
//! Pure domain logic for Web Application Vulnerability Management:
//! - OWASP Top 10 (2021) classifier
//! - CVSS v3.1 scoring formulas, Appendix A roundup, and asset context risk weighting
//! - RFC 3986 URL path normalization and deterministic SHA-256 fingerprint deduplication
//! - Scan-to-scan diff engine with lifecycle state tracking and triage preservation

pub mod classifier;
pub mod cvss_engine;
pub mod deduplicator;
pub mod diff_engine;

// Re-export classifier
pub use classifier::{
    classify_owasp, A01_BROKEN_ACCESS_CONTROL, A02_CRYPTOGRAPHIC_FAILURES, A03_INJECTION,
    A04_INSECURE_DESIGN, A05_SECURITY_MISCONFIGURATION, A06_VULNERABLE_AND_OUTDATED_COMPONENTS,
    A07_IDENTIFICATION_AND_AUTHENTICATION_FAILURES, A08_SOFTWARE_AND_DATA_INTEGRITY_FAILURES,
    A09_SECURITY_LOGGING_AND_MONITORING_FAILURES, A10_SSRF,
};

// Re-export cvss engine
pub use cvss_engine::{calculate_asset_risk, calculate_cvss_v31, roundup};

// Re-export deduplicator
pub use deduplicator::{generate_fingerprint, normalize_url_path};

// Re-export diff engine
pub use diff_engine::{
    diff_scans, DiffItem, FindingFingerprint, FindingLifecycleState, ScanDiffResult,
};
