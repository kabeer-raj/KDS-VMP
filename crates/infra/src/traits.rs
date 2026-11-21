use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use core_domain::diff_engine::ScanDiffResult;
use shared_types::{
    ApiKeyResponse, AppEnvironment, AppTrendsResponse, ApplicationResponse,
    BulkUpdateVulnsRequest, ConfigureAuthRequest, CreateApiKeyRequest, CreateApplicationRequest,
    PaginatedResponse, RemediationAuditLogResponse, RemediationStatus, ScanDiffSummary,
    ScanResponse, ScanStatus, SeverityCounts, SeverityLevel, TriggerScanRequest,
    UpdateApplicationRequest, UpdateVulnerabilityRequest, UserProfile, UserRole,
    VulnerabilityDetail, VulnerabilitySummary, WsServerEvent,
};

use crate::error::InfraError;

// ============================================================================
// Filter and Ingestion Models
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct VulnFilter {
    pub app_id: Option<Uuid>,
    pub severity: Option<SeverityLevel>,
    pub status: Option<RemediationStatus>,
    pub owasp_category: Option<String>,
    pub assigned_to: Option<Uuid>,
    pub search: Option<String>,
    pub sort_by: Option<String>,
    pub order: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingIngestionInput {
    pub zap_plugin_id: String,
    pub title: String,
    pub cwe_id: Option<i32>,
    pub wasc_id: Option<i32>,
    pub confidence: String,
    pub http_method: String,
    pub affected_url: String,
    pub affected_param: Option<String>,
    pub attack_payload: Option<String>,
    pub evidence_snippet: Option<String>,
    pub description: String,
    pub solution: String,
    pub reference_urls: Vec<String>,
    pub raw_request_header: Option<String>,
    pub raw_response_header: Option<String>,
    pub cvss_score: Option<f64>,
    pub severity: Option<SeverityLevel>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZapContextConfig {
    pub context_name: String,
    pub target_url: String,
    pub include_regexes: Vec<String>,
    pub exclude_regexes: Vec<String>,
    pub auth_header: Option<(String, String)>,
    pub session_cookie: Option<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZapAlert {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "pluginId", default)]
    pub plugin_id: String,
    #[serde(default)]
    pub alert: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub risk: String,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub param: Option<String>,
    #[serde(default)]
    pub attack: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub solution: String,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub cweid: Option<String>,
    #[serde(default)]
    pub wascid: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(rename = "requestHeader", default)]
    pub request_header: Option<String>,
    #[serde(rename = "responseHeader", default)]
    pub response_header: Option<String>,
}

// ============================================================================
// Core Repository & Adapter Ports (Traits)
// ============================================================================

#[async_trait]
pub trait AppRepository: Send + Sync {
    async fn create(&self, req: &CreateApplicationRequest, owner_id: Option<Uuid>) -> Result<ApplicationResponse, InfraError>;
    async fn get_by_id(&self, id: Uuid) -> Result<Option<ApplicationResponse>, InfraError>;
    async fn list(&self, owner_id: Option<Uuid>, env: Option<AppEnvironment>) -> Result<Vec<ApplicationResponse>, InfraError>;
    async fn list_by_owner(&self, owner_id: Option<Uuid>) -> Result<Vec<ApplicationResponse>, InfraError> {
        self.list(owner_id, None).await
    }
    async fn update(&self, id: Uuid, req: &UpdateApplicationRequest) -> Result<Option<ApplicationResponse>, InfraError>;
    async fn delete(&self, id: Uuid) -> Result<bool, InfraError>;
    async fn get_trends(&self, app_id: Uuid) -> Result<AppTrendsResponse, InfraError>;
    async fn update_auth_config(&self, app_id: Uuid, req: &ConfigureAuthRequest) -> Result<(), InfraError>;
    async fn update_latest_risk(&self, app_id: Uuid, risk_score: f64, last_scanned_at: DateTime<Utc>) -> Result<(), InfraError>;
}

#[async_trait]
pub trait ScanRepository: Send + Sync {
    async fn create(&self, app_id: Uuid, triggered_by: Option<Uuid>, req: &TriggerScanRequest, prev_scan_id: Option<Uuid>) -> Result<ScanResponse, InfraError>;
    async fn get_by_id(&self, scan_id: Uuid) -> Result<Option<ScanResponse>, InfraError>;
    async fn list_by_app(&self, app_id: Uuid, page: u64, per_page: u64) -> Result<PaginatedResponse<ScanResponse>, InfraError>;
    async fn update_status(&self, scan_id: Uuid, status: ScanStatus, error_message: Option<String>) -> Result<(), InfraError>;
    async fn update_progress(&self, scan_id: Uuid, progress_percent: u8) -> Result<(), InfraError>;
    async fn update_metrics(&self, scan_id: Uuid, counts: &SeverityCounts, diff: &ScanDiffSummary, risk_score: f64, duration_seconds: Option<i32>) -> Result<(), InfraError>;
    async fn cancel(&self, scan_id: Uuid) -> Result<bool, InfraError>;
    async fn list_findings(&self, scan_id: Uuid, page: u64, per_page: u64) -> Result<PaginatedResponse<VulnerabilitySummary>, InfraError>;
    async fn get_latest_completed_scan_id(&self, app_id: Uuid) -> Result<Option<Uuid>, InfraError>;
}

#[async_trait]
pub trait VulnRepository: Send + Sync {
    async fn upsert_findings(&self, scan_id: Uuid, app_id: Uuid, raw_findings: &[FindingIngestionInput], prev_scan_id: Option<Uuid>) -> Result<ScanDiffResult, InfraError>;
    async fn list_with_filters(&self, filter: &VulnFilter, page: u64, per_page: u64) -> Result<PaginatedResponse<VulnerabilitySummary>, InfraError>;
    async fn get_by_id(&self, id: Uuid) -> Result<Option<VulnerabilityDetail>, InfraError>;
    async fn update_triage(&self, id: Uuid, req: &UpdateVulnerabilityRequest, actor_id: Option<Uuid>) -> Result<Option<VulnerabilityDetail>, InfraError>;
    async fn bulk_update(&self, req: &BulkUpdateVulnsRequest, actor_id: Option<Uuid>) -> Result<usize, InfraError>;
    async fn get_history(&self, id: Uuid) -> Result<Vec<RemediationAuditLogResponse>, InfraError>;
    async fn add_comment(&self, id: Uuid, comment: &str, actor_id: Option<Uuid>) -> Result<RemediationAuditLogResponse, InfraError>;
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_email(&self, email: &str) -> Result<Option<UserProfile>, InfraError>;
    async fn find_by_id(&self, user_id: Uuid) -> Result<Option<UserProfile>, InfraError>;
    async fn get_password_hash(&self, email: &str) -> Result<Option<(UserProfile, String)>, InfraError>;
    async fn verify_password(&self, email: &str, password_hash: &str) -> Result<Option<UserProfile>, InfraError>;
    async fn create(&self, email: &str, full_name: &str, password_hash: &str, role: UserRole) -> Result<UserProfile, InfraError>;
    async fn update_last_login(&self, user_id: Uuid) -> Result<(), InfraError>;
    async fn api_key_lookup(&self, key_hash: &str) -> Result<Option<(UserProfile, Uuid)>, InfraError>;
    async fn create_api_key(&self, user_id: Uuid, req: &CreateApiKeyRequest, key_prefix: &str, key_hash: &str) -> Result<ApiKeyResponse, InfraError>;
    async fn list_api_keys(&self, user_id: Uuid) -> Result<Vec<ApiKeyResponse>, InfraError>;
    async fn revoke_api_key(&self, key_id: Uuid, user_id: Uuid) -> Result<bool, InfraError>;
}

#[async_trait]
pub trait AuditLogRepository: Send + Sync {
    async fn record_log(
        &self,
        vuln_id: Uuid,
        actor_id: Option<Uuid>,
        scan_id: Option<Uuid>,
        action_type: &str,
        old_status: Option<RemediationStatus>,
        new_status: Option<RemediationStatus>,
        comment: Option<&str>,
    ) -> Result<RemediationAuditLogResponse, InfraError>;
    async fn list_by_vuln(&self, vuln_id: Uuid) -> Result<Vec<RemediationAuditLogResponse>, InfraError>;
}

#[async_trait]
pub trait PubSubPort: Send + Sync {
    async fn publish_scan_progress(&self, event: &WsServerEvent) -> Result<(), InfraError>;
    async fn subscribe_scan_progress(&self, scan_id: Uuid) -> Result<tokio::sync::broadcast::Receiver<WsServerEvent>, InfraError>;
}

#[async_trait]
pub trait ZapClient: Send + Sync {
    async fn start_spider(&self, target_url: &str, context_name: Option<&str>) -> Result<String, InfraError>;
    async fn get_spider_status(&self, scan_id: &str) -> Result<u8, InfraError>;
    async fn start_active_scan(&self, target_url: &str, context_name: Option<&str>) -> Result<String, InfraError>;
    async fn get_active_scan_status(&self, scan_id: &str) -> Result<u8, InfraError>;
    async fn get_alerts(&self, base_url: &str, start: Option<u32>, count: Option<u32>) -> Result<Vec<ZapAlert>, InfraError>;
    async fn configure_context(&self, context: &ZapContextConfig) -> Result<String, InfraError>;
}

#[async_trait]
pub trait PdfGenerator: Send + Sync {
    async fn generate_scan_report(&self, scan: &ScanResponse, app: &ApplicationResponse, findings: &[VulnerabilityDetail]) -> Result<Vec<u8>, InfraError>;
    async fn generate_app_report(&self, app: &ApplicationResponse, scans: &[ScanResponse], open_vulns: &[VulnerabilityDetail]) -> Result<Vec<u8>, InfraError>;
}
